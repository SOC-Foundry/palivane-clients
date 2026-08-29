"""Palivane egress-proxy capture plane (mitmproxy addon).

Catches AI usage that the browser extension can't see — **desktop apps** (Claude /
ChatGPT desktop), IDE assistants, CLIs, anything that makes its own HTTPS calls to an
AI provider. Run it as a TLS-inspecting forward proxy; on a managed device the system
proxy + corporate root cert are pushed via MDM, so it's transparent to the user.

For each outbound POST to a known AI domain it extracts the prompt, scores it through
Palivane (`POST /api/ingest/ai-usage`), records a finding, and — in enforce mode —
**blocks** the request with a 400 before it reaches the provider.

It also inspects **MCP** (Model Context Protocol) traffic — the JSON-RPC an AI coding
agent uses to call tools and read resources. Remote/Streamable-HTTP MCP servers flow
through this proxy, so their tool calls, resource reads, and tool listings are scored via
`POST /api/ingest/mcp` and blocked (JSON-RPC error) on a block verdict — agentlessly.
Local *stdio* MCP servers never touch the network; those are governed by policy (a server
allowlist) and surfaced via the tool definitions the agent sends to the LLM API, which we
*can* see here.

Run (mitmproxy >= 8 on Python >= 3.9 — the hooks are async and use asyncio.to_thread):
    pip install mitmproxy
    PALIVANE_URL=http://localhost:8090 PALIVANE_TOKEN=ext-demo-token-123 \
    PALIVANE_PROXY_ENFORCE=true \
    mitmdump -s proxy/palivane_addon.py --listen-port 8081

The parsing/decision logic is plain functions (no mitmproxy import) so it's unit-tested
standalone; the mitmproxy hook is a thin wrapper.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

# Outbound destinations we inspect (suffix match on the request host).

# Reported in the User-Agent so the console can inventory client builds per device.
VERSION = "1.3.0"
AI_HOST_SUFFIXES = (
    # chatgpt.com also covers the ChatGPT *desktop app* (Atlas's successor, with the
    # built-in browser): its Chat/Work/Codex modes all talk to the chatgpt.com backend,
    # so the suffix match sweeps in every subdomain the desktop app uses.
    "api.openai.com", "chatgpt.com", "chat.openai.com",
    "api.anthropic.com", "claude.ai",
    "generativelanguage.googleapis.com", "gemini.google.com",
    # Gemini CLI: API-key mode hits generativelanguage (above); the default OAuth
    # "log in with Google" mode routes through Code Assist, and Vertex mode through
    # aiplatform — both carry the same generateContent body shape.
    "cloudcode-pa.googleapis.com", "aiplatform.googleapis.com",
    "api.cohere.ai", "api.mistral.ai", "api.perplexity.ai",
    # Perplexity Comet (agentic browser): assistant prompts flow as SSE on
    # www.perplexity.ai/rest/sse/perplexity_ask, agent automation over
    # wss://www.perplexity.ai/agent. Only the www host — the api. host above is the
    # structured API; other perplexity.ai subdomains stay un-decrypted.
    "www.perplexity.ai",
    # GitHub Copilot (IDE assistants): chat + completions. The suffix
    # "githubcopilot.com" covers api / api.business / api.individual variants.
    "githubcopilot.com", "copilot-proxy.githubusercontent.com",
    # Microsoft Copilot (consumer web / desktop).
    "copilot.microsoft.com",
    # Cursor (AI IDE): model calls route through Cursor's backend (api2/api3.cursor.sh,
    # newer cursor.com). detect_tool() tags these "cursor".
    "cursor.sh", "cursor.com",
)

_ACTION_RANK = {"benign": 0, "low": 1, "suspicious": 2, "high": 3, "critical": 4}


def is_ai_host(host: str) -> bool:
    host = (host or "").lower()
    return any(host == s or host.endswith("." + s) or host.endswith(s) for s in AI_HOST_SUFFIXES)


def intercept_hosts() -> list[str]:
    """Host suffixes whose TLS we terminate: the AI list plus any org-added extras
    (PALIVANE_PROXY_INTERCEPT_EXTRA, comma-separated — e.g. remote MCP servers)."""
    extra = [h.strip().lower() for h in
             os.getenv("PALIVANE_PROXY_INTERCEPT_EXTRA", "").split(",") if h.strip()]
    return list(AI_HOST_SUFFIXES) + extra


def intercept_patterns() -> list[str]:
    """mitmproxy allow_hosts regexes (matched against "host:port"): the suffix itself or
    any subdomain of it, on any port."""
    return [r"(^|\.)" + re.escape(h) + r":\d+$" for h in intercept_hosts()]


# Hosts whose request shape we reliably parse (messages/contents). On THESE, a body that
# isn't a recognized prompt shape is not a prompt — it's the tool's telemetry/metadata to
# the same API host (e.g. Claude Code's ClaudeCodeInternalEvent / session-count events,
# which carry the user's own email). We must NOT harvest those; doing so false-positived
# on the tool's own analytics and blocked every prompt. Web/proprietary hosts (chat UIs,
# Cursor) still get the harvest fallback since we can't parse their bodies.
STRUCTURED_API_SUFFIXES = (
    "api.openai.com", "api.anthropic.com",
    "generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com",
    "aiplatform.googleapis.com", "api.cohere.ai", "api.mistral.ai", "api.perplexity.ai",
    "githubcopilot.com", "copilot-proxy.githubusercontent.com",
)


def needs_harvest(host: str) -> bool:
    """Only harvest-all-strings for AI hosts whose body shape we can't parse (proprietary
    backends, chat web UIs). Structured API hosts are excluded — an unrecognized body
    there is telemetry, not user data."""
    host = (host or "").lower()
    if any(host == s or host.endswith("." + s) or host.endswith(s) for s in STRUCTURED_API_SUFFIXES):
        return False
    return is_ai_host(host)


# Agent clients inject context wrappers into the user turn — Claude Code's <system-reminder>
# carries the user's own email/date/env as "context". That's scaffolding, not user
# data-egress; scanning it flags the user's own identity as a PII leak on every turn.
_SYSTEM_REMINDER_RE = re.compile(r"<system-reminder>.*?</system-reminder>", re.S | re.I)


def _harvest_strings(obj, out: list[str]) -> None:
    """Recursively collect string *values* from an arbitrary JSON structure (dict keys
    are ignored). Lets us scan unknown request shapes — e.g. Cursor's proprietary body —
    for secrets/PII without a per-vendor parser."""
    if isinstance(obj, str):
        if len(obj) >= 2:
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _harvest_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _harvest_strings(v, out)


def extract_prompt(body: bytes | str) -> str:
    """Pull the user-authored text from a request body.

    Recognizes OpenAI/Anthropic/Gemini shapes; for any other JSON body (e.g. an IDE's
    proprietary protocol) it falls back to harvesting all string values so secrets/PII
    are still scanned. Non-JSON bodies fall back to the raw text."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    if not body:
        return ""
    try:
        j = json.loads(body)
    except (ValueError, TypeError):
        return body[:8000]

    parts: list[str] = []

    # OpenAI / Anthropic messages API: [{role, content}], content str or block list.
    # Scan only the CURRENT user turn — the LAST user message — not the whole history or
    # the tool's system prompt. Agent clients (Claude Code, Cursor) resend the entire
    # conversation plus a large context/env scaffold (git email, cwd, file listings) on
    # every request; scanning all of it re-flags the same content every turn and
    # false-positives on the assistant's own scaffolding, blocking every prompt. The user's
    # actual data-egress is what they send now — the latest user message. (Mirrors the
    # gateway's _scan_messages scoping; earlier turns were already scanned when they were new.)
    msgs = j.get("messages") if isinstance(j, dict) else None
    if isinstance(msgs, list):
        last_user = ""
        for m in msgs:
            if not isinstance(m, dict):
                continue
            role = (m.get("author") or {}).get("role") if isinstance(m.get("author"), dict) else m.get("role")
            if role != "user":
                continue
            c = m.get("content")
            text = ""
            if isinstance(c, str):
                text = c
            elif isinstance(c, dict) and isinstance(c.get("parts"), list):   # ChatGPT web
                text = "\n".join(p for p in c["parts"] if isinstance(p, str))
            elif isinstance(c, list):                                         # Anthropic blocks
                text = "\n".join(b["text"] for b in c
                                 if isinstance(b, dict) and isinstance(b.get("text"), str))
            if text.strip():
                last_user = text        # keep the LAST user turn only
        if last_user:
            parts.append(last_user)

    # Gemini: contents:[{role, parts:[{text}]}] — same current-turn scoping: the last user
    # turn only (role defaults to "user" when absent, e.g. single-shot generateContent).
    contents = j.get("contents") if isinstance(j, dict) else None
    if isinstance(contents, list):
        last_user = ""
        for item in contents:
            if not isinstance(item, dict):
                continue
            if item.get("role", "user") != "user":
                continue
            text = "\n".join(p["text"] for p in (item.get("parts") or [])
                             if isinstance(p, dict) and isinstance(p.get("text"), str))
            if text.strip():
                last_user = text
        if last_user:
            parts.append(last_user)

    # Legacy single-field shapes.
    if isinstance(j, dict):
        for key in ("prompt", "input", "text"):
            v = j.get(key)
            if isinstance(v, str):
                parts.append(v)

    structured = "\n".join(p for p in parts if p).strip()
    # Strip agent-injected context wrappers before returning (Claude Code's <system-reminder>
    # carries the user's own email/env — not user data-egress).
    structured = _SYSTEM_REMINDER_RE.sub(" ", structured).strip()
    # "" when no recognized prompt shape: the caller harvests ONLY for proprietary hosts
    # (needs_harvest) — a shapeless body on a structured API host is telemetry, not a prompt.
    return structured


def harvest_prompt(body: bytes | str) -> str:
    """Fallback for proprietary/unparseable request bodies (Cursor, chat web UIs): harvest
    every string value so a secret/PII is still caught without a per-vendor parser. Used
    only for hosts where needs_harvest() is true — never for structured API telemetry."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    if not body:
        return ""
    try:
        j = json.loads(body)
    except (ValueError, TypeError):
        return body[:8000]
    harvested: list[str] = []
    _harvest_strings(j, harvested)
    text = "\n".join(harvested)[:20000] if harvested else body[:8000]
    return _SYSTEM_REMINDER_RE.sub(" ", text).strip()


# --- Agentic browsers: Perplexity Comet ------------------------------------------------
# Comet runs the agent *in the browser*, so the model call never comes through a page
# fetch the extension wraps — the egress proxy is the inline path. Per the Zenity Labs
# teardown (Aug 2026): the user/assistant prompt is a JSON POST answered by an SSE stream
# on www.perplexity.ai/rest/sse/perplexity_ask, and agent automation rides a WebSocket to
# wss://www.perplexity.ai/agent. The parsers below are built to that teardown shape and
# degrade gracefully — a body that doesn't match is reported as a parse-miss finding (and
# harvest-scanned), never a crash. Built on Linux against synthetic fixtures
# (proxy/fixtures/comet/); NOT yet verified against a real Comet build — no Linux build
# exists. Verification runbook: docs/agentic-browser-verification.md.

COMET_ASK_PATH = "/rest/sse/perplexity_ask"
COMET_AGENT_WS_PATH = "/agent"
_COMET_SSE_CAP = 1 << 20        # tee at most 1 MiB of a streamed SSE response


def _is_perplexity_host(host: str) -> bool:
    host = (host or "").lower()
    return host == "perplexity.ai" or host.endswith(".perplexity.ai")


def _path_only(path: str) -> str:
    return (path or "").split("?", 1)[0]


def is_comet_ask(host: str, path: str) -> bool:
    """The Comet/Perplexity assistant endpoint (JSON request, SSE response)."""
    return _is_perplexity_host(host) and _path_only(path) == COMET_ASK_PATH


def is_comet_agent_ws(host: str, path: str) -> bool:
    """The Comet agent-automation WebSocket (wss://www.perplexity.ai/agent)."""
    return _is_perplexity_host(host) and _path_only(path) == COMET_AGENT_WS_PATH


def extract_comet_ask(body: bytes | str) -> tuple[str, bool]:
    """User/agent prompt from a perplexity_ask *request* body -> (text, parsed_ok).

    Expected shape (Zenity teardown): JSON with `query_str` at the top level and/or
    under `params`. parsed_ok=False means the body didn't match — the caller records a
    parse-miss and falls back to harvesting, so shape drift degrades to observe-only
    scanning instead of silence (or a crash)."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    try:
        j = json.loads(body or "")
    except (ValueError, TypeError):
        return "", False
    if not isinstance(j, dict):
        return "", False
    parts: list[str] = []
    for container in (j, j.get("params") if isinstance(j.get("params"), dict) else {}):
        q = container.get("query_str")
        if isinstance(q, str) and q.strip() and q not in parts:
            parts.append(q)
    if not parts:
        return "", False
    return "\n".join(parts)[:20000], True


def _comet_frame_text(j: dict, parts: list[str]) -> None:
    """Collect scannable text from one SSE data frame (mutates `parts`)."""
    q = j.get("query_str")
    if isinstance(q, str) and q.strip():
        parts.append(q)
    # Streamed answer/agent-step markdown: blocks[].markdown_block.chunks[]. Progress
    # frames are cumulative (each resends all chunks so far) — collect all here; the
    # caller drops earlier partials that are prefixes of a later, fuller frame.
    blocks = j.get("blocks")
    if isinstance(blocks, list):
        for b in blocks:
            if not isinstance(b, dict):
                continue
            mb = b.get("markdown_block")
            if isinstance(mb, dict) and isinstance(mb.get("chunks"), list):
                text = "".join(c for c in mb["chunks"] if isinstance(c, str))
                if text.strip():
                    parts.append(text)
    # Legacy/step shape: "text" is either plain text or a JSON-encoded list of steps
    # ([{step_type, content:{answer: ...}}]) — harvest whatever strings are inside.
    t = j.get("text")
    if isinstance(t, str) and t.strip():
        try:
            steps = json.loads(t)
        except (ValueError, TypeError):
            parts.append(t)
        else:
            harvested: list[str] = []
            _harvest_strings(steps, harvested)
            parts.extend(harvested)
    a = j.get("answer")
    if isinstance(a, str) and a.strip():
        parts.append(a)


def extract_comet_sse(body: bytes | str) -> tuple[str, bool]:
    """User query + agent/answer text from a perplexity_ask SSE *response* stream ->
    (text, parsed_ok). Reuses the `data:`-frame parser; unknown-but-JSON frames with no
    recognizable text yield ("", False) so the caller logs a parse-miss finding."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    if not (body or "").strip():
        return "", False
    parts: list[str] = []
    frames = _json_objects(body)
    for j in frames:
        if isinstance(j, dict):
            _comet_frame_text(j, parts)
    if not parts:
        return "", False
    # Progress frames are cumulative (each resends all markdown so far): drop exact
    # duplicates AND any part that is a prefix of a later, fuller part, keeping order.
    seen: set[str] = set()
    uniq = [p for p in parts if not (p in seen or seen.add(p))]
    final = [p for i, p in enumerate(uniq)
             if not any(q.startswith(p) for q in uniq[i + 1:])]
    return "\n".join(final)[:20000], True


def extract_ws_text(payload: bytes | str) -> str:
    """Scannable text from a WebSocket frame on the Comet agent channel: harvest string
    values from a JSON frame, pass a plain-text frame through, and return "" for binary
    (nothing scannable — the hook still logs the frame's existence + size)."""
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError:
            return ""
    if not (payload or "").strip():
        return ""
    # Socket.io-style frames prefix JSON with digits (e.g. `42["event",{...}]`) — strip.
    stripped = payload.lstrip("0123456789")
    for candidate in (payload, stripped):
        if candidate[:1] in ("{", "["):
            try:
                j = json.loads(candidate)
            except (ValueError, TypeError):
                continue
            harvested: list[str] = []
            _harvest_strings(j, harvested)
            return "\n".join(harvested)[:20000]
    return payload[:8000]


def detect_tool(user_agent: str) -> str:
    """Identify a coding assistant from its User-Agent so per-tool policy can apply."""
    ua = (user_agent or "").lower()
    if "claude-cli" in ua or "claude-code" in ua:
        return "claude-code"
    if "cursor" in ua:
        return "cursor"
    if "copilot" in ua:
        return "copilot"
    if "gemini" in ua or "geminicli" in ua:
        return "gemini-cli"
    # Comet's UA may be indistinguishable from Chrome (unverified — no Linux build); the
    # request() hook tags Comet by endpoint (is_comet_ask), this is best-effort backup.
    if "comet" in ua:
        return "comet"
    return ""


# --- Auth circuit breaker -------------------------------------------------------------
# HTTP 401/403 means THIS token is dead (revoked or invalid) — a permanent signal, so we
# stop calling out on every intercepted request. We fingerprint the token, stand down (fail
# open, no network) for _DEAUTH_SECS, and re-probe hourly in case the 401 was transient. A
# fresh token from `palivane connect` has a different fingerprint, so a stale marker never
# suppresses it. Repeated transient errors (timeouts/5xx) trip a shorter cooldown so we
# don't retry-storm an unreachable backend either.
_DEAUTH_SECS = 3600
_COOLDOWN_SECS = 300
_FAIL_THRESHOLD = 3


def _breaker_path() -> str:
    d = os.path.expanduser(os.getenv("PALIVANE_STATE_DIR", "~/.palivane"))
    return os.path.join(d, "proxy-breaker.json")


def _token_fp(token: str) -> str:
    return hashlib.sha256((token or "").encode()).hexdigest()[:16]


def _breaker_load() -> dict:
    try:
        with open(_breaker_path()) as fh:
            return json.load(fh)
    except Exception:
        return {}


def _breaker_save(state: dict) -> None:
    try:
        path = _breaker_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(state, fh)
        os.replace(tmp, path)
    except Exception:
        pass


def _breaker_skip(token: str) -> str:
    """Reason to skip the network and fail open, or '' to proceed."""
    st, fp, now = _breaker_load(), _token_fp(token), time.time()
    if st.get("deauth_fp") == fp and now < st.get("deauth_until", 0):
        return "deauthorized"
    if now < st.get("cooldown_until", 0):
        return "backoff"
    return ""


def _breaker_record(token: str, status) -> None:
    """status: 200 healthy | 401/403 revoked | None transient error."""
    st, fp, now = _breaker_load(), _token_fp(token), time.time()
    if status == 200:
        if st:
            _breaker_save({})                       # healthy — clear breaker state
        return
    if status in (401, 403):
        first = st.get("deauth_fp") != fp
        _breaker_save({"deauth_fp": fp, "deauth_until": now + _DEAUTH_SECS})
        if first:
            sys.stderr.write("palivane: capture key rejected (revoked or invalid) — standing "
                             "down; re-run `palivane connect` to re-issue.\n")
        return
    fails = int(st.get("fails", 0)) + 1
    if fails >= _FAIL_THRESHOLD:
        st.update(fails=0, cooldown_until=now + _COOLDOWN_SECS)
    else:
        st["fails"] = fails
    _breaker_save(st)


def scan(content: str, destination: str, tool: str = "",
         url: str | None = None, token: str | None = None, timeout: float = 8.0) -> dict:
    """Call the Palivane ai-usage endpoint; fail open (action=allow) on any error. A revoked
    key trips the circuit breaker so we stop hammering the backend on every request."""
    base = (url or os.getenv("PALIVANE_URL", "http://localhost:8090")).rstrip("/")
    tok = token if token is not None else os.getenv("PALIVANE_TOKEN", "")
    skip = _breaker_skip(tok)
    if skip:
        return {"action": "allow", "reason": f"scan-skipped:{skip}"}
    try:
        req = urllib.request.Request(
            base + "/api/ingest/ai-usage", method="POST",
            data=json.dumps({"content": content, "destination": destination, "tool": tool,
                             "user": os.getenv("PALIVANE_PROXY_USER", "")}).encode(),
            headers={"content-type": "application/json", "User-Agent": f"palivane-proxy/{VERSION}", "X-Palivane-Token": tok},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out = json.loads(r.read())
        _breaker_record(tok, 200)
        return out
    except urllib.error.HTTPError as e:
        _breaker_record(tok, e.code)
        return {"action": "allow", "reason": f"scan-failed:{e.code}"}
    except Exception:
        _breaker_record(tok, None)
        return {"action": "allow", "reason": "scan-failed"}


def should_block(verdict: dict, enforce: bool) -> bool:
    # A confirmed secret/PII leak (force_block) is hard-blocked even in monitor mode —
    # "block the certain, monitor the fuzzy". Everything else blocks under enforce —
    # the local PALIVANE_PROXY_ENFORCE, or the org's console stance (Settings →
    # Enforcement) returned on every verdict, so the console governs deployed proxies live.
    if verdict.get("force_block"):
        return True
    return (enforce or bool(verdict.get("enforce"))) and verdict.get("action") == "block"


# --- MCP inspection (agentic tool-use) -----------------------------------------------
# MCP is JSON-RPC 2.0. Remote/Streamable-HTTP servers flow through this proxy, so we can
# inspect and block them agentlessly. Local stdio servers never touch the network — those
# are governed by policy (the allowlist) and surfaced via the tool definitions the agent
# sends to the LLM API (extract_tool_defs), which we *can* see here.

_MCP_INSPECT_METHODS = ("tools/call", "resources/read", "initialize")


def is_mcp(body: bytes | str) -> bool:
    """Cheap content sniff: a JSON-RPC 2.0 message (MCP rides JSON-RPC)."""
    if isinstance(body, bytes):
        body = body[:400].decode("utf-8", "replace")
    head = body[:400]
    return '"jsonrpc"' in head and ('"method"' in head or '"result"' in head)


def _json_objects(body: str) -> list:
    """Parse JSON from a body that's raw JSON *or* SSE (Streamable-HTTP `data:` frames)."""
    body = body.strip()
    if body[:1] in ("{", "["):
        try:
            return [json.loads(body)]
        except (ValueError, TypeError):
            return []
    objs = []
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[5:].strip()
            if payload and payload != "[DONE]":
                try:
                    objs.append(json.loads(payload))
                except (ValueError, TypeError):
                    pass
    return objs


def extract_mcp_activity(body: bytes | str) -> dict | None:
    """Normalize an MCP JSON-RPC request/response into a scannable activity dict.

    Recognizes tool calls, resource reads, the initialize handshake (request), and the
    tools/list result (response, where tool-poisoning lives). Returns None for anything
    that isn't an inspectable MCP message."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    for j in _json_objects(body):
        if not isinstance(j, dict):
            continue
        method = j.get("method", "")
        params = j.get("params") if isinstance(j.get("params"), dict) else {}
        if method == "tools/call":
            harvested: list[str] = []
            _harvest_strings(params.get("arguments", {}), harvested)
            return {"method": method, "tool": params.get("name", ""),
                    "args_text": "\n".join(harvested)[:20000]}
        if method == "resources/read":
            return {"method": method, "resource": str(params.get("uri", ""))}
        if method == "initialize":
            return {"method": method}
        result = j.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            descs = [t.get("description", "") for t in result["tools"]
                     if isinstance(t, dict) and t.get("description")]
            if descs:
                return {"method": "tools/list.result", "tool_descriptions": descs}
    return None


def extract_tool_defs(body: bytes | str) -> list[dict]:
    """Pull advertised tool definitions from an LLM API request (Anthropic/OpenAI `tools`).

    An agent using *local* MCP servers still sends those tools' definitions to the model —
    so this is the agentless handle on local MCP: we can vet the tool descriptions for
    poisoning even though the stdio traffic never hits the network."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    try:
        j = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(j, dict) or not isinstance(j.get("tools"), list):
        return []
    out = []
    for t in j["tools"]:
        if not isinstance(t, dict):
            continue
        if isinstance(t.get("description"), str):                     # Anthropic shape
            out.append({"name": t.get("name", ""), "description": t["description"]})
        fn = t.get("function")                                        # OpenAI shape
        if isinstance(fn, dict) and isinstance(fn.get("description"), str):
            out.append({"name": fn.get("name", ""), "description": fn["description"]})
    return out


def extract_agentic(body: bytes | str) -> dict | None:
    """Extract current-turn agentic tool activity from an LLM API request body
    (OpenAI/Anthropic): the latest tool_use (name + args) and its tool_result output.

    This is the agentless handle on an agent's *behavior* — the tool it's running and the
    data coming back — even for local stdio MCP, because it all round-trips the model.
    Returns an mcp-activity dict (transport=via-llm-api) or None."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    try:
        j = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(j, dict):
        return None
    messages = j.get("messages") or []
    tool_name, args_parts, result_parts = "", [], []
    for m in reversed(messages):
        if not isinstance(m, dict) or m.get("role") != "assistant":
            continue
        content = m.get("content")
        if isinstance(content, list):
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    tool_name = tool_name or b.get("name", "")
                    _harvest_strings(b.get("input", {}), args_parts)
        for tc in m.get("tool_calls") or []:
            fn = tc.get("function") if isinstance(tc, dict) else None
            if isinstance(fn, dict):
                tool_name = tool_name or fn.get("name", "")
                if isinstance(fn.get("arguments"), str):
                    args_parts.append(fn["arguments"])
        if tool_name or args_parts:
            break
    for m in reversed(messages):
        if not isinstance(m, dict):
            continue
        if m.get("role") == "tool":
            if isinstance(m.get("content"), str):
                result_parts.append(m["content"])
            break
        content = m.get("content")
        if isinstance(content, list):
            trs = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"]
            if trs:
                for b in trs:
                    rc = b.get("content")
                    if isinstance(rc, str):
                        result_parts.append(rc)
                    elif isinstance(rc, list):
                        result_parts.extend(x.get("text", "") for x in rc if isinstance(x, dict))
                break
    if not (tool_name or args_parts or result_parts):
        return None
    return {"method": "tools/call" if (tool_name or args_parts) else "tool_result",
            "tool": tool_name,
            "args_text": ("\n".join(args_parts) + "\n" + "\n".join(result_parts))[:20000]}


# --- EMA ID-JAG issuance audit (enterprise-managed authorization) ---------------------
# Under EMA (MCP 2026-07-28 / SEP-990; Okta "Cross App Access") the client swaps its SSO
# assertion at the IdP for an ID-JAG — a per-server, ~5-min JWT grant (RFC 8693 token
# exchange, requested_token_type …:id-jag) — then redeems it at the MCP server's AS
# (RFC 7523 jwt-bearer) for the actual access token. The IdP logs issuance in its own
# console; nothing standardized logs it as part of the *session*. When those token
# endpoints route through this proxy (their hosts added via PALIVANE_PROXY_INTERCEPT_EXTRA),
# we record audience/resource/scope of each leg as session events. Audit-only — the IdP is
# the connection PDP; we never block this leg.

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag"
ID_JAG_TYP = "oauth-id-jag+jwt"


def _jwt_segment(token: str, index: int) -> dict:
    """Unverified decode of one compact-JWS segment (0=header, 1=payload); {} on failure.
    Metadata extraction only — nothing here verifies a signature or trusts a claim."""
    import base64
    try:
        seg = token.split(".")[index]
        seg += "=" * (-len(seg) % 4)
        out = json.loads(base64.urlsafe_b64decode(seg))
        return out if isinstance(out, dict) else {}
    except Exception:
        return {}


def extract_token_exchange(body: bytes | str) -> dict | None:
    """Detect an EMA ID-JAG leg in a form-encoded OAuth token-endpoint POST.

    Recognizes:
      - client -> IdP:    RFC 8693 token exchange requesting an ID-JAG
                          (grant_type=…token-exchange, requested_token_type=…id-jag)
                          -> method "auth/id-jag.issuance"
      - client -> MCP AS: RFC 7523 redemption whose assertion is an ID-JAG
                          (grant_type=…jwt-bearer, assertion header typ oauth-id-jag+jwt)
                          -> method "auth/id-jag.redemption"

    Returns an mcp-activity dict whose args_text carries audience/resource/scope (never
    the assertion/token material itself), or None for anything else."""
    from urllib.parse import parse_qs
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    if not body or body.lstrip()[:1] in ("{", "["):    # token endpoints are form-encoded
        return None
    if "grant_type=" not in body:
        return None
    try:
        form = {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items() if v}
    except Exception:
        return None
    grant = form.get("grant_type", "")
    fields: list[str] = []

    def _put(name: str, value: str) -> None:
        if value:
            fields.append(f"{name}={value}")

    if grant == TOKEN_EXCHANGE_GRANT and form.get("requested_token_type") == ID_JAG_TOKEN_TYPE:
        _put("audience", form.get("audience", ""))
        _put("resource", form.get("resource", ""))
        _put("scope", form.get("scope", ""))
        _put("requested_token_type", form.get("requested_token_type", ""))
        _put("client_id", form.get("client_id", ""))
        return {"method": "auth/id-jag.issuance", "args_text": "\n".join(fields)}

    if grant == JWT_BEARER_GRANT:
        assertion = form.get("assertion", "")
        header = _jwt_segment(assertion, 0)
        if str(header.get("typ") or "").lower() != ID_JAG_TYP:
            return None                          # ordinary jwt-bearer, not an EMA artifact
        claims = _jwt_segment(assertion, 1)      # unverified — audit metadata only
        aud = claims.get("aud")
        _put("audience", " ".join(aud) if isinstance(aud, list) else str(aud or ""))
        _put("resource", str(claims.get("resource") or ""))
        _put("scope", form.get("scope", "") or str(claims.get("scope") or ""))
        _put("subject", str(claims.get("sub") or ""))
        _put("issuer", str(claims.get("iss") or ""))
        return {"method": "auth/id-jag.redemption", "args_text": "\n".join(fields)}

    return None


def bearer_token(header_value: str) -> str:
    """The credential part of an `Authorization: Bearer …` header, else ''."""
    scheme, _, tok = (header_value or "").strip().partition(" ")
    return tok.strip() if scheme.lower() == "bearer" else ""


def scan_mcp(activity: dict, server: str = "", transport: str = "http",
             url: str | None = None, token: str | None = None, timeout: float = 8.0,
             authorization: str = "") -> dict:
    """Call the Palivane MCP ingest endpoint; fail open (action=allow) on any error.

    `authorization` is the Bearer credential the intercepted MCP request carried (EMA-
    minted access token / ID-JAG where the tenant runs enterprise-managed authorization).
    The backend inspects it for IdP-governed actor identity; an opaque token is fine —
    it's attributed as opaque-token, never an error."""
    base = (url or os.getenv("PALIVANE_URL", "http://localhost:8090")).rstrip("/")
    tok = token if token is not None else os.getenv("PALIVANE_TOKEN", "")
    skip = _breaker_skip(tok)
    if skip:
        return {"action": "allow", "reason": f"scan-skipped:{skip}"}
    payload = {"server": server, "transport": transport,
               "user": os.getenv("PALIVANE_PROXY_USER", ""), **activity}
    if authorization:
        payload["authorization"] = authorization
    try:
        req = urllib.request.Request(
            base + "/api/ingest/mcp", method="POST",
            data=json.dumps(payload).encode(),
            headers={"content-type": "application/json", "User-Agent": f"palivane-proxy/{VERSION}", "X-Palivane-Token": tok},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out = json.loads(r.read())
        _breaker_record(tok, 200)
        return out
    except urllib.error.HTTPError as e:
        _breaker_record(tok, e.code)
        return {"action": "allow", "reason": f"scan-failed:{e.code}"}
    except Exception:
        _breaker_record(tok, None)
        return {"action": "allow", "reason": "scan-failed"}


def _sig_summary(verdict: dict) -> str:
    return ", ".join(s.get("category", "") for s in verdict.get("signals", [])[:4])


def ai_block_body(verdict: dict) -> bytes:
    return json.dumps({"type": "error", "error": {
        "type": "invalid_request_error",
        "message": f"Blocked by Palivane: sensitive data ({_sig_summary(verdict)}) "
                   f"— risk {verdict.get('risk_score')}/{verdict.get('severity')}. "
                   f"Remove the secret/PII and start a new chat to continue.",
    }}).encode()


def mcp_block_body(verdict: dict) -> bytes:
    """JSON-RPC error envelope so the agent surfaces the block cleanly."""
    return json.dumps({"jsonrpc": "2.0", "id": None, "error": {
        "code": -32001,
        "message": f"Blocked by Palivane: risky MCP activity ({_sig_summary(verdict)}) "
                   f"— risk {verdict.get('risk_score')}/{verdict.get('severity')}.",
    }}).encode()


# --- mitmproxy hook (thin wrapper around the functions above) -------------------------

class PalivaneGuard:
    def __init__(self) -> None:
        self.enforce = os.getenv("PALIVANE_PROXY_ENFORCE", "").lower() in ("1", "true", "yes")

    def running(self) -> None:
        """Scope TLS interception to the hosts we actually inspect. Everything else is
        tunneled opaquely — never decrypted — so cert-pinned apps, tools with their own CA
        bundles, and VPN/ZTNA clients that do their own TLS inspection (Zscaler, Netskope,
        Tailscale-gated services) keep working even with the system proxy pointed at us.
        PALIVANE_PROXY_INTERCEPT_ALL=true restores full interception for orgs that want it;
        PALIVANE_PROXY_INTERCEPT_EXTRA adds hosts (e.g. remote MCP servers) to the list."""
        if os.getenv("PALIVANE_PROXY_INTERCEPT_ALL", "").lower() in ("1", "true", "yes"):
            return
        import logging

        from mitmproxy import ctx  # lazy, like the http import below
        ctx.options.update(allow_hosts=intercept_patterns())
        logging.info("palivane: TLS interception scoped to %d host suffixes (other traffic "
                     "tunnels un-decrypted; PALIVANE_PROXY_INTERCEPT_ALL=true to widen)",
                     len(intercept_hosts()))

    def responseheaders(self, flow) -> None:
        """AI responses are long-lived SSE streams the response() hook never inspects —
        stream them through unbuffered, or clients stall on the buffered body and time
        out (Claude Code retries in a loop). Request-side scanning is unaffected.

        Comet's perplexity_ask SSE response carries the *agent's* steps/answer, so for
        that one endpoint we tee the stream: chunks pass through unbuffered (no stall),
        a capped copy accumulates on the flow, and response() scans it once the stream
        ends. Observe-only by construction — the bytes have already reached the client."""
        if not is_ai_host(flow.request.pretty_host):
            return
        if is_comet_ask(flow.request.pretty_host, flow.request.path):
            buf: list[bytes] = []
            flow.metadata["palivane_comet_sse"] = buf
            size = {"n": 0}

            def tee(chunk: bytes) -> bytes:
                if chunk and size["n"] < _COMET_SSE_CAP:
                    buf.append(chunk)
                    size["n"] += len(chunk)
                return chunk

            flow.response.stream = tee
        else:
            flow.response.stream = True

    async def request(self, flow) -> None:
        # Async so backend scan calls run in a worker thread: a sync hook blocks
        # mitmproxy's whole event loop, so one slow/unreachable Palivane backend froze
        # EVERY proxied connection (clients saw dead sockets and retry-stormed). Async
        # holds only this flow for its verdict; all other traffic keeps moving.
        from mitmproxy import http  # imported lazily so unit tests need no mitmproxy

        req = flow.request
        if req.method != "POST":
            return
        raw = req.raw_content or b""

        # Perplexity Comet (agentic browser): the assistant endpoint has its own body
        # shape, so it gets a dedicated parser. A parse-miss (shape drift, new build)
        # degrades to the harvest fallback with a visible marker — never a crash.
        if is_comet_ask(req.pretty_host, req.path):
            prompt, ok = extract_comet_ask(raw)
            if not ok and raw.strip():
                import logging
                logging.warning("palivane: comet perplexity_ask request did not match the "
                                "expected shape (parse-miss) — harvest fallback; capture the "
                                "body and re-run the self-test (docs/agentic-browser-verification.md)")
                harvested = harvest_prompt(raw)
                prompt = ("[comet parse-miss] " + harvested).strip() if harvested else ""
            if prompt.strip():
                verdict = await asyncio.to_thread(
                    scan, prompt, f"https://{req.pretty_host}{COMET_ASK_PATH}", tool="comet")
                if should_block(verdict, self.enforce):
                    flow.response = http.Response.make(
                        400, ai_block_body(verdict), {"Content-Type": "application/json"})
            return

        if is_ai_host(req.pretty_host):
            # 1) Prompt content scan (shadow-AI / data-loss). extract_prompt returns the
            #    current user turn from a recognized shape; only fall back to harvesting all
            #    strings for hosts we can't parse (never on structured API telemetry).
            prompt = extract_prompt(raw)
            if not prompt.strip() and needs_harvest(req.pretty_host):
                prompt = harvest_prompt(raw)
            if prompt.strip():
                tool = detect_tool(req.headers.get("user-agent", ""))
                verdict = await asyncio.to_thread(
                    scan, prompt, f"https://{req.pretty_host}", tool=tool)
                if should_block(verdict, self.enforce):
                    flow.response = http.Response.make(
                        400, ai_block_body(verdict), {"Content-Type": "application/json"})
                    return
            # 2) Agentic behavior — the tool the agent is running + its result, visible in
            #    the LLM traffic even for local stdio MCP (agentless).
            act = extract_agentic(raw)
            if act:
                va = await asyncio.to_thread(scan_mcp, act, transport="via-llm-api")
                if should_block(va, self.enforce):
                    flow.response = http.Response.make(
                        400, ai_block_body(va), {"Content-Type": "application/json"})
                    return
            # 3) Policy-flag for MCP tools the agent advertises to the model — the
            #    agentless handle on local (stdio) MCP servers we can't otherwise see.
            defs = extract_tool_defs(raw)
            if defs:
                v = await asyncio.to_thread(
                    scan_mcp, {"method": "tools/advertised",
                               "tool_descriptions": [d["description"] for d in defs]},
                    transport="via-llm-api")
                if should_block(v, self.enforce):
                    flow.response = http.Response.make(
                        400, ai_block_body(v), {"Content-Type": "application/json"})
            return

        # 4) MCP over HTTP to any server (remote/Streamable-HTTP) — inspect the call.
        #    The request's Bearer credential rides along so the backend can attribute the
        #    session to the EMA/IdP-governed identity (opaque tokens degrade gracefully).
        if is_mcp(raw):
            activity = extract_mcp_activity(raw)
            if activity:
                verdict = await asyncio.to_thread(
                    scan_mcp, activity, server=req.pretty_host, transport="http",
                    authorization=bearer_token(req.headers.get("authorization", "")))
                if should_block(verdict, self.enforce):
                    flow.response = http.Response.make(
                        200, mcp_block_body(verdict), {"Content-Type": "application/json"})
            return

        # 5) EMA ID-JAG issuance/redemption (client -> IdP / client -> MCP AS token
        #    endpoints) — record audience/resource/scope as a session event. Visible only
        #    when the IdP/AS host is intercepted (PALIVANE_PROXY_INTERCEPT_EXTRA).
        #    Audit-only: the IdP is the connection PDP, so this leg is never blocked.
        tx = extract_token_exchange(raw)
        if tx:
            await asyncio.to_thread(scan_mcp, tx, server=req.pretty_host, transport="http")

    async def response(self, flow) -> None:
        # Comet SSE response: the teed stream (responseheaders) has finished — scan the
        # agent's steps/answer. Observe-only: the bytes were streamed to the client as
        # they arrived, so a block verdict here is recorded, not enforced. A parsed-JSON
        # body with no recognizable text is reported as a parse-miss so shape drift shows
        # up in the console instead of going silent.
        buf = flow.metadata.pop("palivane_comet_sse", None)
        if buf is not None:
            body = b"".join(buf)
            text, ok = extract_comet_sse(body)
            if not ok and body.strip():
                import logging
                logging.warning("palivane: comet perplexity_ask SSE response did not match "
                                "the expected shape (parse-miss) — capture the stream and "
                                "re-run the self-test (docs/agentic-browser-verification.md)")
                harvested = harvest_prompt(body)
                text = ("[comet parse-miss] " + harvested).strip() if harvested else ""
            if text.strip():
                await asyncio.to_thread(
                    scan, text,
                    f"https://{flow.request.pretty_host}{COMET_ASK_PATH}#sse-response",
                    tool="comet")
            return

        # Tool poisoning lives in the server's tools/list *response* — vet it, and in
        # enforce mode replace a poisoned listing so those tools never reach the agent.
        # Async for the same event-loop reason as request() above.
        req, resp = flow.request, flow.response
        if req.method != "POST" or resp is None or is_ai_host(req.pretty_host):
            return
        body = resp.raw_content or b""
        if not is_mcp(body):
            return
        activity = extract_mcp_activity(body)
        if activity and activity.get("method") == "tools/list.result":
            verdict = await asyncio.to_thread(
                scan_mcp, activity, server=req.pretty_host, transport="http")
            if should_block(verdict, self.enforce):
                resp.status_code = 200
                resp.content = mcp_block_body(verdict)
                resp.headers["Content-Type"] = "application/json"

    # --- Comet agent WebSocket (wss://www.perplexity.ai/agent) --------------------------
    # The automation channel the Comet agent drives the browser over (Zenity teardown).
    # Observe-only: we flag the channel opening and scan each text frame's content;
    # in-stream blocking of a WS message is a verification-pass question (mitmproxy can
    # drop frames, but killing an opaque automation protocol mid-session needs testing
    # against a real build before we ship it as enforcement).

    async def websocket_start(self, flow) -> None:
        if not is_comet_agent_ws(flow.request.pretty_host, flow.request.path):
            return
        import logging
        logging.warning("palivane: Comet agent WebSocket opened: wss://%s%s",
                        flow.request.pretty_host, COMET_AGENT_WS_PATH)
        # Record the channel itself as a usage finding — agentic automation is running on
        # this device even if every frame turns out to be binary/opaque.
        await asyncio.to_thread(
            scan, "[comet] agent automation WebSocket channel opened",
            f"wss://{flow.request.pretty_host}{COMET_AGENT_WS_PATH}", tool="comet")

    async def websocket_message(self, flow) -> None:
        if not is_comet_agent_ws(flow.request.pretty_host, flow.request.path):
            return
        msg = flow.websocket.messages[-1]
        text = extract_ws_text(msg.content)
        if not text.strip():
            return  # binary/empty frame — websocket_start already flagged the channel
        await asyncio.to_thread(
            scan, text,
            f"wss://{flow.request.pretty_host}{COMET_AGENT_WS_PATH}", tool="comet")


addons = [PalivaneGuard()]


# --- Offline self-test (no mitmproxy, no backend) ---------------------------------------

def selftest_comet(fixture_dir: str | None = None) -> int:
    """Run the Comet parsers against recorded/synthetic fixture bodies and print
    PASS/FAIL per file. For a field engineer verifying a real capture: export the bodies
    from mitmproxy (request body -> .json, SSE response -> .sse) into a directory and
    point this at it. Exit 0 iff every fixture parses.

        python3 proxy/palivane_addon.py --selftest-comet [fixture-dir]

    Defaults to the synthetic fixtures in proxy/fixtures/comet/ (Zenity-teardown shape).
    """
    d = fixture_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "fixtures", "comet")
    files = sorted(f for f in os.listdir(d) if f.endswith((".json", ".sse")))
    if not files:
        print(f"selftest-comet: no .json/.sse fixtures in {d}")
        return 1
    failures = 0
    for name in files:
        with open(os.path.join(d, name), "rb") as fh:
            body = fh.read()
        if name.endswith(".json"):
            text, ok = extract_comet_ask(body)
            kind = "request (extract_comet_ask)"
        else:
            text, ok = extract_comet_sse(body)
            kind = "SSE response (extract_comet_sse)"
        status = "PASS" if ok and text.strip() else "FAIL (parse-miss)"
        if status != "PASS":
            failures += 1
        excerpt = " | ".join(text.splitlines())[:120]
        print(f"[{status}] {name}: {kind}\n         extracted: {excerpt!r}")
    print(f"selftest-comet: {len(files) - failures}/{len(files)} fixtures parsed")
    return 1 if failures else 0


if __name__ == "__main__":
    if "--selftest-comet" in sys.argv:
        i = sys.argv.index("--selftest-comet")
        arg = sys.argv[i + 1] if len(sys.argv) > i + 1 else None
        sys.exit(selftest_comet(arg))
    print(__doc__)
