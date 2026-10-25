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
import math
import os
import re
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

# Outbound destinations we inspect (suffix match on the request host).

# Reported in the User-Agent so the console can inventory client builds per device.
VERSION = "1.4.7"
AI_HOST_SUFFIXES = (
    # chatgpt.com also covers the ChatGPT *desktop app* (Atlas's successor, with the
    # built-in browser): its Chat/Work/Codex modes all talk to the chatgpt.com backend,
    # so the suffix match sweeps in every subdomain the desktop app uses.
    "api.openai.com", "chatgpt.com", "chat.openai.com",
    "api.anthropic.com", "claude.ai",
    # Claude in Chrome: Anthropic lists its chat traffic as claude.ai, api.anthropic.com and
    # platform.claude.com (the Claude in Chrome admin controls article). The extension runs
    # in Chrome's own network stack, so the system proxy sees it like any page.
    "platform.claude.com",
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
    # AI sidebar browser extensions that send prompts to their own backend, not to the
    # model vendors above (read from each extension's shipped code, 2026-10-23). Only
    # their chat endpoints are scanned: see SIDEBAR_PROMPT_PATHS.
    "api.monica.im", "sider.ai", "www.getmerlin.in", "api.harpa.ai", "api.maxai.me",
)

# For the AI sidebar extension hosts: the request paths that carry a prompt. Their bodies
# are proprietary, so a scanned request is harvested, and these hosts also carry the
# extension's analytics (event.sider.ai), sync and, for www.getmerlin.in, a marketing
# site. Harvesting all of that turns every id and token into a finding, so anything off
# these paths is let through unscanned. Matched as substrings of the path.
SIDEBAR_PROMPT_PATHS = {
    "api.monica.im": ("/custom_bot/chat", "/custom_bot/preview_chat", "/agent_v1/"),
    "sider.ai": ("/chat/v1/completions",),
    "www.getmerlin.in": ("/arcane/api/v2/extension/",),
    "api.harpa.ai": ("/ai/ask",),
    "api.maxai.me": ("/gpt/",),
}


def sidebar_skip(host: str, path: str) -> bool:
    """True for a request to an AI sidebar extension's host that is not one of its prompt
    endpoints: decrypted (the host is on the list) but not scanned."""
    host = (host or "").lower()
    for suffix, paths in SIDEBAR_PROMPT_PATHS.items():
        if host == suffix or host.endswith("." + suffix):
            p = (path or "").split("?", 1)[0]
            return not any(x in p for x in paths)
    return False

_ACTION_RANK = {"benign": 0, "low": 1, "suspicious": 2, "high": 3, "critical": 4}

# --- TLS-inspecting VPN/ZTNA diagnosis ------------------------------------------------
#
# When something terminates TLS between us and the AI host, our *upstream* handshake fails:
# mitmproxy verifies against the public roots, which never contain a Zero-Trust vendor's
# private root. The visible symptom is every AI tool on the device dying with an opaque
# "certificate verify failed", which reads like Palivane broke the network. It didn't — the
# fix is to trust that vendor's root on the upstream leg (PALIVANE_UPSTREAM_CA) or to exempt
# the AI hosts from their inspection. Naming the vendor turns a support ticket into a
# one-line config change, so map the issuer strings we can recognize.
ZTNA_CA_VENDORS = (
    ("cloudflare", "Cloudflare WARP / Zero Trust Gateway"),
    ("zscaler", "Zscaler"),
    ("netskope", "Netskope"),
    ("palo alto", "Palo Alto Prisma Access"),
    ("prisma", "Palo Alto Prisma Access"),
    ("umbrella", "Cisco Umbrella"),
    ("opendns", "Cisco Umbrella"),
    ("forcepoint", "Forcepoint"),
    ("fortinet", "Fortinet / FortiGate"),
    ("fortigate", "Fortinet / FortiGate"),
    ("sophos", "Sophos"),
    ("mcafee", "Skyhigh / McAfee Web Gateway"),
    ("skyhigh", "Skyhigh / McAfee Web Gateway"),
    ("bluecoat", "Broadcom / Symantec (Blue Coat)"),
    ("blue coat", "Broadcom / Symantec (Blue Coat)"),
    ("broadcom", "Broadcom / Symantec (Blue Coat)"),
    ("menlo", "Menlo Security"),
    ("iboss", "iboss"),
    ("check point", "Check Point"),
    ("barracuda", "Barracuda"),
)

# OpenSSL/mitmproxy phrasings for "I don't trust the cert the peer presented".
_VERIFY_FAIL_MARKERS = (
    "certificate verify failed", "unable to get local issuer",
    "self signed certificate", "self-signed certificate",
    "certificate is not trusted", "unknown ca",
)


def ztna_vendor(text: str) -> str | None:
    """The ZTNA/SWG vendor named anywhere in `text` (a cert issuer, subject, or error
    string), or None. Substring match on purpose: issuer DNs vary by version and tenant
    ("Cloudflare for Teams ECC Certificate Authority", "Zscaler Root CA")."""
    low = (text or "").lower()
    for needle, label in ZTNA_CA_VENDORS:
        if needle in low:
            return label
    return None


def upstream_tls_hint(host: str, error: str,
                      issuers: tuple[str, ...] | list[str] = ()) -> str | None:
    """Actionable one-liner for an upstream TLS failure, or None if this isn't a trust
    problem we can explain (a genuine network error, an expired cert, a real MITM).

    Kept pure so it is unit-testable without mitmproxy: the hook below just feeds it what
    it scraped off the failed connection.
    """
    if not is_ai_host(host):
        return None
    err = error or ""
    if not any(m in err.lower() for m in _VERIFY_FAIL_MARKERS):
        return None
    vendor = ztna_vendor(" ".join(issuers)) or ztna_vendor(err)
    who = vendor or "a TLS-inspecting proxy or VPN/ZTNA client"
    return (
        f"palivane: upstream TLS to {host} failed certificate verification — {who} appears "
        f"to be inspecting this connection, and its private root is not in the public trust "
        f"store. AI tools on this device will fail until this is resolved. Fix EITHER side: "
        f"(a) exempt the AI hosts from that product's TLS inspection (a Cloudflare Gateway "
        f'"Do Not Inspect" rule, a Zscaler/Netskope SSL-bypass entry), or (b) trust its root '
        f"on our upstream leg: PALIVANE_UPSTREAM_CA=/path/to/their-root.pem, then reinstall "
        f"with palivane-desktop install. Underlying error: {err.strip()[:200]}"
    )


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
    # claude.ai is a chat UI, but its send is a KNOWN shape, so it is parsed rather than
    # harvested: {"prompt": …} on the old /completion route, and since autumn 2026 a protobuf
    # PerformAction RPC (see claude_rpc_text below). Harvesting it was harmless only while the body arrived
    # gzipped and matched nothing; once decoding was fixed, "every string value" meant the
    # 57KB envelope — conversation UUIDs, a device id, a sessionKey, sha256 file hashes —
    # and the entropy detector made a separate "secret" finding out of each one. One prompt,
    # four findings, none of them the user's data.
    "claude.ai",
    # Anthropic's own API shape; never harvested, for the same reason as api.anthropic.com.
    "platform.claude.com",
    "generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com",
    "aiplatform.googleapis.com", "api.cohere.ai", "api.mistral.ai", "api.perplexity.ai",
    "githubcopilot.com", "copilot-proxy.githubusercontent.com",
)


# Endpoint paths that carry a user prompt, for the structured hosts. Used only to decide
# whether an unparseable body deserves a warning — a telemetry or sync POST parsing to
# nothing is normal and must stay quiet, or the log becomes noise nobody reads.
_PROMPT_PATHS = ("/completion", "/messages", "/chat/completions", "/generateContent")


def _carries_a_prompt(path: str) -> bool:
    p = (path or "").split("?", 1)[0]
    return any(p.endswith(s) or s in p for s in _PROMPT_PATHS)


# A request the proxy decrypted but neither parsed nor harvested passes unscanned, and the
# failure is silent: Claude in Chrome's side panel sent prompts for weeks in a shape nothing
# parsed (fixed in 1.4.4), and only a live test showed it. This flags the next one. It looks
# for an actual sentence (3+ words) under a key a prompt lives in, outside the paths that are
# known telemetry, and counts it as "unparsed-prompt" in the fail-open ledger Fleet shows.
_TEXTY_KEYS = frozenset({"content", "text", "prompt", "message", "query", "input", "question"})
_TELEMETRY_PATH_PARTS = ("event_logging", "/rum", "metrics", "telemetry", "/log", "analytics",
                         "/track", "/ping", "/heartbeat", "safety_flags", "reflections")


def looks_like_typed_text(body: bytes | str, path: str = "") -> bool:
    """True when an unparsed body carries what reads like something a person typed."""
    p = _path_only(path).lower()
    if any(part in p for part in _TELEMETRY_PATH_PARTS):
        return False
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    try:
        j = json.loads(body)
    except (ValueError, TypeError):
        return False
    stack, seen = [j], 0
    while stack and seen < 5000:
        node = stack.pop()
        seen += 1
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str) and k.lower() in _TEXTY_KEYS \
                        and len(v) >= 12 and len(v.split()) >= 3:
                    return True
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(node, list):
            stack.extend(x for x in node if isinstance(x, (dict, list)))
    return False


_UNPARSED_WARNED: dict[str, float] = {}


def note_unparsed_prompt(host: str, path: str) -> None:
    """Count one unparsed prompt-like request for Fleet, and say so in the log at most once
    an hour per host and path shape (ids collapsed), never with any of the content."""
    record_scan_failure("unparsed-prompt")
    shape = re.sub(r"/[0-9a-zA-Z_-]{16,}(?=/|$)", "/<id>", _path_only(path))[:120]
    key, now = f"{host}{shape}", time.time()
    if now - _UNPARSED_WARNED.get(key, 0) > 3600:
        _UNPARSED_WARNED[key] = now
        import logging
        logging.warning("palivane: %s%s carried what looks like a typed prompt in a shape the "
                        "proxy does not parse — this request was NOT scanned (counted for Fleet "
                        "as unparsed-prompt).", host, shape)


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


# --- claude.ai's current send: a Connect RPC with a protobuf body ----------------------------
# claude.ai no longer posts {"prompt": …} to /completion. A message is
#   POST /claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/PerformAction
# with a protobuf body: the typed text is one string among conversation/message/session uuids, a
# locale and a timezone. The same service carries state calls with no text (StreamTimeline,
# ReportViewing, GetNewConversationDefaults, small PerformActions), and the page posts its own
# Datadog telemetry to the same host as compressed blobs. extract_prompt treats any non-JSON body as
# raw text, so all of that was scanned as garbage: the message was found, but every uuid and every
# telemetry blob became a "possible secret". The message is decoded as protobuf and every string that
# is not an id is the text (no field number assumed: the schema is v1alpha). Mirrors the browser
# extension's decoder (extension/injected.js protoPrompt) so both planes agree.
_CLAUDE_RPC_PREFIX = "/claudeai-rpc/"
_OPAQUE_ID = [
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),   # uuid
    re.compile(r"^sess_[0-9a-f]+$", re.I),                                                # session id
    re.compile(r"^\d{9,}-\d+$"),                                                          # timeline cursor
    re.compile(r"^[a-z]{2,3}(-[A-Za-z]{2,4})?$"),                                         # locale
    re.compile(r"^[A-Z][A-Za-z]+(/[A-Z][A-Za-z_]+)+$"),                                    # timezone
]
_CTRL_RE = re.compile(r"[\x00-\x08\x0e-\x1f]")


def is_claude_rpc(host: str, path: str) -> bool:
    return (host or "").lower().endswith("claude.ai") and (path or "").startswith(_CLAUDE_RPC_PREFIX)


# Cloud agent sessions on claude.ai: Claude in Chrome's side panel (and Claude Code on the
# web) send the user's message as a session event, not a chat completion:
#   POST claude.ai/v1/code/sessions/<id>/events
#   {"events": [{"payload": {"type": "user", "message": {"role": "user", "content": …}}},
#               {"payload": {"type": "control_request", …}}, …]}
# Seen from Chrome 2026-10-23 (origin https://claude.ai, platform web_claude_ai). The proxy
# parsed none of it, and claude.ai is never harvested, so the prompt went out unscanned.
_CODE_SESSION_EVENTS_RE = re.compile(r"^/v1/code/sessions/[^/]+/events$")


def is_code_session_events(host: str, path: str) -> bool:
    h = (host or "").lower()
    return (h == "claude.ai" or h.endswith(".claude.ai")) and \
        bool(_CODE_SESSION_EVENTS_RE.match(_path_only(path)))


def code_session_user_text(body: bytes | str) -> str | None:
    """The typed text of the `user` events in a session-events POST: string content, or the
    `text` blocks of block content. Tool results (page text, command output the agent's
    tools produced) are skipped, as on every other plane in v1. None when the body is not
    the expected shape, so the caller can say so instead of passing it silently."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    try:
        j = json.loads(body)
    except (ValueError, TypeError):
        return None
    events = j.get("events") if isinstance(j, dict) else None
    if not isinstance(events, list):
        return None
    parts: list[str] = []
    for ev in events:
        payload = ev.get("payload") if isinstance(ev, dict) else None
        if not isinstance(payload, dict) or payload.get("type") != "user":
            continue
        msg = payload.get("message")
        if not isinstance(msg, dict) or msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts.extend(b.get("text") or "" for b in content
                         if isinstance(b, dict) and b.get("type") == "text")
    return "\n".join(p for p in parts if p.strip())


def _what_matched(verdict: dict, limit: int = 3) -> str:
    """The strongest signals' masked evidence ("SSN", "AWS access key id"), else their
    category. A format-less token's 10-character prefix is cut to 4, as in palivane-hook."""
    def strength(s: dict) -> float:
        try:
            return float(s.get("weight", 0) or 0) * float(s.get("confidence", 1) or 0)
        except (TypeError, ValueError):
            return 0.0
    out: list[str] = []
    for sig in sorted((x for x in verdict.get("signals") or [] if isinstance(x, dict)),
                      key=strength, reverse=True):
        parts = [p.strip() for p in str(sig.get("evidence") or "").split(",") if p.strip()]
        what = ", ".join(p[:4] + "…" if p.endswith("…") else p for p in parts)[:80] \
            or str(sig.get("category") or "")
        if what and what not in out:
            out.append(what)
        if len(out) == limit:
            break
    return "; ".join(out) or "sensitive data"


def session_block_notice(verdict: dict) -> str:
    """What replaces a blocked message in a session-events POST. It shows in the transcript
    as the person's own message, so it is written to them, not as an instruction to the
    model; the model reads it and answers in kind, and the panel stays usable."""
    return (f"[Palivane blocked this message before it left your device because it contained "
            f"sensitive data: {_what_matched(verdict)}. It was not sent. Send it again without "
            f"that information.]")


def replace_user_event_text(body: bytes | str, notice: str) -> bytes | None:
    """The session-events body with the typed text of every `user` event replaced by
    `notice`; other events (the session's own setup, sent in the same batch as the first
    message) and non-text blocks are kept as they are. None when there was nothing to
    replace, so the caller falls back to refusing the request."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    try:
        j = json.loads(body)
    except (ValueError, TypeError):
        return None
    changed = False
    for ev in j.get("events") or [] if isinstance(j, dict) else []:
        payload = ev.get("payload") if isinstance(ev, dict) else None
        if not isinstance(payload, dict) or payload.get("type") != "user":
            continue
        msg = payload.get("message")
        if not isinstance(msg, dict) or msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            msg["content"], changed = notice, True
        elif isinstance(content, list) and any(
                isinstance(b, dict) and b.get("type") == "text" for b in content):
            msg["content"] = [{"type": "text", "text": notice}] + [
                b for b in content if not (isinstance(b, dict) and b.get("type") == "text")]
            changed = True
    return json.dumps(j).encode() if changed else None


def is_claude_rpc_send(path: str) -> bool:
    return _path_only(path).endswith("ConversationService/PerformAction")   # …v1alpha.ConversationService


def is_page_telemetry(path: str) -> bool:
    """The page's own analytics (Datadog RUM rides first-party on claude.ai as a compressed blob):
    not something the person typed, and no JSON shape to recognise it by."""
    p = path or ""
    return p.startswith("/api/v2/rum") or "ddsource=browser" in p


def _pb_strings(buf: bytes, depth: int = 0) -> list[str] | None:
    """Every string leaf of a protobuf message, nested messages included; None if it is not one."""
    out: list[str] = []
    i, n = 0, len(buf)

    def varint():
        nonlocal i
        v, shift = 0, 0
        while True:
            if i >= n:
                return None
            b = buf[i]
            i += 1
            v |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                return v
            if shift >= 64:
                return None

    while i < n:
        tag = varint()
        if not tag:
            return None
        wire = tag & 7
        if wire == 0:
            if varint() is None:
                return None
        elif wire in (1, 5):
            i += 8 if wire == 1 else 4
            if i > n:
                return None
        elif wire == 2:
            ln = varint()
            if ln is None or i + ln > n:
                return None
            sub, i = buf[i:i + ln], i + ln
            nested = _pb_strings(sub, depth + 1) if depth < 8 and ln > 1 else None
            if nested:
                out.extend(nested)
                continue
            try:
                t = sub.decode("utf-8")
            except UnicodeDecodeError:
                continue                                  # binary, not text
            if not _CTRL_RE.search(t):
                out.append(t)
        else:
            return None
    return out


def claude_rpc_text(raw: bytes | str) -> str | None:
    """The typed text of a claude.ai PerformAction body: "" when it carries none, None when the
    body is not protobuf (or is a compressed envelope) so the caller can say so and not skip it."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogatepass")
    buf = raw
    if len(raw) > 5 and raw[0] in (0, 1) and int.from_bytes(raw[1:5], "big") == len(raw) - 5:
        if raw[0] == 1:
            return None                                   # compressed Connect envelope
        buf = raw[5:]
    leaves = _pb_strings(buf)
    if leaves is None:
        return None
    if not leaves and buf and sum(32 <= c < 127 or c in (9, 10, 13) for c in buf) >= 0.9 * len(buf):
        return None             # readable text that merely parsed as protobuf: not a message to skip
    return "\n".join(t for t in leaves if t.strip() and not any(r.match(t) for r in _OPAQUE_ID))


def _pb_varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b, v = v & 0x7F, v >> 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _pb_replace(buf: bytes, swap: dict, depth: int = 0) -> bytes | None:
    """`buf` with each length-delimited field whose bytes are a key of `swap` replaced by its
    value, at any depth. Only the fields on the way to a replaced one are re-encoded (new
    lengths); every other byte is copied as it was. None if `buf` is not a message."""
    out = bytearray()
    i, n = 0, len(buf)

    def varint():
        nonlocal i
        v, shift = 0, 0
        while True:
            if i >= n or shift >= 64:
                return None
            b = buf[i]
            i += 1
            v |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                return v

    while i < n:
        start = i
        tag = varint()
        if not tag:
            return None
        wire = tag & 7
        if wire == 0:
            if varint() is None:
                return None
            out += buf[start:i]
        elif wire in (1, 5):
            i += 8 if wire == 1 else 4
            if i > n:
                return None
            out += buf[start:i]
        elif wire == 2:
            tag_end = i
            ln = varint()
            if ln is None or i + ln > n:
                return None
            sub, i = buf[i:i + ln], i + ln
            new = swap.get(sub)
            if new is None and depth < 8 and any(k in sub for k in swap):
                new = _pb_replace(sub, swap, depth + 1)
            if new is None or new == sub:
                out += buf[start:i]
            else:
                out += buf[start:tag_end] + _pb_varint(len(new)) + new
        else:
            return None
    return bytes(out)


def replace_rpc_text(raw: bytes, notice: str) -> bytes | None:
    """A claude.ai PerformAction body with the typed text replaced by `notice`, so a blocked
    send still reaches the conversation (as the notice) and the app shows Claude's answer
    instead of a bare "failed to send". The typed text is the string fields that read like
    something typed (they contain whitespace), else the longest one; ids, locales, a model
    name stay as they are. None when that can't be done safely (a compressed envelope, not
    protobuf, nothing to replace): the caller refuses the request instead."""
    framed = len(raw) > 5 and raw[0] in (0, 1) and int.from_bytes(raw[1:5], "big") == len(raw) - 5
    if framed and raw[0] == 1:
        return None
    buf = raw[5:] if framed else raw
    leaves = _pb_strings(buf)
    if not leaves:
        return None
    typed = [t for t in leaves if t.strip() and not any(r.match(t) for r in _OPAQUE_ID)]
    targets = [t for t in typed if any(c.isspace() for c in t.strip())] or \
        ([max(typed, key=len)] if typed else [])
    if not targets:
        return None
    swap = {targets[0].encode(): notice.encode()}
    for t in targets[1:]:
        swap.setdefault(t.encode(), b"[removed by Palivane]")
    new = _pb_replace(buf, swap)
    if new is None or new == buf:
        return None
    return (raw[:1] + len(new).to_bytes(4, "big") + new) if framed else new


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


# --- deferring to a live local hook ------------------------------------------------------
# A prompt typed into Claude Code is captured twice: by the hook before it leaves, and again
# here when the agent calls the provider. Two findings for one action. The hook sees the
# better artefact (the typed prompt, not the whole payload with the agent's context scaffold),
# so this defers to it — but ONLY while the backend confirms that hook actually reported
# recently. Presence would be a signal the monitored person can delete; liveness is not.
#
# Fails CLOSED: any error, timeout or unreachable backend leaves the set empty and this proxy
# keeps scanning everything. Losing a duplicate is cheap; losing the capture is not.
_HOOKED: dict = {"tools": frozenset(), "at": 0.0}
_HOOKED_TTL = 300.0          # 5 min — deference lags a hook going quiet by at most this


_HOOKED_LOCK = threading.Lock()   # single-flight: one refresh at a time


def _hooked_fresh() -> bool:
    return time.time() - _HOOKED["at"] < _HOOKED_TTL


def hooked_tools() -> frozenset:
    """Tools whose local hook is live for this actor, cached. Empty on any failure.

    Blocking (a urlopen of up to 3s): call it from a worker thread, never from the event
    loop — the async request() hook goes through hooked_tools_async(). While one refresh is
    in flight, other callers get the cached set rather than queueing a duplicate lookup."""
    if _hooked_fresh():
        return _HOOKED["tools"]
    if not _HOOKED_LOCK.acquire(blocking=False):
        return _HOOKED["tools"]            # a refresh is already running: serve the cache
    try:
        if _hooked_fresh():                # refreshed while we raced for the lock
            return _HOOKED["tools"]
        _HOOKED["at"] = time.time()
        base = os.getenv("PALIVANE_URL", "").rstrip("/")
        token = os.getenv("PALIVANE_TOKEN", "")
        if not base or not token:
            _HOOKED["tools"] = frozenset()
            return _HOOKED["tools"]
        try:
            req = urllib.request.Request(f"{base}/api/capture/hooked",
                                         headers={"X-Palivane-Token": token})
            with urllib.request.urlopen(req, timeout=3) as r:
                data = json.loads(r.read() or b"{}")
            _HOOKED["tools"] = frozenset(t for t in (data.get("tools") or []) if t)
        except Exception:
            _HOOKED["tools"] = frozenset()      # fail closed: scan everything
        return _HOOKED["tools"]
    finally:
        _HOOKED_LOCK.release()


async def hooked_tools_async() -> frozenset:
    """hooked_tools() for the event loop: the cache hit is answered inline, a refresh runs
    in a worker thread so a slow backend never stalls every other proxied connection."""
    if _hooked_fresh():
        return _HOOKED["tools"]
    return await asyncio.to_thread(hooked_tools)


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


_BREAKER_LOCK = threading.Lock()   # concurrent flows record from worker threads


def _breaker_load() -> dict:
    try:
        with open(_breaker_path()) as fh:
            st = json.load(fh)
        return st if isinstance(st, dict) else {}
    except Exception:
        return {}


def _breaker_save(state: dict) -> None:
    # A unique temp name per write: concurrent flows (worker threads here, other processes
    # sharing the state dir) used to share one fixed "<path>.tmp" and clobber each other.
    try:
        path = _breaker_path()
        d = os.path.dirname(path)
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".proxy-breaker.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(state, fh)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception:
        pass


def _deadline(v, now: float, cap: float) -> float:
    """A breaker deadline read from the state file, which anything running as this user can
    write. Only a finite positive number no further out than now+cap counts — every deadline
    this code writes is at most `cap` away, so anything beyond it (a hand-written 9e18 that
    would stand the sensor down forever) is tampering or clock skew: treat it as closed."""
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0:
        return 0.0
    return float(v) if v <= now + cap else 0.0


def _breaker_skip(token: str) -> str:
    """Reason to skip the network and fail open, or '' to proceed."""
    st, fp, now = _breaker_load(), _token_fp(token), time.time()
    if st.get("deauth_fp") == fp and now < _deadline(st.get("deauth_until"), now, _DEAUTH_SECS):
        return "deauthorized"
    if now < _deadline(st.get("cooldown_until"), now, _COOLDOWN_SECS):
        return "backoff"
    return ""


def _breaker_record(token: str, status) -> None:
    """status: 200 healthy | 401/403 revoked | None transient error."""
    with _BREAKER_LOCK:
        _breaker_record_locked(token, status)


def _breaker_record_locked(token: str, status) -> None:
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
    prev = st.get("fails")
    fails = (prev if isinstance(prev, int) and not isinstance(prev, bool) and prev > 0 else 0) + 1
    if fails >= _FAIL_THRESHOLD:
        st.update(fails=0, cooldown_until=now + _COOLDOWN_SECS)
    else:
        st["fails"] = fails
    _breaker_save(st)


# --- Scan-failed ledger (SEC-01) --------------------------------------------------------
# Every scan error still fails open: Palivane being unreachable never blocks the user. What
# changed is that a failed scan is no longer folded silently into "allow". Each one is
# counted here (how many, first and last time, a reason from a fixed vocabulary, never any
# content) and the tally rides along on the next request that reaches the backend, which
# adds it to this sensor's heartbeat. The console's Fleet view then says "N scans failed
# open since T, reason X" instead of showing a healthy, quiet sensor. No extra request is
# ever made for it, and the happy path pays one rename that finds no file.
#
# Claim-by-rename keeps concurrent runs from reporting the same tally twice: a sender
# atomically renames the pending file to a private claim and attaches it, then deletes the
# claim once the backend accepted the request or folds it back in when the request failed.
# A claim left behind by a killed process is folded back by the next failure. Counting is a
# read-modify-write under a lock (threads) with an atomic replace (processes), so two
# processes failing at the same instant can drop a count, and a request the backend took but
# never answered is counted again: off by one at the edges, never by an episode. If the
# backend stays unreachable nothing is delivered, and the sensor's
# last-seen ages into the console's stale/dark buckets and the gone-dark alert instead.
# Copied in every hook and the proxy (each is a standalone file); keep the copies identical
# apart from _FAILOPEN_FILE.
_FAILOPEN_FILE = "scan-failed-proxy.json"
_FAILOPEN_REASONS = ("timeout", "network", "server-error", "auth-rejected", "rate-limited",
                     "http-error", "bad-response", "breaker-open", "error", "update-failed",
                     "unparsed-prompt")
_FAILOPEN_MAX = 1000000
_FAILOPEN_ORPHAN_SECS = 120
_FAILOPEN_LOCK = threading.Lock()


def _failopen_path() -> str:
    d = os.path.expanduser(os.getenv("PALIVANE_STATE_DIR", "~/.palivane"))
    return os.path.join(d, _FAILOPEN_FILE)


def failure_reason(exc) -> str:
    """Bucket a failed scan into the fixed reason vocabulary. Never the error's text: that
    can quote a URL or a server message, and the report must carry nothing but counts."""
    if isinstance(exc, str):
        return exc if exc in _FAILOPEN_REASONS else "error"
    if isinstance(exc, urllib.error.HTTPError):
        code = exc.code if isinstance(exc.code, int) else 0
        if code in (401, 403):
            return "auth-rejected"
        if code == 429:
            return "rate-limited"
        return "server-error" if code >= 500 else "http-error"
    if isinstance(exc, (TimeoutError, socket.timeout)) or isinstance(
            getattr(exc, "reason", None), (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, OSError):
        return "network"
    if isinstance(exc, ValueError):
        return "bad-response"
    return "error"


def _failopen_clean(st) -> dict:
    """Only well-formed fields survive: the file is writable by anything running as this
    user, so a known reason with a positive int count, and finite positive timestamps."""
    if not isinstance(st, dict):
        return {}
    reasons = {}
    raw = st.get("reasons")
    if isinstance(raw, dict):
        for k, v in raw.items():
            if k in _FAILOPEN_REASONS and isinstance(v, int) and not isinstance(v, bool) and v > 0:
                reasons[k] = min(v, _FAILOPEN_MAX)
    if not reasons:
        return {}
    out = {"count": min(sum(reasons.values()), _FAILOPEN_MAX), "reasons": reasons}
    for k in ("first", "last"):
        v = st.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v > 0:
            out[k] = int(v)
    return out


def _failopen_merge(a: dict, b: dict) -> dict:
    reasons = dict(a.get("reasons") or {})
    for k, v in (b.get("reasons") or {}).items():
        reasons[k] = reasons.get(k, 0) + v
    firsts = [x["first"] for x in (a, b) if "first" in x]
    lasts = [x["last"] for x in (a, b) if "last" in x]
    return _failopen_clean({"reasons": reasons, "first": min(firsts) if firsts else None,
                            "last": max(lasts) if lasts else None})


def _failopen_read(path: str) -> dict:
    try:
        with open(path) as fh:
            return _failopen_clean(json.load(fh))
    except Exception:
        return {}


def _failopen_write(path: str, st: dict) -> None:
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".scan-failed.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(st, fh)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def record_scan_failure(reason, claim: str = "") -> None:
    """Count one scan that failed open (`reason`: the exception, or a vocabulary word),
    and fold back an undelivered claim plus any claim a killed process left behind. Runs
    only on the failure path. Never raises."""
    try:
        with _FAILOPEN_LOCK:
            path, now = _failopen_path(), int(time.time())
            back = [claim] if claim else []
            d, prefix = os.path.dirname(path), "." + _FAILOPEN_FILE + ".claim."
            try:
                for name in os.listdir(d):
                    p = os.path.join(d, name)
                    if (name.startswith(prefix) and p != claim
                            and time.time() - os.path.getmtime(p) > _FAILOPEN_ORPHAN_SECS):
                        back.append(p)
            except OSError:
                pass
            st = _failopen_read(path)
            for p in back:
                st = _failopen_merge(st, _failopen_read(p))
            st = _failopen_merge(st, {"reasons": {failure_reason(reason): 1},
                                      "first": now, "last": now})
            _failopen_write(path, st)
            for p in back:
                try:
                    os.unlink(p)
                except OSError:
                    pass
    except Exception:
        pass


def claim_scan_failures() -> tuple:
    """Take the pending tally for the request about to be sent: (claim path, report), or
    ("", {}) when nothing is pending, which costs one rename that finds no file. The report
    is counts, reasons and two timestamps; nothing else is ever in it."""
    try:
        path = _failopen_path()
        claim = os.path.join(os.path.dirname(path), "." + _FAILOPEN_FILE + ".claim."
                             + str(os.getpid()) + "." + os.urandom(4).hex())
        os.rename(path, claim)
    except Exception:
        return "", {}
    try:
        os.utime(claim)          # a fresh claim, so the orphan sweep leaves it alone
    except OSError:
        pass
    report = _failopen_read(claim)
    if not report:
        scan_failures_delivered(claim)
        return "", {}
    return claim, report


def scan_failures_delivered(claim: str) -> None:
    """The backend accepted the request that carried this claim: drop it."""
    if claim:
        try:
            os.unlink(claim)
        except OSError:
            pass


def scan(content: str, destination: str, tool: str = "",
         url: str | None = None, token: str | None = None, timeout: float = 8.0) -> dict:
    """Call the Palivane ai-usage endpoint; fail open (action=allow) on any error. A revoked
    key trips the circuit breaker so we stop hammering the backend on every request."""
    base = (url or os.getenv("PALIVANE_URL", "http://localhost:8090")).rstrip("/")
    tok = token if token is not None else os.getenv("PALIVANE_TOKEN", "")
    skip = _breaker_skip(tok)
    if skip:
        record_scan_failure("auth-rejected" if skip == "deauthorized" else "breaker-open")
        return {"action": "allow", "reason": f"scan-skipped:{skip}"}
    body = {"content": content, "destination": destination, "tool": tool,
            "user": os.getenv("PALIVANE_PROXY_USER", "")}
    claim, report = claim_scan_failures()
    if report:
        body["scan_failed"] = report
    try:
        req = urllib.request.Request(
            base + "/api/ingest/ai-usage", method="POST",
            data=json.dumps(body).encode(),
            headers={"content-type": "application/json", "User-Agent": f"palivane-proxy/{VERSION}", "X-Palivane-Token": tok},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        _breaker_record(tok, e.code)
        record_scan_failure(e, claim)
        return {"action": "allow", "reason": f"scan-failed:{e.code}"}
    except Exception as e:
        _breaker_record(tok, None)
        record_scan_failure(e, claim)
        return {"action": "allow", "reason": "scan-failed"}
    scan_failures_delivered(claim)          # the backend took the request, and the tally
    try:
        out = json.loads(raw)
    except Exception as e:
        _breaker_record(tok, None)
        record_scan_failure(e)
        return {"action": "allow", "reason": "scan-failed"}
    _breaker_record(tok, 200)
    return out


def should_block(verdict: dict, enforce: bool) -> bool:
    # A confirmed secret/PII leak (force_block) is hard-blocked even in monitor mode —
    # "block the certain, monitor the fuzzy". Everything else blocks under enforce —
    # the local PALIVANE_PROXY_ENFORCE, or the org's console stance (Settings →
    # Enforcement) returned on every verdict, so the console governs deployed proxies live.
    if verdict.get("force_block"):
        return True
    # A coached verdict is a block the org softened on the assumption that the client shows
    # the cleaned copy (only the extension can). Under enforce it still stops the prompt.
    return (enforce or bool(verdict.get("enforce"))) and (
        verdict.get("action") == "block" or verdict.get("coached") is True)


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
        record_scan_failure("auth-rejected" if skip == "deauthorized" else "breaker-open")
        return {"action": "allow", "reason": f"scan-skipped:{skip}"}
    payload = {"server": server, "transport": transport,
               "user": os.getenv("PALIVANE_PROXY_USER", ""), **activity}
    if authorization:
        payload["authorization"] = authorization
    claim, report = claim_scan_failures()
    if report:
        payload["scan_failed"] = report
    try:
        req = urllib.request.Request(
            base + "/api/ingest/mcp", method="POST",
            data=json.dumps(payload).encode(),
            headers={"content-type": "application/json", "User-Agent": f"palivane-proxy/{VERSION}", "X-Palivane-Token": tok},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        _breaker_record(tok, e.code)
        record_scan_failure(e, claim)
        return {"action": "allow", "reason": f"scan-failed:{e.code}"}
    except Exception as e:
        _breaker_record(tok, None)
        record_scan_failure(e, claim)
        return {"action": "allow", "reason": "scan-failed"}
    scan_failures_delivered(claim)          # the backend took the request, and the tally
    try:
        out = json.loads(raw)
    except Exception as e:
        _breaker_record(tok, None)
        record_scan_failure(e)
        return {"action": "allow", "reason": "scan-failed"}
    _breaker_record(tok, 200)
    return out


def _sig_summary(verdict: dict) -> str:
    return ", ".join(s.get("category", "") for s in verdict.get("signals", [])[:4])


def block_message(verdict: dict) -> str:
    return (f"Blocked by Palivane: sensitive data ({_sig_summary(verdict)}) "
            f"— risk {verdict.get('risk_score')}/{verdict.get('severity')}. "
            f"Remove the secret/PII and start a new chat to continue.")


def ai_block_body(verdict: dict) -> bytes:
    """The Anthropic-API-shaped error, which the provider SDKs read as `error.message`. The
    top-level `message` is for the AI sidebar extensions: Sider and MaxAI show only a top-level
    `message` (Sider showed this body as raw JSON, MaxAI a generic "Something went wrong")."""
    msg = block_message(verdict)
    return json.dumps({"type": "error", "message": msg,
                       "error": {"type": "invalid_request_error", "message": msg}}).encode()


def connect_block_body(verdict: dict) -> bytes:
    """A Connect-protocol error for claude.ai's RPC. A client reads `code`, and permission_denied
    is a final answer, where the Anthropic-API-shaped body above carries no code and was taken for
    a transient failure and retried."""
    return json.dumps({"code": "permission_denied", "message": block_message(verdict)}).encode()


# A client told its send failed may send it again (claude.ai retries on a growing backoff), and each
# retry was scanned, blocked and counted as another sighting of the same finding, for as long as the
# app kept trying. An identical send inside this window of a block is the same stopped send: it gets
# the same answer without another scan. Sliding, so a long backoff stays quiet.
_BLOCK_QUIET_SECS = 30.0


def monica_block_body(verdict: dict) -> bytes:
    """A refusal Monica shows. Its chat stream reads a JSON reply's top-level `code` and shows
    "(code) msg"; with no `code` it shows only "INVALID_MESSAGE_CONTENT", which is what the
    Anthropic-shaped body above got. Its agent_v1 endpoints are Connect, which read `code` and
    `message`, so the body carries both."""
    msg = block_message(verdict)
    return json.dumps({"code": "permission_denied", "msg": msg, "message": msg}).encode()


def merlin_block_body(verdict: dict) -> bytes:
    """A refusal Merlin shows. Its chat call is axios, which turns any non-2xx into "Request failed
    with status code 400" without reading the body (and 401/403 send it to refresh, then sign out;
    5xx is retried). A 200 event stream with an `error` event is shown as its `message`."""
    data = json.dumps({"type": "PALIVANE_BLOCKED", "message": block_message(verdict)})
    return f"event: error\ndata: {data}\n\n".encode()


def harpa_block_body(verdict: dict) -> bytes:
    """A refusal HARPA shows. It prints a failed reply's whole JSON under "ERROR:", pretty-printed
    when it is an object, as-is when it is a string, so the body is the message as a JSON string."""
    return json.dumps(block_message(verdict)).encode()


def _host_is(host: str, domain: str) -> bool:
    host = (host or "").lower()
    return host == domain or host.endswith("." + domain)


def mcp_block_body(verdict: dict) -> bytes:
    """JSON-RPC error envelope so the agent surfaces the block cleanly."""
    return json.dumps({"jsonrpc": "2.0", "id": None, "error": {
        "code": -32001,
        "message": f"Blocked by Palivane: risky MCP activity ({_sig_summary(verdict)}) "
                   f"— risk {verdict.get('risk_score')}/{verdict.get('severity')}.",
    }}).encode()


# --- Loaded marker: which addon build the running proxy actually executes -------------
# palivane-desktop's updater swaps this file in place, and mitmproxy (12.x) re-imports a
# script whose mtime changes within about a second, then calls running() on the new module.
# running() records the sha256 of the file it was loaded from; the updater reads it back to
# confirm the new build is live, restarts the service if it is not, and puts the previous
# file back if even a restart does not load it. Never raises: a marker that cannot be
# written only makes the updater fall back to a restart.
_LOADED_FILE = "proxy-loaded.json"


def _loaded_marker_path() -> str:
    d = os.path.expanduser(os.getenv("PALIVANE_STATE_DIR", "~/.palivane"))
    return os.path.join(d, _LOADED_FILE)


def write_loaded_marker(source: str | None = None) -> None:
    try:
        with open(source or __file__, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        path = _loaded_marker_path()
        d = os.path.dirname(path)
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".proxy-loaded.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump({"version": VERSION, "sha256": digest, "pid": os.getpid(),
                           "at": int(time.time())}, fh)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception:
        pass


# --- mitmproxy hook (thin wrapper around the functions above) -------------------------

class PalivaneGuard:
    def __init__(self) -> None:
        self.enforce = os.getenv("PALIVANE_PROXY_ENFORCE", "").lower() in ("1", "true", "yes")
        self._tls_warned: set[str] = set()   # hosts we've already explained a TLS failure for
        self._recent_blocks: dict[str, tuple[float, dict]] = {}   # send fingerprint -> (until, verdict)

    def running(self) -> None:
        """Scope TLS interception to the hosts we actually inspect. Everything else is
        tunneled opaquely — never decrypted — so cert-pinned apps, tools with their own CA
        bundles, and VPN/ZTNA clients that do their own TLS inspection (Zscaler, Netskope,
        Tailscale-gated services) keep working even with the system proxy pointed at us.
        PALIVANE_PROXY_INTERCEPT_ALL=true restores full interception for orgs that want it;
        PALIVANE_PROXY_INTERCEPT_EXTRA adds hosts (e.g. remote MCP servers) to the list.

        mitmproxy calls this again after it reloads a replaced script, so it is also where
        this build tells the updater it is live (write_loaded_marker)."""
        write_loaded_marker()
        if os.getenv("PALIVANE_PROXY_INTERCEPT_ALL", "").lower() in ("1", "true", "yes"):
            return
        import logging

        from mitmproxy import ctx  # lazy, like the http import below
        ctx.options.update(allow_hosts=intercept_patterns())
        logging.info("palivane: TLS interception scoped to %d host suffixes (other traffic "
                     "tunnels un-decrypted; PALIVANE_PROXY_INTERCEPT_ALL=true to widen)",
                     len(intercept_hosts()))

    def tls_failed_server(self, data) -> None:
        """Upstream handshake failed. If it's a trust failure on a host we inspect, say who
        is intercepting and how to fix it — once per host, so a retry storm doesn't bury the
        message. Diagnostic only: nothing is blocked, retried, or changed here.

        `tls_failed_server` is a mitmproxy >= 9 hook; on anything older it simply never
        fires and we're back to the bare TLS error. Every field access is defensive because
        the hook's data shape has moved between versions and a diagnostic must not be able
        to take the proxy down."""
        import logging

        host = ""
        try:
            host = data.context.server.address[0] or ""
        except Exception:      # hook data shape varies across mitmproxy versions
            pass
        if not host or host in self._tls_warned:
            return
        conn = getattr(data, "conn", None)
        issuers: list[str] = []
        try:
            for cert in (getattr(conn, "certificate_list", None) or ()):
                issuers.append(str(getattr(cert, "issuer", "")))
        except Exception:
            pass
        hint = upstream_tls_hint(host, str(getattr(conn, "error", "") or ""), issuers)
        if hint:
            self._tls_warned.add(host)
            logging.error(hint)

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

    def _refuse(self, flow, http, rpc: bool, verdict: dict) -> None:
        """Stop a prompt. Where the typed text can be swapped out, the request goes through
        with a notice in its place, so the person reads why in the conversation:
        - a cloud agent session's events POST (Claude in Chrome's side panel): the same batch
          carries the session's own setup, and refusing it left the panel stuck;
        - a claude.ai PerformAction send (Claude Desktop, claude.ai): a refusal showed only
          "failed to send".
        Anything that can't be rewritten safely gets the refusal."""
        req = flow.request
        if rpc and is_claude_rpc_send(req.path):
            try:
                body = req.content or b""
            except Exception:
                body = req.raw_content or b""
            rewritten = replace_rpc_text(body, session_block_notice(verdict))
            if rewritten is not None:
                req.content = rewritten
                return
        if is_code_session_events(req.pretty_host, req.path):
            try:
                body = req.content or b""
            except Exception:
                body = req.raw_content or b""
            rewritten = replace_user_event_text(body, session_block_notice(verdict))
            if rewritten is not None:
                req.content = rewritten
                return
        flow.response = self._blocked(http, rpc, verdict, req.pretty_host)

    @staticmethod
    def _blocked(http, rpc: bool, verdict: dict, host: str = ""):
        """The refusal: a Connect error (403, permission_denied) for claude.ai's RPC, which a client
        takes as final; the shape each AI sidebar extension shows for Monica, Merlin and HARPA;
        the Anthropic-API-shaped 400 for everything else (Sider and MaxAI read it too)."""
        if _host_is(host, "monica.im"):
            return http.Response.make(403, monica_block_body(verdict), {"Content-Type": "application/json"})
        if _host_is(host, "getmerlin.in"):
            return http.Response.make(200, merlin_block_body(verdict), {"Content-Type": "text/event-stream"})
        if _host_is(host, "harpa.ai"):
            return http.Response.make(400, harpa_block_body(verdict), {"Content-Type": "application/json"})
        if rpc:
            return http.Response.make(403, connect_block_body(verdict), {"Content-Type": "application/json"})
        return http.Response.make(400, ai_block_body(verdict), {"Content-Type": "application/json"})

    async def request(self, flow) -> None:
        # Async so backend scan calls run in a worker thread: a sync hook blocks
        # mitmproxy's whole event loop, so one slow/unreachable Palivane backend froze
        # EVERY proxied connection (clients saw dead sockets and retry-stormed). Async
        # holds only this flow for its verdict; all other traffic keeps moving.
        from mitmproxy import http  # imported lazily so unit tests need no mitmproxy

        req = flow.request
        if req.method != "POST":
            return
        # `.content`, not `.raw_content`: raw_content is the body EXACTLY as it arrived,
        # still compressed when the client sets content-encoding. Claude Desktop gzips every
        # request (anthropic-client-platform: desktop_app, content-encoding: gzip), so the
        # parsers below received gzip bytes, failed to decode JSON, extracted nothing, and
        # every prompt from the desktop app passed unscanned — a browser sending the same
        # text uncompressed was blocked correctly, which is why this looked like it worked.
        # mitmproxy decodes content-encoding for `.content`; fall back to raw for a body it
        # cannot decode, so a malformed/unknown encoding still gets scanned as bytes rather
        # than silently skipped.
        try:
            raw = req.content or b""
        except Exception:                      # undecodable encoding — scan what we have
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
            # A live local hook already scanned this prompt before it left the machine, and
            # saw the better artefact. Skip ONLY the prompt scan: section 2 below reads the
            # agent's tool USE out of the same request, which is a different exposure and
            # stays covered. An early return here would have silently dropped it.
            if is_page_telemetry(req.path) or sidebar_skip(req.pretty_host, req.path):
                return
            rpc = is_claude_rpc(req.pretty_host, req.path)
            if rpc and not is_claude_rpc_send(req.path):
                return              # claude.ai state calls (timeline, viewing, defaults): no typed text
            ua_tool = detect_tool(req.headers.get("user-agent", ""))
            defer_prompt = bool(ua_tool) and ua_tool in await hooked_tools_async()

            if rpc:
                prompt = ""
                if not defer_prompt:
                    decoded = claude_rpc_text(raw)
                    if decoded is None:
                        import logging
                        logging.warning(
                            "palivane: %s%s was not a readable protobuf (%d bytes) — scanning it as "
                            "text; shape drift or a compressed envelope?",
                            req.pretty_host, req.path[:80], len(raw))
                        decoded = extract_prompt(raw)
                    prompt = decoded
            elif is_code_session_events(req.pretty_host, req.path):
                prompt = ""
                if not defer_prompt:
                    text = code_session_user_text(raw)
                    if text is None and raw.strip():
                        import logging
                        logging.warning(
                            "palivane: %s%s was not the expected session-events shape (%d bytes) "
                            "— this request was NOT scanned.", req.pretty_host, req.path[:80], len(raw))
                    prompt = text or ""
            else:
                prompt = "" if defer_prompt else extract_prompt(raw)
            if rpc:
                pass                # decoded above: no harvest, no drift warning for the RPC
            elif not defer_prompt and not prompt.strip() and needs_harvest(req.pretty_host):
                prompt = harvest_prompt(raw)
            elif not defer_prompt and not prompt.strip() and raw.strip() \
                    and looks_like_typed_text(raw, req.path):
                note_unparsed_prompt(req.pretty_host, req.path)
            elif not defer_prompt and not prompt.strip() and raw.strip() \
                    and _carries_a_prompt(req.path):
                # A structured host whose prompt-carrying endpoint parsed to nothing means the
                # vendor changed shape, and the failure mode is silence: the request sails
                # through unscanned and no finding is ever created to notice. Say so. Not a
                # harvest fallback — that is what produced a "secret" finding per UUID in the
                # envelope — but loud enough that shape drift is discovered by us, not by a
                # customer wondering why their console went quiet.
                import logging
                logging.warning(
                    "palivane: %s%s carried no recognizable prompt (%d bytes) — shape drift? "
                    "This request was NOT scanned.", req.pretty_host, req.path[:80], len(raw))
            if prompt.strip():
                key = hashlib.sha1(f"{req.pretty_host}\0{prompt}".encode("utf-8", "replace")).hexdigest()[:20]
                now = time.time()
                prior = self._recent_blocks.get(key)
                if prior and prior[0] > now:        # a retry of a send already stopped: same answer
                    self._recent_blocks[key] = (now + _BLOCK_QUIET_SECS, prior[1])
                    self._refuse(flow, http, rpc, prior[1])
                    return
                tool = detect_tool(req.headers.get("user-agent", ""))
                verdict = await asyncio.to_thread(
                    scan, prompt, f"https://{req.pretty_host}", tool=tool)
                if should_block(verdict, self.enforce):
                    self._recent_blocks[key] = (now + _BLOCK_QUIET_SECS, verdict)
                    if len(self._recent_blocks) > 100:
                        self._recent_blocks = {k: v for k, v in self._recent_blocks.items() if v[0] > now}
                    self._refuse(flow, http, rpc, verdict)
                    return
            if rpc:
                return              # a chat message: no tool use or tool definitions to read from it
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
        try:
            body = resp.content or b""      # decoded; raw_content is still gzip/br/zstd
        except Exception:
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
