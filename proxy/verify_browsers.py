"""Palivane agentic-browser verification collector (mitmproxy companion script).

Runs the normal capture addon (proxy/palivane_addon.py — unchanged) PLUS an evidence
recorder for the macOS/Windows verification pass in
docs/agentic-browser-verification.md. While a field engineer performs the manual
browser actions (Comet assistant prompt, agentic task, ChatGPT desktop prompts, Dia
sidebar session), the recorder classifies what actually crossed the proxy:

  - which AI hosts were seen, and per-host TLS success vs. handshake failure — a
    client handshake failure on an intercepted AI host is the *pinning* signature
    (same signal we measured for Cursor's api2.cursor.sh);
  - Comet: whether perplexity_ask request/SSE-response bodies parsed via the addon's
    own extractors (extract_comet_ask / extract_comet_sse — reused, not duplicated)
    or parse-missed, and whether the /agent WebSocket opened and produced readable
    text frames;
  - ChatGPT desktop: whether chatgpt.com conversation POSTs parsed via extract_prompt;
  - Dia: any *.diabrowser.com (or other non-AI-list) hosts observed, listed for
    catalog follow-up.

On shutdown (Ctrl-C / SIGINT) it writes `verification-report.md` — PASS / PARTIAL /
FAIL / NOT-EXERCISED per runbook check, plus paste-ready rows for the runbook's
Results table — and the raw evidence as `verification-report.json` alongside
(directory: $PALIVANE_VERIFY_DIR, default the current directory).

Run (in place of the bare addon; everything the addon does still happens):

    PALIVANE_URL=https://app.palivane.io PALIVANE_TOKEN=<capture-key> \
    mitmdump -s proxy/verify_browsers.py --listen-port 8081

Honesty note: this automates *evidence capture and classification only* — the browser
actions themselves are manual, and extension/policy-side checks (Comet 1a forced-install,
1b sidecar invisibility) are outside the proxy's view and stay hand-recorded.

The classification logic is plain functions/classes (no mitmproxy import) so it's
unit-tested standalone (backend/tests/test_verify_browsers.py); the mitmproxy hooks are
a thin wrapper — same layout as the addon itself.
"""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import sys
import time

COLLECTOR_VERSION = "1.0.0"

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_addon():
    """Load the real addon from this directory so its extractors are REUSED — the
    collector must classify with the exact parsers under test, never a copy."""
    spec = importlib.util.spec_from_file_location(
        "palivane_addon", os.path.join(_HERE, "palivane_addon.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


pal = _load_addon()

# Check statuses. PARTIAL is the runbook's own "partial pass" (e.g. agent WebSocket
# opened but frames are binary/opaque) and marks composite rows where only some legs ran.
PASS, PARTIAL, FAIL, NOT_EXERCISED = "PASS", "PARTIAL", "FAIL", "NOT-EXERCISED"
_SEVERITY = {NOT_EXERCISED: 0, PASS: 1, PARTIAL: 2, FAIL: 3}

_MAX_ERRORS_PER_HOST = 3
_ERROR_EXCERPT = 200

# The pinning signature the runbook describes: mitmproxy's client-TLS handshake dying
# right after the CONNECT ("Client TLS handshake failed... does not trust the proxy's
# certificate" / "tlsv1 alert unknown ca") — same signal measured for api2.cursor.sh.
PINNING_NOTE = "client TLS handshake failed — pinning signature (cf. Cursor caveat, proxy/README.md)"


def _is_chatgpt_host(host: str) -> bool:
    host = (host or "").lower()
    return any(host == s or host.endswith("." + s)
               for s in ("chatgpt.com", "chat.openai.com"))


def _is_dia_host(host: str) -> bool:
    host = (host or "").lower()
    return host == "diabrowser.com" or host.endswith(".diabrowser.com")


def _platform_name() -> str:
    return {"Darwin": "macOS", "Windows": "Windows"}.get(platform.system(),
                                                         platform.system() or "unknown")


def _cell(text: str) -> str:
    """Sanitize a string for a markdown table cell."""
    return " ".join((text or "").replace("|", "/").split())


class EvidenceCollector:
    """Accumulates proxy-side evidence and classifies the runbook checks.

    Pure stdlib — feed it events (see_connect / tls_* / see_request / ...) from the
    mitmproxy hooks or from a test, then read checks() / render reports."""

    def __init__(self, platform_name: str | None = None, date: str | None = None) -> None:
        self.platform = platform_name or _platform_name()
        self.date = date or time.strftime("%Y-%m-%d")
        self.started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        # host -> {"connects", "requests", "tls_ok", "tls_failed", "errors"}
        self.hosts: dict[str, dict] = {}
        self.comet_ask = {"parsed": 0, "miss": 0}
        self.comet_sse = {"parsed": 0, "miss": 0}
        self.ws = {"opened": 0, "text_frames": 0, "opaque_frames": 0}
        self.chatgpt = {"posts": 0, "parsed": 0}
        self.blocks: dict[str, int] = {}     # host -> enforce blocks observed (bonus signal)

    # --- event intake (called by the mitmproxy hooks, or directly by tests) ------------

    def _host(self, host: str) -> dict:
        host = (host or "").lower() or "(unknown)"
        return self.hosts.setdefault(
            host, {"connects": 0, "requests": 0, "tls_ok": 0, "tls_failed": 0, "errors": []})

    def see_connect(self, host: str) -> None:
        """Any CONNECT through the proxy — fires even for hosts we tunnel un-decrypted,
        which is exactly what the Dia host-discovery session needs."""
        self._host(host)["connects"] += 1

    def tls_established(self, host: str) -> None:
        self._host(host)["tls_ok"] += 1

    def tls_failed(self, host: str, error: str = "") -> None:
        rec = self._host(host)
        rec["tls_failed"] += 1
        err = (error or "").strip()[:_ERROR_EXCERPT]
        if err and err not in rec["errors"] and len(rec["errors"]) < _MAX_ERRORS_PER_HOST:
            rec["errors"].append(err)

    def see_request(self, host: str, path: str, body: bytes | str = b"",
                    method: str = "POST") -> None:
        """One intercepted HTTP request. POST bodies to the Comet ask endpoint and to
        chatgpt.com are classified through the addon's own extractors."""
        self._host(host)["requests"] += 1
        if method != "POST":
            return
        if isinstance(body, str):
            body = body.encode()
        if pal.is_comet_ask(host, path):
            if not body.strip():
                return                      # mirror the addon: empty body is a no-op
            _, ok = pal.extract_comet_ask(body)
            self.comet_ask["parsed" if ok else "miss"] += 1
        elif _is_chatgpt_host(host):
            if not body.strip():
                return
            self.chatgpt["posts"] += 1
            if pal.extract_prompt(body).strip():
                self.chatgpt["parsed"] += 1

    def see_sse_response(self, host: str, path: str, body: bytes | str) -> None:
        """A completed (teed) Comet perplexity_ask SSE response stream."""
        if not pal.is_comet_ask(host, path):
            return
        if isinstance(body, str):
            body = body.encode()
        if not body.strip():
            return
        _, ok = pal.extract_comet_sse(body)
        self.comet_sse["parsed" if ok else "miss"] += 1

    def ws_open(self, host: str, path: str) -> None:
        if pal.is_comet_agent_ws(host, path):
            self.ws["opened"] += 1

    def ws_frame(self, host: str, path: str, payload: bytes | str) -> None:
        if not pal.is_comet_agent_ws(host, path):
            return
        if pal.extract_ws_text(payload).strip():
            self.ws["text_frames"] += 1
        else:
            self.ws["opaque_frames"] += 1

    def saw_block(self, host: str) -> None:
        """An enforce-mode 400 block the addon served (visible when the engineer re-runs
        the ChatGPT enforce leg with PALIVANE_PROXY_ENFORCE=true)."""
        host = (host or "").lower()
        self.blocks[host] = self.blocks.get(host, 0) + 1

    # --- classification -----------------------------------------------------------------

    def _hosts_where(self, pred) -> list[tuple[str, dict]]:
        return [(h, rec) for h, rec in sorted(self.hosts.items()) if pred(h)]

    def _tls_verdict(self, pred, label: str) -> tuple[str, str]:
        """(status, evidence) for TLS interception of hosts matching pred: any client
        handshake failure is the pinning signature; traffic with none is a pass."""
        matched = self._hosts_where(pred)
        failed = [(h, rec) for h, rec in matched if rec["tls_failed"]]
        if failed:
            detail = "; ".join(
                f"{h}: {rec['tls_failed']} failure(s)"
                + (f" ({rec['errors'][0]})" if rec["errors"] else "")
                for h, rec in failed)
            return FAIL, f"{PINNING_NOTE}: {detail}"
        traffic = sum(rec["connects"] + rec["requests"] + rec["tls_ok"] for _, rec in matched)
        if traffic:
            oks = sum(rec["tls_ok"] for _, rec in matched)
            return PASS, (f"{label} traffic observed ({traffic} event(s), {oks} TLS "
                          f"handshake(s) OK), no client handshake failures")
        return NOT_EXERCISED, f"no {label} traffic observed"

    def checks(self) -> dict[str, dict]:
        """Runbook-check id -> {"title", "status", "evidence"} (insertion-ordered)."""
        out: dict[str, dict] = {}

        def put(cid: str, title: str, status: str, evidence: str) -> None:
            out[cid] = {"title": title, "status": status, "evidence": evidence}

        # Comet 1c — request-side parsing.
        parsed, miss = self.comet_ask["parsed"], self.comet_ask["miss"]
        if parsed:
            st, ev = PASS, (f"{parsed} perplexity_ask request body(ies) parsed via "
                            f"extract_comet_ask" + (f"; {miss} parse-miss" if miss else ""))
        elif miss:
            st, ev = FAIL, (f"parse-miss on all {miss} perplexity_ask request body(ies) — "
                            f"shape drift; capture the bodies and run "
                            f"`python3 proxy/palivane_addon.py --selftest-comet <dir>`")
        else:
            st, ev = NOT_EXERCISED, "no perplexity_ask request observed — submit a Comet assistant prompt"
        put("comet_1c_request", "Comet 1c — perplexity_ask request parsed", st, ev)

        # Comet 1c — SSE-response parsing (the agent's streamed steps/answer).
        parsed, miss = self.comet_sse["parsed"], self.comet_sse["miss"]
        if parsed:
            st, ev = PASS, (f"{parsed} SSE response stream(s) parsed via extract_comet_sse"
                            + (f"; {miss} parse-miss" if miss else ""))
        elif miss:
            st, ev = FAIL, (f"parse-miss on all {miss} SSE response stream(s) — shape "
                            f"drift; capture the stream and run the self-test")
        else:
            st, ev = NOT_EXERCISED, "no perplexity_ask SSE response observed"
        put("comet_1c_sse_response", "Comet 1c — perplexity_ask SSE response parsed", st, ev)

        # Comet 1c — pinning signal on the perplexity host.
        st, ev = self._tls_verdict(pal._is_perplexity_host, "perplexity.ai")
        put("comet_1c_pinning", "Comet 1c — TLS interception (pinning check)", st, ev)

        # Comet 1d — agent WebSocket.
        if not self.ws["opened"]:
            st, ev = NOT_EXERCISED, ("no wss://www.perplexity.ai/agent channel observed — "
                                     "give the Comet assistant an agentic task")
        elif self.ws["text_frames"]:
            st, ev = PASS, (f"channel opened ({self.ws['opened']}x); "
                            f"{self.ws['text_frames']} readable text frame(s), "
                            f"{self.ws['opaque_frames']} binary/opaque")
        else:
            st, ev = PARTIAL, (f"channel opened ({self.ws['opened']}x) but "
                               f"{self.ws['opaque_frames']} frame(s) were binary/opaque "
                               f"(or none arrived) — record the framing so a decoder can "
                               f"be scoped (runbook 1d 'partial pass')")
        put("comet_1d_agent_ws", "Comet 1d — agent WebSocket", st, ev)

        # ChatGPT desktop — system proxy + trust store.
        st, ev = self._tls_verdict(_is_chatgpt_host, "chatgpt.com")
        put("chatgpt_proxy_trust", "ChatGPT desktop — system proxy + trust store", st, ev)

        # ChatGPT desktop — conversation parsing. Many chatgpt.com POSTs are telemetry;
        # the check passes if ANY body parsed as a prompt, and fails only when bodies
        # flowed and none did.
        posts, parsed = self.chatgpt["posts"], self.chatgpt["parsed"]
        blocked = sum(n for h, n in self.blocks.items() if _is_chatgpt_host(h))
        if not posts:
            st, ev = NOT_EXERCISED, "no chatgpt.com POST bodies observed"
        elif parsed:
            st, ev = PASS, (f"{parsed} of {posts} POST body(ies) parsed via extract_prompt"
                            + (f"; {blocked} enforce block(s) observed" if blocked else ""))
        else:
            st, ev = FAIL, (f"{posts} POST body(ies) observed, none parsed via "
                            f"extract_prompt — capture the bodies and check which host/"
                            f"mode the app used (may need an AI_HOST_SUFFIXES addition)")
        put("chatgpt_parsing", "ChatGPT desktop — conversation parsing", st, ev)

        # Dia — host discovery (capture only; no parsing until real hosts are confirmed).
        dia = self._hosts_where(_is_dia_host)
        if dia:
            st = PASS
            ev = ("diabrowser.com traffic observed: "
                  + ", ".join(f"{h} ({rec['connects'] + rec['requests']} event(s))"
                              for h, rec in dia)
                  + " — promote/replace the provisional catalog row")
        else:
            st, ev = NOT_EXERCISED, ("no diabrowser.com traffic observed — see the host "
                                     "inventory for other candidate hosts")
        put("dia_host_capture", "Dia — sidebar host capture", st, ev)

        return out

    # --- report rendering -----------------------------------------------------------------

    @staticmethod
    def _combine(statuses: list[str]) -> str:
        """One Results-table verdict from several sub-checks: any FAIL fails the row;
        a mix of exercised/not-exercised (or an explicit partial) is PARTIAL."""
        if all(s == NOT_EXERCISED for s in statuses):
            return NOT_EXERCISED
        if any(s == FAIL for s in statuses):
            return FAIL
        if any(s in (PARTIAL, NOT_EXERCISED) for s in statuses):
            return PARTIAL
        return PASS

    def results_table_rows(self) -> list[str]:
        """Paste-ready rows for the runbook's Results table
        (`| Check | Platform | Date | Result | Notes |`)."""
        checks = self.checks()

        def row(name: str, platform_: str, ids: list[str], extra: str = "") -> str:
            sub = [checks[i] for i in ids]
            status = self._combine([c["status"] for c in sub])
            exercised = [c for c in sub if c["status"] != NOT_EXERCISED]
            parts = [c["evidence"] for c in (exercised or sub)]
            if exercised and len(exercised) < len(sub):
                parts.append("not exercised: " + ", ".join(
                    c["title"] for c in sub if c["status"] == NOT_EXERCISED))
            if extra:
                parts.append(extra)
            return f"| {name} | {platform_} | {self.date} | {status} | {_cell('; '.join(parts))} |"

        blocked = sum(n for h, n in self.blocks.items() if _is_chatgpt_host(h))
        enforce_note = (f"{blocked} enforce block(s) observed" if blocked
                        else "enforce leg not observed — re-run with PALIVANE_PROXY_ENFORCE=true (manual)")
        return [
            row("Comet 1c SSE inspect/pinning", self.platform,
                ["comet_1c_request", "comet_1c_sse_response", "comet_1c_pinning"]),
            row("Comet 1d agent WebSocket", self.platform, ["comet_1d_agent_ws"]),
            row("ChatGPT desktop proxy/trust", self.platform, ["chatgpt_proxy_trust"]),
            row("ChatGPT desktop parsing/enforce", "either", ["chatgpt_parsing"],
                extra=enforce_note),
            row("Dia host capture", self.platform, ["dia_host_capture"]),
        ]

    def to_json(self) -> dict:
        return {
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "started": self.started,
            "collector_version": COLLECTOR_VERSION,
            "addon_version": pal.VERSION,
            "platform": self.platform,
            "date": self.date,
            "checks": self.checks(),
            "results_table_rows": self.results_table_rows(),
            "hosts": self.hosts,
            "comet_ask": self.comet_ask,
            "comet_sse": self.comet_sse,
            "agent_websocket": self.ws,
            "chatgpt": self.chatgpt,
            "enforce_blocks": self.blocks,
        }

    def render_markdown(self) -> str:
        checks = self.checks()
        lines = [
            "# Agentic-browser verification report",
            "",
            f"- Generated: {time.strftime('%Y-%m-%dT%H:%M:%S%z')} by "
            f"`proxy/verify_browsers.py` v{COLLECTOR_VERSION} "
            f"(addon `palivane_addon.py` v{pal.VERSION})",
            f"- Platform: {self.platform}",
            "- Runbook: `docs/agentic-browser-verification.md`",
            "",
            "> **Scope honesty:** this collector automates *evidence capture and",
            "> classification only* — the browser actions (submitting prompts, driving the",
            "> agent, installing policies) were performed manually by the engineer.",
            "> Extension/policy-side checks — Comet 1a (forced-install) and 1b (sidecar",
            "> invisibility) — happen outside the proxy's view and must be recorded by hand.",
            "",
            "## Checks",
            "",
            "| Check id | Runbook check | Status | Evidence |",
            "|---|---|---|---|",
        ]
        for cid, c in checks.items():
            lines.append(f"| `{cid}` | {_cell(c['title'])} | {c['status']} | "
                         f"{_cell(c['evidence'])} |")
        lines += [
            "",
            "## Results-table rows (paste into the runbook's Results table)",
            "",
            "| Check | Platform | Date | Result | Notes |",
            "|---|---|---|---|---|",
            *self.results_table_rows(),
            "",
            "## Host inventory",
            "",
            "Every host that traversed the proxy (CONNECTs fire even for hosts tunneled",
            "un-decrypted, so this doubles as the Dia discovery list).",
            "",
            "| Host | AI-listed | CONNECTs | Requests | TLS ok | TLS failed | Errors |",
            "|---|---|---|---|---|---|---|",
        ]
        for host, rec in sorted(self.hosts.items(),
                                key=lambda kv: -(kv[1]["connects"] + kv[1]["requests"])):
            ai = "yes" if pal.is_ai_host(host) else ("DIA" if _is_dia_host(host) else "no")
            lines.append(f"| {_cell(host)} | {ai} | {rec['connects']} | {rec['requests']} "
                         f"| {rec['tls_ok']} | {rec['tls_failed']} | "
                         f"{_cell('; '.join(rec['errors']))} |")
        if not self.hosts:
            lines.append("| (none observed) |  |  |  |  |  |  |")
        lines += ["", "Raw evidence: `verification-report.json` (same directory).", ""]
        return "\n".join(lines)

    def write_reports(self, out_dir: str) -> tuple[str, str]:
        os.makedirs(out_dir, exist_ok=True)
        md_path = os.path.join(out_dir, "verification-report.md")
        json_path = os.path.join(out_dir, "verification-report.json")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(self.render_markdown())
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(self.to_json(), fh, indent=2, sort_keys=False)
        return md_path, json_path


# --- mitmproxy hooks (thin wrapper; classification lives above) -------------------------

def _tls_host(data) -> str:
    """Destination host of a client-TLS event: the ClientHello SNI, else the upstream
    address from the connection context."""
    host = getattr(getattr(data, "conn", None), "sni", None)
    if not host:
        addr = getattr(getattr(getattr(data, "context", None), "server", None), "address", None)
        if addr:
            host = addr[0]
    return (host or "").lower()


def _tls_error(data) -> str:
    return str(getattr(getattr(data, "conn", None), "error", None) or "")


class VerificationRecorder:
    """Sits AFTER PalivaneGuard in the addon chain: the guard scans/tees as always, the
    recorder observes the same flows and files evidence. Order matters — the recorder's
    responseheaders aliases the guard's Comet SSE tee buffer (created first), and its
    request hook sees any block response the guard already staged."""

    def __init__(self, collector: EvidenceCollector | None = None,
                 out_dir: str | None = None) -> None:
        self.c = collector or EvidenceCollector()
        self.out_dir = out_dir or os.getenv("PALIVANE_VERIFY_DIR") or os.getcwd()

    def running(self) -> None:
        import logging
        logging.info("palivane-verify: evidence collector armed — perform the runbook's "
                     "browser actions, then Ctrl-C; reports land in %s", self.out_dir)

    def http_connect(self, flow) -> None:
        self.c.see_connect(flow.request.pretty_host)

    def tls_established_client(self, data) -> None:
        self.c.tls_established(_tls_host(data))

    def tls_failed_client(self, data) -> None:
        self.c.tls_failed(_tls_host(data), _tls_error(data))

    def request(self, flow) -> None:
        req = flow.request
        self.c.see_request(req.pretty_host, req.path, req.raw_content or b"",
                           method=req.method)
        # The guard (earlier in the chain) may have staged an enforce-mode block —
        # record it, and don't mis-classify the block body as a failed SSE parse.
        resp = flow.response
        if resp is not None and resp.status_code == 400 \
                and b"Blocked by Palivane" in (resp.raw_content or b""):
            self.c.saw_block(req.pretty_host)
            flow.metadata["palivane_verify_blocked"] = True

    def responseheaders(self, flow) -> None:
        # Alias the guard's Comet SSE tee buffer under our own key: the guard pops ITS
        # key in response(), but the shared list stays readable through ours.
        buf = flow.metadata.get("palivane_comet_sse")
        if buf is not None:
            flow.metadata["palivane_verify_sse"] = buf

    def response(self, flow) -> None:
        buf = flow.metadata.pop("palivane_verify_sse", None)
        if buf is None or flow.metadata.pop("palivane_verify_blocked", False):
            return
        self.c.see_sse_response(flow.request.pretty_host, flow.request.path,
                                b"".join(buf))

    def websocket_start(self, flow) -> None:
        self.c.ws_open(flow.request.pretty_host, flow.request.path)

    def websocket_message(self, flow) -> None:
        msg = flow.websocket.messages[-1]
        self.c.ws_frame(flow.request.pretty_host, flow.request.path, msg.content)

    def done(self) -> None:
        md_path, json_path = self.c.write_reports(self.out_dir)
        sys.stderr.write(f"palivane-verify: wrote {md_path} and {json_path}\n")


# Guard first (unchanged behavior: scoped interception, scanning, the Comet SSE tee),
# recorder second (evidence only, no network) — see VerificationRecorder docstring.
addons = [pal.PalivaneGuard(), VerificationRecorder()]


if __name__ == "__main__":
    print(__doc__)
