# Palivane egress proxy (desktop / network capture plane)

Catches AI usage the browser extension can't: **desktop apps** (Claude/ChatGPT
desktop), **IDE assistants** (Cursor, GitHub Copilot), **CLIs**, and anything else that
makes its own HTTPS calls to an AI provider. It's a [mitmproxy](https://mitmproxy.org/)
addon that inspects outbound POSTs to AI domains, scores the prompt through Palivane,
records a finding, and blocks (HTTP 400, provider-error shape) on a block verdict.

Inspected destinations include OpenAI (incl. the `openai` CLI and Codex CLI via
`api.openai.com`), Anthropic, and Gemini. The **Gemini CLI** is covered in all three of
its modes: API-key (`generativelanguage.googleapis.com`), the default OAuth "log in with
Google" / Code Assist (`cloudcode-pa.googleapis.com`), and Vertex
(`aiplatform.googleapis.com`). Also Cohere/Mistral/Perplexity, **GitHub Copilot**
(`*.githubcopilot.com`, `copilot-proxy.githubusercontent.com`), **Microsoft Copilot**
(`copilot.microsoft.com`), and **Cursor** (`*.cursor.sh`, `cursor.com`) — see
`AI_HOST_SUFFIXES` in `palivane_addon.py`. The tool is identified from the User-Agent
(`detect_tool`), so the backend's per-tool policy suppresses routine `source_code_leak`
for coding tools (`claude-code`, `cursor`, `copilot`, `gemini-cli`) while still catching
secrets and PII.

## MCP inspection (agentic tool-use)

Beyond prompt capture, the addon inspects **MCP** (Model Context Protocol) — the JSON-RPC
an AI coding agent uses to call tools and read resources. It's **content-sniffed** (any
POST whose body is JSON-RPC 2.0), so it works for MCP servers on any *decrypted* host —
the AI list by default; add your MCP servers via `PALIVANE_PROXY_INTERCEPT_EXTRA` or set
`PALIVANE_PROXY_INTERCEPT_ALL=true` (see "Scoped TLS interception") — and posts a
normalized activity to `POST /api/ingest/mcp` on the **`mcp`** surface. A block verdict
returns a **JSON-RPC error** so the agent surfaces it cleanly. It flags:

- **sensitive resource access** (tool/resource touching `.env`, private keys, cloud creds…)
- **dangerous commands** (`curl … | sh`, `rm -rf /`, reverse shells…)
- **tool poisoning** (injected instructions in a server's advertised tool descriptions —
  caught in the `tools/list` response *and* in the tool defs the agent sends to the LLM API)
- **untrusted servers** (not on `MCP_ALLOWED_SERVERS`)
- **secrets/PII** in tool-call arguments

> **Transport boundary (agentless).** Remote / Streamable-HTTP MCP servers flow through
> the proxy and are fully inspected + blockable. **Local stdio** MCP servers never touch
> the network — agentlessly they're governed by *policy* (`MCP_ALLOWED_SERVERS`) and
> surfaced via the tool definitions the agent sends to the model (so tool-poisoning is
> still caught). For **inline** inspection of local stdio, wrap the server command with
> [`cli/palivane-mcp`](../cli/README.md) — an app-scoped shim, not an endpoint agent.

MCP env vars are read by the **backend** (`MCP_ENFORCE`, `MCP_BLOCK_SEVERITY`,
`MCP_ALLOWED_SERVERS`), not the proxy — the proxy just relays; the backend decides.

## Agentic browsers (Comet / ChatGPT desktop) — parsing shipped, UNVERIFIED

**Perplexity Comet** runs the agent in the browser, so the extension can't see the
sidecar's prompts — the proxy is the inline path. The addon parses the assistant
endpoint (`www.perplexity.ai/rest/sse/perplexity_ask`): the JSON request is scanned and
blockable like any other prompt (`tool=comet`), and the SSE *response* (the agent's
steps/answer) is teed off the stream — no buffering, no client stall — and scanned
observe-only once it completes. The agent-automation WebSocket
(`wss://www.perplexity.ai/agent`) is flagged on open and its text frames are scanned. A
body that doesn't match the expected (Zenity-teardown) shape becomes a `[comet
parse-miss]` finding plus a harvest scan — shape drift degrades, it doesn't crash or go
silent. The **ChatGPT desktop app** (Atlas's successor, with built-in browser) talks to
the `chatgpt.com` backend the addon already parses.

**Honesty note:** all of this was built on Linux against synthetic fixtures
(`fixtures/comet/`) — no Linux builds of these browsers exist, so none of it is verified
against real traffic yet. The per-browser verification pass (managed-install flow,
pinning checks, per-mode host inventory) is
[docs/agentic-browser-verification.md](../docs/agentic-browser-verification.md). Offline
parser check, for CI or a field engineer with a real capture:

```bash
python3 proxy/palivane_addon.py --selftest-comet          # bundled synthetic fixtures
python3 proxy/palivane_addon.py --selftest-comet <dir>    # your captured bodies
```

For the on-machine pass itself, run `mitmdump -s proxy/verify_browsers.py` instead of
the bare addon: it runs the addon unchanged plus an evidence recorder that classifies
each runbook check (host/TLS-pinning signals, Comet request/SSE parse vs. parse-miss,
agent-WebSocket frames, ChatGPT desktop parsing, Dia host discovery) and writes
`verification-report.md` / `.json` on Ctrl-C — evidence capture is automated, the
browser actions are still manual.

> **Cursor caveat (measured).** Cursor's model/chat endpoint (`api2.cursor.sh`) **pins
> its certificate** — a TLS-inspecting proxy is rejected (`tlsv1 alert unknown ca`) even
> with a trusted CA, so **chat prompts can't be intercepted** this way. The proxy can
> still see Cursor's codebase-index uploads (`aiserver.v1.CodebaseSnapshotService`,
> protobuf) and telemetry, but those aren't the prompt. **The fix isn't the proxy —
> it's the local plane:** [`palivane-cursor-hook`](../cli/README.md) uses Cursor's Hooks
> API to inspect the prompt (`beforeSubmitPrompt`), shell/MCP calls, and file reads/edits
> before they run, immune to the pinning. Pair with the **git plane** and the **gateway**
> for first-party AI.

## Run

```bash
pip install mitmproxy
PALIVANE_URL=http://localhost:8090 \
PALIVANE_TOKEN=<EXTENSION_INGEST_TOKEN> \
PALIVANE_PROXY_ENFORCE=true \
PALIVANE_PROXY_USER=alice@company.com \
mitmdump -s proxy/palivane_addon.py --listen-port 8081
```

Point a client at it and watch a sensitive prompt get blocked:

```bash
curl -x http://localhost:8081 https://api.openai.com/v1/chat/completions \
  -H "authorization: Bearer $OPENAI_KEY" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"SSN 123-45-6789, AWS key AKIA..."}]}'
# -> 400 {"error":{"type":"invalid_request_error", "message":"Blocked by Palivane: sensitive data (...)"}}
```

| Env | Purpose |
| --- | --- |
| `PALIVANE_URL` | Palivane backend base URL |
| `PALIVANE_TOKEN` | the backend's `EXTENSION_INGEST_TOKEN` |
| `PALIVANE_PROXY_ENFORCE` | `true` blocks; otherwise observe + record only. Either way the org's console stance (Settings → *Device enforcement*) rides along on each verdict and blocks when on |
| `PALIVANE_PROXY_USER` | end-user identity to attribute findings to |

**Attribution:** on a per-device install (`palivane-desktop`), leave `PALIVANE_PROXY_USER`
unset — the proxy authenticates with the device's per-user `ak_…` key (from
`palivane connect`), and the backend attributes findings to that key's owner
automatically. `PALIVANE_PROXY_USER` matters only for a *central* egress proxy running
with the shared `EXTENSION_INGEST_TOKEN`, where one process serves many people: it can
only carry a single static identity, so per-user attribution needs either per-device
proxies or per-user keys. Prefer per-device installs when attribution matters.

## Deploying to managed devices

1. **System proxy** — push the proxy address via MDM (or a PAC file) so all traffic
   routes through it.
2. **TLS inspection** — install mitmproxy's CA (or your corporate root CA, with
   mitmproxy configured to use it) on managed devices so HTTPS bodies are inspectable.
   On a managed fleet this cert is already trusted.
3. Run `mitmdump` as a service (systemd) near the egress point; scale horizontally —
   the addon is stateless (it calls the Palivane API).

### Scoped TLS interception (the default, since addon 1.2.0)

Decrypting *all* TLS is a bigger ask — operationally (more cert-pinning breakage) and
politically (privacy review, works councils) — than the proxy actually needs. So the
addon now **scopes interception itself**: on startup it sets mitmproxy's `allow_hosts`
to `AI_HOST_SUFFIXES`, so matching hosts are decrypted and inspected and **everything
else is tunneled untouched, end-to-end encrypted** — no launch flag, no regex to keep in
sync, and existing installs pick it up via the normal plane self-update. This is also
what makes the proxy coexist with VPN/ZTNA stacks (Zscaler, Netskope, Tailscale-gated
services) and cert-pinned or own-CA-bundle tools: their traffic is never terminated.

Two env knobs on the proxy service:

- `PALIVANE_PROXY_INTERCEPT_EXTRA` — comma-separated host suffixes to *add* (e.g. your
  remote MCP servers: content-sniffed MCP detection only sees hosts that are decrypted).
- `PALIVANE_PROXY_INTERCEPT_ALL=true` — restore full interception when you need MCP
  inspection on arbitrary, unpredictable hosts.

The objection this answers changes from "you decrypt everything" to "we inspect a short
list of AI domains".

### Fail-open by construction

The proxy must never become the outage. Three layers, all shipped:

- **Scoring fails open** — if the Palivane backend is unreachable or the key is revoked,
  requests pass (a circuit breaker stops the hammering).
- **CLI shims fail open** — each shim probes the proxy port at launch and runs the tool
  *direct* (with a stderr note) if the proxy is down, instead of exporting a dead proxy.
- **The system proxy fails open** (Linux, `palivane-desktop`) — a systemd user timer
  checks the port every 20s; after ~60s of proxy death it removes the system-proxy
  config so the machine keeps working, and re-applies it automatically on recovery.
  (macOS system-proxy changes need sudo, so there the shim fail-open is the net.)

`no_proxy` defaults also exclude loopback, `.ts.net` + the CGNAT range (Tailscale), and
RFC1918 — intranet/VPC traffic never takes the proxy hop. Extend at install time with
`PALIVANE_PROXY_NO_PROXY_EXTRA`.

### Chaining through a corporate proxy (Zscaler / Netskope / SWG)

On a fleet behind a mandatory egress proxy, mitmdump can't reach the internet directly —
it has to forward through that proxy. `palivane-desktop` runs mitmdump in mitmproxy's
`--mode upstream:` for this, so the local capture proxy sits *in front of* the corporate
one: apps → Palivane (inspects AI hosts) → corporate proxy → internet.

- `PALIVANE_UPSTREAM_PROXY=http://corp-proxy:port` — the upstream proxy (MDM-pushed). If
  unset, the installer **auto-adopts an ambient `https_proxy`** so a device already
  configured for the corporate proxy works out of the box.
- `PALIVANE_UPSTREAM_CA=/path/to/corp-root.pem` — when the corporate proxy TLS-inspects,
  point this at its root bundle so mitmproxy trusts the *upstream* leg
  (`ssl_verify_upstream_trusted_ca`). Without it, chained HTTPS to an inspecting proxy
  fails cert verification.
- `PALIVANE_UPSTREAM_AUTH=user:pass` — for an authenticated proxy.
- `PALIVANE_UPSTREAM_INSECURE=1` — skip upstream cert verification (last resort; prefer
  `PALIVANE_UPSTREAM_CA`).

Scoped interception still applies over the chain: AI hosts are decrypted and inspected,
everything else is CONNECT-tunnelled to the corporate proxy untouched.

## Honest limits

- **TLS inspection required** to read request bodies. Apps that **certificate-pin**
  (some native clients) will refuse the inspected cert — they break or bypass rather
  than being inspected. Most major AI desktop/web clients don't hard-pin, but verify
  per app.
- Covers traffic that **routes through the proxy** — i.e. managed/on-network devices.
  Off-network personal devices need an endpoint agent (out of scope here).
- **Fails open**: if Palivane is unreachable the request is allowed through, so the
  proxy never becomes a single point of failure for the company's AI access.
- Prompt extraction recognizes OpenAI / Anthropic / Gemini shapes; for **any other JSON
  body** it harvests all string values so secrets/PII are still scanned without a
  per-vendor parser, and falls back to the raw text for non-JSON (e.g. protobuf/binary)
  bodies. GitHub Copilot Chat uses a `messages` body (covered) and inline completion uses
  a `prompt` field (covered). Note Cursor uses **protobuf** (`application/proto`), not
  JSON — and its chat endpoint pins certs anyway (see the Cursor caveat above).
- **Verify TLS interception per IDE before relying on enforcement.** Some builds pin
  certs (Cursor's chat endpoint does — measured); where they do, the client bypasses or
  fails rather than being inspected.
