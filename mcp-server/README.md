# Palivane MCP server

Govern your AI-security posture **from your AI assistant** — query findings, inspect
shadow-AI usage and pull reports by asking, instead of opening the console.

There are two ways to run it, and one thing with a confusingly similar name. Start here:

| You want | Use |
|---|---|
| Palivane's tools in Claude Desktop / Code / any MCP client | **The hosted endpoint** — one line, below |
| The same, against your own self-hosted Palivane | **The stdio server** in this directory |
| To *inspect somebody else's* MCP server for risky tool calls | **`palivane-mcp-guard`** — a different product, see the bottom |

---

## The hosted endpoint (recommended)

Nothing to clone, no Python, no virtualenv, no key pasted into a config file:

```bash
claude mcp add --transport http palivane https://app.palivane.io/api/mcp/
```

Your client discovers the authorization server, opens a browser, and you approve the
request in the Palivane console — signed in as yourself, seeing exactly which app is asking
and what it gets. The token acts as **you**: it reads what your role can read and nothing
more, it cannot change anything, and you can cut it off from **Connections → Authorized
apps** at any time.

For a client that does not do OAuth yet, a console API key works as a bearer token:

```bash
claude mcp add --transport http palivane https://app.palivane.io/api/mcp/ \
  --header "Authorization: Bearer ak_…"
```

Mint that under **Connections → Console API key**, scope *Read only*. It is long-lived and
revocable from the same screen.

### What the hosted endpoint exposes

Read-only, deliberately:

| Tool | Does |
|------|------|
| `list_findings` | Findings for your tenant, filterable by severity, status, surface, actor |
| `get_finding` | Full detail for one finding — signals, evidence, actor, owner response |
| `ai_tool_inventory` | Shadow-AI inventory: tools in use, sanctioned or not, and the exposure |
| `list_connectors` | SaaS connectors and their sync status |
| `gateway_usage` | LLM-gateway usage against the limit |
| `investigate_finding` | Runs the read-only analyst on a finding and returns a written investigation with a recommended action (never applies one) |

Triage and sync tools (`set_finding_status`, `sync_connector`) are **not** here yet. The
REST API gates writes with an explicit route allowlist, and MCP puts every call — reads
included — through a single POST, so that allowlist has no equivalent on this transport.
Rather than grow a second permission system, this ships reads only until there is a real
answer. The stdio server below still has them.

---

## The stdio server (self-hosted, or when you need the write tools)

Runs locally and talks to whichever Palivane you point it at. Use it if your deployment has
no hosted endpoint — a self-hosted install that has not set `PALIVANE_PUBLIC_URL` does not
publish one — or if you need triage and sync from your assistant today.

```bash
cd mcp-server
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

```bash
claude mcp add palivane \
  --env PALIVANE_API_KEY=ak_… \
  -- /abs/path/mcp-server/.venv/bin/python /abs/path/mcp-server/palivane_mcp.py
```

It exposes every tool above (`list_findings`, `get_finding`, `ai_tool_inventory`,
`list_connectors`, `gateway_usage`, `investigate_finding`) plus `health`,
`compliance_report`, `set_finding_status` and `sync_connector`. A key scoped *Read +
triage/sync* is required for the last two; a read-only key gets a refusal that says so.

### Environment

| Var | Meaning |
|-----|---------|
| `PALIVANE_BASE_URL` | Console origin. Default `https://app.palivane.io`. |
| `PALIVANE_API_KEY` | **Preferred.** A console-scoped `ak_…` key. Long-lived, revocable, works with MFA. |
| `PALIVANE_API_TOKEN` | A session JWT. Works, but expires on `AUTH_TOKEN_TTL` (~12h) and needs re-minting. |
| `PALIVANE_EMAIL` / `PALIVANE_PASSWORD` | Last resort. **MFA accounts cannot use this.** |
| `PALIVANE_ORG` | Org slug — email/password path only, and only when your email is in more than one org. |

---

## Not this: `palivane-mcp-guard`

`palivane-mcp-guard` (installed by `install.sh`, also available under its original name
`palivane-mcp`) is **the opposite direction**. It wraps a *third-party* MCP server and
inspects what that server is being asked to do — dangerous commands, sensitive resource
reads, tool poisoning, secrets in arguments — because a local stdio server never touches
the network and the egress proxy cannot see it.

```json
{"mcpServers": {"github": {
    "command": "palivane-mcp-guard",
    "args": ["--", "npx", "-y", "@modelcontextprotocol/server-github"]}}}
```

One inspects other people's servers. The other *is* Palivane's server. They shared a name
for months, which is why the guard now installs under both.
