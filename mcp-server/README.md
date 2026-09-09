# Palivane MCP server

Govern your AI-security posture **from your AI assistant.** This is an [MCP](https://modelcontextprotocol.io)
server that exposes Palivane's console API as tools, so an operator can query findings, work
the triage queue, inspect shadow-AI usage, run connector syncs, and pull a compliance report
by *asking* — no web console needed for the day-to-day. The console stays for the map (coverage,
audits, exec reporting); everything actionable becomes headless.

On-brand by design: Palivane secures the `mcp` surface, and this is Palivane *as* an MCP server —
you run your DLP from the same kind of tool it protects.

## Tools

**Implemented (this minimal server):**

| Tool | Does | API |
|------|------|-----|
| `health` | Service health + posture flags (signups, email, judge, demo). No auth. | `GET /api/health` |
| `list_findings` | Findings for your tenant, filterable by severity/status/surface/actor. | `GET /api/findings` |
| `get_finding` | Full detail for one finding (signals, evidence, actor, owner response). | `GET /api/findings/{id}` |
| `ai_tool_inventory` | Shadow-AI inventory: tools in use by team, sanctioned vs not, exposure. | `GET /api/discovery/inventory` |
| `list_connectors` | SaaS connectors and their sync status. | `GET /api/discovery/connectors` |
| `gateway_usage` | LLM-gateway usage (minute/24h/day totals, limit). | `GET /api/usage` |
| `compliance_report` | Framework coverage (OWASP LLM Top 10, …), control-by-control. | `GET /api/compliance/report` |
| `set_finding_status` | Triage a finding: `open` / `triaged` / `dismissed` (dismiss is admin-only). | `PATCH /api/findings/{id}` |
| `sync_connector` | Run an on-demand incremental connector sync; returns the run summary. | `POST /api/discovery/connectors/{id}/sync` |

**Roadmap (next tools — the API exists; wiring is the work):**

- `add_custom_pattern` / `list_custom_patterns` — manage tenant PII/secret regexes (read-modify-write on `PATCH /api/tenant`; needs a settings read first so an append can't clobber).
- `set_policy` — toggle checks and monitor↔enforce (`POST /api/policies/overrides`, `PATCH /api/tenant`).
- `resolve_exception` — approve/deny a user's justify/exception request (`POST /api/exceptions/{id}/resolve`).
- `redteam_selftest` — replay the injection/jailbreak corpus through the live policy (`POST /api/redteam/selftest`).
- `provision_device` — mint an enrollment token + setup script (`POST /api/provision`).
- Resources (not tools): expose the coverage map and audit timeline as MCP *resources* for read-only context.

## Setup

```bash
cd mcp-server
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

Auth (env):

### Use a console API key (recommended)

In the console: **Connections → Console API key**. Give it a label, pick a scope, mint,
and copy the `ak_…` value — it is shown once.

| Scope | Gets you |
|-------|----------|
| **Read only** | Every read tool: `list_findings`, `get_finding`, `ai_tool_inventory`, `list_connectors`, `gateway_usage`, `compliance_report`. |
| **Read + triage/sync** | The above, plus `set_finding_status` and `sync_connector`. |

```bash
claude mcp add palivane \
  --env PALIVANE_API_KEY=ak_... \
  -- /abs/path/mcp-server/.venv/bin/python /abs/path/mcp-server/palivane_mcp.py
```

It does not expire, holds no password, works with MFA enabled, and is revocable from the
same screen. The key acts as **the person who minted it** — it can reach exactly what
their role can, and *never* org settings, user management, or minting another key, whatever
their role. Revoke it and it is dead immediately; deactivate that user and it dies with
them.

### Full env reference

| Var | Meaning |
|-----|---------|
| `PALIVANE_BASE_URL` | Console origin. Default `https://app.palivane.io`. |
| `PALIVANE_API_KEY` | **Preferred.** A console-scoped API key (`ak_…`) from Connections. Long-lived and revocable. |
| `PALIVANE_API_TOKEN` | A bearer JWT from `POST /api/auth/login`. Works, but it is a *session* token — see below. |
| `PALIVANE_EMAIL` / `PALIVANE_PASSWORD` | Last-resort login (auto-refreshes the token). Ignored if either credential above is set. **MFA accounts cannot use this path.** |
| `PALIVANE_ORG` | Org slug. Email/password path only, and needed **only** if your email belongs to more than one org — the API refuses to guess between them, and login returns `409` until you name one. |

<details>
<summary>If you use a session token or a password instead</summary>

```bash
curl -s https://app.palivane.io/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@corp.com","password":"..."}' | jq -r .access_token
# add "org":"your-slug" if the email is in more than one org
```

`PALIVANE_API_TOKEN` is a console **session** token: it expires on the server's
`AUTH_TOKEN_TTL` (**~12h** by default) and is invalidated by a password change or a
sign-out-everywhere. So either set `PALIVANE_EMAIL` + `PALIVANE_PASSWORD` and let the
server re-login when it lapses (the cost being a password in your client config), or
re-mint the token by hand. MFA accounts can't auto-refresh at all — login returns a
challenge, not a token. **A console API key avoids all of this**; prefer it.

An ingest-scoped `ak_…` key — the default scope, and what every key minted before console
scopes is — is **not** accepted by the console API. That is deliberate: it keeps keys
issued for the gateway/SIEM planes from silently gaining console reach.

</details>

Every tool calls the same API the console does, so a caller only sees their own tenant, and
admin-gated actions (e.g. dismissing a finding) return the API's own `403`.

## Wire it into a client

**Claude Code:**

```bash
claude mcp add palivane \
  --env PALIVANE_API_KEY=ak_... \
  -- /abs/path/mcp-server/.venv/bin/python /abs/path/mcp-server/palivane_mcp.py
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "palivane": {
      "command": "/abs/path/mcp-server/.venv/bin/python",
      "args": ["/abs/path/mcp-server/palivane_mcp.py"],
      "env": { "PALIVANE_API_KEY": "ak_..." }
    }
  }
}
```

## Ask it things

- "What high-severity findings landed today, and who triggered them?"
- "Show me finding 4821 in detail, then mark it triaged."
- "Which AI tools are in use that we haven't sanctioned, and what data leaked to them?"
- "Run a sync on the Google Workspace connector and tell me what it found."
- "Are we covered for the OWASP LLM Top 10? Where are the gaps?"

## Notes

- Pinned to `mcp<2` — v2 renamed `FastMCP` → `MCPServer` and changed APIs; v1's `FastMCP` is
  the stable, widely-documented surface. v2 migration is a tracked follow-up.
- stdio transport. For a shared/remote deployment, front it with the MCP HTTP transport and
  per-user tokens (a later step).
