"""Palivane MCP server — govern your AI-security posture from your AI assistant.

Exposes Palivane's console API as MCP tools so an operator can query findings, work the
triage queue, inspect shadow-AI usage, run connector syncs, and pull a compliance report
without opening the web console. "UI-less" for the day-to-day; the console stays for the map.

Auth (env):
  PALIVANE_BASE_URL   console origin (default https://app.palivane.io)
  PALIVANE_API_TOKEN  a bearer JWT (from POST /api/auth/login) — preferred for automation
  PALIVANE_EMAIL      fallback: log in with these to obtain (and auto-refresh) a token;
  PALIVANE_PASSWORD   ignored if PALIVANE_API_TOKEN is set. MFA accounts must use a token.

Every tool calls the same API the console does, so a caller only ever sees their own tenant's
data and admin-gated actions (e.g. dismissing a finding) return the API's own 403.

Run:  python palivane_mcp.py     (stdio transport; wire into Claude Desktop/Code — see README)
"""

from __future__ import annotations

import os

import httpx
from mcp.server.fastmcp import FastMCP

BASE_URL = os.environ.get("PALIVANE_BASE_URL", "https://app.palivane.io").rstrip("/")
_TIMEOUT = float(os.environ.get("PALIVANE_TIMEOUT", "30"))

mcp = FastMCP("palivane")


class _Api:
    """Thin Palivane API client: bearer auth with one transparent re-login on 401."""

    def __init__(self) -> None:
        self._token = os.environ.get("PALIVANE_API_TOKEN", "").strip()
        self._client = httpx.Client(base_url=BASE_URL, timeout=_TIMEOUT)

    def _login(self) -> None:
        email = os.environ.get("PALIVANE_EMAIL", "")
        password = os.environ.get("PALIVANE_PASSWORD", "")
        if not email or not password:
            raise RuntimeError(
                "not authenticated: set PALIVANE_API_TOKEN, or PALIVANE_EMAIL + PALIVANE_PASSWORD")
        r = self._client.post("/api/auth/login", json={"email": email, "password": password})
        if r.status_code != 200:
            raise RuntimeError(f"login failed ({r.status_code}): {r.text[:200]}")
        body = r.json()
        token = body.get("access_token")
        if not token:
            # A challenge (e.g. MFA) came back instead of a token.
            raise RuntimeError(
                "login did not return a token (MFA-enabled accounts must use PALIVANE_API_TOKEN)")
        self._token = token

    def request(self, method: str, path: str, *, params=None, json=None) -> object:
        if not self._token:
            self._login()
        for attempt in (1, 2):
            r = self._client.request(
                method, path, params=params, json=json,
                headers={"Authorization": f"Bearer {self._token}"})
            if r.status_code == 401 and attempt == 1:
                self._login()          # token expired/revoked — refresh once and retry
                continue
            if r.status_code >= 400:
                raise RuntimeError(f"{method} {path} -> {r.status_code}: {r.text[:300]}")
            return r.json() if r.content else {}
        raise RuntimeError(f"{method} {path}: unauthorized after re-login")


_api = _Api()


# --- read tools -----------------------------------------------------------------------

@mcp.tool()
def health() -> dict:
    """Palivane service health + posture flags (signups, email, judge, demo). No auth."""
    return httpx.get(f"{BASE_URL}/api/health", timeout=_TIMEOUT).json()


@mcp.tool()
def list_findings(severity: str = "", status: str = "", surface: str = "",
                  actor: str = "", limit: int = 50) -> dict:
    """List detection findings for your tenant, newest activity first.

    Filters (all optional): severity (low|medium|high|critical), status (open|triaged|
    dismissed), surface (ai_usage|llm_io|mcp|collab|...), actor (sender email). limit<=500.
    """
    params = {k: v for k, v in
              (("severity", severity), ("status", status), ("surface", surface),
               ("actor", actor), ("limit", limit)) if v}
    return _api.request("GET", "/api/findings", params=params)


@mcp.tool()
def get_finding(finding_id: int) -> dict:
    """Full detail for one finding: signals, evidence, actor, surface, owner response."""
    return _api.request("GET", f"/api/findings/{finding_id}")


@mcp.tool()
def ai_tool_inventory() -> dict:
    """Shadow-AI inventory: every AI tool observed, by tool and by team, marked
    sanctioned/unsanctioned against the tenant allowlist, with the sensitive-data exposure
    each tool saw. The 'who is using what AI, and what leaked to it' view."""
    return _api.request("GET", "/api/discovery/inventory")


@mcp.tool()
def list_connectors() -> dict:
    """SaaS connectors (Google/M365/Slack/Salesforce/…) and their sync status."""
    return _api.request("GET", "/api/discovery/connectors")


@mcp.tool()
def gateway_usage() -> dict:
    """LLM-gateway usage for this tenant: current-minute count, 24h total, per-day totals,
    and the effective per-minute limit."""
    return _api.request("GET", "/api/usage")


@mcp.tool()
def compliance_report() -> dict:
    """Framework-coverage report for the tenant's live policy (OWASP LLM Top 10, etc.) —
    each control marked covered/partial/gap. Good for 'are we covered for X?' questions."""
    return _api.request("GET", "/api/compliance/report")


# --- write tools (actions) ------------------------------------------------------------

@mcp.tool()
def set_finding_status(finding_id: int, status: str) -> dict:
    """Triage a finding. status is one of: open, triaged, dismissed. Dismissing is
    admin-only server-side — a non-admin token gets a 403, surfaced as an error."""
    if status not in ("open", "triaged", "dismissed"):
        raise ValueError("status must be one of: open, triaged, dismissed")
    return _api.request("PATCH", f"/api/findings/{finding_id}", json={"status": status})


@mcp.tool()
def sync_connector(connector_id: int) -> dict:
    """Run an on-demand incremental sync for a SaaS connector. Returns the run summary
    (conversations/messages/files scanned, findings, anything skipped)."""
    return _api.request("POST", f"/api/discovery/connectors/{connector_id}/sync")


if __name__ == "__main__":
    mcp.run()
