"""Palivane MCP server — govern your AI-security posture from your AI assistant.

Exposes Palivane's console API as MCP tools so an operator can query findings, work the
triage queue, inspect shadow-AI usage, run connector syncs, and pull a compliance report
without opening the web console. "UI-less" for the day-to-day; the console stays for the map.

Auth (env) — three ways, in order of preference:
  PALIVANE_BASE_URL   console origin (default https://app.palivane.io)
  PALIVANE_API_KEY    BEST: a console-scoped API key (`ak_…`) minted in Connections. It is
                      long-lived, revocable from the console, works with MFA on, and needs
                      no password anywhere. Mint it "read only" for the read tools, or
                      "read + triage/sync" to also use set_finding_status/sync_connector.
  PALIVANE_API_TOKEN  a bearer JWT from POST /api/auth/login. Works, but it is a console
                      *session* token: it expires (AUTH_TOKEN_TTL, ~12h by default) and is
                      invalidated by a password change or sign-out-everywhere, so it needs
                      re-minting. Prefer PALIVANE_API_KEY.
  PALIVANE_EMAIL      last resort: log in with these to obtain (and auto-refresh) a token.
  PALIVANE_PASSWORD   Ignored if either credential above is set. MFA accounts cannot use
                      this path at all — use PALIVANE_API_KEY.
  PALIVANE_ORG        org slug — only for the email/password path, and only when the email
                      belongs to more than one org (the API refuses to guess; it would be a
                      cross-tenant hazard).

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
    """Thin Palivane API client: bearer auth with one transparent re-login on 401.

    A console API key needs none of that machinery — it does not expire, so there is
    nothing to refresh and no password to hold. When one is set it is simply the bearer
    credential for every call, and a 401 means it was revoked (which re-logging-in could
    not fix anyway, so we don't try).
    """

    def __init__(self) -> None:
        self._api_key = os.environ.get("PALIVANE_API_KEY", "").strip()
        self._token = os.environ.get("PALIVANE_API_TOKEN", "").strip()
        # Whether the token we started with came from the environment. Used only to tell
        # "your token stopped working" apart from "you configured no credentials at all" —
        # reporting the latter when the operator plainly did set a token reads as a bug in
        # this server rather than as an expired session.
        self._token_from_env = bool(self._token)
        self._client = httpx.Client(base_url=BASE_URL, timeout=_TIMEOUT)

    def _login(self) -> None:
        email = os.environ.get("PALIVANE_EMAIL", "")
        password = os.environ.get("PALIVANE_PASSWORD", "")
        if not email or not password:
            if self._token_from_env:
                raise RuntimeError(
                    "PALIVANE_API_TOKEN is no longer accepted. It is a console session "
                    "token, so it expires (~12h by default) and is also invalidated by a "
                    "password change or sign-out-everywhere. Mint a fresh one via "
                    "POST /api/auth/login, or set PALIVANE_EMAIL + PALIVANE_PASSWORD so "
                    "this server can re-login by itself (not possible on MFA-enabled "
                    "accounts — those must re-mint the token).")
            raise RuntimeError(
                "not authenticated: set PALIVANE_API_TOKEN, or PALIVANE_EMAIL + PALIVANE_PASSWORD")
        payload = {"email": email, "password": password}
        org = os.environ.get("PALIVANE_ORG", "").strip()
        if org:
            payload["org"] = org
        r = self._client.post("/api/auth/login", json=payload)
        if r.status_code == 409:
            # The API refuses to auto-pick between orgs sharing an email (cross-tenant
            # hazard), so this is config we can ask for by name rather than a raw 409.
            raise RuntimeError(
                "this email belongs to more than one Palivane org — set PALIVANE_ORG to "
                "your org slug (the same one you choose when signing in to the console).")
        if r.status_code != 200:
            raise RuntimeError(f"login failed ({r.status_code}): {r.text[:200]}")
        body = r.json()
        token = body.get("access_token")
        if not token:
            # A challenge (e.g. MFA) came back instead of a token.
            raise RuntimeError(
                "login did not return a token (MFA-enabled accounts must use PALIVANE_API_TOKEN)")
        self._token = token
        self._token_from_env = False

    def request(self, method: str, path: str, *, params=None, json=None) -> object:
        if self._api_key:
            r = self._client.request(
                method, path, params=params, json=json,
                headers={"Authorization": f"Bearer {self._api_key}"})
            if r.status_code == 401:
                raise RuntimeError(
                    "PALIVANE_API_KEY was rejected. A console key is long-lived, so this "
                    "means it was revoked, it expired, the user it acts as was "
                    "deactivated — or it is an ingest-scoped key, which the console API "
                    "does not accept. Mint one under Connections -> Console API key.")
            if r.status_code == 403:
                raise RuntimeError(
                    f"{method} {path} -> 403: {r.text[:200]} (a read-only key cannot write; "
                    "mint one with 'Read + triage/sync' if you need set_finding_status or "
                    "sync_connector)")
            if r.status_code >= 400:
                raise RuntimeError(f"{method} {path} -> {r.status_code}: {r.text[:300]}")
            return r.json() if r.content else {}
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
