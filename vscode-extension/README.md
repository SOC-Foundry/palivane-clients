# Palivane for VS Code, in-IDE posture sensor

Continuous, event-driven device posture from inside the editor, the always-on version
of the `palivane-posture` CLI (which reports only when a Claude Code session starts):

- **Extension inventory drift**, the installed-extension list is reported to
  `POST /api/scan/ide-extensions` on startup and *the moment it changes*
  (`vscode.extensions.onDidChange`), so a rogue or denylisted extension surfaces as a
  finding within seconds, not at the next session start.
- **MCP config changes**, workspace `.mcp.json` is watched live; `~/.claude.json`
  (synthesized to `{"mcpServers": ...}` only, the raw file never leaves the machine),
  VS Code and Cursor user MCP configs are reported on activation and on demand.
- **AI-assistant autonomy settings**. Claude Code / Cursor settings are scanned for
  unsafe autonomy (YOLO / auto-apply / auto-run) via `POST /api/scan/agent-config`.

Everything is fail-open, deduplicated (sha256 per report, per backend), and attributes
findings to the signed-in user.

## Sign-in

Three ways, tried in order:

1. **`Palivane: Connect to console`** (command palette or the status-bar shield), opens
   the console's `/extension-connect` page, mints a per-user capture key, stores it in
   VS Code SecretStorage. Same flow as the browser extension and `palivane-connect`.
2. `PALIVANE_URL` / `PALIVANE_TOKEN` in the environment.
3. The `env` block of `~/.claude/settings.json`, a machine already onboarded by
   `palivane-connect` reports with zero extra setup.

Set `palivane.url` in VS Code settings for self-hosted deployments (default: the hosted
SaaS, or whatever `~/.claude/settings.json` points at).

## Build & install

No build step (plain JS). Package with:

    cd vscode-extension
    npx @vscode/vsce package        # -> palivane-vscode-0.2.0.vsix

Install: `code --install-extension palivane-vscode-0.2.0.vsix`, or Extensions view →
`...` -> *Install from VSIX*. Marketplace publishing (when ready) follows the same
publisher flow as the browser extension's `extension/STORE.md`.

`package.json` declares `"publisher": "palivane"`. That publisher does not exist on the
Marketplace yet, so `vsce publish` will fail until it is registered against an Azure
DevOps organization owned by SOC Foundry. Register the name before the first publish:
unlike a Chrome item id, a Marketplace publisher cannot be renamed afterwards, and the
extension's identity is `publisher.name`, so changing it later means a new listing and a
reinstall for everyone.
