# Palivane endpoint components

The client-side components of [Palivane](https://palivane.io) — the AI security gateway
that shows you what your team sends to AI tools and stops the customer data, credentials,
and source code that shouldn't go.

This repo contains **everything Palivane runs on your machines**, published so you can
audit it before you deploy it:

| Component | What it does |
| --- | --- |
| [`extension/`](extension/) | Browser extension (Chrome/Edge, MV3): inspects prompts to AI sites *before* they leave, warns or blocks per your org's policy. [Chrome Web Store listing](https://chromewebstore.google.com/detail/fnejondlaacijahdjkhcgiijlnjoapho). |
| [`cli/`](cli/) | Capture hooks for AI coding tools (Claude Code, Cursor, Codex, Copilot, Gemini CLI), device posture + at-rest secrets scanning, MCP config wrapping, CI scanning, and the `palivane-connect` self-serve enrollment. |
| [`proxy/`](proxy/) | The egress proxy addon (mitmproxy-based) covering desktop AI apps and anything else that won't take a base-URL override. |

Every component is fail-open by design: if the backend is unreachable, your AI tools keep
working — a down security control must never take engineering down with it.

## Where the verdicts come from

These clients capture; the scoring engine and console live in the Palivane backend —
either the hosted service at [app.palivane.io](https://app.palivane.io) or a self-hosted
deployment. A free self-hosted edition (full detection, no LLM key required) is
available: contact [sales@palivane.io](mailto:sales@palivane.io) while the public source
release of the backend is being prepared.

## Provenance

This is a read-only mirror of the client directories in Palivane's main repository.
Issues are welcome here; fixes land in the primary repo and sync out.

Security reports: [security@palivane.io](mailto:security@palivane.io) — see our
[disclosure policy](https://app.palivane.io/trust).

## License

Apache-2.0 — the code that runs on your machines should be maximally auditable and
reusable. (The backend will ship separately under a source-available license.)
