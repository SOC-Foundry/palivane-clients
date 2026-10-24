# Palivane. Shadow-AI Guard (browser extension)

A Manifest V3 extension that catches **secrets, PII, and proprietary data being pasted
into external AI tools** (ChatGPT, Claude, Gemini, Microsoft Copilot, Perplexity, Mistral
Le Chat, DeepSeek, Grok, Google AI Studio, Poe), and warns or blocks **before the prompt
is sent**. It's the Module C (`ai_usage`) capture client; all detection happens in the
Palivane backend (`POST /api/ingest/ai-usage`).

> **Coverage caveat.** Capture keys off per-vendor request shapes (`SEND_PATTERNS` +
> `extractPrompt` in `injected.js`). The newer hosts (Perplexity, Mistral, DeepSeek,
> Grok, AI Studio, Poe) match on their submit endpoints and fall back to scanning the raw
> request body; a vendor changing its endpoint/payload can silently break capture for
> that site until the pattern is updated. Text prompts only, file/image **attachments
> are not yet scanned**.

> **Microsoft Copilot note.** `copilot.microsoft.com` is in the extension's matched
> hosts, and the backend already labels it as a destination. Reliable browser capture
> still needs a site-specific request-shape match in `injected.js` (`SEND_PATTERNS` +
> `extractPrompt`) once that shape is confirmed, and the consumer client uses a
> WebSocket transport that fetch-wrapping can't see. The **egress proxy** is the
> dependable capture plane for Copilot (it inspects the GitHub Copilot IDE domains and
> `copilot.microsoft.com` directly).

## How it works

`content.js` injects `injected.js` into the page, which wraps `window.fetch`. When the
page submits a prompt, the interceptor extracts the prompt text, asks the background
worker for a verdict (which calls Palivane), and:

- **allow** → sends normally,
- **warn** → sends, but shows an amber banner,
- **block** → the request is **not sent**; a modal explains *why* and offers a **way
  forward**, the org's **approved AI tools** to use instead (from the tenant's
  sanctioned-tools list, returned with the verdict) and a **"Request exception"** button
  that files the request to the security team's audit log (`POST /api/exception-request`).
  This turns a hard wall into a redirect, which is what keeps users from finding a
  workaround.
- **coached** (the org turned on Coaching mode) → the server softens a secret/PII block
  into a warning on the assumption that the client will show the cleaned version. The
  original message is still **held, never sent**; the modal shows the cleaned copy
  (sensitive values replaced) with a **Copy cleaned message** button, plus the approved
  tools. In monitor mode (Enforce off in Options) it is the plain amber warning instead,
  unless the leak is confirmed (`force_block`): that is held with the cleaned copy either way.

It reads the body of a send however the page builds it: a string, `URLSearchParams`,
`FormData` text fields, a `Blob`, an `ArrayBuffer` or typed array, or a `Request` object
(read from a clone, so the page's own send is untouched), over `fetch` and `XMLHttpRequest`.
A body it cannot read (a stream, or anything over 1 MB) is reported as a parse-miss on the
device's sensor in the console instead of being skipped in silence. The backend scores at most
200,000 characters a call, so a longer message is scanned in overlapping 150,000-character
windows (up to 1.2 million characters; the rest is reported the same way), and a send that is
not JSON (Gemini's form-encoded one) is scanned whole rather than cut to its first 8,000
characters.

It **fails open**: if the backend is slow, unreachable, or unconfigured, prompts go
through, the extension never breaks the user's tool. But a check that did not happen no
longer looks like a clean one:

- A message sent **unchecked** (not signed in, capture key rejected, server error, no
  answer within 4 seconds, or the extension was updated under an open tab) shows a grey
  banner (at most one per five minutes), puts a **!** on the toolbar icon, and the popup
  says why. The next successful check clears the mark.
- If the answer arrives **after** the 4 seconds and would have stopped the message, a red
  banner says so, so nobody assumes it was checked.
- After an extension update or reload, tabs that were already open lose their link to the
  extension until they are reloaded; the banner says "reload this tab".

## Backend setup

Set a shared token and the tenant on the Palivane backend, then restart it:

```
EXTENSION_INGEST_TOKEN=<a long random string>
INGEST_TENANT=<tenant slug, e.g. acme>
```

## Build a package

```bash
./build.sh            # -> palivane-shadow-ai-guard-<version>.zip
```

## Install, pilot (one machine)

1. `chrome://extensions` → **Developer mode** → **Load unpacked** → pick this folder.
2. Open **Options** and set **Backend URL**, **Ingest token** (`EXTENSION_INGEST_TOKEN`),
   and **Enforce**.
3. Visit `https://claude.ai`, submit a prompt with a fake SSN `123-45-6789` + an `AKIA…`
   key, it should be blocked.

## Install, so users can just install it

The extension is published publicly on the Chrome Web Store:
**https://chromewebstore.google.com/detail/fnejondlaacijahdjkhcgiijlnjoapho** (id `fnejondlaacijahdjkhcgiijlnjoapho` — set as `PALIVANE_EXTENSION_ID` on the
deployment so MDM packs and the console reference it). Self-hosting the CRX with an
`update_url` remains supported for air-gapped fleets. Then either:
- users click **Add to Chrome** (one click), or
- you **force-install** it so it appears automatically, no user action.

> **Full store-submission walkthrough**, listing copy, the permission/privacy review
> answers, and the step-by-step upload, is in [`STORE.md`](./STORE.md), with a hostable
> privacy policy in [`PRIVACY.md`](./PRIVACY.md). The package now ships the required
> icons (`icons/`), so `./build.sh` produces a store-ready zip.

## Enterprise rollout, zero-touch (force-install + managed config)

Push via your MDM / Google Admin / group policy:

1. **Force-install** by extension ID. Chrome `ExtensionInstallForcelist`
   (Edge: `ExtensionInstallForcelist`; with a self-hosted CRX, include the `update_url`).
2. **Configure centrally** via managed storage (`3rdparty/extensions/<id>/policy`), the
   extension declares a `managed_schema.json`, so policy values are applied automatically
   and **override** user settings (users can't repoint it):

   ```json
   {
     "backendUrl": { "Value": "https://palivane.corp.example.com" },
     "token":      { "Value": "<EXTENSION_INGEST_TOKEN>" },
     "enforce":    { "Value": true }
   }
   ```

With this, a managed device installs and configures the extension with **zero user
interaction**. Set `user` from SSO if your management layer can template it.

**Self-healing alternative, push an `enrollToken` instead of a static `token`:**

   ```json
   {
     "backendUrl":  { "Value": "https://palivane.corp.example.com" },
     "enrollToken": { "Value": "et_<fleet enrollment token>" },
     "enforce":     { "Value": true }
   }
   ```

With an `enrollToken` the extension redeems it once for its **own per-device key**
(`POST /api/enroll`), caches it, and **re-enrolls automatically** if that key is ever
revoked/rotated (retries once on a 401). That gives per-device attribution and revocation,
and means a rotated key self-heals without re-pushing policy. A static `token` still works
(and wins if both are set); `enrollToken` is what the `/api/provision` installer emits.

## Scope & limits (honest)

- Covers **managed browsers/devices** where the extension is installed; personal
  devices bypass it (use a network proxy plane for those).
- The fetch-interception parsing is tuned for current ChatGPT/Claude/Gemini request
  shapes; their internal APIs change, so the `SEND_PATTERNS` / `extractPrompt` logic in
  `injected.js` needs occasional maintenance. Unknown shapes fall back to scanning the
  raw request body, so detection degrades gracefully rather than failing silently.
