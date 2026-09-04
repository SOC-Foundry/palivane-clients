// Service worker: calls the Palivane AI-usage ingest endpoint and returns a verdict.
// Config (backend URL, token or enrollToken, user, enforce) comes from chrome.storage, in
// a managed rollout these are pushed via enterprise policy (managed storage).

const DEFAULTS = {
  backendUrl: "http://localhost:8090",
  // Palivane console URL for self-serve sign-in (set to your SaaS app URL before publishing;
  // in a managed rollout it's pushed via policy). Falls back to backendUrl.
  consoleUrl: "",
  token: "",
  // Fleet enrollment token (et_...) pushed via policy instead of a static ingest token.
  // The extension redeems it once for its own per-device key, so a leaked/rotated key
  // self-heals on the next call without re-pushing policy to every device.
  enrollToken: "",
  user: "",
  enforce: true, // when false, "block" verdicts are downgraded to "warn"
};

async function config() {
  const sync = await chrome.storage.sync.get(DEFAULTS);
  // Enterprise policy (chrome.storage.managed) wins over user settings, so a
  // force-installed deployment is configured centrally and users can't repoint it.
  let managed = {};
  try {
    managed = (await chrome.storage.managed.get(null)) || {};
  } catch (_) { /* no managed policy present */ }
  return Object.assign({}, DEFAULTS, sync, managed);
}

// Stable per-install device identity, used to attribute the device key. Generated once and
// cached in local storage (never synced, it's this browser install's identity).
async function deviceId() {
  const { deviceId } = await chrome.storage.local.get({ deviceId: "" });
  if (deviceId) return deviceId;
  const id = "chrome-" + crypto.randomUUID();
  await chrome.storage.local.set({ deviceId: id });
  return id;
}

// Resolve the ingest key. A static `token` (from sign-in or a legacy static policy) wins.
// Otherwise, with an `enrollToken` set, redeem it for a per-device key and cache it. Pass
// forceRenew=true to discard a cached key that just got rejected and re-enroll.
async function getIngestKey(c, forceRenew = false) {
  if (c.token) return c.token;
  if (!c.enrollToken) return "";
  if (!forceRenew) {
    const { deviceKey } = await chrome.storage.local.get({ deviceKey: "" });
    if (deviceKey) return deviceKey;
  }
  const res = await fetch(c.backendUrl.replace(/\/$/, "") + "/api/enroll", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: c.enrollToken, device: await deviceId(), user: c.user || "" }),
  });
  if (!res.ok) return "";
  const { token } = await res.json();
  if (token) await chrome.storage.local.set({ deviceKey: token });
  return token || "";
}

async function isManaged() {
  try { return Object.keys((await chrome.storage.managed.get(null)) || {}).length > 0; }
  catch (_) { return false; }
}

// Self-serve / BYOD sign-in: open the Palivane console, let the user authenticate (login or
// SSO), and receive a per-user tenant-scoped token via the OAuth redirect. Not used on
// managed devices (policy config wins).
async function signIn() {
  const c = await config();
  const consoleUrl = (c.consoleUrl || c.backendUrl || "").replace(/\/$/, "");
  if (!consoleUrl) throw new Error("Set your Palivane URL first (Options).");
  const redirectUri = chrome.identity.getRedirectURL();          // https://<id>.chromiumapp.org/
  const state = Math.random().toString(36).slice(2);
  // device scopes the capture key so re-signing-in this browser rotates one key instead of
  // minting a new one every time (console dedups on it).
  const authUrl = `${consoleUrl}/extension-connect?redirect_uri=${encodeURIComponent(redirectUri)}` +
                  `&state=${state}&device=${encodeURIComponent(await deviceId())}`;
  const resultUrl = await chrome.identity.launchWebAuthFlow({ url: authUrl, interactive: true });
  const frag = new URLSearchParams(new URL(resultUrl).hash.slice(1));
  if (frag.get("state") !== state) throw new Error("state mismatch");
  const token = frag.get("token");
  if (!token) throw new Error("no token returned");
  await chrome.storage.sync.set({
    token,
    backendUrl: frag.get("backend") || consoleUrl,
    user: frag.get("user") || "",
  });
  return { user: frag.get("user") || "" };
}

// SHA-256 hex for the justify flow: the override grant is pinned to the exact blocked
// message, not just its finding (findings fold on violation classes, not text).
async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function recordVerdict(verdict) {
  // Keep a session block counter + the last verdict for the popup, and reflect blocks
  // on the toolbar badge.
  const { blockCount = 0 } = await chrome.storage.local.get({ blockCount: 0 });
  const next = verdict.action === "block" ? blockCount + 1 : blockCount;
  await chrome.storage.local.set({
    blockCount: next,
    lastVerdict: { ...verdict, at: Date.now() },
  });
  try {
    if (next > 0) {
      await chrome.action.setBadgeText({ text: String(next) });
      await chrome.action.setBadgeBackgroundColor({ color: "#c0283a" });
    }
  } catch (_) { /* action API may be unavailable in some contexts */ }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "status") {
    (async () => {
      const c = await config();
      sendResponse({ configured: !!(c.token || c.enrollToken), user: c.user || "",
                     backendUrl: c.backendUrl, managed: await isManaged() });
    })();
    return true;
  }
  if (msg && msg.type === "signIn") {
    (async () => {
      try { sendResponse({ ok: true, ...(await signIn()) }); }
      catch (e) { sendResponse({ ok: false, error: String(e.message || e) }); }
    })();
    return true;
  }
  if (msg && msg.type === "justify") {
    (async () => {
      try {
        const c = await config();
        const key = await getIngestKey(c);
        if (!key) { sendResponse({ ok: false }); return; }
        const hKey = "blockedHash:" + (msg.payload && msg.payload.finding_id);
        const stored = await chrome.storage.session.get({ [hKey]: "" });
        const res = await fetch(c.backendUrl.replace(/\/$/, "") + "/api/ingest/justify", {
          method: "POST",
          headers: { "content-type": "application/json", "X-Palivane-Token": key },
          body: JSON.stringify({ ...msg.payload, user: c.user,
                                 content_hash: stored[hKey] || "" }),
        });
        if (!res.ok) {
          sendResponse({ ok: false, error: res.status === 403 ? "confirmed" : String(res.status) });
          return;
        }
        const data = await res.json();
        // One pending grant at a time, in session storage: MV3 service workers are torn
        // down between events, so an in-memory variable would forget the grant before the
        // user presses send again. The backend binds the token to the finding + actor.
        await chrome.storage.session.set({ overrideGrant: {
          token: data.override_token || "",
          expires: Date.now() + ((data.expires_in || 600) - 30) * 1000,
        }});
        sendResponse({ ok: true });
      } catch (e) { sendResponse({ ok: false, error: String(e) }); }
    })();
    return true;
  }
  if (msg && msg.type === "exception") {
    (async () => {
      try {
        const c = await config();
        const key = await getIngestKey(c);
        if (!key) { sendResponse({ ok: false }); return; }
        const res = await fetch(c.backendUrl.replace(/\/$/, "") + "/api/exception-request", {
          method: "POST",
          headers: { "content-type": "application/json", "X-Palivane-Token": key },
          body: JSON.stringify({ ...msg.payload, user: c.user }),
        });
        sendResponse({ ok: res.ok });
      } catch (e) { sendResponse({ ok: false, error: String(e) }); }
    })();
    return true;
  }
  if (!msg || msg.type !== "scan") return;
  (async () => {
    try {
      const c = await config();
      let key = await getIngestKey(c);
      if (!key) { sendResponse({ action: "allow", reason: "unconfigured" }); return; }
      // A recorded justification grants exactly one send: attach the token, and clear it
      // when the backend honored it (verdict.overridden) so it cannot linger.
      const { overrideGrant } = await chrome.storage.session.get({ overrideGrant: null });
      const grant = overrideGrant && overrideGrant.expires > Date.now() ? overrideGrant.token : "";
      const call = (k) => fetch(c.backendUrl.replace(/\/$/, "") + "/api/ingest/ai-usage", {
        method: "POST",
        headers: { "content-type": "application/json", "X-Palivane-Token": k },
        body: JSON.stringify({ content: msg.content, destination: msg.destination, user: c.user,
                               ...(grant ? { override_token: grant } : {}) }),
      });
      let res = await call(key);
      // A cached device key can be revoked/rotated server-side. With an enrollToken we can
      // self-heal: re-enroll for a fresh key and retry once. A static token has no fallback.
      if ((res.status === 401 || res.status === 403) && !c.token && c.enrollToken) {
        key = await getIngestKey(c, true);
        if (key) res = await call(key);
      }
      if (!res.ok) { sendResponse({ action: "allow", reason: "backend " + res.status }); return; }
      const verdict = await res.json();
      // In monitor mode (enforce off) a "block" is normally downgraded to "warn", but a
      // CONFIRMED secret/PII leak (force_block) is hard-blocked regardless: block the
      // certain, monitor the fuzzy.
      if (!c.enforce && verdict.action === "block" && !verdict.force_block) verdict.action = "warn";
      if (verdict.overridden) await chrome.storage.session.remove("overrideGrant");  // consumed
      if (verdict.action === "block" && verdict.finding_id && verdict.self_justify) {
        await chrome.storage.session.set({
          ["blockedHash:" + verdict.finding_id]: await sha256Hex(msg.content) });
      }
      await recordVerdict(verdict);
      sendResponse(verdict);
    } catch (e) {
      sendResponse({ action: "allow", reason: String(e) }); // fail open
    }
  })();
  return true; // keep the message channel open for the async sendResponse
});
