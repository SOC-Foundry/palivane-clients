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

// The per-user capture key is a credential for this browser: it lives in chrome.storage.local,
// never sync (which copies it to every browser signed in to the same Google account and
// through Google's servers). Older versions stored it in sync, move it over once.
async function localToken() {
  const { token: legacy } = await chrome.storage.sync.get({ token: "" });
  if (legacy) {
    const { token: have } = await chrome.storage.local.get({ token: "" });
    if (!have) await chrome.storage.local.set({ token: legacy });
    await chrome.storage.sync.remove("token");
  }
  return (await chrome.storage.local.get({ token: "" })).token;
}

async function config() {
  const sync = await chrome.storage.sync.get(DEFAULTS);
  sync.token = await localToken();
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
  await chrome.storage.local.set({ token });
  await chrome.storage.sync.set({
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

async function recordVerdict(verdict, partial = false) {
  // Keep a session block counter + the last verdict for the popup, and reflect blocks
  // on the toolbar badge. A partial verdict covered only part of a message (the rest was never
  // scored): it is shown, but it is not a clean check and does not clear an "unchecked" mark.
  const { blockCount = 0 } = await chrome.storage.local.get({ blockCount: 0 });
  // A coached verdict is held like a block (injected.js), so it counts as one.
  const next = verdict.action === "block" || verdict.coached ? blockCount + 1 : blockCount;
  await chrome.storage.local.set({
    blockCount: next,
    lastVerdict: { ...verdict, at: Date.now(), ...(partial ? { partial: true } : {}) },
  });
  if (partial) return;   // the caller records a skip next, and that owns the badge
  try {
    if (next > 0) {
      await chrome.action.setBadgeText({ text: String(next) });
      await chrome.action.setBadgeBackgroundColor({ color: "#c0283a" });
    } else {
      await chrome.action.setBadgeText({ text: "" });   // a good check clears an "unchecked" mark
    }
  } catch (_) { /* action API may be unavailable in some contexts */ }
}

// A message went out without being checked (not signed in, key rejected, server down or slow,
// a body we could not read). Fail-open is the stated stance, but it must not look the same as a
// clean check: the popup says so and the badge carries a "!" until the next good verdict.
async function recordSkip(label) {
  try {
    await chrome.storage.local.set({ lastSkip: { label: String(label || "unknown"), at: Date.now() } });
    await chrome.action.setBadgeText({ text: "!" });
    await chrome.action.setBadgeBackgroundColor({ color: "#b8791f" });
  } catch (_) { /* action API may be unavailable in some contexts */ }
}

function skipped(label, reason) {
  recordSkip(label);
  return { action: "allow", reason, skipped: label };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === "ui") {
    // A block/warn/notice raised inside an iframe: show it in the tab's top frame, where it
    // is fully visible. ok:false tells the frame to draw it itself.
    const tabId = sender && sender.tab && sender.tab.id;
    if (tabId == null || !sender.frameId) { sendResponse({ ok: false }); return; }
    chrome.tabs.sendMessage(tabId, { type: "palivane-ui", kind: msg.kind, data: msg.data }, { frameId: 0 })
      .then((r) => sendResponse({ ok: !!(r && r.ok) }), () => sendResponse({ ok: false }));
    return true;
  }
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
  if (msg && msg.type === "skipped") {
    recordSkip(msg.reason);       // injected.js gave up waiting; nothing to answer
    return;
  }
  if (msg && msg.type === "blind") {
    (async () => {
      try {
        // A send we saw but could not read. The person is told every time (a good check in
        // between must not hide this one); the console once per site per ten minutes
        // (parse_miss: no content, it only moves the sensor's drift counter).
        const origin = String(msg.destination || "");
        await recordSkip("could not read a message on " + origin.replace(/^https?:\/\//, ""));
        const k = "blindAt:" + origin;
        const seen = (await chrome.storage.session.get({ [k]: 0 }))[k];
        if (Date.now() - seen < 10 * 60 * 1000) return;
        await chrome.storage.session.set({ [k]: Date.now() });
        const c = await config();
        const key = await getIngestKey(c);
        if (!key) return;
        await fetch(c.backendUrl.replace(/\/$/, "") + "/api/ingest/ai-usage", {
          method: "POST",
          headers: { "content-type": "application/json", "X-Palivane-Token": key },
          body: JSON.stringify({ content: "[palivane parse-miss]", destination: origin,
                                 user: c.user, parse_miss: true }),
        });
      } catch (_) { /* fail open */ }
    })();
    return;
  }
  if (!msg || msg.type !== "scan") return;
  (async () => {
    try {
      const c = await config();
      let key = await getIngestKey(c);
      if (!key) { sendResponse(skipped("not signed in", "unconfigured")); return; }
      // A recorded justification grants exactly one send: attach the token, and clear it
      // when the backend honored it (verdict.overridden) so it cannot linger.
      const { overrideGrant } = await chrome.storage.session.get({ overrideGrant: null });
      const grant = overrideGrant && overrideGrant.expires > Date.now() ? overrideGrant.token : "";
      const call = (k) => fetch(c.backendUrl.replace(/\/$/, "") + "/api/ingest/ai-usage", {
        method: "POST",
        headers: { "content-type": "application/json", "X-Palivane-Token": k },
        body: JSON.stringify({ content: msg.content, destination: msg.destination, user: c.user,
                               ...(msg.endpoint ? { endpoint: String(msg.endpoint).slice(0, 200) } : {}),
                               ...(grant ? { override_token: grant } : {}) }),
      });
      let res = await call(key);
      // A cached device key can be revoked/rotated server-side. With an enrollToken we can
      // self-heal: re-enroll for a fresh key and retry once. A static token has no fallback.
      if ((res.status === 401 || res.status === 403) && !c.token && c.enrollToken) {
        key = await getIngestKey(c, true);
        if (key) res = await call(key);
      }
      if (!res.ok) {
        const why = res.status === 401 || res.status === 403 ? "capture key rejected, sign in again"
                                                              : "server error " + res.status;
        sendResponse(skipped(why, "backend " + res.status));
        return;
      }
      const verdict = await res.json();
      // In monitor mode (enforce off) a "block" is normally downgraded to "warn", but a
      // CONFIRMED secret/PII leak (force_block) is hard-blocked regardless: block the
      // certain, monitor the fuzzy.
      if (!c.enforce && verdict.action === "block" && !verdict.force_block) verdict.action = "warn";
      // Monitor mode never holds a message, and a coached verdict is held: it falls back to the
      // plain warning the org's softer action already was. A confirmed leak (force_block) is
      // the exception, as above: it stays held, with the cleaned copy to send instead.
      if (!c.enforce && verdict.coached && !verdict.force_block) verdict.coached = false;
      if (verdict.overridden) await chrome.storage.session.remove("overrideGrant");  // consumed
      if (verdict.action === "block" && verdict.finding_id && verdict.self_justify) {
        await chrome.storage.session.set({
          ["blockedHash:" + verdict.finding_id]: await sha256Hex(msg.content) });
      }
      await recordVerdict(verdict, !!msg.partial);
      // Only part of the message was scored: it went out partly unchecked, and must say so.
      if (msg.partial) await recordSkip("message too long, only the first part was checked");
      sendResponse(verdict);
    } catch (e) {
      sendResponse(skipped("could not reach Palivane", String(e))); // fail open
    }
  })();
  return true; // keep the message channel open for the async sendResponse
});
