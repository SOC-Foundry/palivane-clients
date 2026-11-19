// Service worker: calls the Palivane AI-usage ingest endpoint and returns a verdict.
// Config (backend URL, token or enrollToken, user, enforce) comes from chrome.storage, in
// a managed rollout these are pushed via enterprise policy (managed storage).

// Fail-open ledger (extension/failopen.js): the same counts-only tally the CLI writes to
// ~/.palivane/scan-failed-*.json. A scan that cannot reach the backend is recorded here
// and attached to the next request that does, which is what Fleet shows.
importScripts("failopen.js");
const failOpen = globalThis.palivaneFailOpen;

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

// Monitor mode downgrades a block to a warning, except a confirmed leak (force_block),
// which is held either way. Shared by prompt scans and attachment scans.
function applyEnforce(c, verdict) {
  if (!verdict || typeof verdict !== "object") return { action: "allow" };
  if (!c.enforce && verdict.action === "block" && !verdict.force_block) verdict.action = "warn";
  if (!c.enforce && verdict.coached && !verdict.force_block) verdict.coached = false;
  return verdict;
}

function unreadLabel(code) {
  if (code === "image") return "an attached image was not read";
  if (code === "too_large") return "an attachment was too large to check";
  if (code === "partial") return "an attachment was only partly read";
  return "an attachment could not be read";
}

// chrome.storage has no atomic rename, so the claim the CLI does with a file is a key
// move serialized on this promise. Two scans failing at once share one tally instead of
// each writing over the other.
const SCAN_FAILED_KEY = "scanFailed";
const SCAN_FAILED_CLAIM = "scanFailedClaim";
let ledgerChain = Promise.resolve();
function withLedger(fn) {
  const run = ledgerChain.then(fn, fn);
  ledgerChain = run.then(() => {}, () => {});
  return run;
}
async function ledgerState() {
  const bag = await chrome.storage.local.get({ [SCAN_FAILED_KEY]: null, [SCAN_FAILED_CLAIM]: null });
  return { pending: bag[SCAN_FAILED_KEY], claim: bag[SCAN_FAILED_CLAIM] };
}
async function saveLedger(state) {
  const keep = {};
  const drop = [];
  if (state.pending && state.pending.count) keep[SCAN_FAILED_KEY] = state.pending;
  else drop.push(SCAN_FAILED_KEY);
  if (state.claim && state.claim.count) keep[SCAN_FAILED_CLAIM] = state.claim;
  else drop.push(SCAN_FAILED_CLAIM);
  if (drop.length) await chrome.storage.local.remove(drop);
  if (Object.keys(keep).length) await chrome.storage.local.set(keep);
}
async function recordScanFailure(reason) {
  try {
    await withLedger(async () => {
      await saveLedger(failOpen.recordFailure(await ledgerState(), reason, Math.floor(Date.now() / 1000)));
    });
  } catch (_) { /* counting a failure must not change the fail-open the caller already chose */ }
}
async function claimScanFailures() {
  try {
    return await withLedger(async () => {
      const taken = failOpen.takeClaim(await ledgerState());
      await saveLedger(taken.state);
      return taken.report;
    });
  } catch (_) { return null; }
}
async function scanFailuresDelivered() {
  try {
    await withLedger(async () => { await saveLedger(failOpen.dropClaim(await ledgerState())); });
  } catch (_) { /* a delivered tally left behind is folded back on the next failure */ }
}
function clientHeaders() {
  // The browser will not let an extension set User-Agent. Fleet reads this header as the
  // same client token the hooks put in that header (palivane-extension/<version>).
  let version = "0";
  try { version = chrome.runtime.getManifest().version || "0"; } catch (_) {}
  return { "X-Palivane-Client": "palivane-extension/" + version };
}

// Installed-extension inventory. Chrome isolates extensions from each other, so Palivane can't
// see what an AI extension sends, only that it is installed (chrome.management). `management`
// is an OPTIONAL permission: made required, Chrome would disable the store install for every
// existing user until they accepted the new warning. Someone grants it from the Options page
// (no policy can grant it); until then none of this runs, and an org can turn it off with the
// managed `reportInstalledExtensions: false`. What leaves the browser: id, name, version,
// enabled, install type and a coarse host-access count, never URLs or page content. Which
// ones are AI is decided by the backend, so the list grows without a store release.
const INVENTORY_MAX_AGE_MS = 24 * 60 * 60 * 1000;

async function hasManagement() {
  try { return await chrome.permissions.contains({ permissions: ["management"] }); }
  catch (_) { return false; }
}

// "all sites" for a match-everything pattern, else how many hosts; never the hosts themselves.
function hostAccess(info) {
  const hosts = info.hostPermissions || [];
  if (hosts.some((h) => h === "<all_urls>" || /^(\*|https?):\/\/\*\//.test(h))) return "all sites";
  return hosts.length ? `${hosts.length} host${hosts.length === 1 ? "" : "s"}` : "none";
}

async function installedExtensions() {
  return (await chrome.management.getAll())
    .filter((e) => e.type === "extension" && e.id !== chrome.runtime.id)
    .map((e) => ({ id: e.id, name: e.name, version: e.version, enabled: e.enabled,
                   install_type: e.installType, host_access: hostAccess(e) }))
    .sort((a, b) => a.id.localeCompare(b.id));
}

// Sent when the list (or the backend) changed since the last good report, otherwise at most
// once a day. Checked on every service-worker start, so a browser left open for days still
// re-reports without needing the alarms permission. One run at a time: an extension update
// fires several management events back to back.
let inventoryRun = null;
function reportInventory(force = false) {
  inventoryRun = inventoryRun || (async () => {
    try {
      if (!(await hasManagement())) return;
      const c = await config();
      if (c.reportInstalledExtensions === false) return;   // the org opted out
      let key = await getIngestKey(c);
      if (!key) return;
      const extensions = await installedExtensions();
      const hash = await sha256Hex(c.backendUrl + "\n" + JSON.stringify(extensions));
      const { inventory } = await chrome.storage.local.get({ inventory: {} });
      if (!force && inventory.hash === hash && Date.now() - (inventory.at || 0) < INVENTORY_MAX_AGE_MS) return;
      const body = JSON.stringify({ extensions, device: await deviceId(), user: c.user, record: true });
      const call = (k) => fetch(c.backendUrl.replace(/\/$/, "") + "/api/scan/browser-extensions", {
        method: "POST",
        headers: { "content-type": "application/json", "X-Palivane-Token": k },
        body,
      });
      let res = await call(key);
      if ((res.status === 401 || res.status === 403) && !c.token && c.enrollToken) {
        key = await getIngestKey(c, true);
        if (key) res = await call(key);
      }
      if (res.ok) await chrome.storage.local.set({ inventory: { hash, at: Date.now() } });
    } catch (_) { /* best-effort: the next start or change retries */ }
    finally { inventoryRun = null; }
  })();
  return inventoryRun;
}

chrome.permissions.onAdded.addListener((p) => {
  if ((p.permissions || []).includes("management")) reportInventory(true);
});
chrome.permissions.onRemoved.addListener((p) => {
  // Forget the last report, so granting it again sends the list straight away.
  if ((p.permissions || []).includes("management")) chrome.storage.local.remove("inventory");
});
// chrome.management only exists in a worker started after the permission was granted.
if (chrome.management && chrome.management.onInstalled) {
  for (const ev of ["onInstalled", "onUninstalled", "onEnabled", "onDisabled"]) {
    chrome.management[ev].addListener(() => reportInventory());
  }
}
reportInventory();

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
                     backendUrl: c.backendUrl, managed: await isManaged(),
                     // The org asked (by policy) for the extension list and nobody granted it yet.
                     inventoryAsked: c.reportInstalledExtensions === true && !(await hasManagement()) });
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
  if (msg && msg.type === "scan-attachment") {
    (async () => {
      try {
        const c = await config();
        let key = await getIngestKey(c);
        if (!key) { sendResponse(skipped("not signed in", "unconfigured")); return; }
        const call = (k) => fetch(c.backendUrl.replace(/\/$/, "") + "/api/ingest/ai-attachment", {
          method: "POST",
          headers: { "content-type": "application/json", "X-Palivane-Token": k, ...clientHeaders() },
          body: JSON.stringify({
            filename: String(msg.name || "attachment").slice(0, 200),
            mime: String(msg.mime || "").slice(0, 128),
            data_b64: msg.data_b64 || "",
            destination: msg.destination || "",
            user: c.user,
            ...(msg.endpoint ? { endpoint: String(msg.endpoint).slice(0, 200) } : {}),
          }),
        });
        let res = await call(key);
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
        const verdict = applyEnforce(c, await res.json());
        // Unreadable (OCR off, a format we cannot open, only partly read) is not a clean
        // check and is not a block: the file goes, and the popup says so.
        if (verdict.unread) {
          await recordSkip(unreadLabel(verdict.unread));
          sendResponse(verdict);
          return;
        }
        await recordVerdict(verdict, false);
        sendResponse(verdict);
      } catch (e) {
        sendResponse(skipped("could not reach Palivane", String(e)));
      }
    })();
    return true;
  }
  if (!msg || msg.type !== "scan") return;
  (async () => {
    // Set once the backend has accepted this request, so a later local error (badge,
    // storage) is not counted as "the backend was unreachable".
    let reported = false;
    try {
      const c = await config();
      let key = await getIngestKey(c);
      if (!key) { sendResponse(skipped("not signed in", "unconfigured")); return; }
      // A recorded justification grants exactly one send: attach the token, and clear it
      // when the backend honored it (verdict.overridden) so it cannot linger.
      const { overrideGrant } = await chrome.storage.session.get({ overrideGrant: null });
      const grant = overrideGrant && overrideGrant.expires > Date.now() ? overrideGrant.token : "";
      // The pending fail-open tally rides on this request, the way the CLI attaches it.
      // Counts and times only — never the prompt that could not be scanned.
      const report = await claimScanFailures();
      const call = (k) => fetch(c.backendUrl.replace(/\/$/, "") + "/api/ingest/ai-usage", {
        method: "POST",
        headers: { "content-type": "application/json", "X-Palivane-Token": k, ...clientHeaders() },
        body: JSON.stringify({ content: msg.content, destination: msg.destination, user: c.user,
                               ...(msg.endpoint ? { endpoint: String(msg.endpoint).slice(0, 200) } : {}),
                               ...(grant ? { override_token: grant } : {}),
                               // the edited message from "send with these removed": links it
                               // to the block it fixes (the backend marks that finding)
                               ...(Number.isInteger(msg.redactedFrom) ? { redacted_from: msg.redactedFrom } : {}),
                               ...(report ? { scan_failed: report } : {}) }),
      });
      let res = await call(key);
      // A cached device key can be revoked/rotated server-side. With an enrollToken we can
      // self-heal: re-enroll for a fresh key and retry once. A static token has no fallback.
      // A 401 that the retry repairs is not a fail-open: the message was scanned.
      if ((res.status === 401 || res.status === 403) && !c.token && c.enrollToken) {
        key = await getIngestKey(c, true);
        if (key) res = await call(key);
      }
      if (!res.ok) {
        const why = res.status === 401 || res.status === 403 ? "capture key rejected, sign in again"
                                                              : "server error " + res.status;
        await recordScanFailure(res.status);   // folds the undelivered claim back in
        sendResponse(skipped(why, "backend " + res.status));
        return;
      }
      let verdict;
      try { verdict = await res.json(); }
      catch (_) {
        // The backend accepted the request (and the tally on it). The unreadable body is
        // a new failure, not the same one sent again.
        await scanFailuresDelivered();
        await recordScanFailure("bad-response");
        sendResponse(skipped("could not reach Palivane", "bad response"));
        return;
      }
      await scanFailuresDelivered();
      reported = true;
      verdict = applyEnforce(c, verdict);
      if (verdict.overridden) await chrome.storage.session.remove("overrideGrant");  // consumed
      if (verdict.action === "block" && verdict.finding_id && verdict.self_justify) {
        await chrome.storage.session.set({
          ["blockedHash:" + verdict.finding_id]: await sha256Hex(msg.content) });
      }
      await recordVerdict(verdict, !!msg.partial);
      // Only part of the message was scored: it went out partly unchecked, and must say so.
      if (msg.partial) await recordSkip(msg.partialReason || "message too long, only the first part was checked");
      sendResponse(verdict);
    } catch (e) {
      // The backend was unreachable. The message still goes out — fail open — and the
      // miss is counted locally so Fleet hears about it on the next request that lands.
      if (!reported) await recordScanFailure(e);
      sendResponse(skipped("could not reach Palivane", String(e))); // fail open
    }
  })();
  return true; // keep the message channel open for the async sendResponse
});
