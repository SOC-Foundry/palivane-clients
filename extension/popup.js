const $ = (id) => document.getElementById(id);

// Escape before interpolating any server-supplied value into innerHTML — verdict fields,
// signal categories and the account display name all originate off-box.
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function render(state) {
  $("blockCount").textContent = state.blockCount || 0;
  const v = state.lastVerdict;
  const el = $("verdict");
  // A message that went out unchecked is newer news than the last verdict: say so, because a
  // failed check otherwise looks exactly like a clean one.
  const sk = state.lastSkip;
  const skipEl = $("skip");
  // A partial verdict (only part of a long message was scored) is not a clean check either: it
  // never hides the notice. Only a newer verdict on a whole message does.
  if (sk && (!v || v.partial || sk.at > (v.at || 0))) {
    skipEl.hidden = false;
    skipEl.textContent = `Last message was sent unchecked: ${sk.label} (${new Date(sk.at).toLocaleTimeString()})`;
  } else {
    skipEl.hidden = true;
  }
  if (!v) {
    el.className = "verdict muted";
    el.textContent = "No prompts inspected yet.";
    return;
  }
  const sigs = (v.signals || []).map((s) => esc(s.category)).join(", ") || "-";
  const when = v.at ? esc(new Date(v.at).toLocaleTimeString()) : "";
  el.className = "verdict";
  el.innerHTML =
    `<div>last verdict, <span class="sev sev-${esc(v.severity)}">${esc(v.coached ? "held (coached)" : v.action)} · ${esc(v.severity)}</span> ` +
    `(risk ${esc(v.risk_score ?? "?")})${v.partial ? ", first part only" : ""}</div>` +
    `<div class="sigs">${sigs}</div>` +
    `<div class="muted" style="margin-top:4px;font-size:11px;">${when}</div>`;
}

function renderConn(s) {
  const el = $("conn");
  if (s && s.configured) {
    el.className = "conn";
    el.innerHTML = `<div>Connected${s.user ? ' as <span class="who">' + esc(s.user) + "</span>" : ""}` +
      `${s.managed ? " (managed by your organization)" : ""}.</div>` +
      // The org asked by policy for the installed-extension list; only a click can grant it.
      (s.inventoryAsked ? `<div style="margin-top:6px;">Your organization asks you to share your installed ` +
                          `AI extensions. <a id="share">Review in options</a></div>` : "");
    const share = $("share");
    if (share) share.addEventListener("click", () => chrome.runtime.openOptionsPage());
  } else {
    el.className = "conn muted";
    el.innerHTML = `<div>Not connected to Palivane.</div>` +
      (s && s.managed ? "" : `<button id="signin">Sign in to Palivane</button>`);
  }
}

function bindSignin() {
  const btn = $("signin");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    btn.textContent = "Opening sign-in…"; btn.disabled = true;
    const r = await chrome.runtime.sendMessage({ type: "signIn" });
    if (r && r.ok) { loadConn(); return; }
    $("conn").innerHTML = `<div class="err">Sign-in failed: ${esc((r && r.error) || "unknown")}</div>` +
      `<button id="signin">Try again</button>`;
    bindSignin();
  });
}

async function loadConn() {
  renderConn(await chrome.runtime.sendMessage({ type: "status" }));
  bindSignin();
}

async function load() {
  render(await chrome.storage.local.get({ blockCount: 0, lastVerdict: null, lastSkip: null }));
  loadConn();
}

document.addEventListener("DOMContentLoaded", load);
$("reset").addEventListener("click", async () => {
  await chrome.storage.local.set({ blockCount: 0, lastSkip: null });
  try { await chrome.action.setBadgeText({ text: "" }); } catch (_) {}
  load();
});
$("options").addEventListener("click", () => chrome.runtime.openOptionsPage());
