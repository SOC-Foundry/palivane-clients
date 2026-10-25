const DEFAULTS = { backendUrl: "http://localhost:8090", token: "", user: "", enforce: true };
const $ = (id) => document.getElementById(id);

async function load() {
  const c = Object.assign({}, DEFAULTS, await chrome.storage.sync.get(DEFAULTS));
  // The token lives in local storage (background.js moves a legacy synced one over).
  const { token: legacy } = await chrome.storage.sync.get({ token: "" });
  c.token = (await chrome.storage.local.get({ token: "" })).token || legacy;
  let managed = {};
  try { managed = (await chrome.storage.managed.get(null)) || {}; } catch (_) {}
  // Managed (policy-set) values win and are shown read-only.
  const merged = Object.assign({}, c, managed);
  $("backendUrl").value = merged.backendUrl;
  $("token").value = merged.token;
  $("user").value = merged.user || "";
  $("enforce").checked = !!merged.enforce;

  loadInventory(managed);
  // reportInstalledExtensions isn't a field on this form, so it doesn't count toward "managed".
  const managedKeys = Object.keys(managed).filter((k) => k !== "reportInstalledExtensions");
  if (managedKeys.length) {
    for (const k of ["backendUrl", "token", "user", "enforce"]) {
      if (k in managed) $(k).disabled = true;
    }
    $("save").disabled = managedKeys.length >= 2;  // mostly/fully managed
    const note = document.createElement("div");
    note.style.cssText = "margin-top:12px;color:#1a7f37;font-size:12px;";
    note.textContent = "Some settings are managed by your organization and can't be changed here.";
    document.body.appendChild(note);
  }
}

async function save() {
  // The token is a credential for this browser only: local, never synced.
  await chrome.storage.local.set({ token: $("token").value.trim() });
  await chrome.storage.sync.remove("token");
  await chrome.storage.sync.set({
    backendUrl: $("backendUrl").value.trim() || DEFAULTS.backendUrl,
    user: $("user").value.trim(),
    enforce: $("enforce").checked,
  });
  $("saved").textContent = "saved";
  setTimeout(() => ($("saved").textContent = ""), 1500);
}

// The installed-extension inventory (background.js) runs only with the optional `management`
// permission, which Chrome grants from a click on a page like this one: no policy can grant it.
// An org's managed `reportInstalledExtensions` turns it off (false) or says it asked (true).
async function loadInventory(managed) {
  if (managed.reportInstalledExtensions === false) { $("inventory").hidden = true; return; }
  const granted = await chrome.permissions.contains({ permissions: ["management"] });
  $("inventory").hidden = false;
  $("invShare").hidden = granted;
  $("invStop").hidden = !granted;
  $("invStatus").textContent = granted
    ? "Shared. The list is sent when it changes, and otherwise at most once a day."
    : managed.reportInstalledExtensions
      ? "Your organization asks you to share this. Chrome needs you to approve it once."
      : "Not shared.";
}

async function reloadInventory() {
  let managed = {};
  try { managed = (await chrome.storage.managed.get(null)) || {}; } catch (_) {}
  await loadInventory(managed);
}

document.addEventListener("DOMContentLoaded", load);
document.getElementById("save").addEventListener("click", save);
// permissions.request has to be the first thing the click does: Chrome only shows the prompt
// inside a user gesture, and an await before it would lose that.
$("invShare").addEventListener("click", () => {
  chrome.permissions.request({ permissions: ["management"] }).then(reloadInventory, reloadInventory);
});
$("invStop").addEventListener("click", () => {
  chrome.permissions.remove({ permissions: ["management"] }).then(reloadInventory, reloadInventory);
});
