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

  const managedKeys = Object.keys(managed);
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

document.addEventListener("DOMContentLoaded", load);
document.getElementById("save").addEventListener("click", save);
