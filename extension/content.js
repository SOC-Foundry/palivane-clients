// Isolated-world content script. Relays scan requests from the MAIN-world interceptor
// (injected.js, registered as a world:MAIN content script) to the background worker,
// and renders the warn/block UI. injected.js no longer needs to be injected via a
// <script> tag, that was blocked by strict-CSP sites like Microsoft Copilot.

window.addEventListener("message", async (e) => {
  // Only accept messages from the interceptor in THIS window (injected.js runs in the
  // MAIN world of the same window). Rejecting other sources/origins stops a hostile page
  // script from spoofing verdicts or summoning a fake Palivane block/warn UI (phishing).
  if (e.source !== window) return;
  const d = e.data;
  if (!d || !d.__palivane) return;

  if (d.kind === "scan") {
    let verdict = { action: "allow" };
    try {
      verdict = await chrome.runtime.sendMessage({
        type: "scan", content: d.content, destination: d.destination,
      });
    } catch (_) { verdict = { action: "allow" }; }
    window.postMessage({ __palivane: true, kind: "verdict", id: d.id, verdict: verdict || { action: "allow" } }, "*");
  } else if (d.kind === "blocked") {
    showBlockModal(d.verdict);
  } else if (d.kind === "warn") {
    showWarnBanner(d.verdict);
  }
});

const CATEGORY_LABELS = {
  secret_leak: "Credentials / secrets",
  pii_exposure: "Personal data (PII)",
  phi_exposure: "Health data (PHI)",
  source_code_leak: "Proprietary code / confidential material",
  confidential_data: "Confidential business data",
  prompt_injection: "Prompt injection",
  jailbreak: "Jailbreak attempt",
  data_exfiltration: "Data-exfiltration attempt",
  unsanctioned_ai: "Unsanctioned AI tool",
  unsafe_autonomy: "Unsafe agent autonomy (YOLO)",
  dangerous_command: "Dangerous command",
  agent_authz: "Agent acted outside its role",
};

function dataSignals(verdict) {
  // The categories that explain the block, most-specific first (destination last).
  const order = (c) => (c === "unsanctioned_ai" ? 1 : 0);
  const seen = new Set();
  return (verdict.signals || [])
    .filter((s) => !seen.has(s.category) && seen.add(s.category))
    .sort((a, b) => order(a.category) - order(b.category));
}

function reasonText(verdict) {
  const labels = dataSignals(verdict)
    .filter((s) => s.category !== "unsanctioned_ai")
    .map((s) => (CATEGORY_LABELS[s.category] || s.category).toLowerCase());
  if (!labels.length) return "sensitive content";
  if (labels.length === 1) return labels[0];
  return labels.slice(0, -1).join(", ") + " and " + labels[labels.length - 1];
}

// --- Block: a prominent, explanatory modal (so claude.ai's own fetch error reads as expected) ---
function showBlockModal(verdict) {
  document.getElementById("palivane-modal")?.remove();
  const rows = dataSignals(verdict).map((s) => {
    const label = CATEGORY_LABELS[s.category] || s.category;
    const ev = s.evidence ? `, <span style="opacity:.7">${escapeHtml(s.evidence)}</span>` : "";
    return `<li style="margin:4px 0">${escapeHtml(label)}${ev}</li>`;
  }).join("");

  // Turn a hard "no" into "no, use this instead": the org's approved AI tools.
  const tools = (verdict.sanctioned_tools || []).slice(0, 4);
  const alt = tools.length ? `
    <div style="margin-top:14px;padding:11px 13px;background:rgba(63,185,80,.08);
        border:1px solid rgba(63,185,80,.35);border-radius:10px">
      <div style="font-weight:700;color:#4ade80;font-size:13px">✓ Approved for sensitive data, use instead:</div>
      <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:8px">
        ${tools.map((t) => safeUrl(t.url)
          ? `<a href="${escapeHtml(safeUrl(t.url))}" target="_blank" rel="noopener" style="
               color:#9ecbff;text-decoration:none;border:1px solid #2a3346;border-radius:7px;
               padding:5px 10px;font-size:12.5px">${escapeHtml(t.label)} ↗</a>`
          : `<span style="color:#c4ccdb;border:1px solid #2a3346;border-radius:7px;
               padding:5px 10px;font-size:12.5px">${escapeHtml(t.label)}</span>`).join("")}
      </div>
    </div>` : "";

  // "How to fix", concrete remediation steps from the verdict, shown inline.
  const fixes = (verdict.remediation || []).slice(0, 4);
  const fix = fixes.length ? `
    <div style="margin-top:14px;padding:11px 13px;background:rgba(77,163,255,.08);
        border:1px solid rgba(77,163,255,.32);border-radius:10px">
      <div style="font-weight:700;color:#9ecbff;font-size:13px">How to fix</div>
      <ul style="margin:6px 0 0;padding-left:18px;color:#c4ccdb;font-size:12.5px">
        ${fixes.map((f) => `<li style="margin:3px 0">${escapeHtml(f)}</li>`).join("")}
      </ul>
    </div>` : "";

  const wrap = document.createElement("div");
  wrap.id = "palivane-modal";
  wrap.style.cssText = [
    "position:fixed", "inset:0", "z-index:2147483647",
    "background:rgba(10,12,18,.55)", "backdrop-filter:blur(2px)",
    "display:flex", "align-items:center", "justify-content:center",
    "font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif",
  ].join(";");
  wrap.innerHTML = `
    <div role="alertdialog" aria-modal="true" style="
        width:460px;max-width:92vw;background:#151926;color:#e6e9f0;
        border:1px solid #2a3346;border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.5);
        padding:22px 24px">
      <div style="display:flex;align-items:center;gap:10px;font-size:17px;font-weight:800">
        <span style="color:#ff5d6c">🛡</span> Palivane blocked this message
      </div>
      <p style="color:#c4ccdb;margin:12px 0 6px">
        It was <strong>not sent</strong> to the AI tool because it contained ${reasonText(verdict)}.
      </p>
      <ul style="margin:8px 0 4px;padding-left:18px;color:#e6e9f0">${rows}</ul>
      ${fix}
      ${alt}
      <div style="color:#8a93a6;font-size:12px;margin-top:12px">
        risk ${riskText(verdict)} ·
        the AI tool may show a "failed to send" error, that's the block working.
      </div>
      <div style="display:flex;gap:8px;margin-top:18px">
        <button id="palivane-modal-x" style="
          flex:1;padding:11px;border:none;border-radius:8px;
          background:#4da3ff;color:#04101f;font-weight:700;font-size:14px;cursor:pointer">
          Edit my message
        </button>
        <button id="palivane-modal-exc" style="
          padding:11px 14px;border:1px solid #2a3346;border-radius:8px;background:transparent;
          color:#c4ccdb;font-size:13px;cursor:pointer">
          Request exception
        </button>
      </div>
    </div>`;
  const close = () => wrap.remove();
  wrap.addEventListener("click", (e) => { if (e.target === wrap) close(); });
  document.documentElement.appendChild(wrap);
  const btn = document.getElementById("palivane-modal-x");
  btn.addEventListener("click", close);
  btn.focus();

  document.getElementById("palivane-modal-exc").addEventListener("click", async (e) => {
    const b = e.currentTarget;
    b.disabled = true; b.textContent = "Sending...";
    try {
      const r = await chrome.runtime.sendMessage({
        type: "exception",
        payload: {
          finding_id: verdict.finding_id || null,
          destination: (verdict.signals || []).find((s) => s.category === "unsanctioned_ai")?.evidence || "",
          categories: dataSignals(verdict).map((s) => s.category),
          reason: "Requested from the block screen",
        },
      });
      b.textContent = r && r.ok ? "✓ Request sent" : "Couldn't send";
      b.style.color = r && r.ok ? "#4ade80" : "#ff9d9d";
    } catch (_) { b.textContent = "Couldn't send"; b.style.color = "#ff9d9d"; }
  });

  document.addEventListener("keydown", function esc(e) {
    if (e.key === "Escape") { close(); document.removeEventListener("keydown", esc); }
  });
}

// --- Warn: a lightweight top banner (content was sent, just flagged) ---
function showWarnBanner(verdict) {
  const id = "palivane-banner";
  document.getElementById(id)?.remove();
  const el = document.createElement("div");
  el.id = id;
  el.style.cssText = [
    "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
    "padding:12px 18px", "font:14px/1.45 system-ui,sans-serif", "color:#fff",
    "box-shadow:0 2px 14px rgba(0,0,0,.45)", "background:#b8791f",
  ].join(";");
  el.innerHTML =
    `<strong>⚠ Palivane warning</strong> ` +
    `<span style="opacity:.95">Detected ${reasonText(verdict)} ` +
    `(risk ${riskText(verdict)}). Review before sending sensitive data.</span>`;
  const close = document.createElement("span");
  close.textContent = "✕";
  close.style.cssText = "cursor:pointer;float:right;opacity:.85;font-weight:700;margin-left:12px";
  close.onclick = () => el.remove();
  el.prepend(close);
  document.documentElement.appendChild(el);
  setTimeout(() => el.remove(), 8000);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

// Only allow http(s) links, an org's sanctioned-tool URL is free text, and escapeHtml
// does NOT neutralize a `javascript:` scheme, which would run in the AI tool's origin.
function safeUrl(u) {
  try {
    const p = new URL(String(u), location.href).protocol;
    return (p === "http:" || p === "https:") ? String(u) : "";
  } catch (_) { return ""; }
}

// Coerce backend-typed verdict scalars before interpolating into innerHTML (defense in
// depth, and safe if a spoofed message supplies odd shapes): numeric risk, alnum severity.
function riskText(v) {
  const r = Number(v && v.risk_score);
  const sev = String((v && v.severity) || "").replace(/[^a-zA-Z]/g, "").toUpperCase();
  return `${Number.isFinite(r) ? r : "?"}/${sev}`;
}
