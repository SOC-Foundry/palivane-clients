// Isolated-world content script. Relays scan requests from the MAIN-world interceptor
// (injected.js, registered as a world:MAIN content script) to the background worker,
// and renders the warn/block UI. injected.js no longer needs to be injected via a
// <script> tag, that was blocked by strict-CSP sites like Microsoft Copilot.

// Private channel to injected.js. window.postMessage is readable and forgeable by every page
// script (`e.source === window` holds for them too), so a page could summon a fake block modal,
// file findings in the user's name, or answer a pending scan with "allow". Instead both scripts
// talk over DOM events named after a random secret that only they know. The secret is handed
// over at document_start, before any page script exists to listen: we offer it on load (when
// injected.js loaded first), and answer injected.js's hello once (when we loaded first).
// injected.js acknowledges, after which neither handshake event is answered again.
const SECRET = Array.from(crypto.getRandomValues(new Uint8Array(16)),
                          (b) => b.toString(16).padStart(2, "0")).join("");
const CHANNEL = "palivane:" + SECRET;
let linked = false;
const offerKey = () => document.dispatchEvent(new CustomEvent("palivane:key", { detail: SECRET }));
document.addEventListener("palivane:ack", function ack() {
  linked = true;
  document.removeEventListener("palivane:ack", ack);
});
function onHello() {
  document.removeEventListener("palivane:hello", onHello);
  if (!linked) offerKey();
}
document.addEventListener("palivane:hello", onHello);
offerKey();
if (linked) document.removeEventListener("palivane:hello", onHello);

function reply(msg) {
  document.dispatchEvent(new CustomEvent(CHANNEL + ":down", { detail: JSON.stringify(msg) }));
}

document.addEventListener(CHANNEL + ":up", async (e) => {
  let d;
  try { d = JSON.parse(e.detail); } catch (_) { return; }
  if (!d) return;

  if (d.kind === "scan") {
    let verdict = { action: "allow" };
    try {
      verdict = await chrome.runtime.sendMessage({
        type: "scan", content: d.content, destination: d.destination, endpoint: d.endpoint,
        partial: !!d.partial, ...(resendOf(d.content) ? { redactedFrom: resendOf(d.content) } : {}),
      });
      if (verdict && verdict.redacted_resend) pendingResend = null;   // recorded: one use
    } catch (_) {
      // The extension was updated or reloaded under this tab: its old content script can no
      // longer reach it, so every message from here on goes out unchecked until the tab reloads.
      verdict = { action: "allow", skipped: "reload this tab" };
    }
    if (verdict && verdict.skipped) noteSkipped(verdict.skipped);
    reply({ kind: "verdict", id: d.id, verdict: verdict || { action: "allow" } });
  } else if (d.kind === "blocked") {
    showUi(d.kind, d.verdict, typeof d.prompt === "string" ? d.prompt : null);
  } else if (d.kind === "warn" || d.kind === "late") {
    showUi(d.kind, d.verdict);
  } else if (d.kind === "skipped") {
    noteSkipped(d.reason);
  } else if (d.kind === "blind") {
    try { chrome.runtime.sendMessage({ type: "blind", destination: d.destination }); } catch (_) { /* fail open */ }
  }
});

// --- Where the UI goes ---
// This script runs in every frame (a send from an iframe is checked like any other), but a
// modal inside a small embedded frame can be clipped or invisible. A subframe asks the
// background worker to show it in the tab's top frame, and draws it itself only when that
// fails (the top frame is a site this extension does not run on, say).
function renderUi(kind, data, prompt = null) {
  if (kind === "blocked") showBlockModal(data, prompt);
  else if (kind === "warn") showWarnBanner(data);
  else if (kind === "late") showLateNotice(data);
  else if (kind === "skipped") showSkippedNotice(data);
}

async function showUi(kind, data, prompt = null) {
  // "Send with these removed" edits the message box the person typed in, which lives in THIS
  // frame. When it can be offered here, draw the modal here; otherwise relay it as before (the
  // top frame then shows the plain block, with no redaction offer).
  if (kind === "blocked" && prompt !== null && redactOffer(data) && findComposer()) {
    renderUi(kind, data, prompt);
    return;
  }
  if (window !== window.top) {
    try {
      const r = await chrome.runtime.sendMessage({ type: "ui", kind, data });
      if (r && r.ok) return;
    } catch (_) { /* extension unreachable: draw it here */ }
  }
  renderUi(kind, data);
}

// The top frame's half of the relay. Only the background worker can send this.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (window !== window.top || !msg || msg.type !== "palivane-ui") return;
  renderUi(msg.kind, msg.data);
  sendResponse({ ok: true });
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
    .map((s) => escapeHtml(CATEGORY_LABELS[s.category] || s.category).toLowerCase());
  // Callers interpolate this into innerHTML: an unknown category is free text, escaped above.
  if (!labels.length) return "sensitive content";
  if (labels.length === 1) return labels[0];
  return labels.slice(0, -1).join(", ") + " and " + labels[labels.length - 1];
}

// --- Block: a prominent, explanatory modal (so claude.ai's own fetch error reads as expected) ---
function showBlockModal(verdict, prompt = null) {
  document.getElementById("palivane-modal")?.remove();
  // Redact-on-block: the org allows it and the backend proved that removing these values clears
  // the block. Offered only with the scanned text in hand (the offsets point into it) and a
  // message box in this frame to put the edited text in.
  const redact = prompt !== null && redactOffer(verdict) && findComposer();
  const redactLabels = redact ? [...new Set(verdict.redactions.map((s) => String(s.label)))] : [];
  const redactBox = redact ? `
    <div id="palivane-redact" style="margin-top:14px;padding:11px 13px;background:rgba(63,185,80,.08);
        border:1px solid rgba(63,185,80,.35);border-radius:10px">
      <div style="font-weight:700;color:#4ade80;font-size:13px">Send it without the sensitive parts</div>
      <div style="color:#c4ccdb;font-size:12.5px;margin-top:3px">Removes
        ${redactLabels.map((l) => `<strong>${escapeHtml(l)}</strong>`).join(", ")} from your message,
        shows you the edited text in the message box, and sends that.</div>
      <button id="palivane-redact-go" style="margin-top:8px;padding:8px 12px;border:none;
          border-radius:8px;background:#4ade80;color:#04140b;font-weight:700;font-size:12.5px;cursor:pointer">
        Send with these removed
      </button>
      <div id="palivane-redact-msg" style="color:#ff9d9d;font-size:12px;margin-top:6px" hidden></div>
    </div>` : "";
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

  // Coaching: the org would rather the person send a cleaned version than be hard-stopped.
  // The message is still held, since the original must not leave; this hands them the clean
  // copy to send instead (or an approved tool, above).
  const cleaned = verdict.coached && typeof verdict.redacted_content === "string" ? verdict.redacted_content : "";
  const clean = cleaned ? `
    <div style="margin-top:14px;padding:11px 13px;background:rgba(63,185,80,.08);
        border:1px solid rgba(63,185,80,.35);border-radius:10px">
      <div style="font-weight:700;color:#4ade80;font-size:13px">Cleaned version, sensitive values removed</div>
      <pre id="palivane-clean" style="margin:8px 0 0;white-space:pre-wrap;word-break:break-word;
          max-height:130px;overflow:auto;color:#c4ccdb;font:12px/1.45 ui-monospace,Menlo,Consolas,monospace">${escapeHtml(cleaned)}</pre>
      <button id="palivane-copy-clean" style="margin-top:8px;padding:7px 12px;border:none;
          border-radius:8px;background:#4ade80;color:#04140b;font-weight:700;font-size:12.5px;cursor:pointer">
        Copy cleaned message
      </button>
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
        <span style="color:#ff5d6c">🛡</span> Palivane ${cleaned ? "held" : "blocked"} this message
      </div>
      <p style="color:#c4ccdb;margin:12px 0 6px">
        It was <strong>not sent</strong> to the AI tool because it contained ${reasonText(verdict)}.
      </p>
      <ul style="margin:8px 0 4px;padding-left:18px;color:#e6e9f0">${rows}</ul>
      ${redactBox}
      ${clean}
      ${fix}
      ${alt}
      <div style="color:#8a93a6;font-size:12px;margin-top:12px">
        risk ${riskText(verdict)} ·
        the AI tool may show a "failed to send" error, that's the block working.
      </div>
      ${verdict.self_justify && verdict.finding_id ? `
      <div id="palivane-justify" style="margin-top:14px;padding:11px 13px;
          background:rgba(184,121,31,.10);border:1px solid rgba(184,121,31,.4);border-radius:10px">
        <div style="font-weight:700;color:#e8b04b;font-size:13px">Business need to send this anyway?</div>
        <div style="color:#8a93a6;font-size:12px;margin-top:3px">Your justification is recorded
          for the security team, then pressing send again delivers this exact message.</div>
        <textarea id="palivane-justify-text" rows="2" minlength="10" placeholder="Why this needs to go (10+ characters)…"
          style="width:100%;margin-top:8px;box-sizing:border-box;background:#0f1320;color:#e6e9f0;
                 border:1px solid #2a3346;border-radius:8px;padding:8px;font:12.5px/1.4 inherit;resize:vertical"></textarea>
        <button id="palivane-justify-go" style="margin-top:8px;padding:8px 12px;border:none;
          border-radius:8px;background:#e8b04b;color:#231803;font-weight:700;font-size:12.5px;cursor:pointer">
          Record justification & unlock send
        </button>
      </div>` : ""}
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

  document.getElementById("palivane-redact-go")?.addEventListener("click", async (e) => {
    const b = e.currentTarget;
    const msg = document.getElementById("palivane-redact-msg");
    b.disabled = true; b.textContent = "Removing…";
    const r = await redactAndSend(verdict, prompt);
    if (r.ok) { close(); return; }
    b.disabled = !!r.final;
    b.textContent = r.final ? "Edit your message instead" : "Send with these removed";
    msg.hidden = false; msg.textContent = r.why;
  });

  document.getElementById("palivane-copy-clean")?.addEventListener("click", async (e) => {
    const b = e.currentTarget;
    try {
      await navigator.clipboard.writeText(cleaned);
      b.textContent = "✓ Copied, paste it into the message box";
    } catch (_) {
      // Clipboard blocked on this page: select the text so Ctrl/Cmd+C finishes the job.
      const pre = document.getElementById("palivane-clean");
      const r = document.createRange(); r.selectNodeContents(pre);
      const s = getSelection(); s.removeAllRanges(); s.addRange(r);
      b.textContent = "Selected, press Ctrl/Cmd+C";
    }
  });

  // Justified proceed: record the reason, background stores the override token, the
  // user's next send of the same message goes through (as a warn, audit-logged).
  document.getElementById("palivane-justify-go")?.addEventListener("click", async (e) => {
    const b = e.currentTarget;
    const text = (document.getElementById("palivane-justify-text")?.value || "").trim();
    if (text.length < 10) {
      b.textContent = "Add a few more words (10+ characters)";
      return;
    }
    b.disabled = true; b.textContent = "Recording…";
    try {
      const r = await chrome.runtime.sendMessage({
        type: "justify",
        payload: { finding_id: verdict.finding_id, justification: text },
      });
      if (r && r.ok) {
        b.textContent = "✓ Recorded — press send again to deliver";
        b.style.background = "#2f9e5f"; b.style.color = "#04140b";
      } else {
        b.disabled = false;
        b.textContent = r && r.error === "confirmed"
          ? "Confirmed secret/PII — ask an admin via Request exception"
          : "Couldn't record, try again";
      }
    } catch (_) { b.disabled = false; b.textContent = "Couldn't record, try again"; }
  });

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

// --- Redact-on-block: send the message with the flagged values removed ------------------------
// The verdict's `redactions` are {start, end, start16, end16, label} offsets into the exact text
// that was scanned; this script uses the UTF-16 pair (JavaScript string indexing). The values
// never come from the backend: they are cut out of the text this page already has.
//
// The edit goes into the page's own message box and the page's own send button sends it, so what
// the person sees is what is sent, on every site, and the outgoing request (JSON, form-encoded,
// claude.ai's protobuf RPC, a WebSocket frame) is built by the site as usual and scanned again by
// injected.js like any other send. Nothing rewrites a request body behind the person's back.

const MARK = (label) => `«redacted:${label}»`;          // the same marker stored findings use
let lastComposer = null;                                  // the box the person last typed in
let pendingResend = null;                                 // { findingId, marks, until }

// What counts as a message box: a textarea, a text input, or a rich editor (ProseMirror on
// chatgpt.com and claude.ai, Quill on Gemini), all of which are contenteditable.
function isComposer(el) {
  if (!el || el.nodeType !== 1 || el.closest?.("#palivane-modal")) return false;
  if (el instanceof HTMLTextAreaElement) return !el.disabled && !el.readOnly;
  if (el instanceof HTMLInputElement) return /^(text|search)$/i.test(el.type) && !el.disabled && !el.readOnly;
  return !!el.isContentEditable;
}
function editableRoot(el) {
  if (!el || el.nodeType !== 1) return null;
  if (el.isContentEditable) {                // the outermost editable, not a <p> inside it
    while (el.parentElement && el.parentElement.isContentEditable) el = el.parentElement;
  }
  return isComposer(el) ? el : null;
}
for (const ev of ["focusin", "input", "keydown"]) {
  document.addEventListener(ev, (e) => {
    const el = editableRoot(e.target);
    if (el) lastComposer = el;
  }, true);
}
const visible = (el) => !!el && el.isConnected && el.getClientRects().length > 0;
function findComposer() {
  if (visible(lastComposer)) return lastComposer;
  for (const sel of ["#prompt-textarea", "div.ProseMirror[contenteditable=true]",
                     "rich-textarea [contenteditable=true]", ".ql-editor[contenteditable=true]",
                     "[contenteditable=true][role=textbox]", "textarea"]) {
    const el = editableRoot(document.querySelector(sel));
    if (visible(el)) return el;
  }
  return null;
}

function redactOffer(v) {
  return !!v && v.redactable === true && Array.isArray(v.redactions) && v.redactions.length > 0
    && (v.redaction_mode === "offer" || v.redaction_mode === "auto")   // auto: this client can ask, so it asks
    && v.redactions.every((s) => Number.isInteger(s.start16) && Number.isInteger(s.end16)
                                 && s.end16 > s.start16 && typeof s.label === "string");
}

function readComposer(el) {
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) return el.value;
  return el.innerText;
}
const sameText = (a, b) => a.replace(/\s+$/, "") === b.replace(/\s+$/, "");

// Right to left, so the offsets still ahead of us stay valid as earlier text changes length.
function cut(text, spans, shift = 0) {
  let out = text;
  for (const s of [...spans].sort((a, b) => b.start16 - a.start16)) {
    out = out.slice(0, s.start16 + shift) + MARK(s.label) + out.slice(s.end16 + shift);
  }
  return out;
}

// Put `text` in the box the way typing would, so the page's framework (React, ProseMirror, Quill)
// sees the change. A textarea takes the native value setter plus an input event; a rich editor
// takes an insertText over a select-all, then a paste, then plain text as a last resort.
function writeComposer(el, text) {
  el.focus();
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, text);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return;
  }
  const selectAll = () => {
    const r = document.createRange(); r.selectNodeContents(el);
    const s = getSelection(); s.removeAllRanges(); s.addRange(r);
  };
  selectAll();
  try { document.execCommand("insertText", false, text); } catch (_) { /* try the next way */ }
  if (sameText(readComposer(el), text)) return;
  try {
    selectAll();
    const dt = new DataTransfer(); dt.setData("text/plain", text);
    el.dispatchEvent(new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true }));
  } catch (_) { /* try the next way */ }
  if (sameText(readComposer(el), text)) return;
  el.innerText = text;
  el.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: text }));
}

// The page's own send control nearest the box: a button whose label, test id, id or title says
// send/submit. Failing that, Enter in the box, which every chat site treats as send.
function findSend(el) {
  const re = /\bsend\b|submit/i;
  for (let n = el.parentElement, depth = 0; n && depth < 8; n = n.parentElement, depth++) {
    for (const b of n.querySelectorAll("button, [role=button], input[type=submit]")) {
      if (b.closest("#palivane-modal") || !visible(b)) continue;
      const words = [b.getAttribute("aria-label"), b.getAttribute("data-testid"), b.id, b.title,
                     b.type === "submit" ? "submit" : "", (b.textContent || "").trim().slice(0, 24)].join(" ");
      if (re.test(words)) return b;
    }
  }
  return null;
}
async function pressSend(el) {
  const t0 = Date.now();
  let b = findSend(el);
  // A framework enables its send button a tick after it sees the new text.
  while (b && (b.disabled || b.getAttribute("aria-disabled") === "true") && Date.now() - t0 < 2000) {
    await new Promise((r) => setTimeout(r, 100));
    b = findSend(el);
  }
  if (b && !b.disabled) { b.click(); return; }
  el.focus();
  for (const type of ["keydown", "keypress", "keyup"]) {
    el.dispatchEvent(new KeyboardEvent(type, { key: "Enter", code: "Enter", keyCode: 13, which: 13, bubbles: true, cancelable: true }));
  }
}

// The scan of the edited message is linked to the block it fixes (the backend marks that finding,
// no content), recognised by carrying every marker this click put in. One use, two minutes.
function resendOf(content) {
  const p = pendingResend;
  if (!p || p.until < Date.now() || typeof content !== "string") return null;
  return p.marks.every((m) => content.includes(m)) ? p.findingId : null;
}

// Returns { ok } or { ok: false, why, final }.
async function redactAndSend(verdict, prompt) {
  const el = findComposer();
  if (!el) return { ok: false, final: true, why: "Couldn't find the message box on this page." };
  const now = readComposer(el);
  let base, spans = verdict.redactions, shift = 0, findingId = verdict.finding_id || null;
  if (!now.trim()) {
    base = prompt;                          // the site cleared the box when it tried to send
  } else if (sameText(now, prompt)) {
    base = now;
  } else if (now.indexOf(prompt) >= 0) {
    base = now; shift = now.indexOf(prompt);   // the same text, inside some wrapping
  } else {
    // The text changed after it was checked: old offsets would cut the wrong characters, so
    // check what is in the box now and use that answer instead.
    let v;
    try {
      v = await chrome.runtime.sendMessage({ type: "scan", content: now, destination: location.origin,
                                             endpoint: location.host + location.pathname });
    } catch (_) { return { ok: false, why: "Couldn't reach Palivane to re-check the edited message." }; }
    if (!v || v.skipped) return { ok: false, why: "Couldn't re-check the edited message." };
    if (v.action !== "block" && !v.coached && !v.force_block) {
      el.focus();
      toast("Your edited message passes the check. Press send.");
      return { ok: true };
    }
    if (!redactOffer(v)) return { ok: false, final: true, why: "Removing values won't clear this one. Edit your message." };
    base = now; spans = v.redactions; findingId = v.finding_id || findingId;
  }
  const text = cut(base, spans, shift);
  writeComposer(el, text);
  const marks = [...new Set(spans.map((s) => MARK(s.label)))];
  const got = readComposer(el);
  const removed = spans.map((s) => base.slice(s.start16 + shift, s.end16 + shift));
  if (!marks.every((m) => got.includes(m)) || removed.some((v) => v && got.includes(v))) {
    return { ok: false, final: true, why: "Couldn't edit the message box on this page. Edit your message." };
  }
  pendingResend = { findingId, marks, until: Date.now() + 120000 };
  document.getElementById("palivane-modal")?.remove();     // uncover the edited message box
  const labels = [...new Set(spans.map((s) => s.label))];
  toast(`Removed ${labels.join(", ")}. Sending the edited message…`);
  // A beat so the person sees the edited text in the box before it goes.
  await new Promise((r) => setTimeout(r, 700));
  await pressSend(el);
  return { ok: true };
}

function toast(text) {
  document.getElementById("palivane-toast")?.remove();
  const el = document.createElement("div");
  el.id = "palivane-toast";
  el.setAttribute("role", "status");
  el.style.cssText = [
    "position:fixed", "bottom:22px", "left:50%", "transform:translateX(-50%)", "z-index:2147483647",
    "padding:10px 16px", "border-radius:10px", "font:13.5px/1.4 system-ui,sans-serif", "color:#04140b",
    "background:#4ade80", "box-shadow:0 6px 24px rgba(0,0,0,.35)", "max-width:90vw",
  ].join(";");
  el.textContent = "🛡 " + text;
  document.documentElement.appendChild(el);
  setTimeout(() => el.remove(), 6000);
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

// --- Notices: a check that did not happen, or happened too late ---
// Fail-open means a broken check looks exactly like a clean one. These make the difference
// visible: the banner here, the toolbar badge and popup line via the background worker.
function showNotice(html, color) {
  const id = "palivane-notice";
  document.getElementById(id)?.remove();
  const el = document.createElement("div");
  el.id = id;
  el.style.cssText = [
    "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
    "padding:12px 18px", "font:14px/1.45 system-ui,sans-serif", "color:#fff",
    "box-shadow:0 2px 14px rgba(0,0,0,.45)", `background:${color}`,
  ].join(";");
  el.innerHTML = html;
  const close = document.createElement("span");
  close.textContent = "✕";
  close.style.cssText = "cursor:pointer;float:right;opacity:.85;font-weight:700;margin-left:12px";
  close.onclick = () => el.remove();
  el.prepend(close);
  document.documentElement.appendChild(el);
  setTimeout(() => el.remove(), 10000);
}

// One banner every five minutes, not one per message: a backend that is down for an hour
// should not nag on every send. The popup and badge carry the persistent state.
let lastSkipNotice = 0;
function noteSkipped(reason) {
  try { chrome.runtime.sendMessage({ type: "skipped", reason: String(reason || "") }); } catch (_) { /* fail open */ }
  const now = Date.now();
  if (now - lastSkipNotice < 5 * 60 * 1000) return;
  lastSkipNotice = now;
  showUi("skipped", String(reason || ""));
}

function showSkippedNotice(reason) {
  showNotice(`<strong>Palivane could not check that message</strong> ` +
             `<span style="opacity:.95">(${escapeHtml(reason || "unknown")}), so it was sent unchecked.</span>`, "#475569");
}

function showLateNotice(verdict) {
  showNotice(`<strong>Palivane found ${reasonText(verdict)} in that message,</strong> ` +
             `<span style="opacity:.95">but its answer arrived after the message was sent. ` +
             `Tell your security team if this was real data.</span>`, "#c0283a");
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
