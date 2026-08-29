// Runs in the PAGE context. Wraps window.fetch so we can inspect a prompt *before*
// it's sent to the AI tool, ask Palivane for a verdict, and block/warn inline.
// Communicates with the content script (isolated world) via window.postMessage.
(() => {
  const PENDING = new Map();
  let SEQ = 0;

  // URL patterns that look like "the user is submitting a prompt".
  const SEND_PATTERNS = [
    /\/backend-api\/(f\/)?conversation\b/, // chatgpt.com
    /\/completion\b/,                      // claude.ai, deepseek (/chat/completion)
    /\/append_message\b/,                  // claude.ai (older)
    /\/retry_completion\b/,
    /\/chat_conversations\/.+\/(completion|messages)\b/, // claude.ai (current)
    /GenerateContent|StreamGenerate/i,     // gemini, Google AI Studio (aistudio)
    /\/v1\/(chat\/completions|messages|responses)\b/,    // OpenAI/Anthropic-style APIs
    /perplexity_ask\b/,                    // perplexity.ai (SSE ask)
    /\/api\/chat\b/,                       // mistral (Le Chat) + generic /api/chat
    /\/app-chat\/conversations\b/,         // grok.com
    /\/gql_POST\b/,                        // poe.com (GraphQL sendMessage)
  ];
  const looksLikeSend = (url) => SEND_PATTERNS.some((re) => re.test(url));

  function extractPrompt(bodyText) {
    if (!bodyText) return "";
    try {
      const j = JSON.parse(bodyText);
      if (Array.isArray(j.messages)) {            // OpenAI/ChatGPT shape
        const parts = [];
        for (const m of j.messages) {
          const role = (m.author && m.author.role) || m.role;
          if (role && role !== "user") continue;
          const c = m.content;
          if (typeof c === "string") parts.push(c);
          else if (c && Array.isArray(c.parts)) parts.push(c.parts.filter((p) => typeof p === "string").join("\n"));
        }
        if (parts.length) return parts.join("\n");
      }
      if (typeof j.prompt === "string") return j.prompt;   // claude.ai
      if (typeof j.text === "string") return j.text;
      if (typeof j.message === "string") return j.message;            // grok, misc chat apps
      if (typeof j.query === "string") return j.query;                // misc search-style
      if (typeof j.query_str === "string") return j.query_str;        // perplexity
      if (j.params && typeof j.params.query_str === "string") return j.params.query_str; // perplexity
      if (typeof j.input === "string") return j.input;
      // Poe (GraphQL): the user's text rides in variables, grab the longest string field.
      if (j.variables && typeof j.variables === "object") {
        const v = Object.values(j.variables).filter((x) => typeof x === "string");
        if (v.length) return v.sort((a, b) => b.length - a.length)[0];
      }
    } catch (_) { /* not JSON, fall through */ }
    return String(bodyText).slice(0, 8000);
  }

  function scan(content, destination) {
    return new Promise((resolve) => {
      const id = ++SEQ;
      PENDING.set(id, resolve);
      window.postMessage({ __palivane: true, kind: "scan", id, content, destination }, "*");
      // Fail OPEN: never break the user's tool if Palivane is slow/unreachable.
      setTimeout(() => {
        if (PENDING.has(id)) { PENDING.delete(id); resolve({ action: "allow" }); }
      }, 4000);
    });
  }

  window.addEventListener("message", (e) => {
    if (e.source !== window) return;   // only our content-script relay, same window
    const d = e.data;
    if (!d || !d.__palivane || d.kind !== "verdict") return;
    const resolve = PENDING.get(d.id);
    if (resolve) { PENDING.delete(d.id); resolve(d.verdict || { action: "allow" }); }
  });

  const DEBUG = false; // flip to true to log captured requests/verdicts to the page console (per-site tuning)

  // Some tools (e.g. Microsoft Copilot) stream prompts over a WebSocket, which
  // fetch/XHR wrapping can't see. Pull the user's text out of a "send"-type frame.
  function wsPrompt(data) {
    if (typeof data !== "string" || data.length < 4) return "";
    let j;
    try { j = JSON.parse(data); } catch (_) { return ""; }
    const ev = j.event || j.type || "";
    if (!/^(send|append|message|userMessage|chat)$/i.test(ev)) return "";  // only user turns
    const parts = [];
    const c = j.content;
    if (typeof c === "string") parts.push(c);
    else if (Array.isArray(c)) for (const b of c) { if (b && typeof b.text === "string") parts.push(b.text); }
    if (typeof j.text === "string") parts.push(j.text);
    if (typeof j.prompt === "string") parts.push(j.prompt);
    return parts.join("\n").trim();
  }

  try {
    const OrigWS = window.WebSocket;
    if (OrigWS) {
      const WrappedWS = function (url, protocols) {
        if (DEBUG) console.debug("[Palivane] WebSocket open", url);
        const ws = protocols === undefined ? new OrigWS(url) : new OrigWS(url, protocols);
        const origWsSend = ws.send.bind(ws);
        ws.send = function (data) {
          try {
            const prompt = wsPrompt(data);
            if (prompt) {
              if (DEBUG) console.log("[Palivane] ws user-send captured chars=", prompt.length,
                "snippet=", prompt.slice(0, 80));
              scan(prompt, location.origin).then((verdict) => {
                if (DEBUG) console.log("[Palivane] ws verdict", verdict.action, verdict.severity, verdict.risk_score);
                if (verdict.action === "block") {
                  // Drop the frame, the prompt never leaves, and show the block UI.
                  window.postMessage({ __palivane: true, kind: "blocked", verdict }, "*");
                  return;
                }
                if (verdict.action === "warn") {
                  window.postMessage({ __palivane: true, kind: "warn", verdict }, "*");
                }
                origWsSend(data);   // allowed → send the frame for real
              });
              return;   // defer this frame until the verdict resolves
            }
          } catch (_) { /* fail open */ }
          return origWsSend(data);
        };
        return ws;
      };
      WrappedWS.prototype = OrigWS.prototype;
      WrappedWS.CONNECTING = OrigWS.CONNECTING; WrappedWS.OPEN = OrigWS.OPEN;
      WrappedWS.CLOSING = OrigWS.CLOSING; WrappedWS.CLOSED = OrigWS.CLOSED;
      window.WebSocket = WrappedWS;
    }
  } catch (_) { /* leave WebSocket alone on failure */ }

  // Coerce fetch/XHR bodies of any shape to scannable text. Gemini and some apps use
  // URLSearchParams / FormData rather than a JSON string.
  function bodyToText(body) {
    if (body == null) return "";
    if (typeof body === "string") return body;
    try {
      if (body instanceof URLSearchParams) return decodeURIComponent(body.toString());
      if (typeof FormData !== "undefined" && body instanceof FormData) {
        const out = [];
        for (const [k, v] of body.entries()) if (typeof v === "string") out.push(v);
        return out.join("\n");
      }
    } catch (_) { /* fall through */ }
    return "";
  }

  const origFetch = window.fetch;
  window.fetch = async function (input, init) {
    try {
      const url = typeof input === "string" ? input : (input && input.url) || "";
      const method = ((init && init.method) || (input && input.method) || "GET").toUpperCase();
      const bodyText = bodyToText(init && init.body);
      if (DEBUG && method === "POST") {
        console.debug("[Palivane] fetch POST", url, "match=", looksLikeSend(url),
          "bodyChars=", bodyText.length);
      }
      if (method === "POST" && looksLikeSend(url) && bodyText) {
        const prompt = extractPrompt(bodyText);
        if (DEBUG) console.log("[Palivane] captured", url, "promptChars=", (prompt || "").length,
          "snippet=", (prompt || "").slice(0, 80));
        if (prompt && prompt.trim()) {
          const verdict = await scan(prompt, location.origin);
          if (DEBUG) console.log("[Palivane] verdict", verdict.action, verdict.severity, verdict.risk_score);
          if (verdict.action === "block") {
            window.postMessage({ __palivane: true, kind: "blocked", verdict }, "*");
            return new Response(JSON.stringify({ error: "Blocked by Palivane: sensitive data detected." }),
              { status: 451, headers: { "content-type": "application/json" } });
          }
          if (verdict.action === "warn") {
            window.postMessage({ __palivane: true, kind: "warn", verdict }, "*");
          }
        }
      }
    } catch (_) { /* fail open */ }
    return origFetch.apply(this, arguments);
  };

  // --- XMLHttpRequest interception (Gemini and other apps submit prompts via XHR) ---
  // Blocking an XHR: we defer the real send until the verdict resolves, then either
  // send it or synthesize a network failure (data never leaves) + show the block UI.
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url) {
    this.__palivane = { method: String(method || "GET").toUpperCase(), url: url || "" };
    return origOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function (body) {
    try {
      const info = this.__palivane;
      if (info && info.method === "POST" && looksLikeSend(info.url)) {
        const bodyText = bodyToText(body);
        if (DEBUG) console.debug("[Palivane] xhr POST", info.url, "match= true bodyChars=", bodyText.length);
        const prompt = bodyText ? extractPrompt(bodyText) : "";
        if (prompt && prompt.trim()) {
          const xhr = this, args = arguments;
          scan(prompt, location.origin).then((verdict) => {
            if (DEBUG) console.log("[Palivane] xhr verdict", verdict.action, verdict.severity, verdict.risk_score);
            if (verdict.action === "block") {
              window.postMessage({ __palivane: true, kind: "blocked", verdict }, "*");
              // Don't send. Signal a network failure so the app's error path runs;
              // the sensitive body never left the browser.
              try {
                Object.defineProperty(xhr, "readyState", { value: 4, configurable: true });
                Object.defineProperty(xhr, "status", { value: 0, configurable: true });
              } catch (_) { /* native props may be non-configurable; events still fire */ }
              try { xhr.dispatchEvent(new Event("readystatechange")); } catch (_) {}
              try { xhr.dispatchEvent(new ProgressEvent("error")); } catch (_) {}
              try { xhr.dispatchEvent(new ProgressEvent("loadend")); } catch (_) {}
              return;
            }
            if (verdict.action === "warn") {
              window.postMessage({ __palivane: true, kind: "warn", verdict }, "*");
            }
            origSend.apply(xhr, args);   // allowed → send for real
          });
          return;   // defer the real send until the verdict resolves
        }
      }
    } catch (_) { /* fail open */ }
    return origSend.apply(this, arguments);
  };
})();
