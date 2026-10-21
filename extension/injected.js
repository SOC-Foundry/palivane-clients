// Runs in the PAGE context. Wraps window.fetch so we can inspect a prompt *before*
// it's sent to the AI tool, ask Palivane for a verdict, and block/warn inline.
// Communicates with the content script (isolated world) over a private DOM-event channel,
// not window messages: any page script can read and forge those.
(() => {
  const PENDING = new Map();
  const LATE = new Set();   // scans we stopped waiting for; their answer may still arrive

  // --- Private channel to content.js -------------------------------------------------------
  // This runs at document_start, before any page script, so everything the channel relies on
  // is captured here: a page that later patches dispatchEvent, CustomEvent, JSON or crypto
  // can neither read our traffic nor forge it. content.js hands over a random secret during a
  // handshake that completes synchronously before the page can listen; events are then named
  // after the secret, so a page script cannot listen for them or dispatch them.
  const doc = document;
  const dispatch = EventTarget.prototype.dispatchEvent;
  const listen = EventTarget.prototype.addEventListener;
  const unlisten = EventTarget.prototype.removeEventListener;
  const CE = CustomEvent;
  const detailOf = Object.getOwnPropertyDescriptor(CustomEvent.prototype, "detail").get;
  const toJson = JSON.stringify, fromJson = JSON.parse;
  // randomUUID exists only in secure contexts; getRandomValues everywhere.
  const getRandom = crypto.getRandomValues.bind(crypto);
  const newId = crypto.randomUUID ? crypto.randomUUID.bind(crypto)
    : () => Array.from(getRandom(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
  let CHANNEL = "";

  // Send to content.js. False when there is no channel (no content script in this frame).
  function post(msg) {
    if (!CHANNEL) return false;
    try { dispatch.call(doc, new CE(CHANNEL + ":up", { detail: toJson(msg) })); return true; }
    catch (_) { return false; }
  }

  // Answers from content.js. Only these can resolve a scan: nothing the page posts can.
  function onDown(e) {
    let d;
    try { d = fromJson(detailOf.call(e)); } catch (_) { return; }
    if (!d || d.kind !== "verdict") return;
    const resolve = PENDING.get(d.id);
    if (resolve) { PENDING.delete(d.id); resolve(d.verdict || { action: "allow" }); return; }
    // The answer came after we stopped waiting and the message had already gone out. If it
    // would have stopped that message, say so instead of leaving the person to assume it was
    // checked.
    if (LATE.delete(d.id) && stop(d.verdict)) post({ kind: "late", verdict: d.verdict });
  }

  // Handshake, whichever of the two scripts loads first: content.js offers the secret on
  // load, and answers our hello once if it loaded before us. We take the first secret only.
  function onKey(e) {
    const k = detailOf.call(e);
    if (CHANNEL || typeof k !== "string" || !k) return;
    CHANNEL = "palivane:" + k;
    unlisten.call(doc, "palivane:key", onKey);
    listen.call(doc, CHANNEL + ":down", onDown);
    dispatch.call(doc, new CE("palivane:ack"));
  }
  listen.call(doc, "palivane:key", onKey);
  dispatch.call(doc, new CE("palivane:hello"));

  // How long a message waits for Palivane's answer before it goes out unchecked.
  const SCAN_TIMEOUT_MS = 4000;
  // A prompt is text. Past this size a body is an upload, not something to read into memory.
  const MAX_BODY_BYTES = 1 << 20;
  // The backend scores at most 200,000 characters a call and answers 422 above that, which used to
  // read as "Palivane is unavailable" and let the whole message out. A longer message is scanned in
  // windows (concurrently, so the 4s budget is per message, not per window), overlapping a little
  // so a value that straddles a boundary is not cut in two. Past MAX_WINDOWS it is scanned up to
  // there and the rest is reported as unreadable.
  const WINDOW = 150000, OVERLAP = 500, MAX_WINDOWS = 8;

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
  // The page's own analytics and error reporting ride the same patterns (a RUM beacon posted to a
  // `/completion` route, say) and are not something the person typed. A beacon is not a prompt, so
  // it is left alone: by host (the usual vendors) and, for a first-party proxy of one, by shape.
  const TELEMETRY_HOSTS = /(^|[.-])datadoghq\.(com|eu)$|(^|\.)(datadoghq-browser-agent\.com|sentry\.io|segment\.(io|com)|statsig(api)?\.com|featuregates\.org|amplitude\.com|mixpanel\.com|posthog\.com|google-analytics\.com|doubleclick\.net|clarity\.ms|hotjar\.(com|io)|fullstory\.com|logrocket\.(com|io)|cloudflareinsights\.com|launchdarkly\.com|intercom\.io|bugsnag\.com)$/i;
  function parseUrl(url) {
    try { return new URL(url, location.href); } catch (_) { return null; }
  }
  // Only the path says "this is a send"; a query string such as `?ref=/completion` does not.
  const looksLikeSend = (url) => {
    const u = parseUrl(url);
    if (u && TELEMETRY_HOSTS.test(u.hostname)) return false;
    const path = u ? u.pathname : String(url);
    return SEND_PATTERNS.some((re) => re.test(path));
  };
  // Where a captured message was headed: host and path of the request, never the query string
  // (it can carry tokens). It rides with the scan so a finding can say which request it came from,
  // which is what tells a real send from the page's own traffic when a check fires on something odd.
  const endpointOf = (url) => {
    const u = parseUrl(url);
    return u ? (u.host + u.pathname).slice(0, 200) : "";
  };
  // Datadog RUM events carry a `_dd` object; no chat request does.
  const isTelemetryBody = (bodyText) => {
    if (typeof bodyText !== "string" || bodyText.charCodeAt(0) !== 123 /* { */) return false;
    try { const j = JSON.parse(bodyText); return !!j && typeof j === "object" && "_dd" in j; }
    catch (_) { return false; }
  };

  // A verdict that must stop the message. A coached verdict is a block the org softened into a
  // warning on the assumption that the client would show the cleaned version and let the person
  // send THAT; this client holds the message and shows it (content.js), it never lets the
  // original out.
  const stop = (v) => !!v && (v.action === "block" || v.coached === true);

  function extractPrompt(bodyText) {
    if (!bodyText || isTelemetryBody(bodyText)) return "";
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
    return String(bodyText);
  }

  function scan(content, destination, endpoint) {
    return new Promise((resolve) => {
      const id = newId();
      PENDING.set(id, resolve);
      if (!post({ kind: "scan", id, content, destination, endpoint })) {
        PENDING.delete(id); resolve({ action: "allow" }); return;   // no content script here
      }
      // Fail OPEN: never break the user's tool if Palivane is slow/unreachable. But not in
      // silence: a message that went out unchecked is a gap the person has to be able to see.
      setTimeout(() => {
        if (PENDING.has(id)) {
          PENDING.delete(id);
          LATE.add(id);
          post({ kind: "skipped", reason: "no answer in time" });
          resolve({ action: "allow" });
        }
      }, SCAN_TIMEOUT_MS);
    });
  }

  async function scanAll(prompt, destination, endpoint) {
    if (prompt.length <= WINDOW) return scan(prompt, destination, endpoint);
    if (prompt.length > WINDOW * MAX_WINDOWS) { reportBlind(); prompt = prompt.slice(0, WINDOW * MAX_WINDOWS); }
    const parts = [];
    for (let i = 0; ; i += WINDOW - OVERLAP) {
      parts.push(prompt.slice(i, i + WINDOW));
      if (i + WINDOW >= prompt.length) break;
    }
    const verdicts = await Promise.all(parts.map((p) => scan(p, destination, endpoint)));
    return verdicts.find(stop) || verdicts.find((v) => v.action === "warn") || { action: "allow" };
  }

  // A send we could see but not read (a stream, or something too big to be a prompt). Reported
  // so the console can show the blind spot; the message itself still goes out.
  function reportBlind() {
    post({ kind: "blind", destination: location.origin });
  }

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
              scanAll(prompt, location.origin, endpointOf(String(url))).then((verdict) => {
                if (DEBUG) console.log("[Palivane] ws verdict", verdict.action, verdict.severity, verdict.risk_score);
                if (stop(verdict)) {
                  // Drop the frame, the prompt never leaves, and show the block UI.
                  post({ kind: "blocked", verdict });
                  return;
                }
                if (verdict.action === "warn") {
                  post({ kind: "warn", verdict });
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

  // Coerce a fetch/XHR body of any shape to scannable text. Gemini and some apps use
  // URLSearchParams / FormData rather than a JSON string, and a page is free to hand fetch a
  // Blob or a typed array too. `unreadable` means there IS a body we cannot read (a stream, or
  // one too big to be a prompt), so the caller can report it instead of skipping the scan.
  async function readBody(body) {
    if (body == null) return { text: "", unreadable: false };
    if (typeof body === "string") return { text: body, unreadable: false };
    try {
      if (body instanceof URLSearchParams) {
        const raw = body.toString();
        try { return { text: decodeURIComponent(raw), unreadable: false }; }
        catch (_) { return { text: raw, unreadable: false }; }
      }
      if (typeof FormData !== "undefined" && body instanceof FormData) {
        const out = [];
        for (const [, v] of body.entries()) if (typeof v === "string") out.push(v);
        return { text: out.join("\n"), unreadable: false };
      }
      if (typeof Blob !== "undefined" && body instanceof Blob) {
        return body.size > MAX_BODY_BYTES ? { text: "", unreadable: true }
                                          : { text: await body.text(), unreadable: false };
      }
      if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
        return body.byteLength > MAX_BODY_BYTES ? { text: "", unreadable: true }
                                                : { text: new TextDecoder().decode(body), unreadable: false };
      }
    } catch (_) { /* fall through */ }
    return { text: "", unreadable: true };
  }

  const origFetch = window.fetch;
  window.fetch = async function (input, init) {
    try {
      const isReq = typeof Request !== "undefined" && input instanceof Request;
      const url = typeof input === "string" ? input : (input && (input.url || input.href)) || "";
      const method = ((init && init.method) || (isReq && input.method) || "GET").toUpperCase();
      if (method === "POST" && looksLikeSend(url)) {
        // fetch(url, {body}) or fetch(new Request(url, {body})): init.body wins when both exist.
        // A Request's own body is read from a clone, so the page's real send is untouched.
        let body;
        try {
          if (init && init.body != null) body = await readBody(init.body);
          else if (isReq && !input.bodyUsed) body = { text: await input.clone().text(), unreadable: false };
          else body = { text: "", unreadable: false };
        } catch (_) { body = { text: "", unreadable: true }; }   // e.g. a locked stream: say so, do not skip in silence
        if (DEBUG) {
          console.debug("[Palivane] fetch POST", url, "bodyChars=", body.text.length, "unreadable=", body.unreadable);
        }
        if (body.unreadable) reportBlind();
        const prompt = body.text ? extractPrompt(body.text) : "";
        if (DEBUG) console.log("[Palivane] captured", url, "promptChars=", (prompt || "").length,
          "snippet=", (prompt || "").slice(0, 80));
        if (prompt && prompt.trim()) {
          const verdict = await scanAll(prompt, location.origin, endpointOf(url));
          if (DEBUG) console.log("[Palivane] verdict", verdict.action, verdict.severity, verdict.risk_score);
          if (stop(verdict)) {
            post({ kind: "blocked", verdict });
            return new Response(JSON.stringify({ error: "Blocked by Palivane: sensitive data detected." }),
              { status: 451, headers: { "content-type": "application/json" } });
          }
          if (verdict.action === "warn") {
            post({ kind: "warn", verdict });
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
      if (info && info.method === "POST" && looksLikeSend(info.url) && body != null) {
        const xhr = this, args = arguments;
        // Reading a Blob is asynchronous, so the real send is deferred until we know whether
        // there is a prompt in it (and, if so, what Palivane says about it).
        readBody(body).then(async (b) => {
          if (DEBUG) console.debug("[Palivane] xhr POST", info.url, "bodyChars=", b.text.length, "unreadable=", b.unreadable);
          if (b.unreadable) reportBlind();
          const prompt = b.text ? extractPrompt(b.text) : "";
          if (!(prompt && prompt.trim())) { origSend.apply(xhr, args); return; }
          const verdict = await scanAll(prompt, location.origin, endpointOf(info.url));
          if (DEBUG) console.log("[Palivane] xhr verdict", verdict.action, verdict.severity, verdict.risk_score);
          if (stop(verdict)) {
            post({ kind: "blocked", verdict });
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
            post({ kind: "warn", verdict });
          }
          origSend.apply(xhr, args);   // allowed → send for real
        }).catch(() => { try { origSend.apply(xhr, args); } catch (_) { /* fail open */ } });
        return;   // defer the real send until the verdict resolves
      }
    } catch (_) { /* fail open */ }
    return origSend.apply(this, arguments);
  };
})();
