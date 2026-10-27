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
    /\/claudeai-rpc\/[^/]*ConversationService\/PerformAction\b/, // claude.ai (current): a Connect/protobuf RPC
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

  // claude.ai no longer posts JSON to /completion. A message is a Connect RPC, PerformAction, whose
  // body is a protobuf: the typed text is one string field among ids (conversation, message and
  // session uuids), a locale and a timezone. Decoding that as UTF-8 text would scan the ids and
  // miss nothing, but every uuid is random-looking, so it is walked as protobuf and the ids are set
  // aside. Which field holds the text is not assumed (the schema is v1alpha): every string that is
  // not an id is the message.
  const OPAQUE_ID = [
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,   // uuid
    /^sess_[0-9a-f]+$/i,                                                 // session id
    /^\d{9,}-\d+$/,                                                      // timeline cursor
    /^[a-z]{2,3}(-[A-Za-z]{2,4})?$/,                                     // locale, en-US
    /^[A-Z][A-Za-z]+(\/[A-Z][A-Za-z_]+)+$/,                              // timezone, America/Chicago
  ];
  function protoWalk(buf, out, depth) {
    const n = buf.length;
    let i = 0;
    const found = [];
    const varint = () => {
      let v = 0, shift = 0, b;
      do {
        if (i >= n) return null;
        b = buf[i++];
        v += (b & 0x7f) * Math.pow(2, shift);
        shift += 7;
      } while ((b & 0x80) && shift < 63);
      return v;
    };
    while (i < n) {
      const tag = varint();
      if (tag === null || tag === 0) return false;
      const wire = tag % 8;
      if (wire === 0) { if (varint() === null) return false; }
      else if (wire === 1) { i += 8; if (i > n) return false; }
      else if (wire === 5) { i += 4; if (i > n) return false; }
      else if (wire === 2) {
        const len = varint();
        if (len === null || i + len > n) return false;
        const sub = buf.subarray(i, i + len);
        i += len;
        const nested = [];
        if (depth < 8 && len > 1 && protoWalk(sub, nested, depth + 1) && nested.length) found.push(...nested);
        else {
          let t = null;
          try { t = new TextDecoder("utf-8", { fatal: true }).decode(sub); } catch (_) { /* binary */ }
          if (t !== null && !/[\u0000-\u0008\u000e-\u001f]/.test(t)) found.push(t);
        }
      } else return false;
    }
    out.push(...found);
    return true;
  }
  // The typed text of a claude.ai RPC body, "" when it carries none (most calls are state), or null
  // when the body is not protobuf at all (the caller then scans it as text, never skips it).
  function protoPrompt(u8) {
    let buf = u8;
    if (u8.length > 5 && (u8[0] === 0 || u8[0] === 1)) {          // Connect envelope: flag + length
      const len = ((u8[1] << 24) | (u8[2] << 16) | (u8[3] << 8) | u8[4]) >>> 0;
      if (len === u8.length - 5) {
        if (u8[0] === 1) { reportBlind(); return ""; }               // compressed: cannot read it
        buf = u8.subarray(5);
      }
    }
    const leaves = [];
    if (!protoWalk(buf, leaves, 0)) return null;
    return leaves.filter((t) => t.trim() && !OPAQUE_ID.some((re) => re.test(t))).join("\n");
  }
  const isRpc = (url) => /\/claudeai-rpc\//.test(String(url));
  // What to scan for one captured send: the decoded protobuf text for an RPC body, else the usual shapes.
  function promptFrom(url, body) {
    if (isRpc(url) && body.bytes) {
      const typed = protoPrompt(body.bytes);
      if (typed !== null) return typed;
    }
    return body.text ? extractPrompt(body.text) : "";
  }

  // Gemini and Google AI Studio send `f.req=<json>&at=<xsrf token>`. f.req is [null, "<json>"], and
  // the typed text is the first string of the inner array's first element. Everything else in the
  // body (an image upload id, a session uuid, page state ids, the `at` token) is opaque state the
  // page generated, not something the person typed. Scanned as if it were the prompt, each of those
  // random-looking ids read as a possible secret, so an ordinary message was blocked. Returns the
  // typed text, or null when the body is not that shape (the caller then scans the whole thing).
  function geminiPrompt(fReq) {
    try {
      const inner = JSON.parse(JSON.parse(fReq)[1]);
      const first = Array.isArray(inner) ? inner[0] : null;
      if (Array.isArray(first) && typeof first[0] === "string") return first[0];
    } catch (_) { /* not that shape */ }
    return null;
  }

  function extractPrompt(bodyText) {
    if (!bodyText || isTelemetryBody(bodyText)) return "";
    if (bodyText.includes("f.req=")) {
      const typed = geminiPrompt(new URLSearchParams(bodyText).get("f.req"));
      if (typed !== null) return typed;
    }
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

  // partial: this content is only part of the message (the rest was never scanned), so its verdict
  // must not read as a clean check of the whole message (background.js keeps the "unchecked" mark).
  function scan(content, destination, endpoint, partial = false) {
    return new Promise((resolve) => {
      const id = newId();
      PENDING.set(id, resolve);
      if (!post({ kind: "scan", id, content, destination, endpoint, ...(partial ? { partial: true } : {}) })) {
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
    // Past the cap the tail is never scored: report it, and mark every window's scan partial so an
    // allow on the prefix does not clear the "sent unchecked" notice. Still fail open: it goes out.
    const truncated = prompt.length > WINDOW * MAX_WINDOWS;
    if (truncated) { reportBlind(); prompt = prompt.slice(0, WINDOW * MAX_WINDOWS); }
    const parts = [];
    for (let i = 0; ; i += WINDOW - OVERLAP) {
      parts.push(prompt.slice(i, i + WINDOW));
      if (i + WINDOW >= prompt.length) break;
    }
    const verdicts = await Promise.all(parts.map((p) => scan(p, destination, endpoint, truncated)));
    return verdicts.find(stop) || verdicts.find((v) => v.action === "warn") || { action: "allow" };
  }

  // The block notice for content.js. It carries the scanned text when one scan covered all of it,
  // because a verdict's `redactions` are offsets into exactly that string: content.js needs it to
  // offer "send with these removed". A windowed (very long) message has offsets per window, so it
  // gets no offer and keeps the plain block.
  function blockedMsg(verdict, prompt) {
    const whole = typeof prompt === "string" && prompt.length <= WINDOW;
    return { kind: "blocked", verdict, ...(whole ? { prompt } : {}) };
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
                  post(blockedMsg(verdict, prompt));
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
        if (body.has("f.req")) {
          const typed = geminiPrompt(body.get("f.req"));
          if (typed !== null) return { text: typed, unreadable: false };
        }
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
        if (body.byteLength > MAX_BODY_BYTES) return { text: "", unreadable: true };
        const bytes = body instanceof ArrayBuffer ? new Uint8Array(body)
                                                  : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
        return { text: new TextDecoder().decode(bytes), bytes, unreadable: false };
      }
    } catch (_) { /* fall through */ }
    return { text: "", unreadable: true };
  }

  // A page that is told its send failed may simply send it again: claude.ai retries a failed
  // PerformAction on a backoff (about 0.4s, 0.75s, 1s, 2s, 3s, ...). Each retry was scanned, blocked
  // and shown as a fresh popup, so one blocked message produced a stream of them. Two defences:
  // the block is answered the way a Connect client reads as final (HTTP 403, code permission_denied),
  // and an identical send inside BLOCK_QUIET_MS of a block is not a new event: no new popup, and, when
  // the block offers no "send anyway" path, no new scan either. A block that does offer one (a
  // justification) is still re-scanned, so recording the reason and pressing send again works.
  const BLOCK_QUIET_MS = 30000;
  const recentBlocks = new Map();                 // send fingerprint -> { until, rescan }
  function sendKey(url, text) {
    let h = 5381;
    for (let i = 0; i < text.length; i++) h = ((h * 33) ^ text.charCodeAt(i)) >>> 0;
    return endpointOf(url) + "|" + text.length + "|" + h;
  }
  function blockedResponse(url) {
    const rpc = isRpc(url);
    const body = rpc ? { code: "permission_denied", message: "Blocked by Palivane: sensitive data detected." }
                     : { error: "Blocked by Palivane: sensitive data detected." };
    return new Response(JSON.stringify(body), { status: rpc ? 403 : 451, headers: { "content-type": "application/json" } });
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
          else if (isReq && !input.bodyUsed && isRpc(url)) {
            const bytes = new Uint8Array(await input.clone().arrayBuffer());
            body = { text: new TextDecoder().decode(bytes), bytes, unreadable: false };
          }
          else if (isReq && !input.bodyUsed) body = { text: await input.clone().text(), unreadable: false };
          else body = { text: "", unreadable: false };
        } catch (_) { body = { text: "", unreadable: true }; }   // e.g. a locked stream: say so, do not skip in silence
        if (DEBUG) {
          console.debug("[Palivane] fetch POST", url, "bodyChars=", body.text.length, "unreadable=", body.unreadable);
        }
        if (body.unreadable) reportBlind();
        const prompt = promptFrom(url, body);
        if (DEBUG) console.log("[Palivane] captured", url, "promptChars=", (prompt || "").length,
          "snippet=", (prompt || "").slice(0, 80));
        if (prompt && prompt.trim()) {
          const key = sendKey(url, prompt);
          const prior = recentBlocks.get(key);
          const repeat = !!prior && prior.until > Date.now();
          if (repeat && !prior.rescan) {              // a retry of a send already stopped: same answer
            prior.until = Date.now() + BLOCK_QUIET_MS;
            return blockedResponse(url);
          }
          const verdict = await scanAll(prompt, location.origin, endpointOf(url));
          if (DEBUG) console.log("[Palivane] verdict", verdict.action, verdict.severity, verdict.risk_score);
          if (stop(verdict)) {
            recentBlocks.set(key, { until: Date.now() + BLOCK_QUIET_MS,
                                    rescan: !!(verdict.self_justify && verdict.finding_id) });
            if (recentBlocks.size > 50) {
              for (const [k, v] of recentBlocks) if (v.until <= Date.now()) recentBlocks.delete(k);
            }
            if (!repeat) post(blockedMsg(verdict, prompt));   // one popup per stopped send, not per retry
            return blockedResponse(url);
          }
          recentBlocks.delete(key);
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
          const prompt = promptFrom(info.url, b);
          if (!(prompt && prompt.trim())) { origSend.apply(xhr, args); return; }
          const verdict = await scanAll(prompt, location.origin, endpointOf(info.url));
          if (DEBUG) console.log("[Palivane] xhr verdict", verdict.action, verdict.severity, verdict.risk_score);
          if (stop(verdict)) {
            post(blockedMsg(verdict, prompt));
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
