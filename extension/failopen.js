// The scan-failed ledger, the same shape the CLI keeps in ~/.palivane/scan-failed-*.json:
// counts, a fixed reason vocabulary, first and last time. Never content, never a URL,
// never the error's text. The service worker stores it in chrome.storage.local and
// attaches it to the next request that reaches the backend (SEC-01). Copied as plain
// functions so a test can run the rules without Chrome.
(function (root) {
  var REASONS = ["timeout", "network", "server-error", "auth-rejected", "rate-limited",
                 "http-error", "bad-response", "breaker-open", "error", "update-failed",
                 "unparsed-prompt"];
  var MAX = 1000000;
  var REASON_SET = {};
  for (var i = 0; i < REASONS.length; i++) REASON_SET[REASONS[i]] = true;

  function failureReason(exc) {
    if (typeof exc === "string") return REASON_SET[exc] ? exc : "error";
    if (typeof exc === "number" && isFinite(exc)) {
      var code = exc | 0;
      if (code === 401 || code === 403) return "auth-rejected";
      if (code === 429) return "rate-limited";
      return code >= 500 ? "server-error" : "http-error";
    }
    var name = exc && exc.name;
    if (name === "AbortError" || name === "TimeoutError") return "timeout";
    if (name === "SyntaxError") return "bad-response";
    // A fetch that cannot reach the backend throws TypeError ("Failed to fetch").
    return "network";
  }

  function clean(st) {
    if (!st || typeof st !== "object") return {};
    var reasons = {};
    var raw = st.reasons;
    var n = 0;
    if (raw && typeof raw === "object") {
      for (var k in raw) {
        if (!Object.prototype.hasOwnProperty.call(raw, k)) continue;
        var v = raw[k];
        if (REASON_SET[k] && typeof v === "number" && v > 0 && isFinite(v) && Math.floor(v) === v) {
          reasons[k] = Math.min(v, MAX);
          n++;
          if (n >= 32) break;
        }
      }
    }
    var keys = Object.keys(reasons);
    if (!keys.length) return {};
    var sum = 0;
    for (var i = 0; i < keys.length; i++) sum += reasons[keys[i]];
    var out = { count: Math.min(sum, MAX), reasons: reasons };
    for (var t = 0; t < 2; t++) {
      var field = t === 0 ? "first" : "last";
      var ts = st[field];
      if (typeof ts === "number" && ts > 0 && isFinite(ts)) out[field] = Math.floor(ts);
    }
    return out;
  }

  function merge(a, b) {
    var reasons = {};
    var left = (a && a.reasons) || {};
    var right = (b && b.reasons) || {};
    var k;
    for (k in left) if (Object.prototype.hasOwnProperty.call(left, k)) reasons[k] = left[k];
    for (k in right) {
      if (!Object.prototype.hasOwnProperty.call(right, k)) continue;
      reasons[k] = (reasons[k] || 0) + right[k];
    }
    var firsts = [];
    var lasts = [];
    if (a && typeof a.first === "number") firsts.push(a.first);
    if (b && typeof b.first === "number") firsts.push(b.first);
    if (a && typeof a.last === "number") lasts.push(a.last);
    if (b && typeof b.last === "number") lasts.push(b.last);
    return clean({
      reasons: reasons,
      first: firsts.length ? Math.min.apply(null, firsts) : null,
      last: lasts.length ? Math.max.apply(null, lasts) : null,
    });
  }

  // state is { pending, claim }, each a ledger object or null. The claim is the tally
  // already attached to a request that has not been answered yet. A new failure folds it
  // back so a delivery that itself failed open is not lost.
  function recordFailure(state, reason, now) {
    state = state || {};
    var bump = { reasons: {}, first: now, last: now };
    bump.reasons[failureReason(reason)] = 1;
    return { pending: merge(merge(clean(state.pending), clean(state.claim)), bump), claim: null };
  }

  function takeClaim(state) {
    state = state || {};
    // An undelivered claim from a request that never answered is part of the tally,
    // not a second ledger. Merging it in is what the CLI's orphan sweep does.
    var pending = merge(clean(state.pending), clean(state.claim));
    if (!pending.count) return { state: { pending: null, claim: null }, report: null };
    return { state: { pending: null, claim: pending }, report: pending };
  }

  function dropClaim(state) {
    state = state || {};
    return { pending: clean(state.pending), claim: null };
  }

  var api = {
    REASONS: REASONS, MAX: MAX, failureReason: failureReason, clean: clean, merge: merge,
    recordFailure: recordFailure, takeClaim: takeClaim, dropClaim: dropClaim,
  };
  root.palivaneFailOpen = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
