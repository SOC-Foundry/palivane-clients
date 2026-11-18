// The extension's fail-open ledger, without Chrome: the same rules as the CLI file
// (~/.palivane/scan-failed-*.json). Counts and times only.
const test = require("node:test");
const assert = require("node:assert/strict");
const fo = require("./failopen.js");

test("an unreachable backend is a network failure, and the vocabulary matches Fleet", () => {
  assert.equal(fo.failureReason(new TypeError("Failed to fetch")), "network");
  assert.equal(fo.failureReason({ name: "AbortError" }), "timeout");
  assert.equal(fo.failureReason({ name: "TimeoutError" }), "timeout");
  assert.equal(fo.failureReason({ name: "SyntaxError" }), "bad-response");
  assert.equal(fo.failureReason(401), "auth-rejected");
  assert.equal(fo.failureReason(403), "auth-rejected");
  assert.equal(fo.failureReason(429), "rate-limited");
  assert.equal(fo.failureReason(503), "server-error");
  assert.equal(fo.failureReason(404), "http-error");
  assert.equal(fo.failureReason("network"), "network");
  assert.equal(fo.failureReason("quote the prompt"), "error");
  for (const word of ["timeout", "network", "server-error", "auth-rejected", "rate-limited",
                      "http-error", "bad-response", "breaker-open", "error"]) {
    assert.ok(fo.REASONS.includes(word), word);
  }
});

test("a stored tally keeps counts and times, and drops everything else", () => {
  const cleaned = fo.clean({
    count: 99,
    reasons: { network: 2, timeout: true, "not-a-reason": 4, error: 0, "server-error": 1.5 },
    first: 100, last: 200.9,
    content: "AKIAIOSFODNN7EXAMPLE", url: "https://secret.example/path",
  });
  assert.deepEqual(cleaned.reasons, { network: 2 });
  assert.equal(cleaned.count, 2);
  assert.equal(cleaned.first, 100);
  assert.equal(cleaned.last, 200);
  assert.equal(JSON.stringify(cleaned).includes("AKIA"), false);
  assert.equal("content" in cleaned, false);
  assert.equal("url" in cleaned, false);
});

test("only integer reason counts from the fixed vocabulary survive", () => {
  const cleaned = fo.clean({
    reasons: { network: 2, timeout: true, error: 0, "server-error": 3, madeup: 4 },
    note: "the prompt was hello",
  });
  assert.deepEqual(cleaned.reasons, { network: 2, "server-error": 3 });
  assert.equal(cleaned.count, 5);
  assert.equal(JSON.stringify(cleaned).includes("hello"), false);
});

test("a failed delivery folds the claim back and adds the new failure", () => {
  const claimed = fo.takeClaim({ pending: { reasons: { network: 1 }, first: 10, last: 10 }, claim: null });
  assert.deepEqual(claimed.report.reasons, { network: 1 });
  assert.equal(claimed.state.pending, null);
  const again = fo.recordFailure(claimed.state, 503, 40);
  assert.deepEqual(again.pending.reasons, { network: 1, "server-error": 1 });
  assert.equal(again.pending.count, 2);
  assert.equal(again.pending.first, 10);
  assert.equal(again.pending.last, 40);
  assert.equal(again.claim, null);
});

test("a delivered claim is dropped, and the next request sends nothing", () => {
  const claimed = fo.takeClaim({
    pending: { reasons: { network: 1 }, first: 10, last: 12 }, claim: null,
  });
  const done = fo.dropClaim(claimed.state);
  assert.equal(done.claim, null);
  assert.deepEqual(done.pending, {});
  const next = fo.takeClaim(done);
  assert.equal(next.report, null);
});

test("two failures before any delivery add up, and the report has no message text", () => {
  let state = { pending: null, claim: null };
  state = fo.recordFailure(state, new TypeError("Failed to fetch https://app.example/api"), 5);
  state = fo.recordFailure(state, new TypeError("Failed to fetch"), 9);
  const body = JSON.stringify(state.pending);
  assert.deepEqual(state.pending.reasons, { network: 2 });
  assert.equal(state.pending.count, 2);
  assert.equal(body.includes("app.example"), false);
  assert.equal(body.includes("Failed"), false);
  assert.deepEqual(Object.keys(state.pending).sort(), ["count", "first", "last", "reasons"]);
});
