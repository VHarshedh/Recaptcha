/**
 * test_attestation.js — Comprehensive unit tests for the attestation system
 *
 * Run:  node attestation/test_attestation.js
 *
 * Tests all modules: scorer, token, verifier, ip_mask, nonce_cache.
 */

"use strict";

const crypto = require("node:crypto");

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${label}`);
  } else {
    failed++;
    console.error(`  ✗ ${label}`);
  }
}

function assertClose(a, b, label, epsilon = 0.01) {
  assert(Math.abs(a - b) < epsilon, `${label} (got ${a}, expected ~${b})`);
}

/* ================================================================== */
console.log("\n══ ip_mask.js ══");
/* ================================================================== */

const { maskIP } = require("./ip_mask");

assert(maskIP("192.168.1.42") === "192.168.1.0/24", "IPv4 /24 masking");
assert(maskIP("10.0.0.255") === "10.0.0.0/24", "IPv4 /24 last-octet strip");
assert(maskIP("::ffff:10.0.0.5") === "10.0.0.0/24", "IPv4-mapped IPv6 → /24");
assert(maskIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334") === "2001:0db8:85a3::/48", "IPv6 /48 masking");
assert(maskIP("2001:db8:85a3::1") === "2001:0db8:85a3::/48", "IPv6 abbreviated /48");
assert(maskIP("") === "unknown", "empty string → unknown");
assert(maskIP(undefined) === "unknown", "undefined → unknown");
assert(maskIP("garbage") === "unknown", "garbage → unknown");
assert(maskIP("1.2.3.4:443") === "1.2.3.0/24", "IPv4 with port");
assert(maskIP("[::1]:8080") === "0000:0000:0000::/48", "IPv6 bracket+port");

/* ================================================================== */
console.log("\n══ nonce_cache.js ══");
/* ================================================================== */

const { NonceCache } = require("./nonce_cache");

{
  const nc = new NonceCache(5000);
  assert(nc.claim("aaa") === true, "first claim succeeds");
  assert(nc.claim("aaa") === false, "duplicate claim fails (replay)");
  assert(nc.claim("bbb") === true, "different nonce succeeds");
  assert(nc.has("aaa") === true, "has() finds claimed nonce");
  assert(nc.has("zzz") === false, "has() negative for unclaimed");
  assert(nc.size === 2, "size reflects claimed nonces");
  assert(nc.claim("") === false, "empty nonce rejected");
  nc.destroy();
}

/* ================================================================== */
console.log("\n══ scorer.js ══");
/* ================================================================== */

const { computeScore, _scoreRuntime, _scoreHardware, _scoreKinematics, _scorePoW } = require("./scorer");

// Sub-scorers (raw telemetry)
assert(_scoreRuntime({ confidence_penalty: 0.8 }) <= 0.15, "tampered runtime (penalty 0.8) → low");
assert(_scoreRuntime({ confidence_penalty: 0 }) === 1.0, "clean runtime (penalty 0) → 1.0");
assert(_scoreRuntime({ confidence_penalty: 0.2, anomalies: ["1","2","3","4","5","6"] }) < 0.85, "anomalies penalty");
assert(_scoreRuntime(null) === 0, "null runtime → 0");

assert(_scoreHardware({ profile: { hardwareConcurrency: 8 } }) === 1.0, "clean hardware profile → 1.0");
assert(_scoreHardware({ consistency: "discrepancies_observed" }) <= 0.9, "inconsistent hardware → penalized");
assert(_scoreHardware({ webgl: { softwareRasterizers: ["SwiftShader"] } }) < 0.7, "SwiftShader penalty");

assert(_scoreKinematics({ eventCounts: { rejectedUntrusted: 50, mousemove: 5 } }) < 0.25, "rejected untrusted kinematics → penalized");
assert(_scoreKinematics({ eventCounts: { mousemove: 100 }, mouse: { pointCount: 20, entropyRatio: 0.9 } }) > 0.4, "good kinematics → high");

assert(_scorePoW({ serverVerified: true, durationMs: 400, difficulty: 16 }) > 0.7, "server-verified PoW → high");
assert(_scorePoW({ serverVerified: false }) === 0, "unverified PoW → 0");
assert(_scorePoW(null) === 0, "null PoW → 0");

// Composite scoring
{
  const full = computeScore({
    runtime: { confidence_penalty: 0, anomalies: [] },
    hardware: { profile: { hardwareConcurrency: 8 }, consistency: "consistent" },
    kinematics: { eventCounts: { mousemove: 80 }, mouse: { pointCount: 20, entropyRatio: 0.85 } },
    pow: { serverVerified: true, durationMs: 450, difficulty: 16 },
  });
  assert(full.score > 0.7, `full human payload → high score (${full.score})`);
  assert(full.clamped === false, "no clamp for clean payload");
}

// Hard clamp: tampered runtime (confidence_penalty >= 0.5)
{
  const tampered = computeScore({
    runtime: { confidence_penalty: 0.8 },
    hardware: { profile: { hardwareConcurrency: 8 } },
    kinematics: { eventCounts: { mousemove: 50 }, mouse: { pointCount: 15, entropyRatio: 0.9 } },
    pow: { serverVerified: true },
  });
  assert(tampered.score <= 0.1, `tampered → clamped ≤ 0.1 (${tampered.score})`);
  assert(tampered.clamped === true, "clamped flag set");
  assert(tampered.clampReason.includes("tamper"), "clamp reason mentions tamper");
}

// Hard clamp: failed PoW
{
  const noPow = computeScore({
    runtime: { confidence_penalty: 0 },
    hardware: { profile: { hardwareConcurrency: 8 } },
    kinematics: { eventCounts: { mousemove: 50 } },
    pow: { serverVerified: false },
  });
  assert(noPow.score <= 0.1, `failed PoW → clamped ≤ 0.1 (${noPow.score})`);
  assert(noPow.clamped === true, "clamped flag for failed PoW");
}

// Hard clamp: tampered + failed PoW → 0.0
{
  const worst = computeScore({
    runtime: { confidence_penalty: 0.8 },
    pow: { serverVerified: false },
  });
  assert(worst.score === 0.0, "tampered + no PoW → 0.0");
  assert(worst.clampReason.includes("AND"), "worst-case clamp reason");
}

// Missing payload
{
  const empty = computeScore(null);
  assert(empty.score === 0.0, "null payload → 0.0");
}

/* ================================================================== */
console.log("\n══ token.js ══");
/* ================================================================== */

const { issueToken, MIN_TTL_S, MAX_TTL_S } = require("./token");

{
  const { token, claims } = issueToken({ origin: "https://example.test", host: "https://example.test",
    score: 0.85,
    action: "login",
    ipSubnet: "192.168.1.0/24",
  });
  assert(typeof token === "string", "token is a string");
  assert(token.split(".").length === 3, "token has 3 parts");
  assert(claims.score === 0.85, "score preserved");
  assert(claims.action === "login", "action preserved");
  assert(claims.ip_subnet === "192.168.1.0/24", "ip_subnet preserved");
  assert(typeof claims.nonce === "string" && claims.nonce.length === 32, "nonce is 32 hex chars");

  const ttl = claims.exp - claims.iat;
  assert(ttl >= MIN_TTL_S && ttl <= MAX_TTL_S, `TTL in range [${MIN_TTL_S}, ${MAX_TTL_S}]`);
}

// Score clamping
{
  const { claims } = issueToken({ origin: "https://example.test", host: "https://example.test", score: 1.5, action: "test", ipSubnet: "10.0.0.0/24" });
  assert(claims.score <= 1.0, "score clamped to max 1.0");
}
{
  const { claims } = issueToken({ origin: "https://example.test", host: "https://example.test", score: -0.5, action: "test", ipSubnet: "10.0.0.0/24" });
  assert(claims.score >= 0.0, "score clamped to min 0.0");
}

// Bad inputs
{
  let threw = false;
  try { issueToken({ origin: "https://example.test", host: "https://example.test", score: NaN, action: "x", ipSubnet: "10.0.0.0/24" }); }
  catch { threw = true; }
  assert(threw, "NaN score throws");
}
{
  let threw = false;
  try { issueToken({ origin: "https://example.test", host: "https://example.test", score: 0.8, action: "", ipSubnet: "10.0.0.0/24" }); }
  catch { threw = true; }
  assert(threw, "empty action throws");
}

/* ================================================================== */
console.log("\n══ verifier.js ══");
/* ================================================================== */

const { verifyToken: verifyStrict, nonceCache: verifierCache } = require("./verifier");

const verifyToken = (token, opts = {}) => verifyStrict(token, { action: "test", clientIP: "10.0.0.1", origin: "https://example.test", host: "https://example.test", ...opts });

// Valid token round-trip
{
  const { token } = issueToken({ origin: "https://example.test", host: "https://example.test", score: 0.9, action: "checkout", ipSubnet: "10.0.0.0/24" });
  const result = verifyToken(token, {
    clientIP: "10.0.0.42",
    action: "checkout",
    skipNonce: true,  // allow repeated testing
  });
  assert(result.valid === true, "valid token verifies");
  assert(result.claims.score === 0.9, "score round-trips");
  assert(result.claims.action === "checkout", "action round-trips");
}

// Tampered token
{
  const { token } = issueToken({ origin: "https://example.test", host: "https://example.test", score: 0.8, action: "test", ipSubnet: "10.0.0.0/24" });
  const parts = token.split(".");
  const signature = Buffer.from(parts[2], "base64url");
  signature[0] ^= 1;
  parts[2] = signature.toString("base64url");
  const tampered = parts.join(".");
  const result = verifyToken(tampered, { skipNonce: true });
  assert(result.valid === false, "tampered token rejected");
  assert(result.reason.includes("signature"), "reason: invalid signature");
}

// Expired token
{
  const pastMs = Date.now() - 120_000; // 2 minutes ago
  const { token } = issueToken({ origin: "https://example.test", host: "https://example.test", score: 0.8, action: "test", ipSubnet: "10.0.0.0/24", nowMs: pastMs });
  const result = verifyToken(token, { skipNonce: true });
  assert(result.valid === false, "expired token rejected");
  assert(result.reason.includes("expired"), "reason: expired");
}

// Future-issued token (beyond clock skew)
{
  const futureMs = Date.now() + 120_000; // 2 minutes in the future
  const { token } = issueToken({ origin: "https://example.test", host: "https://example.test", score: 0.8, action: "test", ipSubnet: "10.0.0.0/24", nowMs: futureMs });
  const result = verifyToken(token, { skipNonce: true });
  assert(result.valid === false, "future token rejected");
  assert(result.reason.includes("future"), "reason: future");
}

// Action mismatch
{
  const { token } = issueToken({ origin: "https://example.test", host: "https://example.test", score: 0.8, action: "login", ipSubnet: "10.0.0.0/24" });
  const result = verifyToken(token, { action: "checkout", skipNonce: true });
  assert(result.valid === false, "action mismatch rejected");
  assert(result.reason.includes("mismatch"), "reason: action mismatch");
}

// IP subnet mismatch
{
  const { token } = issueToken({ origin: "https://example.test", host: "https://example.test", score: 0.8, action: "test", ipSubnet: "192.168.1.0/24" });
  const result = verifyToken(token, { clientIP: "10.0.0.1", skipNonce: true });
  assert(result.valid === false, "IP subnet mismatch rejected");
  assert(result.reason.includes("subnet"), "reason: IP subnet mismatch");
}

// Score threshold
{
  const { token } = issueToken({ origin: "https://example.test", host: "https://example.test", score: 0.3, action: "test", ipSubnet: "10.0.0.0/24" });
  const result = verifyToken(token, { minScore: 0.7, skipNonce: true });
  assert(result.valid === false, "below-threshold score rejected");
  assert(result.reason.includes("threshold"), "reason: below threshold");
}

// Nonce replay
{
  const { token } = issueToken({ origin: "https://example.test", host: "https://example.test", score: 0.8, action: "test", ipSubnet: "10.0.0.0/24" });
  const first = verifyToken(token);
  const second = verifyToken(token);
  assert(first.valid === true, "first use of nonce succeeds");
  assert(second.valid === false, "second use of nonce fails (replay)");
  assert(second.reason.includes("replay"), "reason: replay detected");
}

// Malformed inputs
{
  assert(verifyToken("").valid === false, "empty string rejected");
  assert(verifyToken("a.b").valid === false, "2-part token rejected");
  assert(verifyToken("a.b.c.d").valid === false, "4-part token rejected");
  assert(verifyToken(123).valid === false, "non-string rejected");
  assert(verifyToken(null).valid === false, "null rejected");
}

// Clock skew tolerance (token issued 3 seconds ago, verified "now" — should pass)
{
  const now = Date.now();
  const { token } = issueToken({ origin: "https://example.test", host: "https://example.test", score: 0.8, action: "test", ipSubnet: "10.0.0.0/24", nowMs: now });
  // Simulate verifier clock being 3 seconds behind.
  const result = verifyToken(token, { nowMs: now - 3000, skipNonce: true });
  assert(result.valid === true, "3s clock skew within tolerance");
}

/* ================================================================== */

// Cleanup
verifierCache.destroy();

console.log(`\n${"═".repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
