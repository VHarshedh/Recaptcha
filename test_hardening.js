"use strict";
const assert = require("node:assert/strict");
const { RateLimiter } = require("./attestation/rate_limiter");
const { AdaptiveChallenge } = require("./attestation/adaptive_challenge");
const { SessionStore } = require("./compiler/middleware");
const { computeScore, _scoreRuntime, _scoreHardware, _scorePoW } = require("./attestation/scorer");
const { validateEnvelope, generateEphemeralKeyPair } = require("./compiler/ecdh_session");
const { verifyPoW } = require("./pow_verifier");
async function main() {
  let now = 0;
  const limiter = new RateLimiter({ maxEntries: 1, failureLimit: 1, now: () => now });
  limiter.failure("victim");
  assert.equal(limiter.check("victim").allowed, false);
  assert.equal(limiter.check("other").allowed, false);
  assert.equal(limiter.check("victim").allowed, false);
  now = 1000000;
  assert(limiter.check("other").allowed);
  assert.throws(() => new AdaptiveChallenge(new SessionStore()), /authorization/);
  new AdaptiveChallenge(new SessionStore(), { allowInsecureDemo: true });
  const old = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = "production";
    assert.throws(() => new AdaptiveChallenge(new SessionStore(), { allowInsecureDemo: true }), /authorization/);
  } finally { if (old === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = old; }
  assert.equal(_scoreRuntime(JSON.parse('{"confidence_penalty":1e400}')), 0);
  assert.equal(_scoreHardware({}), 0);
  assert.equal(computeScore({ hardware: { anomalies: [null] } }).score, 0);
  assert.equal(_scorePoW({ serverVerified: true, durationMs: 1 }), _scorePoW({ serverVerified: true, durationMs: 1e9 }));
  assert.equal(verifyPoW({ challenge: "a", nonce: 0, difficulty: 1, issuedAt: Date.now(), maxAgeMs: NaN }).valid, false);
  const kp = generateEphemeralKeyPair();
  const envelope = { sid: kp.id, cpk: kp.publicKeyBase64, iv: Buffer.alloc(12).toString("base64"), ct: Buffer.alloc(16).toString("base64") };
  validateEnvelope(envelope);
  assert.throws(() => validateEnvelope({ ...envelope, iv: "AAAA" }));
  assert.throws(() => validateEnvelope({ ...envelope, cpk: envelope.cpk + " " }));
  const { compileAsync } = require("./compiler/compile_async");
  for (let i = 0; i < 3; i++) await assert.rejects(compileAsync({ uncloneable: () => {} }));
  assert((await compileAsync({ powDifficulty: 1 })).bundle);
  console.log("Hardening regressions passed");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
