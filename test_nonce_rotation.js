"use strict";
const assert = require("node:assert/strict");
const { NonceCache } = require("./attestation/nonce_cache");
const { issueToken } = require("./attestation/token");
const { verifyToken, nonceCache } = require("./attestation/verifier");
const originalNow = Date.now;
let now = originalNow();
Date.now = () => now;
const cache = new NonceCache(120000);
try {
  const policy = { action: "login", origin: "https://app.test", host: "https://app.test", clientIP: "192.0.2.1" };
  // Consume a still-valid token just before the rotation boundary.
  now = nonceCache._lastRotation + 119999;
  const { token } = issueToken({ ...policy, score: 0.9, ipSubnet: "192.0.2.0/24" });
  assert.equal(verifyToken(token, policy).valid, true);
  now += 2;
  assert.equal(nonceCache.claim("unrelated-request"), true); // lazy rotation
  nonceCache._rotate(); // delayed timer callback in the same event-loop turn
  assert.equal(verifyToken(token, policy).valid, false, "Consumed token must not become reusable after adjacent rotations");

  now = cache._lastRotation + 119999;
  assert.equal(cache.claim("nonce"), true);
  now += 2;
  cache.claim("trigger");
  cache._rotate();
  assert.equal(cache.claim("nonce"), false);
  now += 120000;
  cache._rotate();
  assert.equal(cache.claim("nonce"), true, "Expired nonces should eventually be released");
  console.log("Nonce timer/lazy rotation replay regression passed");
} finally {
  Date.now = originalNow;
  cache.destroy();
  nonceCache.destroy();
}
