"use strict";
const assert = require("node:assert/strict");
const { attestationMiddleware, verifyToken } = require("./attestation/verifier");
const { issueToken } = require("./attestation/token");
const { maskIP } = require("./attestation/ip_mask");
const { NonceCache } = require("./attestation/nonce_cache");
assert.throws(() => attestationMiddleware({ action: "login" }), /origin required/);
const origin = "https://trusted.example";
const attacker = "https://attacker.example";
const policy = { action: "login", origin, host: origin, clientIP: "192.0.2.1" };
const { token } = issueToken({ score: 1, action: "login", origin: attacker, host: attacker, ipSubnet: maskIP(policy.clientIP) });
let status, passed = false;
attestationMiddleware(policy)({ headers: { host: "attacker.example", origin: attacker, "x-attestation-token": token }, socket: { remoteAddress: policy.clientIP } }, {
  writeHead(code) { status = code; }, end() {},
}, () => { passed = true; });
assert.equal(status, 403);
assert.equal(passed, false);
assert.equal(verifyToken("x".repeat(8193), policy).valid, false);
const cache = new NonceCache(120000, 2);
try {
  assert.equal(cache.claim("first"), true);
  assert.equal(cache.claim("second"), true);
  assert.equal(cache.claim("overflow"), false);
  assert.equal(cache.claim("first"), false);
  assert.equal(cache.size, 2);
} finally { cache.destroy(); }
console.log("Boundary security regressions passed");
