"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const vm = require("node:vm");
const { spawnSync } = require("node:child_process");
const { Readable } = require("node:stream");
const { compile, preprocess } = require("./compiler/pipeline");
const { decryptTelemetry, deriveSessionKey } = require("./compiler/ecdh_session");
const { SessionStore, createDecryptHandler } = require("./compiler/middleware");
const { extractHeaderProfile, verifyHeaderConsistency } = require("./attestation/header_check");
const { computeScore } = require("./attestation/scorer");
const { getClientIP } = require("./attestation/ip_mask");
const { issueToken } = require("./attestation/token");
const { attestationMiddleware } = require("./attestation/verifier");

async function main() {
  const keyEnv = { ...process.env, NODE_ENV: "production" };
  delete keyEnv.ATTESTATION_KEY_PATH;
  const missingKey = spawnSync(process.execPath, ["-e", 'require("./attestation/keys")'], { env: keyEnv, encoding: "utf8" });
  assert.notEqual(missingKey.status, 0);
  assert(missingKey.stderr.includes("ATTESTATION_KEY_PATH is required"));
  const badKey = spawnSync(process.execPath, ["-e", 'require("./attestation/keys")'], {
    env: { ...keyEnv, ATTESTATION_KEY_PATH: "nonexistent-security-test-key" }, encoding: "utf8",
  });
  assert.notEqual(badKey.status, 0);
  assert(badKey.stderr.includes("ENOENT"));
  const originalProxy = process.env.TRUST_PROXY;
  const req = { headers: { "user-agent": "Chrome/130.0", "accept-language": "en-US",
    "sec-ch-ua": '"Chromium";v="130"', "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"', "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors",
    "x-forwarded-for": "198.51.100.1, 203.0.113.10" }, socket: { remoteAddress: "192.0.2.1" } };
  try {
    delete process.env.TRUST_PROXY;
    assert.equal(getClientIP(req), "192.0.2.1");
    const token = issueToken({ score: 0.9, action: "login", ipSubnet: "198.51.100.0/24" }).token;
    let status;
    attestationMiddleware()({ ...req, headers: { ...req.headers, "x-attestation-token": token } },
      { writeHead(code) { status = code; }, end() {} }, () => assert.fail("spoofed IP accepted"));
    assert.equal(status, 403);
    process.env.TRUST_PROXY = "1";
    assert.equal(getClientIP(req), "203.0.113.10");
    assert.equal(getClientIP({ ...req, headers: { "x-forwarded-for": "198.51.100.1, invalid" } }), "192.0.2.1");
  } finally {
    if (originalProxy === undefined) delete process.env.TRUST_PROXY;
    else process.env.TRUST_PROXY = originalProxy;
  }
  const profile = extractHeaderProfile(req);
  const telemetry = { hardware: { profile: { userAgent: profile.ua } },
    runtime: { confidence_penalty: 0, receiverErrorText: "TypeError: Illegal invocation" },
    pow: { serverVerified: true }, kinematics: { eventCounts: {} } };
  assert.equal(verifyHeaderConsistency(profile, profile, telemetry).penalty, 0);
  assert(verifyHeaderConsistency(profile, { ...profile, ua: "Firefox/130.0" }, telemetry).penalty >= 0.5);
  assert(verifyHeaderConsistency(profile, { ...profile, clientIP: "other" }, telemetry).penalty >= 0.5);
  const firefox = { ...profile, ua: "Firefox/130.0", secChUa: "", secChUaMobile: "", secChUaPlatform: "" };
  const ffTelemetry = { ...telemetry, hardware: { profile: { userAgent: firefox.ua } },
    runtime: { receiverErrorText: "TypeError: 'get languages' called on an object that does not implement interface Navigator." } };
  assert.equal(verifyHeaderConsistency(firefox, firefox, ffTelemetry).penalty, 0);
  assert(verifyHeaderConsistency(firefox, firefox, { ...ffTelemetry, runtime: telemetry.runtime }).penalty >= 0.5);
  for (const counts of [{}, { rejectedUntrusted: 100 }, { mousemove: "100" }, { keydown: -1 }, { touchmove: NaN }]) {
    telemetry.kinematics.eventCounts = counts;
    assert(computeScore(telemetry).score <= 0.45);
  }
  telemetry.kinematics.eventCounts = { keydown: 20 };
  assert(computeScore(telemetry).score > 0.6);
  assert(computeScore(telemetry, { penalty: 0.8, anomalies: ["mismatch"] }).score <= 0.1);
  const sample = 'var value = "/* keep this literal */"; /* remove this */';
  assert(preprocess(sample).includes('"/* keep this literal */"'));
  assert(!preprocess(sample).includes("remove this"));

  // Execute randomized real collectors and generated Web Crypto code. Node
  // supplies crypto; browser DOM/probes are intentionally unavailable here.
  for (let i = 0; i < 5; i++) {
    const build = compile({ sourceFiles: ["runtime_integrity.js", "hardware_consistency.js", "kinematics.js"], powDifficulty: 1 });
    let wire;
    const subtle = {};
    for (const name of ["encrypt", "decrypt", "importKey", "generateKey", "deriveBits", "exportKey", "digest"])
      subtle[name] = crypto.webcrypto.subtle[name].bind(crypto.webcrypto.subtle);
    const context = vm.createContext({ crypto: { subtle, getRandomValues: crypto.webcrypto.getRandomValues.bind(crypto.webcrypto) },
      TextEncoder, atob, btoa, performance, setTimeout, clearTimeout,
      addEventListener() {}, removeEventListener() {},
      solvePoW: async () => ({ nonce: 0, durationMs: 1 }),
      fetch: async (_url, opts) => { wire = JSON.parse(opts.body); return { ok: true, json: async () => ({ status: "passed", token: "test-token" }) }; } });
    vm.runInContext(build.bundle, context);
    assert.equal(typeof context.RuntimeIntegrity.collect, "function");
    await context.__attestation.execute("login");
    const plain = decryptTelemetry(wire, build.ecdhKeyPair.privateKey, build.expectedVmState);
    assert.equal(plain.action, "login");
    assert.equal(typeof plain.runtime.confidence_penalty, "number");
    assert(!plain.runtime.anomalies.some(x => x.includes("source-text preservation")));
    assert(plain.hardware.profile);
    assert(plain.kinematics.eventCounts);
    assert.throws(() => decryptTelemetry(wire, build.ecdhKeyPair.privateKey));
    assert.throws(() => decryptTelemetry(wire, build.ecdhKeyPair.privateKey, build.expectedVmState ^ 1));
    assert.throws(() => deriveSessionKey(Buffer.alloc(32), NaN));

    // Session context reaches the scorer separately from untrusted JSON.
    const store = new SessionStore();
    store.set(wire.sid, { keyPair: build.ecdhKeyPair, expectedVmState: build.expectedVmState,
      headerProfile: profile, pow: build.pow });
    let invoked = false;
    const handler = createDecryptHandler(store, (data, _req, _res, check) => {
      invoked = true;
      assert.equal(typeof data.pow.serverVerified, "boolean");
      assert(check.anomalies.includes("http_ua_vs_js_ua_mismatch"));
    });
    const request = () => Object.assign(Readable.from([Buffer.from(JSON.stringify(wire))]), req);
    const response = { writeHead(code) { this.status = code; }, end() {} };
    await handler(request(), response);
    assert(invoked);
    await handler(request(), response);
    assert.equal(response.status, 403);
  }
  console.log("Security regressions passed (including 5 randomized compiled crypto round trips)");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
