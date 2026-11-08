"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
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
const { attestationMiddleware, verifyToken } = require("./attestation/verifier");
const { RateLimiter } = require("./attestation/rate_limiter");
const { validModalKinematics } = require("./attestation/adaptive_challenge");
const { createServer } = require("./attestation/server");
const { maskIP } = require("./attestation/ip_mask");
const { hashPoW, countLeadingZeroBits } = require("./pow_verifier");

async function main() {
  await hardeningRegressions();
  const modal = { trustedPointerdowns: 1, trustedFocusChanges: 0, pointerBeforeTyping: true, focusBeforeTyping: false, screenSamples: 0, displacementSamples: 0, zeroScreenDeltaRatio: 0, zeroMovementRatio: 0, untrustedCount: 0, trustedKeydowns: 6, dwellCount: 6, ttfkMs: 250,
    totalTypingMs: 300, dwellVariance: 4, intervalVariance: 8 };
  assert(validModalKinematics(modal));
  for (const invalid of [null, {}, { ...modal, untrustedCount: 1 }, { ...modal, trustedKeydowns: 5 },
    { ...modal, pointerBeforeTyping: false }, { ...modal, intervalVariance: 7.99 }, { ...modal, dwellVariance: 3.99 },
    { ...modal, screenSamples: 12, zeroScreenDeltaRatio: 1 }, { ...modal, displacementSamples: 12, zeroMovementRatio: 1 },
    { ...modal, totalTypingMs: 299 }, { ...modal, ttfkMs: 249 }, { ...modal, dwellVariance: 0 },
    { ...modal, dwellCount: 0 }, { ...modal, dwellVariance: NaN }, { ...modal, ttfkMs: "300" }])
    assert(!validModalKinematics(invalid));
  let time = 1000;
  const limiter = new RateLimiter({ now: () => time, maxRequests: 2, windowMs: 1000,
    cooldownMs: 1000, failureWindowMs: 5000, maxEntries: 2 });
  const subnet = maskIP("192.0.2.1");
  assert(limiter.check(subnet).allowed); assert(limiter.check(maskIP("192.0.2.99")).allowed);
  assert(!limiter.check(subnet).allowed);
  time += 1000; assert(limiter.check(subnet).allowed);
  for (let i = 0; i < 3; i++) limiter.failure(subnet);
  assert.equal(limiter.penalty(subnet), 0.50);
  limiter.success(subnet); assert.equal(limiter.penalty(subnet), 0);
  for (let i = 0; i < 5; i++) limiter.failure(subnet);
  assert(!limiter.check(subnet).allowed);
  time += 1000; assert(limiter.check(subnet).allowed);
  limiter.failure(subnet); assert.equal(limiter.check(subnet).retryAfter, 2);
  assert(limiter.check("other").allowed); assert(!limiter.check("overflow").allowed); assert(limiter.entries.has(subnet));
  time += 6000; assert(limiter.check("overflow").allowed); assert(limiter.entries.size <= 2);
  const limitedServer = createServer({ allowInsecureDemo: true, rateLimit: { maxRequests: 2 } });
  await new Promise(resolve => limitedServer.listen(0, "127.0.0.1", resolve));
  try {
    const origin = `http://127.0.0.1:${limitedServer.address().port}`;
    for (const path of ["/attest", "/attest/verify-challenge"])
      assert.equal((await fetch(origin + path, { method: "POST", body: "{}" })).status, 403);
    const blocked = await fetch(origin + "/collector.js");
    assert.equal(blocked.status, 429); assert(Number(blocked.headers.get("retry-after")) > 0);
  } finally { await new Promise(resolve => limitedServer.close(resolve)); }
  const failureStore = new SessionStore(), reputation = new RateLimiter({ maxRequests: 100 });
  const failureServer = createServer({ allowInsecureDemo: true, sessionStore: failureStore, rateLimiter: reputation });
  await new Promise(resolve => failureServer.listen(0, "127.0.0.1", resolve));
  try {
    const origin = `http://127.0.0.1:${failureServer.address().port}`;
    const build = compile({ powDifficulty: 1 });
    for (let i = 0; i < 8; i++) {
      failureStore.set(build.ecdhKeyPair.id, { keyPair: build.ecdhKeyPair, expectedVmState: build.expectedVmState });
      const response = await fetch(origin + "/attest", { method: "POST", body: JSON.stringify({
        sid: build.ecdhKeyPair.id, cpk: build.ecdhKeyPair.publicKeyBase64,
        iv: Buffer.alloc(12).toString("base64"), ct: Buffer.alloc(32).toString("base64") }) });
      assert.equal(response.status, 400);
      if (i === 2) assert.equal(reputation.penalty("127.0.0.1"), 0.50);
    }
    assert.equal((await fetch(origin + "/collector.js")).status, 429);
  } finally { await new Promise(resolve => failureServer.close(resolve)); }
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
    attestationMiddleware({ action: "login", origin: "https://example.com", host: "https://example.com" })({ ...req, headers: { ...req.headers, "x-attestation-token": token } },
      { writeHead(code) { status = code; }, end() {} }, () => assert.fail("spoofed IP accepted"));
    assert.equal(status, 403);
    process.env.TRUST_PROXY = "1";
    assert.equal(getClientIP(req), "203.0.113.10");
    assert.equal(getClientIP({ ...req, headers: { "x-forwarded-for": "198.51.100.1, invalid" } }), "unknown");
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
  for (const counts of [{ keydown: 4 }, { keydown: 1 }, {}, { rejectedUntrusted: 100 }, { mousemove: "100" }, { keydown: -1 }, { touchmove: NaN }]) {
    telemetry.kinematics.eventCounts = counts;
    assert(computeScore(telemetry).score <= 0.30);
  }
  telemetry.kinematics.eventCounts = { keydown: 20 };
  assert(computeScore(telemetry).score > 0.6);
  telemetry.kinematics.pointerArtifacts = { screenSamples: 12, zeroScreenDeltaRatio: 1 };
  assert(computeScore(telemetry).score <= 0.30);
  delete telemetry.kinematics.pointerArtifacts;
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
    const context = vm.createContext({ Uint8Array, Int32Array, Float32Array, ArrayBuffer, DataView, crypto: { subtle, getRandomValues: crypto.webcrypto.getRandomValues.bind(crypto.webcrypto) },
      TextEncoder, atob, btoa, performance, setTimeout, clearTimeout,
      addEventListener() {}, removeEventListener() {},
      solvePoW: async ({challenge,difficulty}) => {
        let nonce=0;
        while(countLeadingZeroBits(hashPoW(challenge,nonce)) < difficulty) nonce++;
        return {nonce,durationMs:1};
      },
      fetch: async (_url, opts) => { wire = JSON.parse(opts.body); return { ok: true, json: async () => ({ status: "passed", token: "test-token" }) }; } });
    context.window = context;
    context.navigator = { [Symbol.toStringTag]: "Navigator" };
    context.document = { createElement: () => ({ getContext: () => ({ fillRect() {} }) }) };
    vm.runInContext(build.bundle, context);
    assert.equal(context.RuntimeIntegrity, undefined);
    assert.equal(context.HardwareConsistency, undefined);
    assert.equal(context.Kinematics, undefined);
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
    context.navigator = {};
    await context.__attestation.execute("login");
    assert.throws(() => decryptTelemetry(wire, build.ecdhKeyPair.privateKey, build.expectedVmState));
    context.navigator = { [Symbol.toStringTag]: "Navigator" };
    await context.__attestation.execute("login");
    if (i === 0) {
      const originalHardware = context.HardwareConsistency;
      context.HardwareConsistency = { collect: () => { throw new Error("global collector invoked"); } };
      await context.__attestation.execute("login");
      assert(decryptTelemetry(wire, build.ecdhKeyPair.privateKey, build.expectedVmState).hardware.profile);
      context.HardwareConsistency = originalHardware;
      const originalDocument = context.document;
      context.document = { createElement: () => ({ getContext: () => null }) };
      await context.__attestation.execute("login");
      assert.throws(() => decryptTelemetry(wire, build.ecdhKeyPair.privateKey, build.expectedVmState));
      context.document = originalDocument;
      vm.runInContext('globalThis.savedToString = Function.prototype.toString; Function.prototype.toString = function() { return "patched"; };', context);
      await context.__attestation.execute("login");
      assert.throws(() => decryptTelemetry(wire, build.ecdhKeyPair.privateKey, build.expectedVmState));
      vm.runInContext('Function.prototype.toString = globalThis.savedToString;', context);
      await context.__attestation.execute("login");
    }

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
async function hardeningRegressions() {
  // Hot compilation must not touch disk; per-build bytecode remains unique.
  const first = compile({ powDifficulty: 1 });
  const read = fs.readFileSync, exists = fs.existsSync;
  try {
    fs.readFileSync = fs.existsSync = () => { throw new Error("hot compile touched disk"); };
    const second = compile({ powDifficulty: 1 });
    assert.notEqual(first.stats.runtimeProgramDigest, second.stats.runtimeProgramDigest);
    assert.notEqual(first.expectedVmState, second.expectedVmState);
  } finally { fs.readFileSync = read; fs.existsSync = exists; }

  const store = new SessionStore(4, 60000, 2);
  const data = ip => ({ keyPair: {}, headerProfile: { clientIP: ip } });
  assert(store.set("victim", data("192.0.2.4")));
  assert(store.set("a1", data("198.51.100.1"))); assert(store.set("a2", data("198.51.100.1")));
  assert.equal(store.set("a3", data("198.51.100.1")), false);
  assert(store.set("other", data("203.0.113.4")));
  assert.equal(store.set("overflow", data("10.0.0.1")), false);
  assert(store.consume("victim")); assert(store.consume("a1"));
  assert(store.set("a3", data("198.51.100.1")));
  store._map.get("a2").createdAt = Date.now() - 60001;
  assert(store.canAccept("198.51.100.1"));
  assert(store._subnets.get("198.51.100.1") <= 2);

  let now = 0;
  const limiter = new RateLimiter({ maxEntries: 3, now: () => now, failureWindowMs: 1000 });
  for (const key of ["a", "b", "c"]) { assert(limiter.check(key).allowed); limiter.failure(key); }
  assert(!limiter.check("d").allowed);
  assert(limiter.expiry.heap.length <= 3);
  for (let i = 0; i < 100; i++) limiter.failure("a");
  assert(limiter.expiry.heap.length <= 3);
  now = 1001;
  assert(!limiter.check("d").allowed); assert(limiter.entries.has("a"));
  for (let i = 0; i < 100; i++) assert(!limiter.check("clean" + i).allowed);
  assert.equal(limiter.entries.size, 3); assert(limiter.entries.has("a"));

  // Serialize the same Error with and without a DevTools-like getter read.
  const runtimeSource = fs.readFileSync("runtime_integrity.js", "utf8");
  const runtime = vm.createContext({ console: { debug() {} } });
  vm.runInContext(runtimeSource, runtime);
  const baseline = runtime.RuntimeIntegrity.collect();
  runtime.console.debug = error => { void error.stack; };
  const observed = runtime.RuntimeIntegrity.collect();
  assert.equal(observed.serialization.stackGetterCalls, 1);
  assert.equal(observed.confidence_penalty, baseline.confidence_penalty);

  const listeners = {}, motion = vm.createContext({ performance: { now: () => ++now },
    document: {}, innerWidth: 1000, innerHeight: 700,
    addEventListener: (name, fn) => { listeners[name] = fn; }, removeEventListener() {} });
  vm.runInContext(fs.readFileSync("kinematics.js", "utf8"), motion); motion.Kinematics.start();
  for (let i = 0; i < 12; i++) listeners.mousemove({ type: "mousemove", isTrusted: true,
    clientX: i, clientY: i, screenX: i, screenY: i, movementX: 0, movementY: 0, timeStamp: 1 });
  const artifact = motion.Kinematics.getBiometricVector().pointerArtifacts;
  assert.equal(artifact.zeroScreenDeltaRatio, 1); assert.equal(artifact.zeroMovementRatio, 1);
  assert.equal(artifact.duplicateTimestampRatio, 1);
  motion.Kinematics.stop();

  const { renderAnswer } = require("./attestation/visual_captcha");
  const clutter = renderAnswer(""); // Inspect decoys alone: they must also have paired neighbors.
  assert.equal(clutter.noise.layerOffsets.length, 3);
  const points = clutter.paths.map(p => {
    const v = p.d.match(/^M(-?[\d.]+) (-?[\d.]+)/);
    return [+v[1] + clutter.noise.layerOffsets[p.layer][0], +v[2] + clutter.noise.layerOffsets[p.layer][1]];
  });
  const paired = points.filter((p, i) => points.some((q, j) => i !== j && Math.hypot(p[0]-q[0], p[1]-q[1]) < 3.5));
  assert(paired.length / points.length > 0.9);

  const bound = issueToken({ score: 0.9, action: "login", ipSubnet: "192.0.2.0/24", origin: "https://app.example", host: "https://attest.example" }).token;
  assert(!verifyToken(bound, { skipNonce: true }).valid);
  assert(!verifyToken(bound, { origin: "https://evil.example", host: "https://attest.example", skipNonce: true }).valid);
  assert(!verifyToken(bound, { origin: "https://app.example", host: "https://evil.example", skipNonce: true }).valid);
  assert(verifyToken(bound, { action: "login", clientIP: "192.0.2.1", ipSubnet: "192.0.2.0/24", origin: "https://app.example", host: "https://attest.example", skipNonce: true }).valid);
  const server = createServer({ allowInsecureDemo: true, allowedOrigins: ["https://app.example"] });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  try {
    const url = `http://127.0.0.1:${server.address().port}`;
    for (const origin of ["https://evil.example", "null"])
      assert.equal((await fetch(url + "/collector.js", { headers: { Origin: origin } })).status, 403);
    assert.equal((await fetch(url + "/collector.js", { headers: { "sec-fetch-site": "cross-site" } })).status, 403);
    const preflight = await fetch(url + "/attest", { method: "OPTIONS", headers: { Origin: "https://app.example" } });
    assert.equal(preflight.status, 204); assert.equal(preflight.headers.get("access-control-allow-origin"), "https://app.example");
    const own = await fetch(url + "/health", { headers: { Origin: url } });
    assert.equal(own.status, 200); assert.equal(own.headers.get("access-control-allow-origin"), url);
    assert.equal((await fetch(url + "/health")).headers.get("access-control-allow-origin"), null);
  } finally { await new Promise(resolve => server.close(resolve)); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
