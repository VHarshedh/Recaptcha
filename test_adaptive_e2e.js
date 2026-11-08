"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { hashPoW, createScratchpad } = require("./pow_verifier");
const vm = require("node:vm");
const fs = require("node:fs");
const { RateLimiter } = require("./attestation/rate_limiter");
const { createServer } = require("./attestation/server");
const { SessionStore } = require("./compiler/middleware");
const { AdaptiveChallenge, difficultyForScore } = require("./attestation/adaptive_challenge");
const { generateVisual, renderAnswer, answerHash, ALPHABET } = require("./attestation/visual_captcha");
const { generateEphemeralKeyPair, deriveSessionKey } = require("./compiler/ecdh_session");
const { extractHeaderProfile, verifyHeaderConsistency } = require("./attestation/header_check");
const { generateChallenge, countLeadingZeroBits } = require("./pow_verifier");
const { verifyToken } = require("./attestation/verifier");
const { compile } = require("./compiler/pipeline");

function solve(challenge, difficulty) {
  const pad = createScratchpad(challenge);
  for (let nonce = 0; ; nonce++) {
    if (countLeadingZeroBits(hashPoW(challenge, nonce, pad)) >= difficulty) return { nonce };
  }
}
const headers = { "user-agent": "Mozilla/5.0 Chrome/130.0", "accept-language": "en-US",
  "sec-ch-ua": '"Chromium";v="130"', "sec-ch-ua-platform": '"Windows"', "sec-ch-ua-mobile": "?0",
  "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "content-type": "application/json" };
const requestProfile = extractHeaderProfile({ headers, socket: { remoteAddress: "127.0.0.1" } });
function human() {
  return { action: "login", runtime: { confidence_penalty: 0, receiverErrorText: "TypeError: Illegal invocation" },
    hardware: { profile: { userAgent: headers["user-agent"], hardwareConcurrency: 8 } },
    kinematics: { eventCounts: { mousemove: 80 }, mouse: { pointCount: 45, entropyRatio: 0.92 } } };
}

async function main() {
  assert.deepEqual([0.1, 0.35, 0.4499, 0.45, 0.5499, 0.55, 0.6999].map(difficultyForScore), [21, 22, 22, 20, 20, 18, 18]);
  assert(!/[01OIl]/.test(ALPHABET));
  const secret = crypto.randomBytes(32);
  const visual = generateVisual(secret, "test-id");
  assert.equal(visual.answerHash.length, 32);
  assert(!JSON.stringify(visual.instructions).includes("<text"));
  assert.equal(visual.instructions.noise.fps, 60);
  assert(visual.instructions.noise.particles >= 250);
  const curves = visual.instructions.paths.filter(p => p.d.includes("C"));
  assert.equal(curves.length, visual.instructions.paths.length);
  for (const p of curves) { assert.deepEqual(Object.keys(p).sort(), ["color", "d", "layer"]); assert.equal(p.d.replace(/[^A-Z]/g, ""), "MCCZ"); }
  assert.notDeepEqual(renderAnswer("ABC234"), renderAnswer("ABC234"));
  const sessions = new SessionStore();
  const challenges = new SessionStore(100, 60_000);
  // Inject a known answer only in this test, while exercising the real renderer.
  // Exercise real hashing at low difficulty to avoid probabilistic timeout
  // failures on slow CI machines; assert the requested policy difficulty too.
  let requestedDifficulty;
  const adaptive = new AdaptiveChallenge(challenges, { secret, allowInsecureDemo: true,
    powFactory: difficulty => { requestedDifficulty = difficulty; return { ...generateChallenge(), difficulty: 8 }; },
    visualFactory: (key, id) => ({
    answerHash: answerHash(key, "ABC234", id), instructions: renderAnswer("ABC234"),
  }) });
  const rateLimiter = new RateLimiter({ maxRequests: 1000, failureLimit: 1000 });
  const server = createServer({ allowInsecureDemo: true, sessionStore: sessions, adaptive, rateLimiter, allowedOrigins: ["https://other.example"] });
  // Native synchronous mining blocks this test process; avoid stale keep-alive
  // sockets while mining. Production mining runs in the browser worker.
  server.keepAliveTimeout = 120_000;
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  requestProfile.origin = origin; requestProfile.host = origin;
  async function post(path, body, extra = {}) {
    const res = await fetch(origin + path, { method: "POST", headers: { ...headers, ...extra }, body: JSON.stringify(body) });
    return { status: res.status, data: await res.json() };
  }
  function fixture() {
    const kp = generateEphemeralKeyPair();
    const client = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const state = crypto.randomBytes(4).readInt32BE();
    const cpk = client.publicKey.export({ type: "spki", format: "der" }).toString("base64");
    const key = deriveSessionKey(crypto.diffieHellman({ privateKey: client.privateKey, publicKey: kp.publicKey }), state);
    const pow = { ...generateChallenge(), difficulty: 8 };
    sessions.set(kp.id, { keyPair: kp, expectedVmState: state, headerProfile: requestProfile, pow });
    function encrypt(data) {
      const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
      const ct = Buffer.concat([cipher.update(JSON.stringify(data)), cipher.final(), cipher.getAuthTag()]);
      return { sid: kp.id, cpk, iv: iv.toString("base64"), ct: ct.toString("base64") };
    }
    return { sid: kp.id, key, encrypt, assess: (data, extra) => post("/attest", encrypt({ ...data,
      pow: { challenge: pow.challenge, ...solve(pow.challenge, pow.difficulty), durationMs: 100 } }), extra) };
  }
  function submission(result, solution, answer = "") {
    return { sessionId: result.sessionId, challengeId: result.challengeId, challengeToken: result.challengeToken,
      answer, powSolution: solution, modalKinematics: { trustedPointerdowns: 1, trustedFocusChanges: 0, pointerBeforeTyping: true, focusBeforeTyping: false, screenSamples: 0, displacementSamples: 0, zeroScreenDeltaRatio: 0, zeroMovementRatio: 0, untrustedCount: 0, trustedKeydowns: 6, dwellCount: 6, ttfkMs: 400, totalTypingMs: 800, dwellVariance: 10, intervalVariance: 20 } };
  }
  function checkToken(result) {
    assert.equal(result.status, "passed");
    assert.equal(verifyToken(result.token, { clientIP: "127.0.0.1", action: "login", origin, host: origin }).valid, false);
    const verified = verifyToken(result.token, { allowInsecureDemo: true, clientIP: "127.0.0.1", action: "login", minScore: 0.70, origin, host: origin });
    assert(verified.valid, verified.reason);
    assert.equal(verified.claims.demo, true);
  }
  try {
    let fx = fixture();
    let response = await fx.assess(human());
    assert.equal(response.status, 200); checkToken(response.data);
    assert.equal((await fx.assess(human())).status, 403);
    console.log("High trust and initial-session replay checks passed");

    fx = fixture(); const passive = human(); passive.kinematics.eventCounts = {};
    response = await fx.assess(passive);
    const grey = response.data;
    assert.equal(grey.status, "step_up_visual"); assert.equal(grey.score, 0.30); assert.equal(requestedDifficulty, 21);
    assert.equal(grey.token, undefined);
    const greyWire = fx.encrypt(submission(grey, solve(grey.pow.challenge, grey.pow.difficulty), "abc234"));
    checkToken((await post("/attest/verify-challenge", greyWire)).data);
    assert.equal((await post("/attest/verify-challenge", greyWire)).status, 403);
    console.log("Adaptive PoW upgrade and replay checks passed");

    const suspicious = human(); suspicious.runtime.confidence_penalty = 0.8;
    for (const answer of ["ZZZZZZ", "abc234"]) {
      rateLimiter.success("127.0.0.1");
      fx = fixture(); const low = (await fx.assess(suspicious)).data;
      assert.equal(low.status, "step_up_visual"); assert.equal(requestedDifficulty, rateLimiter.penalty("127.0.0.1") ? 22 : 21); assert.equal(low.token, undefined);
      assert(!JSON.stringify(low).includes("ABC234"));
      const ct = Buffer.from(low.rendering.ct, "base64");
      const decipher = crypto.createDecipheriv("aes-256-gcm", fx.key, Buffer.from(low.rendering.iv, "base64"));
      decipher.setAuthTag(ct.subarray(-16));
      const instructions = JSON.parse(Buffer.concat([decipher.update(ct.subarray(0, -16)), decipher.final()]));
      assert(instructions.image.startsWith("data:image/png;base64,")); assert.equal(instructions.paths, undefined);
      const solution = solve(low.pow.challenge, low.pow.difficulty);
      const wire = fx.encrypt(submission(low, solution, answer));
      if (answer === "abc234") {
        // Isolate telemetry rejection with valid work/answer. Restore the test
        // fixture only; production challenges remain strictly single attempt.
        const entry = challenges._map.get(fx.sid);
        for (const bad of [undefined, { untrustedCount: 1 }, { trustedKeydowns: 5 },
          { totalTypingMs: 299 }, { dwellVariance: 0 }, { ttfkMs: 249 }]) {
          const data = submission(low, solution, answer);
          data.modalKinematics = bad === undefined ? undefined : { ...data.modalKinematics, ...bad };
          assert.equal((await post("/attest/verify-challenge", fx.encrypt(data))).status, 403);
          assert.equal(challenges.consume(fx.sid), null);
          challenges.set(fx.sid, entry);
        }
      }
      const verified = await post("/attest/verify-challenge", wire);
      if (answer === "abc234") checkToken(verified.data); else assert.equal(verified.status, 403);
      assert.equal((await post("/attest/verify-challenge", wire)).status, 403);
    }
    console.log("Encrypted visual rendering, wrong answer, correct answer, and single-attempt checks passed");

    // Server-owned expiry, signature, nonce and request context must not be replaceable.
    for (const attack of ["expired", "signature", "nonce", "header", "session", "ciphertext", "origin", "host"]) {
      fx = fixture(); const challenge = (await fx.assess(passive)).data;
      const data = submission(challenge, { nonce: -1 });
      if (attack === "expired") challenges._map.get(fx.sid).claims.expiresAt = Date.now() - 1;
      if (attack === "signature") data.challengeToken += "x";
      if (attack === "session") data.sessionId = "wrong";
      const wire = fx.encrypt(data);
      if (attack === "ciphertext") wire.ct = Buffer.alloc(20).toString("base64");
      const extra = attack === "header" ? { "accept-language": "fr" } : attack === "origin" ? { origin: "https://other.example" } :
        attack === "host" ? { host: "other.example" } : {};
      const result = await post("/attest/verify-challenge", wire, extra);
      assert.equal(result.status, 403, attack);
      assert.equal(challenges.consume(fx.sid), null, "failed attempt must be consumed");
    }
    for (const spoof of [{ "user-agent": "Mozilla/5.0 Firefox/130.0" }, { "sec-ch-ua": "" }]) {
      fx = fixture(); const low = (await fx.assess(human(), spoof)).data;
      assert.equal(low.status, "step_up_visual"); assert(low.score <= 0.1);
    }
    assert.equal((await fixture().assess(human(), { origin: "https://other.example" })).status, 403);
    const firefox = { ...requestProfile, ua: "Firefox/130", secChUa: "", secChUaPlatform: "", secChUaMobile: "" };
    assert(verifyHeaderConsistency(firefox, firefox, { ...human(), hardware: { profile: { userAgent: firefox.ua } } }).penalty >= 0.5);
    console.log("Expiry, signature, bad-work, header spoofing, and session-binding checks passed");

    for (let i = 0; i < 3; i++) rateLimiter.failure("127.0.0.1");
    const penalized = (await fixture().assess(human())).data;
    assert.equal(penalized.status, "step_up_visual"); assert(penalized.score <= 0.30);
    assert.equal(requestedDifficulty, 22);
    // Exercise generated crypto + flattened orchestrator, with an actual server token.
    rateLimiter.success("127.0.0.1");
    const build = compile({ rawSourceOverride: `var RuntimeIntegrity={collect:()=>(${JSON.stringify(human().runtime)})}; var HardwareConsistency={collect:async()=>(${JSON.stringify(human().hardware)})}; var Kinematics={getBiometricVector:()=>(${JSON.stringify(human().kinematics)})};` });
    sessions.set(build.ecdhKeyPair.id, { keyPair: build.ecdhKeyPair, expectedVmState: build.expectedVmState,
      headerProfile: requestProfile, pow: { ...build.pow, issuedAt: Number(build.pow.challenge.split(".")[0]) } });
    const subtle = {};
    for (const name of ["encrypt", "decrypt", "importKey", "generateKey", "deriveBits", "exportKey", "digest"])
      subtle[name] = crypto.webcrypto.subtle[name].bind(crypto.webcrypto.subtle);
    const context = vm.createContext({ Uint8Array, Int32Array, Float32Array, ArrayBuffer, DataView, crypto: { subtle, getRandomValues: crypto.webcrypto.getRandomValues.bind(crypto.webcrypto) },
      TextEncoder, TextDecoder, AbortController, atob, btoa, performance, setTimeout, clearTimeout,
      addEventListener() {}, removeEventListener() {},
      solvePoW: async opts => ({ ...solve(opts.challenge, opts.difficulty), durationMs: 100 }),
      fetch: (url, opts) => fetch(origin + url, { ...opts, headers: { ...headers, ...opts.headers } }) });
    context.window = context; context.navigator = { [Symbol.toStringTag]: "Navigator" };
    context.document = { createElement: () => ({ getContext: () => ({ fillRect() {} }) }) };
    vm.runInContext(build.bundle, context);
    context.RuntimeIntegrity = { collect: () => human().runtime };
    context.HardwareConsistency = { collect: async () => human().hardware };
    context.Kinematics = { getBiometricVector: () => human().kinematics };
    const token = await context.__attestation.execute("login");
    assert.equal(typeof token, "string");
    checkToken({ status: "passed", token });
    console.log("Compiled client automatically completes adaptive PoW and resolves to a valid token");

    // DOM simulation exercises the complete compiled visual orchestration,
    // including decrypting the server's rendering stream and drawing Path2D.
    let clock = 0;
    let canvasDraws = 0, modalRemoved = false, focusRestored = false;
    const elements = [];
    function element(tag) {
      const node = { tag, children: [], events: {}, value: "abc234",
        append(...nodes) { this.children.push(...nodes); },
        appendChild(child) { this.children.push(child); return child; },
        setAttribute() {}, checkValidity() { return true; },
        addEventListener(name, fn) { this.events[name] = fn; },
        removeEventListener() {},
        attachShadow() { return element("shadow"); },
        remove() { modalRemoved = true; },
        focus() {
          if (tag === "input") queueMicrotask(() => {
            const shadow = elements.find(e => e.tag === "shadow");
            clock += 300;
            shadow.events.pointerdown({ type: "pointerdown", target: node, isTrusted: true });
            for (let i = 0; i < 6; i++) {
              shadow.events.keydown({ type: "keydown", target: node, isTrusted: true, key: "a", code: "KeyA" });
              clock += [62, 104, 71, 93, 55, 121][i];
              shadow.events.keyup({ type: "keyup", target: node, isTrusted: true, key: "a", code: "KeyA" });
              clock += [81, 133, 74, 97, 128, 69][i];
            }
            elements.find(e => e.tag === "form").events.submit({ preventDefault() {} });
          });
        },
        getContext() { return { drawImage() { canvasDraws++; }, fillRect() {}, fill() {}, stroke() {}, save() {}, restore() {}, translate() {} }; },
      };
      elements.push(node); return node;
    }
    const visualBuild = compile({ sourceFiles: ["runtime_integrity.js", "hardware_consistency.js", "kinematics.js"], powDifficulty: 8 });
    sessions.set(visualBuild.ecdhKeyPair.id, { keyPair: visualBuild.ecdhKeyPair, expectedVmState: visualBuild.expectedVmState,
      headerProfile: requestProfile, pow: { ...visualBuild.pow, issuedAt: Number(visualBuild.pow.challenge.split(".")[0]) } });
    const visualContext = vm.createContext({ Uint8Array, Int32Array, Float32Array, ArrayBuffer, DataView, crypto: { subtle, getRandomValues: crypto.webcrypto.getRandomValues.bind(crypto.webcrypto) },
      TextEncoder, TextDecoder, AbortController, atob, btoa, performance: { now: () => clock }, setTimeout, clearTimeout, setInterval, clearInterval,
      addEventListener() {}, removeEventListener() {}, Image: class { set src(value) { assert(value.startsWith("data:image/png;base64,")); this.onload(); } },
      document: { body: element("body"), activeElement: { focus() { focusRestored = true; } }, createElement: element },
      solvePoW: async opts => ({ ...solve(opts.challenge, opts.difficulty), durationMs: 100 }),
      fetch: (url, opts) => fetch(origin + url, { ...opts, headers: { ...headers, ...opts.headers } }) });
    visualContext.window = visualContext; visualContext.navigator = { [Symbol.toStringTag]: "Navigator" };
    vm.runInContext(visualBuild.bundle, visualContext);
    visualContext.RuntimeIntegrity = { collect: () => suspicious.runtime };
    visualContext.HardwareConsistency = { collect: async () => human().hardware };
    visualContext.Kinematics = { getBiometricVector: () => passive.kinematics };
    checkToken({ status: "passed", token: await visualContext.__attestation.execute("login") });
    assert.equal(canvasDraws, 1); assert(modalRemoved); assert(focusRestored);
    console.log("Compiled visual client decrypts and draws glyphs, submits answer and work, and cleans up modal");

    // Client cancellation/error cleanup on the visual path without requiring a DOM.
    const client = vm.createContext({ AbortController, setTimeout, clearTimeout });
    vm.runInContext(fs.readFileSync("compiler/step_up.js", "utf8"), client);
    let destroyed = false;
    client.openVisualChallenge = () => ({ answer: Promise.reject(new Error("cancelled")), destroy() { destroyed = true; } });
    client.solvePoW = opts => new Promise((resolve, reject) => opts.signal.addEventListener("abort", () => reject(new Error("aborted"))));
    await assert.rejects(client.completeAttestation({ status: "step_up_visual", expiresAt: Date.now() + 1000, pow: {} }, () => assert.fail("cancelled challenge submitted")));
    assert(destroyed);
  } finally { await new Promise(resolve => server.close(resolve)); }
  console.log("All adaptive end-to-end checks passed");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
