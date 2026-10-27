"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const vm = require("node:vm");
const fs = require("node:fs");
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
  for (let nonce = 0; ; nonce++) {
    if (countLeadingZeroBits(crypto.createHash("sha256").update(challenge + nonce).digest()) >= difficulty) return { nonce };
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
  assert.equal(visual.instructions.noise.fps, 30);
  assert(visual.instructions.noise.particles >= 250);
  const curves = visual.instructions.paths.filter(p => p.d.includes("C"));
  assert(curves.length >= 12 && curves.length <= 18);
  assert.notDeepEqual(renderAnswer("ABC234"), renderAnswer("ABC234"));
  const sessions = new SessionStore();
  const challenges = new SessionStore(100, 60_000);
  // Inject a known answer only in this test, while exercising the real renderer.
  const adaptive = new AdaptiveChallenge(challenges, { secret, visualFactory: (key, id) => ({
    answerHash: answerHash(key, "ABC234", id), instructions: renderAnswer("ABC234"),
  }) });
  const server = createServer({ sessionStore: sessions, adaptive });
  // Native synchronous mining blocks this test process; avoid stale keep-alive
  // sockets while mining. Production mining runs in the browser worker.
  server.keepAliveTimeout = 120_000;
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
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
      answer, powSolution: solution };
  }
  function checkToken(result) {
    assert.equal(result.status, "passed");
    const verified = verifyToken(result.token, { clientIP: "127.0.0.1", action: "login", minScore: 0.70 });
    assert(verified.valid, verified.reason);
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
    assert.equal(grey.status, "step_up_pow"); assert.equal(grey.score, 0.45); assert.equal(grey.pow.difficulty, 20);
    assert.equal(grey.token, undefined);
    const greyWire = fx.encrypt(submission(grey, solve(grey.pow.challenge, grey.pow.difficulty)));
    checkToken((await post("/attest/verify-challenge", greyWire)).data);
    assert.equal((await post("/attest/verify-challenge", greyWire)).status, 403);
    console.log("Adaptive PoW upgrade and replay checks passed");

    const suspicious = human(); suspicious.runtime.confidence_penalty = 0.8;
    for (const answer of ["ZZZZZZ", "abc234"]) {
      fx = fixture(); const low = (await fx.assess(suspicious)).data;
      assert.equal(low.status, "step_up_visual"); assert.equal(low.pow.difficulty, 21); assert.equal(low.token, undefined);
      assert(!JSON.stringify(low).includes("ABC234"));
      const ct = Buffer.from(low.rendering.ct, "base64");
      const decipher = crypto.createDecipheriv("aes-256-gcm", fx.key, Buffer.from(low.rendering.iv, "base64"));
      decipher.setAuthTag(ct.subarray(-16));
      const instructions = JSON.parse(Buffer.concat([decipher.update(ct.subarray(0, -16)), decipher.final()]));
      assert(instructions.paths.length > 100); assert.equal(instructions.noise.particles, 300);
      const wire = fx.encrypt(submission(low, solve(low.pow.challenge, low.pow.difficulty), answer));
      const verified = await post("/attest/verify-challenge", wire);
      if (answer === "abc234") checkToken(verified.data); else assert.equal(verified.status, 403);
      assert.equal((await post("/attest/verify-challenge", wire)).status, 403);
    }
    console.log("Encrypted visual rendering, wrong answer, correct answer, and single-attempt checks passed");

    // Server-owned expiry, signature, nonce and request context must not be replaceable.
    for (const attack of ["expired", "signature", "nonce", "header", "session", "ciphertext"]) {
      fx = fixture(); const challenge = (await fx.assess(passive)).data;
      const data = submission(challenge, { nonce: -1 });
      if (attack === "expired") challenges._map.get(fx.sid).claims.expiresAt = Date.now() - 1;
      if (attack === "signature") data.challengeToken += "x";
      if (attack === "session") data.sessionId = "wrong";
      const wire = fx.encrypt(data);
      if (attack === "ciphertext") wire.ct = Buffer.alloc(20).toString("base64");
      const result = await post("/attest/verify-challenge", wire, attack === "header" ? { "accept-language": "fr" } : {});
      assert.equal(result.status, 403, attack);
      assert.equal(challenges.consume(fx.sid), null, "failed attempt must be consumed");
    }
    for (const spoof of [{ "user-agent": "Mozilla/5.0 Firefox/130.0" }, { "sec-ch-ua": "" }]) {
      fx = fixture(); const low = (await fx.assess(human(), spoof)).data;
      assert.equal(low.status, "step_up_visual"); assert(low.score <= 0.1);
    }
    const firefox = { ...requestProfile, ua: "Firefox/130", secChUa: "", secChUaPlatform: "", secChUaMobile: "" };
    assert(verifyHeaderConsistency(firefox, firefox, { ...human(), hardware: { profile: { userAgent: firefox.ua } } }).penalty >= 0.5);
    console.log("Expiry, signature, bad-work, header spoofing, and session-binding checks passed");

    // Exercise generated crypto + flattened orchestrator, with an actual server token.
    const build = compile({ sourceFiles: ["runtime_integrity.js", "hardware_consistency.js", "kinematics.js"] });
    sessions.set(build.ecdhKeyPair.id, { keyPair: build.ecdhKeyPair, expectedVmState: build.expectedVmState,
      headerProfile: requestProfile, pow: { ...build.pow, issuedAt: Number(build.pow.challenge.split(".")[0]) } });
    const subtle = {};
    for (const name of ["encrypt", "decrypt", "importKey", "generateKey", "deriveBits", "exportKey", "digest"])
      subtle[name] = crypto.webcrypto.subtle[name].bind(crypto.webcrypto.subtle);
    const context = vm.createContext({ crypto: { subtle, getRandomValues: crypto.webcrypto.getRandomValues.bind(crypto.webcrypto) },
      TextEncoder, TextDecoder, AbortController, atob, btoa, performance, setTimeout, clearTimeout,
      addEventListener() {}, removeEventListener() {},
      solvePoW: async opts => ({ ...solve(opts.challenge, opts.difficulty), durationMs: 100 }),
      fetch: (url, opts) => fetch(origin + url, { ...opts, headers: { ...headers, ...opts.headers } }) });
    vm.runInContext(build.bundle, context);
    context.RuntimeIntegrity = { collect: () => human().runtime };
    context.HardwareConsistency = { collect: async () => human().hardware };
    context.Kinematics = { getBiometricVector: () => passive.kinematics };
    const token = await context.__attestation.execute("login");
    assert.equal(typeof token, "string");
    checkToken({ status: "passed", token });
    console.log("Compiled client automatically completes adaptive PoW and resolves to a valid token");

    // DOM simulation exercises the complete compiled visual orchestration,
    // including decrypting the server's rendering stream and drawing Path2D.
    let canvasDraws = 0, modalRemoved = false, focusRestored = false;
    const elements = [];
    function element(tag) {
      const node = { tag, children: [], events: {}, value: "abc234",
        append(...nodes) { this.children.push(...nodes); },
        appendChild(child) { this.children.push(child); return child; },
        setAttribute() {}, checkValidity() { return true; },
        addEventListener(name, fn) { this.events[name] = fn; },
        attachShadow() { return element("shadow"); },
        remove() { modalRemoved = true; },
        focus() {
          if (tag === "input") queueMicrotask(() => elements.find(e => e.tag === "form").events.submit({ preventDefault() {} }));
        },
        getContext() { return { fillRect() { canvasDraws++; }, fill() {}, stroke() {} }; },
      };
      elements.push(node); return node;
    }
    const visualBuild = compile({ sourceFiles: ["runtime_integrity.js", "hardware_consistency.js", "kinematics.js"], powDifficulty: 8 });
    sessions.set(visualBuild.ecdhKeyPair.id, { keyPair: visualBuild.ecdhKeyPair, expectedVmState: visualBuild.expectedVmState,
      headerProfile: requestProfile, pow: { ...visualBuild.pow, issuedAt: Number(visualBuild.pow.challenge.split(".")[0]) } });
    const visualContext = vm.createContext({ crypto: { subtle, getRandomValues: crypto.webcrypto.getRandomValues.bind(crypto.webcrypto) },
      TextEncoder, TextDecoder, AbortController, atob, btoa, performance, setTimeout, clearTimeout, setInterval, clearInterval,
      addEventListener() {}, removeEventListener() {}, Path2D: class { constructor(path) { assert(path.startsWith("M")); } },
      document: { body: element("body"), activeElement: { focus() { focusRestored = true; } }, createElement: element },
      solvePoW: async opts => ({ ...solve(opts.challenge, opts.difficulty), durationMs: 100 }),
      fetch: (url, opts) => fetch(origin + url, { ...opts, headers: { ...headers, ...opts.headers } }) });
    visualContext.window = visualContext;
    vm.runInContext(visualBuild.bundle, visualContext);
    visualContext.RuntimeIntegrity = { collect: () => suspicious.runtime };
    visualContext.HardwareConsistency = { collect: async () => human().hardware };
    visualContext.Kinematics = { getBiometricVector: () => passive.kinematics };
    checkToken({ status: "passed", token: await visualContext.__attestation.execute("login") });
    assert(canvasDraws >= 301); assert(modalRemoved); assert(focusRestored);
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
