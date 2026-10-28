"use strict";
const crypto = require("node:crypto");
const { computeScore } = require("./scorer");
const { issueToken } = require("./token");
const { maskIP, getClientIP } = require("./ip_mask");
const { extractHeaderProfile } = require("./header_check");
const { generateChallenge, verifyPoW } = require("../pow_verifier");
const { decryptTelemetry, deriveSessionKey } = require("../compiler/ecdh_session");
const { generateVisual, answerHash } = require("./visual_captcha");

function difficultyForScore(score) {
  if (score < 0.35) return 21;
  if (score < 0.45) return 22;
  if (score < 0.55) return 20;
  return 18;
}
const binding = profile => JSON.stringify([profile.ua, profile.acceptLanguage, profile.secChUa,
  profile.secChUaPlatform, profile.secChUaMobile, profile.clientIP, profile.origin, profile.host]);
const equal = (a, b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length && crypto.timingSafeEqual(a, b);

function encryptRendering(instructions, session) {
  const publicKey = crypto.createPublicKey({ key: Buffer.from(session.clientPublicKey, "base64"), format: "der", type: "spki" });
  const secret = crypto.diffieHellman({ privateKey: session.keyPair.privateKey, publicKey });
  const key = deriveSessionKey(secret, session.expectedVmState);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(instructions)), cipher.final(), cipher.getAuthTag()]);
  return { iv: iv.toString("base64"), ct: ct.toString("base64") };
}

class AdaptiveChallenge {
  constructor(store, { secret = crypto.randomBytes(32), visualFactory = generateVisual,
    powFactory = difficulty => ({ ...generateChallenge(), difficulty }) } = {}) {
    this.store = store;
    this.secret = secret;
    this.visualFactory = visualFactory;
    this.powFactory = powFactory;
  }
  assess(telemetry, req, headerCheck, session, reputationPenalty = 0) {
    const result = computeScore(telemetry, headerCheck);
    if (reputationPenalty > 0) result.score = Math.min(0.30, Math.max(0, result.score - reputationPenalty));
    const action = typeof telemetry.action === "string" && telemetry.action ? telemetry.action : "unknown";
    const ipSubnet = maskIP(getClientIP(req));
    const origin = extractHeaderProfile(req).origin;
    const host = extractHeaderProfile(req).host;
    if (result.score >= 0.70) return { status: "passed", ...result, ...issueToken({ score: result.score, action, ipSubnet, origin, host }) };
    const challengeId = crypto.randomBytes(16).toString("hex");
    const status = result.score < 0.35 ? "step_up_visual" : "step_up_pow";
    const pow = this.powFactory(reputationPenalty > 0 ? 22 : difficultyForScore(result.score));
    const expiresAt = Date.now() + 60_000;
    const profile = extractHeaderProfile(req);
    const claims = { sessionId: session.sessionId, challengeId, status, action, ipSubnet, origin, host,
      binding: binding(profile), score: result.score, expiresAt, pow };
    const encoded = Buffer.from(JSON.stringify(claims)).toString("base64url");
    const signature = crypto.createHmac("sha256", this.secret).update(encoded).digest("base64url");
    const challengeToken = encoded + "." + signature;
    const visual = status === "step_up_visual" ? this.visualFactory(this.secret, challengeId) : null;
    if (!this.store.set(session.sessionId, { ...session, claims, challengeToken,
      answerHash: visual?.answerHash, headerProfile: profile })) throw new Error("challenge capacity reached");
    return { status, score: result.score, sessionId: session.sessionId, challengeId, expiresAt,
      pow, challengeToken, ...(visual ? { rendering: encryptRendering(visual.instructions, session) } : {}) };
  }
  // Consume before decryption or validation: any attempt burns this challenge.
  verify(envelope, req) {
    const entry = this.store.consume(envelope?.sid);
    if (!entry) throw new Error("unknown, expired, or consumed challenge");
    const { claims } = entry;
    if (!claims || Date.now() >= claims.expiresAt || binding(extractHeaderProfile(req)) !== claims.binding)
      throw new Error("challenge expired or request binding mismatch");
    if (envelope.cpk !== entry.clientPublicKey) throw new Error("client key mismatch");
    const data = decryptTelemetry(envelope, entry.keyPair.privateKey, entry.expectedVmState);
    if (data?.sessionId !== claims.sessionId || data?.challengeId !== claims.challengeId || typeof data.challengeToken !== "string")
      throw new Error("challenge binding mismatch");
    const parts = data.challengeToken.split(".");
    if (parts.length !== 2 || data.challengeToken !== entry.challengeToken ||
        !equal(Buffer.from(parts[1], "base64url"), crypto.createHmac("sha256", this.secret).update(parts[0]).digest()))
      throw new Error("invalid challenge signature");
    // Difficulty, timestamps, score and action always come from server state.
    if (!verifyPoW({ ...claims.pow, nonce: data.powSolution?.nonce, maxAgeMs: 60_000 }).valid)
      throw new Error("invalid challenge work");
    if (claims.status === "step_up_visual") {
      if (!validModalKinematics(data.modalKinematics)) throw new Error("invalid modal kinematics");
      if (typeof data.answer !== "string" || !/^[A-Za-z2-9]{6}$/.test(data.answer) ||
          !equal(answerHash(this.secret, data.answer, claims.challengeId), entry.answerHash))
        throw new Error("invalid visual answer");
    }
    // A step-up is a policy override, not evidence that passive telemetry improved.
    return { status: "passed", passiveScore: claims.score, score: 0.70,
      ...issueToken({ score: 0.70, action: claims.action, ipSubnet: claims.ipSubnet, origin: claims.origin, host: claims.host }) };
  }
}
function validModalKinematics(k) {
  if (!k || typeof k !== "object") return false;
  for (const field of ["untrustedCount", "trustedKeydowns", "dwellCount", "ttfkMs", "totalTypingMs", "dwellVariance", "intervalVariance",
    "trustedPointerdowns", "trustedFocusChanges", "screenSamples", "displacementSamples", "zeroScreenDeltaRatio", "zeroMovementRatio"])
    if (!Number.isFinite(k[field]) || k[field] < 0) return false;
  if (k.zeroScreenDeltaRatio > 1 || k.zeroMovementRatio > 1 ||
      (k.screenSamples >= 8 && k.zeroScreenDeltaRatio >= 0.9) ||
      (k.displacementSamples >= 8 && k.zeroMovementRatio >= 0.9)) return false;
  if (!(k.trustedPointerdowns >= 1 && k.pointerBeforeTyping === true) &&
      !(k.trustedFocusChanges >= 1 && k.focusBeforeTyping === true)) return false;
  return k.untrustedCount === 0 && Number.isSafeInteger(k.trustedKeydowns) && k.trustedKeydowns >= 6 &&
    Number.isSafeInteger(k.dwellCount) && k.dwellCount >= 6 && k.dwellCount <= k.trustedKeydowns &&
    k.ttfkMs >= 250 && k.totalTypingMs >= 300 && k.dwellVariance >= 4 && k.intervalVariance >= 8;
}
module.exports = { AdaptiveChallenge, difficultyForScore, validModalKinematics };
