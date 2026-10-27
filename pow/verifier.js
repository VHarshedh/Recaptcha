/**
 * pow_verifier.js — Node.js server-side PoW verification
 *
 * Pure stdlib — zero external dependencies.
 *
 * API:
 *   verifyPoW({ challenge, nonce, difficulty, issuedAt, maxAgeMs? })
 *     → { valid: boolean, reason?: string, hash?: string }
 */

"use strict";

const crypto = require("node:crypto");

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/**
 * Count the number of leading zero bits in a Buffer.
 * @param {Buffer} buf
 * @returns {number}
 */
function countLeadingZeroBits(buf) {
  let bits = 0;
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0) {
      bits += 8;
    } else {
      bits += Math.clz32(buf[i]) - 24;
      break;
    }
  }
  return bits;
}

/**
 * Constant-time comparison of two buffers.
 * Prevents timing side-channels when comparing hashes.
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {boolean}
 */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/* ------------------------------------------------------------------ */
/*  Challenge generation helper                                        */
/* ------------------------------------------------------------------ */

/**
 * Generate a cryptographically random challenge token with an embedded
 * timestamp so the verifier can enforce expiry without external state.
 *
 * Format: `<timestampMs>.<128-bit hex random>`
 *
 * @returns {{ challenge: string, issuedAt: number }}
 */
function generateChallenge() {
  const issuedAt = Date.now();
  const random = crypto.randomBytes(16).toString("hex");
  return {
    challenge: `${issuedAt}.${random}`,
    issuedAt,
  };
}

/* ------------------------------------------------------------------ */
/*  Core verifier                                                      */
/* ------------------------------------------------------------------ */

/**
 * Verify a Proof-of-Work solution.
 *
 * Timing characteristics:
 *   • The SHA-256 computation is inherently constant-time for a fixed
 *     input length.
 *   • The leading-zero-bit check short-circuits, but this leaks at most
 *     which *byte* failed — information the client already possesses
 *     because it computed the same hash.  No secret is revealed.
 *   • Timestamp comparison uses regular arithmetic (no secret involved).
 *
 * @param {Object}  opts
 * @param {string}  opts.challenge  – the original challenge string
 * @param {number}  opts.nonce      – the nonce the client found
 * @param {number}  opts.difficulty – required leading zero bits
 * @param {number}  opts.issuedAt   – Unix-ms timestamp when the challenge was issued
 * @param {number}  [opts.maxAgeMs=60000] – maximum acceptable age in ms
 *
 * @returns {{ valid: boolean, reason?: string, hash?: string }}
 */
function verifyPoW({
  challenge,
  nonce,
  difficulty,
  issuedAt,
  maxAgeMs = 60_000,
}) {
  // ---- Input validation ------------------------------------------------
  if (typeof challenge !== "string" || challenge.length === 0) {
    return { valid: false, reason: "invalid challenge" };
  }
  if (!Number.isFinite(nonce) || nonce < 0 || !Number.isInteger(nonce)) {
    return { valid: false, reason: "invalid nonce" };
  }
  if (
    !Number.isInteger(difficulty) ||
    difficulty < 1 ||
    difficulty > 256
  ) {
    return { valid: false, reason: "invalid difficulty" };
  }
  if (!Number.isFinite(issuedAt)) {
    return { valid: false, reason: "invalid issuedAt" };
  }

  // ---- Timestamp freshness ---------------------------------------------
  const age = Date.now() - issuedAt;
  if (age > maxAgeMs) {
    return { valid: false, reason: `challenge expired (age ${age} ms > ${maxAgeMs} ms)` };
  }
  if (age < 0) {
    return { valid: false, reason: "challenge issued in the future" };
  }

  // ---- Hash computation (single SHA-256) --------------------------------
  const message = challenge + String(nonce);
  const hashBuf = crypto.createHash("sha256").update(message).digest();
  const hashHex = hashBuf.toString("hex");

  // ---- Leading zero-bit check -------------------------------------------
  const zeroBits = countLeadingZeroBits(hashBuf);
  if (zeroBits < difficulty) {
    return {
      valid: false,
      reason: `insufficient difficulty: got ${zeroBits} leading zero bits, need ${difficulty}`,
      hash: hashHex,
    };
  }

  return { valid: true, hash: hashHex };
}

/* ------------------------------------------------------------------ */
/*  Exports                                                            */
/* ------------------------------------------------------------------ */

module.exports = {
  generateChallenge,
  verifyPoW,
  countLeadingZeroBits,
};
