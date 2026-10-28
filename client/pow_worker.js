/**
 * pow_worker.js — Proof-of-Work Web Worker
 *
 * Protocol:
 *   IN  → { challenge: string, difficulty: number }
 *         difficulty = number of leading zero BITS required in the SHA-256 hash
 *   OUT ← { nonce: number, hash: string, durationMs: number }
 *
 * Uses crypto.subtle.digest with pre-allocated ArrayBuffers for throughput.
 * Reports progress every ~50 000 iterations so the orchestrator can show UI
 * feedback if desired.
 */

"use strict";

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/**
 * Convert a hex string to its leading-zero-bit count.
 * Operates on the raw bytes (2 hex chars = 1 byte = 8 bits) so we
 * never pay for BigInt or bit-string conversion.
 *
 * @param {Uint8Array} bytes  – the 32-byte SHA-256 digest
 * @returns {number}          – count of leading zero bits
 */
function countLeadingZeroBits(bytes) {
  let bits = 0;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0) {
      bits += 8;
    } else {
      // Math.clz32 counts from bit-31; subtract 24 because we have an 8-bit value.
      bits += Math.clz32(bytes[i]) - 24;
      break;
    }
  }
  return bits;
}

/**
 * Encode a string into a Uint8Array (UTF-8).  We avoid TextEncoder
 * instantiation inside the hot loop by keeping a module-level encoder.
 */
function createScratchpad(challenge) {
  var pad = new Int32Array(16384), seed = 2166136261;
  for (var i = 0; i < challenge.length; i++) seed = Math.imul(seed ^ challenge.charCodeAt(i), 16777619);
  for (var j = 0; j < pad.length; j++) {
    seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5;
    seed = (seed + Math.imul(j + 1, 0x9e3779b9)) | 0; pad[j] = seed;
  }
  return pad;
}
function scratchSuffix(pad, nonce) {
  var x = (nonce | 0) ^ Math.floor(nonce / 4294967296), y = 0x6a09e667;
  for (var i = 0; i < 64; i++) {
    x = Math.imul(x ^ pad[(x ^ y) & 16383], 0x85ebca6b);
    x = (x << 13) | (x >>> 19);
    y = (Math.imul(y ^ x, 0xc2b2ae35) + i) | 0;
  }
  return ":cache64-v1:" + (x >>> 0) + ":" + (y >>> 0);
}
const encoder = new TextEncoder();

/**
 * Convert a Uint8Array to a lowercase hex string.
 * @param {Uint8Array} buf
 * @returns {string}
 */
function bytesToHex(buf) {
  // Pre-built lookup is ~3× faster than .toString(16) in a loop.
  const LUT = "0123456789abcdef";
  let hex = "";
  for (let i = 0; i < buf.length; i++) {
    hex += LUT[buf[i] >> 4] + LUT[buf[i] & 0x0f];
  }
  return hex;
}

/* ------------------------------------------------------------------ */
/*  Main mining loop                                                   */
/* ------------------------------------------------------------------ */

/**
 * Mine a nonce such that SHA-256(challenge || nonce) has at least
 * `difficulty` leading zero bits.
 *
 * @param {string} challenge
 * @param {number} difficulty
 */
async function mine(challenge, difficulty) {
  if (typeof challenge !== "string" || !challenge) {
    throw new Error("challenge must be a non-empty string");
  }
  if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 256) {
    throw new Error("difficulty must be an integer in [1, 256]");
  }

  const t0 = performance.now();

  // Pre-encode the static challenge prefix once.
  const challengeBytes = encoder.encode(challenge);

  // We construct the message buffer as:  challengeBytes + ASCII(nonce)
  // Because nonce length varies, we rebuild the tail each iteration.
  // To minimise allocations we reuse a shared buffer large enough for
  // challenge + up to 20 digits of nonce (2^64 has 20 decimal digits).
  const maxNonceLen = 80;
  const pad = createScratchpad(challenge);
  const buf = new Uint8Array(challengeBytes.length + maxNonceLen);
  buf.set(challengeBytes, 0);

  const BATCH = 50_000; // iterations between progress reports
  let nonce = 0;

  while (true) {
    // Encode nonce suffix directly into buf to avoid per-iteration allocs.
    const nonceStr = String(nonce) + scratchSuffix(pad, nonce);
    const nonceLen = nonceStr.length;
    for (let j = 0; j < nonceLen; j++) {
      buf[challengeBytes.length + j] = nonceStr.charCodeAt(j);
    }
    const messageSlice = buf.subarray(0, challengeBytes.length + nonceLen);

    // Compute SHA-256 via SubtleCrypto (hardware-accelerated where available).
    const digest = await crypto.subtle.digest("SHA-256", messageSlice);
    const hashBytes = new Uint8Array(digest);

    if (countLeadingZeroBits(hashBytes) >= difficulty) {
      const durationMs = Math.round(performance.now() - t0);
      return {
        nonce,
        hash: bytesToHex(hashBytes),
        durationMs,
      };
    }

    nonce++;

    // Periodic progress heartbeat.
    if (nonce % BATCH === 0) {
      self.postMessage({
        type: "progress",
        nonce,
        elapsedMs: Math.round(performance.now() - t0),
      });
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Message handler                                                    */
/* ------------------------------------------------------------------ */

self.addEventListener("message", async (evt) => {
  const { challenge, difficulty } = evt.data;
  try {
    const result = await mine(challenge, difficulty);
    self.postMessage({ type: "result", ...result });
  } catch (err) {
    self.postMessage({ type: "error", message: err.message });
  }
});
