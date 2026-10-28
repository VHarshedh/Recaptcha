/**
 * pow_client.js — Client-side PoW orchestrator
 *
 * Provides two consumption modes:
 *   1. Inline Blob worker   – zero extra network requests; the worker
 *      source is embedded at build time via the exported `WORKER_SOURCE`.
 *   2. Static asset worker  – loads `pow_worker.js` from the same origin.
 *
 * Public API:
 *   solvePoW({ challenge, difficulty, workerUrl?, onProgress? }) → Promise<result>
 *
 * The returned promise resolves with:
 *   { nonce: number, hash: string, durationMs: number }
 *
 * Everything runs off the main thread; the UI stays fully responsive.
 */

"use strict";

/* ------------------------------------------------------------------ */
/*  Embedded worker source (for inline Blob mode)                      */
/* ------------------------------------------------------------------ */

// prettier-ignore
const WORKER_SOURCE = "/**\n * pow_worker.js — Proof-of-Work Web Worker\n *\n * Protocol:\n *   IN  → { challenge: string, difficulty: number }\n *         difficulty = number of leading zero BITS required in the SHA-256 hash\n *   OUT ← { nonce: number, hash: string, durationMs: number }\n *\n * Uses crypto.subtle.digest with pre-allocated ArrayBuffers for throughput.\n * Reports progress every ~50 000 iterations so the orchestrator can show UI\n * feedback if desired.\n */\n\n\"use strict\";\n\n/* ------------------------------------------------------------------ */\n/*  Helpers                                                            */\n/* ------------------------------------------------------------------ */\n\n/**\n * Convert a hex string to its leading-zero-bit count.\n * Operates on the raw bytes (2 hex chars = 1 byte = 8 bits) so we\n * never pay for BigInt or bit-string conversion.\n *\n * @param {Uint8Array} bytes  – the 32-byte SHA-256 digest\n * @returns {number}          – count of leading zero bits\n */\nfunction countLeadingZeroBits(bytes) {\n  let bits = 0;\n  for (let i = 0; i < bytes.length; i++) {\n    if (bytes[i] === 0) {\n      bits += 8;\n    } else {\n      // Math.clz32 counts from bit-31; subtract 24 because we have an 8-bit value.\n      bits += Math.clz32(bytes[i]) - 24;\n      break;\n    }\n  }\n  return bits;\n}\n\n/**\n * Encode a string into a Uint8Array (UTF-8).  We avoid TextEncoder\n * instantiation inside the hot loop by keeping a module-level encoder.\n */\nfunction createScratchpad(challenge) {\n  var pad = new Int32Array(16384), seed = 2166136261;\n  for (var i = 0; i < challenge.length; i++) seed = Math.imul(seed ^ challenge.charCodeAt(i), 16777619);\n  for (var j = 0; j < pad.length; j++) {\n    seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5;\n    seed = (seed + Math.imul(j + 1, 0x9e3779b9)) | 0; pad[j] = seed;\n  }\n  return pad;\n}\nfunction scratchSuffix(pad, nonce) {\n  var x = (nonce | 0) ^ Math.floor(nonce / 4294967296), y = 0x6a09e667;\n  for (var i = 0; i < 64; i++) {\n    x = Math.imul(x ^ pad[(x ^ y) & 16383], 0x85ebca6b);\n    x = (x << 13) | (x >>> 19);\n    y = (Math.imul(y ^ x, 0xc2b2ae35) + i) | 0;\n  }\n  return \":cache64-v1:\" + (x >>> 0) + \":\" + (y >>> 0);\n}\nconst encoder = new TextEncoder();\n\n/**\n * Convert a Uint8Array to a lowercase hex string.\n * @param {Uint8Array} buf\n * @returns {string}\n */\nfunction bytesToHex(buf) {\n  // Pre-built lookup is ~3× faster than .toString(16) in a loop.\n  const LUT = \"0123456789abcdef\";\n  let hex = \"\";\n  for (let i = 0; i < buf.length; i++) {\n    hex += LUT[buf[i] >> 4] + LUT[buf[i] & 0x0f];\n  }\n  return hex;\n}\n\n/* ------------------------------------------------------------------ */\n/*  Main mining loop                                                   */\n/* ------------------------------------------------------------------ */\n\n/**\n * Mine a nonce such that SHA-256(challenge || nonce) has at least\n * `difficulty` leading zero bits.\n *\n * @param {string} challenge\n * @param {number} difficulty\n */\nasync function mine(challenge, difficulty) {\n  if (typeof challenge !== \"string\" || !challenge) {\n    throw new Error(\"challenge must be a non-empty string\");\n  }\n  if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 256) {\n    throw new Error(\"difficulty must be an integer in [1, 256]\");\n  }\n\n  const t0 = performance.now();\n\n  // Pre-encode the static challenge prefix once.\n  const challengeBytes = encoder.encode(challenge);\n\n  // We construct the message buffer as:  challengeBytes + ASCII(nonce)\n  // Because nonce length varies, we rebuild the tail each iteration.\n  // To minimise allocations we reuse a shared buffer large enough for\n  // challenge + up to 20 digits of nonce (2^64 has 20 decimal digits).\n  const maxNonceLen = 80;\n  const pad = createScratchpad(challenge);\n  const buf = new Uint8Array(challengeBytes.length + maxNonceLen);\n  buf.set(challengeBytes, 0);\n\n  const BATCH = 50_000; // iterations between progress reports\n  let nonce = 0;\n\n  while (true) {\n    // Encode nonce suffix directly into buf to avoid per-iteration allocs.\n    const nonceStr = String(nonce) + scratchSuffix(pad, nonce);\n    const nonceLen = nonceStr.length;\n    for (let j = 0; j < nonceLen; j++) {\n      buf[challengeBytes.length + j] = nonceStr.charCodeAt(j);\n    }\n    const messageSlice = buf.subarray(0, challengeBytes.length + nonceLen);\n\n    // Compute SHA-256 via SubtleCrypto (hardware-accelerated where available).\n    const digest = await crypto.subtle.digest(\"SHA-256\", messageSlice);\n    const hashBytes = new Uint8Array(digest);\n\n    if (countLeadingZeroBits(hashBytes) >= difficulty) {\n      const durationMs = Math.round(performance.now() - t0);\n      return {\n        nonce,\n        hash: bytesToHex(hashBytes),\n        durationMs,\n      };\n    }\n\n    nonce++;\n\n    // Periodic progress heartbeat.\n    if (nonce % BATCH === 0) {\n      self.postMessage({\n        type: \"progress\",\n        nonce,\n        elapsedMs: Math.round(performance.now() - t0),\n      });\n    }\n  }\n}\n\n/* ------------------------------------------------------------------ */\n/*  Message handler                                                    */\n/* ------------------------------------------------------------------ */\n\nself.addEventListener(\"message\", async (evt) => {\n  const { challenge, difficulty } = evt.data;\n  try {\n    const result = await mine(challenge, difficulty);\n    self.postMessage({ type: \"result\", ...result });\n  } catch (err) {\n    self.postMessage({ type: \"error\", message: err.message });\n  }\n});\n";

/* ------------------------------------------------------------------ */
/*  Worker factory                                                     */
/* ------------------------------------------------------------------ */

/**
 * Create a disposable Web Worker.
 *
 * @param {string} [workerUrl] – optional URL to `pow_worker.js`.
 *   When omitted the worker is created from an inline Blob.
 * @returns {Worker}
 */
function createWorker(workerUrl) {
  if (workerUrl) {
    return new Worker(workerUrl);
  }
  const blob = new Blob([WORKER_SOURCE], { type: "application/javascript" });
  const url = URL.createObjectURL(blob);
  const worker = new Worker(url);
  // Revoke the object-URL once the worker has loaded (it keeps its own ref).
  worker.addEventListener("error", () => URL.revokeObjectURL(url), { once: true });
  // Small delay so the worker can finish loading before we revoke.
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  return worker;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

/**
 * Solve a Proof-of-Work challenge without blocking the main thread.
 *
 * @param {Object}   opts
 * @param {string}   opts.challenge    – server-issued challenge token
 * @param {number}   opts.difficulty   – required leading zero bits
 * @param {string}   [opts.workerUrl]  – URL to pow_worker.js (omit for inline Blob)
 * @param {Function} [opts.onProgress] – callback({ nonce, elapsedMs })
 * @param {number}   [opts.timeoutMs=120000] – hard timeout in ms
 *
 * @returns {Promise<{ nonce: number, hash: string, durationMs: number }>}
 */
function solvePoW({
  challenge,
  difficulty,
  workerUrl,
  onProgress,
  timeoutMs = 120_000,
}) {
  return new Promise((resolve, reject) => {
    const worker = createWorker(workerUrl);
    let settled = false;

    // Hard timeout guard.
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        worker.terminate();
        reject(new Error(`PoW timed out after ${timeoutMs} ms`));
      }
    }, timeoutMs);

    worker.addEventListener("message", (evt) => {
      const data = evt.data;

      if (data.type === "progress" && typeof onProgress === "function") {
        onProgress({ nonce: data.nonce, elapsedMs: data.elapsedMs });
        return;
      }

      if (data.type === "result") {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          worker.terminate();
          resolve({
            nonce: data.nonce,
            hash: data.hash,
            durationMs: data.durationMs,
          });
        }
        return;
      }

      if (data.type === "error") {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          worker.terminate();
          reject(new Error(data.message));
        }
      }
    });

    worker.addEventListener("error", (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        worker.terminate();
        reject(err);
      }
    });

    // Kick off the mining.
    worker.postMessage({ challenge, difficulty });
  });
}

/* ------------------------------------------------------------------ */
/*  Exports / global attachment                                        */
/* ------------------------------------------------------------------ */

// UMD-lite: works as ES module, CommonJS, or plain <script>.
if (typeof module !== "undefined" && module.exports) {
  module.exports = { solvePoW, WORKER_SOURCE };
} else if (typeof window !== "undefined") {
  window.solvePoW = solvePoW;
}
