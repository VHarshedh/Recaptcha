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
const WORKER_SOURCE = "var K=new Int32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);\nvar W=new Int32Array(64),HB=new Uint8Array(32);\nfunction rr(x,n){return (x>>>n)|(x<<(32-n));}\nfunction sha256(bytes){\n var len=bytes.length,total=((len+9+63)>>6)<<6;\n var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];\n for(var off=0;off<total;off+=64){\n  for(var i=0;i<16;i++){var word=0;for(var j=0;j<4;j++){var pos=off+i*4+j;var v=pos<len?bytes[pos]:pos===len?128:pos>=total-4?((len*8)>>>((total-1-pos)*8))&255:0;word=(word<<8)|v;}W[i]=word;}\n  for(var i=16;i<64;i++){var x=W[i-15],y=W[i-2];W[i]=(W[i-16]+(rr(x,7)^rr(x,18)^(x>>>3))+W[i-7]+(rr(y,17)^rr(y,19)^(y>>>10)))|0;}\n  var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];\n  for(var i=0;i<64;i++){var t1=(h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+K[i]+W[i])|0;var t2=((rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c)))|0;h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}\n  H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;\n }\n for(var i=0;i<32;i++)HB[i]=(H[i>>2]>>>(24-(i%4)*8))&255;\n return HB;\n}\n/**\n * pow_worker.js \u2014 Proof-of-Work Web Worker\n *\n * Protocol:\n *   IN  \u2192 { challenge: string, difficulty: number }\n *         difficulty = number of leading zero BITS required in the SHA-256 hash\n *   OUT \u2190 { nonce: number, hash: string, durationMs: number }\n *\n * Uses crypto.subtle.digest with pre-allocated ArrayBuffers for throughput.\n * Reports progress every ~50 000 iterations so the orchestrator can show UI\n * feedback if desired.\n */\n\n\"use strict\";\n\n/* ------------------------------------------------------------------ */\n/*  Helpers                                                            */\n/* ------------------------------------------------------------------ */\n\n/**\n * Convert a hex string to its leading-zero-bit count.\n * Operates on the raw bytes (2 hex chars = 1 byte = 8 bits) so we\n * never pay for BigInt or bit-string conversion.\n *\n * @param {Uint8Array} bytes  \u2013 the 32-byte SHA-256 digest\n * @returns {number}          \u2013 count of leading zero bits\n */\nfunction countLeadingZeroBits(bytes) {\n  let bits = 0;\n  for (let i = 0; i < bytes.length; i++) {\n    if (bytes[i] === 0) {\n      bits += 8;\n    } else {\n      // Math.clz32 counts from bit-31; subtract 24 because we have an 8-bit value.\n      bits += Math.clz32(bytes[i]) - 24;\n      break;\n    }\n  }\n  return bits;\n}\n\n/**\n * Encode a string into a Uint8Array (UTF-8).  We avoid TextEncoder\n * instantiation inside the hot loop by keeping a module-level encoder.\n */\nfunction createScratchpad(challenge) {\n  var pad = new Int32Array(16384), seed = 2166136261;\n  for (var i = 0; i < challenge.length; i++) seed = Math.imul(seed ^ challenge.charCodeAt(i), 16777619);\n  for (var j = 0; j < pad.length; j++) {\n    seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5;\n    seed = (seed + Math.imul(j + 1, 0x9e3779b9)) | 0; pad[j] = seed;\n  }\n  return pad;\n}\nfunction scratchSuffix(pad, nonce) {\n  var x = (nonce | 0) ^ Math.floor(nonce / 4294967296), y = 0x6a09e667;\n  for (var i = 0; i < 64; i++) {\n    x = Math.imul(x ^ pad[(x ^ y) & 16383], 0x85ebca6b);\n    x = (x << 13) | (x >>> 19);\n    y = (Math.imul(y ^ x, 0xc2b2ae35) + i) | 0;\n  }\n  return \":cache64-v1:\" + (x >>> 0) + \":\" + (y >>> 0);\n}\nconst encoder = new TextEncoder();\n\n/**\n * Convert a Uint8Array to a lowercase hex string.\n * @param {Uint8Array} buf\n * @returns {string}\n */\nfunction bytesToHex(buf) {\n  // Pre-built lookup is ~3\u00d7 faster than .toString(16) in a loop.\n  const LUT = \"0123456789abcdef\";\n  let hex = \"\";\n  for (let i = 0; i < buf.length; i++) {\n    hex += LUT[buf[i] >> 4] + LUT[buf[i] & 0x0f];\n  }\n  return hex;\n}\n\n/* ------------------------------------------------------------------ */\n/*  Main mining loop                                                   */\n/* ------------------------------------------------------------------ */\n\n/**\n * Mine a nonce such that SHA-256(challenge || nonce) has at least\n * `difficulty` leading zero bits.\n *\n * @param {string} challenge\n * @param {number} difficulty\n */\nasync function mine(challenge, difficulty) {\n  if (typeof challenge !== \"string\" || !challenge) {\n    throw new Error(\"challenge must be a non-empty string\");\n  }\n  if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 256) {\n    throw new Error(\"difficulty must be an integer in [1, 256]\");\n  }\n\n  const t0 = performance.now();\n\n  // Pre-encode the static challenge prefix once.\n  const challengeBytes = encoder.encode(challenge);\n\n  // We construct the message buffer as:  challengeBytes + ASCII(nonce)\n  // Because nonce length varies, we rebuild the tail each iteration.\n  // To minimise allocations we reuse a shared buffer large enough for\n  // challenge + up to 20 digits of nonce (2^64 has 20 decimal digits).\n  const maxNonceLen = 80;\n  const pad = createScratchpad(challenge);\n  const buf = new Uint8Array(challengeBytes.length + maxNonceLen);\n  buf.set(challengeBytes, 0);\n\n  const BATCH = 50_000; // iterations between progress reports\n  let nonce = 0;\n\n  while (true) {\n    // Encode nonce suffix directly into buf to avoid per-iteration allocs.\n    const nonceStr = String(nonce) + scratchSuffix(pad, nonce);\n    const nonceLen = nonceStr.length;\n    for (let j = 0; j < nonceLen; j++) {\n      buf[challengeBytes.length + j] = nonceStr.charCodeAt(j);\n    }\n    const messageSlice = buf.subarray(0, challengeBytes.length + nonceLen);\n\n    // Compute SHA-256 via SubtleCrypto (hardware-accelerated where available).\n    const hashBytes = sha256(messageSlice);\n\n    if (countLeadingZeroBits(hashBytes) >= difficulty) {\n      const durationMs = Math.round(performance.now() - t0);\n      return {\n        nonce,\n        hash: bytesToHex(hashBytes),\n        durationMs,\n      };\n    }\n\n    nonce++;\n\n    // Periodic progress heartbeat.\n    if (nonce % BATCH === 0) {\n      self.postMessage({\n        type: \"progress\",\n        nonce,\n        elapsedMs: Math.round(performance.now() - t0),\n      });\n    }\n  }\n}\n\n/* ------------------------------------------------------------------ */\n/*  Message handler                                                    */\n/* ------------------------------------------------------------------ */\n\nself.addEventListener(\"message\", async (evt) => {\n  const { challenge, difficulty } = evt.data;\n  try {\n    const result = await mine(challenge, difficulty);\n    self.postMessage({ type: \"result\", ...result });\n  } catch (err) {\n    self.postMessage({ type: \"error\", message: err.message });\n  }\n});\n";

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
