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
const WORKER_SOURCE = `
"use strict";
const encoder = new TextEncoder();
function countLeadingZeroBits(bytes) {
  let bits = 0;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0) { bits += 8; }
    else { bits += Math.clz32(bytes[i]) - 24; break; }
  }
  return bits;
}
function bytesToHex(buf) {
  const L = "0123456789abcdef";
  let h = "";
  for (let i = 0; i < buf.length; i++) h += L[buf[i] >> 4] + L[buf[i] & 0x0f];
  return h;
}
async function mine(challenge, difficulty) {
  if (typeof challenge !== "string" || !challenge) throw new Error("challenge must be a non-empty string");
  if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 256) throw new Error("difficulty must be in [1,256]");
  const t0 = performance.now();
  const cb = encoder.encode(challenge);
  const maxNL = 20;
  const buf = new Uint8Array(cb.length + maxNL);
  buf.set(cb, 0);
  const BATCH = 50000;
  let nonce = 0;
  while (true) {
    const ns = String(nonce), nl = ns.length;
    for (let j = 0; j < nl; j++) buf[cb.length + j] = ns.charCodeAt(j);
    const d = await crypto.subtle.digest("SHA-256", buf.subarray(0, cb.length + nl));
    const hb = new Uint8Array(d);
    if (countLeadingZeroBits(hb) >= difficulty) {
      return { nonce, hash: bytesToHex(hb), durationMs: Math.round(performance.now() - t0) };
    }
    nonce++;
    if (nonce % BATCH === 0) self.postMessage({ type:"progress", nonce, elapsedMs: Math.round(performance.now() - t0) });
  }
}
self.addEventListener("message", async (e) => {
  try { const r = await mine(e.data.challenge, e.data.difficulty); self.postMessage({ type:"result", ...r }); }
  catch (err) { self.postMessage({ type:"error", message: err.message }); }
});
`;

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
