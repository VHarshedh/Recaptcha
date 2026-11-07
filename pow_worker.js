var K=new Int32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
var W=new Int32Array(64),HB=new Uint8Array(32);
function rr(x,n){return (x>>>n)|(x<<(32-n));}
function sha256(bytes){
 var len=bytes.length,total=((len+9+63)>>6)<<6;
 var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
 for(var off=0;off<total;off+=64){
  for(var i=0;i<16;i++){var word=0;for(var j=0;j<4;j++){var pos=off+i*4+j;var v=pos<len?bytes[pos]:pos===len?128:pos>=total-4?((len*8)>>>((total-1-pos)*8))&255:0;word=(word<<8)|v;}W[i]=word;}
  for(var i=16;i<64;i++){var x=W[i-15],y=W[i-2];W[i]=(W[i-16]+(rr(x,7)^rr(x,18)^(x>>>3))+W[i-7]+(rr(y,17)^rr(y,19)^(y>>>10)))|0;}
  var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
  for(var i=0;i<64;i++){var t1=(h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+K[i]+W[i])|0;var t2=((rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c)))|0;h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}
  H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;
 }
 for(var i=0;i<32;i++)HB[i]=(H[i>>2]>>>(24-(i%4)*8))&255;
 return HB;
}
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
    const hashBytes = sha256(messageSlice);

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
