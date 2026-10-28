"use strict";
// Fixed 64 KiB read-only pad per challenge; never mutated across nonce trials.
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
module.exports = { createScratchpad, scratchSuffix };
