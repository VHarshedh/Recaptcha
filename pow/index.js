/**
 * pow/index.js — Proof-of-Work Subsystem Module
 *
 * Provides server-side PoW challenge generation & verification,
 * and client-side background mining orchestrators.
 */

"use strict";

const verifier = require("./verifier");
const client = require("./client");

module.exports = {
  // Server-side verification
  generateChallenge: verifier.generateChallenge,
  verifyPoW: verifier.verifyPoW,
  countLeadingZeroBits: verifier.countLeadingZeroBits,

  // Client-side solver
  solvePoW: client.solvePoW,
  WORKER_SOURCE: client.WORKER_SOURCE,
};
