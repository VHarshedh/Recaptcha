/**
 * attestation/index.js — Air-Gapped Attestation & Scoring Subsystem
 *
 * Provides:
 *   - HTTP microservice factory (`createServer`)
 *   - Raw telemetry risk scoring (`computeScore`)
 *   - Ed25519 token minting & verification (`issueToken`, `verifyToken`, `attestationMiddleware`)
 *   - Adaptive step-up challenges & visual captcha (`AdaptiveChallenge`, `generateVisual`)
 *   - Privacy-preserving IP subnet masking & trusted proxy parsing (`maskIP`, `getClientIP`)
 *   - Header & browser consistency validation (`extractHeaderProfile`, `verifyHeaderConsistency`)
 */

"use strict";

const server = require("./server");
const scorer = require("./scorer");
const token = require("./token");
const verifier = require("./verifier");
const ipMask = require("./ip_mask");
const keys = require("./keys");
const nonceCache = require("./nonce_cache");
const adaptive = require("./adaptive_challenge");
const headerCheck = require("./header_check");
const visual = require("./visual_captcha");

module.exports = {
  // Microservice server factory
  createServer: server.createServer,

  // Risk scoring
  computeScore: scorer.computeScore,
  WEIGHTS: scorer.WEIGHTS,
  _scoreRuntime: scorer._scoreRuntime,
  _scoreHardware: scorer._scoreHardware,
  _scoreKinematics: scorer._scoreKinematics,
  _scorePoW: scorer._scorePoW,

  // Token minting & verification
  issueToken: token.issueToken,
  MIN_TTL_S: token.MIN_TTL_S,
  MAX_TTL_S: token.MAX_TTL_S,
  verifyToken: verifier.verifyToken,
  attestationMiddleware: verifier.attestationMiddleware,

  // IP masking & network extraction
  maskIP: ipMask.maskIP,
  getClientIP: ipMask.getClientIP,

  // Signing keys
  keys: {
    publicKey: keys.publicKey,
    privateKey: keys.privateKey,
    publicKeyPem: keys.publicKeyPem,
    publicKeyDer: keys.publicKeyDer,
  },

  // Single-use nonce tracking
  NonceCache: nonceCache.NonceCache,

  // Adaptive challenge & step-up
  AdaptiveChallenge: adaptive.AdaptiveChallenge,
  difficultyForScore: adaptive.difficultyForScore,

  // Header & client consistency check
  extractHeaderProfile: headerCheck.extractHeaderProfile,
  verifyHeaderConsistency: headerCheck.verifyHeaderConsistency,

  // Visual captcha generator
  visualCaptcha: {
    generateVisual: visual.generateVisual,
    renderAnswer: visual.renderAnswer,
    answerHash: visual.answerHash,
    ALPHABET: visual.ALPHABET,
  },
};
