/**
 * index.js — Polymorphic Recaptcha & Browser Attestation Suite
 *
 * Modular unified entrypoint exposing:
 *   - compiler: polymorphic bundle compilation & session middleware
 *   - attestation: air-gapped risk scoring, token issuance & verification
 *   - pow: Proof-of-Work challenge verification and client mining
 *   - client: browser collectors (runtime, hardware, kinematics)
 */

"use strict";

const compiler = require("./compiler");
const attestation = require("./attestation");
const pow = require("./pow");
const client = require("./client");

module.exports = {
  // Subsystem namespaces
  compiler,
  attestation,
  pow,
  client,

  // Compiler entry points
  compile: compiler.compile,
  createMiddleware: compiler.createMiddleware,
  createDecryptHandler: compiler.createDecryptHandler,
  SessionStore: compiler.SessionStore,

  // Attestation & verification entry points
  createServer: attestation.createServer,
  computeScore: attestation.computeScore,
  issueToken: attestation.issueToken,
  verifyToken: attestation.verifyToken,
  attestationMiddleware: attestation.attestationMiddleware,

  // PoW entry points
  generateChallenge: pow.generateChallenge,
  verifyPoW: pow.verifyPoW,
  solvePoW: pow.solvePoW,
};

Object.assign(module.exports, { verifyTokenAsync: attestation.verifyTokenAsync, Passkeys: attestation.Passkeys, createRedisDeployment: attestation.createRedisDeployment });
