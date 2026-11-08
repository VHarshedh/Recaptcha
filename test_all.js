/**
 * test_all.js — Master Test Suite Runner
 *
 * Runs all unit, integration, crypto, and security test suites across
 * the modular codebase and verifies module entry points.
 *
 * Run:
 *   node test_all.js
 *   npm test
 */

"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");

const ROOT_DIR = __dirname;

const TEST_SUITES = [
  { name: "Production Restart Isolation", file: "test_restart_binding.js" },
  { name: "Canonical IP Identities", file: "test_ip_identity.js" },
  { name: "Mapped IPv4 Token Binding", file: "test_mapped_ip_binding.js" },
  { name: "Malformed Token Availability", file: "test_malformed_tokens.js" },
  { name: "Puzzle Work Gate", file: "test_puzzle_gate.js" },
  { name: "Demo Token Isolation", file: "test_demo_tokens.js" },
  { name: "Nonce Rotation Replay Regression", file: "test_nonce_rotation.js" },
  { name: "Hardening regressions", file: "test_hardening.js" },
  { name: "Boundary Security Regressions", file: "test_boundary_security.js" },
  { name: "Modular Exports Verification", file: null, run: testModularExports },
  { name: "Compiler Suite", file: "compiler/test_compiler.js" },
  { name: "Attestation Suite", file: "attestation/test_attestation.js" },
  { name: "PoW Verifier Suite", file: "test_pow_verifier.js" },
  { name: "PoW Inline Worker Suite", file: "test_pow_inline.js" },
  { name: "E2E Crypto & Scoring Suite", file: "test_e2e_crypto.js" },
  { name: "Adaptive Challenge & Step-Up Suite", file: "test_adaptive_e2e.js" },
  { name: "Security & Anti-Spoofing Regressions", file: "test_security.js" },
];

function testModularExports() {
  const root = require("./index.js");
  const compiler = require("./compiler");
  const attestation = require("./attestation");
  const pow = require("./pow");
  const client = require("./client");

  // Verify top-level root exports
  if (typeof root.compile !== "function") throw new Error("root.compile missing");
  if (typeof root.createMiddleware !== "function") throw new Error("root.createMiddleware missing");
  if (typeof root.computeScore !== "function") throw new Error("root.computeScore missing");
  if (typeof root.issueToken !== "function") throw new Error("root.issueToken missing");
  if (typeof root.verifyToken !== "function") throw new Error("root.verifyToken missing");
  if (typeof root.generateChallenge !== "function") throw new Error("root.generateChallenge missing");
  if (typeof root.verifyPoW !== "function") throw new Error("root.verifyPoW missing");

  // Verify compiler exports
  if (typeof compiler.compile !== "function") throw new Error("compiler.compile missing");
  if (typeof compiler.SessionStore !== "function") throw new Error("compiler.SessionStore missing");
  if (typeof compiler.generateEphemeralKeyPair !== "function") throw new Error("compiler.generateEphemeralKeyPair missing");

  // Verify attestation exports
  if (typeof attestation.createServer !== "function") throw new Error("attestation.createServer missing");
  if (typeof attestation.computeScore !== "function") throw new Error("attestation.computeScore missing");
  if (typeof attestation.AdaptiveChallenge !== "function") throw new Error("attestation.AdaptiveChallenge missing");
  if (typeof attestation.extractHeaderProfile !== "function") throw new Error("attestation.extractHeaderProfile missing");

  // Verify pow exports
  if (typeof pow.generateChallenge !== "function") throw new Error("pow.generateChallenge missing");
  if (typeof pow.verifyPoW !== "function") throw new Error("pow.verifyPoW missing");
  if (typeof pow.solvePoW !== "function") throw new Error("pow.solvePoW missing");

  // Verify client exports
  if (typeof client.CLIENT_DIR !== "string") throw new Error("client.CLIENT_DIR missing");
  if (!Array.isArray(client.COLLECTOR_FILES)) throw new Error("client.COLLECTOR_FILES missing");
}

function run() {
  console.log("════════════════════════════════════════════════════════════");
  console.log("  Recaptcha Attestation Suite — Running All Test Suites");
  console.log("════════════════════════════════════════════════════════════\n");

  let totalPassed = 0;
  let totalFailed = 0;
  const startAll = Date.now();

  for (const suite of TEST_SUITES) {
    const t0 = Date.now();
    process.stdout.write(`▶ Running ${suite.name}... `);

    if (suite.run) {
      try {
        suite.run();
        const duration = Date.now() - t0;
        console.log(`✓ PASSED (${duration} ms)`);
        totalPassed++;
      } catch (err) {
        console.log(`✗ FAILED`);
        console.error(`  Error: ${err.message}`);
        totalFailed++;
      }
      continue;
    }

    const res = spawnSync(process.execPath, [path.join(ROOT_DIR, suite.file)], {
      cwd: ROOT_DIR,
      encoding: "utf8",
      env: process.env,
    });

    const duration = Date.now() - t0;
    if (res.status === 0) {
      console.log(`✓ PASSED (${duration} ms)`);
      totalPassed++;
    } else {
      console.log(`✗ FAILED (${duration} ms)`);
      if (res.stdout) console.log(res.stdout);
      if (res.stderr) console.error(res.stderr);
      totalFailed++;
    }
  }

  const totalDuration = ((Date.now() - startAll) / 1000).toFixed(2);
  console.log("\n════════════════════════════════════════════════════════════");
  console.log(`Summary: ${totalPassed} passed, ${totalFailed} failed (Total: ${totalDuration}s)`);
  console.log("════════════════════════════════════════════════════════════");

  process.exit(totalFailed > 0 ? 1 : 0);
}

run();
