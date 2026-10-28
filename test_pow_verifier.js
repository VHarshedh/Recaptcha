/**
 * test_pow_verifier.js — Unit tests for the Node.js verifier
 *
 * Run:  node test_pow_verifier.js
 */

"use strict";

const crypto = require("node:crypto");
const { hashPoW, createScratchpad } = require("./pow_verifier");
const { generateChallenge, verifyPoW, countLeadingZeroBits } = require("./pow_verifier");

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${label}`);
  } else {
    failed++;
    console.error(`  ✗ ${label}`);
  }
}

/* ------------------------------------------------------------------ */
console.log("\n── countLeadingZeroBits ──");

assert(countLeadingZeroBits(Buffer.from([0x00, 0x00, 0xff])) === 16, "16 zero bits for 0x0000ff");
assert(countLeadingZeroBits(Buffer.from([0x00, 0x01, 0xff])) === 15, "15 zero bits for 0x0001ff");
assert(countLeadingZeroBits(Buffer.from([0x80, 0x00])) === 0, "0 zero bits for 0x8000");
assert(countLeadingZeroBits(Buffer.from([0x0f])) === 4, "4 zero bits for 0x0f");
assert(countLeadingZeroBits(Buffer.from([0x00, 0x00, 0x00, 0x00])) === 32, "32 zero bits for all zeros");

/* ------------------------------------------------------------------ */
console.log("\n── generateChallenge ──");

const ch = generateChallenge();
assert(typeof ch.challenge === "string" && ch.challenge.length > 0, "challenge is non-empty string");
assert(typeof ch.issuedAt === "number" && ch.issuedAt > 0, "issuedAt is positive number");
assert(ch.challenge.startsWith(String(ch.issuedAt)), "challenge contains timestamp prefix");

/* ------------------------------------------------------------------ */
console.log("\n── verifyPoW – valid solution ──");

// Mine a real solution with difficulty 8 (1 leading zero byte).
{
  const { challenge, issuedAt } = generateChallenge();
  const difficulty = 8;
  let nonce = 0;
  let hashHex;
  const pad = createScratchpad(challenge);
  while (true) {
    const msg = challenge + String(nonce);
    const buf = hashPoW(challenge, nonce, pad);
    if (countLeadingZeroBits(buf) >= difficulty) {
      hashHex = buf.toString("hex");
      break;
    }
    nonce++;
  }
  const result = verifyPoW({ challenge, nonce, difficulty, issuedAt });
  assert(result.valid === true, "valid solution accepted");
  assert(result.hash === hashHex, "hash matches");
}

/* ------------------------------------------------------------------ */
console.log("\n── verifyPoW – wrong nonce ──");

{
  const { challenge, issuedAt } = generateChallenge();
  const result = verifyPoW({ challenge, nonce: 999999999, difficulty: 24, issuedAt });
  // Overwhelmingly likely to fail at difficulty 24 with a random nonce.
  assert(result.valid === false, "wrong nonce rejected");
}

/* ------------------------------------------------------------------ */
console.log("\n── verifyPoW – expired challenge ──");

{
  const { challenge } = generateChallenge();
  const oldTimestamp = Date.now() - 120_000; // 2 minutes ago
  const result = verifyPoW({ challenge, nonce: 0, difficulty: 1, issuedAt: oldTimestamp });
  assert(result.valid === false, "expired challenge rejected");
  assert(result.reason.includes("expired"), "reason mentions expiry");
}

/* ------------------------------------------------------------------ */
console.log("\n── verifyPoW – future timestamp ──");

{
  const { challenge } = generateChallenge();
  const futureTs = Date.now() + 60_000;
  const result = verifyPoW({ challenge, nonce: 0, difficulty: 1, issuedAt: futureTs });
  assert(result.valid === false, "future timestamp rejected");
}

/* ------------------------------------------------------------------ */
console.log("\n── verifyPoW – bad inputs ──");

{
  const now = Date.now();
  assert(verifyPoW({ challenge: "", nonce: 0, difficulty: 1, issuedAt: now }).valid === false, "empty challenge");
  assert(verifyPoW({ challenge: "x", nonce: -1, difficulty: 1, issuedAt: now }).valid === false, "negative nonce");
  assert(verifyPoW({ challenge: "x", nonce: 0, difficulty: 0, issuedAt: now }).valid === false, "difficulty 0");
  assert(verifyPoW({ challenge: "x", nonce: 0, difficulty: 257, issuedAt: now }).valid === false, "difficulty 257");
}

/* ------------------------------------------------------------------ */
console.log(`\n${"═".repeat(40)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
