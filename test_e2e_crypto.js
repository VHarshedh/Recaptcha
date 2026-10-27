/**
 * test_e2e_crypto.js — End-to-end ECDH + AES-GCM + Server-Verified PoW + Attestation Test
 */

"use strict";

const crypto = require("node:crypto");
const { generateEphemeralKeyPair, decryptTelemetry } = require("./compiler/ecdh_session");
const { generateChallenge, verifyPoW, countLeadingZeroBits } = require("./pow_verifier");
const { computeScore } = require("./attestation/scorer");
const { issueToken } = require("./attestation/token");
const { verifyToken } = require("./attestation/verifier");
const { maskIP } = require("./attestation/ip_mask");

function solvePoWLocal(challenge, difficulty) {
  let nonce = 0;
  const t0 = Date.now();
  while (true) {
    const hash = crypto.createHash("sha256").update(challenge + String(nonce)).digest();
    if (countLeadingZeroBits(hash) >= difficulty) {
      return {
        nonce,
        hash: hash.toString("hex"),
        durationMs: Date.now() - t0,
      };
    }
    nonce++;
  }
}

async function run() {
  console.log("Starting End-to-End Test...");

  // 1. Server generates ephemeral ECDH key pair and PoW challenge
  const serverKP = generateEphemeralKeyPair();
  const powChallenge = generateChallenge();
  const powDifficulty = 8; // fast for integration test
  console.log("1. Server ECDH KeyPair generated, session ID:", serverKP.id);
  console.log("   PoW Challenge issued:", powChallenge.challenge);

  // 2. Client solves PoW challenge
  const powSolution = solvePoWLocal(powChallenge.challenge, powDifficulty);
  console.log(`2. Client solved PoW: nonce=${powSolution.nonce} duration=${powSolution.durationMs}ms`);

  // 3. Client collects raw telemetry and encrypts via Web Crypto ECDH + AES-GCM
  const serverPubDer = Buffer.from(serverKP.publicKeyBase64, "base64");
  const serverPub = await crypto.subtle.importKey(
    "spki",
    serverPubDer,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  const clientKP = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );

  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverPub },
    clientKP.privateKey,
    256
  );

  const aesKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const rawTelemetry = {
    action: "login",
    runtime: { confidence_penalty: 0, anomalies: [] },
    hardware: { profile: { hardwareConcurrency: 8 }, consistency: "consistent", webgl: {}, audio: {} },
    kinematics: { eventCounts: { mousemove: 80 }, mouse: { pointCount: 20, entropyRatio: 0.85 } },
    pow: {
      challenge: powChallenge.challenge,
      nonce: powSolution.nonce,
      durationMs: powSolution.durationMs,
    },
  };

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(rawTelemetry));
  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    plaintext
  );

  const clientPubSpki = await crypto.subtle.exportKey("spki", clientKP.publicKey);

  const wirePayload = {
    cpk: Buffer.from(clientPubSpki).toString("base64"),
    iv: Buffer.from(iv).toString("base64"),
    ct: Buffer.from(cipherBuf).toString("base64"),
    sid: serverKP.id,
  };

  console.log("3. Telemetry encrypted with AES-GCM. Ciphertext length:", wirePayload.ct.length);

  // 4. Server receives and decrypts payload using ECDH private key
  const decrypted = decryptTelemetry(wirePayload, serverKP.privateKey);
  console.log("4. Server decrypted telemetry successfully:");
  console.log("   Action:", decrypted.action);

  // 5. Server cryptographically verifies the PoW challenge
  const powVerification = verifyPoW({
    challenge: powChallenge.challenge,
    nonce: decrypted.pow.nonce,
    difficulty: powDifficulty,
    issuedAt: powChallenge.issuedAt,
  });

  if (!powVerification.valid) {
    throw new Error(`Server PoW verification failed: ${powVerification.reason}`);
  }
  console.log("5. Server verified PoW successfully:", powVerification.valid);

  // Overwrite client-reported PoW with server verified state
  decrypted.pow = {
    serverVerified: powVerification.valid,
    difficulty: powDifficulty,
    durationMs: decrypted.pow.durationMs,
    hash: powVerification.hash,
  };

  // 6. Server scores the decrypted payload using raw signals
  const scoreResult = computeScore(decrypted);
  console.log("6. Telemetry scored:");
  console.log("   Score:", scoreResult.score);
  console.log("   Clamped:", scoreResult.clamped);

  if (scoreResult.score < 0.7) {
    throw new Error(`Score too low for clean telemetry: ${scoreResult.score}`);
  }

  // 7. Server issues Ed25519 token
  const clientIP = "203.0.113.195";
  const ipSubnet = maskIP(clientIP);
  const tokenResult = issueToken({
    score: scoreResult.score,
    action: decrypted.action,
    ipSubnet,
  });
  console.log("7. Ed25519 Token issued:");
  console.log("   Token length:", tokenResult.token.length);

  // 8. Production App Server middleware verifies the token
  const verifyResult = verifyToken(tokenResult.token, {
    clientIP,
    action: "login",
    minScore: 0.6,
  });

  console.log("8. Verification result:");
  console.log("   Valid:", verifyResult.valid);
  if (!verifyResult.valid) {
    throw new Error(`Token verification failed: ${verifyResult.reason}`);
  }
  console.log("   Verified claims:", verifyResult.claims);

  console.log("\n✅ ALL END-TO-END STEPS PASSED SUCCESSFULLY!");
}

run().catch((err) => {
  console.error("❌ E2E Failed:", err);
  process.exit(1);
});
