/**
 * test_e2e_crypto.js — End-to-end ECDH + AES-GCM + Attestation Integration Test
 */

"use strict";

const { generateEphemeralKeyPair, decryptTelemetry } = require("./compiler/ecdh_session");
const { computeScore } = require("./attestation/scorer");
const { issueToken } = require("./attestation/token");
const { verifyToken } = require("./attestation/verifier");
const { maskIP } = require("./attestation/ip_mask");

async function run() {
  console.log("Starting End-to-End Test...");

  // 1. Server generates ephemeral ECDH key pair
  const serverKP = generateEphemeralKeyPair();
  console.log("1. Server ECDH KeyPair generated, session ID:", serverKP.id);

  // 2. Client simulates Web Crypto ECDH + AES-GCM encryption
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
    runtime: { tampered: false, signals: {} },
    hardware: { consistent: true, cores: 8, memory: 8 },
    kinematics: { humanLike: true, entropy: 0.85, eventCount: 120 },
    pow: { valid: true, durationMs: 450, difficulty: 16 }
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
    sid: serverKP.id
  };

  console.log("2. Telemetry encrypted with AES-GCM. Ciphertext length:", wirePayload.ct.length);

  // 3. Server receives and decrypts payload using private key
  const decrypted = decryptTelemetry(wirePayload, serverKP.privateKey);
  console.log("3. Server decrypted telemetry successfully:");
  console.log("   Action:", decrypted.action);
  console.log("   Runtime tampered:", decrypted.runtime.tampered);

  if (JSON.stringify(decrypted) !== JSON.stringify(rawTelemetry)) {
    throw new Error("Decrypted telemetry does not match original!");
  }

  // 4. Server scores the decrypted payload
  const scoreResult = computeScore(decrypted);
  console.log("4. Telemetry scored:");
  console.log("   Score:", scoreResult.score);
  console.log("   Clamped:", scoreResult.clamped);

  if (scoreResult.score < 0.7) {
    throw new Error(`Score too low for clean telemetry: ${scoreResult.score}`);
  }

  // 5. Server issues Ed25519 token
  const clientIP = "203.0.113.195";
  const ipSubnet = maskIP(clientIP);
  const tokenResult = issueToken({
    score: scoreResult.score,
    action: decrypted.action,
    ipSubnet
  });
  console.log("5. Ed25519 Token issued:");
  console.log("   Token length:", tokenResult.token.length);
  console.log("   Token parts:", tokenResult.token.split(".").length);

  // 6. Production App Server middleware verifies the token
  const verifyResult = verifyToken(tokenResult.token, {
    clientIP,
    action: "login",
    minScore: 0.6
  });

  console.log("6. Verification result:");
  console.log("   Valid:", verifyResult.valid);
  if (!verifyResult.valid) {
    throw new Error(`Token verification failed: ${verifyResult.reason}`);
  }
  console.log("   Verified claims:", verifyResult.claims);

  console.log("\n✅ ALL END-TO-END STEPS PASSED SUCCESSFULLY!");
}

run().catch(err => {
  console.error("❌ E2E Failed:", err);
  process.exit(1);
});
