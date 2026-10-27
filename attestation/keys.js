/**
 * keys.js — Persistent Ed25519 Key-Pair Manager
 *
 * Loads an existing Ed25519 key pair from disk on startup, or generates
 * a new one and persists it.  This ensures that the compiler middleware
 * and the attestation server share the same signing identity across
 * process restarts and separate Node processes.
 *
 * Configuration:
 *   ATTESTATION_KEY_PATH  env var — file path (default: ./attestation_ed25519.key)
 *
 * Exports:
 *   privateKey   – crypto.KeyObject (Ed25519 private)
 *   publicKey    – crypto.KeyObject (Ed25519 public)
 *   publicKeyPem – PEM-encoded public key string (for distribution)
 *   publicKeyDer – raw DER-encoded public key Buffer
 */

"use strict";

const crypto = require("node:crypto");
const fs     = require("node:fs");
const path   = require("node:path");

const KEY_PATH = process.env.ATTESTATION_KEY_PATH ||
  path.join(__dirname, "..", "attestation_ed25519.key");

let privateKey, publicKey;

try {
  if (fs.existsSync(KEY_PATH)) {
    // ── Load existing key pair from disk ─────────────────────────────
    const stored = JSON.parse(fs.readFileSync(KEY_PATH, "utf-8"));
    privateKey = crypto.createPrivateKey({
      key: Buffer.from(stored.privateKeyDer, "base64"),
      format: "der",
      type: "pkcs8",
    });
    publicKey = crypto.createPublicKey(privateKey);
    console.log(`[keys] loaded Ed25519 key pair from ${KEY_PATH}`);
  }
} catch (err) {
  console.warn(`[keys] failed to load key from ${KEY_PATH}: ${err.message}`);
  privateKey = null;
}

if (!privateKey) {
  // ── Generate new key pair and persist to disk ─────────────────────
  const pair = crypto.generateKeyPairSync("ed25519");
  privateKey = pair.privateKey;
  publicKey  = pair.publicKey;

  const keyData = {
    algorithm: "ed25519",
    privateKeyDer: privateKey
      .export({ type: "pkcs8", format: "der" })
      .toString("base64"),
    createdAt: new Date().toISOString(),
  };

  try {
    const dir = path.dirname(KEY_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(KEY_PATH, JSON.stringify(keyData, null, 2), {
      mode: 0o600,
    });
    console.log(`[keys] generated and saved new Ed25519 key pair → ${KEY_PATH}`);
  } catch (writeErr) {
    console.warn(
      `[keys] could not persist key to ${KEY_PATH}: ${writeErr.message}. ` +
      `Key exists only in memory for this process.`
    );
  }
}

const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });

// Raw DER-encoded public key for compact wire format.
const publicKeyDer = publicKey.export({ type: "spki", format: "der" });

module.exports = Object.freeze({
  privateKey,
  publicKey,
  publicKeyPem,
  publicKeyDer,
});
