/**
 * keys.js — Ed25519 Key-Pair Manager
 *
 * Generates a fresh Ed25519 key pair on first import.
 * Keys live only in process memory — never touch disk in production.
 *
 * Exports:
 *   privateKey  – crypto.KeyObject (Ed25519 private)
 *   publicKey   – crypto.KeyObject (Ed25519 public)
 *   publicKeyPem – PEM-encoded public key string (for distribution)
 *   publicKeyDer – raw 32-byte public key Buffer
 */

"use strict";

const crypto = require("node:crypto");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });

// Raw 32-byte public key for compact wire format.
const publicKeyDer = publicKey.export({ type: "spki", format: "der" });

module.exports = Object.freeze({
  privateKey,
  publicKey,
  publicKeyPem,
  publicKeyDer,
});
