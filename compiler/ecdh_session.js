/**
 * ecdh_session.js — Ephemeral ECDH Key Exchange & AES-GCM Telemetry Encryption
 *
 * Server side:  generate per-request P-256 key pairs, decrypt client payloads.
 * Client side:  generate JS code that performs ECDH + AES-GCM in-browser via
 *               Web Crypto API, making telemetry opaque to DevTools / proxies.
 */

"use strict";

const crypto = require("node:crypto");

/* ------------------------------------------------------------------ */
/*  Server-side key management                                         */
/* ------------------------------------------------------------------ */

/**
 * Generate an ephemeral ECDH P-256 key pair.
 *
 * @returns {{
 *   publicKey:  crypto.KeyObject,
 *   privateKey: crypto.KeyObject,
 *   publicKeyBase64: string,    — SPKI DER, base64-encoded (for embedding in JS)
 *   id: string                  — 8-byte hex session identifier
 * }}
 */
function generateEphemeralKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  return {
    publicKey,
    privateKey,
    publicKeyBase64: spkiDer.toString("base64"),
    id: crypto.randomBytes(8).toString("hex"),
  };
}

/* ------------------------------------------------------------------ */
/*  Client-side code generation                                        */
/* ------------------------------------------------------------------ */

/**
 * Generate the client-side JS code for ECDH key exchange + AES-GCM
 * encrypted telemetry submission.
 *
 * The generated function signature:
 *   async function <fnName>(payload, endpoint)
 *
 * It performs:
 *   1. Import server's SPKI public key
 *   2. Generate ephemeral client EC key pair
 *   3. ECDH → 256-bit shared secret
 *   4. Derive AES-GCM key from shared bits
 *   5. Encrypt JSON payload with AES-GCM (random 96-bit IV)
 *   6. POST { cpk, iv, ct, sid } to endpoint
 *
 * All property accesses use bracket notation for string encryption.
 *
 * @param {string} serverPubKeyBase64 — server's SPKI public key (base64)
 * @param {string} sessionId          — session identifier
 * @param {string} fnName             — function name (randomized by caller)
 * @returns {string}                  — JS source code
 */
function generateClientECDHCode(serverPubKeyBase64, sessionId, fnName) {
  const name = fnName || "encryptAndSend";

  // The generated code is deliberately verbose with bracket notation so
  // the string encryption pass can encrypt every identifiable string.
  return `
async function ${name}(payloadObj, endpointUrl) {
  var spkiB64 = "${serverPubKeyBase64}";
  var sessionId = "${sessionId}";

  var spkiRaw = atob(spkiB64);
  var spkiBytes = new Uint8Array(spkiRaw["length"]);
  for (var si = 0; si < spkiRaw["length"]; si++) {
    spkiBytes[si] = spkiRaw["charCodeAt"](si);
  }

  var serverPub = await crypto["subtle"]["importKey"](
    "spki",
    spkiBytes["buffer"],
    { "name": "ECDH", "namedCurve": "P-256" },
    false,
    []
  );

  var clientKP = await crypto["subtle"]["generateKey"](
    { "name": "ECDH", "namedCurve": "P-256" },
    true,
    ["deriveBits"]
  );

  var sharedBits = await crypto["subtle"]["deriveBits"](
    { "name": "ECDH", "public": serverPub },
    clientKP["privateKey"],
    256
  );

  var aesKey = await crypto["subtle"]["importKey"](
    "raw",
    sharedBits,
    { "name": "AES-GCM" },
    false,
    ["encrypt"]
  );

  var ivBytes = crypto["getRandomValues"](new Uint8Array(12));
  var plainBytes = new TextEncoder()["encode"](JSON["stringify"](payloadObj));

  var cipherBuf = await crypto["subtle"]["encrypt"](
    { "name": "AES-GCM", "iv": ivBytes },
    aesKey,
    plainBytes
  );

  var clientPubSpki = await crypto["subtle"]["exportKey"]("spki", clientKP["publicKey"]);

  function toB64(arrBuf) {
    var bytes = new Uint8Array(arrBuf);
    var binStr = "";
    for (var bi = 0; bi < bytes["length"]; bi++) {
      binStr += String["fromCharCode"](bytes[bi]);
    }
    return btoa(binStr);
  }

  var wireMsg = {};
  wireMsg["cpk"] = toB64(clientPubSpki);
  wireMsg["iv"]  = toB64(ivBytes["buffer"]);
  wireMsg["ct"]  = toB64(cipherBuf);
  wireMsg["sid"] = sessionId;

  return fetch(endpointUrl, {
    "method": "POST",
    "headers": { "Content-Type": "application/json" },
    "body": JSON["stringify"](wireMsg)
  });
}
`;
}

/* ------------------------------------------------------------------ */
/*  Server-side decryption                                             */
/* ------------------------------------------------------------------ */

/**
 * Decrypt an encrypted telemetry payload from the client.
 *
 * Wire format (all base64):
 *   { cpk: clientPublicKey(SPKI), iv: 12-byte IV, ct: AES-GCM ciphertext, sid: sessionId }
 *
 * AES-GCM ciphertext from Web Crypto includes the 16-byte auth tag
 * appended to the ciphertext.
 *
 * @param {{ cpk: string, iv: string, ct: string }} encrypted
 * @param {crypto.KeyObject} serverPrivateKey
 * @returns {Object} — the decrypted JSON payload
 */
function decryptTelemetry(encrypted, serverPrivateKey) {
  // Decode base64 fields.
  const clientPubDer = Buffer.from(encrypted.cpk, "base64");
  const iv           = Buffer.from(encrypted.iv, "base64");
  const ciphertext   = Buffer.from(encrypted.ct, "base64");

  // Import client's ephemeral public key.
  const clientPubKey = crypto.createPublicKey({
    key: clientPubDer,
    format: "der",
    type: "spki",
  });

  // ECDH shared secret.
  const sharedSecret = crypto.diffieHellman({
    privateKey: serverPrivateKey,
    publicKey: clientPubKey,
  });

  // Web Crypto deriveBits for P-256 returns the raw 32-byte X coordinate.
  const aesKey = sharedSecret.subarray(0, 32);

  // AES-GCM: Web Crypto appends the 16-byte auth tag to the ciphertext.
  if (ciphertext.length < 16) {
    throw new Error("ciphertext too short for AES-GCM auth tag");
  }
  const authTag    = ciphertext.subarray(ciphertext.length - 16);
  const encPayload = ciphertext.subarray(0, ciphertext.length - 16);

  const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encPayload),
    decipher.final(),
  ]);

  return JSON.parse(decrypted.toString("utf-8"));
}

/* ------------------------------------------------------------------ */

module.exports = {
  generateEphemeralKeyPair,
  generateClientECDHCode,
  decryptTelemetry,
};
