/** Ed25519 signing identity. ATTESTATION_KEY_PATH must point to an externally
 * provisioned JSON key file in production. Invalid configured keys fail closed.
 * Development without configuration uses an ephemeral process-local identity.
 */

"use strict";

const crypto = require("node:crypto");
const fs     = require("node:fs");

// Deployment keys must be injected explicitly, outside source/build artifacts.
// Development defaults are ephemeral and never write a private key into the repo.
const KEY_PATH = process.env.ATTESTATION_KEY_PATH;
let privateKey, publicKey;
if (KEY_PATH) {
  const stored = JSON.parse(fs.readFileSync(KEY_PATH, "utf-8"));
  privateKey = crypto.createPrivateKey({
    key: Buffer.from(stored.privateKeyDer, "base64"), format: "der", type: "pkcs8",
  });
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Ed25519 key required");
  // Reject the disclosed key by public fingerprint, without embedding its secret.
  const fingerprint = crypto.createHash("sha256")
    .update(crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" })).digest("hex");
  if (["3aac5fa35b993f6b6cf028f051d83d52f4f6c287780eebdf55373f14184ce820"].includes(fingerprint)) throw new Error("Disclosed signing key revoked; provision a new key");
  publicKey = crypto.createPublicKey(privateKey);
} else {
  if (process.env.NODE_ENV === "production") throw new Error("ATTESTATION_KEY_PATH is required in production");
  ({ privateKey, publicKey } = crypto.generateKeyPairSync("ed25519"));
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
