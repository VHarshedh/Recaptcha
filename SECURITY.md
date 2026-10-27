# Attestation security and deployment

This system scores consistency signals. It does not authenticate a human or
prove execution in an untampered browser. Public keys, challenges, state-machine
constants, event counts, and engine error strings are available to or supplied
by the client. A sufficiently capable client can reproduce them.

Each build now advances a random signed 32-bit state through six collector
dispatch stages. Its AES-256-GCM key is SHA-256(ECDH shared secret || state),
where state is four big-endian bytes. The server stores the expected state in
the single-use session. Legacy raw-ECDH ciphertext and wrong-state ciphertext
fail authentication. This defeats the former simple extractor's encryption
recipe, but provides obfuscation rather than remote browser attestation.

Collector and attestation requests are compared for User-Agent, Accept-Language,
client hints, and client IP. HTTP UA is also compared with the reported JS UA.
Known engine contradictions reduce the score. Missing hints/Fetch Metadata are
weak evidence because browser policies, request contexts, and intermediaries can
omit them. Script GET and fetch POST metadata can legitimately differ and are
not required to be identical. No TE header requirement is imposed.

Zero reported trusted mouse, touch, or keyboard events caps scores at 0.45.
These counts remain client claims. Passive page views and users who have not
interacted will therefore not pass a threshold above 0.45.

## Signing keys

The previous workspace signing key has been removed and its public fingerprint
revoked by the key loader. Development starts with an ephemeral process-local
key. In production, set NODE_ENV=production and ATTESTATION_KEY_PATH to a
protected externally provisioned JSON file with algorithm `ed25519` and
`privateKeyDer` containing a base64 PKCS#8 DER key. Invalid or missing production
configuration fails startup. Do not reuse the disclosed key.

Generate a fresh Ed25519 key in your secret-management environment, restrict
file access to the service identity, and mount it at runtime. Never put it in
source, archives, or images. Git archive and Docker exclusions are included;
arbitrary ZIP tools do not honor them automatically.

Update every verifier's trusted public key and purge old public-key caches when
rotating. Existing archives, deployed instances, and external verifier trust
stores cannot be revoked by editing this workspace. Previously issued tokens
remain acceptable wherever the old public key is still trusted.

## Reverse proxies

By default only the socket peer address is used. TRUST_PROXY=1 selects the
rightmost valid X-Forwarded-For entry consistently for collection, issuance,
and verification. Enable it only when the origin is reachable exclusively
through a trusted proxy that appends the actual peer address. A public origin
with TRUST_PROXY=1 would still trust attacker-supplied forwarding headers.

## Checks

Run `node compiler/test_compiler.js`, `node attestation/test_attestation.js`,
`node test_pow_verifier.js`, `node test_e2e_crypto.js`, and
`node test_security.js`. Security regressions execute randomized compiled
collectors with Node Web Crypto, check canary preservation and telemetry schemas,
reject wrong-state ciphertext and session reuse, and cover header and IP spoofing.
The simulated host does not validate real-browser compatibility or detection rates.
