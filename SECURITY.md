# Attestation security and deployment

This system scores consistency signals. It does not authenticate a human or
prove execution in an untampered browser. Public keys, challenges, state-machine
constants, event counts, and engine error strings are available to or supplied
by the client. A sufficiently capable client can reproduce them.

Each build advances a random signed 32-bit state through six collector
dispatch stages, mixing collector type, Navigator tag, native-function source,
and deterministic Canvas/Math/ArrayBuffer execution invariants with rotations,
integer multiplication and XORs. Its AES-256-GCM key is SHA-256(ECDH shared secret || state),
where state is four big-endian bytes. The server stores the expected state in
the single-use session. Legacy raw-ECDH ciphertext and wrong-state ciphertext
fail authentication. This defeats the former simple extractor's encryption
recipe, but provides obfuscation rather than remote browser attestation.

Collector and attestation requests are compared for User-Agent, Accept-Language,
client hints, and client IP. HTTP UA is also compared with the reported JS UA.
Known engine contradictions reduce the score. Under the strict adaptive policy,
Chrome without client hints or the expected receiver error triggers step-up, as
does Firefox with Chromium hints or V8 receiver errors. This can challenge real
users whose policies or intermediaries suppress headers. Fetch Metadata absence
is weaker evidence. Script GET and fetch POST metadata can legitimately differ and are
not required to be identical. No TE header requirement is imposed.

Fewer than five reported trusted mouse, touch, or keyboard events caps scores at 0.30.
These counts remain client claims. Passive page views and users who have not
interacted will therefore require step-up before obtaining a token.

## Adaptive flow

The initial collector still performs baseline difficulty-16 work. POST /attest
then returns `passed` and a token at scores >= 0.70. Lower scores receive no
token until the server verifies a single-use, HMAC-signed step-up:

| Passive score | Step-up |
| --- | --- |
| 0.55–<0.70 | PoW difficulty 18 |
| 0.45–<0.55 | PoW difficulty 20 |
| 0.35–<0.45 | PoW difficulty 22 |
| <0.35 | PoW difficulty 21 AND six-character visual answer |

POST /attest/verify-challenge accepts an ECDH-encrypted envelope using the same
client key and execution state. It binds the original action, request profile,
session and challenge IDs, enforces a 60-second expiry, and consumes the challenge
before checking the attempt. Client-supplied difficulty/score values are ignored.
Successful step-up issues a score-0.70 token as an explicit policy override;
`passiveScore` remains available in the response. Solving work does not establish
human identity. Low-interaction submissions now require a visual answer.
Visual submissions also require modal telemetry: zero untrusted events, six
trusted character keydowns and completed dwell samples, first keystroke at least
250ms after opening, at least 300ms typing, and positive dwell variance. These
encrypted measurements are still client claims, not authenticated biometrics.

Visual instructions are AES-GCM encrypted with the session key. Only distorted
closed cubic blobs and a noise descriptor are sent, with no
answer or character labels. The answer HMAC is held server-side. Encryption and
animation do not stop a controlled client from capturing the decrypted paths,
averaging frames, or using OCR/vision models. No OCR-resistance claim is measured.

The compiled `await window.__attestation.execute(action)` now resolves to a token
string, not a Fetch Response. It automatically handles work and opens a shadow-DOM
canvas modal for visual checks. Cancellation, expiry and failures reject the
Promise. Load a fresh collector for another attempt; sessions are single-use.
The worker uses local SHA-256 to avoid a Web Crypto round trip per candidate.
All paths share `{d,color,layer}` and `M C C Z` structure. Glyph shards and clutter
alternate over three layers at a target 60fps, with spatial jitter and noise.
Rendering timers may be throttled; each layer recurs at 20Hz. This requires
real-browser readability and flicker testing. Freezing the animation for reduced
motion would leave an incomplete glyph, so this policy currently requires animation.
Keyboard navigation
and labels are provided, but there is no nonvisual equivalent for blind users.
Host pages must permit blob workers via CSP and inline shadow-DOM styles.

PoW now hashes the challenge, decimal nonce, and a versioned scratchpad-mixing
suffix. A challenge-derived 64 KiB pad supplies 64 dependent reads per candidate.
The server precomputes pads at issuance in a bounded 128-entry cache; cache misses
reconstruct the pad. Verification cost is independent of difficulty. Deploy
workers and verifier together: legacy SHA-only nonces are incompatible. This is
a cache-cost heuristic, not a demonstrated memory-hard construction or a guarantee
against GPU/ASIC acceleration. It needs hardware benchmarking at production load.

The server shares a sliding 30-requests/minute budget across `/collector.js`,
`/attest`, and `/attest/verify-challenge` per IPv4 /24 or IPv6 /48. Three consecutive
failures subtract 0.50 and cap the score at 0.30, requiring visual plus difficulty-22
work. Eight failures in five minutes start a 60-second cooldown, doubling on repeat
failure up to 15 minutes. Successful attestations reset consecutive failures, not
the five-minute failure history. `createServer({rateLimit: {...}})` configures limits.
Storage defaults to 10,000 subnets and fails closed at capacity; idle entries expire.
State is process-local and resets on restart; multiple processes need coordinated
routing or a shared enforcement layer. Shared subnets may challenge legitimate users.

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
`node test_pow_verifier.js`, `node test_e2e_crypto.js`, `node test_pow_inline.js`,
`node test_adaptive_e2e.js`, and `node test_security.js`. Security regressions execute randomized compiled
collectors with Node Web Crypto, check canary preservation and telemetry schemas,
reject wrong-state ciphertext and session reuse, and cover header and IP spoofing.
Adaptive tests exercise the actual HTTP server and real scratchpad work at an
injected low difficulty (asserting the production difficulty selection separately),
encrypted render streams, valid tokens, wrong answers, replay, expiry, signature
tampering, and compiled client orchestration. Worker tests check SHA-256 vectors
and cancellation/cleanup. DOM simulation checks drawing and modal cleanup.
No browser was available for visual inspection; the simulated host does not
validate real-browser compatibility, readability, or detection rates.
