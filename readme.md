# recaptcha-attestation

A Node.js browser-signal scoring service with encrypted telemetry, proof of work, short-lived Ed25519 tokens, and a passkey verification path.

Browser telemetry and VM obfuscation are client-controlled signals. They cannot establish human identity or an untampered browser. Passkeys verify possession of an enrolled credential and require user verification; they do not guarantee that a client is human or that a credential is hardware-bound. Synced passkeys are supported.

## Requirements

- Node.js 20 or later and npm.
- Python for the cross-language report regression tests.
- HTTPS for deployed WebAuthn; a configured relying-party hostname and exact origin.
- Redis 6.2 or later for shared state, with `maxmemory-policy noeviction`. Use a dedicated protected instance, capacity monitoring, TLS for remote connections, and persistence appropriate to your credential/replay requirements.

## Local development

```powershell
npm ci
npm test
npm run test:report
npm run test:passkeys
npm start
```

The development service listens on port 3100. Override it with `node attestation/server.js 3200`. It exposes `GET /collector.js`, `POST /attest`, `POST /attest/verify-challenge`, `GET /pubkey`, and `GET /health`. It does not serve an application page. `/verify` is intentionally absent: verify tokens inside the relying server.

Serve the collector through your application's same-origin proxy:

```html
<script src="/collector.js"></script>
<script>
  async function getAttestation() {
    return window.__attestation.execute('login');
  }
</script>
```

Development telemetry below the score threshold invokes PoW or a static PNG visual challenge. Visual typing checks have no audio alternative. Use the passkey path for an accessible production verification flow.

## Production passkeys and shared state

Provision one Ed25519 signing key file outside the repository. Its JSON schema is `{ "privateKeyDer": "<base64 PKCS8 DER>" }`. Set `ATTESTATION_KEY_PATH` to that file before loading this package, and `NODE_ENV=production`. Share the signing identity across the issuer/verifier processes. Never commit keys.

Generate two independent random 32-byte secrets, store them in your secret manager, and supply identical values to every instance as `STATE_ENCRYPTION_KEY` and `CHALLENGE_SECRET`, encoded as base64. State values are encrypted before entering Redis. Do not rotate these secrets while requests are in flight without planning for invalidation.

Create an application entry point:

```js
const { createRedisDeployment, verifyTokenAsync } = require('./index');

async function main() {
  const deployment = await createRedisDeployment({
    url: process.env.REDIS_URL,
    encryptionKey: Buffer.from(process.env.STATE_ENCRYPTION_KEY || '', 'base64'),
    challengeSecret: Buffer.from(process.env.CHALLENGE_SECRET || '', 'base64'),
    rpID: 'app.example.com',
    origin: 'https://app.example.com',
  });
  deployment.server.listen(3100);

  // Inside your trusted account-provisioning process only:
  // const ticket = await deployment.passkeys.enrollmentTicket(user.id, user.name);
  // Deliver it to that user through an authenticated channel. It expires in 5 minutes.

  // In your protected application route, using the same shared nonce store:
  // const result = await verifyTokenAsync(token, {
  //   action: 'login', origin: 'https://app.example.com',
  //   host: 'https://app.example.com', clientIP: trustedClientIP,
  //   minScore: 0.70, nonceStore: deployment.nonceStore,
  // });
  // Reject the request unless result.valid is true.
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
```

The Redis configuration check requires permission to read `CONFIG GET maxmemory-policy`. Startup fails if that policy permits eviction. Memory exhaustion and Redis outages reject operations; there is no local replay-cache fallback. Use a single Redis primary or compatible shared endpoint; Redis Cluster sharding has not been validated.

Production telemetry alone is denied by this deployment factory. Obtain tokens through the passkey flow. Each instance shares encrypted sessions, challenges, credentials, request limits, and atomic nonce claims. Authentication counter updates use atomic compare-and-set to reject conflicting updates.

The passkey endpoints are:

| POST endpoint | Request |
| --- | --- |
| `/passkeys/register/options` | `{ ticket }` |
| `/passkeys/register/verify` | `{ id, response }` |
| `/passkeys/authenticate/options` | `{ action: "login" }` |
| `/passkeys/authenticate/verify` | `{ id, response }` |

Import `enrollPasskey` and `authenticatePasskey` from `client/passkeys.mjs` in your browser application bundle. Call them from labeled buttons so users can activate their authenticator. Enrollment accepts a trusted provisioning ticket; authentication returns `{ status, score, token, claims }`. Errors should be displayed with retry controls. The browser uses the platform authenticator UI, avoiding visual transcription and typing-cadence requirements. Additional action names require configuring `Passkeys.actions`; the deployment factory currently enables `login`.

Registration tickets and challenges are single-use. Credentials currently expire after one year; account recovery, credential renewal/revocation UI, and trusted user provisioning remain application responsibilities. Never expose `enrollmentTicket()` as an unauthenticated HTTP API. Self-enrolling an arbitrary key does not establish a trusted account.

## Token policy and proxies

`verifyToken` is synchronous and uses a process-local nonce cache. In production it requires an explicit `ATTESTATION_STATE_MODE=single-process`; all token consumption must then occur in that process. For multiple instances, use `verifyTokenAsync` with shared `nonceStore`, or pass `nonceStore` to `attestationMiddleware`.

Middleware requires explicit canonical `origin` and `host` configuration, for example `attestationMiddleware({ action: "login", origin: "https://example.com", host: "https://example.com" })`. These must come from trusted application configuration, never request headers. Local replay storage rejects new claims at 100,000 live entries without evicting used nonces. Tokens larger than 8 KiB are rejected before parsing. Run `node test_boundary_security.js` for these regression checks.

Every verification requires the expected `action`, `origin`, `host`, and a valid `clientIP`. `host` is the full issuer request origin, including scheme, not a bare hostname. Minimum score defaults to 0.70 and cannot be lower. A token is single-use and lasts 45 seconds by default. Failed policy checks do not consume its nonce.

Set `TRUST_PROXY=1` only behind a trusted proxy that overwrites forwarded headers and prevents direct access to the origin. HTTPS termination uses `X-Forwarded-Proto`; malformed or multiple scheme values are rejected. Set `ALLOWED_ORIGINS` to a comma-separated allowlist for telemetry CORS if needed. Passkey routes require the configured exact same origin.

## Security changes and validation

See [SECURITY_REMEDIATION.md](SECURITY_REMEDIATION.md) for all 15 report findings and [security_report.md](security_report.md) for the original audit.

Validated locally: eight existing suites, report regressions including Python/JavaScript PoW parity, and real WebAuthn registration/signature/replay tests using a software authenticator fixture. The Redis adapters have not yet been exercised against a live Redis instance in this workspace. Run `npm run test:redis` with `TEST_REDIS_URL` pointing to a dedicated Redis instance to exercise cross-client atomic consumption, replay races, TTL and concurrent counter updates. Real browser/platform-authenticator accessibility testing and multi-instance Redis integration testing are required before production rollout. Passing these tests does not certify resistance to all bots or autonomous agents.

Compilation runs in at most two worker threads per process with a ten-second timeout; excess jobs receive 503. Storage and request limits reduce resource abuse, but an upstream proxy/CDN still needs capacity controls. Session eviction can invalidate in-flight development requests. Individual public IP limits can still affect users sharing a NAT.

WebAuthn implementation follows the [SimpleWebAuthn server API](https://simplewebauthn.dev/docs/packages/server); browser helpers use its matching browser package.

## Security migration: explicit demo mode

Adaptive issuance now requires an independent `authorize(req, action)` callback in every environment. For local demonstrations only, pass `{ allowInsecureDemo: true }` to `AdaptiveChallenge` or `createServer`. Production still requires independent authorization; do not expose demo mode publicly. The standalone server intentionally fails without an authorization configuration.

Local rate limits and session stores reject new identities/sessions when full instead of evicting live protection. Size capacity for expected traffic and monitor 429 responses. Redis session quotas now count outstanding sessions and enforce insertion atomically. Deploy this change with pending sessions drained (up to five minutes); old Redis session records lack quota metadata. Redis Cluster is not supported by these multi-key transactions.

Encrypted submissions require canonical base64, P-256 keys and 12-byte IVs. Missing hardware evidence earns no hardware credit, malformed telemetry fails scoring, and client timing earns no PoW bonus. Passkey-issued CAPTCHA tokens establish a verification event, not the application account identity or permission to access it.

Validation: `npm test`, `npm run test:passkeys`, and `npm run test:report`. Run `npm run test:redis` with `TEST_REDIS_URL` pointing to a dedicated instance before deploying Redis changes.

## Redis state security migration

Encrypted Redis records are now authenticated against their full storage key
(including namespace). Copying ciphertext between keys or namespaces is rejected.
This closes a record-substitution weakness for an attacker with Redis write
access; it does not protect against deletion, rollback at the same key, or a
compromised Redis server. Keep Redis isolated and access-controlled.

Credential counter updates now preserve the original expiration instead of
renewing enrollment for another year on every authentication. Explicit TTLs
passed to `RedisState.update` still replace the expiration.

Existing encrypted records are incompatible with this change. Do not mix old
and new instances against the same state. Before deployment, stop issuers and
verifiers and drain outstanding tokens and challenges. Plan an offline migration
of trusted credentials to the new authenticated format while preserving their
remaining TTL, or require trusted re-enrollment. Never add a fallback that accepts
unbound ciphertext. Keep replay state until all previously issued tokens expire;
do not flush a live Redis database. Back up state before migration.

Run `TEST_REDIS_URL=<dedicated-test-instance> npm run test:redis` to exercise
cross-client atomic operations, record substitution rejection, and expiration
preservation against a real Redis server.

## Passkey relying-party isolation migration

Passkey tickets, challenges and credentials now use a `passkeys:v2:` namespace
scoped to both the configured relying-party ID and exact origin. Replicas with
identical configuration share state; different origins (including ports) do not.
Previously, a software authenticator enrolled on one site could authenticate on
another site sharing the same store, and enrollment tickets could cross sites.
The server now enforces isolation independently of browser/authenticator behavior.

Existing passkey records are not automatically adopted. Before deploying, stop
old issuers, drain pending challenges and tokens, and either require trusted
re-enrollment or migrate records offline using independently verified ownership
of each credential. Legacy records do not contain sufficient relying-party
metadata to infer ownership safely. Do not copy every credential into every new
namespace or fall back to the old global keys. Coordinate this with the encrypted
Redis state migration above and preserve remaining credential TTLs.

`npm run test:passkeys` checks a real signed cross-relying-party authentication
attempt, enrollment-ticket isolation, exact-origin separation, and same-site
replica interoperability, in addition to the normal WebAuthn flow.
