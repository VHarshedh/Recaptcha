# Security report remediation status

This file supersedes earlier deployment guidance where it conflicts. Client JavaScript remains untrusted. No change here establishes hardware attestation or proves a human is present.

| Finding | Change and limits |
| --- | --- |
| 01 | Collectors stay lexical; global replacement is ignored, with regression coverage. |
| 02 | Production requires an independent `authorize(req, action)` policy on `AdaptiveChallenge`, or the passkey deployment factory which denies telemetry-only issuance. Only literal `true` authorizes. VM state remains obfuscation, not hardware attestation. Built-in passkey enrollment uses trusted single-use provisioning tickets; authentication verifies real WebAuthn signatures and user verification. Never trust request JSON or a client-set header. |
| 03 | Server rasterizes glyphs into PNG; clients receive no vector coordinates. OCR remains possible. Production uses independent authorization. |
| 04 | Bounded oldest-entry eviction avoids global table lockout. Eviction can invalidate pending sessions or discard bans under sustained pressure; upstream capacity protection is still necessary. |
| 05 | HTTPS proxy scheme supported only with `TRUST_PROXY=1`; malformed/multiple schemes rejected. Restrict direct origin access and overwrite forwarded headers at the trusted proxy. |
| 06 | Redis adapters now share encrypted sessions, challenges, credentials and rate limits; `verifyTokenAsync` uses shared atomic nonce claims. `createRedisDeployment` requires shared secrets and a noeviction Redis policy. Live Redis integration remains unvalidated locally; `npm run test:redis` is provided for a dedicated test instance. Local-only production still requires explicit single-process configuration. |
| 07 | HTTP compilation uses bounded worker threads (two concurrent jobs, ten-second timeout); overload returns 503. Threads are created per job, not a warmed pool. |
| 08 | Both Python entry points implement scratchpad mixing and reject unsafe integer/timestamp inputs; cross-language parity tested. |
| 09 | Request reputation/session quotas use individual client IPs; malformed or unknown initial envelopes do not add reputation failures. Shared public NAT IPs still share quotas. |
| 10 | Action, origin, host, client IP and score policy required; unknown IP rejected; default/floor score 0.70. Policy failures no longer consume nonces. |
| 11 | Public `/verify` removed; verify inside the relying server. |
| 12 | Missing hints penalty reduced; pointer interactions counted; flicker removed. Independently authorized production sessions bypass visual/typing checks. Development CAPTCHA alone has no audio alternative. Production passkey endpoints and browser helpers provide a platform-authenticator path without transcription or cadence checks. |
| 13 | Acorn parses comments and string literals; token-aware renaming leaves regex/string contents intact; Unicode code units round-trip. Renaming remains conservative rather than a full scope optimizer. |
| 14 | Standalone/embedded worker copies use the same synchronous SHA-256 implementation. Compatibility copies retained; existing tests check embedded worker parity. |
| 15 | Host binary intrinsics supplied in VM tests; standalone compiler entry point uses the real attestation server without wildcard CORS. |

## Integration changes

`verifyToken` callers must pass `{ action, origin, host, clientIP }` and a minimum score of at least 0.70. Missing bindings on older tokens now fail. `/verify` is no longer exposed.

Production applications must provision `ATTESTATION_KEY_PATH`. Use `createRedisDeployment` for shared state and passkeys, or explicitly configure a single-process deployment with an independent authorization policy. See `readme.md` for enrollment, verification, shared-secret requirements, and validation gaps.

Validation: `npm test` and `npm run test:report`. The latter also requires Python and checks JavaScript/Python PoW hashes, unsafe numeric inputs, proxy trust, Unicode/regex preservation, and nonce handling after rejected verification.

## Additional hardening (supersedes conflicting rows above)

Independent authorization is now the default in all environments; telemetry-only demonstrations require explicit `allowInsecureDemo`. Local rate-limit and session capacity now fail closed without evicting live entries. Redis quotas enforce outstanding-session limits during atomic insertion. Strict envelope validation precedes session consumption; invalid telemetry no longer earns full hardware/runtime credit. Worker failures release capacity, and Redis initialization failures close the connection. See the README migration notes, including draining old Redis sessions before deployment.

Local hardening regressions are included in the master suite. Live Redis quota/race validation requires a dedicated instance and was not run in this workspace.
