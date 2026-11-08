# Bug report and resolution status

Reviewed commit: `df59688f834c959bf6ab6974fd319dfc343c0941` on `fix/recaptcha-passkey-policy-hardening`.

The findings below were reproduced on the reviewed commit. All three are now
addressed on the hardening branch:

- Finding 1: production local verification checks the signed issuer-process identity; restart invalidates outstanding local tokens. Independent issuers use retained shared replay storage.
- Finding 2: socket and trusted forwarded IP addresses are canonicalized before becoming identities.
- Finding 3: mixed-notation IPv6 is supported; invalid trusted forwarded identities fail closed instead of using the proxy address.

Regression coverage: `test_restart_binding.js` and `test_ip_identity.js`.
Deployment changes are documented in `readme.md`. The original findings and
prerequisites are retained below as historical evidence. This report does not
establish that a deployed website was exploited or that every vulnerability has
been eliminated.

## 1. Used tokens become reusable after a verifier restart

**Severity:** High when a still-valid token authorizes a sensitive operation; deployment-dependent.

**Locations:** `attestation/verifier.js:68–70,207–211`; `attestation/nonce_cache.js:30–45,63–78`.

The supported production `ATTESTATION_STATE_MODE=single-process` mode keeps consumed nonces exclusively in process memory. Restarting the verifier creates an empty cache while retaining the configured signing identity. Previously consumed tokens therefore pass signature, expiry, policy, and nonce checks again.

**Reproduction:** Generate an ephemeral Ed25519 key in a temporary external key file. Issue one token with that configured key. Start a production verifier process in single-process mode and verify the token twice. Start a fresh verifier process with the same key and verify that same token twice again, before its expiry.

**Observed:** Both processes returned `[true, false]`: accepted once in the first process and accepted again in the replacement process. Temporary key material was removed after testing.

**Prerequisites and impact:** The attacker must possess a previously accepted token that remains valid, match its action/site/IP policy, and encounter a verifier restart. No ability to force a restart was demonstrated. This can duplicate a protected action if the application relies solely on the token's one-use guarantee. Explicit single-process configuration avoids concurrent-process replay but does not provide restart durability. This finding does not apply to verification using a correctly retained shared nonce store.

## 2. Equivalent IP spellings receive separate rate-limit and session-quota identities

**Severity:** Medium; dependent on upstream address formatting.

**Locations:** `attestation/ip_mask.js:114–122`; `attestation/rate_limiter.js:47–55`; `attestation/redis_adapters.js:8–13,34–38`; `compiler/middleware.js:123–127`.

`getClientIP()` validates trusted forwarded addresses but returns their original spelling. Rate limits and session quotas use that raw string. Equivalent IPv6 addresses consequently select different buckets. Raw address equality also binds pending passkey challenges, so a formatting change between requests can reject a legitimate ceremony.

**Reproduction:** Set `TRUST_PROXY=1`. Extract the client IP from otherwise identical requests whose trusted forwarded address is respectively `2001:db8::1` and `2001:0DB8:0:0:0:0:0:1`. Use the results with a `RateLimiter({ maxRequests: 1 })`.

**Observed:** Both requests were allowed, despite representing the exact same address and a one-request limit. The extracted strings were different.

**Prerequisites and impact:** An attacker needs a deployment where equivalent spellings can reach the trusted final forwarded-address position. A proxy that always overwrites/appends a canonical actual peer address prevents attacker-selected spellings; this test does not demonstrate bypass of such a proxy. Where representation can vary, one address can split its request budget, outstanding-session quota, and reputation across multiple identities.

## 3. Valid mixed-notation IPv6 addresses fall back to the proxy's identity

**Severity:** Medium; dependent on proxy output and deployment topology.

**Locations:** `attestation/ip_mask.js:42–45,87–109,114–122`.

The parser recognizes the compressed dotted mapped form `::ffff:192.0.2.1`, but not the equally valid expanded form `0:0:0:0:0:ffff:192.0.2.1`. Its IPv6 forwarded-address branch excludes dotted components. Instead of retaining the actual client identity or rejecting an unparseable forwarded identity, `getClientIP()` falls back to the reverse proxy socket address.

**Reproduction:** With `TRUST_PROXY=1`, provide `X-Forwarded-For: 0:0:0:0:0:ffff:192.0.2.1` and socket peer `10.0.0.1`.

**Observed:** Node's `net.isIP()` identifies the forwarded value as IPv6 (`6`), but `maskIP()` returns `unknown` and `getClientIP()` returns `10.0.0.1`.

**Prerequisites and impact:** A trusted proxy must emit this valid address notation. Clients represented this way share the proxy's rate-limit identity and token subnet instead of their actual identities. This can cause collateral rate-limit denial and weaken intended IP binding. Token misuse additionally requires possession of a valid token and matching remaining verification policy; the identity collision alone does not forge tokens. No live reverse-proxy deployment was tested.
