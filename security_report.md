# Enterprise Security Audit Report: `recaptcha-attestation` v1.0.0

## Executive Verdict: Not Safe for Standalone Enterprise Deployment

**No — this codebase is not safe to deploy as a primary enterprise safeguard against malicious career hackers or autonomous AI agents.**

While the system implements thoughtful defense-in-depth engineering—including ephemeral P-256 ECDH payload encryption, Ed25519 JWS token signing, per-request polymorphic string/identifier obfuscation, a 64 KiB scratchpad Proof-of-Work (PoW) construction, and an adaptive step-up flow—it suffers from **fundamental architectural limitations inherent to client-side JavaScript attestation**, compounded by **15 concrete vulnerabilities and operational defects** (3 Critical, 5 High, 5 Medium, 2 Low).

As acknowledged in the repository's own `SECURITY.md` and demonstrated by the bundled `audit_bypass.cjs` exploit reproducer:

1. **Career Hackers** can bypass telemetry collection, VM state-machine derivation, and modal biometric checks in under 50 lines of Node.js or Python without launching a real browser, or trigger a **100% global Denial of Service (DoS)** locking out all legitimate website visitors for 5 minutes using fewer than 10,000 requests.

2. **Autonomous AI Agents** (either operating real browsers via stealth CDP/OS-level input injection or executing headless HTTP/VM harnesses) can trivially overwrite the globally exposed collector objects (`window.RuntimeIntegrity`, `window.HardwareConsistency`, `window.Kinematics`) or reconstruct the 6-character visual CAPTCHA directly from the decrypted vector path coordinates (`Path2D` cubic curves) without even needing OCR.

3. **Enterprise Production Environments** behind TLS-terminating reverse proxies, multi-instance load balancers, or corporate NAT gateways will experience immediate availability failures (`403 Session origin mismatch`, cross-node session misses, and `/24` subnet-wide lockouts).

## Summary of Findings

| ID | Severity | Vulnerability / Defect Title | Affected Component(s) | Impact Category | 
| ----- | ----- | ----- | ----- | ----- | 
| **VULN-01** | **Critical** | Global Exposure & Late Binding of Collector Modules Enables Trivial Telemetry Forgery | `compiler/pipeline.js`, `audit_bypass.cjs` | Complete Attestation Bypass | 
| **VULN-02** | **Critical** | Deterministic Client-Controlled VM State KDF (`expectedVmState`) Lacks Hardware Attestation | `compiler/pipeline.js`, `compiler/runtime_state.js`, `compiler/ecdh_session.js` | Cryptographic Key Derivation Emulation | 
| **VULN-03** | **Critical** | Visual Step-Up CAPTCHA Ships Raw Vector Coordinates &Deterministic Layout to Client | `attestation/visual_captcha.js`, `compiler/ecdh_session.js`, `compiler/step_up.js` | Automated Agent / Solver Bypass | 
| **VULN-04** | **High** | Global `SessionStore` & `RateLimiter` Table Exhaustion Triggers Site-Wide Fail-Closed DoS | `attestation/rate_limiter.js`, `compiler/middleware.js` | Global Denial of Service | 
| **VULN-05** | **High** | TLS Reverse-Proxy Scheme Mismatch Causes 100% Same-Origin Session Failure (`http` vs `https`) | `attestation/origin.js`, `attestation/server.js`, `compiler/middleware.js` | Production Availability Failure | 
| **VULN-06** | **High** | Process-Local State & Ephemeral Secrets Break Multi-Node Scaling and Enable `N×` Token Replay | `attestation/verifier.js`, `attestation/adaptive_challenge.js`, `compiler/middleware.js` | Token Replay & Horizontal Scaling Failure | 
| **VULN-07** | **High** | Synchronous Per-Request Bundle Compilation, Keygen, and Scratchpad Allocation Exhaust Event Loop | `compiler/pipeline.js`, `compiler/middleware.js`, `pow_verifier.js` | CPU Exhaustion / Event-Loop DoS | 
| **VULN-08** | **High** | Python PoW Verifier (`pow_verifier.py`) Omits Scratchpad Mixing & Fails on Arbitrary-Precision Ints | `pow_verifier.py`, `pow/verifier.py` | Protocol Desync, PoW Downgrade & DoS | 
| **VULN-09** | **Medium** | IPv4 `/24` & IPv6 `/48` Subnet Grouping Enables Reputation Poisoning Against Enterprise NATs | `attestation/ip_mask.js`, `attestation/rate_limiter.js`, `attestation/server.js` | Targeted Subnet Lockout / Collateral DoS | 
| **VULN-10** | **Medium** | `verifyToken()` Fails Open on `"unknown"` IP Subnets and Optional `action` / `origin` / `minScore` | `attestation/verifier.js`, `attestation/token.js` | Cross-Action Replay & Policy Bypass | 
| **VULN-11** | **Medium** | Unauthenticated, Unthrottled `POST /verify` Endpoint Allows Pre-Emptive Token Nonce Burning | `attestation/server.js` | Token Invalidation / Probing | 
| **VULN-12** | **Medium** | Strict Client-Hint & Engine Error Rules Penalize Legitimate Browsers (iOS, Brave, Enterprise Proxies) | `attestation/header_check.js`, `attestation/scorer.js`, `client/runtime_integrity.js` | High False-Positive Rate & Accessibility Block | 
| **VULN-13** | **Medium** | Regex-Based Obfuscator Risks Syntax Corruption and Crashes on Non-ASCII Strings | `compiler/string_table.js`, `compiler/identifiers.js`, `compiler/pipeline.js` | Client Bundle Corruption / Runtime Error | 
| **VULN-14** | **Low** | Static Worker (`pow_client.js` / `pow_worker.js`) Uses Per-Hash Async `SubtleCrypto` IPC | `pow_client.js`, `pow_worker.js`, `client/pow_client.js`, `pow/client.js` | Browser Tab Freeze / PoW Timeout | 
| **VULN-15** | **Low** | Cross-Realm `ArrayBuffer` Bug in `ecdh_session.js` Breaks Node.js `vm` Test Suites & Standalone CORS `*` | `compiler/ecdh_session.js`, `compiler/middleware.js`, `test_security.js` | Broken CI Regression Tests & Misconfiguration | 

## Detailed Vulnerability Analysis & Remediations

### VULN-01 (Critical): Global Exposure & Late Binding of Collector Modules Enables Trivial Telemetry Forgery

* **Affected Files**: `compiler/pipeline.js` (lines 46–55, 105–155), demonstrated by `audit_bypass.cjs` (lines 48–56).

* **Root Cause**:

  1. In `compiler/pipeline.js`, `preprocess()` rewrites the UMD wrapper of each collector module (`RuntimeIntegrity`, `HardwareConsistency`, `Kinematics`) so that it explicitly attaches itself to `globalThis`:

     ```
     out = `var ${modName} = (function (root) {${body}})(typeof globalThis === 'object' ? globalThis : this);\n` +
           `(typeof globalThis === 'object' ? globalThis : this)["${modName}"] = ${modName};\n`;
     
     ```

  2. In `generateFlattenedMain()`, when `window.__attestation.execute(action)` is called, the state machine dynamically resolves `globalThis["RuntimeIntegrity"]`, `globalThis["HardwareConsistency"]`, and `globalThis["Kinematics"]` from the global object rather than invoking private, lexically scoped functions inside the IIFE:

     ```
     var ${names.rtRef} = (typeof globalThis !== "undefined" && globalThis["RuntimeIntegrity"]) || ...;
     ${names.collector}["runtime"] = (${names.rtRef} && typeof ${names.rtRef}["collect"] === "function") ? ${names.rtRef}["collect"]() : {};
     
     ```

  3. Furthermore, `compiler/identifiers.js` (lines 108–115) intentionally excludes any identifier used after a dot or as a property name from identifier randomization, leaving `"RuntimeIntegrity"`, `"HardwareConsistency"`, `"Kinematics"`, `"collect"`, and `"getBiometricVector"` intact as predictable global hooks.

  4. The runtime state checks (`invariantHash` and `telemetryShape` in `compiler/runtime_state.js`) only verify that `typeof globalThis.RuntimeIntegrity.collect === "function"` and that the returned object contains numeric `runtime.confidence_penalty`, object `hardware.profile`, and object `kinematics.eventCounts` (yielding a static bitmask of `7`).

* **Exploitability**:
  As proven by `audit_bypass.cjs`, an attacker or headless agent can load `/collector.js` in a minimal JavaScript context (or overwrite the globals in-page via console/userscript/CDP before calling `__attestation.execute()`) with 6 lines of code:

  ```
  window.RuntimeIntegrity = { collect: () => ({ confidence_penalty: 0, anomalies: [], receiverErrorText: "TypeError: Illegal invocation" }) };
  window.HardwareConsistency = { collect: async () => ({ profile: { userAgent: navigator.userAgent, hardwareConcurrency: 8 } }) };
  window.Kinematics = { getBiometricVector: () => ({ eventCounts: { mousemove: 80 }, mouse: { pointCount: 45, entropyRatio: 0.92 } }) };
  const token = await window.__attestation.execute("login");
  
  ```

  This computes the exact `expectedVmState`, encrypts the forged telemetry, passes all server checks, and mints a high-score (`>= 0.85`) Ed25519 token with zero browser interaction.

* **Suggested Fix**:
  Remove global attachment from `preprocess()` so collector modules remain strictly private `var` bindings inside the compiled IIFE, and invoke their randomized lexical identifiers directly inside `generateFlattenedMain()`:

  ```
  // In compiler/pipeline.js — preprocess(src):
  const match = out.match(umdRegex);
  if (match) {
    const modName = match[1];
    const body = match[2];
    // Keep collector strictly lexical inside the bundle IIFE; NEVER attach to globalThis/window
    out = `var ${modName} = (function (root) {${body}})(typeof globalThis === 'object' ? globalThis : this);\n`;
  }
  
  ```

  In `generateFlattenedMain()`, reference the lexical identifiers directly and allow `identifiers.js` to rename `RuntimeIntegrity`, `HardwareConsistency`, and `Kinematics` per build:

  ```
  // Inside generateFlattenedMain():
  case ${cv[0]}:
    ${names.vmState} = mixRuntimeState(${names.vmState}, stateSlots[1](),
      (invariantHash(typeof RuntimeIntegrity["collect"]) ^ invariantHash(Object["prototype"]["toString"]["call"](window["navigator"]))) ^ executeProgram(challengeProgram, 0));
    ${names.collector}["runtime"] = RuntimeIntegrity["collect"]();
    ${names.state} = ${cv[1]};
    break;
  
  ```

### VULN-02 (Critical): Deterministic Client-Controlled VM State KDF (`expectedVmState`) Lacks Hardware Attestation

* **Affected Files**: `compiler/pipeline.js` (lines 89–162, 232–243), `compiler/runtime_state.js` (lines 16–39), `compiler/ecdh_session.js` (lines 100–115, 211–218).

* **Root Cause**:
  The session AES-256-GCM key is derived as `SHA-256(ECDH_shared_secret || expectedVmState)`. However, every input to `expectedVmState` is statically embedded in `/collector.js` and deterministic:

  * `stateSlots[0..6]` are split arithmetic closures `(Math.imul(a, b) ^ c)` whose constants `a`, `b`, and `c` are in the script.

  * `challengeProgram` is a literal JSON array embedded in the script.

  * `canvasInvariant()` (`compiler/pipeline.js`, lines 98–106) creates a canvas, calls `fillRect(0, 0, 1, 1)`, never inspects pixel data, and returns `Math.imul(probe.width, probe.height) ^ challengeProgram[5][0]`—which is a pure arithmetic function of `challengeProgram[1][0]`, `challengeProgram[2][0]`, and `challengeProgram[5][0]`.

  * The 6 stage invariants are static constants (`invariantHash("function") ^ invariantHash("[object Navigator]")`, `1`, `executionCanary() ^ canvasWord`, and `invariantHash("7")` three times).

* **Exploitability**:
  A career hacker does not need to execute the collector or use a browser at all. A lightweight Python or Node.js parser can regex-extract `stateSlots`, `challengeProgram`, `spkiB64`, `sessionId`, and `powChallenge` from the `/collector.js` response (after running the embedded 10-line XOR string decoder), compute `expectedVmState` in <1 ms, solve the 16-bit PoW (\~65,536 hashes, taking \~15 ms in native code), encrypt a synthetic JSON payload, and harvest valid attestation tokens at scale.

* **Suggested Fix**:

  1. Mix intermediate values derived from actual runtime probes and unpredictable environment properties into the telemetry payload and cross-check them server-side.

  2. Because pure JavaScript obfuscation can always be emulated by a sufficiently capable attacker, enterprise deployments protecting high-value endpoints (`login`, `checkout`, `password_reset`, `api`) must layer **hardware/OS-backed attestation** (such as WebAuthn / Passkeys, Apple/Cloudflare Private Access Tokens, or Chrome Private State Tokens) alongside server-side behavioral anomaly detection (TLS JA3/JA4 + HTTP/2 fingerprint correlation, account velocity, and device-graph scoring).

### VULN-03 (Critical): Visual Step-Up CAPTCHA Ships Raw Vector Coordinates & Deterministic Layout to Client

* **Affected Files**: `attestation/visual_captcha.js` (lines 5–75), `compiler/ecdh_session.js` (lines 146–155), `compiler/step_up.js` (lines 1–138), `attestation/adaptive_challenge.js` (lines 72–85).

* **Root Cause**:
  When a client scores `< 0.35`, the server issues a `step_up_visual` challenge containing AES-GCM encrypted vector instructions (`rendering`).

  1. **Client-Side Decryption of Vector Primitives**: `generateClientECDHCode()` (`compiler/ecdh_session.js`, lines 146–155) automatically decrypts `responseData.rendering` into a plain JavaScript object containing `paths: [{ d, color, layer }]` and `noise: { layerOffsets, fps, particles, seed, opacity }` before passing it to `openVisualChallenge()`.

  2. **Deterministic Spatial Separation of Real Glyphs vs. Decoys**: In `attestation/visual_captcha.js` (lines 48–62), the 6 answer characters are rendered from a fixed 5×7 pixel bitmap `FONT` at horizontal centers `cx = 35 + i * 45` (`i = 0..5`) and vertical centers `cy = 58 + 8 * Math.sin(i + phase)` (always within `Y ∈ [50, 66]`). Conversely, all 8 decoy pseudo-glyph clusters are placed strictly at `cy = 85` or `cy = 30` (`i % 2 ? 85 : 30`):

     ```
     // Real answer characters: Y is always in [50, 66]
     for (let i = 0; i < answer.length; i++) {
       ...
       cluster(cells, 35+i*45, 58+8*Math.sin(i+phase));
     }
     // Decoy clusters: Y is hardcoded to 85 or 30!
     for (let i = 0; i < 8; i++) {
       ...
       cluster([...cells.values()], 18+(i%7)*43, i%2 ? 85 : 30);
     }
     
     ```

  3. **Trivial Layer Reassembly & Noise Stripping**: Each path's coordinates were shifted by subtracting `layerOffsets[layer]`. Adding `layerOffsets[path.layer]` back to each path's `M x y` anchor immediately collapses all 3 temporal animation layers into a single static frame with zero particle noise.

  4. **Unauthenticated Modal Kinematics**: `validModalKinematics()` (`attestation/adaptive_challenge.js`, lines 72–85) checks client-reported JSON fields (`trustedKeydowns >= 6`, `ttfkMs >= 250`, `totalTypingMs >= 300`, `dwellVariance >= 4`, `intervalVariance >= 8`), which an automated script can hardcode verbatim.

* **Exploitability**:

  * **Vector Solver (No AI/OCR Required)**: An automated script intercepts the decrypted `rendering` JSON, adds `noise.layerOffsets[path.layer]` to each path coordinate, discards decoy paths whose Y-centroid is near `30` or `85`, segments the remaining 6 clusters at `X ≈ 35 + i * 45`, and matches the 5×7 point cloud against the 32-character `FONT` dictionary in <5 ms with \~100% accuracy.

  * **Vision Agent / Multimodal LLM Solver**: An agent renders all 3 layers onto a static offscreen canvas (omitting the particle noise loop in `paint()`) and passes the clean image to any off-the-shelf OCR or vision model.

* **Suggested Fix**:

  1. Never send raw vector path data and explicit `layerOffsets` to the client where layers and noise can be algebraically inverted. If a visual challenge is used, rasterize and composite the frames server-side or apply non-invertible mesh/wavefields across unified bitmaps where decoys and glyphs share overlapping vertical bands (`Y`) and connected strokes.

  2. Replace 6-character distorted text transcription (which is solved at >98% accuracy by modern multimodal agents) with behavioral/cryptographic step-up (such as WebAuthn platform authenticator verification, Private Access Tokens, or server-scored multi-step interactive tasks).

### VULN-04 (High): Global `SessionStore` & `RateLimiter` Table Exhaustion Triggers Site-Wide Fail-Closed DoS

* **Affected Files**: `compiler/middleware.js` (lines 30–62, 92–95), `attestation/rate_limiter.js` (lines 14–48).

* **Root Cause**:
  Both `SessionStore` and `RateLimiter` enforce hard global capacity limits (`10,000` entries) and **fail closed globally** when full:

  1. **`SessionStore` Exhaustion (`compiler/middleware.js`)**:

     * `SessionStore` defaults to `maxSize = 10_000`, `ttlMs = 300_000` (5 minutes), and `maxPerSubnet = 15`.

     * `canAccept(subnet)` rejects all new sessions globally when `this._map.size >= this._maxSize` (`10,000`), returning `HTTP 429 Session capacity reached`.

     * Because unconsumed sessions live for **5 full minutes** (`300_000 ms`), an attacker rotating across just **667 IPv4 `/24` or IPv6 `/48` subnets** (`667 × 15 = 10,005` requests to `GET /collector.js`, never calling `POST /attest`) fills `SessionStore` to 10,000 entries in a few seconds. Every legitimate user visiting the website from any IP worldwide receives `429 Session capacity reached` for the next 5 minutes.

  2. **`RateLimiter` Protected-Entry Exhaustion (`attestation/rate_limiter.js`)**:

     * `RateLimiter` defaults to `maxEntries = 10_000` and `failureWindowMs = 300_000` (5 minutes).

     * When `rateLimiter.failure(key)` is called **even once** for a subnet (e.g., sending `POST /attest` with `{}`), `this.clean.delete(key)` removes that subnet from the evictable `clean` map for `failureWindowMs` (5 minutes):

       ```
       failure(key) {
         const e = this.entry(key); if (!e) return;
         e.consecutive++; e.failures.push(this.now());
         this.clean.delete(key); // Protected from eviction for 5 minutes after just 1 failure!
       
       ```

     * When `this.entries.size >= 10_000` and `this.clean` is empty, `entry(key)` returns `null` for **all new legitimate subnets**, causing `check(key)` to return `{ allowed: false, retryAfter: 60 }`. An attacker sending just **1 malformed POST request from 10,000 distinct `/24` or `/48` subnets within 5 minutes** triggers a complete global outage (`HTTP 429`) for all new visitors.

* **Suggested Fix**:

  1. Lower `SessionStore` `ttlMs` from `300_000` (5 min) to `60_000` (60s, matching the PoW challenge lifetime) and evict the oldest unconsumed session (FIFO/LRU) when `maxSize` is reached instead of blocking all new users globally.

  2. In `RateLimiter`, only remove an entry from the evictable `clean` map once it crosses the penalty/ban threshold (`e.consecutive >= 3` or `e.failures.length >= this.failureLimit`), and keep `clean` in LRU order so single-shot failed requests from botnet IPs can be evicted under memory pressure:

  ```
  // In attestation/rate_limiter.js:
  failure(key) {
    const e = this.entry(key); if (!e) return;
    const now = this.now();
    e.consecutive++;
    e.failures.push(now);
    if (e.failures.length >= this.failureLimit) {
      e.until = now + Math.min(this.maxCooldownMs, this.cooldownMs * 2 ** Math.min(e.strikes++, 20));
      e.failures = e.failures.slice(-this.failureLimit);
    }
    // Only protect entries from eviction if they have triggered a reputation penalty or cooldown
    if (e.consecutive >= 3 || e.until > now) {
      this.clean.delete(key);
      this.expiry.set(key, Math.max(now + this.failureWindowMs, e.until));
    }
  }
  
  ```

### VULN-05 (High): TLS Reverse-Proxy Scheme Mismatch Causes 100% Same-Origin Session Failure (`http` vs `https`)

* **Affected Files**: `attestation/origin.js` (lines 10–17), `attestation/server.js` (lines 91–95), `compiler/middleware.js` (lines 171–176).

* **Root Cause**:
  In `attestation/origin.js`:

  ```
  function requestHostOrigin(req) {
    const host = req.headers?.host;
    return typeof host === "string" ? normalizeOrigin((req.socket?.encrypted ? "https://" : "http://") + host) : "";
  }
  function requestOrigin(req) {
    return req.headers?.origin === undefined ? requestHostOrigin(req) : normalizeOrigin(req.headers.origin);
  }
  
  ```

  In almost all enterprise deployments, TLS terminates at a reverse proxy, load balancer, or CDN (AWS ALB, Nginx, Cloudflare, Envoy), which forwards traffic over plain HTTP (`req.socket.encrypted === undefined`) to the Node.js container.

  1. When a browser loads `<script src="/collector.js"></script>` on `https://app.enterprise.com`, browsers **do not send an `Origin` header** on same-origin `<script>` navigation/subresource GET requests. Thus `req.headers.origin` is `undefined`, and `requestOrigin(req)` falls back to `requestHostOrigin(req)`, recording `session.headerProfile.origin = "http://app.enterprise.com"`.

  2. When the collector executes `fetch("/attest", { method: "POST", ... })`, browsers **always send an `Origin` header on `POST` requests**: `Origin: https://app.enterprise.com`.

  3. First, in `attestation/server.js` (line 93), `origin` (`"https://app.enterprise.com"`) !== `host` (`"http://app.enterprise.com"`), which immediately rejects the request with `403 Origin not allowed` unless `https://app.enterprise.com` was manually added to `ALLOWED_ORIGINS`.

  4. Second, even if `https://app.enterprise.com` is in `ALLOWED_ORIGINS`, `createDecryptHandler()` (`compiler/middleware.js`, line 172) compares the `GET /collector.js` profile (`session.headerProfile.origin === "http://app.enterprise.com"`) against the `POST /attest` profile (`currentProfile.origin === "https://app.enterprise.com"`):

     ```
     if (session.headerProfile && ["origin", "host"].some(field =>
         session.headerProfile[field] !== currentProfile[field])) {
       onFailure(req); res.writeHead(403, { "Content-Type": "application/json" });
       return res.end(JSON.stringify({ error: "Session origin mismatch" }));
     }
     
     ```

     Because `"http://app.enterprise.com" !== "https://app.enterprise.com"`, **100% of same-origin browser attestations fail with `403 Session origin mismatch`** behind any TLS-terminating reverse proxy!

* **Suggested Fix**:
  When `TRUST_PROXY === "1"` (or an explicit `PUBLIC_ORIGIN` configuration is set), honor `X-Forwarded-Proto` in `requestHostOrigin(req)` so the inferred host scheme matches the external HTTPS listener:

  ```
  // In attestation/origin.js:
  function requestHostOrigin(req) {
    const host = req.headers?.host;
    if (typeof host !== "string") return "";
    let proto = req.socket?.encrypted ? "https" : "http";
    if (process.env.TRUST_PROXY === "1" && typeof req.headers?.["x-forwarded-proto"] === "string") {
      const forwardedProto = req.headers["x-forwarded-proto"].split(",")[0].trim().toLowerCase();
      if (forwardedProto === "https" || forwardedProto === "http") proto = forwardedProto;
    }
    return normalizeOrigin(`${proto}://${host}`);
  }
  
  ```

### VULN-06 (High): Process-Local State & Ephemeral Secrets Break Multi-Node Scaling and Enable `N×` Token Replay

* **Affected Files**: `attestation/verifier.js` (line 27), `attestation/adaptive_challenge.js` (line 24), `attestation/keys.js` (lines 13–28), `compiler/middleware.js` (lines 30–80), `attestation/rate_limiter.js`.

* **Root Cause**:
  All state stores and default secrets are process-local in memory:

  * **Token Replay Across Replicas**: `attestation/verifier.js` instantiates a module-local `const nonceCache = new NonceCache(120_000)`. In an enterprise Kubernetes or auto-scaling deployment with `N` replicas verifying tokens, an attacker can replay the exact same single-use Ed25519 token **`N` times** (once against each replica).

  * **Ephemeral Challenge HMAC Secret**: `AdaptiveChallenge` defaults to `secret = crypto.randomBytes(32)` per process. If `/attest` hits Pod A and `/attest/verify-challenge` hits Pod B, HMAC verification fails (`invalid challenge signature`) and `this.store.consume()` fails (`unknown, expired, or consumed challenge`).

  * **Session Store Split**: If `GET /collector.js` hits Pod A and `POST /attest` hits Pod B, decryption fails with `403 unknown or expired session`.

  * **Lack of Key Rotation (`kid`)**: `attestation/token.js` hardcodes `HEADER = { alg: "EdDSA", typ: "ATT+JWT" }` with no `kid` (Key ID) header, and `attestation/verifier.js` only accepts a single static `publicKey`, making zero-downtime key rotation impossible.

* **Suggested Fix**:

  1. Externalize `SessionStore`, `NonceCache`, and `RateLimiter` to a shared Redis cluster using atomic operations (`GETDEL` for single-use sessions/challenges, `SET nonce 1 NX EX 120` for token replay prevention).

  2. Require `ATTESTATION_HMAC_SECRET` from environment/secret manager in production inside `AdaptiveChallenge`.

  3. Include a `kid` claim in the JWS header (`token.js`) and support a keyring of active public keys during rotation windows in `verifier.js`.

### VULN-07 (High): Synchronous Per-Request Bundle Compilation, Keygen, and Scratchpad Allocation Exhaust Event Loop

* **Affected Files**: `compiler/middleware.js` (lines 90–125), `compiler/pipeline.js` (lines 176–275), `pow_verifier.js` (lines 15–18, 58–66).

* **Root Cause**:

  1. Every `GET /collector.js` runs synchronous CPU-bound operations on the main Node.js event loop:

     * `crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })` (synchronous elliptic-curve key generation).

     * `createScratchpad(challenge)` (16,384 rounds of 32-bit xorshift/imul).

     * Full regex string extraction (435 strings), XOR hex encoding, regex identifier extraction (224 identifiers), regex replacement across \~93 KB of JS source, and dead-code injection.

  2. In `pow_verifier.js` (line 62), `generateChallenge()` precomputes a 64 KiB scratchpad and stores it in a `Map` capped at **only 128 entries**:

     ```
     if (scratchpads.size >= 128) scratchpads.delete(scratchpads.keys().next().value);
     scratchpads.set(challenge, createScratchpad(challenge));
     
     ```

     Because a client takes \~100–1,000 ms to mine PoW and submit `POST /attest`, any traffic rate exceeding \~128 requests/second evicts every precomputed scratchpad before `/attest` arrives! Consequently, `hashPoW()` suffers a 100% cache miss rate under load and recomputes the 64 KiB scratchpad **a second time** synchronously on `POST /attest`.

* **Suggested Fix**:

  1. Do not precompute the scratchpad inside `generateChallenge()`. Compute it lazily only once during `verifyPoW()` (after session and envelope validation succeed), or store the seed in the session and compute only on verification.

  2. Replace synchronous `crypto.generateKeyPairSync` with async `crypto.generateKeyPair`, and pre-compile a rotating ring buffer of polymorphic bundles in a background `worker_threads` pool (rotating every 1–5 seconds) or use template placeholders for `spkiB64`, `sessionId`, and `powChallenge` so per-request serving takes <0.1 ms of main-thread CPU time.

### VULN-08 (High): Python PoW Verifier (`pow_verifier.py`) Omits Scratchpad Mixing & Fails on Arbitrary-Precision Ints

* **Affected Files**: `pow_verifier.py` (lines 55–114) and `pow/verifier.py` (lines 55–114).

* **Root Cause**:

  1. **Protocol Desynchronization**: The client workers (`pow_inline.js`, `pow_worker.js`) and Node verifier (`pow_verifier.js`) hash `challenge + String(nonce) + scratchSuffix(pad, nonce)` (which appends `:cache64-v1:<x>:<y>`). However, both copies of `pow_verifier.py` compute plain SHA-256 without the scratchpad suffix:

     ```
     # pow_verifier.py line 96:
     message = (challenge + str(nonce)).encode("utf-8")
     digest = hashlib.sha256(message).digest()
     
     ```

     Any Python backend calling `verify_pow()` will reject 100% of valid browser PoW solutions! Conversely, if paired with a custom client, it completely bypasses the 64 KiB scratchpad memory-hardening.

  2. **Unbounded Integer DoS / Unhandled Exception**: In Python, `isinstance(True, int)` evaluates to `True`, and `isinstance(nonce, int)` accepts arbitrary-precision integers. Passing a JSON payload with a 5,000-digit integer `nonce` causes `str(nonce)` in Python 3.11+ to raise an unhandled `ValueError: Exceeds the limit (4300 digits) for integer string conversion`, crashing the request handler with HTTP 500.

* **Suggested Fix**:
  Update `pow_verifier.py` and `pow/verifier.py` to enforce safe bounds (`not isinstance(nonce, bool)` and `0 <= nonce <= 9007199254740991`, `len(challenge) <= 256`) and implement the exact 32-bit `create_scratchpad` and `scratch_suffix` functions matching `pow/scratchpad.js`:

  ```
  def _imul32(a: int, b: int) -> int:
      p = ((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)) & 0xFFFFFFFF
      return p - 0x100000000 if p & 0x80000000 else p
  
  def create_scratchpad(challenge: str) -> list[int]:
      pad = [0] * 16384
      seed = 2166136261
      for ch in challenge:
          seed = _imul32(seed ^ ord(ch), 16777619)
      for j in range(16384):
          seed ^= (seed << 13) & 0xFFFFFFFF
          seed = _to_int32(seed)
          seed ^= (seed & 0xFFFFFFFF) >> 17
          seed ^= (seed << 5) & 0xFFFFFFFF
          seed = _to_int32(seed + _imul32(j + 1, 0x9E3779B9))
          pad[j] = seed
      return pad
  
  def scratch_suffix(pad: list[int], nonce: int) -> str:
      x = _to_int32((nonce & 0xFFFFFFFF) ^ (nonce // 4294967296))
      y = 0x6A09E667
      for i in range(64):
          x = _imul32(x ^ pad[(x ^ y) & 16383], 0x85EBCA6B)
          x = _to_int32(((x << 13) & 0xFFFFFFFF) | ((x & 0xFFFFFFFF) >> 19))
          y = _to_int32(_imul32(y ^ x, 0xC2B2AE35) + i)
      return f":cache64-v1:{x & 0xFFFFFFFF}:{y & 0xFFFFFFFF}"
  
  ```

### VULN-09 (Medium): IPv4 `/24` & IPv6 `/48` Subnet Grouping Enables Reputation Poisoning Against Enterprise NATs

* **Affected Files**: `attestation/ip_mask.js` (lines 18–62), `attestation/rate_limiter.js` (lines 38–54), `attestation/server.js` (lines 52–67, 102–108), `compiler/middleware.js` (line 34).

* **Root Cause**:
  All rate limits (`30 req/min`), concurrent session caps (`15 active sessions`), and failure penalties (`3 failures → -0.50 penalty`; `8 failures → up to 15-minute ban`) are keyed by `maskIP(getClientIP(req))`—which collapses **all 256 IPv4 addresses in a `/24` block** into a single bucket.

  * **Enterprise NAT / Campus / Carrier CGNAT Starvation**: A single corporate office, university, or mobile carrier NAT gateway easily generates >10 page loads per minute (each attestation consumes 2–3 requests out of the 30/min `/24` budget) or >15 simultaneous login sessions, causing legitimate enterprise users to hit `429 Too many requests` or `429 Session capacity reached`.

  * **Unauthenticated Reputation Poisoning**: Sending 8 unauthenticated `POST /attest` requests with `{}` from any host in the same `/24` subnet (or spoofing an adjacent user on shared Wi-Fi/ISP) triggers `rateLimiter.failure(key)` 8 times (`server.js` line 57) and locks out the entire `/24` subnet for up to 15 minutes.

* **Suggested Fix**:

  1. Key primary rate limits, failure strikes, and session limits by the full client IP (`/32` for IPv4, `/64` for IPv6), using `/24` and `/48` prefixes only for secondary anomaly scoring with much higher thresholds (e.g., 500 req/min per `/24`).

  2. Do not increment subnet reputation failures on cheap, unauthenticated syntax/envelope errors (`!body.sid`) before verifying that the caller actually holds a valid issued `sessionId`.

### VULN-10 (Medium): `verifyToken()` Fails Open on `"unknown"` IP Subnets and Optional `action` / `origin` / `minScore`

* **Affected Files**: `attestation/verifier.js` (lines 60–225), `attestation/token.js` (lines 48–95).

* **Root Cause**:
  In `attestation/verifier.js`:

  1. **Fail-Open IP Subnet Check (lines 161–171)**:

     ```
     if (typeof opts.clientIP === "string") {
       const expectedSubnet = maskIP(opts.clientIP);
       if (
         claims.ip_subnet !== "unknown" &&
         expectedSubnet !== "unknown" &&
         claims.ip_subnet !== expectedSubnet
       ) {
         return fail(`IP subnet mismatch...`);
       }
     }
     
     ```

     If `opts.clientIP` is omitted, or if `maskIP(opts.clientIP)` returns `"unknown"` (e.g., due to an unparsed proxy header or custom socket), or if the token was minted with `ip_subnet: "unknown"`, subnet verification silently succeeds!

  2. **Optional `action` & Low Default `minScore`**:

     * If a relying-party developer calls `verifyToken(token, { clientIP })` or uses `attestationMiddleware()` without specifying `action`, a token minted for a low-value `"pageview"` action is accepted for `"login"` or `"wire_transfer"`.

     * `attestationMiddleware()` defaults to `minScore = 0.5` (line 196), whereas `/attest` treats scores `< 0.70` as unverified without step-up.

* **Suggested Fix**:
  Require `action`, `origin`, and `host` in `verifyToken()` and `attestationMiddleware()`, set the default `minScore = 0.70`, and fail closed if either `claims.ip_subnet === "unknown"` or `expectedSubnet === "unknown"`:

  ```
  // In attestation/verifier.js:
  if (!opts.action || claims.action !== opts.action) {
    return fail(`action mismatch: expected "${opts.action}", got "${claims.action}"`);
  }
  const expectedSubnet = typeof opts.clientIP === "string" ? maskIP(opts.clientIP) : "unknown";
  if (claims.ip_subnet === "unknown" || expectedSubnet === "unknown" || claims.ip_subnet !== expectedSubnet) {
    return fail(`IP subnet mismatch: token="${claims.ip_subnet}", client="${expectedSubnet}"`);
  }
  const minScore = typeof opts.minScore === "number" ? opts.minScore : 0.70;
  if (claims.score < minScore) {
    return fail(`score ${claims.score} below threshold ${minScore}`);
  }
  
  ```

### VULN-11 (Medium): Unauthenticated, Unthrottled `POST /verify` Endpoint Allows Pre-Emptive Token Nonce Burning

* **Affected Files**: `attestation/server.js` (lines 69–76, 102–115).

* **Root Cause**:
  `server.js` exposes `POST /verify` publicly on the same port as `/collector.js` and `/attest`, and omits `/verify` from the rate-limiter check on line 102 (`if (["/collector.js", "/attest", "/attest/verify-challenge"].includes(url))`). Because `verifyToken()` claims the single-use `nonce` in `nonceCache`, any client on the same origin/subnet can call `/verify` directly or flood `/verify` without rate limiting.

* **Suggested Fix**:
  Remove `/verify` from the public client-facing listener (or protect it with a constant-time internal `Authorization: Bearer <INTERNAL_VERIFY_SECRET>` header / mTLS) and encourage backend services to verify Ed25519 tokens locally or over an internal service mesh.

### VULN-12 (Medium): Strict Client-Hint & Engine Error Rules Penalize Legitimate Browsers (iOS, Brave, Enterprise Proxies)

* **Affected Files**: `attestation/header_check.js` (lines 33–53), `attestation/scorer.js` (lines 285–340), `client/runtime_integrity.js` (lines 141–168), `compiler/step_up.js` (lines 26–138).

* **Root Cause**:

  1. **`chrome_ua_missing_client_hints` (Penalty `0.6` → Hard Clamp to `0.10`)**: `header_check.js` (line 42) penalizes any User-Agent matching `/Chrome\/\d+/` by `0.6` if `sec-ch-ua`, `sec-ch-ua-platform`, or `sec-ch-ua-mobile` is missing. Because `scorer.js` (line 318) hard-clamps `score <= 0.1` whenever `headerCheck.penalty >= 0.5`, legitimate users on **Brave**, **Chrome on iOS (`CriOS` uses WebKit and does not send Chromium Client Hints)**, privacy-hardened Chromium policies, or behind enterprise TLS proxies that strip `Sec-CH-UA-*` headers are automatically clamped to `0.10` and forced into a difficulty-21 PoW + Visual CAPTCHA.

  2. **Interaction Count Excludes Clicks/Pointerdowns (`countInteractions`)**: `scorer.js` (line 334) only sums `["mousemove", "touchstart", "touchmove", "keydown"]`. A user who logs in via a password manager or single mouse click without moving the cursor 5 times has `< 5` counted events and is hard-clamped to `0.30` (forcing a visual CAPTCHA).

  3. **Zero Non-Visual Accessibility Path**: The visual step-up modal (`compiler/step_up.js`) renders an animated 60fps flickering canvas with no audio challenge, WebAuthn alternative, or `prefers-reduced-motion` support, blocking blind and photosensitive users.

* **Suggested Fix**:

  1. Add `pointerdown` and `mousedown` to `countInteractions()` in `attestation/scorer.js`.

  2. Reduce `chrome_ua_missing_client_hints` penalty from `0.6` to `0.25` (so missing Client Hints alone triggers lightweight PoW step-up rather than hard-clamping to `0.10` visual CAPTCHA), and exclude `CriOS` (iOS Chrome) from V8 receiver-error and Client-Hint requirements.

  3. Provide an accessible step-up alternative (e.g., WebAuthn device check or accessible audio/Challenge-Response flow).

### VULN-13 (Medium): Regex-Based Obfuscator Risks Syntax Corruption and Crashes on Non-ASCII Strings

* **Affected Files**: `compiler/string_table.js` (lines 43, 88–93, 146–177), `compiler/identifiers.js` (lines 61–116).

* **Root Cause**:

  * `xorEncrypt()` (`compiler/string_table.js`, line 88) throws a fatal `RangeError` if any string literal contains a UTF-8 character with `charCodeAt(i) > 127`.

  * `replaceStrings()` (lines 163–171) uses a fragile 20-character lookbehind (`source.substring(Math.max(0, offset - 20), offset)`) to decide whether a string followed by `:` is an object property key or a ternary branch.

  * `STRING_RE` and `extractIdentifiers()` operate on raw source text via regexes rather than an AST, meaning quotes inside regex literals or identifiers sharing names across scopes can produce broken JS bundles.

* **Suggested Fix**:
  Encode strings as UTF-8 bytes (`Buffer.from(str, "utf8")`) prior to XOR encryption so non-ASCII characters never crash the compiler, and replace regex source manipulation with a fast AST pass (e.g., `acorn` + `estraverse` + `astring`) performed at build initialization rather than per HTTP request.

### VULN-14 (Low): Static Worker (`pow_client.js` / `pow_worker.js`) Uses Per-Hash Async `SubtleCrypto` IPC

* **Affected Files**: `pow_client.js`, `pow_worker.js`, `client/pow_client.js`, `client/pow_worker.js`, `pow/client.js`, `pow/worker.js`.

* **Root Cause**:
  While `pow_inline.js` (used by the compiler) was updated to use a synchronous in-worker `sha256()` implementation, the standalone `pow_client.js` and `pow_worker.js` files still execute `await crypto.subtle.digest("SHA-256", messageSlice)` inside the `while (true)` loop—incurring millions of asynchronous Promise/IPC round-trips at difficulty 20–22 and causing severe slowdowns or timeouts.

* **Suggested Fix**:
  Unify `pow_client.js` and `pow_worker.js` with the synchronous `sha256()` implementation in `pow_inline.js` and remove duplicate copies across the repository root, `client/`, and `pow/`.

### VULN-15 (Low): Cross-Realm `ArrayBuffer` Bug in `ecdh_session.js` Breaks Node.js `vm` Test Suites & Standalone CORS `*`

* **Affected Files**: `compiler/ecdh_session.js` (lines 80–88), `test_adaptive_e2e.js` (line 191), `test_security.js` (line 147), `audit_bypass.cjs` (line 58), `compiler/middleware.js` (line 228).

* **Root Cause**:

  1. When running `npm test` (`node test_all.js`) on Node.js >=20, both `test_adaptive_e2e.js` and `test_security.js` **fail** with:
     `TypeError: Failed to execute 'importKey' on 'SubtleCrypto': 2nd argument is not instance of ArrayBuffer, Buffer, TypedArray, or DataView.`
     This occurs because `generateClientECDHCode()` creates `new Uint8Array(...)` inside a `vm.createContext()` sandbox (which uses the VM realm's `Uint8Array` / `ArrayBuffer` intrinsics) and passes `spkiBytes["buffer"]` to the host realm's `crypto.webcrypto.subtle.importKey()`.

  2. Additionally, `compiler/middleware.js` (line 228) includes a standalone server mode that sets `Access-Control-Allow-Origin: *` and returns `{ received: true }` without scoring or token verification.

* **Suggested Fix**:
  Pass `Uint8Array`, `Int32Array`, `Float32Array`, `ArrayBuffer`, and `DataView` from the host realm into `vm.createContext(...)` in `test_security.js`, `test_adaptive_e2e.js`, and `audit_bypass.cjs`, and remove or restrict the wildcard CORS standalone listener in `compiler/middleware.js`.

## Enterprise Hardening Roadmap

If you intend to evolve this project into a component of an enterprise defense stack, implement the following layered architecture rather than relying on this codebase alone:

1. **Immediate Code Remediations (P0)**:

   * Fix the global collector exposure in `compiler/pipeline.js` (**VULN-01**) so `RuntimeIntegrity`, `HardwareConsistency`, and `Kinematics` are closed inside the IIFE and randomized per build.

   * Fix `attestation/origin.js` (**VULN-05**) to support `X-Forwarded-Proto` when `TRUST_PROXY=1` so HTTPS reverse proxies do not trigger 100% `Session origin mismatch` failures.

   * Fix `SessionStore` and `RateLimiter` eviction logic (**VULN-04**) so botnets cannot trigger a global fail-closed `429` outage across all legitimate users.

   * Update `pow_verifier.py` (**VULN-08**) to implement the 64 KiB scratchpad suffix and bound integer inputs.

   * Harden `verifyToken()` (**VULN-10**) to fail closed on `"unknown"` subnets and require `action`, `origin`, `host`, and `minScore >= 0.70`.

2. **Distributed State & Performance (P1)**:

   * Replace in-memory `SessionStore`, `NonceCache`, and `RateLimiter` with Redis (**VULN-06**) and move bundle compilation off the hot request thread into a rotating worker pool (**VULN-07**).

3. **Defense Against Advanced Agents & Career Hackers (P2)**:

   * Replace the client-decrypted vector visual CAPTCHA (**VULN-03**) with hardware-backed browser/device attestation (WebAuthn/Passkeys, Private Access Tokens) and network-layer fingerprinting (TLS JA4, HTTP/2 frame telemetry, and ASN/IP intelligence at the WAF/CDN edge).