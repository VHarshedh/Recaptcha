/**
 * verifier.js — Attestation Token Verifier & Express-compatible Middleware
 *
 * Verifies the Ed25519 signature, checks expiry (with configurable
 * clock-skew tolerance), validates the IP subnet binding, and rejects
 * replayed nonces via the sliding-window NonceCache.
 *
 * Usage (standalone):
 *   const { verifyToken } = require("./verifier");
 *   const result = verifyToken(tokenString, { clientIP: "1.2.3.4" });
 *
 * Usage (middleware):
 *   app.post("/api/checkout", attestationMiddleware({ action: "checkout" }), handler);
 */

"use strict";

const crypto = require("node:crypto");
const { publicKey } = require("./keys");
const { maskIP, getClientIP } = require("./ip_mask");
const { normalizeOrigin } = require("./origin");
const { NonceCache } = require("./nonce_cache");

/* ------------------------------------------------------------------ */
/*  Module-level nonce cache                                           */
/* ------------------------------------------------------------------ */

// Window = 2 minutes covers the max token TTL (60s) with generous margin.
const nonceCache = new NonceCache(120_000);

/* ------------------------------------------------------------------ */
/*  Configuration                                                      */
/* ------------------------------------------------------------------ */

/**
 * Maximum acceptable clock skew in seconds.
 * Accounts for minor NTP drift between the signing server and the
 * verifying server (same machine in single-node, but could differ in
 * distributed setups).
 */
const CLOCK_SKEW_S = 5;

/* ------------------------------------------------------------------ */
/*  Core verifier                                                      */
/* ------------------------------------------------------------------ */

/**
 * @typedef {Object} VerifyResult
 * @property {boolean} valid
 * @property {string}  [reason]    – human-readable rejection reason
 * @property {Object}  [claims]    – decoded claims (only when valid)
 */

/**
 * Verify an attestation token.
 *
 * @param {string}  token          – the compact JWS token string
 * @param {Object}  [opts]
 * @param {string}  [opts.clientIP]  – raw client IP for subnet binding check
 * @param {string}  [opts.action]    – expected action claim
 * @param {number}  [opts.minScore]  – reject if score < this threshold
 * @param {number}  [opts.nowMs]     – override current time (testing)
 * @param {boolean} [opts.skipNonce] – skip nonce-replay check (testing only)
 *
 * @returns {VerifyResult}
 */
const SHARED_CHECK = Symbol("shared replay verification");
function verifyToken(token, opts = {}) {
  if (process.env.NODE_ENV === "production" && process.env.ATTESTATION_STATE_MODE !== "single-process" && opts[SHARED_CHECK] !== true)
    return fail("Local replay cache requires explicit single-process deployment");
  for (const field of ["action", "origin", "host", "clientIP"]) {
    if (typeof opts[field] !== "string" || !opts[field]) return fail("expected " + field + " required");
  }
  opts = { ...opts, minScore: opts.minScore === undefined ? 0.70 : opts.minScore };
  if (!Number.isFinite(opts.minScore) || opts.minScore < 0.70 || opts.minScore > 1) return fail("invalid minimum score");
  // ── Structural parse ──────────────────────────────────────────────
  if (typeof token !== "string") {
    return fail("token must be a string");
  }
  if (token.length > 8192) return fail("token too large");

  if (opts.nowMs !== undefined && (!Number.isSafeInteger(opts.nowMs) || opts.nowMs < 0)) return fail("invalid clock");
  const parts = token.split(".");
  if (parts.length !== 3) {
    return fail("malformed token: expected 3 dot-separated parts");
  }

  const [headerB64, claimsB64, sigB64] = parts;

  // ── Decode header ─────────────────────────────────────────────────
  let header;
  try {
    header = JSON.parse(fromBase64URL(headerB64));
  } catch {
    return fail("malformed header");
  }
  if (!header || header.alg !== "EdDSA" || header.typ !== "ATT+JWT") {
    return fail(`unsupported algorithm: ${header?.alg}`);
  }

  // ── Verify signature FIRST (before trusting any claim) ────────────
  const signingInput = Buffer.from(`${headerB64}.${claimsB64}`);
  const signature = base64URLToBuffer(sigB64);

  let sigValid;
  try {
    sigValid = crypto.verify(null, signingInput, publicKey, signature);
  } catch {
    return fail("signature verification threw");
  }
  if (!sigValid) {
    return fail("invalid signature");
  }

  // ── Decode claims ─────────────────────────────────────────────────
  let claims;
  try {
    claims = JSON.parse(fromBase64URL(claimsB64));
  } catch {
    return fail("malformed claims");
  }

  // Puzzle/telemetry demo results are not independent verification. Never
  // permit them at a production relying party, including with an opt-in flag.
  if (typeof claims?.demo !== "boolean") return fail("invalid demo marker");
  if (claims?.demo === true && (opts.allowInsecureDemo !== true || process.env.NODE_ENV === "production"))
    return fail("Demo puzzle token cannot authorize access");

  // ── Required fields ───────────────────────────────────────────────
  if (!claims || typeof claims.score !== "number" || !Number.isFinite(claims.score) || claims.score < 0 || claims.score > 1) {
    return fail("missing or invalid score");
  }
  if (typeof claims.exp !== "number" || !Number.isSafeInteger(claims.exp)) {
    return fail("missing or invalid exp");
  }
  if (typeof claims.iat !== "number" || !Number.isSafeInteger(claims.iat)) {
    return fail("missing or invalid iat");
  }
  if (typeof claims.nonce !== "string" || !/^[a-f0-9]{32}$/.test(claims.nonce)) {
    return fail("missing or invalid nonce");
  }
  if (typeof claims.action !== "string") {
    return fail("missing or invalid action");
  }

  // ── Expiry check (with clock-skew tolerance) ──────────────────────
  const nowS = typeof opts.nowMs === "number"
    ? Math.floor(opts.nowMs / 1000)
    : Math.floor(Date.now() / 1000);

  if (nowS > claims.exp + CLOCK_SKEW_S) {
    return fail(`token expired (exp=${claims.exp}, now=${nowS}, skew=${CLOCK_SKEW_S}s)`);
  }

  // Reject tokens issued in the far future (beyond skew allowance).
  if (claims.iat > nowS + CLOCK_SKEW_S) {
    return fail(`token issued in the future (iat=${claims.iat}, now=${nowS})`);
  }

  // Sanity: exp must be after iat.
  if (claims.exp <= claims.iat) {
    return fail("exp must be after iat");
  }

  // TTL must be in [30, 60].
  const ttl = claims.exp - claims.iat;
  if (ttl < 30 || ttl > 60) {
    return fail(`TTL out of range: ${ttl}s (must be 30–60)`);
  }

  if (claims.origin && typeof opts.origin !== "string") return fail("expected origin required");
  if (typeof opts.origin === "string" && claims.origin !== opts.origin) return fail("origin mismatch");
  if (claims.host && typeof opts.host !== "string") return fail("expected host required");
  if (typeof opts.host === "string" && claims.host !== opts.host) return fail("host mismatch");

  // ── Action binding ────────────────────────────────────────────────
  if (typeof opts.action === "string" && claims.action !== opts.action) {
    return fail(`action mismatch: expected "${opts.action}", got "${claims.action}"`);
  }

  // ── IP subnet binding ────────────────────────────────────────────
  if (typeof opts.clientIP === "string") {
    const expectedSubnet = maskIP(opts.clientIP);
    if (
      claims.ip_subnet === "unknown" ||
      expectedSubnet === "unknown" ||
      claims.ip_subnet !== expectedSubnet
    ) {
      return fail(
        `IP subnet mismatch: token="${claims.ip_subnet}", client="${expectedSubnet}"`
      );
    }
  }

  // ── Score threshold ───────────────────────────────────────────────
  if (typeof opts.minScore === "number" && claims.score < opts.minScore) {
    return fail(`score ${claims.score} below threshold ${opts.minScore}`);
  }

  // ── Nonce replay protection ───────────────────────────────────────
  if (opts.skipNonce === true && process.env.NODE_ENV === "production" && opts[SHARED_CHECK] !== true) return fail("Cannot skip production replay protection");
  if (opts.skipNonce !== true) {
    if (!nonceCache.claim(claims.nonce)) {
      return fail("nonce already used (replay detected)");
    }
  }

  return { valid: true, claims };
}

/* ------------------------------------------------------------------ */
/*  Express / Connect middleware factory                                */
/* ------------------------------------------------------------------ */

/**
 * Create middleware that extracts the attestation token from
 * `Authorization: Bearer <token>` or `x-attestation-token` header,
 * verifies it, and either passes control (req.attestation = claims)
 * or responds with 403.
 *
 * @param {Object}  [opts]
 * @param {string}  [opts.action]    – required action claim
 * @param {number}  [opts.minScore]  – minimum acceptable score (default 0.5)
 * @param {string}  [opts.header]    – custom header name
 *
 * @returns {Function} middleware(req, res, next)
 */
async function verifyTokenAsync(token, opts = {}) {
  if (!opts.nonceStore || typeof opts.nonceStore.claim !== "function") return fail("Shared nonce store required");
  const result = verifyToken(token, { ...opts, skipNonce: true, [SHARED_CHECK]: true });
  if (!result.valid) return result;
  try {
    if (!await opts.nonceStore.claim(result.claims.nonce, 120000)) return fail("nonce already used (replay detected)");
    return result;
  } catch { return fail("Replay store unavailable"); }
}

function attestationMiddleware(opts = {}) {
  // Trust application configuration, never caller-controlled request headers.
  for (const field of ["origin", "host"]) {
    if (!opts[field] || normalizeOrigin(opts[field]) !== opts[field])
      throw new TypeError("Explicit canonical " + field + " required");
  }
  const {
    action,
    minScore = 0.70,
    header: customHeader = "x-attestation-token",
  } = opts;

  return function _attestationMiddleware(req, res, next) {
    // Extract token.
    let token;
    const authHeader = req.headers?.authorization;
    if (typeof authHeader === "string" && authHeader.startsWith("Bearer ")) {
      token = authHeader.slice(7).trim();
    } else {
      token = req.headers?.[customHeader.toLowerCase()];
    }

    if (!token) {
      return sendJSON(res, 403, {
        error: "missing attestation token",
      });
    }

    // Determine client IP (respects X-Forwarded-For for reverse proxies).
    const clientIP = getClientIP(req);

    const verify = opts.nonceStore ? verifyTokenAsync : verifyToken;
    const checked = verify(token, { clientIP, action, minScore, nonceStore: opts.nonceStore, origin: opts.origin, host: opts.host });

    const finish = result => {
    if (!result.valid) {
      return sendJSON(res, 403, {
        error: "attestation failed",
        reason: result.reason,
      });
    }

    // Attach verified claims to the request object.
    req.attestation = result.claims;
    next();
    };
    return checked && typeof checked.then === "function" ? checked.then(finish) : finish(checked);
  };
}

/* ------------------------------------------------------------------ */
/*  Utilities                                                          */
/* ------------------------------------------------------------------ */

function fail(reason) {
  return { valid: false, reason };
}

function fromBase64URL(str) {
  // Restore standard base64 from base64url.
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(padded, "base64").toString("utf-8");
}

function base64URLToBuffer(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(padded, "base64");
}

function sendJSON(res, status, body) {
  if (typeof res.status === "function") {
    // Express-style
    return res.status(status).json(body);
  }
  // Raw Node http.ServerResponse
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

/* ------------------------------------------------------------------ */
/*  Exports                                                            */
/* ------------------------------------------------------------------ */

module.exports = {
  verifyToken,
  verifyTokenAsync,
  attestationMiddleware,
  nonceCache, // exported for testing / manual cache management
  CLOCK_SKEW_S,
};
