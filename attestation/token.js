/**
 * token.js — Ed25519-Signed Attestation Token
 *
 * Token wire format (compact, no external deps):
 *
 *   Base64URL(header_json) "." Base64URL(claims_json) "." Base64URL(signature)
 *
 * This is structurally a JWS Compact Serialization (RFC 7515) with:
 *   header  = { "alg": "EdDSA", "typ": "ATT+JWT" }
 *   claims  = { score, action, exp, iat, nonce, ip_subnet }
 *   sig     = Ed25519(privateKey, ASCII(header64 "." claims64))
 *
 * Compatible with standard JWT libraries, but requires zero external
 * dependencies to create or verify.
 */

"use strict";

const crypto = require("node:crypto");
const { privateKey } = require("./keys");
const { normalizeOrigin } = require("./origin");

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const HEADER = Object.freeze({ alg: "EdDSA", typ: "ATT+JWT" });
const HEADER_B64 = toBase64URL(JSON.stringify(HEADER));

const MIN_TTL_S = 30;
const MAX_TTL_S = 60;
const DEFAULT_TTL_S = 45;

/* ------------------------------------------------------------------ */
/*  Token issuance                                                     */
/* ------------------------------------------------------------------ */

/**
 * Issue a signed attestation token.
 *
 * @param {Object}  opts
 * @param {number}  opts.score      – risk score [0.0, 1.0]
 * @param {string}  opts.action     – action label ("login", "checkout", …)
 * @param {string}  opts.ipSubnet   – masked client subnet
 * @param {number}  [opts.ttlS]     – token lifetime in seconds (30–60, default 45)
 * @param {number}  [opts.nowMs]    – override current time (for testing / clock-skew)
 *
 * @returns {{ token: string, claims: Object }}
 */
function issueToken({ score, action, ipSubnet, ttlS, nowMs, origin = "", host = "", demo = false }) {
  if (typeof demo !== "boolean") throw new TypeError("Invalid demo marker");
  if (ttlS !== undefined && !Number.isSafeInteger(ttlS)) throw new TypeError("Invalid TTL");
  if (nowMs !== undefined && (!Number.isSafeInteger(nowMs) || nowMs < 0)) throw new TypeError("Invalid clock");
  for (const value of [origin, host])
    if (typeof value !== "string" || (value !== "" && normalizeOrigin(value) !== value)) throw new TypeError("invalid token origin/host");
  // ── Validate score ────────────────────────────────────────────────
  if (typeof score !== "number" || !Number.isFinite(score)) {
    throw new TypeError("score must be a finite number");
  }
  score = Math.round(Math.max(0, Math.min(1, score)) * 10000) / 10000;

  // ── Validate action ───────────────────────────────────────────────
  if (typeof action !== "string" || action.length === 0 || action.length > 128) {
    throw new TypeError("action must be a non-empty string (≤128 chars)");
  }

  // ── TTL ───────────────────────────────────────────────────────────
  const ttl = typeof ttlS === "number"
    ? Math.max(MIN_TTL_S, Math.min(MAX_TTL_S, Math.floor(ttlS)))
    : DEFAULT_TTL_S;

  // ── Timestamps ────────────────────────────────────────────────────
  const now = typeof nowMs === "number" ? Math.floor(nowMs / 1000) : Math.floor(Date.now() / 1000);
  const exp = now + ttl;

  // ── Nonce (128-bit hex) ───────────────────────────────────────────
  const nonce = crypto.randomBytes(16).toString("hex");

  // ── Build claims ──────────────────────────────────────────────────
  const claims = {
    demo,
    score,
    origin,
    host,
    action,
    exp,
    iat: now,
    nonce,
    ip_subnet: typeof ipSubnet === "string" ? ipSubnet : "unknown",
  };

  const claimsB64 = toBase64URL(JSON.stringify(claims));

  // ── Sign ──────────────────────────────────────────────────────────
  const signingInput = `${HEADER_B64}.${claimsB64}`;
  const signature = crypto.sign(null, Buffer.from(signingInput), privateKey);
  const sigB64 = bufferToBase64URL(signature);

  const token = `${signingInput}.${sigB64}`;

  return { token, claims };
}

/* ------------------------------------------------------------------ */
/*  Base64URL helpers (RFC 4648 §5, no padding)                        */
/* ------------------------------------------------------------------ */

function toBase64URL(str) {
  return Buffer.from(str, "utf-8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function bufferToBase64URL(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

module.exports = { issueToken, MIN_TTL_S, MAX_TTL_S, DEFAULT_TTL_S };
