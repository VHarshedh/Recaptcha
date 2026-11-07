/**
 * server.js — Air-Gapped Attestation Microservice
 *
 * A single-file HTTP server using only `node:http` + `node:crypto`.
 * Zero external dependencies.
 *
 * Endpoints:
 *   POST /attest   – accept telemetry, compute score, return signed token
 *   GET  /pubkey   – return the Ed25519 public key (PEM)
 *   GET  /health   – liveness probe
 *
 * Run:   node attestation/server.js [port]
 */

"use strict";

const http = require("node:http");
const { normalizeOrigin, requestHostOrigin, requestOrigin } = require("./origin");
const { RateLimiter } = require("./rate_limiter");
const { AdaptiveChallenge } = require("./adaptive_challenge");
const { verifyToken } = require("./verifier");
const { maskIP, getClientIP } = require("./ip_mask");
const { publicKeyPem } = require("./keys");
const { createMiddleware, createDecryptHandler, SessionStore } = require("../compiler/middleware");

const PORT = parseInt(process.argv[2], 10) || 3100;

function createServer({ sessionStore = new SessionStore(), adaptive = new AdaptiveChallenge(new SessionStore(10_000, 60_000)), allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",").map(s => s.trim()) : [], rateLimit = {}, rateLimiter = new RateLimiter(rateLimit), passkeys = null } = {}) {
if (process.env.NODE_ENV === "production" && process.env.ATTESTATION_STATE_MODE !== "single-process" && !(sessionStore.distributed && adaptive.store.distributed && rateLimiter.distributed))
  throw new Error("Local state requires ATTESTATION_STATE_MODE=single-process; clustered deployment is unsupported");
const origins = new Set(allowedOrigins.map(value => { const origin = normalizeOrigin(value); if (!origin) throw new Error("invalid allowed origin"); return origin; }));
const collectorMiddleware = createMiddleware({ attestEndpoint: "/attest", sessionStore });

/* ------------------------------------------------------------------ */
/*  Safe IP extraction (Vuln 5 fix)                                    */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  Request body parser (JSON, capped at 64 KB)                        */
/* ------------------------------------------------------------------ */

function readBody(req, maxBytes = 65_536) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        req.destroy();
        reject(new Error("payload too large"));
      } else {
        chunks.push(chunk);
      }
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/* ------------------------------------------------------------------ */
/*  Route handlers                                                     */
/* ------------------------------------------------------------------ */

// POST /attest handler — mandatory ECDH decryption + server-verified PoW
const handleAttest = createDecryptHandler(sessionStore, async (telemetry, req, res, headerCheck, session) => {
  const key = getClientIP(req);
  const result = await adaptive.assess(telemetry, req, headerCheck, session, await rateLimiter.penalty(key));
  if (result.status === "passed") await rateLimiter.success(key);
  return json(res, 200, result);
}, (req) => rateLimiter.failure(getClientIP(req)));

async function handleChallenge(req, res) {
  try {
    const body = JSON.parse((await readBody(req)).toString("utf8"));
    const result = await adaptive.verify(body, req);
    await rateLimiter.success(getClientIP(req));
    return json(res, 200, result);
  } catch (_) {
    await rateLimiter.failure(getClientIP(req));
    return json(res, 403, { status: "failed", error: "Challenge failed or expired. Start again." });
  }
}

function handleVerify(req, res) {
  // Quick inline verification endpoint for integration tests.
  return readBody(req)
    .then((raw) => {
      const { token, action, minScore } = JSON.parse(raw.toString("utf-8"));
      const result = verifyToken(token, { clientIP: getClientIP(req), action, minScore, origin: requestOrigin(req), host: requestHostOrigin(req) });
      return json(res, result.valid ? 200 : 403, result);
    })
    .catch((err) => json(res, 400, { error: err.message }));
}

function handlePubkey(_req, res) {
  res.writeHead(200, {
    "Content-Type": "application/x-pem-file",
    "Cache-Control": "public, max-age=86400",
  });
  res.end(publicKeyPem);
}

function handleHealth(_req, res) {
  json(res, 200, { status: "ok", uptime: process.uptime() });
}

/* ------------------------------------------------------------------ */
/*  Router                                                             */
/* ------------------------------------------------------------------ */

const server = http.createServer(async (req, res) => {
  const origin = requestOrigin(req), host = requestHostOrigin(req);
  const crossSiteWithoutOrigin = req.headers.origin === undefined && req.headers["sec-fetch-site"] === "cross-site";
  if (!host || !origin || crossSiteWithoutOrigin || (origin !== host && !origins.has(origin)))
    return json(res, 403, { error: "Origin not allowed" });
  res.setHeader("Vary", "Origin");
  if (req.headers.origin !== undefined) res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Attestation-Token");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  const url = req.url?.split("?")[0];
  try {
  if (["/collector.js", "/attest", "/attest/verify-challenge"].includes(url) || url?.startsWith("/passkeys/")) {
    const limit = await rateLimiter.check(getClientIP(req));
    if (!limit.allowed) {
      res.setHeader("Retry-After", String(limit.retryAfter));
      return json(res, 429, { error: "Too many requests" });
    }
  }

    if (passkeys && url?.startsWith("/passkeys/") && req.method === "POST") {
      try { return json(res,200,await passkeys.handle(url.slice(10),JSON.parse((await readBody(req)).toString("utf8")),req)); }
      catch { return json(res,403,{error:"Passkey request failed"}); }
    }
    if (url === "/collector.js" && req.method === "GET") return await collectorMiddleware(req, res);
    if (url === "/attest/verify-challenge" && req.method === "POST") return await handleChallenge(req, res);
    if (url === "/attest" && req.method === "POST") return await handleAttest(req, res);

    if (url === "/pubkey" && req.method === "GET")  return handlePubkey(req, res);
    if (url === "/health" && req.method === "GET")  return handleHealth(req, res);

    json(res, 404, { error: "not found" });
  } catch (err) {
    console.error("[attestation] unhandled error:", err);
    json(res, 500, { error: "internal server error" });
  }
});

return server;
}
if (require.main === module) {
  createServer().listen(PORT, () => console.log(`[attestation] listening on :${PORT}`));
}
module.exports = { createServer };

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}
