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
const { computeScore } = require("./scorer");
const { issueToken } = require("./token");
const { verifyToken } = require("./verifier");
const { maskIP } = require("./ip_mask");
const { publicKeyPem } = require("./keys");

const PORT = parseInt(process.argv[2], 10) || 3100;

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

async function handleAttest(req, res) {
  // ── Parse body ────────────────────────────────────────────────────
  let body;
  try {
    const raw = await readBody(req);
    body = JSON.parse(raw.toString("utf-8"));
  } catch (err) {
    return json(res, 400, { error: "invalid JSON", detail: err.message });
  }

  if (!body || typeof body !== "object") {
    return json(res, 400, { error: "request body must be a JSON object" });
  }

  // ── Extract action ───────────────────────────────────────────────
  const action = typeof body.action === "string" && body.action.length > 0
    ? body.action
    : "unknown";

  // ── Determine client subnet ──────────────────────────────────────
  const clientIP =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    "unknown";
  const ipSubnet = maskIP(clientIP);

  // ── Score ─────────────────────────────────────────────────────────
  const { score, breakdown, clamped, clampReason } = computeScore(body);

  // ── Issue token ───────────────────────────────────────────────────
  const { token, claims } = issueToken({ score, action, ipSubnet });

  return json(res, 200, {
    score,
    breakdown,
    clamped,
    clampReason,
    token,
    claims,
  });
}

function handleVerify(req, res) {
  // Quick inline verification endpoint for integration tests.
  return readBody(req)
    .then((raw) => {
      const { token, clientIP, action, minScore } = JSON.parse(raw.toString("utf-8"));
      const result = verifyToken(token, { clientIP, action, minScore });
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
  // CORS (permissive for dev — tighten in production).
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Attestation-Token");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  const url = req.url?.split("?")[0];

  try {
    if (url === "/attest" && req.method === "POST") return await handleAttest(req, res);
    if (url === "/verify" && req.method === "POST") return await handleVerify(req, res);
    if (url === "/pubkey" && req.method === "GET")  return handlePubkey(req, res);
    if (url === "/health" && req.method === "GET")  return handleHealth(req, res);

    json(res, 404, { error: "not found" });
  } catch (err) {
    console.error("[attestation] unhandled error:", err);
    json(res, 500, { error: "internal server error" });
  }
});

server.listen(PORT, () => {
  console.log(`[attestation] listening on :${PORT}`);
  console.log(`[attestation] endpoints: POST /attest, POST /verify, GET /pubkey, GET /health`);
});

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}
