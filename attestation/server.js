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
const { maskIP, getClientIP } = require("./ip_mask");
const { publicKeyPem } = require("./keys");
const { createMiddleware, createDecryptHandler, SessionStore } = require("../compiler/middleware");

const PORT = parseInt(process.argv[2], 10) || 3100;

const sessionStore = new SessionStore();
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
const handleAttest = createDecryptHandler(sessionStore, (telemetry, req, res, headerCheck) => {
  const action = typeof telemetry.action === "string" && telemetry.action.length > 0
    ? telemetry.action
    : "unknown";

  const clientIP = getClientIP(req);
  const ipSubnet = maskIP(clientIP);

  const { score, breakdown, clamped, clampReason } = computeScore(telemetry, headerCheck);
  const { token, claims } = issueToken({ score, action, ipSubnet });

  return json(res, 200, {
    score,
    breakdown,
    clamped,
    clampReason,
    token,
    claims,
  });
});

function handleVerify(req, res) {
  // Quick inline verification endpoint for integration tests.
  return readBody(req)
    .then((raw) => {
      const { token, action, minScore } = JSON.parse(raw.toString("utf-8"));
      const result = verifyToken(token, { clientIP: getClientIP(req), action, minScore });
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
    if (url === "/collector.js" && req.method === "GET") return collectorMiddleware(req, res);
    if (url === "/attest" && req.method === "POST") return handleAttest(req, res);
    if (url === "/verify" && req.method === "POST") return handleVerify(req, res);
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
