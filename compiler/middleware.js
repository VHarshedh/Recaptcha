/**
 * middleware.js — HTTP Middleware for Serving Polymorphic Bundles
 *
 * On every GET request to the collector endpoint, generates a fresh
 * polymorphic build and streams it with strict no-cache headers.
 *
 * Usage (standalone):
 *   node compiler/middleware.js [port]
 *
 * Usage (as middleware):
 *   const { createMiddleware } = require("./middleware");
 *   app.get("/collector.js", createMiddleware({ attestEndpoint: "/attest" }));
 *
 * The middleware also stores ECDH key pairs indexed by session ID
 * so the attestation endpoint can decrypt incoming telemetry.
 */

"use strict";

const http = require("node:http");
const { compile } = require("./pipeline");
const { decryptTelemetry } = require("./ecdh_session");
const { generateChallenge, verifyPoW } = require("../pow_verifier");

/* ------------------------------------------------------------------ */
/*  ECDH session store (in-memory, keyed by session ID)                */
/* ------------------------------------------------------------------ */

class SessionStore {
  /**
   * @param {number} maxSize — maximum stored sessions
   * @param {number} ttlMs  — session lifetime in ms
   */
  constructor(maxSize = 10_000, ttlMs = 300_000) {
    this._map     = new Map();
    this._maxSize = maxSize;
    this._ttlMs   = ttlMs;
  }

  /** Store a session's ECDH key pair and PoW challenge. */
  set(sessionId, data) {
    // Evict oldest if at capacity.
    if (this._map.size >= this._maxSize) {
      const oldest = this._map.keys().next().value;
      this._map.delete(oldest);
    }
    const entry = (data && data.keyPair) ? data : { keyPair: data };
    this._map.set(sessionId, {
      ...entry,
      createdAt: Date.now(),
    });
  }

  /** Retrieve and consume a session (one-time use). */
  consume(sessionId) {
    const entry = this._map.get(sessionId);
    if (!entry) return null;
    this._map.delete(sessionId);
    if (Date.now() - entry.createdAt > this._ttlMs) return null;
    if (entry.keyPair) {
      return Object.assign(Object.create(entry.keyPair), entry);
    }
    return entry;
  }

  get size() { return this._map.size; }
}

/* ------------------------------------------------------------------ */
/*  Middleware factory                                                  */
/* ------------------------------------------------------------------ */

/**
 * Create an HTTP handler that serves a unique polymorphic bundle
 * on every request.
 *
 * @param {Object}  [opts]
 * @param {string}  [opts.attestEndpoint="/attest"]
 * @param {number}  [opts.deadCodeBlocks=8]
 * @param {SessionStore} [opts.sessionStore]
 * @returns {Function} (req, res, next?) => void
 */
function createMiddleware(opts = {}) {
  const {
    attestEndpoint = "/attest",
    deadCodeBlocks = 8,
    sessionStore   = new SessionStore(),
  } = opts;

  function handler(req, res, next) {
    try {
      const { challenge, issuedAt } = generateChallenge();
      const difficulty = 16;

      const { bundle, buildId, ecdhKeyPair, stats } = compile({
        attestEndpoint,
        deadCodeBlocks,
        powChallenge: challenge,
        powDifficulty: difficulty,
      });

      // Store session for later telemetry decryption and PoW verification.
      if (ecdhKeyPair) {
        sessionStore.set(ecdhKeyPair.id, {
          keyPair: ecdhKeyPair,
          pow: { challenge, difficulty, issuedAt },
        });
      }

      // Strict no-cache, no-store.
      res.writeHead(200, {
        "Content-Type":  "application/javascript; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
        "Pragma":        "no-cache",
        "Expires":       "0",
        "X-Build-Id":    buildId,
        "X-Content-Length": String(Buffer.byteLength(bundle)),
        "Content-Length":   String(Buffer.byteLength(bundle)),
      });
      res.end(bundle);

      console.log(
        `[compiler] build=${buildId} strings=${stats.strings} ` +
        `ids=${stats.identifiers} dead=${stats.deadBlocks} ` +
        `bytes=${stats.bytes}`
      );
    } catch (err) {
      console.error("[compiler] compilation failed:", err);
      if (typeof next === "function") return next(err);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "compilation failed" }));
    }
  }

  // Expose the session store so the attestation route can decrypt.
  handler.sessionStore = sessionStore;

  return handler;
}

/* ------------------------------------------------------------------ */
/*  Telemetry decryption endpoint handler                              */
/* ------------------------------------------------------------------ */

/**
 * Create a handler for POST /attest that decrypts the ECDH-encrypted
 * telemetry and forwards the plaintext to the scoring pipeline.
 *
 * Enforces mandatory ECDH encryption (rejects plaintext payloads with 403)
 * and cryptographically verifies the server-issued PoW challenge.
 *
 * @param {SessionStore} sessionStore
 * @param {Function}     onTelemetry — callback(plaintext, req, res)
 * @returns {Function}   (req, res) => void
 */
function createDecryptHandler(sessionStore, onTelemetry) {
  return async function decryptHandler(req, res) {
    try {
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 65_536) {
          res.writeHead(413);
          return res.end();
        }
        chunks.push(chunk);
      }

      let body;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf-8"));
      } catch (parseErr) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "invalid JSON" }));
      }

      // Mandatory ECDH — reject plaintext or missing crypto envelope
      if (!body || !body.cpk || !body.iv || !body.ct || !body.sid) {
        res.writeHead(403, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "missing or invalid encrypted payload envelope" }));
      }

      const session = sessionStore.consume(body.sid);
      if (!session) {
        res.writeHead(403, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "unknown or expired session" }));
      }

      const keyPair = session.keyPair || session;
      const plaintext = decryptTelemetry(body, keyPair.privateKey);

      // Cryptographically verify PoW challenge server-side
      const clientPoW = plaintext.pow || {};
      const expectedChallenge = session.pow?.challenge;
      const expectedDifficulty = session.pow?.difficulty || 16;
      const issuedAt = session.pow?.issuedAt ||
        (expectedChallenge ? parseInt(expectedChallenge.split(".")[0], 10) : Date.now());

      let powVerification = { valid: false, reason: "challenge mismatch" };
      if (expectedChallenge && clientPoW.challenge === expectedChallenge) {
        powVerification = verifyPoW({
          challenge: expectedChallenge,
          nonce: clientPoW.nonce,
          difficulty: expectedDifficulty,
          issuedAt: issuedAt,
        });
      }

      // Overwrite client-reported PoW with server's verification
      plaintext.pow = {
        serverVerified: powVerification.valid,
        difficulty: expectedDifficulty,
        durationMs: clientPoW.durationMs,
        hash: powVerification.hash,
        reason: powVerification.reason,
      };

      return onTelemetry(plaintext, req, res);
    } catch (err) {
      console.error("[attest] decrypt error:", err.message);
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid payload" }));
    }
  };
}

/* ------------------------------------------------------------------ */
/*  Standalone server (for testing / demo)                             */
/* ------------------------------------------------------------------ */

if (require.main === module) {
  const PORT = parseInt(process.argv[2], 10) || 3200;

  const collectorMiddleware = createMiddleware();

  // Wire up the attestation endpoint.
  const decryptHandler = createDecryptHandler(
    collectorMiddleware.sessionStore,
    (telemetry, _req, res) => {
      // In production, pipe through scorer + token issuer here.
      console.log("[attest] received telemetry:", JSON.stringify(telemetry).slice(0, 200));
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ received: true, keys: Object.keys(telemetry) }));
    },
  );

  const server = http.createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

    const url = req.url?.split("?")[0];

    if (url === "/collector.js" && req.method === "GET") {
      return collectorMiddleware(req, res);
    }
    if (url === "/attest" && req.method === "POST") {
      return decryptHandler(req, res);
    }
    if (url === "/" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end(`<!DOCTYPE html><html><head><title>PolyMorph Demo</title></head>
<body><h3>Polymorphic Collector Demo</h3>
<p>Open DevTools Network tab, then reload to see a unique bundle each time.</p>
<script src="/collector.js"><\/script></body></html>`);
    }

    res.writeHead(404);
    res.end("not found");
  });

  server.listen(PORT, () => {
    console.log(`[compiler] polymorphic server on :${PORT}`);
    console.log(`  GET  /collector.js  — unique obfuscated bundle per request`);
    console.log(`  POST /attest        — ECDH-decrypted telemetry receiver`);
    console.log(`  GET  /              — demo page`);
  });
}

/* ------------------------------------------------------------------ */

module.exports = {
  createMiddleware,
  createDecryptHandler,
  SessionStore,
};
