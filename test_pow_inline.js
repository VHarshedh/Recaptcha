"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const vm = require("node:vm");
const { verifyPoW, generateChallenge } = require("./pow_verifier");

async function main() {
  let blob, source, revoked = 0, terminated = 0;
  class Worker {
    constructor() {
      this.events = {};
      this.ready = blob.text().then(text => {
        source = text;
        const self = { addEventListener: (_type, fn) => { this.onWork = fn; },
          postMessage: data => { if (!this.stopped) this.events.message?.({ data }); } };
        vm.runInNewContext(text, { self, TextEncoder, performance });
      });
    }
    addEventListener(type, fn) { this.events[type] = fn; }
    terminate() { this.stopped = true; terminated++; }
    postMessage(data) { this.ready.then(() => { if (!this.stopped) this.onWork({ data }); }); }
  }
  const context = vm.createContext({ Worker, Blob, setTimeout, clearTimeout,
    URL: { createObjectURL(value) { blob = value; return "blob:test"; }, revokeObjectURL() { revoked++; } } });
  vm.runInContext(fs.readFileSync("pow_inline.js", "utf8"), context);
  const challenge = generateChallenge();
  const solution = await context.solvePoW({ challenge: challenge.challenge, difficulty: 8 });
  assert(verifyPoW({ ...challenge, difficulty: 8, nonce: solution.nonce }).valid);
  assert.equal(revoked, 1); assert.equal(terminated, 1);
  const hashing = vm.createContext({ TextEncoder, performance, self: { addEventListener() {} } });
  vm.runInContext(source, hashing);
  for (const text of ["", "abc", "a".repeat(55), "b".repeat(56), "c".repeat(64), "d".repeat(1000)]) {
    assert.equal(Buffer.from(hashing.sha256(Buffer.from(text))).toString("hex"), crypto.createHash("sha256").update(text).digest("hex"));
  }
  const controller = new AbortController();
  const pending = context.solvePoW({ challenge: challenge.challenge, difficulty: 22, signal: controller.signal });
  controller.abort(); await assert.rejects(pending, /cancelled/);
  assert.equal(revoked, 2); assert.equal(terminated, 2);
  context.Worker = class { addEventListener() {} terminate() { terminated++; } postMessage() {} };
  await assert.rejects(context.solvePoW({ challenge: challenge.challenge, difficulty: 22, timeoutMs: 1 }), /timeout/);
  assert.equal(revoked, 3); assert.equal(terminated, 3);
  context.Worker = class { constructor() { throw new Error("worker blocked"); } };
  await assert.rejects(context.solvePoW({ challenge: challenge.challenge, difficulty: 22 }), /blocked/);
  assert.equal(revoked, 4);
  console.log("Inline worker SHA-256 vectors, PoW verification, abort, timeout, and cleanup passed");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
