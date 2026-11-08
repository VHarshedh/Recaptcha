"use strict";
const assert = require("node:assert/strict");
const { Passkeys } = require("./attestation/passkeys");
const entries = new Map();
const store = {
  async put(k, v) { if (entries.has(k)) return false; entries.set(k, v); return true; },
  async get(k) { return entries.get(k); },
  async consume(k) { const v = entries.get(k); entries.delete(k); return v; },
};
const req = host => ({ headers: { host, origin: "https://" + host }, socket: { encrypted: true, remoteAddress: "192.0.2.1" } });
(async () => {
  const a = new Passkeys({ store, rpID: "a.test", origin: "https://a.test" });
  const b = new Passkeys({ store, rpID: "b.test", origin: "https://b.test" });
  const ticket = await a.enrollmentTicket("alice", "Alice");
  await assert.rejects(() => b.handle("register/options", { ticket }, req("b.test")), /provisioning ticket/);
  // A foreign request must not consume the owning site's ticket.
  assert((await a.handle("register/options", { ticket }, req("a.test"))).options);
  const sibling = new Passkeys({ store, rpID: "a.test", origin: "https://a.test:8443" });
  const ticket2 = await a.enrollmentTicket("alice", "Alice");
  await assert.rejects(() => sibling.handle("register/options", { ticket: ticket2 }, req("a.test:8443")), /provisioning ticket/);
  const replica = new Passkeys({ store, rpID: "a.test", origin: "https://a.test" });
  assert((await replica.handle("register/options", { ticket: ticket2 }, req("a.test"))).options);
  console.log("Passkey enrollment isolation across relying parties and origins passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
