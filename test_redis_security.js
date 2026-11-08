"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createClient } = require("redis");
const { RedisState } = require("./attestation/redis_state");
(async () => {
  assert(process.env.TEST_REDIS_URL, "Dedicated TEST_REDIS_URL required");
  const client = createClient({ url: process.env.TEST_REDIS_URL });
  await client.connect();
  const prefix = "security-test:" + crypto.randomUUID() + ":";
  const state = new RedisState(client, { prefix, encryptionKey: crypto.randomBytes(32) });
  const keys = ["credential:a", "credential:b", "expiry"].map(k => state.name(k));
  const failures = [];
  try {
    await state.put("credential:a", { revision: 0, user: "a" }, 60000);
    await client.set(state.name("credential:b"), await client.get(state.name("credential:a")));
    try { await assert.rejects(() => state.get("credential:b")); }
    catch (error) { failures.push("Record transplant accepted: " + error.message); }
    await state.put("expiry", { revision: 0 }, 5000);
    const before = await client.pTTL(state.name("expiry"));
    assert(await state.update("expiry", { revision: 0 }, { revision: 1 }));
    const after = await client.pTTL(state.name("expiry"));
    if (!(after > 0 && after <= before)) failures.push("Credential lifetime extended: " + after);
    assert.equal(failures.length, 0, failures.join("\n"));
    assert.deepEqual(await state.consume("expiry"), { revision: 1 });
    assert.equal(await state.consume("expiry"), null);
    console.log("Redis record binding and credential expiration regressions passed");
  } finally { await client.del(keys); await client.quit(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
