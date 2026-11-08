"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto");
const {createClient}=require("redis"),{RedisState}=require("./attestation/redis_state"),{RedisSessions}=require("./attestation/redis_adapters");
const {generateEphemeralKeyPair}=require("./compiler/ecdh_session");
const {issueToken}=require("./attestation/token"),{verifyTokenAsync}=require("./attestation/verifier");
(async()=>{
 if(!process.env.TEST_REDIS_URL) throw new Error("Set TEST_REDIS_URL to a dedicated test Redis instance");
 const clients=[createClient({url:process.env.TEST_REDIS_URL}),createClient({url:process.env.TEST_REDIS_URL})];
 clients.forEach(c=>c.on("error",()=>{}));
 await Promise.all(clients.map(c=>c.connect()));
 try {
  const encryptionKey=crypto.randomBytes(32),prefix="test:"+crypto.randomUUID()+":";
  const states=clients.map(c=>new RedisState(c,{prefix,encryptionKey}));
  const stores=states.map(s=>new RedisSessions(s));
  const limited=states.map(s=>new RedisSessions(s,{namespace:"quota-test",maxPerIP:1,ttl:1000}));
  assert(await limited[0].canAccept("test-ip")); assert(await limited[0].canAccept("test-ip"));
  const attempts=await Promise.all(limited.map((s,i)=>s.set("race"+i,{keyPair:generateEphemeralKeyPair(),headerProfile:{clientIP:"test-ip"}})));
  assert.equal(attempts.filter(Boolean).length,1);
  assert.equal(await limited[0].canAccept("test-ip"),false);
  await limited[1].consume("race"+attempts.indexOf(true));
  assert(await limited[0].canAccept("test-ip"));
  const kp=generateEphemeralKeyPair();
  assert(await stores[0].set(kp.id,{keyPair:kp,expectedVmState:42}));
  const results=await Promise.all(stores.map(s=>s.consume(kp.id)));
  assert.equal(results.filter(Boolean).length,1);
  assert.equal(results.find(Boolean).keyPair.privateKey.asymmetricKeyType,"ec");
  const policy={action:"login",origin:"https://app.test",host:"https://app.test",clientIP:"192.0.2.1"};
  const token=issueToken({...policy,ipSubnet:"192.0.2.0/24",score:0.9}).token;
  const verified=await Promise.all(states.map(nonceStore=>verifyTokenAsync(token,{...policy,nonceStore})));
  assert.equal(verified.filter(r=>r.valid).length,1);
  await states[0].put("expiry",{test:true},20);
  await new Promise(r=>setTimeout(r,40));assert.equal(await states[1].consume("expiry"),null);
  await states[0].put("counter",{revision:0},1000);
  const updates=await Promise.all(states.map(s=>s.update("counter",{revision:0},{revision:1},1000)));
  assert.equal(updates.filter(Boolean).length,1);
  console.log("Live Redis cross-client session consumption, nonce races, TTL and CAS passed");
 } finally {await Promise.all(clients.map(c=>c.quit()));}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
