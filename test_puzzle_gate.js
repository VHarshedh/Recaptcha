"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Readable } = require("node:stream");
const { SessionStore, createDecryptHandler } = require("./compiler/middleware");
const { generateEphemeralKeyPair, deriveSessionKey } = require("./compiler/ecdh_session");
const { generateChallenge, verifyPoW } = require("./pow_verifier");
(async()=>{
  const store = new SessionStore();
  let invoked = 0, failures = 0, verified;
  const handler = createDecryptHandler(store, (data,_req,res)=>{
    invoked++; verified = data.pow.serverVerified; res.writeHead(200); res.end();
  },()=>{failures++;});
  async function submit(mode) {
    const kp = generateEphemeralKeyPair(), client = generateEphemeralKeyPair();
    const pow = {...generateChallenge(),difficulty:4};
    if (mode === "expired") pow.issuedAt -= 120000;
    store.set(kp.id,{keyPair:kp,expectedVmState:42,pow});
    let nonce=0;
    if (mode === "valid") while (!verifyPoW({...pow,nonce}).valid) nonce++;
    else while (verifyPoW({...pow,nonce}).valid) nonce++;
    const payload = {action:"login",pow:{challenge:pow.challenge,nonce,serverVerified:true,difficulty:0}};
    if(mode==="missing") delete payload.pow;
    if(mode==="foreign") payload.pow.challenge="different-challenge";
    const key=deriveSessionKey(crypto.diffieHellman({privateKey:client.privateKey,publicKey:kp.publicKey}),42);
    const iv=crypto.randomBytes(12), cipher=crypto.createCipheriv("aes-256-gcm",key,iv);
    const ct=Buffer.concat([cipher.update(JSON.stringify(payload)),cipher.final(),cipher.getAuthTag()]);
    const wire={sid:kp.id,cpk:client.publicKeyBase64,iv:iv.toString("base64"),ct:ct.toString("base64")};
    const req=Readable.from([Buffer.from(JSON.stringify(wire))]);
    req.headers={host:"app.test"};req.socket={remoteAddress:"192.0.2.1"};
    const res={status:0,writeHead(status){this.status=status;},end(){}};
    await handler(req,res);
    assert.equal(res.status,mode==="valid"?200:403,mode);
    assert.equal(store.consume(kp.id),null,"Every attempt consumes its session");
  }
  for(const mode of ["missing","invalid","foreign","expired"]) await submit(mode);
  assert.equal(invoked,0,"Unpaid work must never reach scoring/puzzle generation");
  assert.equal(failures,4);
  await submit("valid");assert.equal(invoked,1);assert.equal(verified,true);
  console.log("Mandatory work gate and consumed-session regressions passed");
})().catch(error=>{console.error(error);process.exitCode=1;});
