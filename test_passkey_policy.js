"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { encodeCBOR } = require("@levischuck/tiny-cbor");
const { Passkeys } = require("./attestation/passkeys");
const b64 = b => Buffer.from(b).toString("base64url");
const entries = new Map();
const store = {
  async put(k,v) { if(entries.has(k)) return false; entries.set(k,v); return true; },
  async get(k) { return entries.get(k); },
  async consume(k) { const v=entries.get(k); entries.delete(k); return v; },
  async update(k,p,n) { if(entries.get(k)?.revision!==p.revision) return false; entries.set(k,n); return true; },
};
const origin = "https://app.test";
const req = { headers:{host:"app.test",origin}, socket:{encrypted:true,remoteAddress:"192.0.2.1"} };
const service = new Passkeys({store,rpID:"app.test",origin});
const pair = crypto.generateKeyPairSync("ec",{namedCurve:"P-256"});
const jwk = pair.publicKey.export({format:"jwk"});
const cose = encodeCBOR(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,"base64url")],[-3,Buffer.from(jwk.y,"base64url")]]));
const rpHash = crypto.createHash("sha256").update("app.test").digest();
let counter = 0;
async function registration(extra={}) {
  const ticket = await service.enrollmentTicket("alice","Alice");
  const pending = await service.handle("register/options",{ticket},req);
  const credential = crypto.randomBytes(32), length = Buffer.alloc(2);
  length.writeUInt16BE(credential.length);
  const data = Buffer.from(JSON.stringify({type:"webauthn.create",challenge:pending.options.challenge,origin,...extra}));
  const auth = Buffer.concat([rpHash,Buffer.from([0x45]),Buffer.alloc(4),Buffer.alloc(16),length,credential,Buffer.from(cose)]);
  const response = {id:b64(credential),rawId:b64(credential),type:"public-key",clientExtensionResults:{},response:{clientDataJSON:b64(data),attestationObject:b64(encodeCBOR(new Map([["fmt","none"],["attStmt",new Map()],["authData",auth]])))}};
  return {id:pending.id,response};
}
async function authentication(credential, extra={}) {
  const pending = await service.handle("authenticate/options",{action:"login"},req);
  const data = Buffer.from(JSON.stringify({type:"webauthn.get",challenge:pending.options.challenge,origin,...extra}));
  const count = Buffer.alloc(4); count.writeUInt32BE(++counter);
  const auth = Buffer.concat([rpHash,Buffer.from([5]),count]);
  const signature = crypto.sign("sha256",Buffer.concat([auth,crypto.createHash("sha256").update(data).digest()]),pair.privateKey);
  return {id:pending.id,response:{id:credential,rawId:credential,type:"public-key",clientExtensionResults:{},response:{clientDataJSON:b64(data),authenticatorData:b64(auth),signature:b64(signature)}}};
}
(async()=>{
  const failures = [];
  async function rejects(label, operation, pattern) {
    try { await assert.rejects(operation,pattern); } catch(error) { failures.push(label+": "+error.message); }
  }
  const crossRegistration = await registration({crossOrigin:true});
  await rejects("Cross-origin registration",()=>service.handle("register/verify",crossRegistration,req),/Cross-origin/);
  const normal = await registration({crossOrigin:false});
  assert.deepEqual(await service.handle("register/verify",normal,req),{registered:true});
  for (const extra of [{crossOrigin:true},{crossOrigin:true,topOrigin:"https://evil.test"},{crossOrigin:"false"}]) {
    const body = await authentication(normal.response.id,extra);
    await rejects("Cross-origin authentication",()=>service.handle("authenticate/verify",body,req),/Cross-origin/);
  }
  const stale = await authentication(normal.response.id);
  service.actions.delete("login");
  await rejects("Removed action",()=>service.handle("authenticate/verify",stale,req),/Unsupported action/);
  service.actions.add("login");
  const valid = await authentication(normal.response.id,{crossOrigin:false});
  assert.equal((await service.handle("authenticate/verify",valid,req)).status,"passed");
  await assert.rejects(()=>service.handle("authenticate/verify",valid,req),/consumed challenge/);
  try { assert.throws(()=>new Passkeys({store,rpID:"app.test",origin:"http://app.test"}),/HTTPS/); }
  catch(error) { failures.push("Insecure origin: "+error.message); }
  new Passkeys({store,rpID:"localhost",origin:"http://localhost:3100"});
  new Passkeys({store,rpID:"app.test",origin:"https://app.test"});
  for (const actions of ["login", [], [""], [null]]) {
    assert.throws(()=>new Passkeys({store,rpID:"app.test",origin,actions}),/configuration/);
  }
  const oldEnv = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = "production";
    assert.throws(()=>new Passkeys({store,rpID:"localhost",origin:"http://localhost:3100"}),/HTTPS/);
  } finally {
    if (oldEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = oldEnv;
  }
  assert.equal(failures.length,0,failures.join("\n"));
  console.log("Passkey ceremony, current-action policy and secure-origin regressions passed");
})().catch(error=>{console.error(error);process.exitCode=1;});
