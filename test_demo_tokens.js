"use strict";
const assert=require("node:assert/strict");
const {issueToken}=require("./attestation/token");
const {verifyToken,verifyTokenAsync,attestationMiddleware}=require("./attestation/verifier");
const policy={action:"login",origin:"https://app.test",host:"https://app.test",clientIP:"192.0.2.1"};
(async()=>{
 const {token}=issueToken({...policy,score:0.9,ipSubnet:"192.0.2.0/24",demo:true});
 assert.equal(verifyToken(token,policy).valid,false);
 const parts=token.split(".");
 const modified=JSON.parse(Buffer.from(parts[1],"base64url"));
 modified.demo=false;
 assert.equal(verifyToken(parts[0]+"."+Buffer.from(JSON.stringify(modified)).toString("base64url")+"."+parts[2],policy).valid,false);
 // Pre-upgrade tokens lack provenance and must not silently bypass the check.
 delete modified.demo;
 const legacyInput=parts[0]+"."+Buffer.from(JSON.stringify(modified)).toString("base64url");
 const legacy=legacyInput+"."+require("node:crypto").sign(null,Buffer.from(legacyInput),require("./attestation/keys").privateKey).toString("base64url");
 assert.equal(verifyToken(legacy,policy).valid,false);
 let claims=0;
 const nonceStore={claim:async()=>{claims++;return true;}};
 assert.equal((await verifyTokenAsync(token,{...policy,nonceStore})).valid,false);
 assert.equal(claims,0);
 let status;
 attestationMiddleware(policy)({headers:{"x-attestation-token":token},socket:{remoteAddress:policy.clientIP}},
  {writeHead(code){status=code;},end(){}},()=>assert.fail("Demo token reached protected route"));
 assert.equal(status,403);
 const previous=process.env.NODE_ENV, state=process.env.ATTESTATION_STATE_MODE;
 try {
  process.env.NODE_ENV="production";process.env.ATTESTATION_STATE_MODE="single-process";
  assert.equal(verifyToken(token,{...policy,allowInsecureDemo:true}).valid,false);
  assert.equal((await verifyTokenAsync(token,{...policy,nonceStore,allowInsecureDemo:true})).valid,false);
 } finally {
  if(previous===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=previous;
  if(state===undefined)delete process.env.ATTESTATION_STATE_MODE;else process.env.ATTESTATION_STATE_MODE=state;
 }
 assert.equal(verifyToken(token,{...policy,allowInsecureDemo:true}).valid,true);
 assert.equal(verifyToken(token,{...policy,allowInsecureDemo:true}).valid,false);
 const trusted=issueToken({...policy,score:0.9,ipSubnet:"192.0.2.0/24"});
 assert.equal(verifyToken(trusted.token,policy).valid,true);
 console.log("Demo puzzle tokens rejected by default, middleware and production verification");
})().catch(e=>{console.error(e);process.exitCode=1;});
