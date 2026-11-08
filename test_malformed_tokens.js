"use strict";
const assert = require("node:assert/strict");
const http = require("node:http");
const { verifyToken, verifyTokenAsync, attestationMiddleware } = require("./attestation/verifier");
const { issueToken } = require("./attestation/token");
const policy = { action:"login", origin:"https://app.test", host:"https://app.test", clientIP:"127.0.0.1" };
(async()=>{
  const headers = [null, false, 42, "EdDSA", [], {},
    {alg:{toString:null,valueOf:null},typ:"ATT+JWT"},
    {alg:[{toString:{}}],typ:"ATT+JWT"},
    {alg:"EdDSA",typ:{toString:null}},
    {alg:"EdDSA",typ:"ATT+JWT"}];
  const tokens = headers.map(h=>Buffer.from(JSON.stringify(h)).toString("base64url")+".e30.AA");
  for (const token of tokens) {
    assert.equal(verifyToken(token,policy).valid,false);
    const result = await verifyTokenAsync(token,{...policy,nonceStore:{claim(){assert.fail("Malformed token reached replay store");}}});
    assert.equal(result.valid,false);
  }
  const original = issueToken({...policy,score:0.9,ipSubnet:"127.0.0.0/24"}).token;
  // Node's permissive base64 decoder previously accepted these aliases.
  for (const alias of [original+"!", original+"=", original+"\n"]) {
    assert.equal(verifyToken(alias,policy).valid,false,"Reject noncanonical signature encodings");
  }
  const middleware = attestationMiddleware(policy);
  const server = http.createServer((req,res)=>middleware(req,res,()=>{res.writeHead(200);res.end("allowed");}));
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  try {
    const base="http://127.0.0.1:"+server.address().port;
    for(const token of tokens) {
      const response=await fetch(base,{headers:{"x-attestation-token":token}});
      assert.equal(response.status,403);await response.text();
    }
    const response=await fetch(base,{headers:{"x-attestation-token":original}});
    assert.equal(response.status,200);assert.equal(await response.text(),"allowed");
  } finally { await new Promise(resolve=>server.close(resolve)); }
  console.log("Malformed token rejection and live middleware availability passed");
})().catch(error=>{console.error(error);process.exitCode=1;});
