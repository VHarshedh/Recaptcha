"use strict";
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { hashPoW } = require("./pow_verifier");
const { issueToken } = require("./attestation/token");
const { verifyToken } = require("./attestation/verifier");
const { requestHostOrigin } = require("./attestation/origin");
const { extractStrings, replaceStrings, buildStringTable, generateDecoderSource } = require("./compiler/string_table");
const vm = require("node:vm");
const policy = { action: "login", origin: "https://app.test", host: "https://app.test", clientIP: "192.0.2.3" };
const token = issueToken({ ...policy, ipSubnet: "192.0.2.0/24", score: 0.9 }).token;
assert(!verifyToken(token, { ...policy, action: "other" }).valid);
assert(!verifyToken(token, { ...policy, clientIP: "invalid" }).valid);
assert(verifyToken(token, policy).valid);
assert(!verifyToken(token, policy).valid);
const old = process.env.TRUST_PROXY;
try {
  const req = { headers: { host: "app.test", "x-forwarded-proto": "https" }, socket: {} };
  delete process.env.TRUST_PROXY; assert.equal(requestHostOrigin(req), "http://app.test");
  process.env.TRUST_PROXY="1"; assert.equal(requestHostOrigin(req), "https://app.test");
  req.headers["x-forwarded-proto"]="https,http"; assert.equal(requestHostOrigin(req), "");
} finally { if (old === undefined) delete process.env.TRUST_PROXY; else process.env.TRUST_PROXY=old; }
const source = 'var result = /"quoted"/.test("no") ? "bad" : "日本語😀";';
const strings = extractStrings(source), key=[17,29];
const compiled=generateDecoderSource('table','key','decode',buildStringTable(strings,key),key)+replaceStrings(source,strings,'decode');
assert.equal(vm.runInNewContext(compiled+'result'), "日本語😀");
for (const nonce of [0, 4294967297, Number.MAX_SAFE_INTEGER]) {
  const challenge = Date.now()+".parity";
  const result=spawnSync('python',['-c','import json,sys; from pow_verifier import verify_pow; print(json.dumps(verify_pow(sys.argv[1],int(sys.argv[2]),1,int(sys.argv[1].split(".")[0]))))',challenge,String(nonce)],{encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  assert.equal(JSON.parse(result.stdout).hash,hashPoW(challenge,nonce).toString('hex'));
}
const invalid=spawnSync('python',['-c','from pow_verifier import verify_pow; assert not verify_pow("x",10**5000,1,0)["valid"]; assert not verify_pow("x",True,1,0)["valid"]'],{encoding:'utf8'});
assert.equal(invalid.status,0,invalid.stderr);
console.log("Report regressions passed: policy/replay, proxy trust, Unicode/regex, Python parity and bounds");
