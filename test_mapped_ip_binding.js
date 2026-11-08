"use strict";
const assert=require("node:assert/strict");
const {maskIP}=require("./attestation/ip_mask");
const {issueToken}=require("./attestation/token");
const {verifyToken}=require("./attestation/verifier");
for(const address of ["192.0.2.1","::ffff:192.0.2.1","::ffff:c000:201","0:0:0:0:0:FFFF:C000:0201","[::ffff:c000:201]:443"])
 assert.equal(maskIP(address),"192.0.2.0/24",address);
assert.equal(maskIP("::ffff:c633:6401"),"198.51.100.0/24");
// IPv4-compatible IPv6 is not IPv4-mapped and keeps the existing IPv6 policy.
assert.equal(maskIP("2001:db8::1"),"2001:0db8:0000::/48");
const policy={action:"login",origin:"https://app.test",host:"https://app.test"};
const {token}=issueToken({...policy,score:0.9,ipSubnet:maskIP("::ffff:c000:201")});
assert.equal(verifyToken(token,{...policy,clientIP:"::ffff:c633:6401"}).valid,false);
assert.equal(verifyToken(token,{...policy,clientIP:"::ffff:c000:2fe"}).valid,true);
assert.equal(verifyToken(token,{...policy,clientIP:"192.0.2.1"}).valid,false,"Representation changes must not bypass replay checking");
console.log("IPv4-mapped IPv6 subnet isolation and equivalent-address replay checks passed");
