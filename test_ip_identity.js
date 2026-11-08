"use strict";
const assert=require("node:assert/strict");
const {getClientIP,maskIP,normalizeIP}=require("./attestation/ip_mask");
const {RateLimiter}=require("./attestation/rate_limiter");
const {SessionStore}=require("./compiler/middleware");
const previous=process.env.TRUST_PROXY;
try {
 process.env.TRUST_PROXY="1";
 const request=ip=>({headers:{"x-forwarded-for":ip},socket:{remoteAddress:"10.0.0.1"}});
 for(const addresses of [["2001:db8::1","2001:0DB8:0:0:0:0:0:1"],["192.0.2.1","::ffff:192.0.2.1","::ffff:c000:201","0:0:0:0:0:ffff:192.0.2.1"]]){
  const limiter=new RateLimiter({maxRequests:1});
  const sessions=new SessionStore(10,60000,1);
  const identity=getClientIP(request(addresses[0]));
  assert(limiter.check(identity).allowed);assert(sessions.set("one",{keyPair:{},headerProfile:{clientIP:identity}}));
  for(const address of addresses.slice(1)){
   const alias=getClientIP(request(address));assert.equal(alias,identity,address);
   assert.equal(limiter.check(alias).allowed,false);assert.equal(sessions.canAccept(alias),false);
  }
 }
 assert.equal(maskIP("0:0:0:0:0:ffff:192.0.2.1"),"192.0.2.0/24");
 assert.equal(maskIP("2001:db8::192.0.2.1"),"2001:0db8:0000::/48");
 for(const invalid of ["invalid","192.0.2.1:443","","example.com",["192.0.2.1"],"2001:db8::1%"])
  assert.equal(getClientIP(request(invalid)),"unknown");
 assert.equal(normalizeIP("fe80::1%eth0"),"fe80:0000:0000:0000:0000:0000:0000:0001");
 delete process.env.TRUST_PROXY;
 assert.equal(getClientIP(request("198.51.100.1")),"10.0.0.1");
 assert.equal(getClientIP({socket:{remoteAddress:"::ffff:192.0.2.1"}}),"192.0.2.1");
 console.log("Canonical IP rate-limit/session identities and mixed IPv6 extraction passed");
}finally{if(previous===undefined)delete process.env.TRUST_PROXY;else process.env.TRUST_PROXY=previous;}
