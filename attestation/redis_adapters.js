"use strict";
const crypto=require("node:crypto");
class RedisSessions {
  constructor(state,{namespace="sessions",ttl=300000,maxPerIP=15}={}) { Object.assign(this,{state,namespace,ttl,maxPerIP}); this.distributed=true; }
  async canAccept(ip) {
    const key=this.state.name(this.namespace+":quota:"+ip);
    const n=await this.state.client.eval('local n=redis.call("INCR",KEYS[1]); if n==1 then redis.call("PEXPIRE",KEYS[1],ARGV[1]) end; return n',{keys:[key],arguments:[String(this.ttl)]});
    return n<=this.maxPerIP;
  }
  async set(id,data) {
    const keyPair={...data.keyPair,privateKey:data.keyPair.privateKey.export({type:"pkcs8",format:"der"}),publicKey:null};
    return this.state.put(this.namespace+":"+id,{...data,keyPair},this.ttl);
  }
  async consume(id) {
    if(typeof id!=="string" || id.length>128) return null;
    const entry=await this.state.consume(this.namespace+":"+id);
    if(entry) entry.keyPair.privateKey=crypto.createPrivateKey({key:entry.keyPair.privateKey,type:"pkcs8",format:"der"});
    return entry;
  }
}
class RedisRateLimiter {
  constructor(state,{maxRequests=30,windowMs=60000}={}) {Object.assign(this,{state,maxRequests,windowMs});this.distributed=true;}
  async check(ip) {
    const key=this.state.name("rate:"+ip);
    const result=await this.state.client.eval('local n=redis.call("INCR",KEYS[1]); if n==1 then redis.call("PEXPIRE",KEYS[1],ARGV[1]) end; return {n,redis.call("PTTL",KEYS[1])}',{keys:[key],arguments:[String(this.windowMs)]});
    return {allowed:result[0]<=this.maxRequests,retryAfter:Math.max(1,Math.ceil(result[1]/1000))};
  }
  async failure(ip) {await this.state.client.set(this.state.name("reputation:"+ip),"1",{PX:60000});}
  async penalty(ip) {return await this.state.client.get(this.state.name("reputation:"+ip)) ? 0.5 : 0;}
  async success() {}
}
module.exports={RedisSessions,RedisRateLimiter};
