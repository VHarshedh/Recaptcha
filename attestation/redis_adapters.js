"use strict";
const crypto=require("node:crypto");
class RedisSessions {
  constructor(state,{namespace="sessions",ttl=300000,maxPerIP=15}={}) {
    for (const n of [ttl,maxPerIP]) if (!Number.isSafeInteger(n) || n < 1) throw new Error("Invalid session limit");
    Object.assign(this,{state,namespace,ttl,maxPerIP}); this.distributed=true;
  }
  quota(ip) { return this.state.name(this.namespace+":quota:"+ip); }
  async canAccept(ip) {
    return Number(await this.state.client.zCount(this.quota(ip), Date.now()+1, "+inf")) < this.maxPerIP;
  }
  async set(id,data) {
    const ip=data.ipSubnet || data.headerProfile?.clientIP || "unknown";
    const keyPair={...data.keyPair,privateKey:data.keyPair.privateKey.export({type:"pkcs8",format:"der"}),publicKey:null};
    const key=this.state.name(this.namespace+":"+id), quota=this.quota(ip);
    const raw=this.state.seal({...data,keyPair,quota}, key);
    return Number(await this.state.client.eval('local t=redis.call("TIME"); local now=t[1]*1000+math.floor(t[2]/1000); redis.call("ZREMRANGEBYSCORE",KEYS[2],"-inf",now); if redis.call("EXISTS",KEYS[1])==1 or redis.call("ZCARD",KEYS[2])>=tonumber(ARGV[3]) then return 0 end; redis.call("SET",KEYS[1],ARGV[1],"PX",ARGV[2]); redis.call("ZADD",KEYS[2],now+tonumber(ARGV[2]),KEYS[1]); redis.call("PEXPIRE",KEYS[2],ARGV[2]); return 1', {keys:[key,quota],arguments:[raw,String(this.ttl),String(this.maxPerIP)]}))===1;
  }
  async consume(id) {
    if(typeof id!=="string" || id.length>128) return null;
    const key=this.state.name(this.namespace+":"+id);
    const raw=await this.state.client.get(key);
    if(!raw) return null;
    const entry=this.state.open(raw, key);
    const taken=await this.state.client.eval('if redis.call("GET",KEYS[1])~=ARGV[1] then return 0 end; redis.call("DEL",KEYS[1]); redis.call("ZREM",KEYS[2],KEYS[1]); return 1',{keys:[key,entry.quota],arguments:[raw]});
    if(Number(taken)!==1) return null;
    entry.keyPair.privateKey=crypto.createPrivateKey({key:entry.keyPair.privateKey,type:"pkcs8",format:"der"});
    return entry;
  }
}

class RedisRateLimiter {
  constructor(state,{maxRequests=30,windowMs=60000}={}) { for (const n of [maxRequests,windowMs]) if (!Number.isSafeInteger(n) || n < 1) throw new Error("Invalid rate limit");Object.assign(this,{state,maxRequests,windowMs});this.distributed=true;}
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
