"use strict";
const crypto = require("node:crypto");
// Redis must use a dedicated namespace and a noeviction policy: evicting used
// nonces can permit replay. The client is supplied by the application.
class RedisState {
  constructor(client, { prefix = "attestation:", encryptionKey } = {}) {
    if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== 32) throw new Error("32-byte state encryption key required");
    this.client=client; this.prefix=prefix; this.key=encryptionKey;
  }
  name(key) { return this.prefix + crypto.createHash("sha256").update(key).digest("hex"); }
  seal(value) {
    const iv=crypto.randomBytes(12), cipher=crypto.createCipheriv("aes-256-gcm",this.key,iv);
    const bytes=Buffer.concat([cipher.update(require("node:v8").serialize(value)),cipher.final()]);
    return Buffer.concat([iv,cipher.getAuthTag(),bytes]).toString("base64");
  }
  open(raw) {
    if (!raw) return null;
    const b=Buffer.from(raw,"base64"), d=crypto.createDecipheriv("aes-256-gcm",this.key,b.subarray(0,12));
    d.setAuthTag(b.subarray(12,28));
    return require("node:v8").deserialize(Buffer.concat([d.update(b.subarray(28)),d.final()]));
  }
  async get(key) { return this.open(await this.client.get(this.name(key))); }
  async put(key,value,ttl=300000) { return (await this.client.set(this.name(key),this.seal(value),{PX:ttl,NX:true})) === "OK"; }
  async consume(key) { return this.open(await this.client.getDel(this.name(key))); }
  async claim(key,ttl=120000) { return (await this.client.set(this.name("nonce:"+key),"1",{PX:ttl,NX:true})) === "OK"; }
  async update(key, previous, next, ttl=31536000000) {
    // Compare decoded version using an explicit revision, then compare the raw
    // encrypted value in Lua so concurrent authentications cannot lose updates.
    const name=this.name(key), raw=await this.client.get(name);
    if (!raw || this.open(raw).revision !== previous.revision) return false;
    return Number(await this.client.eval('if redis.call("GET",KEYS[1]) == ARGV[1] then redis.call("SET",KEYS[1],ARGV[2],"PX",ARGV[3]); return 1 end; return 0', {keys:[name],arguments:[raw,this.seal(next),String(ttl)]}))===1;
  }
}
module.exports={RedisState};
