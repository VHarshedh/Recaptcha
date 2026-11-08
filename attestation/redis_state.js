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
  seal(value, name) {
    if (typeof name !== "string" || !name) throw new Error("State record name required");
    const iv=crypto.randomBytes(12), cipher=crypto.createCipheriv("aes-256-gcm",this.key,iv);
    cipher.setAAD(Buffer.from(name));
    const bytes=Buffer.concat([cipher.update(require("node:v8").serialize(value)),cipher.final()]);
    return Buffer.concat([iv,cipher.getAuthTag(),bytes]).toString("base64");
  }
  open(raw, name) {
    if (!raw) return null;
    if (typeof name !== "string" || !name) throw new Error("State record name required");
    const b=Buffer.from(raw,"base64"), d=crypto.createDecipheriv("aes-256-gcm",this.key,b.subarray(0,12));
    d.setAAD(Buffer.from(name));
    d.setAuthTag(b.subarray(12,28));
    return require("node:v8").deserialize(Buffer.concat([d.update(b.subarray(28)),d.final()]));
  }
  async get(key) { return this.open(await this.client.get(this.name(key)), this.name(key)); }
  async put(key,value,ttl=300000) { return (await this.client.set(this.name(key),this.seal(value, this.name(key)),{PX:ttl,NX:true})) === "OK"; }
  async consume(key) { return this.open(await this.client.getDel(this.name(key)), this.name(key)); }
  async claim(key,ttl=120000) { return (await this.client.set(this.name("nonce:"+key),"1",{PX:ttl,NX:true})) === "OK"; }
  async update(key, previous, next, ttl) {
    // Compare decoded version using an explicit revision, then compare the raw
    // encrypted value in Lua so concurrent authentications cannot lose updates.
    const name=this.name(key), raw=await this.client.get(name);
    if (!raw || this.open(raw, name).revision !== previous.revision) return false;
    return Number(await this.client.eval('if redis.call("GET",KEYS[1]) == ARGV[1] then if ARGV[3] == "" then redis.call("SET",KEYS[1],ARGV[2],"KEEPTTL") else redis.call("SET",KEYS[1],ARGV[2],"PX",ARGV[3]) end; return 1 end; return 0', {keys:[name],arguments:[raw,this.seal(next, name),ttl === undefined ? "" : String(ttl)]}))===1;
  }
}
module.exports={RedisState};
