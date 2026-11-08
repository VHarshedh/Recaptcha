"use strict";
async function createRedisDeployment({url=process.env.REDIS_URL,encryptionKey,challengeSecret,rpID,origin}={}) {
  if (!url || !Buffer.isBuffer(challengeSecret) || challengeSecret.length!==32) throw new Error("Redis URL and shared 32-byte challenge secret required");
  if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== 32 || require("./origin").normalizeOrigin(origin) !== origin || !origin || new URL(origin).hostname !== rpID) throw new Error("Invalid deployment configuration");
  const {createClient}=require("redis");
  const client=createClient({url,disableOfflineQueue:true,socket:{connectTimeout:5000,reconnectStrategy:false}});
  client.on("error",()=>{});
  try {
  await client.connect();
  const policy=await client.configGet("maxmemory-policy");
  if (policy["maxmemory-policy"]!=="noeviction") { await client.quit(); throw new Error("Redis noeviction policy required for replay protection"); }
  const {RedisState}=require("./redis_state"),{RedisSessions,RedisRateLimiter}=require("./redis_adapters");
  const state=new RedisState(client,{encryptionKey});
  const {Passkeys}=require("./passkeys"),{AdaptiveChallenge}=require("./adaptive_challenge");
  const passkeys=new Passkeys({store:state,rpID,origin});
  const sessions=new RedisSessions(state);
  const adaptive=new AdaptiveChallenge(new RedisSessions(state,{namespace:"challenges",ttl:60000}),{secret:challengeSecret,authorize:()=>false});
  const server=require("./server").createServer({sessionStore:sessions,adaptive,rateLimiter:new RedisRateLimiter(state),passkeys});
  return {server,passkeys,nonceStore:state,close:async()=>{await new Promise(resolve=>server.close(resolve));await client.quit();}};
  } catch (error) { if (client.isOpen) client.destroy(); throw error; }
}
module.exports={createRedisDeployment};
