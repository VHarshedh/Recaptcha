"use strict";
const crypto = require("node:crypto");
const webauthn = require("@simplewebauthn/server");
const { issueToken } = require("./token");
const { maskIP, getClientIP } = require("./ip_mask");
const { requestOrigin, requestHostOrigin, normalizeOrigin } = require("./origin");
class Passkeys {
  constructor({ store, rpID, origin, rpName = "Attestation", actions = ["login"] }) {
    if (!store || normalizeOrigin(origin)!==origin || new URL(origin).hostname!==rpID || !actions.length) throw new Error("Invalid passkey configuration");
    Object.assign(this,{store,rpID,origin,rpName,actions:new Set(actions)});
    // Shared Redis may serve multiple relying parties. Scope tickets, pending
    // challenges and credentials alike; client-provided IDs cannot select scope.
    this.namespace = "passkeys:v2:" + crypto.createHash("sha256")
      .update(JSON.stringify([rpID, origin])).digest("hex") + ":";
  }
  // Trusted provisioning API only. Never expose this as an unauthenticated route.
  async enrollmentTicket(userID, userName) {
    if (typeof userID!=="string" || !userID || typeof userName!=="string" || !userName) throw new Error("User identity required");
    const ticket=crypto.randomBytes(32).toString("base64url");
    if (!await this.store.put(this.namespace+"enroll:"+ticket,{userID,userName},300000)) throw new Error("Ticket storage failed");
    return ticket;
  }
  async handle(path, body, req) {
    if (requestOrigin(req)!==this.origin || requestHostOrigin(req)!==this.origin) throw new Error("Passkey origin mismatch");
    if (path==="register/options") {
      const user=await this.store.consume(this.namespace+"enroll:"+body.ticket);
      if (!user) throw new Error("Enrollment requires an unused provisioning ticket");
      const options=await webauthn.generateRegistrationOptions({rpName:this.rpName,rpID:this.rpID,userName:user.userName,
        userID:crypto.createHash("sha256").update(user.userID).digest(),attestationType:"none",
        authenticatorSelection:{residentKey:"required",userVerification:"required"}});
      return this.challenge("register",options,{user},req);
    }
    if (path==="authenticate/options") {
      if (!this.actions.has(body.action)) throw new Error("Unsupported action");
      const options=await webauthn.generateAuthenticationOptions({rpID:this.rpID,userVerification:"required"});
      return this.challenge("authenticate",options,{action:body.action},req);
    }
    if (!["register/verify","authenticate/verify"].includes(path)) throw new Error("Unknown passkey route");
    const pending=await this.store.consume(this.namespace+"webauthn:"+body.id);
    if (!pending || pending.kind!==path.split("/")[0] || pending.ip!==getClientIP(req)) throw new Error("Invalid or consumed challenge");
    const common={response:body.response,expectedChallenge:pending.challenge,expectedOrigin:this.origin,expectedRPID:this.rpID,requireUserVerification:true};
    if (pending.kind==="register") {
      const result=await webauthn.verifyRegistrationResponse(common);
      if (!result.verified || !result.registrationInfo) throw new Error("Registration failed");
      const credential=result.registrationInfo.credential;
      if (!await this.store.put(this.namespace+"credential:"+credential.id,{credential,user:pending.user,revision:0},31536000000)) throw new Error("Credential already registered");
      return {registered:true};
    }
    const saved=await this.store.get(this.namespace+"credential:"+body.response?.id);
    if (!saved) throw new Error("Unknown credential");
    const result=await webauthn.verifyAuthenticationResponse({...common,credential:saved.credential});
    if (!result.verified) throw new Error("Authentication failed");
    const next={...saved,revision:saved.revision+1,credential:{...saved.credential,counter:result.authenticationInfo.newCounter}};
    if (!await this.store.update(this.namespace+"credential:"+saved.credential.id,saved,next)) throw new Error("Concurrent credential update; retry");
    const ipSubnet=maskIP(getClientIP(req));
    if (ipSubnet==="unknown") throw new Error("Client IP required");
    return {status:"passed",score:0.70,...issueToken({score:0.70,action:pending.action,ipSubnet,origin:this.origin,host:this.origin})};
  }
  async challenge(kind,options,extra,req) {
    const id=crypto.randomBytes(32).toString("base64url");
    if (!await this.store.put(this.namespace+"webauthn:"+id,{...extra,kind,challenge:options.challenge,ip:getClientIP(req)},60000)) throw new Error("Challenge storage failed");
    return {id,options};
  }
}
module.exports={Passkeys};
