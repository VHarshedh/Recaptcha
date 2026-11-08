"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {spawnSync}=require("node:child_process");
const dir=fs.mkdtempSync(path.join(os.tmpdir(),"attestation-restart-"));
try {
 const {privateKey}=crypto.generateKeyPairSync("ed25519");
 const key=path.join(dir,"key.json");
 fs.writeFileSync(key,JSON.stringify({privateKeyDer:privateKey.export({type:"pkcs8",format:"der"}).toString("base64")}),{mode:0o600});
 const script=`
 const fs=require('node:fs'),path=require('node:path');
 const {issueToken}=require('./attestation/token');
 const {verifyToken,verifyTokenAsync}=require('./attestation/verifier');
 const p={action:'login',origin:'https://app.test',host:'https://app.test',clientIP:'192.0.2.1'};
 const issue=()=>issueToken({...p,score:0.9,ipSubnet:'192.0.2.0/24'}).token;
 // Atomic on-disk fixture models a replay store retained across processes.
 const nonceStore={claim:async nonce=>{try{fs.closeSync(fs.openSync(path.join(process.argv[1],nonce),'wx'));return true;}catch(e){if(e.code==='EEXIST')return false;throw e;}}};
 (async()=>{
 const input=JSON.parse(process.argv[2]);
 const local=input.local||issue(),shared=input.shared||issue(),foreign=input.foreign||issue();
 const localChecks=[verifyToken(local,p).valid,verifyToken(local,p).valid];
 const sharedCheck=(await verifyTokenAsync(shared,{...p,nonceStore})).valid;
 const foreignCheck=input.foreign?(await verifyTokenAsync(foreign,{...p,nonceStore})).valid:null;
 const freshCheck=verifyToken(issue(),p).valid;
 console.log(JSON.stringify({local,shared,foreign,localChecks,sharedCheck,foreignCheck,freshCheck}));
 })().catch(e=>{console.error(e);process.exitCode=1});`;
 function run(input){const r=spawnSync(process.execPath,["-e",script,dir,JSON.stringify(input)],{cwd:__dirname,encoding:"utf8",env:{...process.env,NODE_ENV:"production",ATTESTATION_STATE_MODE:"single-process",ATTESTATION_KEY_PATH:key}});assert.equal(r.status,0,r.stderr);return JSON.parse(r.stdout);}
 const first=run({});assert.deepEqual(first.localChecks,[true,false]);assert.equal(first.sharedCheck,true);
 const next=run(first);assert.deepEqual(next.localChecks,[false,false],"A replacement process must reject previously consumed local tokens");
 assert.equal(next.sharedCheck,false,"Shared replay history survives restart");
 assert.equal(next.foreignCheck,true,"Shared verification supports another issuer process");assert.equal(next.freshCheck,true);
 console.log("Production restart isolation and retained shared replay history passed");
} finally {fs.rmSync(dir,{recursive:true,force:true});}
