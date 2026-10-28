/**
 * pow_inline.js — PoW Solver with Inline Blob Worker
 *
 * Spawns a Web Worker from an inline source blob to keep the
 * main thread responsive during mining. Worker source is defined
 * as an array of strings for clean compiler string encryption.
 */

function solvePoW(opts) {
  var challenge = opts["challenge"];
  var difficulty = opts["difficulty"] || 16;
  var timeoutMs = opts["timeoutMs"] || 120000;

  var wLines = [];
  wLines["push"]("function createScratchpad(challenge) {\n  var pad = new Int32Array(16384), seed = 2166136261;\n  for (var i = 0; i < challenge.length; i++) seed = Math.imul(seed ^ challenge.charCodeAt(i), 16777619);\n  for (var j = 0; j < pad.length; j++) {\n    seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5;\n    seed = (seed + Math.imul(j + 1, 0x9e3779b9)) | 0; pad[j] = seed;\n  }\n  return pad;\n}\nfunction scratchSuffix(pad, nonce) {\n  var x = (nonce | 0) ^ Math.floor(nonce / 4294967296), y = 0x6a09e667;\n  for (var i = 0; i < 64; i++) {\n    x = Math.imul(x ^ pad[(x ^ y) & 16383], 0x85ebca6b);\n    x = (x << 13) | (x >>> 19);\n    y = (Math.imul(y ^ x, 0xc2b2ae35) + i) | 0;\n  }\n  return \":cache64-v1:\" + (x >>> 0) + \":\" + (y >>> 0);\n}");
  wLines["push"]("var enc=new TextEncoder();");
  // Synchronous SHA-256 inside the worker avoids millions of Web Crypto IPC calls.
  wLines["push"]("var K=new Int32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);\nvar W=new Int32Array(64),HB=new Uint8Array(32);\nfunction rr(x,n){return (x>>>n)|(x<<(32-n));}\nfunction sha256(bytes){\n var len=bytes.length,total=((len+9+63)>>6)<<6;\n var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];\n for(var off=0;off<total;off+=64){\n  for(var i=0;i<16;i++){var word=0;for(var j=0;j<4;j++){var pos=off+i*4+j;var v=pos<len?bytes[pos]:pos===len?128:pos>=total-4?((len*8)>>>((total-1-pos)*8))&255:0;word=(word<<8)|v;}W[i]=word;}\n  for(var i=16;i<64;i++){var x=W[i-15],y=W[i-2];W[i]=(W[i-16]+(rr(x,7)^rr(x,18)^(x>>>3))+W[i-7]+(rr(y,17)^rr(y,19)^(y>>>10)))|0;}\n  var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];\n  for(var i=0;i<64;i++){var t1=(h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+K[i]+W[i])|0;var t2=((rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c)))|0;h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}\n  H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;\n }\n for(var i=0;i<32;i++)HB[i]=(H[i>>2]>>>(24-(i%4)*8))&255;\n return HB;\n}");
  wLines["push"]("function clz(b){var n=0;for(var i=0;i<b.length;i++){if(b[i]===0){n+=8;}else{n+=Math.clz32(b[i])-24;break;}}return n;}");
  wLines["push"]("function hex(b){var L='0123456789abcdef',h='';for(var i=0;i<b.length;i++)h+=L[b[i]>>4]+L[b[i]&15];return h;}");
  wLines["push"]("self.addEventListener('message',async function(e){");
  wLines["push"]("var c=e.data.c,d=e.data.d,t0=performance.now(),pad=createScratchpad(c);");
  wLines["push"]("var cb=enc.encode(c),buf=new Uint8Array(cb.length+80);");
  wLines["push"]("buf.set(cb,0);var n=0;");
  wLines["push"]("while(true){var s=String(n)+scratchSuffix(pad,n),sl=s.length;");
  wLines["push"]("for(var j=0;j<sl;j++)buf[cb.length+j]=s.charCodeAt(j);");
  wLines["push"]("var hb=sha256(buf.subarray(0,cb.length+sl));");
  wLines["push"]("if(clz(hb)>=d){self.postMessage({t:'r',n:n,h:hex(hb),ms:Math.round(performance.now()-t0)});return;}");
  wLines["push"]("n++;if(n%50000===0)self.postMessage({t:'p',n:n,ms:Math.round(performance.now()-t0)});}");
  wLines["push"]("});");

  var wSrc = wLines["join"]("\n");

  return new Promise(function(resolve, reject) {
    var signal = opts["signal"];
    if (signal && signal["aborted"]) return reject(new Error("PoW cancelled"));
    var blobObj = new Blob([wSrc], { "type": "application/javascript" });
    var blobUrl = URL["createObjectURL"](blobObj);
    var worker;
    try { worker = new Worker(blobUrl); }
    catch (error) { URL["revokeObjectURL"](blobUrl); reject(error); return; }
    var settled = false;
    var deadline;
    function finish(error, solution) {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      worker["terminate"]();
      URL["revokeObjectURL"](blobUrl);
      if (signal) signal["removeEventListener"]("abort", abortWork);
      if (error) reject(error); else resolve(solution);
    }
    function abortWork() { finish(new Error("PoW cancelled")); }
    if (signal) signal["addEventListener"]("abort", abortWork, { "once": true });
    deadline = setTimeout(function() { finish(new Error("PoW timeout")); }, timeoutMs);
    worker["addEventListener"]("message", function(evt) {
      var msg = evt["data"];
      if (msg["t"] === "r") finish(null, { "nonce": msg["n"], "hash": msg["h"], "durationMs": msg["ms"] });
    });
    worker["addEventListener"]("error", function() { finish(new Error("PoW worker failed")); });
    try { worker["postMessage"]({ "c": challenge, "d": difficulty }); }
    catch (error) { finish(error); }
  });
}
