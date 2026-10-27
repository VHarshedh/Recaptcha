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
  wLines["push"]("var enc=new TextEncoder();");
  wLines["push"]("function clz(b){var n=0;for(var i=0;i<b.length;i++){if(b[i]===0){n+=8;}else{n+=Math.clz32(b[i])-24;break;}}return n;}");
  wLines["push"]("function hex(b){var L='0123456789abcdef',h='';for(var i=0;i<b.length;i++)h+=L[b[i]>>4]+L[b[i]&15];return h;}");
  wLines["push"]("self.addEventListener('message',async function(e){");
  wLines["push"]("var c=e.data.c,d=e.data.d,t0=performance.now();");
  wLines["push"]("var cb=enc.encode(c),buf=new Uint8Array(cb.length+20);");
  wLines["push"]("buf.set(cb,0);var n=0;");
  wLines["push"]("while(true){var s=String(n),sl=s.length;");
  wLines["push"]("for(var j=0;j<sl;j++)buf[cb.length+j]=s.charCodeAt(j);");
  wLines["push"]("var dg=await crypto.subtle.digest('SHA-256',buf.subarray(0,cb.length+sl));");
  wLines["push"]("var hb=new Uint8Array(dg);");
  wLines["push"]("if(clz(hb)>=d){self.postMessage({t:'r',n:n,h:hex(hb),ms:Math.round(performance.now()-t0)});return;}");
  wLines["push"]("n++;if(n%50000===0)self.postMessage({t:'p',n:n,ms:Math.round(performance.now()-t0)});}");
  wLines["push"]("});");

  var wSrc = wLines["join"]("\n");

  return new Promise(function(resolve, reject) {
    var blobObj = new Blob([wSrc], { "type": "application/javascript" });
    var blobUrl = URL["createObjectURL"](blobObj);
    var worker = new Worker(blobUrl);
    var settled = false;

    var deadline = setTimeout(function() {
      if (!settled) {
        settled = true;
        worker["terminate"]();
        reject(new Error("PoW timeout"));
      }
    }, timeoutMs);

    worker["addEventListener"]("message", function(evt) {
      var msg = evt["data"];
      if (msg["t"] === "r" && !settled) {
        settled = true;
        clearTimeout(deadline);
        worker["terminate"]();
        URL["revokeObjectURL"](blobUrl);
        var solution = {};
        solution["nonce"] = msg["n"];
        solution["hash"] = msg["h"];
        solution["durationMs"] = msg["ms"];
        resolve(solution);
      }
    });

    worker["addEventListener"]("error", function(errEvt) {
      if (!settled) {
        settled = true;
        clearTimeout(deadline);
        worker["terminate"]();
        reject(errEvt);
      }
    });

    var payload = {};
    payload["c"] = challenge;
    payload["d"] = difficulty;
    worker["postMessage"](payload);
  });
}
