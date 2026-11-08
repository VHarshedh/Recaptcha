"use strict";
const { Worker } = require("node:worker_threads");
let active = 0;
// Bound CPU work and memory before allocating workers; overload is retryable.
function compileAsync(options) {
  if (active >= 2) return Promise.reject(Object.assign(new Error("Compiler busy"), { status: 503 }));
  active++;
  return new Promise((resolve, reject) => {
    let worker, timer, settled = false;
    const finish = async (error, result) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      try { if (worker) await worker.terminate(); }
      catch (terminationError) { error ||= terminationError; }
      finally { active--; }
      if (error) reject(error); else resolve(result);
    };
    try {
      worker = new Worker(require.resolve("./compile_worker"));
      timer = setTimeout(() => finish(new Error("Compiler timeout")), 10000);
      worker.once("error", finish);
      worker.once("exit", code => { if (!settled) finish(new Error("Compiler exited: " + code)); });
      worker.once("message", message => finish(message.error ? new Error(message.error) : null, message.result));
      worker.postMessage(options);
    } catch (error) { finish(error); }

  });
}
module.exports = { compileAsync };
