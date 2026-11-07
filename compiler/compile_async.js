"use strict";
const { Worker } = require("node:worker_threads");
let active = 0;
// Bound CPU work and memory before allocating workers; overload is retryable.
function compileAsync(options) {
  if (active >= 2) return Promise.reject(Object.assign(new Error("Compiler busy"), { status: 503 }));
  active++;
  return new Promise((resolve, reject) => {
    const worker = new Worker(require.resolve("./compile_worker"));
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true; clearTimeout(timer); active--; worker.terminate();
      if (error) reject(error); else resolve(result);
    };
    const timer = setTimeout(() => finish(new Error("Compiler timeout")), 10000);
    worker.once("error", finish);
    worker.once("exit", code => { if (!settled) finish(new Error("Compiler exited: " + code)); });
    worker.once("message", message => finish(message.error ? new Error(message.error) : null, message.result));
    worker.postMessage(options);
  });
}
module.exports = { compileAsync };
