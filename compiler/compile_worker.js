const { parentPort } = require('node:worker_threads');
const { compile } = require('./pipeline');
parentPort.on('message', options => {
  try { parentPort.postMessage({ result: compile(options) }); }
  catch (error) { parentPort.postMessage({ error: error.message }); }
});
