"use strict";
function invariantHash(value) {
  var hash = 2166136261;
  for (var i = 0; i < value["length"]; i++) hash = Math["imul"](hash ^ value["charCodeAt"](i), 16777619);
  return hash | 0;
}
function mixRuntimeState(state, step, invariant) {
  var mixed = (state ^ step ^ invariant) | 0;
  mixed = (mixed << 7) | (mixed >>> 25);
  if ((mixed & 1) === 0 || (mixed & 1) === 1) mixed = Math["imul"](mixed, 73244475);
  return (mixed ^ (mixed >>> 16)) | 0;
}
function executionCanary() {
  var bytes = new ArrayBuffer(8), view = new DataView(bytes);
  view["setInt32"](0, Math["imul"](12345, 6789), true);
  view["setInt32"](4, (view["getInt32"](0, true) << 3) ^ 0x5a17, false);
  return (view["getInt32"](4, false) ^ view["getUint8"](1)) | 0;
}
module.exports = { invariantHash, mixRuntimeState, executionCanary };
