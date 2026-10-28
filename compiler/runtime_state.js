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
// Per-build bytecode uses bounded Float32 arithmetic and explicit endian reads,
// avoiding platform-dependent canvas antialiasing in a cryptographic KDF.
function executeProgram(program, stage) {
  var view = new DataView(new ArrayBuffer(4));
  var state = program[stage][0] | 0;
  var descriptor = Object["getOwnPropertyDescriptor"](Uint8Array, "BYTES_PER_ELEMENT");
  var bits = descriptor && descriptor["value"] === 1 && descriptor["writable"] === false ? 0x51a7 : 0;
  for (var i = 1; i < program[stage]["length"]; i++) {
    var op = program[stage][i];
    if (op[0] === 0) state = Math["imul"](state ^ op[1], op[2] | 1);
    if (op[0] === 1) {
      view["setFloat32"](0, (state & 65535) / ((op[1] & 255) + 1) + (op[2] & 4095), false);
      state = view["getInt32"](0, false) ^ state;
    }
    if (op[0] === 2) { var shift = (op[1] & 15) + 1; state = ((state << shift) | (state >>> (32 - shift))) ^ op[2]; }
    state = mixRuntimeState(state, op[1], bits ^ i);
  }
  return state | 0;
}
function telemetryShape(collector) {
  return (typeof (collector["runtime"] && collector["runtime"]["confidence_penalty"]) === "number" ? 1 : 0) |
    (collector["hardware"] && typeof collector["hardware"]["profile"] === "object" && collector["hardware"]["profile"] !== null ? 2 : 0) |
    (collector["kinematics"] && typeof collector["kinematics"]["eventCounts"] === "object" && collector["kinematics"]["eventCounts"] !== null ? 4 : 0);
}
module.exports = { invariantHash, mixRuntimeState, executionCanary, executeProgram, telemetryShape };
