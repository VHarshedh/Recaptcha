/**
 * client/index.js — Client-Side Collectors & HCI Telemetry Module
 *
 * Provides standalone browser collectors and telemetry feature extractors:
 *   - RuntimeIntegrity: prototype integrity, built-in tamper, driver probes
 *   - HardwareConsistency: WebGL, AudioContext, concurrency, screen geometry
 *   - Kinematics: HCI behavioral biometrics (mouse, touch, key cadence)
 *   - solvePoW: non-blocking Proof-of-Work solver (inline Web Worker)
 */

"use strict";

const path = require("node:path");

const CLIENT_DIR = __dirname;
const COLLECTOR_FILES = [
  "runtime_integrity.js",
  "hardware_consistency.js",
  "kinematics.js",
  "pow_inline.js",
];

const RuntimeIntegrity = require("./runtime_integrity");
const HardwareConsistency = require("./hardware_consistency");
const Kinematics = require("./kinematics");
const { solvePoW: solvePoWClient } = require("./pow_client");

module.exports = {
  CLIENT_DIR,
  COLLECTOR_FILES,
  RuntimeIntegrity,
  HardwareConsistency,
  Kinematics,
  solvePoW: solvePoWClient,
};
