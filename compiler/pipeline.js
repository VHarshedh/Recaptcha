/**
 * pipeline.js — Polymorphic Compilation Pipeline
 *
 * Reads the raw client modules, applies string encryption, identifier
 * randomization, dead-code injection, ECDH wrapper generation, and
 * control-flow-flattened main collector — producing a unique bundle
 * on every invocation.
 *
 * Usage:
 *   const { compile } = require("./pipeline");
 *   const { bundle, buildId, ecdhKeyPair } = compile({ attestEndpoint: "/attest" });
 */

"use strict";

const fs   = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const { extractStrings, generateKey, buildStringTable,
        generateDecoderSource, replaceStrings } = require("./string_table");
const { extractIdentifiers, generateMapping, applyMapping } = require("./identifiers");
const { injectDeadCode }         = require("./dead_code");
const { generateEphemeralKeyPair, generateClientECDHCode } = require("./ecdh_session");

/* ------------------------------------------------------------------ */
/*  Source module paths                                                 */
/* ------------------------------------------------------------------ */

const ROOT_DIR   = path.join(__dirname, "..");
const CLIENT_DIR = path.join(__dirname, "..", "client");
const SOURCE_LIST = [
  "runtime_integrity.js",
  "hardware_consistency.js",
  "kinematics.js",
  "pow_inline.js",
];

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/** Strip "use strict" directives, comments, and transform UMD wrappers. */
function preprocess(src) {
  // Protect literals while removing comments; preserve source-text canaries.
  let out = src.replace(/("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|(\/\*[\s\S]*?\*\/|^\s*\/\/[^\r\n]*)/gm,
    (match, literal) => literal || (match.includes("runtime_integrity_source_canary") ? match : " "));
  out = out.replace(/^\s*["']use strict["'];?\s*$/gm, "");

  // Transform UMD wrapper to direct IIFE assignment to globalThis and local var
  const umdRegex = /\(function\s*\(\s*root\s*,\s*factory\s*\)\s*\{[\s\S]*?Object\.defineProperty\(\s*root\s*,\s*['"](\w+)['"][\s\S]*?\}\)\s*\([^,]+,\s*function\s*\(\s*root\s*\)\s*\{([\s\S]*?)\}\);\s*$/;
  const match = out.match(umdRegex);
  if (match) {
    const modName = match[1];
    const body = match[2];
    out = `var ${modName} = (function (root) {${body}})(typeof globalThis === 'object' ? globalThis : this);\n` +
          `(typeof globalThis === 'object' ? globalThis : this)["${modName}"] = ${modName};\n`;
  }

  return out;
}

/**
 * Name generator factory — returns a function that produces unique
 * crypto-random JS identifiers on each call.
 */
function createNameGenerator() {
  const used = new Set();
  const FIRST = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$";
  const REST  = FIRST + "0123456789";
  return function nameGen() {
    let name;
    do {
      const len = 6 + crypto.randomInt(7); // 6–12 chars
      name = FIRST[crypto.randomInt(FIRST.length)];
      for (let i = 1; i < len; i++) name += REST[crypto.randomInt(REST.length)];
    } while (used.has(name));
    used.add(name);
    return name;
  };
}

/* ------------------------------------------------------------------ */
/*  Control-flow-flattened main collector                               */
/* ------------------------------------------------------------------ */

/**
 * Generate the main collector function with a switch-dispatch control
 * flow (flattened). All property accesses use bracket notation.
 *
 * @param {Object} names — random identifiers
 * @param {string} endpoint
 * @param {string} powChallenge
 * @param {number} powDifficulty
 * @returns {string}
 */
function generateFlattenedMain(names, endpoint, powChallenge, powDifficulty, vmSeed, stepConsts) {
  // Generate random case labels and a random dispatch order.
  const caseValues = [];
  for (let i = 0; i < 8; i++) caseValues.push(crypto.randomInt(10, 9999));
  // Ensure uniqueness.
  const caseSet = new Set(caseValues);
  while (caseSet.size < 8) caseSet.add(crypto.randomInt(10, 9999));
  const cv = Array.from(caseSet);

  const SENTINEL = crypto.randomInt(10000, 99999);

  return `
var ${names.kinRef} = (typeof globalThis !== "undefined" && globalThis["Kinematics"]) || (typeof window !== "undefined" && window["Kinematics"]) || (typeof Kinematics !== "undefined" ? Kinematics : null);
if (${names.kinRef} && typeof ${names.kinRef}["start"] === "function") {
  ${names.kinRef}["start"]();
}

var ${names.powPromise} = solvePoW({
  "challenge": "${powChallenge}",
  "difficulty": ${powDifficulty}
});

async function ${names.mainFn}(${names.actionParam}) {
  var ${names.collector} = {};
  var ${names.vmState} = ${vmSeed};
  var ${names.state} = ${cv[0]};
  var ${names.retVal} = null;
  while (${names.state} !== ${SENTINEL}) {
    switch (${names.state}) {
      case ${cv[0]}:
        ${names.vmState} = Math["imul"](${names.vmState} ^ ${stepConsts[0]}, 73244475) | 0;
        var ${names.rtRef} = (typeof globalThis !== "undefined" && globalThis["RuntimeIntegrity"]) || (typeof window !== "undefined" && window["RuntimeIntegrity"]) || (typeof RuntimeIntegrity !== "undefined" ? RuntimeIntegrity : null);
        ${names.collector}["runtime"] = (${names.rtRef} && typeof ${names.rtRef}["collect"] === "function") ? ${names.rtRef}["collect"]() : {};
        ${names.state} = ${cv[1]};
        break;
      case ${cv[1]}:
        ${names.vmState} = Math["imul"](${names.vmState} ^ ${stepConsts[1]}, 73244475) | 0;
        var ${names.hwRef} = (typeof globalThis !== "undefined" && globalThis["HardwareConsistency"]) || (typeof window !== "undefined" && window["HardwareConsistency"]) || (typeof HardwareConsistency !== "undefined" ? HardwareConsistency : null);
        ${names.collector}["hardware"] = (${names.hwRef} && typeof ${names.hwRef}["collect"] === "function") ? await ${names.hwRef}["collect"]() : {};
        ${names.state} = ${cv[2]};
        break;
      case ${cv[2]}:
        ${names.vmState} = Math["imul"](${names.vmState} ^ ${stepConsts[2]}, 73244475) | 0;
        var ${names.kinSnap} = (typeof globalThis !== "undefined" && globalThis["Kinematics"]) || (typeof window !== "undefined" && window["Kinematics"]) || (typeof Kinematics !== "undefined" ? Kinematics : null);
        ${names.collector}["kinematics"] = (${names.kinSnap} && typeof ${names.kinSnap}["getBiometricVector"] === "function") ? ${names.kinSnap}["getBiometricVector"]() : {};
        ${names.state} = ${cv[3]};
        break;
      case ${cv[3]}:
        ${names.vmState} = Math["imul"](${names.vmState} ^ ${stepConsts[3]}, 73244475) | 0;
        ${names.collector}["action"] = (typeof ${names.actionParam} === "string" && ${names.actionParam}["length"] > 0)
          ? ${names.actionParam}
          : ((typeof document !== "undefined" && document["body"])
              ? (document["body"]["getAttribute"]("data-action") || "pageview")
              : "pageview");
        ${names.state} = ${cv[4]};
        break;
      case ${cv[4]}:
        ${names.vmState} = Math["imul"](${names.vmState} ^ ${stepConsts[4]}, 73244475) | 0;
        try {
          var ${names.powRes} = await ${names.powPromise};
          ${names.collector}["pow"] = {
            "challenge": "${powChallenge}",
            "nonce": ${names.powRes}["nonce"],
            "hash": ${names.powRes}["hash"],
            "durationMs": ${names.powRes}["durationMs"]
          };
        } catch (powErr) {
          ${names.collector}["pow"] = {
            "challenge": "${powChallenge}",
            "nonce": -1
          };
        }
        ${names.state} = ${cv[5]};
        break;
      case ${cv[5]}:
        ${names.vmState} = Math["imul"](${names.vmState} ^ ${stepConsts[5]}, 73244475) | 0;
        ${names.retVal} = await ${names.ecdhFn}(${names.collector}, "${endpoint}", ${names.vmState});
        ${names.state} = ${SENTINEL};
        break;
      default:
        ${names.state} = ${SENTINEL};
        break;
    }
  }
  return completeAttestation(${names.retVal}, function(stepPayload) {
    return ${names.ecdhFn}(stepPayload, "${endpoint}/verify-challenge", ${names.vmState});
  });
}

var ${names.hook} = {};
${names.hook}["execute"] = ${names.mainFn};
(typeof window !== "undefined" ? window : (typeof globalThis !== "undefined" ? globalThis : this))["__attestation"] = ${names.hook};
`;
}

/* ------------------------------------------------------------------ */
/*  Main compile entry point                                           */
/* ------------------------------------------------------------------ */

/**
 * Compile a unique polymorphic client bundle.
 *
 * @param {Object}  [options]
 * @param {string}  [options.sourceDir]       — directory containing client modules
 * @param {string[]} [options.sourceFiles]    — module filenames
 * @param {string}  [options.attestEndpoint]  — server endpoint URL
 * @param {number}  [options.deadCodeBlocks]  — number of dead code blocks to inject
 * @param {boolean} [options.includeECDH]     — include ECDH encryption (default true)
 * @param {string}  [options.rawSourceOverride] — pre-bundled source (testing)
 * @param {string}  [options.powChallenge]    — server-issued PoW challenge
 * @param {number}  [options.powDifficulty]   — required difficulty (default 16)
 *
 * @returns {{
 *   bundle: string,
 *   buildId: string,
 *   ecdhKeyPair: Object|null,
 *   pow: { challenge: string, difficulty: number },
 *   stats: { strings: number, identifiers: number, deadBlocks: number, bytes: number }
 * }}
 */
function compile(options = {}) {
  const {
    sourceDir         = ROOT_DIR,
    sourceFiles       = SOURCE_LIST,
    attestEndpoint    = "/attest",
    deadCodeBlocks    = 8,
    includeECDH       = true,
    rawSourceOverride = null,
    powChallenge      = null,
    powDifficulty     = 16,
  } = options;

  let activeChallenge = powChallenge;
  if (!activeChallenge) {
    const { generateChallenge } = require("../pow_verifier");
    activeChallenge = generateChallenge().challenge;
  }
  const activeDifficulty = Number.isInteger(powDifficulty) ? powDifficulty : 16;

  const nameGen = createNameGenerator();

  // ── 1. Read and concatenate source modules ─────────────────────────
  let rawSource;
  if (rawSourceOverride) {
    rawSource = rawSourceOverride;
  } else {
    const modules = [];
    for (const file of sourceFiles) {
      let fp = path.join(sourceDir, file);
      if (!fs.existsSync(fp)) {
        fp = path.join(sourceDir, "client", file);
      }
      if (!fs.existsSync(fp)) {
        fp = path.join(CLIENT_DIR, file);
      }
      if (fs.existsSync(fp)) {
        modules.push(preprocess(fs.readFileSync(fp, "utf-8")));
      }
    }
    rawSource = modules.join("\n\n");
  }

  rawSource += "\n" + preprocess(fs.readFileSync(path.join(__dirname, "step_up.js"), "utf-8"));

  // ── 2. Generate ECDH client code ──────────────────────────────────
  let ecdhKeyPair = null;
  const ecdhFnName = nameGen();
  if (includeECDH) {
    ecdhKeyPair = generateEphemeralKeyPair();
    const ecdhCode = generateClientECDHCode(
      ecdhKeyPair.publicKeyBase64,
      ecdhKeyPair.id,
      ecdhFnName,
    );
    rawSource += "\n\n" + ecdhCode;
  }

  // ── 3. Generate flattened main collector ───────────────────────────
  const vmSeed = crypto.randomBytes(4).readInt32BE();
  const stepConsts = Array.from({ length: 6 }, () => crypto.randomBytes(4).readInt32BE());
  const expectedVmState = stepConsts.reduce((state, step) => Math.imul(state ^ step, 73244475) | 0, vmSeed);
  const mainNames = {
    vmState: nameGen(),
    kinRef:       nameGen(),
    powPromise:   nameGen(),
    mainFn:       nameGen(),
    actionParam:  nameGen(),
    collector:    nameGen(),
    state:        nameGen(),
    rtRef:        nameGen(),
    hwRef:        nameGen(),
    kinSnap:      nameGen(),
    powRes:       nameGen(),
    retVal:       nameGen(),
    hook:         nameGen(),
    ecdhFn:       ecdhFnName,
  };
  rawSource += "\n\n" + generateFlattenedMain(mainNames, attestEndpoint, activeChallenge, activeDifficulty, vmSeed, stepConsts);

  // ── 4. String extraction & encryption ─────────────────────────────
  const strings      = extractStrings(rawSource);
  const xorKey       = generateKey(32);
  const encTable     = buildStringTable(strings, xorKey);
  const tableName    = nameGen();
  const keyVarName   = nameGen();
  const decoderName  = nameGen();
  const decoderSrc   = generateDecoderSource(tableName, keyVarName, decoderName, encTable, xorKey);
  rawSource          = replaceStrings(rawSource, strings, decoderName);

  // ── 5. Identifier randomization ───────────────────────────────────
  const identifiers = extractIdentifiers(rawSource);
  const mapping     = generateMapping(identifiers);
  rawSource         = applyMapping(rawSource, mapping);

  // ── 6. Dead code injection ────────────────────────────────────────
  rawSource = injectDeadCode(rawSource, deadCodeBlocks, nameGen);

  // ── 7. Assemble final IIFE ────────────────────────────────────────
  const buildId = crypto.randomBytes(8).toString("hex");
  const bundle  = `(function(){${decoderSrc}\n${rawSource}\n})();`;

  return {
    bundle,
    buildId,
    expectedVmState,
    ecdhKeyPair,
    pow: {
      challenge: activeChallenge,
      difficulty: activeDifficulty,
    },
    stats: {
      strings:     strings.length,
      identifiers: identifiers.length,
      deadBlocks:  deadCodeBlocks,
      bytes:       Buffer.byteLength(bundle, "utf-8"),
    },
  };
}

/* ------------------------------------------------------------------ */

module.exports = { compile, createNameGenerator, preprocess, ROOT_DIR, CLIENT_DIR };
