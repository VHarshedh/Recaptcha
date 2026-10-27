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

const CLIENT_DIR  = path.join(__dirname, "..", "client");
const SOURCE_LIST = [
  "runtime_integrity.js",
  "hardware_consistency.js",
  "kinematics.js",
  "pow_inline.js",
];

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/** Strip "use strict" directives and JS comments from source. */
function preprocess(src) {
  // Remove single-line comments (not inside strings — good enough for our controlled sources).
  let out = src.replace(/^\s*\/\/.*$/gm, "");
  // Remove multi-line block comments.
  out = out.replace(/\/\*[\s\S]*?\*\//g, "");
  // Remove "use strict" directives.
  out = out.replace(/["']use strict["'];?\s*/g, "");
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
 * flow (flattened).  All property accesses use bracket notation.
 *
 * @param {Object} names — { kin, collector, mainFn, ecdhFn }
 * @param {string} endpoint
 * @returns {string}
 */
function generateFlattenedMain(names, endpoint) {
  // Generate random case labels and a random dispatch order.
  const caseValues = [];
  for (let i = 0; i < 8; i++) caseValues.push(crypto.randomInt(10, 9999));
  // Ensure uniqueness.
  const caseSet = new Set(caseValues);
  while (caseSet.size < 8) caseSet.add(crypto.randomInt(10, 9999));
  const cv = Array.from(caseSet);

  const SENTINEL = crypto.randomInt(10000, 99999);

  return `
var ${names.kin} = createKinematics();
${names.kin}["start"]();

async function ${names.mainFn}() {
  var ${names.collector} = {};
  var ${names.state} = ${cv[0]};
  while (${names.state} !== ${SENTINEL}) {
    switch (${names.state}) {
      case ${cv[0]}:
        ${names.collector}["runtime"] = collectRuntime();
        ${names.state} = ${cv[1]};
        break;
      case ${cv[1]}:
        ${names.collector}["hardware"] = collectHardware();
        ${names.state} = ${cv[2]};
        break;
      case ${cv[2]}:
        ${names.collector}["kinematics"] = ${names.kin}["snapshot"]();
        ${names.state} = ${cv[3]};
        break;
      case ${cv[3]}:
        ${names.collector}["action"] = document["body"]
          ? (document["body"]["getAttribute"]("data-action") || "pageview")
          : "pageview";
        ${names.state} = ${cv[4]};
        break;
      case ${cv[4]}:
        try {
          var ${names.powChallenge} = String(Date["now"]()) + "." +
            Math["random"]()["toString"](36)["substring"](2);
          var ${names.powOpts} = {};
          ${names.powOpts}["challenge"] = ${names.powChallenge};
          ${names.powOpts}["difficulty"] = 16;
          ${names.collector}["pow"] = await solvePoW(${names.powOpts});
          ${names.collector}["pow"]["valid"] = true;
        } catch (powErr) {
          ${names.collector}["pow"] = {};
          ${names.collector}["pow"]["valid"] = false;
        }
        ${names.state} = ${cv[5]};
        break;
      case ${cv[5]}:
        await ${names.ecdhFn}(${names.collector}, "${endpoint}");
        ${names.state} = ${SENTINEL};
        break;
      default:
        ${names.state} = ${SENTINEL};
        break;
    }
  }
}

setTimeout(${names.mainFn}, 2000 + Math["floor"](Math["random"]() * 1000));
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
 *
 * @returns {{
 *   bundle: string,
 *   buildId: string,
 *   ecdhKeyPair: Object|null,
 *   stats: { strings: number, identifiers: number, deadBlocks: number, bytes: number }
 * }}
 */
function compile(options = {}) {
  const {
    sourceDir      = CLIENT_DIR,
    sourceFiles    = SOURCE_LIST,
    attestEndpoint = "/attest",
    deadCodeBlocks = 8,
    includeECDH    = true,
    rawSourceOverride = null,
  } = options;

  const nameGen = createNameGenerator();

  // ── 1. Read and concatenate source modules ─────────────────────────
  let rawSource;
  if (rawSourceOverride) {
    rawSource = rawSourceOverride;
  } else {
    const modules = [];
    for (const file of sourceFiles) {
      const fp = path.join(sourceDir, file);
      if (fs.existsSync(fp)) {
        modules.push(preprocess(fs.readFileSync(fp, "utf-8")));
      }
    }
    rawSource = modules.join("\n\n");
  }

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
  const mainNames = {
    kin:          nameGen(),
    collector:    nameGen(),
    mainFn:       nameGen(),
    state:        nameGen(),
    powChallenge: nameGen(),
    powOpts:      nameGen(),
    ecdhFn:       ecdhFnName,
  };
  rawSource += "\n\n" + generateFlattenedMain(mainNames, attestEndpoint);

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
    ecdhKeyPair,
    stats: {
      strings:     strings.length,
      identifiers: identifiers.length,
      deadBlocks:  deadCodeBlocks,
      bytes:       Buffer.byteLength(bundle, "utf-8"),
    },
  };
}

/* ------------------------------------------------------------------ */

module.exports = { compile, createNameGenerator, preprocess };
