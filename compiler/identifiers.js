/**
 * identifiers.js — Cryptographic Identifier Randomization
 *
 * Extracts locally-declared identifiers from JS source, generates
 * crypto-random replacements, and applies them in a single pass.
 */

"use strict";

const crypto = require("node:crypto");

/* ------------------------------------------------------------------ */
/*  Reserved words & globals (never rename)                            */
/* ------------------------------------------------------------------ */

const RESERVED = new Set([
  // JS keywords & future reserved
  "break","case","catch","continue","debugger","default","delete","do",
  "else","export","extends","finally","for","function","if","import",
  "in","instanceof","new","return","super","switch","this","throw",
  "try","typeof","var","void","while","with","yield","async","await",
  "class","const","let","of","static","get","set","from",
  // Literals
  "true","false","null","undefined","NaN","Infinity",
  // Fundamental globals
  "window","document","navigator","screen","console","performance","crypto",
  "Math","Date","Number","String","Array","Object","Function","Boolean",
  "RegExp","Error","TypeError","RangeError","SyntaxError","ReferenceError",
  "JSON","Promise","Symbol","Proxy","Reflect","Map","Set","WeakMap","WeakSet",
  // Typed arrays & buffers
  "Uint8Array","Uint16Array","Uint32Array","Int8Array","Int32Array",
  "Float32Array","Float64Array","ArrayBuffer","DataView","SharedArrayBuffer",
  // Encoding
  "TextEncoder","TextDecoder","Blob","File","URL","URLSearchParams",
  // Workers
  "Worker","SharedWorker","ServiceWorker",
  // Scheduling & IO
  "fetch","XMLHttpRequest","Request","Response","Headers",
  "setTimeout","setInterval","clearTimeout","clearInterval",
  "requestAnimationFrame","cancelAnimationFrame","requestIdleCallback",
  "queueMicrotask",
  // Parsing & encoding
  "parseInt","parseFloat","isNaN","isFinite",
  "encodeURIComponent","decodeURIComponent","encodeURI","decodeURI",
  "atob","btoa",
  // Scope
  "self","globalThis","top","parent","postMessage",
  "addEventListener","removeEventListener","dispatchEvent",
  // DOM constructors
  "Event","CustomEvent","Element","Node","NodeList","HTMLElement",
  "Notification","MutationObserver","IntersectionObserver",
  // Node.js (for testing)
  "require","module","exports","process","Buffer","global","__dirname","__filename",
]);

/* ------------------------------------------------------------------ */
/*  Declaration patterns                                               */
/* ------------------------------------------------------------------ */

const DECL_PATTERNS = [
  /\bfunction\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g,
  /\b(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g,
  /\bcatch\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\)/g,
  /\bfor\s*\(\s*(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g,
];

/** Matches parameter names inside function signatures. */
const PARAM_RE = /\bfunction\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(([^)]*)\)/g;

/**
 * Find all locally-declared identifiers in source.
 * Skips reserved words and single-character names.
 *
 * @param {string} source
 * @returns {string[]}
 */
function extractIdentifiers(source) {
  const ids = new Set();

  // Declarations (function names, var/let/const, catch, for).
  for (const pattern of DECL_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let m;
    while ((m = re.exec(source)) !== null) {
      const name = m[1];
      if (name.length > 1 && !RESERVED.has(name)) {
        ids.add(name);
      }
    }
  }

  // Function parameters.
  {
    const re = new RegExp(PARAM_RE.source, PARAM_RE.flags);
    let m;
    while ((m = re.exec(source)) !== null) {
      const paramList = m[1];
      if (!paramList.trim()) continue;
      const params = paramList.split(",");
      for (const p of params) {
        const name = p.trim().replace(/=.*$/, "").trim(); // strip default values
        if (name.length > 1 && /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(name) && !RESERVED.has(name)) {
          ids.add(name);
        }
      }
    }
  }

  return Array.from(ids);
}

/* ------------------------------------------------------------------ */
/*  Random name generation                                             */
/* ------------------------------------------------------------------ */

const FIRST_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$";
const REST_CHARS  = FIRST_CHARS + "0123456789";

/**
 * Generate a crypto-random JS identifier.
 * @param {number} minLen
 * @param {number} maxLen
 * @returns {string}
 */
function generateRandomName(minLen = 6, maxLen = 12) {
  const len = minLen + crypto.randomInt(maxLen - minLen + 1);
  let name = FIRST_CHARS[crypto.randomInt(FIRST_CHARS.length)];
  for (let i = 1; i < len; i++) {
    name += REST_CHARS[crypto.randomInt(REST_CHARS.length)];
  }
  return name;
}

/**
 * Generate a unique random name for each identifier.
 *
 * @param {string[]}  identifiers
 * @param {Set<string>} [usedNames] — optional set of already-used names
 * @returns {Object<string,string>}  old→new mapping
 */
function generateMapping(identifiers, usedNames) {
  const used = usedNames || new Set();
  const mapping = {};
  for (const id of identifiers) {
    let newName;
    do {
      newName = generateRandomName();
    } while (used.has(newName) || RESERVED.has(newName));
    used.add(newName);
    mapping[id] = newName;
  }
  return mapping;
}

/* ------------------------------------------------------------------ */
/*  Replacement engine                                                 */
/* ------------------------------------------------------------------ */

/**
 * Replace all occurrences of mapped identifiers in source.
 * Uses a single-pass regex with word boundaries.
 *
 * @param {string} source
 * @param {Object<string,string>} mapping
 * @returns {string}
 */
function applyMapping(source, mapping) {
  const names = Object.keys(mapping);
  if (names.length === 0) return source;

  // Sort longest-first for regex alternation safety.
  names.sort((a, b) => b.length - a.length);

  const escaped = names.map((n) => n.replace(/[$]/g, "\\$&"));
  const pattern = new RegExp(`\\b(${escaped.join("|")})\\b`, "g");

  return source.replace(pattern, (match) => mapping[match] || match);
}

/* ------------------------------------------------------------------ */

module.exports = {
  RESERVED,
  extractIdentifiers,
  generateRandomName,
  generateMapping,
  applyMapping,
};
