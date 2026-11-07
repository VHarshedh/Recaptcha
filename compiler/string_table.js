/**
 * string_table.js — String Extraction & XOR Encryption Engine
 *
 * Extracts all string literals from JS source, encrypts them into a
 * lookup table with an ephemeral XOR key, and generates a compact
 * runtime decoder function.
 */

"use strict";

const crypto = require("node:crypto");

/* ------------------------------------------------------------------ */
/*  JS escape-sequence processor                                       */
/* ------------------------------------------------------------------ */

/**
 * Resolve JS escape sequences in a raw source-text string to their
 * actual character values.  E.g. the two source chars `\n` become
 * the single newline character `\u000A`.
 *
 * @param {string} s — inner content of a string literal (quotes stripped)
 * @returns {string}
 */
function unescapeJS(s) {
  return s.replace(
    /\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|u\{[0-9a-fA-F]+\}|[^])/g,
    (_, p) => {
      if (p.startsWith("x"))  return String.fromCharCode(parseInt(p.slice(1), 16));
      if (p.startsWith("u{")) return String.fromCodePoint(parseInt(p.slice(2, -1), 16));
      if (p.startsWith("u"))  return String.fromCharCode(parseInt(p.slice(1), 16));
      const MAP = {
        n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", v: "\v",
        "0": "\0", "'": "'", '"': '"', "\\": "\\", "/": "/",
      };
      return MAP[p] !== undefined ? MAP[p] : p; // unknown escape → char itself
    }
  );
}

/* ------------------------------------------------------------------ */
/*  String extraction                                                  */
/* ------------------------------------------------------------------ */

/** Matches double-quoted, single-quoted, and simple template literals. */
const STRING_RE = /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g;

/**
 * Extract every unique string literal from JS source.
 * Returns the *unescaped* character values (ready for encryption).
 *
 * @param {string} source
 * @returns {string[]}
 */
function extractStrings(source) {
  const values = new Set();
  require("acorn-walk").simple(require("acorn").parse(source, { ecmaVersion: "latest" }), {
    Literal(node) { if (typeof node.value === "string" && node.value && node.value !== "use strict") values.add(node.value); }
  });
  return [...values];
}

/* ------------------------------------------------------------------ */
/*  XOR encryption                                                     */
/* ------------------------------------------------------------------ */

/**
 * Generate a random XOR key (array of byte values).
 * @param {number} length
 * @returns {number[]}
 */
function generateKey(length = 32) {
  return Array.from(crypto.randomBytes(length));
}

/**
 * XOR-encrypt a string with a byte-array key.
 * Returns a hex string (2 hex chars per character).
 *
 * @param {string}   str      — actual character values (post-unescape)
 * @param {number[]} keyBytes — XOR key
 * @returns {string}          — hex-encoded ciphertext
 */
function xorEncrypt(str, keyBytes) {
  const parts = [];
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);

    parts.push((code ^ keyBytes[i % keyBytes.length]).toString(16).padStart(4, "0"));
  }
  return parts.join("");
}

/**
 * Encrypt every string in the table.
 * @param {string[]}   strings
 * @param {number[]}   keyBytes
 * @returns {string[]}  hex-encoded ciphertexts
 */
function buildStringTable(strings, keyBytes) {
  return strings.map((s) => xorEncrypt(s, keyBytes));
}

/* ------------------------------------------------------------------ */
/*  Runtime decoder generation                                         */
/* ------------------------------------------------------------------ */

/**
 * Produce the JS source for the string decoder infrastructure:
 *   var <table> = ["hex", "hex", ...];
 *   var <key>   = [b0, b1, ...];
 *   function <decoder>(i) { ... }
 *
 * @param {string}   tableName  — variable name for the table
 * @param {string}   keyName    — variable name for the key array
 * @param {string}   decoderName — function name for the decoder
 * @param {string[]} encrypted  — hex-encoded ciphertexts
 * @param {number[]} keyBytes   — XOR key bytes
 * @returns {string}
 */
function generateDecoderSource(tableName, keyName, decoderName, encrypted, keyBytes) {
  const tEntries = encrypted.map((s) => '"' + s + '"').join(",");
  const kEntries = keyBytes.join(",");

  return (
    `var ${tableName}=[${tEntries}];` +
    `var ${keyName}=[${kEntries}];` +
    `function ${decoderName}(i){` +
      `var e=${tableName}[i],r="";` +
      `for(var j=0;j<e.length;j+=4){` +
        `r+=String.fromCharCode(parseInt(e.substr(j,4),16)^${keyName}[(j/4)%${keyName}.length]);` +
      `}` +
      `return r;` +
    `}`
  );
}

/* ------------------------------------------------------------------ */
/*  String replacement                                                 */
/* ------------------------------------------------------------------ */

/**
 * Replace every string literal in `source` with a decoder call.
 * Detects when a string is used as an object literal key (followed by `:`)
 * and wraps the replacement in `[]` for computed property syntax.
 *
 * @param {string}   source
 * @param {string[]} strings     — unescaped string values (same order as table)
 * @param {string}   decoderName
 * @returns {string}
 */
function replaceStrings(source, strings, decoderName) {
  const edits = [];
  require("acorn-walk").ancestor(require("acorn").parse(source, { ecmaVersion: "latest" }), {
    Literal(node, ancestors) {
      if (typeof node.value !== "string" || node.value === "use strict") return;
      const index = strings.indexOf(node.value); if (index < 0) return;
      const parent = ancestors[ancestors.length - 2];
      let value = decoderName + "(" + index + ")";
      if ((parent.type === "Property" || parent.type === "MethodDefinition") && parent.key === node && !parent.computed) value = "[" + value + "]";
      edits.push({ start: node.start, end: node.end, value });
    }
  });
  for (const edit of edits.sort((a,b) => b.start - a.start)) source = source.slice(0,edit.start) + edit.value + source.slice(edit.end);
  return source;
}

/* ------------------------------------------------------------------ */

module.exports = {
  unescapeJS,
  extractStrings,
  generateKey,
  xorEncrypt,
  buildStringTable,
  generateDecoderSource,
  replaceStrings,
};
