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
  const seen = new Set();
  const result = [];
  let m;
  while ((m = STRING_RE.exec(source)) !== null) {
    const raw = m[0];
    const inner = raw.slice(1, -1);
    if (inner.length === 0) continue;           // skip empty strings
    const value = unescapeJS(inner);
    if (value === "use strict") continue;        // preserve directives
    if (!seen.has(value)) {
      seen.add(value);
      result.push(value);
    }
  }
  return result;
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
    if (code > 127) {
      throw new RangeError(
        `Non-ASCII char U+${code.toString(16).toUpperCase()} at pos ${i} — ` +
        `source modules must use ASCII-only strings`
      );
    }
    parts.push((code ^ keyBytes[i % keyBytes.length]).toString(16).padStart(2, "0"));
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
      `for(var j=0;j<e.length;j+=2){` +
        `r+=String.fromCharCode(parseInt(e.substr(j,2),16)^${keyName}[(j/2)%${keyName}.length]);` +
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
  // Map from unescaped value → table index
  const indexMap = new Map();
  strings.forEach((s, i) => indexMap.set(s, i));

  return source.replace(STRING_RE, (match, offset) => {
    const inner = match.slice(1, -1);
    if (inner.length === 0) return match;
    const value = unescapeJS(inner);
    if (value === "use strict") return match;
    if (!indexMap.has(value)) return match;

    const call = `${decoderName}(${indexMap.get(value)})`;

    // Check if this string literal is an object key:
    // skip whitespace after the match and see if the next char is `:` (but not `::`)
    const after = source.substring(offset + match.length);
    const colonMatch = after.match(/^\s*:/);
    if (colonMatch) {
      // Also check it's not a ternary — look behind for `?` on the same expression.
      // A simple heuristic: if the char before the string (ignoring whitespace) is
      // `,`, `{`, or start-of-line, it's likely an object key.
      const before = source.substring(Math.max(0, offset - 20), offset);
      const trimBefore = before.replace(/\s+$/, "");
      const lastChar = trimBefore[trimBefore.length - 1];
      if (lastChar === "{" || lastChar === "," || lastChar === "(" || offset === 0) {
        return `[${call}]`;
      }
    }

    return call;
  });
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
