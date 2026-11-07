/**
 * test_compiler.js — Comprehensive Tests for the Polymorphic Compiler
 *
 * Run:  node compiler/test_compiler.js
 *
 * Tests: string table, identifier randomization, dead code, ECDH,
 *        full pipeline, polymorphism, and obfuscation quality.
 */

"use strict";

const crypto = require("node:crypto");

let passed = 0;
let failed = 0;

function assert(cond, label) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else      { failed++; console.error(`  ✗ ${label}`); }
}

function assertClose(a, b, label, eps = 0.01) {
  assert(Math.abs(a - b) < eps, `${label} (got ${a}, want ~${b})`);
}

/* ================================================================== */
console.log("\n══ string_table.js ══");
/* ================================================================== */

const {
  unescapeJS, extractStrings, generateKey, xorEncrypt,
  buildStringTable, generateDecoderSource, replaceStrings,
} = require("./string_table");

// unescapeJS
assert(unescapeJS("hello") === "hello", "unescape plain string");
assert(unescapeJS("line1\\nline2") === "line1\nline2", "unescape \\n");
assert(unescapeJS("tab\\there") === "tab\there", "unescape \\t");
assert(unescapeJS("quote\\\"end") === 'quote"end', "unescape \\\"");
assert(unescapeJS("back\\\\slash") === "back\\slash", "unescape \\\\");
assert(unescapeJS("\\x41\\x42") === "AB", "unescape \\xNN");
assert(unescapeJS("\\u0041") === "A", "unescape \\uNNNN");

// extractStrings
{
  const src = `var x = "hello"; var y = 'world'; var z = "";`;
  const strs = extractStrings(src);
  assert(strs.includes("hello"), "extracts double-quoted strings");
  assert(strs.includes("world"), "extracts single-quoted strings");
  assert(!strs.includes(""), "skips empty strings");
}

// extractStrings skips "use strict"
{
  const src = `"use strict"; var x = "test";`;
  const strs = extractStrings(src);
  assert(!strs.includes("use strict"), "skips 'use strict' directive");
  assert(strs.includes("test"), "still extracts other strings");
}

// extractStrings handles escape sequences in strings
{
  const src = `var x = "hello\\nworld";`;
  const strs = extractStrings(src);
  assert(strs.length === 1, "one string extracted");
  assert(strs[0] === "hello\nworld", "escape sequences resolved");
}

// XOR encrypt/decrypt round-trip
{
  const key = generateKey(16);
  const original = "testString123!@#";
  const encrypted = xorEncrypt(original, key);
  assert(typeof encrypted === "string", "xorEncrypt returns string");
  assert(encrypted.length === original.length * 4, "hex length = 4 * char count");

  // Decrypt manually
  let decrypted = "";
  for (let j = 0; j < encrypted.length; j += 4) {
    decrypted += String.fromCharCode(
      parseInt(encrypted.substr(j, 4), 16) ^ key[(j / 4) % key.length]
    );
  }
  assert(decrypted === original, "XOR round-trip preserves original");
}

// Decoder function evaluation
{
  const strings = ["hello", "world", "userAgent"];
  const key = generateKey(32);
  const encrypted = buildStringTable(strings, key);
  const decoderSrc = generateDecoderSource("T", "K", "D", encrypted, key);

  // Evaluate the decoder in a V8 function scope
  for (let i = 0; i < strings.length; i++) {
    const fn = new Function(`${decoderSrc}\nreturn D(${i});`);
    const result = fn();
    assert(result === strings[i], `decoder(${i}) returns "${strings[i]}"`);
  }
}

// replaceStrings
{
  const src = `var x = "hello"; if (obj["key"]) { y("world"); }`;
  const strs = extractStrings(src);
  const replaced = replaceStrings(src, strs, "D");
  assert(!replaced.includes('"hello"'), '"hello" replaced');
  assert(!replaced.includes('"key"'), '"key" replaced');
  assert(!replaced.includes('"world"'), '"world" replaced');
  assert(replaced.includes("D("), "decoder calls inserted");
}

/* ================================================================== */
console.log("\n══ identifiers.js ══");
/* ================================================================== */

const {
  extractIdentifiers, generateRandomName, generateMapping, applyMapping, RESERVED,
} = require("./identifiers");

// extractIdentifiers
{
  const src = `function fooBar() { var myVar = 1; const baz = 2; let qux = 3; }`;
  const ids = extractIdentifiers(src);
  assert(ids.includes("fooBar"), "extracts function name");
  assert(ids.includes("myVar"), "extracts var name");
  assert(ids.includes("baz"), "extracts const name");
  assert(ids.includes("qux"), "extracts let name");
}

// Does not extract reserved words
{
  const src = `function test() { var window = 1; var x = undefined; }`;
  const ids = extractIdentifiers(src);
  assert(!ids.includes("window"), "skips 'window' (reserved)");
  assert(!ids.includes("undefined"), "skips 'undefined' (reserved)");
  assert(ids.includes("test"), "extracts 'test' (not reserved)");
}

// generateRandomName
{
  const names = new Set();
  for (let i = 0; i < 100; i++) names.add(generateRandomName());
  assert(names.size === 100, "100 unique random names generated");
  for (const n of names) {
    assert(/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(n), `valid identifier: ${n}`);
  }
}

// applyMapping
{
  const src = `function foo(bar) { return foo(bar + 1); }`;
  const mapping = { foo: "xK3m", bar: "yL4n" };
  const result = applyMapping(src, mapping);
  assert(result.includes("xK3m"), "foo → xK3m");
  assert(result.includes("yL4n"), "bar → yL4n");
  assert(!result.includes("foo"), "original 'foo' removed");
  assert(!result.includes("bar"), "original 'bar' removed");
}

// applyMapping does not corrupt substrings
{
  const src = `var ab = 1; var abc = 2; var a = ab + abc;`;
  const mapping = { ab: "XX", abc: "YY" };
  const result = applyMapping(src, mapping);
  assert(result.includes("XX"), "ab → XX");
  assert(result.includes("YY"), "abc → YY");
  // 'a' should not be affected (single char, not in mapping)
  assert(result.includes("var a ="), "'a' unchanged (not in mapping)");
}

/* ================================================================== */
console.log("\n══ dead_code.js ══");
/* ================================================================== */

const {
  generateOpaqueTrue, generateOpaqueFalse, generateDeadBlock, injectDeadCode,
} = require("./dead_code");

// Opaque predicates evaluate correctly
{
  for (let i = 0; i < 20; i++) {
    const trueExpr = generateOpaqueTrue();
    const trueVal = new Function(`return ${trueExpr}`)();
    assert(trueVal === true, `opaqueTrue: ${trueExpr}`);
  }
  for (let i = 0; i < 20; i++) {
    const falseExpr = generateOpaqueFalse();
    const falseVal = new Function(`return ${falseExpr}`)();
    assert(falseVal === false, `opaqueFalse: ${falseExpr}`);
  }
}

// Dead code blocks are syntactically valid JS
{
  let n = 0;
  const ng = () => `_dead${n++}`;
  for (let i = 0; i < 10; i++) {
    const block = generateDeadBlock(ng);
    let valid = true;
    try { new Function(block); } catch { valid = false; }
    assert(valid, `dead block ${i} is valid JS`);
  }
}

// injectDeadCode increases source length
{
  let n = 0;
  const ng = () => `_d${n++}`;
  const src = `var a = 1;\nvar b = 2;\nvar c = a + b;`;
  const injected = injectDeadCode(src, 3, ng);
  assert(injected.length > src.length, "dead code injection increases length");
  // Injected code is still valid JS
  let valid = true;
  try { new Function(injected); } catch { valid = false; }
  assert(valid, "injected source remains valid JS");
}

/* ================================================================== */
console.log("\n══ ecdh_session.js ══");
/* ================================================================== */

const {
  generateEphemeralKeyPair, generateClientECDHCode,
} = require("./ecdh_session");

// Key pair generation
{
  const kp = generateEphemeralKeyPair();
  assert(kp.publicKey !== null, "public key generated");
  assert(kp.privateKey !== null, "private key generated");
  assert(typeof kp.publicKeyBase64 === "string" && kp.publicKeyBase64.length > 20,
    "base64 public key is non-trivial string");
  assert(typeof kp.id === "string" && kp.id.length === 16,
    "session ID is 16-char hex");
}

// Two key pairs are different
{
  const kp1 = generateEphemeralKeyPair();
  const kp2 = generateEphemeralKeyPair();
  assert(kp1.publicKeyBase64 !== kp2.publicKeyBase64, "two key pairs differ");
  assert(kp1.id !== kp2.id, "two session IDs differ");
}

// Client ECDH code is valid JS
{
  const kp = generateEphemeralKeyPair();
  const code = generateClientECDHCode(kp.publicKeyBase64, kp.id, "testECDH");
  let valid = true;
  try { new Function(code); } catch { valid = false; }
  assert(valid, "generated ECDH client code is valid JS");
  assert(code.includes("testECDH"), "uses provided function name");
}

/* ================================================================== */
console.log("\n══ pipeline.js (full compilation) ══");
/* ================================================================== */

const { compile, preprocess } = require("./pipeline");

// preprocess strips comments and use strict
{
  const src = `"use strict";\n// comment\nvar x = 1; /* block */\nvar y = 2;`;
  const pp = preprocess(src);
  assert(!pp.includes("use strict"), "strips 'use strict'");
  assert(!pp.includes("// comment"), "strips single-line comment");
  assert(!pp.includes("/* block */"), "strips block comment");
  assert(pp.includes("var x = 1"), "preserves code");
}

// Minimal compile with test source
{
  const testSource = `
function testFn(argOne) {
  var localVar = "secretString";
  var result = {};
  result["key"] = argOne;
  return result;
}
`;
  const { bundle, buildId, stats } = compile({
    rawSourceOverride: testSource,
    includeECDH: false,
    deadCodeBlocks: 2,
  });

  assert(typeof bundle === "string" && bundle.length > 0, "bundle is non-empty string");
  assert(typeof buildId === "string" && buildId.length === 16, "buildId is 16-char hex");
  assert(stats.strings > 0, `string table has ${stats.strings} entries`);
  assert(stats.identifiers > 0, `${stats.identifiers} identifiers randomized`);
  assert(stats.bytes > 0, `bundle is ${stats.bytes} bytes`);

  // Bundle is valid JS (parseable by V8)
  let valid = true;
  try { new Function(bundle); } catch (e) { valid = false; console.error("    parse error:", e.message); }
  assert(valid, "compiled bundle is valid JS");

  // Original identifiers are NOT in the output
  assert(!bundle.includes("testFn"), "'testFn' obfuscated away");
  assert(!bundle.includes("argOne"), "'argOne' obfuscated away");
  assert(!bundle.includes("localVar"), "'localVar' obfuscated away");

  // Original string literals are NOT in the output
  assert(!bundle.includes('"secretString"'), '"secretString" encrypted away');
  assert(!bundle.includes("'secretString'"), "'secretString' encrypted away");
  assert(!bundle.includes('"key"'), '"key" encrypted away');
}

// Full compile with real source modules
{
  let fullBundle, fullStats;
  try {
    const result = compile({ includeECDH: true, deadCodeBlocks: 6 });
    fullBundle = result.bundle;
    fullStats = result.stats;
    assert(true, `full compile succeeded (${fullStats.bytes} bytes)`);

    // Validate it parses
    let valid = true;
    try { new Function(fullBundle); } catch (e) { valid = false; console.error("    parse error:", e.message); }
    assert(valid, "full bundle is valid JS");

    // Check known detector strings are encrypted
    const sensitiveStrings = [
      "callPhantom", "__nightmare", "webdriver", "__puppeteer_evaluation_script__",
      "WEBGL_debug_renderer_info", "UNMASKED_RENDERER_WEBGL",
      "hardwareConcurrency", "deviceMemory", "userAgent",
      "mousemove", "SHA-256",
    ];
    for (const s of sensitiveStrings) {
      assert(!fullBundle.includes(`"${s}"`), `"${s}" not visible in bundle`);
    }

    // Check original function names are gone
    const origNames = [
      "collectRuntime", "collectHardware", "createKinematics", "solvePoW",
    ];
    for (const n of origNames) {
      assert(!fullBundle.includes(n), `"${n}" renamed in bundle`);
    }

    assert(fullStats.strings > 30, `${fullStats.strings} strings encrypted (expect >30)`);
    assert(fullStats.identifiers > 10, `${fullStats.identifiers} identifiers randomized (expect >10)`);
  } catch (err) {
    assert(false, `full compile failed: ${err.message}`);
  }
}

// POLYMORPHISM: two compilations of the same source produce different output
{
  const src = `function myFn() { var val = "test"; return val; }`;
  const r1 = compile({ rawSourceOverride: src, includeECDH: false, deadCodeBlocks: 2 });
  const r2 = compile({ rawSourceOverride: src, includeECDH: false, deadCodeBlocks: 2 });

  assert(r1.buildId !== r2.buildId, "different build IDs");
  assert(r1.bundle !== r2.bundle, "bundles are NOT identical (polymorphic)");

  // But both are valid JS
  let v1 = true, v2 = true;
  try { new Function(r1.bundle); } catch { v1 = false; }
  try { new Function(r2.bundle); } catch { v2 = false; }
  assert(v1 && v2, "both polymorphic builds are valid JS");
}

/* ================================================================== */
console.log("\n══ middleware.js (SessionStore) ══");
/* ================================================================== */

const { SessionStore } = require("./middleware");

{
  const store = new SessionStore(100, 5000);
  const kp = generateEphemeralKeyPair();

  store.set("sess1", kp);
  assert(store.size === 1, "store has 1 session");

  const retrieved = store.consume("sess1");
  assert(retrieved !== null, "session retrieved");
  assert(retrieved.id === kp.id, "correct key pair returned");
  assert(store.size === 0, "session consumed (removed)");

  const again = store.consume("sess1");
  assert(again === null, "replay returns null");

  const unknown = store.consume("nonexistent");
  assert(unknown === null, "unknown session returns null");
}

// Capacity eviction
{
  const store = new SessionStore(3, 60000);
  for (let i = 0; i < 5; i++) {
    store.set(`s${i}`, generateEphemeralKeyPair());
  }
  assert(store.size <= 3, `store capped at maxSize (size=${store.size})`);
}

/* ================================================================== */

console.log(`\n${"═".repeat(55)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
