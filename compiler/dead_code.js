/**
 * dead_code.js — Dead Code & Opaque Predicate Generator
 *
 * Injects syntactically valid but semantically unreachable code blocks
 * guarded by opaque predicates (expressions that always evaluate to a
 * known boolean but resist static analysis).
 */

"use strict";

const crypto = require("node:crypto");

/* ------------------------------------------------------------------ */
/*  Opaque predicates                                                  */
/* ------------------------------------------------------------------ */

/** Returns a JS expression string that always evaluates to `true`. */
function generateOpaqueTrue() {
  const templates = [
    () => {
      const a = 2 + crypto.randomInt(98);
      return `(Math.sqrt(${a * a})>${a - 1})`;
    },
    () => {
      const n = 1 + crypto.randomInt(50);
      return `((${n}*${n}+${n})%${n}===0)`;
    },
    () => `(typeof undefined==="undefined")`,
    () => {
      const a = 1 + crypto.randomInt(100);
      return `((${a}|0)===${a})`;
    },
    () => `(Date.now()>0)`,
    () => {
      const x = 1 + crypto.randomInt(254);
      return `((${x}^${x})===0)`;
    },
    () => `((""+[])===(""))`,
    () => {
      const a = 2 + crypto.randomInt(50);
      return `(Math.abs(${-a})===${a})`;
    },
    () => `((0.1+0.2)!==0.3)`,           // IEEE 754 quirk — always true
    () => `(Math.PI>3)`,
    () => {
      const a = 1 + crypto.randomInt(30);
      const b = a + 1 + crypto.randomInt(30);
      return `(${a}<${b})`;
    },
  ];
  return templates[crypto.randomInt(templates.length)]();
}

/** Returns a JS expression string that always evaluates to `false`. */
function generateOpaqueFalse() {
  const templates = [
    () => {
      const a = 2 + crypto.randomInt(98);
      return `(Math.sqrt(${a * a + 1})<${a})`;
    },
    () => `(typeof undefined==="number")`,
    () => {
      const a = 1 + crypto.randomInt(100);
      return `(${a}!==${a})`;
    },
    () => `(NaN===NaN)`,
    () => `(null===undefined)`,
    () => `(""!=="")`,
    () => `(Math.PI<3)`,
    () => {
      const a = 1 + crypto.randomInt(100);
      return `((${a}^0)!==${a})`;
    },
  ];
  return templates[crypto.randomInt(templates.length)]();
}

/* ------------------------------------------------------------------ */
/*  Dead code block generation                                         */
/* ------------------------------------------------------------------ */

/**
 * Generate a realistic-looking dead variable declaration.
 * @param {Function} nameGen — () => randomName
 * @returns {string}
 */
function generateDeadVar(nameGen) {
  const ops = [
    () => `${crypto.randomInt(1000000)}`,
    () => `${crypto.randomInt(100)}*${crypto.randomInt(100)}+${crypto.randomInt(10)}`,
    () => `Math.floor(Math.random()*${1 + crypto.randomInt(9999)})`,
    () => `(${crypto.randomInt(255)}^${crypto.randomInt(255)})`,
    () => `"${crypto.randomBytes(8).toString("hex")}"`,
  ];
  return `var ${nameGen()}=${ops[crypto.randomInt(ops.length)]()};`;
}

/**
 * Generate a realistic-looking dead function.
 * @param {Function} nameGen
 * @returns {string}
 */
function generateDeadFunction(nameGen) {
  const fn = nameGen();
  const p1 = nameGen();
  const p2 = nameGen();
  const local = nameGen();
  const ops = ["+", "-", "^", "|", "&", ">>>"];
  const op = ops[crypto.randomInt(ops.length)];
  const c = 1 + crypto.randomInt(999);
  return (
    `function ${fn}(${p1},${p2}){` +
    `var ${local}=${p1}${op}${c};` +
    `return ${local}>${p2}?${local}:${p2};` +
    `}`
  );
}

/**
 * Generate a dead code block guarded by an opaque false predicate.
 * @param {Function} nameGen
 * @param {number}   [stmts=3] — statements inside the block
 * @returns {string}
 */
function generateDeadBlock(nameGen, stmts) {
  const count = stmts || (2 + crypto.randomInt(4));
  const useFalse = crypto.randomInt(2) === 0;
  const predicate = useFalse ? generateOpaqueFalse() : `!(${generateOpaqueTrue()})`;

  const lines = [`if(${predicate}){`];
  for (let i = 0; i < count; i++) {
    lines.push(crypto.randomInt(2) === 0 ? generateDeadVar(nameGen) : generateDeadFunction(nameGen));
  }
  lines.push("}");
  return lines.join("\n");
}

/* ------------------------------------------------------------------ */
/*  Injection engine                                                   */
/* ------------------------------------------------------------------ */

/**
 * Insert `count` randomized dead code blocks at the program boundary.
 *
 * @param {string}   source
 * @param {number}   count
 * @param {Function} nameGen — () => uniqueRandomName
 * @returns {string}
 */
function injectDeadCode(source, count, nameGen) {
  const blocks = [];
  for (let i = 0; i < count; i++) {
    blocks.push(generateDeadBlock(nameGen));
  }

  // Only inject at the known program boundary. A line ending in } can be
  // an object literal or the middle of an if/else or try/catch statement.
  return blocks.join("\n") + "\n" + source;
}

/* ------------------------------------------------------------------ */

module.exports = {
  generateOpaqueTrue,
  generateOpaqueFalse,
  generateDeadBlock,
  generateDeadVar,
  generateDeadFunction,
  injectDeadCode,
};
