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
 * Insert `count` dead code blocks at random positions in the source.
 *
 * Injection points are chosen after lines ending with `;` or `}`,
 * which are safe locations between statements.
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

  const lines = source.split("\n");

  // Find safe injection points.
  const candidates = [];
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed.endsWith(";") || trimmed.endsWith("}")) {
      candidates.push(i);
    }
  }

  // Pick random unique positions.
  const available = [...candidates];
  const chosen = [];
  for (let i = 0; i < Math.min(count, available.length); i++) {
    const idx = crypto.randomInt(available.length);
    chosen.push(available[idx]);
    available.splice(idx, 1);
  }

  // Sort descending so inserts don't shift earlier indices.
  chosen.sort((a, b) => b - a);

  for (let i = 0; i < chosen.length; i++) {
    lines.splice(chosen[i] + 1, 0, blocks[i]);
  }

  return lines.join("\n");
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
