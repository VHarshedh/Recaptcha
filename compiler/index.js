/**
 * compiler/index.js — Polymorphic Obfuscation & Bundling Subsystem
 *
 * Compiles unique, polymorphic client bundles per request with:
 *   - Ephemeral ECDH key agreement
 *   - Control-flow flattening & VM state machine
 *   - Dynamic XOR string encryption table
 *   - Cryptographic identifier randomization
 *   - Opaque-predicate dead code injection
 *   - Anti-hooking primitives for Web Crypto & JSON
 */

"use strict";

const pipeline = require("./pipeline");
const middleware = require("./middleware");
const ecdh = require("./ecdh_session");
const deadCode = require("./dead_code");
const identifiers = require("./identifiers");
const stringTable = require("./string_table");

module.exports = {
  // Main compilation & pipeline
  compile: pipeline.compile,
  preprocess: pipeline.preprocess,
  createNameGenerator: pipeline.createNameGenerator,
  ROOT_DIR: pipeline.ROOT_DIR,

  // Middleware & session handling
  createMiddleware: middleware.createMiddleware,
  createDecryptHandler: middleware.createDecryptHandler,
  SessionStore: middleware.SessionStore,

  // Cryptographic session & key derivation
  generateEphemeralKeyPair: ecdh.generateEphemeralKeyPair,
  generateClientECDHCode: ecdh.generateClientECDHCode,
  decryptTelemetry: ecdh.decryptTelemetry,
  deriveSessionKey: ecdh.deriveSessionKey,

  // Obfuscation passes
  deadCode: {
    generateOpaqueTrue: deadCode.generateOpaqueTrue,
    generateOpaqueFalse: deadCode.generateOpaqueFalse,
    generateDeadBlock: deadCode.generateDeadBlock,
    injectDeadCode: deadCode.injectDeadCode,
  },
  identifiers: {
    extractIdentifiers: identifiers.extractIdentifiers,
    generateRandomName: identifiers.generateRandomName,
    generateMapping: identifiers.generateMapping,
    applyMapping: identifiers.applyMapping,
    RESERVED: identifiers.RESERVED,
  },
  stringTable: {
    extractStrings: stringTable.extractStrings,
    generateKey: stringTable.generateKey,
    xorEncrypt: stringTable.xorEncrypt,
    buildStringTable: stringTable.buildStringTable,
    generateDecoderSource: stringTable.generateDecoderSource,
    replaceStrings: stringTable.replaceStrings,
  },
};
