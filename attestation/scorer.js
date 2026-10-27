/**
 * scorer.js — Deterministic Weighted Scoring Pipeline
 *
 * Accepts combined telemetry signals and computes a final risk score
 * from 0.0 (high-confidence bot) to 1.0 (high-confidence human).
 *
 * Signal groups:
 *   1. Runtime Integrity  (weight 0.30)
 *   2. Hardware Consistency (weight 0.20)
 *   3. Kinematics          (weight 0.25)
 *   4. Proof-of-Work       (weight 0.25)
 *
 * Hard-clamp rules:
 *   • runtime.tampered === true        → max score 0.1
 *   • pow.valid === false              → max score 0.1
 *   • runtime.tampered && !pow.valid   → score forced to 0.0
 */

"use strict";

/* ------------------------------------------------------------------ */
/*  Weight configuration                                               */
/* ------------------------------------------------------------------ */

const WEIGHTS = Object.freeze({
  runtime:  0.30,
  hardware: 0.20,
  kinematics: 0.25,
  pow:      0.25,
});

// Sanity-check: weights must sum to 1.0.
const SUM = Object.values(WEIGHTS).reduce((a, b) => a + b, 0);
if (Math.abs(SUM - 1.0) > 1e-9) {
  throw new Error(`BUG: weights sum to ${SUM}, expected 1.0`);
}

/* ------------------------------------------------------------------ */
/*  Per-signal sub-scorers                                             */
/* ------------------------------------------------------------------ */

/**
 * Runtime Integrity sub-score (0–1).
 *
 * Input shape:
 *   { tampered: boolean, signals?: { devtools?: bool, debugger?: bool, ... } }
 */
function scoreRuntime(rt) {
  if (!rt || typeof rt !== "object") return 0;
  if (rt.tampered === true) return 0;

  let score = 1.0;
  const s = rt.signals || {};

  if (s.devtools === true)          score -= 0.40;
  if (s.debugger === true)          score -= 0.30;
  if (s.domManipulation === true)   score -= 0.20;
  if (s.automationAPIs === true)    score -= 0.50;
  if (s.iframeEmbedded === true)    score -= 0.15;
  if (s.consoleOverride === true)   score -= 0.10;

  return clamp01(score);
}

/**
 * Hardware Consistency sub-score (0–1).
 *
 * Input shape:
 *   { consistent: boolean, gpuRenderer?: string, cores?: number,
 *     memory?: number, touchSupport?: boolean, screenConsistent?: boolean }
 */
function scoreHardware(hw) {
  if (!hw || typeof hw !== "object") return 0;
  if (hw.consistent === false) return 0.1;

  let score = 1.0;

  // Headless indicators.
  if (hw.cores === 0 || hw.memory === 0)             score -= 0.50;
  if (typeof hw.gpuRenderer === "string" &&
      /swiftshader|llvmpipe|mesa/i.test(hw.gpuRenderer)) score -= 0.40;
  if (hw.touchSupport === false && hw.mobile === true)  score -= 0.20;
  if (hw.screenConsistent === false)                    score -= 0.15;

  return clamp01(score);
}

/**
 * Kinematics (mouse / touch / keyboard) sub-score (0–1).
 *
 * Input shape:
 *   { humanLike: boolean, entropy?: number (0–1),
 *     straightLineRatio?: number (0–1), eventCount?: number,
 *     avgVelocity?: number, jitter?: number }
 */
function scoreKinematics(kin) {
  if (!kin || typeof kin !== "object") return 0;
  if (kin.humanLike === false) return 0.05;

  let score = 0.5; // baseline: "we have *some* events"

  // Entropy bonus: high entropy → more human-like.
  if (typeof kin.entropy === "number") {
    score += 0.3 * clamp01(kin.entropy);
  }

  // Straight-line penalty: bots tend toward 1.0.
  if (typeof kin.straightLineRatio === "number") {
    score -= 0.2 * clamp01(kin.straightLineRatio);
  }

  // Event count bonus (log-scaled, cap at ~200 events).
  if (typeof kin.eventCount === "number" && kin.eventCount > 0) {
    score += 0.15 * clamp01(Math.log2(kin.eventCount + 1) / 8);
  }

  // Jitter presence is human-like.
  if (typeof kin.jitter === "number" && kin.jitter > 0.5) {
    score += 0.05;
  }

  return clamp01(score);
}

/**
 * Proof-of-Work sub-score (0–1).
 *
 * Input shape:
 *   { valid: boolean, durationMs?: number, difficulty?: number }
 */
function scorePoW(pow) {
  if (!pow || typeof pow !== "object") return 0;
  if (pow.valid !== true) return 0;

  let score = 0.80; // valid PoW = strong baseline

  // Duration reasonableness: if it was solved suspiciously fast for
  // the given difficulty, dock some trust (ASICs / GPU farms).
  if (typeof pow.durationMs === "number" && typeof pow.difficulty === "number") {
    // Expected time ≈ 2^difficulty * ~2µs per hash (rough heuristic).
    const expectedMs = Math.pow(2, pow.difficulty) * 0.002;
    const ratio = pow.durationMs / Math.max(expectedMs, 1);
    if (ratio < 0.01) {
      // Solved >100× faster than expected — suspicious.
      score -= 0.30;
    } else if (ratio < 0.1) {
      score -= 0.10;
    } else {
      score += 0.20; // normal range — full credit.
    }
  } else {
    score += 0.10; // no timing data but valid proof — still decent.
  }

  return clamp01(score);
}

/* ------------------------------------------------------------------ */
/*  Main scoring function                                              */
/* ------------------------------------------------------------------ */

/**
 * @typedef {Object} TelemetryPayload
 * @property {Object} [runtime]
 * @property {Object} [hardware]
 * @property {Object} [kinematics]
 * @property {Object} [pow]
 */

/**
 * Compute the composite risk score.
 *
 * @param {TelemetryPayload} payload
 * @returns {{ score: number, breakdown: Object, clamped: boolean, clampReason?: string }}
 */
function computeScore(payload) {
  if (!payload || typeof payload !== "object") {
    return { score: 0.0, breakdown: {}, clamped: true, clampReason: "missing payload" };
  }

  const rt  = scoreRuntime(payload.runtime);
  const hw  = scoreHardware(payload.hardware);
  const kin = scoreKinematics(payload.kinematics);
  const pw  = scorePoW(payload.pow);

  const breakdown = {
    runtime:    { raw: rt,  weighted: round4(rt  * WEIGHTS.runtime)  },
    hardware:   { raw: hw,  weighted: round4(hw  * WEIGHTS.hardware) },
    kinematics: { raw: kin, weighted: round4(kin * WEIGHTS.kinematics) },
    pow:        { raw: pw,  weighted: round4(pw  * WEIGHTS.pow)      },
  };

  let score =
    rt  * WEIGHTS.runtime +
    hw  * WEIGHTS.hardware +
    kin * WEIGHTS.kinematics +
    pw  * WEIGHTS.pow;

  // ── Hard clamps ───────────────────────────────────────────────────
  let clamped = false;
  let clampReason;

  const tampered = payload.runtime?.tampered === true;
  const powFailed = !payload.pow || payload.pow.valid !== true;

  if (tampered && powFailed) {
    score = 0.0;
    clamped = true;
    clampReason = "runtime tampered AND PoW failed";
  } else if (tampered) {
    score = Math.min(score, 0.1);
    clamped = true;
    clampReason = "runtime tampered";
  } else if (powFailed) {
    score = Math.min(score, 0.1);
    clamped = true;
    clampReason = "PoW validation failed";
  }

  score = round4(clamp01(score));

  const result = { score, breakdown, clamped };
  if (clampReason) result.clampReason = clampReason;
  return result;
}

/* ------------------------------------------------------------------ */
/*  Utilities                                                          */
/* ------------------------------------------------------------------ */

function clamp01(v) {
  return Math.max(0, Math.min(1, v));
}

function round4(v) {
  return Math.round(v * 10000) / 10000;
}

/* ------------------------------------------------------------------ */
/*  Exports                                                            */
/* ------------------------------------------------------------------ */

module.exports = {
  computeScore,
  WEIGHTS,
  // Exported for unit testing individual sub-scorers:
  _scoreRuntime: scoreRuntime,
  _scoreHardware: scoreHardware,
  _scoreKinematics: scoreKinematics,
  _scorePoW: scorePoW,
};
