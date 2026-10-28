/**
 * scorer.js — Server-Side Raw Telemetry Scoring Pipeline
 *
 * Accepts raw feature vectors from the advanced client collectors and
 * computes a final risk score from 0.0 (bot) to 1.0 (human).
 *
 * CRITICAL: This module NEVER trusts client-computed booleans like
 * `tampered`, `consistent`, or `humanLike`. All thresholds and
 * pass/fail decisions are computed server-side from raw signal data.
 *
 * Signal groups:
 *   1. Runtime Integrity   (weight 0.30) — confidence_penalty, anomalies
 *   2. Hardware Consistency (weight 0.20) — WebGL, audio, geometry, anomalies
 *   3. Kinematics           (weight 0.25) — jerk, entropy, spectrum, eventCounts
 *   4. Proof-of-Work        (weight 0.25) — server-verified nonce
 *
 * Hard-clamp rules:
 *   • runtime penalty >= 0.5              → max score 0.1
 *   • pow.serverVerified !== true         → max score 0.1
 *   • both runtime tampered AND PoW fail  → score forced to 0.0
 */

"use strict";

/* ------------------------------------------------------------------ */
/*  Weight configuration                                               */
/* ------------------------------------------------------------------ */

const WEIGHTS = Object.freeze({
  runtime:    0.30,
  hardware:   0.20,
  kinematics: 0.25,
  pow:        0.25,
});

// Sanity-check: weights must sum to 1.0.
const SUM = Object.values(WEIGHTS).reduce((a, b) => a + b, 0);
if (Math.abs(SUM - 1.0) > 1e-9) {
  throw new Error(`BUG: weights sum to ${SUM}, expected 1.0`);
}

/* ------------------------------------------------------------------ */
/*  Per-signal sub-scorers (raw telemetry — NO client booleans)        */
/* ------------------------------------------------------------------ */

/**
 * Runtime Integrity sub-score (0–1).
 *
 * Input: raw output from root-level RuntimeIntegrity.collect():
 *   { tampering_detected: bool, anomalies: string[], confidence_penalty: number }
 *
 * The confidence_penalty is computed from corroborated anomaly groups
 * (V8 receiver checks, native-function toString, Plugin/MIME graphs,
 * automation globals, stack inspection).  We use it directly as the
 * trust-reduction signal.  tampering_detected = (penalty >= 0.5).
 */
function scoreRuntime(rt) {
  if (!rt || typeof rt !== "object") return 0;

  const penalty = typeof rt.confidence_penalty === "number"
    ? clamp01(rt.confidence_penalty)
    : 1;

  // If the advanced collector determined tampering (penalty >= 0.5), hard-cap.
  if (penalty >= 0.5) return clamp01(0.15 * (1 - penalty));

  // Proportional reduction from anomalies.
  let score = 1.0 - penalty * 0.8;

  // Additional signal: count of anomalies as a breadth indicator.
  if (Array.isArray(rt.anomalies) && rt.anomalies.length > 5) {
    score -= 0.1 * clamp01((rt.anomalies.length - 5) / 10);
  }

  return clamp01(score);
}

/**
 * Hardware Consistency sub-score (0–1).
 *
 * Input: raw output from root-level HardwareConsistency.collect():
 *   { version, profile, webgl, audio, fonts, geometry,
 *     anomalies: [{probe,code,detail,strength}], timing, consistency }
 */
function scoreHardware(hw) {
  if (!hw || typeof hw !== "object") return 0;

  let score = 1.0;

  // ── WebGL signals ─────────────────────────────────────────────────
  if (hw.webgl && typeof hw.webgl === "object") {
    if (Array.isArray(hw.webgl.softwareRasterizers) &&
        hw.webgl.softwareRasterizers.length > 0) {
      score -= 0.35;
    }
    if (hw.webgl.legacyDirect3D9 === true) {
      score -= 0.10;
    }
    if (hw.webgl.status === "unavailable") {
      score -= 0.15;
    }
  }

  // ── Audio probe ───────────────────────────────────────────────────
  if (hw.audio && typeof hw.audio === "object") {
    if (hw.audio.silent === true) score -= 0.15;
    if (hw.audio.status === "error") score -= 0.10;
  }

  // ── Profile checks ───────────────────────────────────────────────
  if (hw.profile && typeof hw.profile === "object") {
    if (hw.profile.hardwareConcurrency === 0 ||
        hw.profile.hardwareConcurrency === null) {
      score -= 0.30;
    }
  }

  // ── Geometry checks ───────────────────────────────────────────────
  if (hw.geometry && typeof hw.geometry === "object" && hw.geometry.checks) {
    const checks = hw.geometry.checks;
    if (checks.outerAtLeastInner === false)     score -= 0.05;
    if (checks.availableWithinScreen === false) score -= 0.05;
  }

  // ── Structured anomalies from the advanced collector ──────────────
  if (Array.isArray(hw.anomalies)) {
    const moderate = hw.anomalies.filter(a => a.strength === "moderate").length;
    const weak     = hw.anomalies.filter(a => a.strength === "weak").length;
    score -= moderate * 0.15;
    score -= weak * 0.03;
  }

  // ── Overall consistency assessment ────────────────────────────────
  if (hw.consistency === "discrepancies_observed") {
    score -= 0.10;
  }

  return clamp01(score);
}

/**
 * Kinematics sub-score (0–1).
 *
 * Input: raw output from root-level Kinematics.getBiometricVector():
 *   { version, running, historyCount, historyCapacity,
 *     eventCounts: { mousemove, touchstart, ..., rejectedUntrusted, ... },
 *     mouse: { pointCount, velocity, acceleration, jerk, entropyRatio,
 *              zeroJerkRatio, nearConstantJerkRatio, tremorSpectrum,
 *              ballisticHomingScore, ... },
 *     touch: { ... same ... },
 *     typing: { dwell: {milliseconds,normalized,coefficientOfVariation},
 *               interval: {...}, flight: {...} },
 *     flags: [ { code, evidence } ] }
 */
function scoreKinematics(kin) {
  if (!kin || typeof kin !== "object") return 0;

  let score = 0.25; // baseline: "script loaded and captured something"

  const counts = kin.eventCounts || {};
  const totalEvents = countInteractions(counts);

  // ── Untrusted event rejection ─────────────────────────────────────
  // dispatchEvent() / new MouseEvent() have isTrusted=false.
  // The advanced kinematics module rejects and counts them.
  if (typeof counts.rejectedUntrusted === "number" &&
      counts.rejectedUntrusted > 0 && totalEvents > 0) {
    const untrustedRatio =
      counts.rejectedUntrusted / (totalEvents + counts.rejectedUntrusted);
    score -= 0.25 * clamp01(untrustedRatio);
  }

  // ── Event count bonus (log-scaled) ────────────────────────────────
  if (totalEvents > 0) {
    score += 0.12 * clamp01(Math.log2(totalEvents + 1) / 8);
  } else {
    score -= 0.10;
  }

  // ── Mouse movement analysis ───────────────────────────────────────
  const mouse = kin.mouse;
  if (mouse && typeof mouse === "object" && mouse.pointCount > 8) {
    // Angular entropy — high entropy means varied direction changes (human).
    if (typeof mouse.entropyRatio === "number") {
      score += 0.12 * clamp01(mouse.entropyRatio);
    }

    // Zero jerk ratio — exactly zero third derivative = polynomial path.
    if (typeof mouse.zeroJerkRatio === "number" && mouse.zeroJerkRatio > 0.8) {
      score -= 0.18;
    }

    // Near-constant jerk — bezier/linear interpolation.
    if (typeof mouse.nearConstantJerkRatio === "number" &&
        mouse.nearConstantJerkRatio > 0.9) {
      score -= 0.12;
    }

    // Tremor spectrum 8–12 Hz band — human physiological tremor.
    if (mouse.tremorSpectrum && typeof mouse.tremorSpectrum === "object" &&
        typeof mouse.tremorSpectrum.band8to12HzRatio === "number") {
      score += 0.08 * clamp01(mouse.tremorSpectrum.band8to12HzRatio * 5);
    }

    // Ballistic homing (bell-shaped velocity profile around peak).
    if (typeof mouse.ballisticHomingScore === "number") {
      score += 0.05 * clamp01(mouse.ballisticHomingScore);
    }

    // Velocity variance — too uniform = robotic.
    if (mouse.velocity && typeof mouse.velocity.variance === "number" &&
        mouse.velocity.count >= 10 && mouse.velocity.variance < 1e-6) {
      score -= 0.10;
    }
  }

  // ── Touch movement (same signals as mouse) ────────────────────────
  const touch = kin.touch;
  if (touch && typeof touch === "object" && touch.pointCount > 8) {
    if (typeof touch.entropyRatio === "number") {
      score += 0.08 * clamp01(touch.entropyRatio);
    }
    if (typeof touch.zeroJerkRatio === "number" && touch.zeroJerkRatio > 0.8) {
      score -= 0.12;
    }
  }

  // ── Typing cadence ────────────────────────────────────────────────
  if (kin.typing && typeof kin.typing === "object") {
    for (const field of ["dwell", "interval", "flight"]) {
      const data = kin.typing[field];
      if (data && data.milliseconds && data.milliseconds.count >= 8) {
        // Human typing has natural variation in cadence.
        if (typeof data.coefficientOfVariation === "number" &&
            data.coefficientOfVariation > 0.1) {
          score += 0.03;
        }
        // Suspiciously uniform (robot / macro).
        if (typeof data.coefficientOfVariation === "number" &&
            data.coefficientOfVariation < 0.02 &&
            data.milliseconds.count >= 12) {
          score -= 0.05;
        }
      }
    }
  }

  // ── Flags from kinematics module ──────────────────────────────────
  if (Array.isArray(kin.flags)) {
    score -= 0.04 * Math.min(kin.flags.length, 4);
  }

  return clamp01(score);
}

/**
 * Proof-of-Work sub-score (0–1).
 *
 * Input (set exclusively by the server after cryptographic verification):
 *   { serverVerified: bool, difficulty: number, durationMs: number,
 *     reason?: string, hash?: string }
 *
 * The `serverVerified` flag is set by the server's verifyPoW() call —
 * NOT by anything the client sends.
 */
function scorePoW(pow) {
  if (!pow || typeof pow !== "object") return 0;
  if (pow.serverVerified !== true) return 0;

  let score = 0.80; // valid server-verified PoW = strong baseline.

  // Duration reasonableness: very fast solutions → ASIC/GPU farm.
  if (typeof pow.durationMs === "number" &&
      typeof pow.difficulty === "number") {
    const expectedMs = Math.pow(2, pow.difficulty) * 0.002;
    const ratio = pow.durationMs / Math.max(expectedMs, 1);
    if (ratio < 0.01)       score -= 0.30; // >100× faster than expected
    else if (ratio < 0.1)   score -= 0.10; // >10× faster
    else                    score += 0.20; // normal range
  } else {
    score += 0.10;
  }

  return clamp01(score);
}

/* ------------------------------------------------------------------ */
/*  Main scoring function                                              */
/* ------------------------------------------------------------------ */

/**
 * Compute the composite risk score from raw telemetry.
 *
 * @param {Object} payload — decrypted and server-enriched telemetry
 * @returns {{ score: number, breakdown: Object, clamped: boolean, clampReason?: string }}
 */
function computeScore(payload, headerCheck) {
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

  // Use raw confidence_penalty from the advanced collector — NOT client
  // booleans.  tampering_detected = (confidence_penalty >= 0.5).
  const runtimePenalty = payload.runtime?.confidence_penalty;
  const tampered = typeof runtimePenalty === "number" && runtimePenalty >= 0.5;
  const powFailed = !payload.pow || payload.pow.serverVerified !== true;

  if (tampered && powFailed) {
    score = 0.0;
    clamped = true;
    clampReason = "runtime tampered AND PoW failed";
  } else if (tampered) {
    score = Math.min(score, 0.1);
    clamped = true;
    clampReason = "runtime tampered (confidence_penalty >= 0.5)";
  } else if (powFailed) {
    score = Math.min(score, 0.1);
    clamped = true;
    clampReason = "PoW server verification failed";
  }

  if (countInteractions(payload.kinematics?.eventCounts) < 5 && score > 0.30) {
    score = 0.30;
    clamped = true;
    clampReason = "fewer than five trusted interaction events reported";
  }
  // Only accept this result via the server-owned argument, never payload fields.
  if (headerCheck) {
    breakdown.headers = headerCheck;
    score *= 1 - clamp01(headerCheck.penalty);
    if (headerCheck.penalty >= 0.5) {
      score = Math.min(score, 0.1);
      clamped = true;
      clampReason = "HTTP/browser consistency failure";
    }
  }
  score = round4(clamp01(score));

  const result = { score, breakdown, clamped };
  if (clampReason) result.clampReason = clampReason;
  return result;
}

/* ------------------------------------------------------------------ */
/*  Utilities                                                          */
/* ------------------------------------------------------------------ */

function countInteractions(counts = {}) {
  return ["mousemove", "touchstart", "touchmove", "keydown"]
    .reduce((sum, key) => sum + (Number.isSafeInteger(counts?.[key]) && counts[key] > 0 ? counts[key] : 0), 0);
}

function clamp01(v) {
  if (!Number.isFinite(v)) return 0;
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
