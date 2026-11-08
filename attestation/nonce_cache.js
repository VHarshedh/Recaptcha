/**
 * nonce_cache.js — In-Memory Sliding-Window Nonce Cache
 *
 * Prevents replay attacks by storing used nonce values and rejecting
 * any nonce that has been seen before within the sliding window.
 *
 * Design:
 *   • Two rotating Map buckets — "current" and "previous".
 *   • Every `windowMs` the previous bucket is discarded and a fresh
 *     one takes its place. This gives each nonce a lifetime of
 *     [windowMs, 2·windowMs) with O(1) insert and lookup.
 *   • Total memory is bounded: at most 2 × peak-nonces-per-window.
 *   • For multi-process deployments, swap this for a Redis SET with
 *     a TTL equal to the token expiry.
 */

"use strict";

class NonceCache {
  /**
   * @param {number} windowMs — rotation interval in milliseconds.
   *   Must be ≥ the maximum token TTL so that a nonce cannot be replayed
   *   after its bucket has been evicted.  Default: 120 000 ms (2 minutes).
   */
  constructor(windowMs = 120_000, maxEntries = 100_000) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) throw new RangeError("invalid nonce capacity");
    this._maxEntries = maxEntries;
    if (!Number.isFinite(windowMs) || windowMs < 1000) {
      throw new RangeError("windowMs must be ≥ 1000");
    }
    this._windowMs = windowMs;

    /** @type {Set<string>} */
    this._current = new Set();
    /** @type {Set<string>} */
    this._previous = new Set();

    this._lastRotation = Date.now();

    // Periodic rotation via unref'd timer (doesn't keep the process alive).
    this._timer = setInterval(() => this._rotate(), this._windowMs);
    if (typeof this._timer.unref === "function") this._timer.unref();
  }

  /** Rotate buckets. */
  _rotate() {
    this._previous = this._current;
    this._current = new Set();
    this._lastRotation = Date.now();
  }

  /**
   * Attempt to claim a nonce.
   *
   * @param {string} nonce
   * @returns {boolean} `true` if the nonce was freshly claimed;
   *                    `false` if it was already used (replay).
   */
  claim(nonce) {
    if (typeof nonce !== "string" || nonce.length === 0) return false;

    // Lazy rotation in case setInterval drifts or is delayed.
    if (Date.now() - this._lastRotation >= this._windowMs) {
      this._rotate();
    }

    if (this._current.has(nonce) || this._previous.has(nonce)) {
      return false; // replay detected
    }

    // Never evict live nonces: eviction would turn overload into a replay bypass.
    if (this.size >= this._maxEntries) return false;
    this._current.add(nonce);
    return true;
  }

  /**
   * Check whether a nonce has been seen (without claiming it).
   *
   * @param {string} nonce
   * @returns {boolean}
   */
  has(nonce) {
    return this._current.has(nonce) || this._previous.has(nonce);
  }

  /** Current count of tracked nonces across both buckets. */
  get size() {
    return this._current.size + this._previous.size;
  }

  /** Stop the rotation timer and release memory. */
  destroy() {
    clearInterval(this._timer);
    this._current.clear();
    this._previous.clear();
  }
}

module.exports = { NonceCache };
