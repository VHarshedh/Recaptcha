"use strict";
const { ExpiryQueue } = require("./expiry_queue");
// Bounded sliding windows. At capacity fail closed rather than evicting bans.
class RateLimiter {
  constructor({ maxRequests = 30, windowMs = 60_000, maxEntries = 10000,
    failureWindowMs = 300000, failureLimit = 8, cooldownMs = 60000,
    maxCooldownMs = 900000, now = Date.now } = {}) {
    for (const value of [maxRequests, windowMs, maxEntries, failureWindowMs, failureLimit, cooldownMs, maxCooldownMs])
      if (!Number.isSafeInteger(value) || value < 1) throw new Error("invalid rate limit option");
    Object.assign(this, { maxRequests, windowMs, maxEntries, failureWindowMs, failureLimit, cooldownMs, maxCooldownMs, now });
    this.entries = new Map();
    this.clean = new Map();
    this.expiry = new ExpiryQueue();
  }
  entry(key) {
    const now = this.now();
    let expired;
    while ((expired = this.expiry.takeDue(now)) !== null) {
      const entry = this.entries.get(expired);
      if (entry) { entry.failures = []; entry.consecutive = 0; this.clean.set(expired, true); }
    }
    let e = this.entries.get(key);
    if (!e) {
      if (this.entries.size >= this.maxEntries) {
        for (const [id, item] of this.entries) {
          if (item.until <= now && item.requests.every(t => t <= now - this.windowMs) && item.failures.every(t => t <= now - this.failureWindowMs)) {
            this.entries.delete(id); this.clean.delete(id); this.expiry.delete(id);
          }
        }
        if (this.entries.size >= this.maxEntries) return null;
      }
      e = { requests: [], failures: [], consecutive: 0, strikes: 0, until: 0, last: now };
      this.entries.set(key, e);
      this.clean.set(key, true);
    }
    e.requests = e.requests.filter(t => t > now - this.windowMs);
    e.failures = e.failures.filter(t => t > now - this.failureWindowMs);
    if (!e.failures.length) e.consecutive = 0;
    e.last = now;
    return e;
  }
  check(key) {
    const e = this.entry(key), now = this.now();
    if (!e) return { allowed: false, retryAfter: Math.ceil(this.windowMs / 1000) };
    const until = Math.max(e.until, e.requests.length >= this.maxRequests ? e.requests[0] + this.windowMs : 0);
    if (until > now) return { allowed: false, retryAfter: Math.ceil((until - now) / 1000) };
    e.requests.push(now);
    return { allowed: true };
  }
  failure(key) {
    const e = this.entry(key); if (!e) return;
    e.consecutive++; e.failures.push(this.now());
    this.clean.delete(key);
    if (e.failures.length >= this.failureLimit) {
      e.until = this.now() + Math.min(this.maxCooldownMs, this.cooldownMs * 2 ** Math.min(e.strikes++, 20));
      e.failures = e.failures.slice(-this.failureLimit);
    }
    this.expiry.set(key, Math.max(this.now() + this.failureWindowMs, e.until));
  }
  success(key) { const e = this.entry(key); if (e) e.consecutive = 0; }
  penalty(key) { const e = this.entry(key); return !e || e.consecutive >= 3 ? 0.50 : 0; }
}
module.exports = { RateLimiter };
