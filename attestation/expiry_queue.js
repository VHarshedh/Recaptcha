"use strict";
// Indexed min-heap: one expiry per key, no stale unbounded timer records.
class ExpiryQueue {
  constructor() { this.heap = []; this.index = new Map(); }
  swap(a, b) {
    [this.heap[a], this.heap[b]] = [this.heap[b], this.heap[a]];
    this.index.set(this.heap[a].key, a); this.index.set(this.heap[b].key, b);
  }
  repair(i) {
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (this.heap[p].at <= this.heap[i].at) break;
      this.swap(i, p); i = p;
    }
    for (;;) {
      let next = i, left = i * 2 + 1, right = left + 1;
      if (left < this.heap.length && this.heap[left].at < this.heap[next].at) next = left;
      if (right < this.heap.length && this.heap[right].at < this.heap[next].at) next = right;
      if (next === i) break;
      this.swap(i, next); i = next;
    }
  }
  set(key, at) {
    let i = this.index.get(key);
    if (i === undefined) { i = this.heap.length; this.heap.push({ key, at }); this.index.set(key, i); }
    else this.heap[i].at = at;
    this.repair(i);
  }
  delete(key) {
    const i = this.index.get(key); if (i === undefined) return;
    const last = this.heap.pop(); this.index.delete(key);
    if (i < this.heap.length) { this.heap[i] = last; this.index.set(last.key, i); this.repair(i); }
  }
  takeDue(now) {
    const first = this.heap[0];
    if (!first || first.at > now) return null;
    this.delete(first.key); return first.key;
  }
}
module.exports = { ExpiryQueue };
