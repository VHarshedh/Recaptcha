/* Bounded HCI telemetry; no network, DOM writes, dependencies or typed text.
 * Kinematics.start(); Kinematics.getBiometricVector(); Kinematics.stop();
 * Measurements are heuristic features, not a validated human/bot classifier.
 * Browser-generated automation may have isTrusted=true. Timer precision may be
 * reduced by privacy settings; performance.now() does not bypass that policy.
 */
(function (root, factory) {
  'use strict';
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else Object.defineProperty(root, 'Kinematics', { value: api, configurable: true });
})(typeof globalThis === 'object' ? globalThis : this, function (root) {
  'use strict';
  const CAPACITY = 100;
  const buffer = new Array(CAPACITY);
  const activeKeys = new Map(); // At most 32 transient code -> keydown timestamps.
  let size = 0, cursor = 0, running = false, segment = 0;
  let lastPoint = null, touchID = null, lastTouch = -Infinity, lastDown = null, lastUp = null, lastCode = null;
  let counts;
  const listeners = [];
  const now = () => root.performance.now();
  const clamp = v => Math.max(0, Math.min(1, v));
  const squash = v => v / (1 + Math.abs(v));
  function reset() {
    buffer.fill(undefined); size = cursor = segment = 0;
    activeKeys.clear(); lastPoint = null; touchID = null;
    lastDown = lastUp = lastCode = null; lastTouch = -Infinity;
    counts = { mousemove: 0, touchstart: 0, touchmove: 0, touchend: 0, touchcancel: 0,
      keydown: 0, keyup: 0, rejectedUntrusted: 0, repeatedKeys: 0,
      ignoredComposition: 0, ignoredMultitouch: 0, duplicateTimestamps: 0, overwritten: 0 };
  }
  reset();
  function push(record) {
    if (size === CAPACITY) counts.overwritten++;
    buffer[cursor] = record; cursor = (cursor + 1) % CAPACITY;
    size = Math.min(CAPACITY, size + 1);
  }
  function records() {
    return Array.from({ length: size }, (_, i) => buffer[(cursor - size + i + CAPACITY) % CAPACITY]);
  }
  function trusted(event) {
    if (event.isTrusted !== true) { counts.rejectedUntrusted++; return false; }
    counts[event.type]++;
    return true;
  }
  function breakStroke() { segment++; lastPoint = null; }
  function clearTransient() {
    breakStroke(); activeKeys.clear(); lastDown = lastUp = lastCode = null; touchID = null;
  }
  function point(kind, x, y, t) {
    if (![x, y, t].every(Number.isFinite)) return;
    const scale = Math.hypot(root.innerWidth || 1, root.innerHeight || 1);
    if (lastPoint && (lastPoint.kind !== kind || t - lastPoint.t > 200 || lastPoint.scale !== scale)) breakStroke();
    if (lastPoint && t <= lastPoint.t) { counts.duplicateTimestamps++; return; }
    const p = { type: 'point', kind, x, y, t, scale, segment };
    push(p); lastPoint = p;
  }
  function mouse(event) {
    if (!trusted(event)) return;
    const t = now();
    // Suppress compatibility mouse events immediately following touch input.
    if (t - lastTouch < 800 || event.sourceCapabilities && event.sourceCapabilities.firesTouchEvents) return;
    point('mouse', event.clientX, event.clientY, t);
  }
  function touch(event) {
    if (!trusted(event)) return;
    const t = now(); lastTouch = t;
    if (event.type === 'touchcancel') { touchID = null; breakStroke(); return; }
    if (event.type === 'touchend') {
      if (touchID !== null) {
        for (const item of Array.from(event.changedTouches)) {
          if (item.identifier === touchID) {
            point('touch', item.clientX, item.clientY, t); touchID = null; breakStroke(); break;
          }
        }
      }
      return;
    }
    // Do not join different fingers into one fictitious trajectory.
    if (event.touches.length !== 1) { counts.ignoredMultitouch++; touchID = null; breakStroke(); return; }
    const item = event.touches[0];
    if (item.identifier !== touchID) { touchID = item.identifier; breakStroke(); }
    point('touch', item.clientX, item.clientY, t);
  }
  function keyboard(event) {
    if (!trusted(event)) return;
    if (event.isComposing || event.keyCode === 229) { counts.ignoredComposition++; activeKeys.clear(); lastDown = lastUp = lastCode = null; return; }
    // Physical codes are transient matching keys, never part of stored history
    // or exported telemetry. event.key and input field values are never read.
    const code = event.code;
    if (!code || code === 'Unidentified') return;
    const t = now();
    if (event.type === 'keydown') {
      if (event.repeat || activeKeys.has(code)) { counts.repeatedKeys++; return; }
      for (const [key, state] of activeKeys) if (t - state.down > 10000) activeKeys.delete(key);
      if (activeKeys.size >= 32) { activeKeys.clear(); lastDown = lastUp = lastCode = null; }
      const previous = activeKeys.get(lastCode);
      if (previous && t - previous.down < 5000) previous.nextDown = t;
      activeKeys.set(code, { down: t, nextDown: null });
      // Flight is previous key release -> this press (can be negative for
      // overlap); inter-key interval is previous press -> this press.
      push({ type: 'cadence', t,
        interval: lastDown !== null && t - lastDown < 5000 ? t - lastDown : null,
        flight: lastUp !== null && t - lastUp < 5000 ? t - lastUp : null });
      lastDown = t; lastUp = null; lastCode = code;
    } else {
      const state = activeKeys.get(code);
      activeKeys.delete(code);
      if (state === undefined) return;
      const dwell = t - state.down;
      if (dwell >= 0 && dwell <= 10000) push({ type: 'cadence', t, dwell,
        flight: state.nextDown === null ? null : state.nextDown - t });
      if (code === lastCode) lastUp = t;
    }
  }
  function start() {
    if (running) return api;
    if (!root.addEventListener || !root.performance) throw new Error('Kinematics requires a browser Window with performance.now().');
    const add = (name, handler) => {
      root.addEventListener(name, handler, { passive: true, capture: true });
      listeners.push([name, handler]);
    };
    add('mousemove', mouse);
    for (const type of ['touchstart', 'touchmove', 'touchend', 'touchcancel']) add(type, touch);
    add('keydown', keyboard); add('keyup', keyboard);
    add('blur', clearTransient); add('pagehide', clearTransient); add('resize', clearTransient);
    running = true;
    return api;
  }
  function stop() {
    for (const [name, handler] of listeners) root.removeEventListener(name, handler, true);
    listeners.length = 0; running = false; clearTransient();
  }
  function stats(values) {
    if (!values.length) return { count: 0, mean: null, variance: null, stddev: null, max: null };
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length;
    return { count: values.length, mean, variance, stddev: Math.sqrt(variance), max: Math.max(...values) };
  }
  function derivative(points) {
    const out = [];
    for (let i = 1; i < points.length; i++) {
      const a = points[i - 1], b = points[i], dt = (b.t - a.t) / 1000;
      // Near-zero sampling intervals magnify timer quantization dramatically.
      if (dt < 0.001 || dt > 0.2) continue;
      out.push({ x: (b.x - a.x) / dt, y: (b.y - a.y) / dt, t: (a.t + b.t) / 2 });
    }
    return out;
  }
  function entropy(values) {
    if (!values.length) return null;
    const bins = new Array(12).fill(0);
    for (const angle of values) bins[Math.min(11, Math.floor((angle + Math.PI) / (2 * Math.PI) * 12))]++;
    return -bins.reduce((sum, n) => n ? sum + n / values.length * Math.log2(n / values.length) : sum, 0) / Math.log2(12);
  }
  function spectrum(points) {
    // A bounded descriptive spectrum, NOT diagnosis of physiological tremor.
    // Require >=1 second and >=40 Hz source sampling; Nyquist alone is not
    // sufficient to identify physiology. OS filtering and coalescing remain.
    if (points.length < 41) return { status: 'insufficient_sampling', band8to12HzRatio: null };
    const duration = (points[points.length - 1].t - points[0].t) / 1000;
    if (duration < 1 || points.some((p, i) => i && p.t - points[i - 1].t > 25))
      return { status: 'insufficient_sampling', band8to12HzRatio: null };
    const n = Math.floor(duration * 40) + 1, values = [];
    let j = 1;
    const first = points[0], last = points[points.length - 1];
    // Linear interpolation onto 40 Hz grid, remove endpoint trend, Hann window.
    for (let i = 0; i < n; i++) {
      const t = first.t + i * 25;
      while (j < points.length - 1 && points[j].t < t) j++;
      const a = points[j - 1], b = points[j], q = (t - a.t) / (b.t - a.t);
      const fraction = (t - first.t) / (last.t - first.t);
      const window = 0.5 - 0.5 * Math.cos(2 * Math.PI * i / (n - 1));
      values.push({ x: (a.x + q * (b.x - a.x) - first.x - fraction * (last.x - first.x)) * window,
        y: (a.y + q * (b.y - a.y) - first.y - fraction * (last.y - first.y)) * window });
    }
    let total = 0, band = 0;
    for (let k = 1; k <= Math.floor(n / 2); k++) {
      const frequency = k * 40 / n;
      if (frequency < 2 || frequency > 18) continue;
      let xr = 0, xi = 0, yr = 0, yi = 0;
      for (let i = 0; i < n; i++) {
        const phase = 2 * Math.PI * k * i / n;
        xr += values[i].x * Math.cos(phase); xi += values[i].x * Math.sin(phase);
        yr += values[i].y * Math.cos(phase); yi += values[i].y * Math.sin(phase);
      }
      const power = xr * xr + xi * xi + yr * yr + yi * yi;
      total += power; if (frequency >= 8 && frequency <= 12) band += power;
    }
    return { status: total > 1e-20 ? 'descriptive_only' : 'no_residual_energy',
      band8to12HzRatio: total > 1e-20 ? clamp(band / total) : null, frequencyResolutionHz: 40 / n };
  }
  function movement(history, kind) {
    const groups = [];
    for (const p of history.filter(p => p.type === 'point' && p.kind === kind)) {
      if (!groups.length || groups[groups.length - 1][0].segment !== p.segment) groups.push([]);
      groups[groups.length - 1].push(p);
    }
    const speeds = [], accelerations = [], jerks = [], angles = [], bellScores = [];
    let zeroJerk = 0, continuous = 0, jerkPairs = 0;
    for (const group of groups) {
      // Scale coordinates by viewport diagonal; derivatives are diagonal/s^n.
      const points = group.map(p => ({ x: p.x / p.scale, y: p.y / p.scale, t: p.t }));
      const v = derivative(points), a = derivative(v), j = derivative(a);
      const speed = v.map(p => Math.hypot(p.x, p.y));
      speeds.push(...speed); accelerations.push(...a.map(p => Math.hypot(p.x, p.y)));
      jerks.push(...j.map(p => Math.hypot(p.x, p.y)));
      zeroJerk += j.filter(p => p.x === 0 && p.y === 0).length;
      for (let i = 1; i < j.length; i++) {
        jerkPairs++;
        if (Math.hypot(j[i].x - j[i - 1].x, j[i].y - j[i - 1].y) <=
            0.001 * Math.max(1, Math.hypot(j[i].x, j[i].y))) continuous++;
      }
      for (let i = 1; i < v.length; i++) {
        if (!speed[i] || !speed[i - 1]) continue;
        const delta = Math.atan2(v[i].y, v[i].x) - Math.atan2(v[i - 1].y, v[i - 1].x);
        angles.push(Math.atan2(Math.sin(delta), Math.cos(delta)));
      }
      // Descriptive rise/fall score around an interior speed peak. This is NOT
      // a Fitts-law test: MT=a+b*log2(1+D/W) needs target geometry and trials.
      if (speed.length >= 8 && Math.max(...speed) > 0) {
        const peak = speed.indexOf(Math.max(...speed));
        if (peak > 0 && peak < speed.length - 1) {
          let matches = 0;
          for (let i = 1; i < speed.length; i++)
            if (i <= peak ? speed[i] > speed[i - 1] : speed[i] < speed[i - 1]) matches++;
          bellScores.push(matches / (speed.length - 1));
        } else bellScores.push(0);
      }
    }
    const latest = groups.length ? groups[groups.length - 1] : [];
    return {
      pointCount: groups.reduce((n, g) => n + g.length, 0), segmentCount: groups.length,
      velocity: stats(speeds.map(squash)), acceleration: stats(accelerations.map(squash)),
      jerk: stats(jerks.map(squash)), maxJerk: jerks.length ? squash(Math.max(...jerks)) : null,
      angularChanges: stats(angles.map(a => a / Math.PI)), entropyRatio: entropy(angles),
      zeroJerkRatio: jerks.length ? zeroJerk / jerks.length : null,
      nearConstantJerkRatio: jerkPairs ? continuous / jerkPairs : null,
      ballisticHomingScore: stats(bellScores).mean,
      tremorSpectrum: spectrum(latest), fittsLaw: 'not_assessable_without_target_geometry_and_trials'
    };
  }
  function getBiometricVector() {
    const history = records();
    const mouse = movement(history, 'mouse'), touch = movement(history, 'touch');
    const typing = {}, flags = [];
    for (const field of ['dwell', 'interval', 'flight']) {
      const values = history.filter(p => p.type === 'cadence' && Number.isFinite(p[field])).map(p => p[field]);
      const raw = stats(values);
      // Raw cadence milliseconds are provided for interpretability alongside
      // bounded features; uniformity thresholds are heuristics, not biometrics.
      const cv = raw.count && raw.mean > 0 ? raw.stddev / raw.mean : null;
      typing[field] = { milliseconds: raw, normalized: stats(values.map(v => squash(v / 250))), coefficientOfVariation: cv };
      if (raw.count >= 12 && raw.mean >= 20 && cv < 0.02)
        flags.push({ code: 'uniform_' + field, evidence: 'At least 12 samples with coefficient of variation below 0.02; timer quantization and assistive input can also cause this.' });
    }
    for (const [kind, m] of [['mouse', mouse], ['touch', touch]]) {
      if (m.jerk.count >= 12 && (m.zeroJerkRatio > 0.9 || m.nearConstantJerkRatio > 0.95))
        flags.push({ code: kind + '_smooth_trajectory', evidence: 'Near-constant or exactly zero finite-difference jerk; not sufficient to identify synthetic motion.' });
      if (m.angularChanges.count >= 12 && m.angularChanges.variance < 1e-8)
        flags.push({ code: kind + '_low_direction_variance', evidence: 'Nearly constant direction changes; straight human motion is also possible.' });
    }
    return { version: 1, running, historyCount: size, historyCapacity: CAPACITY,
      eventCounts: { ...counts }, mouse, touch, typing, flags,
      normalization: 'Motion magnitudes: viewport-diagonal/s^n, mapped by x/(1+x). Angles: radians/pi. Entropy: Shannon/log2(12). Timing: x=ms/250, mapped by x/(1+abs(x)). Population variances.',
      interpretation: 'Descriptive features only; trusted events, smoothness, and frequency-band energy do not prove human or bot origin.' };
  }
  const api = Object.freeze({ start, stop, reset, getBiometricVector });
  return api;
});
