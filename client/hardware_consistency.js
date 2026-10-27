/* Zero-dependency, browser-side consistency telemetry.
 * Browser: await HardwareConsistency.collect(); CommonJS export also supported.
 * No canvas is inserted into the DOM, audio reaches no physical output, and no
 * fonts, scripts, devices, or remote resources are requested by this module.
 *
 * A browser cannot promise a hard wall-clock deadline: WebGL initialization,
 * font measurement, GC, and timer throttling can block past any JS timeout.
 * This collector uses a 140 ms cooperative budget, reports overruns, and stops
 * waiting for audio at the deadline. Offline rendering cannot be forcibly closed.
 */
(function (root, factory) {
  'use strict';
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else Object.defineProperty(root, 'HardwareConsistency', { value: api, configurable: true });
})(typeof globalThis === 'object' ? globalThis : this, function (root) {
  'use strict';
  const finite = value => typeof value === 'number' && Number.isFinite(value) ? value : null;
  function os(text) {
    if (/Android/i.test(text)) return 'Android';
    if (/iPhone|iPad|iPod/i.test(text)) return 'iOS';
    if (/Windows|Win32|Win64/i.test(text)) return 'Windows';
    if (/Macintosh|MacIntel|Mac OS|macOS/i.test(text)) return 'macOS';
    if (/CrOS/i.test(text)) return 'ChromeOS';
    if (/Linux|X11/i.test(text)) return 'Linux';
    return null;
  }
  function hex64(value) {
    const bytes = new DataView(new ArrayBuffer(8));
    bytes.setFloat64(0, value, false);
    return Array.from({ length: 8 }, (_, i) => bytes.getUint8(i).toString(16).padStart(2, '0')).join('');
  }

  async function collect() {
    const now = root.performance && typeof root.performance.now === 'function'
      ? () => root.performance.now() : () => Date.now();
    const started = now();
    const deadline = started + 140;
    const remaining = () => Math.max(0, deadline - now());
    const result = {
      version: 1,
      profile: {},
      webgl: { status: 'not_run' }, audio: { status: 'not_run' },
      fonts: { status: 'not_run' }, geometry: { status: 'not_run' },
      anomalies: [], timing: {}
    };
    function flag(probe, code, detail, strength) {
      result.anomalies.push({ probe, code, detail, strength });
    }
    function run(name, fn) {
      if (!remaining()) { result[name] = { status: 'budget_exhausted' }; return; }
      try { result[name] = fn(); }
      catch (e) { result[name] = { status: 'error', error: String(e && e.name || 'Error') }; }
    }
    // UA strings are claims, not an authenticated profile. MacIntel and Intel
    // Mac OS X appear on Apple Silicon too: never infer x86 from those tokens.
    const nav = root.navigator || {};
    const ua = String(nav.userAgent || '');
    const platform = String(nav.platform || '');
    const uaOS = os(ua), platformOS = os(platform);
    result.profile = {
      userAgent: ua, platform, uaOS, platformOS,
      hardwareConcurrency: finite(nav.hardwareConcurrency),
      explicitAppleSiliconClaim: /Apple\s+(?:Silicon|M\d\b)|\bM[1-9]\d*\s+(?:Pro|Max|Ultra)\b/i.test(ua),
      cpuArchitecture: 'unverified'
    };
    if (uaOS && platformOS && uaOS !== platformOS &&
        !(uaOS === 'Android' && platformOS === 'Linux') &&
        !(uaOS === 'ChromeOS' && platformOS === 'Linux') &&
        !(uaOS === 'iOS' && platformOS === 'macOS'))
      flag('profile', 'os_claim_disagreement', 'UA and platform name different OS families; compatibility modes can explain this.', 'weak');

    // Begin asynchronous rendering before synchronous probes. Resolving a probe
    // only returns a local object; late completion never mutates returned JSON.
    const audioWork = remaining() ? audioProbe() : Promise.resolve({ status: 'budget_exhausted' });

    run('geometry', function () {
      const s = root.screen || {};
      const g = {
        status: 'ok', outerWidth: finite(root.outerWidth), innerWidth: finite(root.innerWidth),
        screenHeight: finite(s.height), availableHeight: finite(s.availHeight),
        colorDepth: finite(s.colorDepth), pixelDepth: finite(s.pixelDepth),
        devicePixelRatio: finite(root.devicePixelRatio), checks: {}
      };
      g.checks.outerAtLeastInner = g.outerWidth === null || g.innerWidth === null ? null : g.outerWidth >= g.innerWidth;
      g.checks.availableWithinScreen = g.availableHeight === null || g.screenHeight === null ? null : g.availableHeight <= g.screenHeight;
      g.checks.requestedColorDepth = g.colorDepth === null ? null : [24, 30].includes(g.colorDepth);
      // These requested rules are heuristics, not universal OS invariants:
      // zoom, mobile layout viewports, privacy masking, and display setup matter.
      for (const [key, passed] of Object.entries(g.checks)) {
        if (passed === false) flag('geometry', key, 'Requested geometry/depth rule failed; inspect zoom, viewport and privacy settings.', 'weak');
      }
      if (Object.values(g.checks).every(value => value === null)) g.status = 'unavailable';
      return g;
    });

    run('webgl', function () {
      if (!root.document) return { status: 'unavailable' };
      const canvas = root.document.createElement('canvas');
      canvas.width = canvas.height = 1;
      let gl;
      try {
        gl = canvas.getContext('webgl', { antialias: false, depth: false, stencil: false });
        if (!gl) return { status: 'unavailable' };
        const extension = gl.getExtension('WEBGL_debug_renderer_info');
        const data = {
          status: extension ? 'ok' : 'unmasked_info_unavailable',
          vendor: gl.getParameter(gl.VENDOR), renderer: gl.getParameter(gl.RENDERER),
          unmaskedVendor: extension ? gl.getParameter(extension.UNMASKED_VENDOR_WEBGL) : null,
          unmaskedRenderer: extension ? gl.getParameter(extension.UNMASKED_RENDERER_WEBGL) : null
        };
        const renderer = String(data.unmaskedRenderer || data.renderer || '');
        data.softwareRasterizers = renderer.match(/llvmpipe|softpipe|swiftshader|software rasterizer|Microsoft Basic Render Driver/gi) || [];
        data.legacyDirect3D9 = /Direct3D9|\bD3D9\b/i.test(renderer);
        if (data.softwareRasterizers.length)
          flag('webgl', 'software_renderer', 'Software rendering exposed: ' + data.softwareRasterizers.join(', ') + '. Also occurs in ordinary browsers without GPU acceleration.', 'weak');
        // D3D9 is a graphics API, not itself a software rasterizer.
        if (data.legacyDirect3D9) flag('webgl', 'legacy_d3d9', 'Legacy Direct3D9 backend exposed; this does not prove virtualization.', 'weak');
        if (uaOS && uaOS !== 'Windows' && /Direct3D(?:9|11|12)|\bD3D(?:9|11|12)\b/i.test(renderer))
          flag('webgl', 'os_backend_mismatch', 'Non-Windows UA with Direct3D backend; spoofing, translation or remoting may explain this.', 'moderate');
        if (result.profile.explicitAppleSiliconClaim && /Intel|Direct3D|\bD3D\d/i.test(renderer))
          flag('webgl', 'apple_silicon_renderer_mismatch', 'Explicit Apple Silicon UA claim conflicts with Intel/Direct3D renderer.', 'moderate');
        return data;
      } finally {
        // Release our GPU context; a detached canvas has no visual footprint.
        if (gl) { const lose = gl.getExtension('WEBGL_lose_context'); if (lose) lose.loseContext(); }
        canvas.width = canvas.height = 0;
      }
    });

    run('fonts', function () {
      if (!root.document) return { status: 'unavailable' };
      const canvas = root.document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      if (!ctx) return { status: 'unavailable' };
      const families = uaOS === 'Windows' ? ['"Segoe UI"'] : uaOS === 'macOS' || uaOS === 'iOS'
        ? ['"San Francisco"', '-apple-system', 'system-ui'] : uaOS === 'Linux' ? ['"Ubuntu"'] : ['system-ui'];
      const strings = ['mmmmWWWWiiiIl1 0123456789', 'Hamburgefontsiv AV fi ffi'];
      const measures = [];
      function measure(font, text) {
        ctx.font = '32px ' + font;
        const m = ctx.measureText(text);
        // No integer rounding: retain the fractional CSS pixel geometry exposed
        // by TextMetrics. The right bound is distinct from the advance width.
        return { width: finite(m.width), left: finite(m.actualBoundingBoxLeft),
          right: finite(m.actualBoundingBoxRight),
          inkWidth: finite(m.actualBoundingBoxLeft + m.actualBoundingBoxRight) };
      }
      let incomplete = false;
      for (const family of families) {
        if (!remaining()) { incomplete = true; break; }
        let differs = false;
        const samples = [];
        for (const text of strings) {
          for (const fallback of ['monospace', 'serif']) {
            const baseline = measure(fallback, text);
            const target = measure(family + ', ' + fallback, text);
            if (Object.keys(baseline).some(key => baseline[key] !== target[key])) differs = true;
            samples.push({ text, fallback, baseline, target });
          }
        }
        measures.push({ family, distinguishableFromFallback: differs, samples });
        if (!differs) flag('fonts', 'font_not_distinguishable', family + ' matched both fallback metrics; may be absent, aliased or privacy-normalized.', 'weak');
      }
      // Ubuntu is not universal on Linux; San Francisco is often only available
      // through the system UI alias. No font measurement authenticates an OS.
      canvas.width = canvas.height = 0;
      return { status: incomplete ? 'partial_budget_exhausted' : 'ok', measurements: measures };
    });

    let timer;
    try {
      result.audio = await Promise.race([
        audioWork,
        new Promise(resolve => { timer = root.setTimeout(() => resolve({ status: 'timeout', architecture: 'indeterminate', virtualDriver: 'not_observable' }), remaining()); })
      ]);
    } finally { root.clearTimeout(timer); }
    const elapsed = now() - started;
    result.timing = { elapsedMs: elapsed, budgetMs: 140, targetMs: 150, withinTarget: elapsed < 150, hardDeadlineGuaranteed: false };
    result.consistency = result.anomalies.some(a => a.strength === 'moderate') ? 'discrepancies_observed' : 'inconclusive';
    return result;
  }

  async function audioProbe() {
    const Constructor = root.OfflineAudioContext || root.webkitOfflineAudioContext;
    if (!Constructor) return { status: 'unavailable', architecture: 'indeterminate', virtualDriver: 'not_observable' };
    let oscillator, compressor;
    try {
      // Render a short warm-up for compressor look-ahead, then examine exactly
      // 500 Float32 PCM samples. Rendering only 500 frames risks measuring mostly
      // compressor startup silence. The graph is fixed for repeatable telemetry.
      const warmup = 4096, count = 500, sampleRate = 44100;
      const context = new Constructor(1, warmup + count, sampleRate);
      oscillator = context.createOscillator();
      oscillator.type = 'triangle'; oscillator.frequency.value = 1000;
      compressor = context.createDynamicsCompressor();
      compressor.threshold.value = -50; compressor.knee.value = 40;
      compressor.ratio.value = 12; compressor.attack.value = 0;
      compressor.release.value = 0.25;
      oscillator.connect(compressor); compressor.connect(context.destination);
      oscillator.start(0); oscillator.stop((warmup + count) / sampleRate);
      const buffer = await context.startRendering();
      const pcm = buffer.getChannelData(0).subarray(warmup, warmup + count);
      let sum = 0, absoluteSum = 0, energy = 0;
      for (const sample of pcm) {
        // Float32 values convert exactly to binary64; each ordered JS addition
        // then rounds to IEEE-754 binary64. This is a precisely specified FP sum,
        // not an arbitrary-precision mathematical sum or a CPU classifier.
        sum += sample; absoluteSum += Math.abs(sample); energy += sample * sample;
      }
      const valid = pcm.length === count && Number.isFinite(sum) && Number.isFinite(absoluteSum) && Number.isFinite(energy);
      return {
        status: valid ? 'ok' : 'invalid_pcm', sampleRate, sampleCount: pcm.length, warmupSamples: warmup,
        sum: finite(sum), sumFloat64Hex: hex64(sum), absoluteSum: finite(absoluteSum),
        absoluteSumFloat64Hex: hex64(absoluteSum), rms: finite(Math.sqrt(energy / pcm.length)),
        silent: absoluteSum === 0, architecture: 'indeterminate', virtualDriver: 'not_observable',
        interpretation: 'Offline DSP bypasses output drivers. Engine/version, DSP implementation and privacy defenses affect results; no universal ARM/x86 signature exists.'
      };
    } catch (e) {
      return { status: 'error', error: String(e && e.name || 'Error'), architecture: 'indeterminate', virtualDriver: 'not_observable' };
    } finally {
      if (oscillator) { try { oscillator.disconnect(); } catch (_) {} }
      if (compressor) { try { compressor.disconnect(); } catch (_) {} }
    }
  }
  return Object.freeze({ collect });
});
