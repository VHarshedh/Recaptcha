/* runtime_integrity.js — dependency-free browser runtime telemetry.
 * Browser: RuntimeIntegrity.collect(). CommonJS: require('./runtime_integrity.js').
 * Run early, before application code changes built-ins. No permissions prompt,
 * eval, network request, webdriver check, or global prototype mutation is used.
 *
 * This measures observable inconsistencies, NOT automation identity. Proxies can
 * preserve all tested semantics. CDP/WebDriver need not leave page artifacts.
 * Extensions and instrumentation can cause the same observations as automation.
 */
(function (root, factory) {
  'use strict';
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else Object.defineProperty(root, 'RuntimeIntegrity', { value: api, configurable: true });
})(typeof globalThis === 'object' ? globalThis : this, function (root) {
  'use strict';

  // Capture references once. This limits later patching, but is NOT a trust root:
  // a script that ran before this module may already have replaced every one.
  const apply = Reflect.apply;
  const descriptor = Object.getOwnPropertyDescriptor;
  const proto = Object.getPrototypeOf;
  const ownNames = Object.getOwnPropertyNames;
  const stringify = Function.prototype.toString;
  const functionPrototype = Function.prototype;
  const hasOwn = (o, k) => apply(Object.prototype.hasOwnProperty, o, [k]);
  const nativeShape = /^function\s*[^()]*\([^()]*\)\s*\{\s*\[native code\]\s*\}$/;

  /**
   * @param {object} [options]
   * @param {string} [options.expectedLanguagesError]
   *   Exact String(error) from an independently trusted, matching browser build.
   *   For example 'TypeError: Illegal invocation'. Do not learn this baseline
   *   from the same potentially modified page being tested.
   * @returns {{tampering_detected:boolean, anomalies:string[], confidence_penalty:number}}
   * confidence_penalty is a capped heuristic loss of trust, NOT a probability.
   * tampering_detected means a strong discrepancy or corroborating signals;
   * it does not establish malicious intent or identify an automation framework.
   */
  function collect(options) {
    options = options || {};
    const anomalies = [];
    let receiverErrorText = "";
    const scores = Object.create(null);
    function note(group, weight, message) {
      if (!anomalies.includes(message)) anomalies.push(message);
      // Correlated findings within one family do not inflate the score.
      scores[group] = Math.max(scores[group] || 0, weight);
    }
    function safe(label, fn) {
      try { fn(); } catch (_) {
        note('coverage', 0, label + ': probe unavailable or interrupted; result is incomplete');
      }
    }
    function capture(fn) {
      try { fn(); return { threw: false }; }
      catch (error) { return { threw: true, error }; }
    }
    function inspectStack(error, label) {
      const stack = error && error.stack;
      if (typeof stack !== 'string') {
        note('stack', 0.05, label + ': stack missing or non-string (may be configured intentionally)');
        return;
      }
      // These are hints, not signatures guaranteed to be emitted by a framework.
      // Only inspect frames: an error message can itself contain arbitrary text.
      const frames = stack.split(/\r?\n/).slice(1);
      const markers = [
        /puppeteer_evaluation_script/i,
        /pptr:\/\//i,
        /__playwright_evaluation_script__/i,
        /UtilityScript\.(?:evaluate|evaluateHandle)/,
        /(?:webdriver|selenium)[^\s/]*[./](?:execute|evaluate)/i
      ];
      for (const marker of markers) {
        if (frames.some(frame => marker.test(frame)))
          note('automation-stack', 0.3, label + ': evaluation frame matches ' + marker.source);
      }
      if (frames.some(frame => /eval at |<anonymous>/.test(frame)))
        note('stack', 0.05, label + ': anonymous/eval wrapper (also common in legitimate code)');
      for (const frame of frames) {
        const location = frame.match(/:(-?\d+):(-?\d+)\)?\s*$/);
        if (location && (+location[1] < 1 || +location[2] < 1))
          note('stack', 0.1, label + ': non-positive source line or column');
      }
      // Absolute line offsets cannot be validated without a known script build
      // and source map. Large offsets alone are normal in bundled applications.
    }
    function nativeFunction(fn, label) {
      if (typeof fn !== 'function') {
        note('native', 0.65, label + ': expected callable native member');
        return;
      }
      // Calling the captured intrinsic avoids fn.toString overrides. However,
      // callable Proxy objects also legitimately stringify as native functions;
      // a '[native code]' string cannot establish native implementation purity.
      const source = apply(stringify, fn, []);
      if (!nativeShape.test(source))
        note('native', 0.65, label + ': intrinsic toString exposes non-native source');
      const direct = apply(fn.toString, fn, []);
      if (direct !== source)
        note('native', 0.65, label + ': direct and intrinsic toString disagree');
      if (hasOwn(fn, 'toString'))
        note('native', 0.35, label + ': unexpected own toString override');
      // Formatting is implementation-defined. Treat line-break differences as a
      // weak clue and compare to another native in this realm, not a fixed regex.
      const reference = apply(stringify, Object.getPrototypeOf, []);
      if (nativeShape.test(source) && /[\r\n]/.test(source) !== /[\r\n]/.test(reference))
        note('format', 0.1, label + ': native-source line breaks differ from realm reference');
      if (proto(fn) !== functionPrototype)
        note('native', 0.35, label + ': unexpected function prototype (possibly cross-realm)');
      if (hasOwn(fn, 'prototype'))
        note('native', 0.65, label + ': native method/getter has an own constructor prototype');
    }

    safe('Function integrity', function () {
      nativeFunction(stringify, 'Function.prototype.toString');
      const d = descriptor(functionPrototype, 'toString');
      if (!d || !d.writable || !d.configurable || d.enumerable || d.value !== stringify)
        note('native', 0.65, 'Function.prototype.toString: unexpected property descriptor');
      function sourceCanary() { /* runtime_integrity_source_canary */ return 17; }
      // ECMAScript source functions retain their source, including comments.
      if (!apply(stringify, sourceCanary, []).includes('/* runtime_integrity_source_canary */'))
        note('native', 0.65, 'Function.prototype.toString: failed source-text preservation canary');
      for (const receiver of [{}, null, 17]) {
        const result = capture(() => apply(stringify, receiver, []));
        if (!result.threw || !(result.error instanceof TypeError))
          note('receiver', 0.65, 'Function.prototype.toString: non-callable receiver did not throw TypeError');
        else inspectStack(result.error, 'Function.prototype.toString receiver');
      }
    });

    // Node also exposes Navigator, implemented in JavaScript. Browser-native
    // assumptions must not be applied to that separate host environment.
    const nav = root.window === root && root.document ? root.navigator : undefined;
    if (!nav || !root.Navigator) {
      note('coverage', 0, 'Navigator unavailable: browser-specific probes skipped');
    } else {
      safe('Navigator.languages', function () {
        const d = descriptor(root.Navigator.prototype, 'languages');
        if (!d || typeof d.get !== 'function') {
          note('coverage', 0, 'Navigator.languages: prototype getter unavailable');
          return;
        }
        nativeFunction(d.get, 'Navigator.languages getter');
        if (hasOwn(nav, 'languages'))
          note('receiver', 0.55, 'Navigator.languages: own property shadows prototype getter');
        // Web IDL getters brand-check the receiver against the platform object.
        // A plain object has no Navigator internal implementation, so must fail.
        const result = capture(() => apply(d.get, {}, []));
        if (!result.threw || !(result.error instanceof TypeError)) {
          note('receiver', 0.65, 'Navigator.languages: incompatible receiver did not throw TypeError');
        } else {
          const text = String(result.error);
          receiverErrorText = text;
          if (typeof options.expectedLanguagesError === 'string') {
            if (text !== options.expectedLanguagesError)
              note('receiver', 0.65, 'Navigator.languages: error differs from supplied exact baseline: ' + text);
          } else if (!/^TypeError: (?:Illegal invocation|Method get languages called on incompatible receiver(?: .*)?)$/.test(text)) {
            // Chromium/Blink commonly uses Illegal invocation. Other engines
            // and builds differ; an unfamiliar message alone is weak evidence.
            note('format', 0.1, 'Navigator.languages: unfamiliar receiver error: ' + text);
          }
          inspectStack(result.error, 'Navigator.languages receiver');
        }
      });
      safe('Permissions.query', function () {
        if (nav.permissions) nativeFunction(nav.permissions.query, 'Permissions.query');
        else note('coverage', 0, 'Permissions API unavailable');
        // Do not issue a permissions query: source inspection needs no prompt.
      });
    }

    safe('Controlled stacks', function () {
      // Ordinary TypeErrors avoid eval/CSP and never reference page globals.
      for (const trigger of [() => { const o = {}; o.missing(); }, () => null.missing]) {
        const result = capture(trigger);
        if (result.threw) inspectStack(result.error, 'Controlled TypeError');
      }
    });

    function collection(value, constructor, label) {
      if (!value || !constructor) {
        note('coverage', 0, label + ': interface unavailable');
        return [];
      }
      if (proto(value) !== constructor.prototype)
        note('collections', 0.65, label + ': incorrect immediate prototype');
      const length = value.length;
      if (!Number.isInteger(length) || length < 0 || length > 1024) {
        note('collections', 0.65, label + ': invalid or unreasonable length');
        return [];
      }
      nativeFunction(value.item, label + '.item');
      nativeFunction(value.namedItem, label + '.namedItem');
      const items = [];
      for (let i = 0; i < length; i++) {
        const item = value[i];
        items.push(item);
        if (!item || value.item(i) !== item)
          note('collections', 0.65, label + ': index/item identity mismatch at ' + i);
      }
      if (value.item(length) !== null)
        note('collections', 0.65, label + ': out-of-range item must return null');
      // Legacy platform objects are not necessarily JS Arrays or iterable in
      // every browser. If an iterator exists, enforce its consistency and bound
      // its consumption, so an accidental infinite iterator cannot hang us.
      if (value[Symbol.iterator] !== undefined) {
        if (typeof value[Symbol.iterator] !== 'function') {
          note('collections', 0.65, label + ': non-callable iterator');
        } else {
          const iterator = value[Symbol.iterator]();
          for (let i = 0; i <= length; i++) {
            const step = iterator.next();
            if (!step || (i === length ? !step.done : step.done || step.value !== items[i])) {
              note('collections', 0.65, label + ': iterator differs from indexed sequence at ' + i);
              if (typeof iterator.return === 'function') iterator.return();
              break;
            }
          }
        }
      }
      return items;
    }
    safe('Plugin and MIME collections', function () {
      if (!nav) return;
      const plugins = collection(nav.plugins, root.PluginArray, 'navigator.plugins');
      const mimes = collection(nav.mimeTypes, root.MimeTypeArray, 'navigator.mimeTypes');
      // Empty collections are legitimate. Do not require a PDF viewer or a
      // hard-coded plugin count: browser settings/privacy modes change these.
      function named(parent, item, name, label) {
        if (typeof name !== 'string' || !name) {
          note('collections', 0.65, label + ': missing name/type'); return;
        }
        // Web IDL named properties need not be JavaScript accessor descriptors.
        if (parent.namedItem(name) !== item || parent[name] !== item)
          note('collections', 0.65, label + ': named/indexed identity mismatch for ' + name);
      }
      for (const plugin of plugins) {
        if (!plugin) continue;
        named(nav.plugins, plugin, plugin.name, 'PluginArray');
        const types = collection(plugin, root.Plugin, 'Plugin ' + plugin.name);
        for (const mime of types) {
          if (!mime) continue;
          named(plugin, mime, mime.type, 'Plugin');
          if (!root.MimeType || proto(mime) !== root.MimeType.prototype)
            note('collections', 0.65, 'Plugin MIME entry: incorrect prototype');
          // Modern PDF aliases may share MIME objects whose enabledPlugin is
          // the canonical PDF plugin; do not demand equality to every alias.
          if (!plugins.includes(mime.enabledPlugin))
            note('collections', 0.65, 'Plugin MIME entry: enabledPlugin is outside PluginArray');
        }
      }
      for (const mime of mimes) {
        if (!mime) continue;
        named(nav.mimeTypes, mime, mime.type, 'MimeTypeArray');
        if (!root.MimeType || proto(mime) !== root.MimeType.prototype)
          note('collections', 0.65, 'MimeTypeArray entry: incorrect prototype');
        if (!plugins.includes(mime.enabledPlugin) || mime.enabledPlugin.namedItem(mime.type) !== mime)
          note('collections', 0.65, 'MimeTypeArray entry: broken enabledPlugin back-reference');
      }
      if (plugins.some(p => p && p.name === 'Chrome PDF Viewer') &&
          nav.plugins['Chrome PDF Viewer'] !== nav.plugins.namedItem('Chrome PDF Viewer'))
        note('collections', 0.65, 'Chrome PDF Viewer: named property mismatch');
    });

    safe('Automation globals', function () {
      // Inspect names only: reading arbitrary page properties can run getters.
      // Undetected drivers can remove these; their absence proves nothing.
      for (const key of ownNames(root)) {
        if (/^cdc_[A-Za-z0-9]+_(?:Array|Promise|Symbol|Object|Proxy|JSON|Window)$/.test(key) ||
            /^(?:__playwright__binding__|__pwInitScripts|_Selenium_IDE_Recorder|__webdriver_script_fn)$/.test(key))
          note('automation-globals', 0.3, 'Automation-associated global name: ' + key);
      }
    });
    const penalty = Math.min(1, Object.keys(scores).reduce((sum, key) => sum + scores[key], 0));
    return {
      receiverErrorText: receiverErrorText,
      tampering_detected: penalty >= 0.5,
      anomalies,
      confidence_penalty: Math.round(penalty * 1000) / 1000
    };
  }
  return Object.freeze({ collect });
});
