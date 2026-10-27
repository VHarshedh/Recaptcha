/**
 * runtime_integrity.js — Runtime Integrity Collector
 *
 * Detects automation frameworks, devtools, and runtime tampering.
 * All property accesses use bracket notation for compiler string encryption.
 * Object construction uses bracket assignment (no string-keyed literals).
 */

function collectRuntime() {
  var tampered = false;
  var signals = {};

  try {
    // Automation framework detection
    var dominated = (
      typeof window["callPhantom"] !== "undefined" ||
      typeof window["_phantom"] !== "undefined" ||
      typeof window["__nightmare"] !== "undefined" ||
      typeof window["domAutomation"] !== "undefined" ||
      typeof window["domAutomationController"] !== "undefined"
    );
    if (dominated) {
      tampered = true;
      signals["automationAPIs"] = true;
    }

    // WebDriver / CDP detection
    if (navigator["webdriver"] === true) {
      tampered = true;
      signals["automationAPIs"] = true;
    }

    // Puppeteer / Playwright injection
    if (typeof window["__puppeteer_evaluation_script__"] !== "undefined" ||
        typeof window["__playwright"] !== "undefined") {
      tampered = true;
      signals["automationAPIs"] = true;
    }

    // Selenium markers
    if (document["documentElement"]["getAttribute"]("webdriver") !== null ||
        typeof window["_Selenium_IDE_Recorder"] !== "undefined" ||
        typeof window["_selenium"] !== "undefined") {
      tampered = true;
      signals["automationAPIs"] = true;
    }

    // console.log override detection
    var clStr = Function["prototype"]["toString"]["call"](console["log"]);
    if (clStr["indexOf"]("[native code]") === -1) {
      signals["consoleOverride"] = true;
    }

    // Function.prototype.toString tampering
    var ftsStr = Function["prototype"]["toString"]["call"](Function["prototype"]["toString"]);
    if (ftsStr["indexOf"]("[native code]") === -1) {
      tampered = true;
    }

    // Iframe embedding detection
    try {
      if (window["self"] !== window["top"]) {
        signals["iframeEmbedded"] = true;
      }
    } catch (crossOriginErr) {
      signals["iframeEmbedded"] = true;
    }

    // DevTools size heuristic (works on Chromium)
    var widthDelta = window["outerWidth"] - window["innerWidth"];
    var heightDelta = window["outerHeight"] - window["innerHeight"];
    if (widthDelta > 160 || heightDelta > 160) {
      signals["devtools"] = true;
    }

    // Debugger timing probe
    var dbgT0 = performance["now"]();
    (function(){})["constructor"]("debugger")();
    var dbgDt = performance["now"]() - dbgT0;
    if (dbgDt > 100) {
      signals["debugger"] = true;
    }

    // Chrome extension protocol check
    if (window["chrome"] && window["chrome"]["runtime"] && window["chrome"]["runtime"]["id"]) {
      signals["extensionContext"] = true;
    }

    // Permissions inconsistency
    if (navigator["permissions"]) {
      navigator["permissions"]["query"]({ "name": "notifications" })["then"](function(permResult) {
        if (permResult["state"] === "prompt" && typeof Notification !== "undefined" &&
            Notification["permission"] !== "default") {
          signals["domManipulation"] = true;
        }
      })["catch"](function(){});
    }

  } catch (outerErr) {
    tampered = true;
  }

  var result = {};
  result["tampered"] = tampered;
  result["signals"] = signals;
  return result;
}
