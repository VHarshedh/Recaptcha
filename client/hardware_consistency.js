/**
 * hardware_consistency.js — Hardware Fingerprinting Collector
 *
 * Collects hardware signals and detects headless / VM environments.
 * Bracket-notation throughout for compiler string encryption.
 */

function collectHardware() {
  var consistent = true;
  var result = {};

  try {
    // CPU cores
    result["cores"] = navigator["hardwareConcurrency"] || 0;
    if (result["cores"] === 0) consistent = false;

    // Device memory (Chrome / Edge)
    result["memory"] = navigator["deviceMemory"] || 0;

    // Platform
    result["platform"] = navigator["platform"] || "";

    // User-Agent
    result["userAgent"] = navigator["userAgent"] || "";

    // Touch support
    var hasTouchStart = "ontouchstart" in window;
    var hasTouchPoints = navigator["maxTouchPoints"] > 0;
    result["touchSupport"] = hasTouchStart || hasTouchPoints;

    // Mobile heuristic
    var mobileRE = /Mobi|Android/i;
    result["mobile"] = mobileRE["test"](navigator["userAgent"]);

    // Screen metrics
    var sw = screen["width"];
    var sh = screen["height"];
    var cd = screen["colorDepth"];
    var dpr = window["devicePixelRatio"] || 1;
    result["screenWidth"] = sw;
    result["screenHeight"] = sh;
    result["colorDepth"] = cd || 0;
    result["devicePixelRatio"] = dpr;
    result["screenConsistent"] = (sw > 0 && sh > 0 && dpr > 0 && cd > 0);

    // WebGL renderer / vendor
    try {
      var cvs = document["createElement"]("canvas");
      var glCtx = cvs["getContext"]("webgl") || cvs["getContext"]("experimental-webgl");
      if (glCtx) {
        var dbgExt = glCtx["getExtension"]("WEBGL_debug_renderer_info");
        if (dbgExt) {
          result["gpuRenderer"] = glCtx["getParameter"](dbgExt["UNMASKED_RENDERER_WEBGL"]);
          result["gpuVendor"] = glCtx["getParameter"](dbgExt["UNMASKED_VENDOR_WEBGL"]);
        }
      }
    } catch (glErr) {}

    // Headless renderer indicators
    if (result["gpuRenderer"]) {
      var rendererStr = result["gpuRenderer"];
      var headlessRE = /SwiftShader|LLVMpipe|llvmpipe|Mesa|Microsoft Basic Render/i;
      if (headlessRE["test"](rendererStr)) {
        consistent = false;
      }
    }

    // Language list
    var langs = navigator["languages"];
    result["languages"] = langs ? langs["length"] : 0;
    if (result["languages"] === 0) consistent = false;

    // Timezone offset
    result["timezoneOffset"] = new Date()["getTimezoneOffset"]();

    // Connection info
    var conn = navigator["connection"] || navigator["mozConnection"] || navigator["webkitConnection"];
    if (conn) {
      result["connectionType"] = conn["effectiveType"] || "unknown";
    }

  } catch (outerErr) {
    consistent = false;
  }

  result["consistent"] = consistent;
  return result;
}
