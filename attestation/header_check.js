"use strict";

const { requestOrigin, requestHostOrigin } = require("./origin");
const { getClientIP } = require("./ip_mask");

function extractHeaderProfile(req) {
  const h = req.headers || {};
  const read = name => typeof h[name] === "string" ? h[name] : "";
  return {
    origin: requestOrigin(req), host: requestHostOrigin(req),
    ua: read("user-agent"), acceptLanguage: read("accept-language"),
    secChUa: read("sec-ch-ua"), secChUaMobile: read("sec-ch-ua-mobile"),
    secChUaPlatform: read("sec-ch-ua-platform"),
    secFetchSite: read("sec-fetch-site"), secFetchMode: read("sec-fetch-mode"),
    clientIP: getClientIP(req),
  };
}

// Consistency evidence, not browser authentication: all client claims can be forged.
function verifyHeaderConsistency(initial, current, telemetry) {
  const anomalies = [];
  let penalty = 0;
  const note = (code, weight) => { anomalies.push(code); penalty += weight; };
  if (!initial) note("missing_initial_header_profile", 1);
  else {
    for (const field of ["origin", "host", "ua", "acceptLanguage", "secChUa", "secChUaMobile", "secChUaPlatform", "clientIP"]) {
      if (initial[field] !== current[field]) note(field + "_changed_mid_session", 0.6);
    }
  }
  if (!current.ua || telemetry?.hardware?.profile?.userAgent !== current.ua)
    note("http_ua_vs_js_ua_mismatch", 0.9);

  // Fetch metadata absence is weak evidence. Chrome hint/engine mismatches below
  // deliberately trigger step-up under this deployment's stricter policy.
  if (!current.secFetchSite || !current.secFetchMode) note("missing_sec_fetch_headers", 0.05);
  if (!current.acceptLanguage) note("missing_accept_language", 0.05);
  const chromium = /Chrome\/\d+/.test(current.ua);
  const firefox = /Firefox\/\d+/.test(current.ua);
  const receiver = telemetry?.runtime?.receiverErrorText;
  const error = typeof receiver === "string" ? receiver : "";
  if (!error) note("missing_receiver_error", 0.1);
  if (chromium) {
    if (!current.secChUa || !current.secChUaPlatform || !current.secChUaMobile)
      note("chrome_ua_missing_client_hints", 0.25);
    if (error !== "TypeError: Illegal invocation")
      note("chrome_ua_non_v8_receiver_error", 0.8);
  }
  if (firefox) {
    if (current.secChUa || current.secChUaPlatform || current.secChUaMobile)
      note("firefox_ua_sent_chrome_client_hints", 0.8);
    if (/Illegal invocation/.test(error)) note("firefox_ua_with_v8_engine_error", 0.8);
  }
  return { penalty: Math.min(1, penalty), anomalies };
}

module.exports = { extractHeaderProfile, verifyHeaderConsistency };
