"use strict";
function normalizeOrigin(value) {
  if (typeof value !== "string") return "";
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) && !url.username && !url.password &&
      url.pathname === "/" && !url.search && !url.hash ? url.origin : "";
  } catch { return ""; }
}
function requestHostOrigin(req) {
  const host = req.headers?.host;
  return typeof host === "string" ? normalizeOrigin((req.socket?.encrypted ? "https://" : "http://") + host) : "";
}
function requestOrigin(req) {
  return req.headers?.origin === undefined ? requestHostOrigin(req) : normalizeOrigin(req.headers.origin);
}
module.exports = { normalizeOrigin, requestHostOrigin, requestOrigin };
