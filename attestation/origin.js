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
  const forwarded = req.headers?.["x-forwarded-proto"];
  if (process.env.TRUST_PROXY === "1" && forwarded !== undefined && !["http", "https"].includes(forwarded)) return "";
  const secure = process.env.TRUST_PROXY === "1" && forwarded !== undefined ? forwarded === "https" : req.socket?.encrypted;
  return typeof host === "string" ? normalizeOrigin((secure ? "https://" : "http://") + host) : "";
}
function requestOrigin(req) {
  return req.headers?.origin === undefined ? requestHostOrigin(req) : normalizeOrigin(req.headers.origin);
}
module.exports = { normalizeOrigin, requestHostOrigin, requestOrigin };
