"use strict";
const { isIP } = require("node:net");

// Canonical identity for pure socket/forwarded IP addresses. Never interpret a
// hostname, port or URL as an identity. IPv4-mapped IPv6 shares its IPv4 identity.
function normalizeIP(raw) {
  if (typeof raw !== "string") return "unknown";
  let ip = raw.trim();
  // OS socket addresses may carry an IPv6 interface scope.
  const zone = ip.indexOf("%");
  if (zone !== -1) {
    if (!/^[A-Za-z0-9_.-]+$/.test(ip.slice(zone + 1))) return "unknown";
    ip = ip.slice(0, zone);
    if (isIP(ip) !== 6) return "unknown";
  }
  const family = isIP(ip);
  if (family === 4) return ip;
  if (family !== 6) return "unknown";
  // WHATWG URL serializes valid mixed IPv6 notation to hexadecimal groups.
  const compressed = new URL("http://[" + ip + "]/").hostname.slice(1, -1);
  const [leftPart, rightPart] = compressed.split("::");
  const left = leftPart ? leftPart.split(":") : [];
  const right = rightPart ? rightPart.split(":") : [];
  const groups = rightPart === undefined ? left : [...left, ...Array(8-left.length-right.length).fill("0"), ...right];
  const numbers = groups.map(group => parseInt(group, 16));
  if (numbers.slice(0,5).every(n => n === 0) && numbers[5] === 65535) {
    return `${numbers[6] >>> 8}.${numbers[6] & 255}.${numbers[7] >>> 8}.${numbers[7] & 255}`;
  }
  return numbers.map(n => n.toString(16).padStart(4,"0")).join(":");
}

// Token subnet policy: IPv4 /24, native IPv6 /48. Legacy callers may supply
// bracketed IPv6 or an IPv4 address with a port; forwarded identities may not.
function maskIP(raw) {
  if (typeof raw !== "string") return "unknown";
  let ip = raw.trim();
  if (ip.startsWith("[")) {
    const match = /^\[([^\]]+)\](?::\d+)?$/.exec(ip);
    if (!match) return "unknown";
    ip = match[1];
  } else if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(ip)) {
    ip = ip.slice(0,ip.lastIndexOf(":"));
  }
  ip = normalizeIP(ip);
  if (ip === "unknown") return ip;
  if (isIP(ip) === 4) return ip.split(".").slice(0,3).join(".") + ".0/24";
  return ip.split(":").slice(0,3).join(":") + "::/48";
}

// Only enable behind trusted ingress that appends/overwrites the actual peer.
function getClientIP(req) {
  const forwarded = req.headers?.["x-forwarded-for"];
  if (process.env.TRUST_PROXY === "1" && forwarded !== undefined) {
    if (typeof forwarded !== "string") return "unknown";
    // A malformed trusted header must not collapse users onto the proxy's IP.
    return normalizeIP(forwarded.split(",").pop());
  }
  return normalizeIP(req.socket?.remoteAddress || req.connection?.remoteAddress);
}
module.exports = { maskIP, getClientIP, normalizeIP };
