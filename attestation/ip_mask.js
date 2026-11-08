/**
 * ip_mask.js — IP Subnet Masking
 *
 * Masks IPv4 to /24 and IPv6 to /48 to bind attestation tokens to
 * a client's subnet without storing the full address (privacy-preserving).
 *
 * Handles:
 *   • Pure IPv4:           "192.168.1.42"    → "192.168.1.0/24"
 *   • IPv4-mapped IPv6:    "::ffff:10.0.0.5" → "10.0.0.0/24"
 *   • Full IPv6:           "2001:db8:85a3::1" → "2001:db8:85a3::/48"
 *   • Malformed / missing: returns "unknown"
 */

"use strict";

/**
 * @param {string|undefined} raw  — IP address (may include port or zone ID)
 * @returns {string}              — masked subnet string
 */
function maskIP(raw) {
  if (typeof raw !== "string" || raw.length === 0) return "unknown";

  let ip = raw.trim();

  // Strip surrounding brackets and trailing port / zone ID.
  // "[::1]:8080" → "::1"   |   "10.0.0.1:443" → "10.0.0.1"
  if (ip.startsWith("[")) {
    const close = ip.indexOf("]");
    if (close !== -1) ip = ip.slice(1, close);
  } else if (ip.includes(":") && ip.lastIndexOf(":") === ip.indexOf(":")) {
    // Single colon → IPv4 with port.  "1.2.3.4:80"
    ip = ip.slice(0, ip.indexOf(":"));
  }

  // ── IPv4-mapped IPv6 ─────────────────────────────────────────────
  const v4Mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i;
  const m = ip.match(v4Mapped);
  if (m) ip = m[1];

  // ── Pure IPv4 ─────────────────────────────────────────────────────
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const v4m = ip.match(v4);
  if (v4m) {
    const octets = v4m.slice(1).map(Number);
    if (octets.every((o) => o >= 0 && o <= 255)) {
      return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
    }
    return "unknown";
  }

  // ── IPv6 (/48 = first three 16-bit groups) ────────────────────────
  try {
    const expanded = expandIPv6(ip);
    if (expanded) {
      const groups = expanded.split(":");
      // RFC 4291 IPv4-mapped IPv6 uses 80 zero bits followed by ffff.
      // Hex and dotted spellings must share the IPv4 subnet policy; treating
      // the mapped prefix as /48 collapses every mapped IPv4 peer together.
      if (groups.slice(0, 5).every(group => group === "0000") && groups[5] === "ffff") {
        const high = parseInt(groups[6], 16), low = parseInt(groups[7], 16);
        return `${high >>> 8}.${high & 255}.${low >>> 8}.0/24`;
      }
      // Zero out groups 4–8 (indices 3–7) for /48.
      return (
        groups.slice(0, 3).join(":") + "::/48"
      );
    }
  } catch {
    // fall through
  }

  return "unknown";
}

/**
 * Expand an IPv6 address to its full 8-group colon-hex form.
 * Returns null on invalid input.
 *
 * @param {string} addr
 * @returns {string|null}
 */
function expandIPv6(addr) {
  // Remove zone ID (%eth0).
  const zoneIdx = addr.indexOf("%");
  if (zoneIdx !== -1) addr = addr.slice(0, zoneIdx);

  // Handle :: expansion.
  let halves;
  if (addr.includes("::")) {
    const parts = addr.split("::");
    if (parts.length !== 2) return null;
    const left = parts[0] ? parts[0].split(":") : [];
    const right = parts[1] ? parts[1].split(":") : [];
    const fill = 8 - left.length - right.length;
    if (fill <= 0) return null;
    halves = [...left, ...Array(fill).fill("0000"), ...right];
  } else {
    halves = addr.split(":");
  }

  if (halves.length !== 8) return null;

  const expanded = halves.map((g) => {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    return g.padStart(4, "0").toLowerCase();
  });

  if (expanded.includes(null)) return null;
  return expanded.join(":");
}

// TRUST_PROXY=1 is safe only when ingress is restricted to a proxy that
// appends the actual peer address. Never enable it on a public origin.
function getClientIP(req) {
  const forwarded = req.headers?.["x-forwarded-for"];
  if (process.env.TRUST_PROXY === "1" && typeof forwarded === "string") {
    const last = forwarded.split(",").pop().trim();
    const v4 = /^(?:::ffff:)?\d{1,3}(?:\.\d{1,3}){3}$/i.test(last);
    const v6 = /^[0-9a-f:]+$/i.test(last) && expandIPv6(last);
    if ((v4 || v6) && maskIP(last) !== "unknown") return last;
  }
  return req.socket?.remoteAddress || req.connection?.remoteAddress || "unknown";
}
module.exports = { maskIP, getClientIP };
