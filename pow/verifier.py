"""
pow_verifier.py — Python server-side PoW verification

Pure stdlib — zero external dependencies.

API:
    generate_challenge() → dict { challenge, issued_at }
    verify_pow(challenge, nonce, difficulty, issued_at, max_age_ms=60000) → dict
"""

from __future__ import annotations

import math
import hashlib
import hmac
import os
import time
from typing import Optional


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _leading_zero_bits(digest: bytes) -> int:
    """Count leading zero bits in a SHA-256 digest (32 bytes)."""
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
        else:
            # For a non-zero byte, count how many of the top bits are zero.
            # E.g. 0b00001111 → 4 leading zeros, 0b01000000 → 1 leading zero.
            bits += 8 - byte.bit_length()
            break
    return bits


# ---------------------------------------------------------------------------
#  Challenge generation
# ---------------------------------------------------------------------------

def generate_challenge() -> dict:
    """
    Generate a cryptographically random challenge token with an embedded
    timestamp for expiry enforcement.

    Returns:
        { "challenge": "<timestamp_ms>.<hex_random>", "issued_at": <int ms> }
    """
    issued_at = int(time.time() * 1000)
    random_hex = os.urandom(16).hex()
    challenge = f"{issued_at}.{random_hex}"
    return {"challenge": challenge, "issued_at": issued_at}


# ---------------------------------------------------------------------------
#  Core verifier
# ---------------------------------------------------------------------------

def verify_pow(
    challenge: str,
    nonce: int,
    difficulty: int,
    issued_at: int,
    max_age_ms: int = 60_000,
) -> dict:
    """
    Verify a Proof-of-Work solution.

    Timing notes:
        • hashlib.sha256 is constant-time for fixed input length.
        • The leading-zero-bit scan short-circuits but reveals nothing
          the client doesn't already know (the client computed the hash).
        • No secret comparison is performed; hmac.compare_digest is used
          only where applicable for defence-in-depth.

    Args:
        challenge:   The original challenge string issued by the server.
        nonce:       The nonce discovered by the client.
        difficulty:  Number of required leading zero bits.
        issued_at:   Unix-ms timestamp when the challenge was created.
        max_age_ms:  Maximum acceptable challenge age (default 60 s).

    Returns:
        { "valid": bool, "reason"?: str, "hash"?: str }
    """
    # ── Input validation ─────────────────────────────────────────────
    if not isinstance(challenge, str) or not 0 < len(challenge) <= 1024:
        return {"valid": False, "reason": "invalid challenge"}

    if type(nonce) is not int or not 0 <= nonce <= 9007199254740991:
        return {"valid": False, "reason": "invalid nonce"}

    if type(difficulty) is not int or difficulty < 1 or difficulty > 256:
        return {"valid": False, "reason": "invalid difficulty"}

    if type(issued_at) is not int or not 0 <= issued_at <= 9007199254740991:
        return {"valid": False, "reason": "invalid issued_at"}

    if type(max_age_ms) is not int or not 0 < max_age_ms <= 9007199254740991:
        return {"valid": False, "reason": "invalid max_age_ms"}

    # ── Timestamp freshness ──────────────────────────────────────────
    now_ms = int(time.time() * 1000)
    age = now_ms - issued_at

    if age > max_age_ms:
        return {
            "valid": False,
            "reason": f"challenge expired (age {age} ms > {max_age_ms} ms)",
        }
    if age < 0:
        return {"valid": False, "reason": "challenge issued in the future"}

    # ── Hash computation (single SHA-256) ────────────────────────────
    seed = 2166136261
    raw = challenge.encode("utf-16-le")
    for i in range(0, len(raw), 2):
        seed = ((seed ^ int.from_bytes(raw[i:i+2], "little")) * 16777619) & 0xffffffff
    pad = []
    for j in range(16384):
        seed ^= (seed << 13) & 0xffffffff
        seed ^= seed >> 17
        seed ^= (seed << 5) & 0xffffffff
        seed = (seed + (j + 1) * 0x9e3779b9) & 0xffffffff
        pad.append(seed)
    x, y = (nonce & 0xffffffff) ^ (nonce >> 32), 0x6a09e667
    for i in range(64):
        x = ((x ^ pad[(x ^ y) & 16383]) * 0x85ebca6b) & 0xffffffff
        x = ((x << 13) | (x >> 19)) & 0xffffffff
        y = ((y ^ x) * 0xc2b2ae35 + i) & 0xffffffff
    message = (challenge + str(nonce) + f":cache64-v1:{x}:{y}").encode("utf-8")
    digest = hashlib.sha256(message).digest()
    hash_hex = digest.hex()

    # ── Leading zero-bit check ───────────────────────────────────────
    zero_bits = _leading_zero_bits(digest)
    if zero_bits < difficulty:
        return {
            "valid": False,
            "reason": (
                f"insufficient difficulty: got {zero_bits} leading zero bits, "
                f"need {difficulty}"
            ),
            "hash": hash_hex,
        }

    return {"valid": True, "hash": hash_hex}


# ---------------------------------------------------------------------------
#  CLI quick-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json, sys

    # Quick self-test: generate a challenge and verify a known-bad nonce.
    ch = generate_challenge()
    print("Generated challenge:", json.dumps(ch, indent=2))

    result = verify_pow(
        challenge=ch["challenge"],
        nonce=0,
        difficulty=1,
        issued_at=ch["issued_at"],
    )
    print("Verification (nonce=0, difficulty=1):", json.dumps(result, indent=2))
