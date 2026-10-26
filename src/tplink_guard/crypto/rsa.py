"""
RSA public-key encryption (PKCS#1 v1.5 and OAEP/SHA-1), standard library only.

The router hands out bare (modulus, exponent) pairs as hex strings; we only
ever encrypt with them, so no key parsing or private-key math is needed.
"""

from __future__ import annotations

import hashlib
import os


def _key_len(n: int) -> int:
    return (n.bit_length() + 7) // 8


def _raw(message: bytes, n: int, e: int) -> bytes:
    k = _key_len(n)
    return pow(int.from_bytes(message, "big"), e, n).to_bytes(k, "big")


def pkcs1_v15_encrypt(message: bytes, n: int, e: int) -> bytes:
    k = _key_len(n)
    if len(message) > k - 11:
        raise ValueError("message too long for RSA key")
    ps = bytearray()
    while len(ps) < k - 3 - len(message):
        ps += bytes(b for b in os.urandom(k) if b)
    ps = bytes(ps[:k - 3 - len(message)])
    return _raw(b"\x00\x02" + ps + b"\x00" + message, n, e)


def _mgf1(seed: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha1(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def oaep_max_len(n: int) -> int:
    return _key_len(n) - 2 * 20 - 2


def oaep_encrypt(message: bytes, n: int, e: int) -> bytes:
    k = _key_len(n)
    if len(message) > oaep_max_len(n):
        raise ValueError("message too long for RSA key")
    l_hash = hashlib.sha1(b"").digest()
    db = l_hash + b"\x00" * (k - len(message) - 42) + b"\x01" + message
    seed = os.urandom(20)
    masked_db = bytes(a ^ b for a, b in zip(db, _mgf1(seed, k - 21)))
    masked_seed = bytes(a ^ b for a, b in zip(seed, _mgf1(masked_db, 20)))
    return _raw(b"\x00" + masked_seed + masked_db, n, e)


def encrypt_hex(message: str, n_hex: str, e_hex: str, *, oaep: bool = False) -> str:
    """Encrypt ``message`` and return lowercase hex, zero-padded to the key size."""
    n, e = int(n_hex, 16), int(e_hex, 16)
    fn = oaep_encrypt if oaep else pkcs1_v15_encrypt
    return fn(message.encode(), n, e).hex()
