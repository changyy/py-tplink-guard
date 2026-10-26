"""
Pure-Python AES-128-CBC with PKCS#7 padding.

The router admin protocol wraps every request in AES-CBC with a 16-byte
key/IV chosen by the client. Payloads are small (a few KB at most), so a
straightforward table-based implementation is fast enough and lets the
package stay dependency-free.
"""

from __future__ import annotations

BLOCK = 16


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a


def _gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _build_sbox() -> tuple[list[int], list[int]]:
    # Multiplicative inverse in GF(2^8) followed by the affine transform.
    inv = [0] * 256
    for x in range(1, 256):
        for y in range(1, 256):
            if _gmul(x, y) == 1:
                inv[x] = y
                break
    sbox = [0] * 256
    for x in range(256):
        b = inv[x]
        s = b
        for shift in range(1, 5):
            s ^= ((b << shift) | (b >> (8 - shift))) & 0xFF
        sbox[x] = s ^ 0x63
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sbox()
_MUL = {n: [_gmul(x, n) for x in range(256)] for n in (2, 3, 9, 11, 13, 14)}
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def expand_key(key: bytes) -> list[list[int]]:
    if len(key) != 16:
        raise ValueError("AES-128 needs a 16-byte key")
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(words[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= _RCON[i // 4 - 1]
        words.append([a ^ b for a, b in zip(words[i - 4], t)])
    return [sum(words[r * 4:r * 4 + 4], []) for r in range(11)]


def _add(s: list[int], k: list[int]) -> list[int]:
    return [a ^ b for a, b in zip(s, k)]


# State is column-major: byte index = col * 4 + row.
_SHIFT = [(c * 4 + r + 4 * r) % 16 for c in range(4) for r in range(4)]
_INV_SHIFT = [0] * 16
for _i, _j in enumerate(_SHIFT):
    _INV_SHIFT[_j] = _i


def encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    m2, m3 = _MUL[2], _MUL[3]
    s = _add(list(block), round_keys[0])
    for rnd in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[i] for i in _SHIFT]
        if rnd != 10:
            out = []
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c:c + 4]
                out += [
                    m2[a0] ^ m3[a1] ^ a2 ^ a3,
                    a0 ^ m2[a1] ^ m3[a2] ^ a3,
                    a0 ^ a1 ^ m2[a2] ^ m3[a3],
                    m3[a0] ^ a1 ^ a2 ^ m2[a3],
                ]
            s = out
        s = _add(s, round_keys[rnd])
    return bytes(s)


def decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
    s = _add(list(block), round_keys[10])
    for rnd in range(9, -1, -1):
        s = [s[i] for i in _INV_SHIFT]
        s = [INV_SBOX[b] for b in s]
        s = _add(s, round_keys[rnd])
        if rnd != 0:
            out = []
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c:c + 4]
                out += [
                    m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3],
                    m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3],
                    m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3],
                    m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3],
                ]
            s = out
    return bytes(s)


def pkcs7_pad(data: bytes) -> bytes:
    n = BLOCK - len(data) % BLOCK
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK:
        raise ValueError("invalid padded length")
    n = data[-1]
    if not 1 <= n <= BLOCK or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-n]


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    rk = expand_key(key)
    prev = iv
    out = bytearray()
    data = pkcs7_pad(plaintext)
    for i in range(0, len(data), BLOCK):
        prev = encrypt_block(bytes(a ^ b for a, b in zip(data[i:i + BLOCK], prev)), rk)
        out += prev
    return bytes(out)


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) % BLOCK:
        raise ValueError("ciphertext is not a multiple of the block size")
    rk = expand_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK):
        block = ciphertext[i:i + BLOCK]
        out += bytes(a ^ b for a, b in zip(decrypt_block(block, rk), prev))
        prev = block
    return pkcs7_unpad(bytes(out))
