import hashlib

import pytest

from tplink_guard.crypto import aes, rsa


def test_aes_fips197_vector():
    rk = aes.expand_key(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = aes.encrypt_block(pt, rk)
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    assert aes.decrypt_block(ct, rk) == pt


def test_aes_cbc_sp800_38a_vector():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    ct = aes.cbc_encrypt(key, iv, pt)
    assert ct[:32].hex() == "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
    assert aes.cbc_decrypt(key, iv, ct) == pt


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1000])
def test_aes_cbc_roundtrip(size):
    key, iv = b"0123456789abcdef", b"fedcba9876543210"
    data = bytes(range(256)) * 4
    assert aes.cbc_decrypt(key, iv, aes.cbc_encrypt(key, iv, data[:size])) == data[:size]


def test_bad_padding_rejected():
    with pytest.raises(ValueError):
        aes.pkcs7_unpad(b"\x00" * 15 + b"\x05")


# Small fixed RSA key (512-bit) so the tests can decrypt what we encrypt.
P = 0xF7E75FDC469067FFDC4E847C51F452DF8A3F1E7F1D2B9F6F7A8D3E5A2C4B1F6D
Q = 0xE85CED54AF57E53E092113E62F436F4F2D4E5B6C7A8F9D0E1F2A3B4C5D6E7F81


def _keypair():
    def next_prime(n):
        def is_prime(k):
            if k < 2:
                return False
            for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
                if k % p == 0:
                    return k == p
            d, s = k - 1, 0
            while d % 2 == 0:
                d //= 2
                s += 1
            for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
                x = pow(a, d, k)
                if x in (1, k - 1):
                    continue
                for _ in range(s - 1):
                    x = pow(x, 2, k)
                    if x == k - 1:
                        break
                else:
                    return False
            return True

        n |= 1
        while not is_prime(n):
            n += 2
        return n

    p, q = next_prime(P), next_prime(Q)
    n, e = p * q, 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    return n, e, d


def _decrypt(ct: bytes, n: int, d: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    return pow(int.from_bytes(ct, "big"), d, n).to_bytes(k, "big")


def test_pkcs1_v15_padding_structure():
    n, e, d = _keypair()
    em = _decrypt(rsa.pkcs1_v15_encrypt(b"secret", n, e), n, d)
    assert em[:2] == b"\x00\x02"
    sep = em.index(b"\x00", 2)
    assert sep >= 10 and b"\x00" not in em[2:sep]
    assert em[sep + 1:] == b"secret"


def test_oaep_padding_decodes():
    n, e, d = _keypair()
    k = (n.bit_length() + 7) // 8
    em = _decrypt(rsa.oaep_encrypt(b"k=1&i=2", n, e), n, d)
    masked_seed, masked_db = em[1:21], em[21:]
    seed = bytes(a ^ b for a, b in zip(masked_seed, rsa._mgf1(masked_db, 20)))
    db = bytes(a ^ b for a, b in zip(masked_db, rsa._mgf1(seed, k - 21)))
    assert em[0] == 0
    assert db[:20] == hashlib.sha1(b"").digest()
    assert db[db.index(b"\x01", 20) + 1:] == b"k=1&i=2"


def test_encrypt_hex_is_full_width():
    n, e, _ = _keypair()
    out = rsa.encrypt_hex("pw", format(n, "x"), format(e, "x"))
    assert len(out) == 2 * ((n.bit_length() + 7) // 8)


def test_message_too_long():
    n, e, _ = _keypair()
    with pytest.raises(ValueError):
        rsa.pkcs1_v15_encrypt(b"x" * 64, n, e)
