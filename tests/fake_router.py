"""
In-process fake of the router's /cgi-bin/luci admin endpoint.

It plays the server side of both wire schemes: it decrypts and checks the
RSA/HMAC signatures, the hash and the sequence number, so the tests exercise
the real client handshake rather than a mock of it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from urllib.parse import parse_qsl, unquote, urlsplit

from tplink_guard.crypto import aes, rsa

from .test_crypto import _decrypt, _keypair

USER, PASSWORD = "admin", "s3cret"


def _unpad_v15(em: bytes) -> bytes:
    assert em[:2] == b"\x00\x02"
    return em[em.index(b"\x00", 2) + 1:]


def _unpad_oaep(em: bytes, k: int) -> bytes:
    seed = bytes(a ^ b for a, b in zip(em[1:21], rsa._mgf1(em[21:], 20)))
    db = bytes(a ^ b for a, b in zip(em[21:], rsa._mgf1(seed, k - 21)))
    return db[db.index(b"\x01", 20) + 1:]


class FakeRouter:
    def __init__(self, scheme: str = "classic") -> None:
        self.scheme = scheme
        self.n, self.e, self.d = _keypair()
        self.k = (self.n.bit_length() + 7) // 8
        self.seq = 1000
        self.key = self.iv = b""
        self.hash = ""
        self.stok = "STOK123"
        self.calls: list[tuple[str, dict]] = []
        self.handlers = {}
        self.timeout = 5

    # -- transport API --------------------------------------------------

    def post(self, url, body, headers):
        parts = urlsplit(url)
        path = unquote(parts.path)
        query = dict(parse_qsl(parts.query))
        if path.endswith("/device_config"):
            certs = ["SG CLS L1 STAGE2"] if self.scheme == "sg" else []
            return 200, {}, json.dumps({"success": True, "data": {"certification": certs}})
        if path.endswith("/login") and query.get("form") in ("keys", "auth"):
            if body:
                return 200, {}, json.dumps({"success": False, "errorcode": "no such callback"})
            nn, ee = format(self.n, "X"), format(self.e, "06X")
            if query["form"] == "keys":
                return 200, {}, json.dumps({"success": True, "data": {"password": [nn, ee]}})
            return 200, {}, json.dumps({"success": True, "data": {"key": [nn, ee], "seq": self.seq}})
        form = dict(parse_qsl(body))
        if path.endswith("/login"):
            return self._login(form)
        assert f";stok={self.stok}/" in path, path
        assert headers.get("Cookie") == "sysauth=COOKIE"
        return self._request(path.split(f";stok={self.stok}/", 1)[1], query, form)

    # -- server side ----------------------------------------------------

    def _split_sign(self, sign: str) -> list[bytes]:
        width = 2 * self.k
        return [bytes.fromhex(sign[i:i + width]) for i in range(0, len(sign), width)]

    def _login(self, form):
        oaep = self.scheme == "sg"
        text = b"".join(
            (_unpad_oaep if oaep else lambda em, k: _unpad_v15(em))(_decrypt(c, self.n, self.d), self.k)
            for c in self._split_sign(form["sign"])
        ).decode()
        fields = dict(parse_qsl(text))
        self.key, self.iv = fields["k"].encode(), fields["i"].encode()
        algo = hashlib.sha256 if oaep else hashlib.md5
        assert int(fields["s"]) == self.seq + len(form["data"])
        plain = dict(parse_qsl(self._dec(form["data"])))
        pwd = _unpad_v15(_decrypt(bytes.fromhex(plain["password"]), self.n, self.d)).decode()
        if pwd != PASSWORD or fields["h"] != algo((USER + PASSWORD).encode()).hexdigest():
            return 200, {}, json.dumps({"data": self._enc({"success": False, "data": {"errorcode": "login failed"}})})
        self.hash = fields["h"]
        reply = {"success": True, "data": {"stok": self.stok}}
        return 200, {"set-cookie": ["sysauth=COOKIE; path=/cgi-bin/luci"]}, json.dumps({"data": self._enc(reply)})

    def _request(self, path, query, form):
        data, sign = form["data"], form["sign"]
        if self.scheme == "sg":
            h = hashlib.sha256(data.encode()).hexdigest()
            expect = f"h={h}&s={self.seq + len(data)}"
            key = f"k={self.key.decode()}&i={self.iv.decode()}".encode()
            want = "".join(
                hmac.new(key, expect[i:i + 53].encode(), hashlib.sha256).hexdigest() for i in range(0, len(expect), 53)
            )
            assert sign == want
            params = json.loads(self._dec(data))
        else:
            text = b"".join(_unpad_v15(_decrypt(c, self.n, self.d)) for c in self._split_sign(sign)).decode()
            assert text == f"h={self.hash}&s={self.seq + len(data)}"
            params = dict(parse_qsl(self._dec(data)))
            if "operation" in query:
                return 200, {}, json.dumps({"data": self._enc({"success": False, "errorcode": "no such callback"})})
        endpoint = path.split("?", 1)[0] + "?form=" + query.get("form", "")
        self.calls.append((endpoint, params))
        handler = self.handlers.get((endpoint, params.get("operation")))
        reply = handler(params) if handler else {"success": False, "errorcode": "no such callback"}
        return 200, {}, json.dumps({"data": self._enc(reply)})

    def _enc(self, obj) -> str:
        return base64.b64encode(aes.cbc_encrypt(self.key, self.iv, json.dumps(obj).encode())).decode()

    def _dec(self, data: str) -> str:
        return aes.cbc_decrypt(self.key, self.iv, base64.b64decode(data)).decode()
