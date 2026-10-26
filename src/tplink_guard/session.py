"""
Encrypted session with a TP-Link router's local admin CGI (``/cgi-bin/luci``).

Two wire schemes exist in the wild; both share the same handshake shape:

1. ``POST login?form=keys``  -> RSA key used to encrypt the password
2. ``POST login?form=auth``  -> RSA key + sequence number used for signatures
3. ``POST login?form=login`` -> AES-encrypted login, returns ``stok`` + cookie

``classic``  MD5(user+pass) hash, every request signed with RSA PKCS#1 v1.5,
             AES key/IV are 16 hex chars, form-encoded plaintext.
``sg``       Newer SG / CE-RED certified firmware (Wi-Fi 7 era): SHA-256
             hashes, OAEP login signature, HMAC-SHA256 request signatures,
             AES key/IV are 16 decimal digits, JSON plaintext.

Only HTTPS is accepted. The router's self-signed certificate is not verified
(there is no CA to verify it against), but traffic is still encrypted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from .crypto import cbc_decrypt, cbc_encrypt, encrypt_hex
from .crypto.rsa import oaep_max_len

SIGN_CHUNK = 53
SG_CERTIFICATIONS = {"SG CLS L1 STAGE2", "EU CE RED"}


class RouterError(Exception):
    """The router answered, but not with what we expected."""


class AuthError(RouterError):
    """Login was rejected."""


def normalize_host(host: str) -> str:
    """Return ``https://host[:port]``; plain HTTP is refused."""
    host = host.strip().rstrip("/")
    if "://" not in host:
        host = "https://" + host
    parts = urlsplit(host)
    if parts.scheme != "https":
        raise ValueError(f"only https:// is supported, got {host!r}")
    return f"https://{parts.netloc}"


def insecure_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class Transport:
    """Minimal HTTPS POST client (urllib) that skips certificate verification."""

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout
        self._ctx = insecure_ssl_context()

    def post(self, url: str, body: str, headers: dict[str, str]) -> tuple[int, dict[str, list[str]], str]:
        req = urllib.request.Request(url, data=body.encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                return resp.status, _headers(resp.headers), resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, _headers(exc.headers), exc.read().decode("utf-8", "replace")


def _headers(msg) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for k, v in msg.items():
        out.setdefault(k.lower(), []).append(v)
    return out


def _json(text: str, what: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise RouterError(f"{what}: router did not return JSON ({text[:120]!r})") from exc
    if not isinstance(data, dict):
        raise RouterError(f"{what}: unexpected response {data!r}")
    return data


class Session:
    """Logged-in admin session. Use :meth:`request` for authenticated calls."""

    def __init__(
        self,
        host: str,
        password: str,
        username: str = "admin",
        scheme: str = "auto",
        transport: Transport | None = None,
    ) -> None:
        if scheme not in ("auto", "classic", "sg"):
            raise ValueError(f"unknown scheme {scheme!r}")
        self.host = normalize_host(host)
        self.username = username
        self.password = password
        self.scheme = scheme
        self.transport = transport or Transport()
        self.stok = ""
        self.sysauth = ""
        self._key = b""
        self._iv = b""
        self._seq = 0
        self._sign_n = ""
        self._sign_e = ""
        self._hash = ""

    # -- low level -------------------------------------------------------

    @property
    def _referer_headers(self) -> dict[str, str]:
        return {
            "Referer": f"{self.host}/webpages/index.html",
            "Origin": self.host,
            "Content-Type": "application/x-www-form-urlencoded",
        }

    def _url(self, path: str, stok: str | None = None) -> str:
        return f"{self.host}/cgi-bin/luci/;stok={self.stok if stok is None else stok}/{path.lstrip('/')}"

    def _post(self, url: str, body: str, cookie: bool = False) -> tuple[int, dict[str, list[str]], str]:
        headers = dict(self._referer_headers)
        if cookie and self.sysauth:
            headers["Cookie"] = f"sysauth={self.sysauth}"
        return self.transport.post(url, body, headers)

    def public_read(self, path: str, body: str = "operation=read") -> dict[str, Any]:
        """Unauthenticated call (handshake / discovery endpoints)."""
        _, _, text = self._post(self._url(path, stok=""), body)
        return _json(text, path)

    def _encrypt(self, plaintext: str) -> str:
        return base64.b64encode(cbc_encrypt(self._key, self._iv, plaintext.encode())).decode()

    def _decrypt(self, data: str) -> str:
        return cbc_decrypt(self._key, self._iv, base64.b64decode(data)).decode()

    def _rsa_sign(self, text: str, oaep: bool) -> str:
        step = SIGN_CHUNK
        if oaep:
            step = min(SIGN_CHUNK, oaep_max_len(int(self._sign_n, 16)))
        return "".join(
            encrypt_hex(text[i:i + step], self._sign_n, self._sign_e, oaep=oaep)
            for i in range(0, len(text), step)
        )

    def _hmac_sign(self, text: str) -> str:
        key = f"k={self._key.decode()}&i={self._iv.decode()}".encode()
        return "".join(
            hmac.new(key, text[i:i + SIGN_CHUNK].encode(), hashlib.sha256).hexdigest()
            for i in range(0, len(text), SIGN_CHUNK)
        )

    # -- handshake -------------------------------------------------------

    def detect_scheme(self) -> str:
        try:
            data = self.public_read("device_config?form=config")
            certs = (data.get("data") or {}).get("certification") or []
            if any(c in SG_CERTIFICATIONS for c in certs):
                return "sg"
        except RouterError:
            pass
        return "classic"

    def login(self) -> None:
        if self.scheme == "auto":
            self.scheme = self.detect_scheme()
        keys = self.public_read("login?form=keys&operation=read", body="")
        auth = self.public_read("login?form=auth&operation=read", body="")
        try:
            pwd_n, pwd_e = keys["data"]["password"][:2]
            self._sign_n, self._sign_e = auth["data"]["key"][:2]
            self._seq = int(auth["data"]["seq"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RouterError(f"unexpected handshake response: {keys!r} / {auth!r}") from exc

        sg = self.scheme == "sg"
        if sg:
            self._key = "".join(secrets.choice("0123456789") for _ in range(16)).encode()
            self._iv = "".join(secrets.choice("0123456789") for _ in range(16)).encode()
            self._hash = hashlib.sha256((self.username + self.password).encode()).hexdigest()
        else:
            self._key = secrets.token_hex(8).encode()
            self._iv = secrets.token_hex(8).encode()
            self._hash = hashlib.md5((self.username + self.password).encode()).hexdigest()

        enc_pwd = encrypt_hex(self.password, pwd_n, pwd_e)
        data = self._encrypt(f"operation=login&password={enc_pwd}&confirm=true")
        aes_kv = f"k={self._key.decode()}&i={self._iv.decode()}"
        sign = self._rsa_sign(f"{aes_kv}&h={self._hash}&s={self._seq + len(data)}", oaep=sg)

        status, headers, text = self._post(
            self._url("login?form=login", stok=""), f"sign={sign}&data={quote(data, safe='')}"
        )
        reply = self._decode(text, "login")
        if not reply.get("success"):
            detail = reply.get("data") or reply
            raise AuthError(f"login rejected (HTTP {status}): {detail}")
        self.stok = reply["data"]["stok"]
        for cookie in headers.get("set-cookie", []):
            m = re.search(r"sysauth=([^;]+)", cookie)
            if m:
                self.sysauth = m.group(1)

    def logout(self) -> None:
        if self.stok:
            try:
                self.request("admin/system?form=logout", {"operation": "write"}, raw=True)
            except RouterError:
                pass
            self.stok = ""
            self.sysauth = ""

    def __enter__(self) -> "Session":
        self.login()
        return self

    def __exit__(self, *exc) -> None:
        self.logout()

    # -- authenticated requests -----------------------------------------

    def _decode(self, text: str, what: str) -> dict[str, Any]:
        outer = _json(text, what)
        if "data" in outer and isinstance(outer["data"], str):
            try:
                return _json(self._decrypt(outer["data"]), what)
            except ValueError as exc:
                raise RouterError(f"{what}: could not decrypt response") from exc
        return outer

    def request(
        self, path: str, params: dict[str, Any] | str, *, raw: bool = False, op_in_url: bool = False
    ) -> Any:
        """
        Call ``admin/...`` endpoint ``path`` with form ``params``.

        Classic firmware (e.g. Archer AX20 1.3.8) answers "no such callback"
        when ``operation`` is duplicated into the URL, so it stays in the
        body unless ``op_in_url`` is set. SG firmware always gets the
        parameters mirrored into the query string. Returns the
        ``data`` member on success; with ``raw=True`` returns the full
        decrypted reply even when ``success`` is false.
        """
        if not self.stok:
            raise RouterError("not logged in")
        if isinstance(params, str):
            params = dict(parse_qsl(params, keep_blank_values=True))
        params = {k: v for k, v in params.items() if v is not None}
        sep = "&" if "?" in path else "?"
        if self.scheme == "sg":
            # SG firmware reads the parameters from the query string and
            # expects a JSON object as the encrypted body.
            extra = {k: v for k, v in params.items() if f"{k}=" not in path}
            if extra:
                path += sep + urlencode(extra)
            plaintext = json.dumps(params, separators=(",", ":"))
        else:
            op = params.get("operation")
            if op_in_url and op and "operation=" not in path:
                path += f"{sep}operation={quote(str(op))}"
            plaintext = urlencode(params)

        data = self._encrypt(plaintext)
        if self.scheme == "sg":
            self._hash = hashlib.sha256(data.encode()).hexdigest()
            sign = self._hmac_sign(f"h={self._hash}&s={self._seq + len(data)}")
        else:
            sign = self._rsa_sign(f"h={self._hash}&s={self._seq + len(data)}", oaep=False)

        status, _, text = self._post(self._url(path), f"sign={sign}&data={quote(data, safe='')}", cookie=True)
        if status == 403 or (status == 401):
            raise AuthError(f"{path}: session rejected (HTTP {status})")
        reply = self._decode(text, path)
        if raw:
            return reply
        if not reply.get("success"):
            raise RouterError(f"{path}: {reply}")
        return reply.get("data")
