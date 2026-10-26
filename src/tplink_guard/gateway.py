"""
Which router is this machine behind right now?

The default gateway's MAC address (from the ARP / neighbour table) is a
stable identity for a router, unlike its IP: two homes can both use
192.168.0.1. It needs no login and no location permission (reading the
Wi-Fi SSID does on recent macOS), and it works on wired connections too.

Every function returns ``None`` when it cannot tell; callers then fall back
to the configured default router.
"""

from __future__ import annotations

import re
import socket
import subprocess
import sys

from .api import normalize_mac

_MAC = re.compile(r"\b([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\b")


def _run(argv: list[str]) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def default_gateway() -> str | None:
    """IPv4 address of the default gateway."""
    if sys.platform == "darwin":
        m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", _run(["route", "-n", "get", "default"]))
    else:
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", _run(["ip", "-4", "route", "show", "default"]))
    return m.group(1) if m else None


def parse_mac(text: str) -> str | None:
    """
    First MAC in ``text``, normalised. macOS ``arp`` drops leading zeros
    (``0:0:5e:0:53:a``), so each octet is padded before normalising.
    """
    m = _MAC.search(text or "")
    if not m:
        return None
    return normalize_mac("".join(part.zfill(2) for part in m.group(1).split(":")))


def _lookup(ip: str) -> str | None:
    if sys.platform == "darwin":
        # `arp -n IP` misses interface-scoped entries (e.g. with a VPN up),
        # so read the whole table and pick the gateway's row.
        for line in _run(["arp", "-an"]).splitlines():
            if f"({ip})" in line:
                mac = parse_mac(line)
                if mac:
                    return mac
        return None
    return parse_mac(_run(["ip", "neigh", "show", ip]))


def mac_of(ip: str) -> str | None:
    mac = _lookup(ip)
    if mac is None:
        # ARP entries expire after a few minutes of silence; one short
        # connection to the router's HTTPS port puts it back.
        try:
            socket.create_connection((ip, 443), timeout=1).close()
        except OSError:
            pass
        mac = _lookup(ip)
    return mac


def detect() -> tuple[str | None, str | None]:
    """``(gateway_ip, gateway_mac)``, each ``None`` if unknown."""
    ip = default_gateway()
    return ip, (mac_of(ip) if ip else None)
