"""
Local state: router connection settings and the device registry.

The registry is what makes rules survive iPadOS updates. A device is known
by an alias, every MAC it has ever used, and optional hostname hints. When
the device shows up with a new (private, rotating) MAC, ``sync`` matches it
by hostname, remembers the new MAC and re-applies its profile membership.

Files live in ``$TPLINK_GUARD_HOME`` (default ``~/.config/tplink-guard``):

* ``config.json``: ``{"default": NAME, "routers": {NAME: {host, username,
  scheme, timeout, gateway_mac}}}``. Without any setup there is a single
  router called ``default``; more can be added by name. The old flat format
  (``{host, username, ...}``) is read as router ``default``.
* ``devices.json``: registry of router ``default``; ``devices-NAME.json``
  for every other router.

The password is never written to disk.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .api import Client, normalize_mac

DEFAULT_ROUTER = "default"
ROUTER_DEFAULTS = {"host": "https://192.168.0.1", "username": "admin", "scheme": "auto", "timeout": 15}
ROUTER_KEYS = ("host", "username", "scheme", "timeout", "gateway_mac")


def home() -> Path:
    return Path(os.environ.get("TPLINK_GUARD_HOME") or Path.home() / ".config" / "tplink-guard")


def _load(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def _save(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_routers() -> dict[str, Any]:
    """``{"default": NAME, "routers": {NAME: settings}}``; legacy flat files migrate in memory."""
    raw = _load(home() / "config.json", {})
    if "routers" not in raw:
        legacy = {k: raw[k] for k in ROUTER_KEYS if k in raw}
        raw = {"default": DEFAULT_ROUTER, "routers": {DEFAULT_ROUTER: legacy} if legacy else {}}
    raw.setdefault("default", DEFAULT_ROUTER)
    return raw


def save_routers(data: dict[str, Any]) -> None:
    routers = {
        name: {k: v for k, v in cfg.items() if k in ROUTER_KEYS and v is not None}
        for name, cfg in data.get("routers", {}).items()
    }
    _save(home() / "config.json", {"default": data.get("default", DEFAULT_ROUTER), "routers": routers})


def router_settings(name: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Settings of router ``name`` with defaults filled in. ``default`` always exists."""
    data = data or load_routers()
    routers = data.get("routers", {})
    if name not in routers and name != DEFAULT_ROUTER:
        known = ", ".join(sorted(routers)) or "none"
        raise LookupError(f"unknown router {name!r} (configured: {known}); add it with `tplink-guard router set`")
    return {**ROUTER_DEFAULTS, **routers.get(name, {})}


def _devices_file(router: str) -> Path:
    return home() / ("devices.json" if router == DEFAULT_ROUTER else f"devices-{router}.json")


@dataclass
class Device:
    alias: str
    macs: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    profile: str = ""

    def matches(self, client: Client) -> bool:
        if client.mac in self.macs:
            return True
        name = client.hostname.strip().lower()
        return bool(name) and name in {h.lower() for h in self.hostnames}

    def learn(self, mac: str) -> bool:
        mac = normalize_mac(mac)
        if mac in self.macs:
            return False
        self.macs.append(mac)
        return True


class Registry:
    def __init__(self, devices: dict[str, Device] | None = None, router: str = DEFAULT_ROUTER) -> None:
        self.devices = devices or {}
        self.router = router

    @classmethod
    def load(cls, router: str = DEFAULT_ROUTER) -> "Registry":
        raw = _load(_devices_file(router), {"devices": {}})
        devices = {}
        for alias, entry in raw.get("devices", {}).items():
            devices[alias] = Device(
                alias=alias,
                macs=[normalize_mac(m) for m in entry.get("macs", [])],
                hostnames=list(entry.get("hostnames", [])),
                profile=entry.get("profile", ""),
            )
        return cls(devices, router)

    def save(self) -> None:
        data = {
            "devices": {
                alias: {k: v for k, v in asdict(d).items() if k != "alias"}
                for alias, d in sorted(self.devices.items())
            }
        }
        _save(_devices_file(self.router), data)

    def get(self, alias: str) -> Device:
        try:
            return self.devices[alias]
        except KeyError:
            raise LookupError(f"unknown device alias {alias!r} (see `tplink-guard device list`)") from None

    def owner_of(self, client: Client) -> Device | None:
        by_mac = [d for d in self.devices.values() if client.mac in d.macs]
        if by_mac:
            return by_mac[0]
        by_name = [d for d in self.devices.values() if d.matches(client)]
        return by_name[0] if len(by_name) == 1 else None

    def resolve_macs(self, target: str) -> list[str]:
        """Accept an alias or a literal MAC address."""
        if target in self.devices:
            return list(self.devices[target].macs)
        return [normalize_mac(target)]
