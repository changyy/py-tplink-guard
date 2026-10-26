"""
High-level router operations used by tplink-guard.

Endpoints were mapped from the router's own web UI (``webpages/modules``)
and verified read-only on an Archer AX20 v1.0, firmware 1.3.8:

* ``admin/status?form=all``                      connected clients
* ``admin/dhcps?form=client|reservation``        leases / reservations
* ``admin/access_control?form=enable|mode|black_list|black_devices``
* ``admin/smart_network?form=patrol_*``          Parental Controls (HomeCare)
* ``admin/smart_network?form=game_accelerator``  per-device traffic counters

List-style forms follow the web UI's "IPF" store protocol:
``load``; ``insert`` with ``key=add, old=add, index=0, new=<json>``;
``update`` with ``key, old=<json>, new=<json>``; ``remove`` with ``key, index``.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .session import RouterError, Session

STATUS = "admin/status?form=all"
FIRMWARE = "admin/firmware?form=upgrade"
DHCP_CLIENTS = "admin/dhcps?form=client"
DHCP_RESERVATION = "admin/dhcps?form=reservation"
AC_ENABLE = "admin/access_control?form=enable"
AC_MODE = "admin/access_control?form=mode"
AC_BLACK_LIST = "admin/access_control?form=black_list"
AC_BLACK_DEVICES = "admin/access_control?form=black_devices"
PC_ENABLE = "admin/smart_network?form=patrol_enable"
PC_LIMIT = "admin/smart_network?form=patrol_limit"
PC_PROFILES = "admin/smart_network?form=patrol_owner_list"
PC_DEVICES = "admin/smart_network?form=patrol_devices"
PC_OWNER_BLOCK = "admin/smart_network?form=patrol_owner_block"
PC_INSIGHTS = "admin/smart_network?form=patrol_insights"
SMART_DEVICES = "admin/smart_network?form=game_accelerator"

STATUS_LISTS = {
    "access_devices_wired": False,
    "access_devices_wireless_host": False,
    "access_devices_wireless_guest": True,
}


def normalize_mac(value: str) -> str:
    """Return ``AA-BB-CC-DD-EE-FF`` (the router's own format)."""
    hexdigits = re.sub(r"[^0-9a-fA-F]", "", value or "").upper()
    if len(hexdigits) != 12:
        raise ValueError(f"not a MAC address: {value!r}")
    return "-".join(hexdigits[i:i + 2] for i in range(0, 12, 2))


def is_random_mac(mac: str) -> bool:
    """Locally administered bit set: iOS/Android "private Wi-Fi address"."""
    return bool(int(normalize_mac(mac)[:2], 16) & 0x02)


def as_list(value: Any) -> list:
    # The firmware encodes an empty list as ``{}``.
    return value if isinstance(value, list) else []


DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def hour_ranges(mask: list[int], value: int) -> list[tuple[int, int]]:
    """Runs of ``value`` in a 24-hour mask, as ``(start, end)`` hours (end exclusive)."""
    out: list[tuple[int, int]] = []
    start = None
    for hour in range(24):
        hit = hour < len(mask) and int(mask[hour]) == value
        if hit and start is None:
            start = hour
        elif not hit and start is not None:
            out.append((start, hour))
            start = None
    if start is not None:
        out.append((start, 24))
    return out


def fmt_range(r: tuple[int, int]) -> str:
    return f"{r[0]:02d}:00-{r[1]:02d}:00"


@dataclass
class Client:
    mac: str
    ip: str
    hostname: str
    connection: str
    guest: bool = False
    online: bool = True

    @property
    def random_mac(self) -> bool:
        return is_random_mac(self.mac)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "random_mac": self.random_mac}


@dataclass
class Profile:
    """A Parental Controls profile ("owner"); ``raw`` is the router record."""

    raw: dict[str, Any] = field(repr=False)

    @property
    def key(self) -> str:
        return str(self.raw.get("key", ""))

    @property
    def owner_id(self) -> str:
        return str(self.raw.get("owner_id", ""))

    @property
    def name(self) -> str:
        return str(self.raw.get("name", ""))

    @property
    def macs(self) -> list[str]:
        return [normalize_mac(c["mac"]) for c in as_list(self.raw.get("client_list")) if c.get("mac")]

    @property
    def blocked_sites(self) -> list[str]:
        return [str(s) for s in as_list(self.raw.get("black_website_list"))]

    @property
    def allowed_sites(self) -> list[str]:
        return [str(s) for s in as_list(self.raw.get("white_website_list"))]

    @property
    def website_type(self) -> str:
        return str(self.raw.get("website_type") or "black")

    @property
    def internet_blocked(self) -> bool:
        return bool(self.raw.get("internet_blocked"))

    @property
    def time_limits(self) -> dict[str, dict[str, Any]]:
        """Daily online-time budgets: ``weekday`` (Mon-Fri) and ``weekend``."""
        out = {}
        for label, prefix in (("weekday", "workday"), ("weekend", "weekend")):
            out[label] = {
                "enabled": bool(self.raw.get(f"enable_{prefix}_time_limit")),
                "minutes": _int(self.raw.get(f"{prefix}_daily_time")),
            }
        return out

    def hour_mask(self, day: str) -> list[int]:
        """24 entries per day: 1 = internet allowed that hour, 0 = blocked."""
        mask = self.raw.get(f"{day}_time")
        return [int(v) for v in mask] if isinstance(mask, list) and len(mask) == 24 else [1] * 24

    @property
    def schedule(self) -> dict[str, dict[str, list[str]]]:
        return {
            day: {
                "allowed": [fmt_range(r) for r in hour_ranges(self.hour_mask(day), 1)],
                "blocked": [fmt_range(r) for r in hour_ranges(self.hour_mask(day), 0)],
            }
            for day in DAYS
        }

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "key": self.key,
            "owner_id": self.owner_id,
            "internet_blocked": self.internet_blocked,
            "website_type": self.website_type,
            "blocked_sites": self.blocked_sites,
            "allowed_sites": self.allowed_sites,
            "time_limits": self.time_limits,
            "schedule": self.schedule,
            "clients": [
                {"mac": c.get("mac"), "name": c.get("name")} for c in as_list(self.raw.get("client_list"))
            ],
        }


def _ipf_insert(new: dict[str, Any]) -> dict[str, Any]:
    return {"operation": "insert", "key": "add", "old": "add", "index": 0, "new": _compact(new)}


def _ipf_update(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    return {"operation": "update", "key": old.get("key"), "old": _compact(old), "new": _compact(new)}


def _compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


@dataclass
class Write:
    """A planned mutation; executed only when the caller asks for it."""

    description: str
    path: str
    params: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Router:
    def __init__(self, session: Session) -> None:
        self.s = session

    def _read(self, path: str, operation: str = "read", **extra: Any) -> Any:
        return self.s.request(path, {"operation": operation, **extra})

    def apply(self, write: Write) -> Any:
        return self.s.request(write.path, write.params)

    # -- read ----------------------------------------------------------

    def firmware(self) -> dict[str, Any]:
        return self._read(FIRMWARE) or {}

    def clients(self) -> list[Client]:
        """Currently connected clients (wired, wireless, guest)."""
        status = self._read(STATUS) or {}
        out: dict[str, Client] = {}
        for key, guest in STATUS_LISTS.items():
            for item in as_list(status.get(key)):
                try:
                    mac = normalize_mac(item.get("macaddr", ""))
                except ValueError:
                    continue
                out[mac] = Client(
                    mac=mac,
                    ip=item.get("ipaddr", ""),
                    hostname=item.get("hostname", ""),
                    connection=item.get("wire_type", ""),
                    guest=guest,
                )
        return list(out.values())

    def traffic(self) -> dict[str, dict[str, Any]]:
        """Per-device counters by MAC: bytes used, current rates, online time."""
        out = {}
        try:
            items = as_list(self._read(SMART_DEVICES, "loadDevice"))
        except RouterError:
            return out  # firmware without the HomeCare device table
        for item in items:
            try:
                mac = normalize_mac(item.get("mac", ""))
            except ValueError:
                continue
            out[mac] = {
                "traffic_bytes": _int(item.get("trafficUsage")) or 0,
                "down_bps": _int(item.get("downloadSpeed")) or 0,
                "up_bps": _int(item.get("uploadSpeed")) or 0,
                "online_seconds": _int(float(item.get("onlineTime") or 0)),
            }
        return out

    def insights(self, profile: Profile) -> list[dict[str, Any]]:
        """Daily usage for a profile: index 0 is today, then one entry per earlier day."""
        data = self._read(PC_INSIGHTS, "read", owner_id=profile.owner_id) or {}
        return as_list(data.get("insights"))

    def known_devices(self) -> list[dict[str, Any]]:
        """Every device Parental Controls has seen, including offline ones."""
        return as_list(self._read(PC_DEVICES, "load"))

    def reservations(self) -> list[dict[str, Any]]:
        return as_list(self._read(DHCP_RESERVATION, "load"))

    def leases(self) -> list[dict[str, Any]]:
        return as_list(self._read(DHCP_CLIENTS, "load"))

    def access_control(self) -> dict[str, Any]:
        enable = self._read(AC_ENABLE) or {}
        mode = self._read(AC_MODE) or {}
        return {
            "enabled": enable.get("enable") == "on",
            "mode": mode.get("access_mode"),
            "blacklist": as_list(self._read(AC_BLACK_LIST, "load")),
        }

    def parental_controls(self) -> dict[str, Any]:
        enable = self._read(PC_ENABLE) or {}
        limit = self._read(PC_LIMIT) or {}
        return {
            "enabled": enable.get("enable") == "on",
            "max_profiles": _int(limit.get("profile_len")),
            "max_devices_per_profile": _int(limit.get("devices_len")),
            "max_sites_per_profile": _int(limit.get("category_len")),
        }

    def profiles(self) -> list[Profile]:
        return [Profile(raw) for raw in as_list(self._read(PC_PROFILES, "load"))]

    def profile(self, name: str) -> Profile:
        profiles = self.profiles()
        for p in profiles:
            if name in (p.name, p.key, p.owner_id):
                return p
        names = ", ".join(repr(p.name) for p in profiles) or "none"
        raise LookupError(f"no Parental Controls profile {name!r} (have: {names})")

    # -- planned writes ------------------------------------------------

    def plan_profile_update(self, profile: Profile, new: dict[str, Any], description: str) -> Write:
        return Write(description, PC_PROFILES, _ipf_update(profile.raw, new))

    def plan_change_clients(
        self,
        profile: Profile,
        add: list[tuple[str, str]] = (),
        remove: list[str] = (),
    ) -> Write | None:
        """
        Add ``(mac, name)`` pairs and drop ``remove`` MACs in a single update.

        One write per profile matters: each update carries the full record,
        so two separate writes planned from the same snapshot would undo
        each other.
        """
        drop = {normalize_mac(m) for m in remove}
        current = as_list(profile.raw.get("client_list"))
        kept = [c for c in current if normalize_mac(c.get("mac", "")) not in drop]
        removed = [normalize_mac(c["mac"]) for c in current if c not in kept]
        have = {normalize_mac(c["mac"]) for c in kept}
        added = []
        for mac, name in add:
            mac = normalize_mac(mac)
            if mac in have or mac in drop:
                continue
            have.add(mac)
            added.append({
                "mac": mac,
                "name": name or mac,
                "device_id": mac.replace("-", ""),
                "owner_id": profile.owner_id,
                "client_type": "phone",
            })
        if not (added or removed):
            return None
        new = dict(profile.raw, client_list=kept + added)
        parts = []
        if added:
            parts.append(f"add {', '.join(c['mac'] for c in added)}")
        if removed:
            parts.append(f"remove {', '.join(removed)}")
        return self.plan_profile_update(profile, new, f"{' and '.join(parts)} in profile {profile.name!r}")

    def plan_add_clients(self, profile: Profile, clients: list[tuple[str, str]]) -> Write | None:
        """Add ``(mac, name)`` pairs to a profile; ``None`` if nothing to do."""
        return self.plan_change_clients(profile, add=clients)

    def plan_remove_clients(self, profile: Profile, macs: list[str]) -> Write | None:
        return self.plan_change_clients(profile, remove=macs)

    def plan_rename(self, profile: Profile, name: str) -> Write | None:
        name = name.strip()
        if not name or len(name) > 64:
            raise ValueError("profile name must be 1-64 characters (web UI limit)")
        if name == profile.name:
            return None
        new = dict(profile.raw, name=name)
        return self.plan_profile_update(profile, new, f"rename profile {profile.name!r} to {name!r}")

    def plan_schedule(
        self,
        profile: Profile,
        days: list[str],
        blocked_hours: set[int] | None = None,
        limits: dict[str, int | None] | None = None,
    ) -> Write | None:
        """
        Replace the blocked hours of ``days`` (other days untouched) and/or
        set daily limits. ``limits`` maps ``weekday``/``weekend`` to minutes,
        or ``None`` to switch that limit off.
        """
        new = dict(profile.raw)
        changes = []
        if blocked_hours is not None:
            mask = [0 if h in blocked_hours else 1 for h in range(24)]
            for day in days:
                new[f"{day}_time"] = mask
            hours = ", ".join(fmt_range(r) for r in hour_ranges(mask, 0)) or "none"
            changes.append(f"blocked hours on {','.join(days)}: {hours}")
        for label, minutes in (limits or {}).items():
            prefix = {"weekday": "workday", "weekend": "weekend"}[label]
            if minutes is None:
                new[f"enable_{prefix}_time_limit"] = False
                changes.append(f"{label} limit off")
            else:
                new[f"enable_{prefix}_time_limit"] = True
                new[f"{prefix}_daily_time"] = str(minutes)
                changes.append(f"{label} limit {minutes} min")
        if all(new.get(k) == profile.raw.get(k) for k in new):
            return None
        return self.plan_profile_update(profile, new, f"profile {profile.name!r}: " + "; ".join(changes))

    def plan_block_sites(self, profile: Profile, sites: list[str]) -> Write | None:
        current = profile.blocked_sites
        merged = current + [s for s in sites if s not in current]
        if merged == current and profile.website_type == "black":
            return None
        new = dict(profile.raw, black_website_list=merged, website_type="black")
        added = [s for s in merged if s not in current]
        return self.plan_profile_update(profile, new, f"block {', '.join(added) or '(mode only)'} for profile {profile.name!r}")

    def plan_unblock_sites(self, profile: Profile, sites: list[str]) -> Write | None:
        current = profile.blocked_sites
        kept = [s for s in current if s not in sites]
        if kept == current:
            return None
        new = dict(profile.raw, black_website_list=kept)
        return self.plan_profile_update(profile, new, f"unblock {', '.join(s for s in current if s in sites)} for profile {profile.name!r}")

    def plan_pause(self, profile: Profile, blocked: bool) -> Write:
        verb = "pause internet for" if blocked else "resume internet for"
        return Write(
            f"{verb} profile {profile.name!r}",
            PC_OWNER_BLOCK,
            {"operation": "write", "owner_id": profile.owner_id, "internet_blocked": "true" if blocked else "false"},
        )

    def plan_reservation(self, mac: str, ip: str, name: str) -> Write:
        mac = normalize_mac(mac)
        ip = str(ipaddress.IPv4Address(ip))
        for item in self.reservations():
            if normalize_mac(item.get("mac", "0" * 12)) == mac:
                raise ValueError(f"{mac} already has a reservation ({item.get('ip')}); unreserve it first")
            if item.get("ip") == ip:
                raise ValueError(f"{ip} is already reserved for {item.get('mac')}")
        in_use = next((c for c in self.clients() if c.ip == ip and c.mac != mac), None)
        if in_use:
            raise ValueError(f"{ip} is currently used by {in_use.mac} ({in_use.hostname})")
        # Same fields as the web UI's address-reservation store.
        new = {"mac": mac, "ip": ip, "enable": "on", "hostname": name}
        return Write(f"reserve {ip} for {mac} ({name})", DHCP_RESERVATION, _ipf_insert(new))

    def plan_unreservation(self, mac: str) -> Write | None:
        mac = normalize_mac(mac)
        for index, item in enumerate(self.reservations()):
            if normalize_mac(item.get("mac", "0" * 12)) == mac:
                # Stored entries carry no ``key``; the router removes by index.
                return Write(
                    f"remove DHCP reservation {item.get('ip')} for {mac}",
                    DHCP_RESERVATION,
                    {"operation": "remove", "key": item.get("key", mac), "index": index},
                )
        return None

    def plan_blacklist(self, mac: str) -> Write:
        mac = normalize_mac(mac)
        # Like the web UI, refuse to lock out the machine doing the managing.
        host_mac = (self._read(AC_ENABLE) or {}).get("host_mac")
        candidates = as_list(self._read(AC_BLACK_DEVICES, "load"))
        record = next((d for d in candidates if normalize_mac(d.get("mac", "0" * 12)) == mac), None)
        if (host_mac and normalize_mac(host_mac) == mac) or (record or {}).get("host") == "HOST":
            raise ValueError(f"{mac} is the computer managing the router; blocking it would lock you out")
        if record is None:
            # Same shape the web UI sends when a MAC is typed in by hand.
            record = {"name": "", "mac": mac}
        return Write(f"add {mac} to the Access Control blacklist", AC_BLACK_LIST, _ipf_insert(record))

    def plan_unblacklist(self, mac: str) -> Write | None:
        mac = normalize_mac(mac)
        for index, item in enumerate(as_list(self._read(AC_BLACK_LIST, "load"))):
            if normalize_mac(item.get("mac", "0" * 12)) == mac:
                return Write(
                    f"remove {mac} from the Access Control blacklist",
                    AC_BLACK_LIST,
                    {"operation": "remove", "key": item.get("key", mac), "index": index},
                )
        return None


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
