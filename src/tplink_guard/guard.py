"""
Reconciliation: keep router rules attached to devices whose MAC rotates.

``plan_sync`` compares the registry with what the router currently sees and
returns the MACs to learn, the stale MACs to prune, and the profile writes
needed (one per profile). Nothing is applied here; the CLI shows the plan and
applies it only with ``--yes``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .api import Client, Router, Write, is_random_mac
from .registry import Registry

# The router blocks every host *containing* an entry (its UI: "Block all
# websites that contain a specific keyword"), so "youtube" alone already
# covers youtube.com, m.youtube.com, youtube-nocookie.com and
# youtubei.googleapis.com. The rest are YouTube-only hosts without
# "youtube" in the name. Nothing here matches google.com / googleapis.com.
PRESETS: dict[str, list[str]] = {
    "youtube": [
        "youtube",
        "youtu.be",
        "ytimg.com",
        "googlevideo.com",
        "yt3.ggpht.com",
    ],
}


@dataclass
class SyncPlan:
    learned: list[tuple[str, str]] = field(default_factory=list)  # (alias, mac)
    pruned: list[tuple[str, str]] = field(default_factory=list)  # (alias, mac)
    writes: list[Write] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.learned or self.writes)


def expand_sites(sites: list[str]) -> list[str]:
    out: list[str] = []
    for s in sites:
        for item in PRESETS.get(s.lower(), [s]):
            if item not in out:
                out.append(item)
    return out


def plan_sync(
    router: Router,
    registry: Registry,
    clients: list[Client] | None = None,
    *,
    add: bool = True,
    prune: bool = False,
    only_profile: str | None = None,
) -> SyncPlan:
    """
    ``add``: learn new MACs by hostname and put every MAC of a device into
    its profile. ``prune``: drop a device's stale MACs from its profile,
    i.e. random (private) MACs that are not online now. A device always
    keeps at least one MAC: the online one, or else the newest one.
    Only registered devices are touched; unknown MACs are left alone.
    """
    plan = SyncPlan()
    clients = router.clients() if clients is None else clients
    online = {c.mac for c in clients}

    # 1. learn new MACs by hostname hint
    if add:
        for client in clients:
            matches = [d for d in registry.devices.values() if d.matches(client)]
            if len(matches) > 1:
                names = ", ".join(d.alias for d in matches)
                plan.warnings.append(f"{client.mac} ({client.hostname}) matches several devices: {names}; skipped")
                continue
            if matches and client.mac not in matches[0].macs:
                plan.learned.append((matches[0].alias, client.mac))

    learned_by_alias: dict[str, list[str]] = {}
    for alias, mac in plan.learned:
        learned_by_alias.setdefault(alias, []).append(mac)

    devices = [
        d for d in registry.devices.values()
        if d.profile and (only_profile is None or d.profile == only_profile)
    ]
    profiles = {p.name: p for p in router.profiles()} if devices else {}
    member_of = {mac: p.name for p in profiles.values() for mac in p.macs}
    to_add: dict[str, list[tuple[str, str]]] = {}
    to_remove: dict[str, list[str]] = {}

    for device in devices:
        if device.profile not in profiles:
            plan.warnings.append(f"{device.alias}: profile {device.profile!r} does not exist on the router")
            continue
        macs = device.macs + learned_by_alias.get(device.alias, [])

        # 2. prune: stale random MACs of this device that sit in its profile
        if prune:
            keep = [m for m in macs if m in online] or macs[-1:]
            for mac in device.macs:
                if member_of.get(mac) == device.profile and is_random_mac(mac) and mac not in keep:
                    to_remove.setdefault(device.profile, []).append(mac)
                    plan.pruned.append((device.alias, mac))

        # 3. add: every current MAC of the device belongs in its profile
        if add:
            stale = set(to_remove.get(device.profile, []))
            for mac in macs:
                if mac in stale:
                    continue
                other = member_of.get(mac)
                if other and other != device.profile:
                    # A client belongs to one profile; moving it silently could
                    # loosen another rule, so leave that decision to the user.
                    plan.warnings.append(
                        f"{device.alias}: {mac} is already in profile {other!r}; "
                        f"remove it there first to move it to {device.profile!r}"
                    )
                    continue
                to_add.setdefault(device.profile, []).append((mac, device.alias))

    names = set(to_add) | set(to_remove)
    max_devices = router.parental_controls().get("max_devices_per_profile") if names else None
    for name in sorted(names):
        write = router.plan_change_clients(profiles[name], to_add.get(name, []), to_remove.get(name, []))
        if write is None:
            continue
        total = _client_count(write)
        if max_devices and total > max_devices:
            hint = "" if prune else "; try `tplink-guard sync --prune` or `profile remove-device`"
            plan.warnings.append(
                f"profile {name!r} would hold {total} devices but the router allows {max_devices}{hint}"
            )
            continue
        plan.writes.append(write)
    return plan


def _client_count(write: Write) -> int:
    return len(json.loads(write.params["new"]).get("client_list") or [])


def apply_learned(registry: Registry, plan: SyncPlan) -> None:
    for alias, mac in plan.learned:
        registry.get(alias).learn(mac)
