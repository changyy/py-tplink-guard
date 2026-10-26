"""
tplink-guard command line.

Every command that changes the router prints its plan first and only applies
it with ``--yes``. The password comes from ``TPLINK_GUARD_PASSWORD`` or an
interactive prompt and is never stored.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import re
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from . import __version__, gateway, keychain
from .api import DAYS, STATUS, Router, Write, as_list, normalize_mac
from .guard import PRESETS, apply_learned, expand_sites, plan_sync
from .registry import (
    DEFAULT_ROUTER,
    Device,
    Registry,
    load_routers,
    router_settings,
    save_routers,
)
from .session import AuthError, RouterError, Session, normalize_host

PASSWORD_ENV = "TPLINK_GUARD_PASSWORD"

# Exit codes, so scripts can branch without parsing messages.
ROUTER_NAME = re.compile(r"[A-Za-z0-9_-]{1,32}")

EXIT_CODES = {"error": 1, "usage": 2, "auth": 3, "router": 4, "not_found": 5, "network": 6}


class CliError(Exception):
    pass


# -- helpers -------------------------------------------------------------


@dataclass
class Target:
    """The router a command talks to, and why it was picked."""

    name: str
    host: str
    username: str
    scheme: str
    timeout: float
    gateway_mac: str | None
    reason: str

    @property
    def account(self) -> str:
        return keychain.account(self.username, self.host, self.name)


def resolve(args: argparse.Namespace) -> Target:
    """
    ``--router NAME`` wins. Otherwise, with several routers configured, the
    one whose recorded gateway MAC matches this network's gateway; else the
    configured default (``default`` unless changed). ``--host`` only
    overrides the host of the router picked.
    """
    cached = getattr(args, "_target", None)
    if cached:
        return cached
    data = load_routers()
    routers = data.get("routers", {})
    name = getattr(args, "router", None)
    reason = "--router"
    if not name:
        name, reason = data.get("default", DEFAULT_ROUTER), "default router"
        if len(routers) > 1:
            gw_ip, gw_mac = gateway.detect()
            matches = [n for n, cfg in routers.items() if gw_mac and cfg.get("gateway_mac") == gw_mac]
            if len(matches) == 1:
                name, reason = matches[0], f"gateway MAC {gw_mac}"
    cfg = router_settings(name, data)
    target = Target(
        name=name,
        host=normalize_host(args.host or cfg["host"]),
        username=cfg["username"],
        scheme=cfg["scheme"],
        timeout=float(cfg["timeout"]),
        gateway_mac=cfg.get("gateway_mac"),
        reason=reason,
    )
    args._target = target
    return target


def registry_for(args: argparse.Namespace) -> Registry:
    return Registry.load(resolve(args).name)


def _password(target: Target) -> str:
    """Environment, then macOS Keychain, then an interactive prompt."""
    pw = os.environ.get(PASSWORD_ENV)
    if pw:
        return pw
    try:
        pw = keychain.get(target.account)
    except keychain.KeychainError as exc:
        raise CliError(str(exc)) from None
    if pw:
        return pw
    if not sys.stdin.isatty():
        hint = " or store it with `tplink-guard password set`" if keychain.available() else ""
        raise CliError(f"no password: set {PASSWORD_ENV}{hint}, or run interactively")
    return getpass.getpass("Router admin password: ")


@contextmanager
def connect(args: argparse.Namespace) -> Iterator[Router]:
    target = resolve(args)
    session = Session(target.host, _password(target), username=target.username, scheme=target.scheme)
    session.transport.timeout = target.timeout
    with session:
        router = Router(session)
        _learn_gateway_mac(target, router)
        yield router


def _learn_gateway_mac(target: Target, router: Router) -> None:
    """
    Record the router's LAN MAC the first time we reach it from its own
    network, so later runs can pick this router automatically.
    """
    if target.gateway_mac or args_host_is_override(target):
        return
    gw_ip = gateway.default_gateway()
    if not gw_ip or gw_ip != target.host.split("://", 1)[-1].split(":")[0]:
        return
    try:
        lan_mac = normalize_mac((router.s.request(STATUS, {"operation": "read"}) or {}).get("lan_macaddr", ""))
    except (RouterError, ValueError):
        return
    data = load_routers()
    data.setdefault("routers", {}).setdefault(target.name, {k: v for k, v in vars(target).items()
                                                           if k in ("host", "username")})
    data["routers"][target.name]["gateway_mac"] = lan_mac
    save_routers(data)
    target.gateway_mac = lan_mac


def args_host_is_override(target: Target) -> bool:
    # an ad-hoc --host may point somewhere else than the stored router
    return target.host != normalize_host(router_settings(target.name)["host"])


def emit(args: argparse.Namespace, data: Any, text: str | None = None) -> None:
    if args.json or text is None:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print(text)


def table(rows: list[list[str]], header: list[str]) -> str:
    rows = [header] + [[str(c) for c in r] for r in rows]
    widths = [max(len(r[i]) for r in rows) for i in range(len(header))]
    lines = ["  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


def run_writes(
    args: argparse.Namespace,
    router: Router | None,
    writes: list[Write],
    *,
    notes: list[str] | None = None,
    extra: dict[str, Any] | None = None,
    other_work: bool = False,
) -> dict[str, Any]:
    """
    Show (and with ``--yes`` apply) planned writes.

    The same result object backs both outputs. In JSON mode it is printed
    as is: ``{"dry_run", "applied", "changes": [...], "notes": [...]}``
    plus any command-specific ``extra`` keys.
    """
    result: dict[str, Any] = {
        "dry_run": not args.yes,
        "applied": False,
        "changes": [
            {"description": w.description, "path": w.path, **({"params": w.params} if args.verbose else {})}
            for w in writes
        ],
        **(extra or {}),
        "notes": list(notes or []),
    }
    if args.yes and writes and router is not None:
        for w in writes:
            router.apply(w)
        result["applied"] = True

    lines = [f"note: {n}" for n in result["notes"]]
    for w in writes:
        lines.append(f"applied: {w.description}" if result["applied"] else f"- {w.description}")
        if args.verbose:
            lines.append(f"    POST {w.path} {json.dumps(w.params, ensure_ascii=False)}")
    if not writes and not other_work:
        lines.append("Nothing to change.")
    elif result["dry_run"]:
        lines.append("\nDry run. Re-run with --yes to apply.")
    emit(args, result, "\n".join(lines))
    return result


# -- commands ------------------------------------------------------------


def cmd_config(args: argparse.Namespace) -> None:
    """Show / change the settings of the selected router (``default`` unless chosen)."""
    target = resolve(args)
    if args.action == "set":
        _update_router(target.name, host=args.set_host, username=args.username, scheme=args.scheme,
                       timeout=args.timeout)
    cfg = {"router": target.name, **router_settings(target.name)}
    emit(args, cfg, "\n".join(f"{k}: {v}" for k, v in cfg.items()))


def _update_router(name: str, **changes: Any) -> dict[str, Any]:
    data = load_routers()
    entry = data.setdefault("routers", {}).setdefault(name, {})
    if changes.get("host"):
        new_host = normalize_host(changes["host"])
        if entry.get("host") and normalize_host(entry["host"]) != new_host:
            entry.pop("gateway_mac", None)  # a different box; learn it again
        changes["host"] = new_host
    entry.update({k: v for k, v in changes.items() if v is not None})
    save_routers(data)
    return entry


def cmd_router(args: argparse.Namespace) -> None:
    data = load_routers()
    routers = data.get("routers", {})
    if args.action in ("set", "remove", "use") and not args.name:
        raise CliError(f"router {args.action} needs a NAME")
    if args.action == "set":
        if not ROUTER_NAME.fullmatch(args.name):
            raise CliError("router names use letters, digits, '-' and '_' (max 32)")
        if args.name not in routers and not args.set_host and args.name != DEFAULT_ROUTER:
            raise CliError("a new router needs --host")
        entry = _update_router(args.name, host=args.set_host, username=args.username, scheme=args.scheme,
                               timeout=args.timeout, gateway_mac=normalize_mac(args.gateway_mac) if args.gateway_mac else None)
        emit(args, {"saved": args.name, **entry}, f"saved router {args.name}: {entry}")
        return
    if args.action == "remove":
        if args.name not in routers:
            raise LookupError(f"unknown router {args.name!r}")
        del routers[args.name]
        if data.get("default") == args.name:
            data["default"] = DEFAULT_ROUTER
        save_routers(data)
        emit(args, {"removed": args.name},
             f"removed router {args.name} (its device registry file and Keychain item are kept)")
        return
    if args.action == "use":
        router_settings(args.name, data)  # must exist
        data["default"] = args.name
        save_routers(data)
        emit(args, {"default": args.name}, f"default router is now {args.name}")
        return
    if args.action == "current":
        target = resolve(args)
        gw_ip, gw_mac = gateway.detect()
        info = {"router": target.name, "reason": target.reason, "host": target.host,
                "gateway_ip": gw_ip, "gateway_mac": gw_mac, "recorded_gateway_mac": target.gateway_mac}
        emit(args, info, "\n".join(f"{k}: {v}" for k, v in info.items()))
        return
    names = sorted(set(routers) | {DEFAULT_ROUTER})
    rows, out = [], []
    for name in names:
        cfg = router_settings(name, data)
        mark = "*" if name == data.get("default", DEFAULT_ROUTER) else ""
        rows.append([mark, name, cfg["host"], cfg["username"], cfg.get("gateway_mac") or ""])
        out.append({"name": name, "default": bool(mark), **cfg})
    emit(args, out, table(rows, ["", "NAME", "HOST", "USER", "GATEWAY MAC"]))


def cmd_doctor(args: argparse.Namespace) -> None:
    with connect(args) as router:
        fw = router.firmware()
        pc = router.parental_controls()
        ac = router.access_control()
        data = {
            "host": router.s.host,
            "scheme": router.s.scheme,
            "model": fw.get("model"),
            "hardware": fw.get("hardware_version"),
            "firmware": fw.get("firmware_version"),
            "parental_controls": pc,
            "access_control": {k: v for k, v in ac.items() if k != "blacklist"} | {"blacklisted": len(ac["blacklist"])},
        }
    text = (
        f"host       {data['host']} (scheme: {data['scheme']})\n"
        f"model      {data['hardware'] or data['model']}\n"
        f"firmware   {data['firmware']}\n"
        f"parental   enabled={pc['enabled']} profiles<={pc['max_profiles']} "
        f"devices/profile<={pc['max_devices_per_profile']} sites/profile<={pc['max_sites_per_profile']}\n"
        f"access     enabled={ac['enabled']} mode={ac['mode']} blacklisted={len(ac['blacklist'])}"
    )
    emit(args, data, text)


def cmd_devices(args: argparse.Namespace) -> None:
    registry = registry_for(args)
    with connect(args) as router:
        clients = router.clients()
        profiles = router.profiles()
        traffic = router.traffic()
    in_profile = {mac: p.name for p in profiles for mac in p.macs}
    empty = {"traffic_bytes": 0, "down_bps": 0, "up_bps": 0, "online_seconds": 0}
    data = []
    for c in clients:
        owner = registry.owner_of(c)
        data.append(c.to_dict() | {"alias": owner.alias if owner else None, "profile": in_profile.get(c.mac)}
                    | traffic.get(c.mac, empty))
    if args.sort == "traffic":
        data.sort(key=lambda d: d["traffic_bytes"], reverse=True)
    else:
        data.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")) if d["ip"].count(".") == 3 else (999,))
    if args.top:
        data = data[:args.top]
    rows = [[
        d["ip"], d["mac"], "random" if d["random_mac"] else "", d["hostname"],
        d["connection"] + (" guest" if d["guest"] else ""), human_bytes(d["traffic_bytes"]),
        d["alias"] or "", d["profile"] or "",
    ] for d in data]
    emit(args, data, table(rows, ["IP", "MAC", "MAC TYPE", "HOSTNAME", "LINK", "TRAFFIC", "ALIAS", "PROFILE"]))


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def cmd_insights(args: argparse.Namespace) -> None:
    with connect(args) as router:
        profile = router.profile(args.profile)
        days = router.insights(profile)[: args.days]
    totals: dict[str, int] = {}
    for day in days:
        for site in as_list(day.get("website_list")):
            name = site.get("website")
            if name:
                totals[name] = totals.get(name, 0) + int(site.get("spend_online") or 0)
    top = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[: args.top]
    blocked = set(profile.blocked_sites)
    data = {
        "profile": profile.name,
        "days": len(days),
        "online_minutes": sum(int(d.get("spend_online") or 0) for d in days),
        "sites": [{"website": w, "minutes": m, "blocked": w in blocked} for w, m in top],
    }
    rows = [[str(i), d["website"], str(d["minutes"]), "yes" if d["blocked"] else ""] for i, d in enumerate(data["sites"], 1)]
    head = f"[{profile.name}] last {data['days']} day(s), {data['online_minutes']} min online\n"
    emit(args, data, head + table(rows, ["#", "WEBSITE", "MINUTES", "BLOCKED"]))


def parse_days(text: str) -> list[str]:
    """``mon-fri``, ``sat,sun``, ``all``, ``weekday``, ``weekend``."""
    aliases = {"all": "mon-sun", "weekday": "mon-fri", "weekdays": "mon-fri", "weekend": "sat-sun", "weekends": "sat-sun"}
    out: list[str] = []
    for part in aliases.get(text.lower(), text.lower()).split(","):
        part = aliases.get(part, part)
        a, _, b = part.partition("-")
        if a not in DAYS or (b and b not in DAYS):
            raise CliError(f"bad day spec {text!r}; use e.g. mon-fri, sat,sun, weekday, all")
        i, j = DAYS.index(a), DAYS.index(b or a)
        span = range(i, j + 1) if i <= j else list(range(i, 7)) + list(range(0, j + 1))
        out += [DAYS[k] for k in span if DAYS[k] not in out]
    return out


def parse_block(text: str) -> set[int]:
    """``18:00-19:00`` -> {18}. The router stores one flag per whole hour."""
    import re

    m = re.fullmatch(r"(\d{1,2})(?::(\d{2}))?-(\d{1,2})(?::(\d{2}))?", text.strip())
    if not m:
        raise CliError(f"bad time range {text!r}; use HH:MM-HH:MM, e.g. 18:00-19:00")
    h1, m1, h2, m2 = int(m[1]), int(m[2] or 0), int(m[3]), int(m[4] or 0)
    if m1 or m2:
        raise CliError(f"{text!r}: the router only supports whole hours (HH:00)")
    if not (0 <= h1 < h2 <= 24):
        raise CliError(f"{text!r}: start must be before end within one day; "
                       "split overnight ranges, e.g. 21:00-24:00 and 00:00-07:00")
    return set(range(h1, h2))


def parse_limit(text: str) -> tuple[str, int | None]:
    label, _, value = text.partition("=")
    label = {"weekdays": "weekday", "weekends": "weekend"}.get(label, label)
    if label not in ("weekday", "weekend") or not value:
        raise CliError(f"bad limit {text!r}; use weekday=120, weekend=off")
    if value == "off":
        return label, None
    if not value.isdigit() or not 1 <= int(value) <= 1440:
        raise CliError(f"bad limit {text!r}; minutes must be 1-1440 or off")
    return label, int(value)


def cmd_schedule(args: argparse.Namespace) -> None:
    if not (args.block or args.allow_all or args.limit):
        raise CliError("give --block, --allow-all and/or --limit")
    if args.block and args.allow_all:
        raise CliError("--block and --allow-all are mutually exclusive")
    days = parse_days(args.days)
    blocked = None
    if args.allow_all:
        blocked = set()
    elif args.block:
        blocked = set().union(*(parse_block(b) for b in args.block))
    limits = dict(parse_limit(x) for x in args.limit or [])
    with connect(args) as router:
        profile = router.profile(args.profile)
        write = router.plan_schedule(profile, days, blocked, limits)
        notes = []
        if blocked is not None and len(blocked) == 24:
            notes.append("every hour is blocked on those days: devices will have no internet at all")
        run_writes(args, router, [write] if write else [], notes=notes)


def cmd_profiles(args: argparse.Namespace) -> None:
    with connect(args) as router:
        profiles = router.profiles()
    data = [p.summary() for p in profiles]
    lines = []
    for p in profiles:
        state = "PAUSED" if p.internet_blocked else "active"
        lines.append(f"[{p.name}] key={p.key} {state} filter={p.website_type}")
        for c in p.summary()["clients"]:
            lines.append(f"    device  {c['mac']}  {c['name']}")
        sites = p.blocked_sites if p.website_type == "black" else p.allowed_sites
        lines.append(f"    {'blocked' if p.website_type == 'black' else 'allowed'} sites: {', '.join(sites) or '-'}")
        lines.append(f"    daily limit: {_limits_text(p.time_limits)}")
        lines.append(f"    blocked hours: {_schedule_text(p)}")
    emit(args, data, "\n".join(lines) or "No Parental Controls profiles.")


def _limits_text(limits: dict[str, dict[str, Any]]) -> str:
    parts = []
    for label, lim in limits.items():
        if lim["enabled"]:
            parts.append(f"{label} {lim['minutes']} min")
        else:
            parts.append(f"{label} off ({lim['minutes']} min if enabled)")
    return ", ".join(parts)


def _schedule_text(profile) -> str:
    """Group days that share the same blocked hours: ``Mon-Tue,Thu-Sun 06:00-07:00 ...``."""
    groups: dict[tuple[str, ...], list[str]] = {}
    for day, entry in profile.schedule.items():
        groups.setdefault(tuple(entry["blocked"]), []).append(day)
    if list(groups) == [()]:
        return "none (online 24h every day)"
    parts = []
    for blocked, days in groups.items():
        if not blocked:
            continue
        hours = "all day" if blocked == ("00:00-24:00",) else " ".join(blocked)
        parts.append(f"{_days_text(days)} {hours}")
    return "; ".join(parts)


def _days_text(days: list[str]) -> str:
    """``['mon','tue','thu','fri']`` -> ``Mon-Tue,Thu-Fri``."""
    idx = sorted(DAYS.index(d) for d in days)
    runs: list[list[int]] = []
    for i in idx:
        if runs and i == runs[-1][-1] + 1:
            runs[-1].append(i)
        else:
            runs.append([i])
    names = [d.capitalize() for d in DAYS]
    return ",".join(names[r[0]] if len(r) == 1 else f"{names[r[0]]}-{names[r[-1]]}" for r in runs)


def cmd_profile_devices(args: argparse.Namespace) -> None:
    registry = registry_for(args)
    with connect(args) as router:
        profile = router.profile(args.profile)
        if args.action == "rename":
            if len(args.targets) != 1:
                raise CliError("usage: profile rename PROFILE NEW_NAME")
            names = {p.name for p in router.profiles()} - {profile.name}
            if args.targets[0].strip() in names:
                raise CliError(f"a profile named {args.targets[0]!r} already exists")
            write = router.plan_rename(profile, args.targets[0])
            run_writes(args, router, [write] if write else [])
            return
        macs = [m for t in args.targets for m in registry.resolve_macs(t)]
        if args.action == "add-device":
            names = {m: next((t for t in args.targets if t in registry.devices and m in registry.devices[t].macs), "") for m in macs}
            write = router.plan_add_clients(profile, [(m, names[m]) for m in macs])
        else:
            write = router.plan_remove_clients(profile, macs)
        run_writes(args, router, [write] if write else [])


def cmd_sites(args: argparse.Namespace) -> None:
    sites = expand_sites(args.sites)
    with connect(args) as router:
        profile = router.profile(args.profile)
        if args.action == "block":
            limit = router.parental_controls().get("max_sites_per_profile")
            write = router.plan_block_sites(profile, sites)
            if write and limit and len(json.loads(write.params["new"])["black_website_list"]) > limit:
                raise CliError(f"profile {profile.name!r} allows at most {limit} sites")
        else:
            write = router.plan_unblock_sites(profile, sites)
        run_writes(args, router, [write] if write else [])


def cmd_pause(args: argparse.Namespace) -> None:
    with connect(args) as router:
        profile = router.profile(args.profile)
        run_writes(args, router, [router.plan_pause(profile, args.action == "pause")])


def cmd_device(args: argparse.Namespace) -> None:
    registry = registry_for(args)
    if args.action == "list":
        data = {a: vars(d) for a, d in sorted(registry.devices.items())}
        rows = [[d.alias, ", ".join(d.macs), ", ".join(d.hostnames), d.profile] for d in registry.devices.values()]
        emit(args, data, table(rows, ["ALIAS", "MACS", "HOSTNAME HINTS", "PROFILE"]) if rows else "No devices registered.")
        return
    if args.action == "remove":
        removed = registry.get(args.alias)
        del registry.devices[args.alias]
        registry.save()
        emit(args, {"removed": vars(removed)}, f"removed {args.alias}")
        return
    device = registry.devices.get(args.alias) or Device(alias=args.alias)
    for mac in args.mac or []:
        device.learn(mac)
    for name in args.hostname or []:
        if name not in device.hostnames:
            device.hostnames.append(name)
    if args.profile is not None:
        device.profile = args.profile
    if not device.macs and not device.hostnames:
        raise CliError("give at least one --mac or --hostname")
    registry.devices[device.alias] = device
    registry.save()
    emit(
        args,
        {"saved": vars(device)},
        f"saved {device.alias}: macs={device.macs} hostnames={device.hostnames} profile={device.profile or '-'}",
    )


def cmd_sync(args: argparse.Namespace) -> None:
    registry = registry_for(args)
    if not registry.devices:
        raise CliError("no devices registered; add one with `tplink-guard device add`")
    pruning = args.command == "prune" or args.prune
    with connect(args) as router:
        if args.command == "prune" and args.profile:
            router.profile(args.profile)  # fail early on a typo
        plan = plan_sync(
            router, registry,
            add=args.command == "sync", prune=pruning,
            only_profile=getattr(args, "profile", None),
        )
        learned = [{"alias": alias, "mac": mac} for alias, mac in plan.learned]
        pruned = [{"alias": alias, "mac": mac} for alias, mac in plan.pruned]
        notes = (
            [f"warning: {w}" for w in plan.warnings]
            + [f"learn new MAC {m['mac']} for {m['alias']}" for m in learned]
            + [f"prune stale MAC {m['mac']} of {m['alias']}" for m in pruned]
        )
        extra = {"learned": learned, "warnings": plan.warnings, "registry_updated": bool(args.yes and learned)}
        if pruning:
            extra["pruned"] = pruned
        run_writes(args, router, plan.writes, notes=notes, extra=extra, other_work=bool(learned))
    # Only remember new MACs once the router accepted the profile changes.
    if args.yes and learned:
        apply_learned(registry, plan)
        registry.save()


def cmd_password(args: argparse.Namespace) -> None:
    target = resolve(args)
    acct = target.account
    data: dict[str, Any] = {"router": target.name, "keychain_available": keychain.available(),
                            "account": acct, "service": keychain.SERVICE}
    try:
        if args.action == "set":
            keychain.set_interactive(acct)
            data["stored"] = True
            text = f"stored password for {acct} in the Keychain"
        elif args.action == "delete":
            data["deleted"] = keychain.delete(acct)
            text = f"deleted {acct}" if data["deleted"] else f"nothing stored for {acct}"
        else:
            data["stored"] = keychain.available() and keychain.get(acct) is not None
            data["env_set"] = bool(os.environ.get(PASSWORD_ENV))
            source = "environment" if data["env_set"] else "keychain" if data["stored"] else "prompt"
            data["source"] = source
            text = (f"keychain: {'available' if data['keychain_available'] else 'not available'}; "
                    f"stored for {acct}: {'yes' if data['stored'] else 'no'}; "
                    f"{PASSWORD_ENV}: {'set' if data['env_set'] else 'not set'} -> using {source}")
    except keychain.KeychainError as exc:
        raise CliError(str(exc)) from None
    emit(args, data, text)


def cmd_block(args: argparse.Namespace) -> None:
    registry = registry_for(args)
    notes = []
    with connect(args) as router:
        macs = registry.resolve_macs(args.target)
        if args.action == "block":
            writes = [router.plan_blacklist(m) for m in macs]
            ac = router.access_control()
            if not (ac["enabled"] and ac["mode"] == "black"):
                notes.append(f"Access Control is enabled={ac['enabled']} mode={ac['mode']}; "
                             "the blacklist only takes effect when enabled in blacklist mode")
        else:
            writes = [w for w in (router.plan_unblacklist(m) for m in macs) if w]
        run_writes(args, router, writes, notes=notes)


def cmd_reserve(args: argparse.Namespace) -> None:
    registry = registry_for(args)
    macs = registry.resolve_macs(args.target)
    if len(macs) != 1:
        raise CliError(f"{args.target!r} has {len(macs)} MACs; pass the MAC to reserve explicitly")
    with connect(args) as router:
        run_writes(args, router, [router.plan_reservation(macs[0], args.ip, args.name or args.target)])


def cmd_unreserve(args: argparse.Namespace) -> None:
    registry = registry_for(args)
    with connect(args) as router:
        writes = [w for w in (router.plan_unreservation(m) for m in registry.resolve_macs(args.target)) if w]
        run_writes(args, router, writes)


def cmd_reservations(args: argparse.Namespace) -> None:
    with connect(args) as router:
        items = router.reservations()
    rows = [[i.get("ip", ""), i.get("mac", ""), i.get("hostname") or i.get("comment", ""), i.get("enable", "")] for i in items]
    emit(args, items, table(rows, ["IP", "MAC", "NAME", "ENABLED"]))


def cmd_raw(args: argparse.Namespace) -> None:
    params: dict[str, Any] = {"operation": args.operation}
    for pair in args.param or []:
        key, _, value = pair.partition("=")
        params[key] = value
    if args.operation not in ("read", "load") and not args.yes:
        args.verbose = True
        run_writes(args, None, [Write(f"{args.operation} {args.path}", args.path, params)])
        return
    with connect(args) as router:
        emit(args, router.s.request(args.path, params, raw=True, op_in_url=args.op_in_url))


# -- parser --------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", default=argparse.SUPPRESS,
                        help="router URL (https only); overrides the selected router's host")
    common.add_argument("--router", default=argparse.SUPPRESS, metavar="NAME",
                        help="which configured router (default: auto-detect, else the default router)")
    # SUPPRESS keeps a top-level `tplink-guard --json devices` from being reset
    # by the subcommand's default.
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="machine-readable JSON output")
    writes = argparse.ArgumentParser(add_help=False)
    writes.add_argument("--yes", action="store_true", help="apply the change (default is a dry run)")
    writes.add_argument("-v", "--verbose", action="store_true", help="show the raw request payload")

    p = argparse.ArgumentParser(prog="tplink-guard", description="Per-device firewall / parental control for TP-Link routers.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output (any position)")
    p.add_argument("--router", metavar="NAME", help="which configured router (any position)")
    p.add_argument("--host", help="router URL, overriding the selected router's host (any position)")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("config", parents=[common], help="show or set connection settings")
    c.add_argument("action", nargs="?", choices=["show", "set"], default="show")
    c.add_argument("--set-host", metavar="URL")
    c.add_argument("--username")
    c.add_argument("--scheme", choices=["auto", "classic", "sg"])
    c.add_argument("--timeout", type=float)
    c.set_defaults(func=cmd_config)

    rt = sub.add_parser("router", parents=[common], help="manage several routers by name")
    rt.add_argument("action", nargs="?", choices=["list", "set", "remove", "use", "current"], default="list")
    rt.add_argument("name", nargs="?")
    rt.add_argument("--set-host", metavar="URL")
    rt.add_argument("--username")
    rt.add_argument("--scheme", choices=["auto", "classic", "sg"])
    rt.add_argument("--timeout", type=float)
    rt.add_argument("--gateway-mac", metavar="MAC", help="normally learned automatically on first login")
    rt.set_defaults(func=cmd_router)

    sub.add_parser("doctor", parents=[common], help="log in and report model / feature status").set_defaults(func=cmd_doctor)
    dv = sub.add_parser("devices", parents=[common], help="list connected devices")
    dv.add_argument("--sort", choices=["ip", "traffic"], default="ip")
    dv.add_argument("--top", type=int, metavar="N", help="show only the first N rows")
    dv.set_defaults(func=cmd_devices)

    ins = sub.add_parser("insights", parents=[common], help="top web sites of a profile, by minutes online")
    ins.add_argument("profile")
    ins.add_argument("--top", type=int, default=20, metavar="N")
    ins.add_argument("--days", type=int, default=7, metavar="N", help="how many days back, 1 = today (max 7)")
    ins.set_defaults(func=cmd_insights)

    sc = sub.add_parser("schedule", parents=[common, writes], help="set blocked hours / daily limits of a profile")
    sc.add_argument("profile")
    sc.add_argument("--days", default="all", help="mon-fri, sat,sun, weekday, weekend, all (default)")
    sc.add_argument("--block", action="append", metavar="HH:00-HH:00",
                    help="no internet in this range (repeatable); replaces the blocked hours of --days")
    sc.add_argument("--allow-all", action="store_true", help="clear all blocked hours of --days")
    sc.add_argument("--limit", action="append", metavar="weekday=MIN|weekend=MIN|...=off",
                    help="daily online-time limit (repeatable)")
    sc.set_defaults(func=cmd_schedule)
    sub.add_parser("profiles", parents=[common], help="list Parental Controls profiles").set_defaults(func=cmd_profiles)
    sub.add_parser("reservations", parents=[common], help="list DHCP reservations").set_defaults(func=cmd_reservations)

    d = sub.add_parser("device", parents=[common], help="manage the local device registry")
    d.add_argument("action", choices=["list", "add", "remove"])
    d.add_argument("alias", nargs="?")
    d.add_argument("--mac", action="append", help="known MAC (repeatable)")
    d.add_argument("--hostname", action="append", help="hostname hint used to recognise a new MAC (repeatable)")
    d.add_argument("--profile", help="Parental Controls profile this device belongs to")
    d.set_defaults(func=cmd_device)

    s = sub.add_parser("sync", parents=[common, writes], help="re-attach rotated MACs to their profiles")
    s.add_argument("--prune", action="store_true", help="also drop stale MACs (see `prune`)")
    s.set_defaults(func=cmd_sync)

    pr = sub.add_parser("prune", parents=[common, writes],
                        help="drop stale random MACs of registered devices from their profiles")
    pr.add_argument("profile", nargs="?", help="limit to one profile")
    pr.set_defaults(func=cmd_sync, prune=True)

    pw = sub.add_parser("password", parents=[common], help="store the router password in the macOS Keychain")
    pw.add_argument("action", choices=["set", "status", "delete"])
    pw.set_defaults(func=cmd_password)

    pd = sub.add_parser("profile", parents=[common, writes], help="add/remove devices of a profile, or rename it")
    pd.add_argument("action", choices=["add-device", "remove-device", "rename"])
    pd.add_argument("profile")
    pd.add_argument("targets", nargs="+", metavar="ALIAS|MAC|NEW_NAME")
    pd.set_defaults(func=cmd_profile_devices)

    st = sub.add_parser("sites", parents=[common, writes], help="block/unblock web sites for a profile")
    st.add_argument("action", choices=["block", "unblock"])
    st.add_argument("profile")
    st.add_argument("sites", nargs="+", help=f"domains/keywords or a preset ({', '.join(PRESETS)})")
    st.set_defaults(func=cmd_sites)

    for name in ("pause", "resume"):
        pp = sub.add_parser(name, parents=[common, writes], help=f"{name} internet for a profile")
        pp.add_argument("profile")
        pp.set_defaults(func=cmd_pause, action=name)

    for name in ("block", "unblock"):
        b = sub.add_parser(name, parents=[common, writes], help=f"{name} a device via the Access Control blacklist")
        b.add_argument("target", metavar="ALIAS|MAC")
        b.set_defaults(func=cmd_block, action=name)

    r = sub.add_parser("reserve", parents=[common, writes], help="add a DHCP reservation (fixed IP)")
    r.add_argument("target", metavar="ALIAS|MAC")
    r.add_argument("ip")
    r.add_argument("--name")
    r.set_defaults(func=cmd_reserve)

    ur = sub.add_parser("unreserve", parents=[common, writes], help="remove a DHCP reservation")
    ur.add_argument("target", metavar="ALIAS|MAC")
    ur.set_defaults(func=cmd_unreserve)

    raw = sub.add_parser("raw", parents=[common, writes], help="call an admin endpoint directly (discovery)")
    raw.add_argument("path", help="e.g. admin/smart_network?form=patrol_owner_list")
    raw.add_argument("operation", nargs="?", default="read")
    raw.add_argument("param", nargs="*", metavar="KEY=VALUE")
    raw.add_argument("--op-in-url", action="store_true", help="also put operation= in the URL")
    raw.set_defaults(func=cmd_raw)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for attr in ("yes", "verbose"):
        if not hasattr(args, attr):
            setattr(args, attr, False)
    try:
        if args.command == "device" and args.action != "list" and not args.alias:
            raise CliError("device add/remove needs an alias")
        args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        kind = _error_kind(exc)
        if kind is None:
            raise
        if args.json:
            print(json.dumps({"error": {"type": kind, "message": str(exc)}}, ensure_ascii=False), file=sys.stderr)
        else:
            print(f"error: {exc}", file=sys.stderr)
        return EXIT_CODES[kind]
    return 0


def _error_kind(exc: Exception) -> str | None:
    if isinstance(exc, AuthError):
        return "auth"
    if isinstance(exc, RouterError):
        return "router"
    if isinstance(exc, LookupError):
        return "not_found"
    if isinstance(exc, (CliError, ValueError)):
        return "usage"
    if isinstance(exc, OSError):  # URLError, timeouts, TLS failures
        return "network"
    return None
