# tplink-guard

[![PyPI](https://img.shields.io/pypi/v/tplink-guard.svg)](https://pypi.org/project/tplink-guard/)
[![PyPI Downloads](https://static.pepy.tech/badge/tplink-guard)](https://pepy.tech/projects/tplink-guard)
[![Python](https://img.shields.io/pypi/pyversions/tplink-guard.svg)](https://pypi.org/project/tplink-guard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

A small, **zero-dependency** CLI for parents: use a TP-Link router's Parental
Controls to decide **when** a child's devices can go online and **what** they
can reach, from the command line or a script.

It talks to the router's own local admin API (`/cgi-bin/luci`) over **HTTPS**,
using only the Python standard library.

- Per-device rules through Parental Controls *profiles*: blocked hours, daily
  time limits, blocked sites, pause / resume.
- See what a profile actually uses: top sites by minutes online, and devices
  by traffic.
- Rules survive iPadOS updates. iOS / iPadOS use a *private Wi-Fi address*
  that can change. `tplink-guard` remembers each device by alias and
  hostname, and `sync` puts a new MAC back into the right profile.
- Every change is a dry run until you add `--yes`. `--json` works everywhere.

> Unofficial project, not affiliated with TP-Link.

---

## Install

```bash
pip install tplink-guard
```

From source:

```bash
git clone https://github.com/changyy/py-tplink-guard
python3 -m venv .venv && .venv/bin/pip install -e './py-tplink-guard[dev]'
```

## Setup

```bash
tplink-guard config set --set-host https://192.168.0.1   # https only; the router's self-signed cert is accepted
tplink-guard password set                                # macOS: store the password in the Keychain

tplink-guard doctor      # model, firmware, Parental Controls / Access Control status
tplink-guard profiles    # profiles: devices, blocked sites, daily limits, blocked hours
```

### Several routers (optional)

With no extra setup everything uses one router called `default`. To manage
more (say, grandparents' home too), give each one a name:

```bash
tplink-guard router set grandma --set-host https://192.168.0.1   # same IP as home is fine
tplink-guard --router grandma password set
tplink-guard router list
```

```
   NAME     HOST                 USER   GATEWAY MAC
-  -------  -------------------  -----  -----------------
*  default  https://192.168.0.1  admin  00-00-5E-00-53-AA
   grandma  https://192.168.0.1  admin  00-00-5E-00-53-BB
```

- `--router NAME` (anywhere on the command line) picks a router explicitly.
- Without it, `tplink-guard` looks at the network it is on: the **gateway's
  MAC address** from the ARP table identifies the router even when two homes
  use the same IP. No login or location permission is needed, and wired
  connections work too. If nothing matches, the default router is used
  (`router use NAME` changes it).
- The gateway MAC is recorded automatically the first time you log in from
  that router's own network. `router current` shows which router would be
  used and why.
- Each router keeps its own device registry and Keychain item.
- Some environments hide the ARP table from the Python process (e.g. a
  sandboxed terminal). Detection then finds nothing and the default router
  is used; `router current` shows `gateway_mac: None`.

The password is looked up in this order:

1. `TPLINK_GUARD_PASSWORD` environment variable
2. macOS Keychain, per router (`tplink-guard password set`; check with `password status`, remove with `password delete`)
3. an interactive prompt

The tool never writes it to its own files. If the Keychain cannot be read
(for example it is locked and `security` may not ask), the command exits with
a `usage` error that includes `security`'s message. Running from cron /
launchd has not been tested yet. Until it is, `TPLINK_GUARD_PASSWORD` in the
job's environment is the predictable option.

The examples below use a profile named `Kids`. Create it once in the
router's web UI (*Advanced → Parental Controls*). Everything after that can
be done here.

---

## Scenario 1: no internet at dinner and bedtime on school days

Mon–Fri, block 18:00–19:00 (dinner) and 21:00–22:00 (getting ready for bed).
All other hours stay open.

```bash
tplink-guard schedule Kids --days mon-fri --block 18:00-19:00 --block 21:00-22:00          # dry run
tplink-guard schedule Kids --days mon-fri --block 18:00-19:00 --block 21:00-22:00 --yes    # apply

tplink-guard profiles
#   blocked hours: Mon-Fri 18:00-19:00 21:00-22:00
```

- `--block` **replaces** the blocked hours of the chosen `--days`. Other days
  are left alone. Repeat `--block` for several ranges.
- `--days` takes `mon-fri`, `sat,sun`, `weekday`, `weekend`, `all` (default).
- The router stores one flag per hour, so times must be whole hours (`HH:00`).
  Split overnight ranges: `--block 22:00-24:00` and, for the next days, `--block 00:00-07:00`.
- Clear blocked hours: `tplink-guard schedule Kids --days all --allow-all --yes`.
- Daily time budget as well: `--limit weekday=120 --limit weekend=180`, or `--limit weekday=off`.
- For a one-off "internet off now", use `tplink-guard pause Kids --yes` and later `resume Kids --yes`.

## Scenario 2: block YouTube, keep Google

```bash
tplink-guard sites block Kids youtube          # dry run: shows what will be added
tplink-guard sites block Kids youtube --yes
tplink-guard sites unblock Kids youtube --yes  # undo
```

The router blocks every host that **contains** an entry. The `youtube`
preset is therefore kept small:

| Entry | Covers |
|---|---|
| `youtube` | youtube.com, m.youtube.com, youtube-nocookie.com, youtubei.googleapis.com |
| `youtu.be` | short links |
| `ytimg.com` | thumbnails, player assets |
| `googlevideo.com` | the video streams |
| `yt3.ggpht.com` | channel avatars |

None of them matches `google.com`, `googleapis.com`, `gstatic.com` or
`dns.google`, so Search, Gmail, Drive and sign-in keep working. This is
checked in the test suite. Videos embedded from Google Drive also stream
from `googlevideo.com` and will stop too.

Blocking is done by the router from the host name, so test it on the real
device, in Safari *and* in the YouTube app. If something still gets through,
`pause` the profile or `block` the device.

**YouTube Shorts cannot be blocked separately from regular YouTube.** Shorts
use the same hosts (`www.youtube.com/shorts/…`, the same `googlevideo.com`
streams), and over HTTPS the router only sees the host name, never the
path. It is all of YouTube or none of it. Limiting only Shorts has to happen
in the YouTube account (supervised / family settings), not on the router.

## Scenario 3: find the game sites, then block them

The router records how many minutes each profile spends on each host.

```bash
tplink-guard insights Kids --top 20            # last 7 days (the router keeps 7)
tplink-guard insights Kids --top 20 --days 1   # today only
```

```
[Kids] last 7 day(s), 353 min online
#   WEBSITE                         MINUTES  BLOCKED
--  ------------------------------  -------  -------
1   api.some-game.example           173
2   gateway.icloud.com              149
3   cdn.some-game.example            92
...
```

Pick the game's hosts, and block the shortest name they share, since
entries match by substring:

```bash
tplink-guard sites block Kids some-game.example --yes
```

Or straight from JSON, for example everything in the top 20 under one domain:

```bash
tplink-guard --json insights Kids --top 20 \
  | jq -r '.sites[] | select(.website | endswith(".some-game.example")) | .website'
```

## Scenario 4: add and remove devices of a profile

```bash
tplink-guard devices                                            # find the device's MAC
tplink-guard profile add-device Kids 00:00:5E:00:53:02 --yes
tplink-guard profile remove-device Kids 00:00:5E:00:53:02 --yes
```

For an iPad or iPhone whose private address changes, register it once and
let `sync` keep the profile up to date:

```bash
tplink-guard device add kid-ipad --mac 00:00:5E:00:53:02 --hostname Kid-iPad --profile Kids
tplink-guard sync          # dry run: new MACs it recognised and the profile changes
tplink-guard sync --yes    # apply (e.g. from cron / launchd every 10 minutes)
```

`sync` matches a new MAC by the device's hostname. It won't move a MAC that
already belongs to another profile, skips hostnames that match several
registered devices, and respects the router's per-profile device limit (8 on
the Archer AX20). `profile add-device Kids kid-ipad` adds every known MAC of
an alias at once.

Every rotation can leave an old MAC behind in the profile, and profiles hold
a limited number of devices (8 on the AX20). `prune` removes a registered
device's **random MACs that are not online right now**, keeping the online one
(or, if the device is offline, the newest). MACs that are not in your
registry are never touched.

```bash
tplink-guard prune Kids            # dry run: which MACs would go
tplink-guard prune Kids --yes
tplink-guard sync --prune --yes    # learn new MACs and prune old ones in one update
```

Tip: setting *Settings → Wi-Fi → (network) → Private Wi-Fi Address* to
**Fixed** (iPadOS 18+) or **Off** on the home network makes this rarely needed.

## Scenario 5: see devices, and who uses the most traffic

```bash
tplink-guard devices                          # all connected devices, by IP
tplink-guard devices --sort traffic --top 10  # top 10 by traffic
```

```
IP             MAC                MAC TYPE  HOSTNAME    LINK   TRAFFIC  ALIAS     PROFILE
-------------  -----------------  --------  ----------  -----  -------  --------  -------
192.168.0.132  00-00-5E-00-53-03            Living-TV   5G     19.2 GB
192.168.0.199  02-00-00-00-00-01  random    Kid-iPad    2.4G   1.8 GB   kid-ipad  Kids
...
```

`MAC TYPE random` marks a private (rotating) address. `TRAFFIC` is the
router's usage counter for the device. In JSON, each device has
`traffic_bytes`, `down_bps`, `up_bps` and `online_seconds`:

```bash
tplink-guard --json devices --sort traffic --top 10 | jq -r '.[] | "\(.hostname)\t\(.traffic_bytes)"'
```

---

## Command reference

| Command | What it does |
|---|---|
| `doctor` | log in; model, firmware, feature status |
| `devices [--sort ip\|traffic] [--top N]` | connected devices |
| `profiles` | Parental Controls profiles with devices, sites, limits, blocked hours |
| `insights PROFILE [--top N] [--days N]` | top sites of a profile by minutes online |
| `schedule PROFILE [--days D] --block HH:00-HH:00 ... \| --allow-all [--limit weekday=MIN]` | blocked hours / daily limits |
| `sites block\|unblock PROFILE SITE...` | block list (`youtube` preset) |
| `pause PROFILE` / `resume PROFILE` | cut / restore internet for a profile now |
| `profile add-device\|remove-device PROFILE ALIAS\|MAC...` | profile devices |
| `profile rename PROFILE NEW_NAME` | rename a profile |
| `device list\|add\|remove` | local registry: alias → MACs, hostname hints, profile |
| `sync [--prune]` | put rotated MACs back into their profile (and drop stale ones) |
| `prune [PROFILE]` | drop stale random MACs of registered devices from their profiles |
| `password set\|status\|delete` | router password in the macOS Keychain |
| `block ALIAS\|MAC` / `unblock` | Access Control blacklist (no internet at all); refuses to block the managing computer |
| `reserve ALIAS\|MAC IP` / `unreserve ALIAS\|MAC` | DHCP reservation (fixed IP) |
| `reservations` | list DHCP reservations |
| `raw PATH [OPERATION] [k=v ...]` | call any admin endpoint (discovery) |
| `router [list\|set\|remove\|use\|current] [NAME]` | several routers by name; `current` shows which one is selected and why |
| `config show\|set` | host, username, scheme, timeout of the selected router |

Commands that change the router print a plan and do nothing until `--yes`.
Add `-v` to see the exact request.

## JSON output

Every command accepts `--json`, before or after the subcommand. Read
commands print the data as is. Write commands print:

```json
{"dry_run": true, "applied": false,
 "changes": [{"description": "...", "path": "admin/...", "params": {"...": "only with -v"}}],
 "notes": []}
```

`sync` adds `learned` (`[{alias, mac}]`), `warnings` and `registry_updated`; with
`--prune` (and `prune`) also `pruned`.

Errors go to **stderr** as `{"error": {"type", "message"}}`, with an exit
code per type:

| Exit | Type | Meaning |
|---|---|---|
| 0 | | success |
| 2 | `usage` | bad arguments / input |
| 3 | `auth` | login rejected |
| 4 | `router` | router returned an error |
| 5 | `not_found` | unknown profile / alias |
| 6 | `network` | router unreachable, TLS or timeout |

## Tested routers

| Model | Firmware | Login scheme | Status |
|---|---|---|---|
| Archer AX20 v1.0 | 1.3.8 Build 20230830 | classic | every command verified on the device |

Newer SG / CE-RED certified firmware (Wi-Fi 7 era) uses a different signature
scheme (`sg`). It is implemented and unit-tested, but not yet tried on
hardware. Protocol notes: [PROTOCOL.md](./PROTOCOL.md).

## Limits worth knowing

- Site blocking works on host names. Apps that use their own DNS (DoH),
  fixed IPs or QUIC can slip past it, so check on the device. Paths such as
  `/shorts/` are invisible to the router.
- Blocked hours are whole hours. Profiles hold a limited number of devices
  and sites (8 and 32 on the AX20; `doctor` shows yours).
- Logging in from the CLI can end an open web-UI session, since the router
  allows one admin session at a time.

## Development

```bash
.venv/bin/python -m pytest -q
```

The tests include a fake router that plays the server side of both login
schemes, so the full handshake runs without hardware.

## License

MIT. See [LICENSE](./LICENSE).
