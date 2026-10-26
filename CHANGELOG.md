# Changelog

## [1.20261026.1221539] — 2026-10-26

First release. Verified on an Archer AX20 v1.0 (firmware 1.3.8): every command
was run against the device, and each write was undone and checked against a
snapshot taken before it. Tested on Python 3.10–3.14.

### Parental Controls
- `profiles`: devices, blocked / allowed sites, daily limits (weekday / weekend)
  and blocked hours per day, grouped (`Mon-Fri 18:00-19:00 21:00-22:00`).
- `schedule`: set blocked hours for chosen days (`--days mon-fri --block 18:00-19:00`),
  clear them (`--allow-all`), and set daily limits (`--limit weekday=120|off`).
- `sites block|unblock` with a `youtube` preset that blocks YouTube but no Google host
  (the router matches entries as substrings; checked in the tests).
- `pause` / `resume` a profile's internet now.
- `profile add-device|remove-device|rename`.
- `insights`: top sites of a profile by minutes online, over the last 1–7 days.

### Devices
- `devices`: connected devices, flags private (random) MACs, shows alias, profile and
  traffic; `--sort traffic --top N`.
- Local registry (`device add|list|remove`): alias, every MAC seen, hostname hints, profile.
- `sync`: recognises a device's new private MAC by hostname and puts it back into its
  profile. It won't take a MAC from another profile, skips ambiguous hostnames, respects
  the profile device limit, and records new MACs only after the router accepted the change.
- `prune` (or `sync --prune`): drops a registered device's stale random MACs from its profile,
  keeping the one online now (or else the newest); unregistered MACs are never touched.
  Adds and removals for a profile go out as a single update.
- `block` / `unblock` (Access Control blacklist). Like the web UI, it refuses to block the
  computer that manages the router.
- `reserve` / `unreserve` DHCP reservations. Refuses a MAC that is already reserved, an IP
  that is reserved or in use, and invalid IPs.

### Password
- Looked up from `TPLINK_GUARD_PASSWORD`, then the macOS Keychain, then a prompt.
- `password set|status|delete` stores it in the Keychain via the built-in `security` tool
  (`security` prompts for it, so it never shows up in argv / `ps`).

### Several routers
- With no setup there is one router, `default`; existing single-router settings are read as it.
- `router set|use|remove|list|current` adds more by name; `--router NAME` picks one.
- Without `--router`, the router whose recorded gateway MAC matches this network's gateway
  (from the ARP table; no login, no location permission) is used, else the default one.
  The MAC is recorded automatically on the first login from the router's own network.
- Each router has its own device registry (`devices-NAME.json`) and Keychain item
  (`NAME/admin@host`), so two homes behind the same IP never mix.

### Scripting
- `--json`, `--router` and `--host` work before or after the subcommand.
- Write commands return `{dry_run, applied, changes, notes}`; nothing changes without `--yes`.
- Errors as JSON on stderr, with exit codes 2 usage · 3 auth · 4 router · 5 not_found · 6 network.
- `raw` for calling any admin endpoint.

### Under the hood
- Zero dependencies: HTTPS via `urllib` (self-signed certificate accepted, plain `http://`
  refused), AES-128-CBC and RSA (PKCS#1 v1.5, OAEP) in pure Python, tested against
  FIPS-197 / SP800-38A vectors.
- Both TP-Link login schemes, auto-detected: `classic` (MD5 + RSA-signed requests) and
  `sg` (SHA-256 + OAEP + HMAC; implemented and unit-tested, not yet tried on hardware).
- GitHub Actions builds and publishes only when a release is published.

---

**Versioning scheme:** `1.YYYYmmdd.1HHmmss`. The major is `1`, the minor is the build
*date*, and the patch is `1` followed by the build *time*.
