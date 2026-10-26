# tplink-guard — Roadmap & Action Items

Status legend: ✅ done · 🟡 in progress · ⬜ todo · 💡 idea

## v0.1 — Core (current)

- ✅ Zero-dependency HTTPS transport (urllib, self-signed cert accepted, http refused).
- ✅ Pure-Python AES-128-CBC and RSA (PKCS#1 v1.5, OAEP), tested against FIPS-197 / SP800-38A vectors.
- ✅ `classic` and `sg` login schemes with auto-detection; a fake router plays the server side in the tests.
- ✅ Read paths verified live on Archer AX20 v1.0 / 1.3.8: status, firmware, leases,
  reservations, Access Control, Parental Controls profiles / limits / devices.
- ✅ Local device registry (alias → MACs + hostname hints + profile).
- ✅ `sync`: learn rotated MACs by hostname and add them to the device's profile
  (dry run by default; refuses to steal from other profiles; honours device limits).
- ✅ `sites block|unblock` with a `youtube` preset; `pause|resume`; `block|unblock`;
  `reserve`; `raw` for endpoint discovery.
- ✅ Write path verified live (2026-10-26, AX20 1.3.8): `patrol_owner_list` update via
  `sites block` / `sites unblock`; the profile read back identical to its pre-test snapshot.
- ✅ `patrol_owner_block` verified live (2026-10-26): `pause` / `resume` toggled
  `internet_blocked`; all profiles read back identical to the pre-test snapshot.
- ✅ Profile device add / remove verified live (2026-10-26) with a dummy MAC
  `00:11:22:33:44:55`; profiles identical afterwards and no leftover in `patrol_devices`.
  This is the write `sync` relies on.
- ✅ `profile rename` verified live (2026-10-26): the diff showed only the `name` field changed.
- ✅ `access_control` black_list insert / remove verified live (2026-10-26) with a dummy MAC;
  Access Control read back identical to its pre-test snapshot. Enforcement on a real device
  was not tested.
- ✅ `dhcps` reservation insert / remove verified live (2026-10-26): `reserve` / `unreserve`
  with a dummy MAC on 192.168.0.250; reservations read back identical to the pre-test snapshot.
  All write paths are now verified on the AX20.
- ⬜ Verify the `sg` scheme on a Wi-Fi 7 router.

- ✅ `profiles` shows daily limits and blocked hours.
- ✅ `schedule` (blocked hours, daily limits) verified live on the test profile, restored to its snapshot.
- ✅ `insights` (top sites by minutes) and `devices --sort traffic` verified live.

## v0.2 — Hygiene


- ✅ `prune` / `sync --prune`: drop stale random MACs of registered devices (verified live
  on the test profile with dummy MACs; restored to snapshot).
- ✅ Password from the macOS Keychain (`password set|status|delete`).
- ✅ Several routers by name (`router ...`, `--router`), auto-selected by gateway MAC; per-router
  registry and Keychain item. MAC learning verified live; ARP detection verified with the system Python.
- ⬜ `import`: build the registry from the current profiles (`patrol_devices` + `client_list`).
- ⬜ Check that the `youtube` preset blocks the YouTube app on iPadOS and tvOS, and that
  keyword entries (`youtube`) are accepted by the filter.
- ⬜ Re-login on `403` / expired `stok` during long runs.

## Ideas

- 💡 `watch` mode / launchd plist: run `sync` every N minutes.
- 💡 Schedules: write the `*_time` hour masks (bed-time) from a simple `21:00-07:00` syntax.
- 💡 Alert (stdout / webhook) when an unknown device with a random MAC joins.
