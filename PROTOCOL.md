# TP-Link local admin protocol (as used by tplink-guard)

Notes written from observing an Archer AX20 v1.0 (firmware 1.3.8) and from
the router's own web UI scripts (`/webpages/js/su/frame.js`,
`/webpages/modules/**`).

## Transport

* `POST https://<router>/cgi-bin/luci/;stok=<token>/<path>`
* `Content-Type: application/x-www-form-urlencoded`, `Referer: <router>/webpages/index.html`
* After login, the `sysauth` cookie and the `stok` path token identify the session.

## Handshake

| Step | Request | Reply |
|---|---|---|
| 1 | `login?form=keys&operation=read`, **empty body** | `data.password = [n_hex, e_hex]` (1024-bit RSA) |
| 2 | `login?form=auth&operation=read`, **empty body** | `data.key = [n_hex, e_hex]` (512-bit RSA), `data.seq` |
| 3 | `login?form=login`, body `sign=…&data=…` | encrypted `{success, data:{stok}}` + `Set-Cookie: sysauth=…` |

Sending `operation=read` in the body as well as the URL makes steps 1–2
fail with `no such callback`.

The client picks a fresh AES-128-CBC key and IV (PKCS#7 padding). The `data`
field is `base64(AES(plaintext))`, and replies come back the same way.

### `classic` scheme

* key / IV: 16 lowercase hex characters each (used as ASCII bytes)
* `hash = md5(username + password)`
* password: `hex(RSA_PKCS1v1.5(password))` with the step-1 key
* login plaintext: `operation=login&password=<hex>&confirm=true`
* `sign`: the string is cut into 53-character chunks, each chunk is
  encrypted with RSA PKCS#1 v1.5 (step-2 key), and the hex results are
  concatenated.
  * login: `k=<key>&i=<iv>&h=<hash>&s=<seq + len(data)>`
  * later requests: `h=<hash>&s=<seq + len(data)>`
* request plaintext is form-encoded. **`operation` must stay out of the URL**
  (AX20 1.3.8 answers `no such callback` otherwise).

### `sg` scheme (SG CLS L1 STAGE2 / EU CE RED certified firmware)

Detected via `device_config?form=config` → `data.certification`.

* key / IV: 16 random decimal digits each
* login `hash = sha256(username + password)`; login `sign` uses RSA-OAEP
  (SHA-1/MGF1), chunk size `min(53, k − 42)`
* per request: `hash = sha256(base64 data)`, and
  `sign = concat(HMAC-SHA256(key="k=<key>&i=<iv>", chunk))` over
  53-character chunks of `h=<hash>&s=<seq + len(data)>`
* request plaintext is a JSON object; parameters are also mirrored into the
  query string.

Website entries in `black_website_list` / `white_website_list` match as
**substrings** of the host name (web UI: "Block all websites that contain a
specific keyword").

## List ("IPF store") operations

The web UI's generic store proxy uses:

| Operation | Body |
|---|---|
| `load` | `operation=load` |
| `insert` | `operation=insert&key=add&old=add&index=0&new=<json record>` |
| `update` | `operation=update&key=<record.key>&old=<json old record>&new=<json new record>` |
| `remove` | `operation=remove&key=<key>&index=<index>` |

An empty list is often returned as `{}` rather than `[]`.

## Endpoints used

| Path | Ops | Notes |
|---|---|---|
| `admin/status?form=all` | read | `access_devices_wired`, `access_devices_wireless_host`, `access_devices_wireless_guest` |
| `admin/firmware?form=upgrade` | read | model, hardware and firmware version |
| `admin/dhcps?form=client` | load | DHCP leases |
| `admin/dhcps?form=reservation` | load / insert / remove | insert `{mac, ip, enable, hostname}` (web UI fields; the router copies `hostname` into `comment`); new entries go to index 0; remove by `index` |
| `admin/access_control?form=enable` | read | `{enable, host_mac}` |
| `admin/access_control?form=mode` | read | `{access_mode: black\|white}` |
| `admin/access_control?form=black_list` | load / insert / remove | record copied from `black_devices`, or `{name: "", mac}` for a typed-in MAC; stored entries have no `key`, and remove works by `index` |
| `admin/access_control?form=black_devices` | load | candidate devices |
| `admin/smart_network?form=patrol_enable` | read | Parental Controls on/off |
| `admin/smart_network?form=patrol_limit` | read | `profile_len`, `devices_len`, `category_len` |
| `admin/smart_network?form=patrol_owner_list` | load / update / remove | profiles: `name`, `owner_id`, `key`, `client_list`, `black_website_list`, `white_website_list`, `website_type`, time limits, `*_time` hour masks |
| `admin/smart_network?form=patrol_owner_block` | write | `owner_id`, `internet_blocked` (pause a profile) |
| `admin/smart_network?form=patrol_devices` | load | every device HomeCare has seen, including offline ones |
| `admin/smart_network?form=patrol_insights` | read + `owner_id` | `insights`: 7 days, index 0 = today; `spend_online` minutes, `per_hour`, `website_list[{website, spend_online, block}]` |
| `admin/smart_network?form=game_accelerator` | loadDevice | per device: `trafficUsage` bytes, `downloadSpeed`, `uploadSpeed`, `onlineTime` |

### Time rules in a profile record

| Field | Meaning |
|---|---|
| `enable_workday_time_limit`, `workday_daily_time` | Mon–Fri daily online budget on/off, minutes (string) |
| `enable_weekend_time_limit`, `weekend_daily_time` | Sat–Sun daily online budget on/off, minutes (string) |
| `mon_time` … `sun_time` | 24 ints, one per hour: **1 = internet allowed**, 0 = blocked |

The web UI turns runs of `1`s into its "timetable", and warns that an empty
timetable means the profile can never go online (en_US `NO_TIME_TABLE_TIP`).

Verification status on the AX20: all `read`/`load` calls were verified live.
`patrol_owner_list` `update` (website list) was verified live: the profile read
back identical to its pre-change state after block + unblock, and
`patrol_owner_block` `write` (pause / resume), adding / removing a `client_list`
entry, renaming a profile, Access Control black_list insert / remove, and DHCP reservation insert /
remove were verified the same way. Every write tplink-guard makes has now
been applied to hardware.
