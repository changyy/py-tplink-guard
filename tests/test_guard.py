import json

import pytest

from tplink_guard.api import Client, Profile, Router, is_random_mac, normalize_mac
from tplink_guard.guard import expand_sites, plan_sync
from tplink_guard.registry import Device, Registry


def profile(name, key, macs, **extra):
    return {
        "name": name,
        "key": key,
        "owner_id": key,
        "client_list": [{"mac": m, "name": m, "owner_id": key} for m in macs] or {},
        "black_website_list": {},
        "white_website_list": {},
        "website_type": "black",
        **extra,
    }


class StubRouter(Router):
    def __init__(self, clients, profiles, max_devices=8):
        self._clients = clients
        self._profiles = profiles
        self._max = max_devices

    def clients(self):
        return self._clients

    def profiles(self):
        return [Profile(p) for p in self._profiles]

    def parental_controls(self):
        return {"enabled": True, "max_devices_per_profile": self._max}


def test_mac_helpers():
    assert normalize_mac("02:00:00:00:00:01") == "02-00-00-00-00-01"
    assert is_random_mac("02-00-00-00-00-01")
    assert not is_random_mac("00-00-5E-00-53-02")
    with pytest.raises(ValueError):
        normalize_mac("nope")


def test_sync_learns_rotated_mac_and_adds_to_profile():
    reg = Registry({"kid": Device("kid", ["00-00-5E-00-53-01"], ["Kid-iPad"], "kids")})
    router = StubRouter(
        [Client("02-00-00-00-00-01", "192.168.0.199", "Kid-iPad", "2.4G")],
        [profile("kids", "0", ["00-00-5E-00-53-01"])],
    )
    plan = plan_sync(router, reg)
    assert plan.learned == [("kid", "02-00-00-00-00-01")]
    assert len(plan.writes) == 1
    params = plan.writes[0].params
    assert params["operation"] == "update" and params["key"] == "0"
    new = json.loads(params["new"])
    assert [c["mac"] for c in new["client_list"]] == ["00-00-5E-00-53-01", "02-00-00-00-00-01"]
    assert json.loads(params["old"])["client_list"][0]["mac"] == "00-00-5E-00-53-01"


def test_sync_noop_when_in_place():
    reg = Registry({"kid": Device("kid", ["00-00-5E-00-53-01"], [], "kids")})
    router = StubRouter([], [profile("kids", "0", ["00-00-5E-00-53-01"])])
    assert plan_sync(router, reg).empty


def test_sync_does_not_steal_from_other_profile():
    reg = Registry({"kid": Device("kid", [], ["iPad"], "kids")})
    router = StubRouter(
        [Client("02-00-00-00-00-01", "192.168.0.199", "iPad", "2.4G")],
        [profile("kids", "0", []), profile("timer", "2", ["02-00-00-00-00-01"])],
    )
    plan = plan_sync(router, reg)
    assert plan.writes == []
    assert any("already in profile 'timer'" in w for w in plan.warnings)


def test_sync_ambiguous_hostname_is_skipped():
    reg = Registry({
        "a": Device("a", [], ["iPad"], "kids"),
        "b": Device("b", [], ["ipad"], "kids"),
    })
    router = StubRouter([Client("02-00-00-00-00-01", "", "iPad", "")], [profile("kids", "0", [])])
    plan = plan_sync(router, reg)
    assert plan.learned == [] and plan.warnings


def test_sync_respects_device_limit():
    macs = [f"00-00-00-00-00-0{i}" for i in range(8)]
    reg = Registry({"kid": Device("kid", ["00-00-5E-00-53-01"], [], "kids")})
    router = StubRouter([], [profile("kids", "0", macs)], max_devices=8)
    plan = plan_sync(router, reg)
    assert plan.writes == [] and "allows 8" in plan.warnings[0]


def test_block_sites_preset():
    p = Profile(profile("kids", "0", []))
    write = Router(None).plan_block_sites(p, expand_sites(["youtube", "example.com"]))
    new = json.loads(write.params["new"])
    assert new["website_type"] == "black"
    assert "googlevideo.com" in new["black_website_list"] and new["black_website_list"][-1] == "example.com"


def test_unblock_sites():
    p = Profile(profile("kids", "0", [], black_website_list=["youtube", "ytimg.com"]))
    write = Router(None).plan_unblock_sites(p, ["youtube"])
    assert json.loads(write.params["new"])["black_website_list"] == ["ytimg.com"]
    assert Router(None).plan_unblock_sites(p, ["nothing"]) is None


def test_registry_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("TPLINK_GUARD_HOME", str(tmp_path))
    reg = Registry({"kid": Device("kid", ["00-00-5E-00-53-01"], ["Kid-iPad"], "kids")})
    reg.save()
    loaded = Registry.load()
    assert loaded.get("kid").hostnames == ["Kid-iPad"]
    assert loaded.resolve_macs("kid") == ["00-00-5E-00-53-01"]
    assert loaded.resolve_macs("aa:bb:cc:dd:ee:ff") == ["AA-BB-CC-DD-EE-FF"]


def _mask(*blocked):
    return [0 if h in blocked else 1 for h in range(24)]


def test_hour_ranges():
    from tplink_guard.api import hour_ranges

    assert hour_ranges(_mask(6, 21), 0) == [(6, 7), (21, 22)]
    assert hour_ranges(_mask(6, 21), 1) == [(0, 6), (7, 21), (22, 24)]
    assert hour_ranges(_mask(*range(24)), 0) == [(0, 24)]
    assert hour_ranges(_mask(), 0) == []


def test_profile_time_rules():
    raw = profile(
        "timer", "2", [],
        enable_workday_time_limit=True, workday_daily_time="120",
        enable_weekend_time_limit=False, weekend_daily_time="150",
        mon_time=_mask(6, 21), tue_time=_mask(6, 21), wed_time=_mask(6),
        thu_time=_mask(6, 21), fri_time=_mask(6, 21), sat_time=_mask(*range(24)), sun_time=_mask(),
    )
    p = Profile(raw)
    assert p.time_limits == {
        "weekday": {"enabled": True, "minutes": 120},
        "weekend": {"enabled": False, "minutes": 150},
    }
    assert p.schedule["mon"]["blocked"] == ["06:00-07:00", "21:00-22:00"]
    assert p.schedule["sun"] == {"allowed": ["00:00-24:00"], "blocked": []}

    from tplink_guard.cli import _limits_text, _schedule_text

    assert _schedule_text(p) == "Mon-Tue,Thu-Fri 06:00-07:00 21:00-22:00; Wed 06:00-07:00; Sat all day"
    assert _limits_text(p.time_limits) == "weekday 120 min, weekend off (150 min if enabled)"


def test_missing_mask_means_always_allowed():
    p = Profile(profile("x", "0", []))
    from tplink_guard.cli import _schedule_text

    assert _schedule_text(p) == "none (online 24h every day)"


class AclStub(Router):
    def __init__(self, host_mac, devices):
        self.data = {
            "admin/access_control?form=enable": {"enable": "on", "host_mac": host_mac},
            "admin/access_control?form=black_devices": devices,
        }

    def _read(self, path, operation="read", **extra):
        return self.data[path]


def test_blacklist_refuses_managing_host():
    router = AclStub("02-00-00-00-00-02", [])
    with pytest.raises(ValueError, match="lock you out"):
        router.plan_blacklist("02:00:00:00:00:02")
    router = AclStub("", [{"mac": "AA-BB-CC-DD-EE-FF", "host": "HOST"}])
    with pytest.raises(ValueError):
        router.plan_blacklist("AA-BB-CC-DD-EE-FF")


def test_blacklist_manual_mac_matches_web_ui():
    write = AclStub("02-00-00-00-00-02", []).plan_blacklist("00:11:22:33:44:55")
    assert json.loads(write.params["new"]) == {"name": "", "mac": "00-11-22-33-44-55"}
    assert write.params["operation"] == "insert" and write.params["key"] == "add"


GOOGLE_HOSTS = [
    "www.google.com", "google.com", "mail.google.com", "accounts.google.com", "www.googleapis.com",
    "fonts.googleapis.com", "play.googleapis.com", "www.gstatic.com", "dns.google", "drive.google.com",
    "lh3.googleusercontent.com",
]
YOUTUBE_HOSTS = [
    "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com", "www.youtube-nocookie.com",
    "i.ytimg.com", "rr1---sn-abc.googlevideo.com", "yt3.ggpht.com", "youtu.be",
]


def test_youtube_preset_spares_google():
    # The router blocks any host that *contains* an entry.
    from tplink_guard.guard import PRESETS

    hit = lambda host: any(k in host for k in PRESETS["youtube"])  # noqa: E731
    assert [h for h in GOOGLE_HOSTS if hit(h)] == []
    assert [h for h in YOUTUBE_HOSTS if not hit(h)] == []


OLD1, OLD2, NOW = "02-00-00-00-00-11", "02-00-00-00-00-12", "02-00-00-00-00-13"
REAL = "00-00-5E-00-53-09"  # a non-random MAC is never pruned


def test_prune_drops_offline_random_macs_keeps_online():
    reg = Registry({"kid": Device("kid", [OLD1, OLD2, NOW, REAL], [], "kids")})
    router = StubRouter([Client(NOW, "", "Kid-iPad", "")], [profile("kids", "0", [OLD1, OLD2, NOW, REAL, "02-00-00-00-00-99"])])
    plan = plan_sync(router, reg, add=False, prune=True)
    assert plan.pruned == [("kid", OLD1), ("kid", OLD2)]
    [write] = plan.writes
    left = [c["mac"] for c in json.loads(write.params["new"])["client_list"]]
    # the unregistered 02-...-99 is left alone
    assert left == [NOW, REAL, "02-00-00-00-00-99"]


def test_prune_offline_device_keeps_newest_mac():
    reg = Registry({"kid": Device("kid", [OLD1, OLD2, NOW], [], "kids")})
    router = StubRouter([], [profile("kids", "0", [OLD1, OLD2, NOW])])
    plan = plan_sync(router, reg, add=False, prune=True)
    assert [m for _, m in plan.pruned] == [OLD1, OLD2]


def test_sync_with_prune_is_one_write_per_profile():
    # new MAC shows up by hostname while two old ones fill the profile
    reg = Registry({"kid": Device("kid", [OLD1, OLD2], ["Kid-iPad"], "kids")})
    router = StubRouter([Client(NOW, "", "Kid-iPad", "")], [profile("kids", "0", [OLD1, OLD2])])
    plan = plan_sync(router, reg, add=True, prune=True)
    assert plan.learned == [("kid", NOW)]
    [write] = plan.writes
    assert [c["mac"] for c in json.loads(write.params["new"])["client_list"]] == [NOW]
    assert "add " + NOW in write.description and "remove" in write.description


def test_prune_makes_room_under_device_limit():
    full = [f"02-00-00-00-01-{i:02d}" for i in range(8)]
    reg = Registry({"kid": Device("kid", full, ["Kid-iPad"], "kids")})
    router = StubRouter([Client(NOW, "", "Kid-iPad", "")], [profile("kids", "0", full)], max_devices=8)
    assert plan_sync(router, reg).writes == []  # would be 9 > 8
    plan = plan_sync(router, reg, prune=True)
    [write] = plan.writes
    assert [c["mac"] for c in json.loads(write.params["new"])["client_list"]] == [NOW]


def test_prune_only_profile_filter():
    reg = Registry({
        "a": Device("a", [OLD1, NOW], [], "kids"),
        "b": Device("b", [OLD2, REAL], [], "other"),
    })
    router = StubRouter([], [profile("kids", "0", [OLD1, NOW]), profile("other", "1", [OLD2, REAL])])
    plan = plan_sync(router, reg, add=False, prune=True, only_profile="kids")
    assert plan.pruned == [("a", OLD1)]
