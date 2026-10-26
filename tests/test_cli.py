import json

import pytest

from tplink_guard import cli, session

from .fake_router import PASSWORD, FakeRouter


def ok(data):
    return lambda params: {"success": True, "data": data}


@pytest.fixture
def fake(monkeypatch, tmp_path):
    router = FakeRouter()
    profiles = [{
        "name": "Kids", "key": "1", "owner_id": "1", "client_list": {}, "black_website_list": {},
        "white_website_list": {}, "website_type": "black", "internet_blocked": False,
    }]
    router.handlers.update({
        ("admin/status?form=all", "read"): ok({
            "lan_macaddr": "00-00-5E-00-53-AA",
            "access_devices_wireless_host": [
                {"macaddr": "02-00-00-00-00-01", "ipaddr": "192.168.0.199", "hostname": "Kid-iPad", "wire_type": "5G"},
            ],
        }),
        ("admin/smart_network?form=patrol_owner_list", "load"): ok(profiles),
        ("admin/smart_network?form=game_accelerator", "loadDevice"): ok([
            {"mac": "02-00-00-00-00-01", "trafficUsage": 2000000000, "downloadSpeed": 100, "uploadSpeed": 5, "onlineTime": 12.5},
        ]),
        ("admin/smart_network?form=patrol_insights", "read"): ok({"owner_id": "1", "insights": [
            {"spend_online": "60", "website_list": [
                {"website": "game.example.com", "spend_online": "40", "block": False},
                {"website": "www.youtube.com", "spend_online": "20", "block": False},
            ]},
            {"spend_online": "30", "website_list": [{"website": "www.youtube.com", "spend_online": "30", "block": False}]},
        ]}),
        ("admin/smart_network?form=patrol_owner_list", "update"): ok({}),
        ("admin/smart_network?form=patrol_enable", "read"): ok({"enable": "on"}),
        ("admin/smart_network?form=patrol_limit", "read"): ok({"profile_len": 4, "devices_len": 8, "category_len": 32}),
    })
    monkeypatch.setattr(session, "Transport", lambda: router)
    monkeypatch.setenv("TPLINK_GUARD_HOME", str(tmp_path))
    monkeypatch.setenv(cli.PASSWORD_ENV, PASSWORD)
    return router


def run(capsys, *argv):
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def updates(router):
    return [p for path, p in router.calls if p.get("operation") == "update"]


@pytest.mark.parametrize("argv", [["--json", "devices"], ["devices", "--json"]])
def test_json_flag_any_position(fake, capsys, argv):
    code, out, _ = run(capsys, *argv)
    assert code == 0
    [dev] = json.loads(out)
    assert dev["mac"] == "02-00-00-00-00-01" and dev["random_mac"] is True and dev["alias"] is None


def test_write_dry_run_json(fake, capsys):
    code, out, _ = run(capsys, "--json", "sites", "block", "Kids", "youtube")
    data = json.loads(out)
    assert code == 0 and data["dry_run"] is True and data["applied"] is False
    assert data["changes"][0]["path"] == "admin/smart_network?form=patrol_owner_list"
    assert "params" not in data["changes"][0]
    assert updates(fake) == []


def test_write_apply_json(fake, capsys):
    code, out, _ = run(capsys, "--json", "sites", "block", "Kids", "example.com", "--yes", "-v")
    data = json.loads(out)
    assert data["applied"] is True and data["changes"][0]["params"]["operation"] == "update"
    assert json.loads(updates(fake)[0]["new"])["black_website_list"] == ["example.com"]


def test_nothing_to_change_json(fake, capsys):
    code, out, _ = run(capsys, "--json", "sites", "unblock", "Kids", "example.com")
    assert code == 0 and json.loads(out)["changes"] == []


def test_sync_json_learns_after_apply(fake, capsys):
    run(capsys, "device", "add", "kid", "--hostname", "Kid-iPad", "--profile", "Kids", "--json")
    code, out, _ = run(capsys, "--json", "sync")
    data = json.loads(out)
    assert data["learned"] == [{"alias": "kid", "mac": "02-00-00-00-00-01"}]
    assert data["registry_updated"] is False
    code, out, _ = run(capsys, "--json", "sync", "--yes")
    assert json.loads(out)["registry_updated"] is True
    _, out, _ = run(capsys, "--json", "device", "list")
    assert json.loads(out)["kid"]["macs"] == ["02-00-00-00-00-01"]


@pytest.mark.parametrize(
    "argv, kind, code",
    [
        (["sites", "block", "Nope", "x.com"], "not_found", 5),
        (["device", "add"], "usage", 2),
    ],
)
def test_errors_are_json_on_stderr(fake, capsys, argv, kind, code):
    rc, out, err = run(capsys, "--json", *argv)
    assert rc == code and out == ""
    assert json.loads(err)["error"]["type"] == kind


def test_auth_error_exit_code(fake, capsys, monkeypatch):
    monkeypatch.setenv(cli.PASSWORD_ENV, "wrong")
    rc, _, err = run(capsys, "--json", "devices")
    assert rc == 3 and json.loads(err)["error"]["type"] == "auth"


def test_profile_rename(fake, capsys):
    code, out, _ = run(capsys, "--json", "profile", "rename", "Kids", "tplink-guard-test", "--yes")
    assert code == 0 and json.loads(out)["applied"] is True
    new = json.loads(updates(fake)[0]["new"])
    assert new["name"] == "tplink-guard-test" and new["key"] == "1"


def test_profile_rename_rejects_long_name(fake, capsys):
    rc, _, err = run(capsys, "--json", "profile", "rename", "Kids", "x" * 65)
    assert rc == 2 and json.loads(err)["error"]["type"] == "usage"


@pytest.fixture
def dhcp(fake):
    reservations = [{"mac": "00-00-5E-00-53-04", "ip": "192.168.0.170", "hostname": "", "enable": "on"}]
    fake.handlers[("admin/dhcps?form=reservation", "load")] = ok(reservations)
    fake.handlers[("admin/dhcps?form=reservation", "insert")] = ok({})
    fake.handlers[("admin/dhcps?form=reservation", "remove")] = ok({})
    return fake


def test_reserve_record_matches_web_ui(dhcp, capsys):
    code, out, _ = run(capsys, "--json", "reserve", "00:11:22:33:44:55", "192.168.0.250", "--name", "test", "--yes")
    assert code == 0 and json.loads(out)["applied"] is True
    [params] = [p for _, p in dhcp.calls if p.get("operation") == "insert"]
    assert json.loads(params["new"]) == {"mac": "00-11-22-33-44-55", "ip": "192.168.0.250", "enable": "on", "hostname": "test"}


@pytest.mark.parametrize(
    "mac, ip, msg",
    [
        ("00-00-5E-00-53-04", "192.168.0.250", "already has a reservation"),
        ("00:11:22:33:44:55", "192.168.0.170", "already reserved"),
        ("00:11:22:33:44:55", "192.168.0.199", "currently used"),
        ("00:11:22:33:44:55", "192.168.0.999", "999"),
    ],
)
def test_reserve_refuses_conflicts(dhcp, capsys, mac, ip, msg):
    rc, _, err = run(capsys, "--json", "reserve", mac, ip)
    assert rc == 2 and msg in json.loads(err)["error"]["message"]


def test_unreserve_by_index(dhcp, capsys):
    code, out, _ = run(capsys, "--json", "unreserve", "00:00:5e:00:53:04", "--yes")
    assert json.loads(out)["applied"] is True
    [params] = [p for _, p in dhcp.calls if p.get("operation") == "remove"]
    assert params["index"] == "0"
    _, out, _ = run(capsys, "--json", "unreserve", "00:11:22:33:44:55")
    assert json.loads(out)["changes"] == []


def test_devices_traffic_sort(fake, capsys):
    code, out, _ = run(capsys, "--json", "devices", "--sort", "traffic", "--top", "1")
    [dev] = json.loads(out)
    assert code == 0 and dev["traffic_bytes"] == 2000000000 and dev["online_seconds"] == 12


def test_insights_aggregates_days(fake, capsys):
    code, out, _ = run(capsys, "--json", "insights", "Kids", "--top", "5")
    data = json.loads(out)
    assert data["online_minutes"] == 90
    assert data["sites"][0] == {"website": "www.youtube.com", "minutes": 50, "blocked": False}
    _, out, _ = run(capsys, "--json", "insights", "Kids", "--days", "1")
    assert json.loads(out)["sites"][0]["website"] == "game.example.com"


def test_schedule_weekday_dinner_and_bedtime(fake, capsys):
    code, out, _ = run(capsys, "--json", "schedule", "Kids", "--days", "mon-fri",
                       "--block", "18:00-19:00", "--block", "21:00-22:00", "--yes")
    assert code == 0 and json.loads(out)["applied"] is True
    new = json.loads(updates(fake)[0]["new"])
    expect = [0 if h in (18, 21) else 1 for h in range(24)]
    assert all(new[f"{d}_time"] == expect for d in ("mon", "tue", "wed", "thu", "fri"))
    assert "sat_time" not in new and "sun_time" not in new


def test_schedule_limits(fake, capsys):
    run(capsys, "--json", "schedule", "Kids", "--limit", "weekday=90", "--limit", "weekend=off", "--yes")
    new = json.loads(updates(fake)[0]["new"])
    assert new["enable_workday_time_limit"] is True and new["workday_daily_time"] == "90"
    assert new["enable_weekend_time_limit"] is False


@pytest.mark.parametrize("argv", [
    ["--block", "18:30-19:00"],
    ["--block", "21:00-07:00"],
    ["--days", "funday", "--block", "18:00-19:00"],
    ["--limit", "weekday=abc"],
    [],
])
def test_schedule_rejects_bad_input(fake, capsys, argv):
    rc, _, err = run(capsys, "--json", "schedule", "Kids", *argv)
    assert rc == 2 and json.loads(err)["error"]["type"] == "usage"


def test_parse_days():
    from tplink_guard.cli import parse_days

    assert parse_days("mon-fri") == ["mon", "tue", "wed", "thu", "fri"]
    assert parse_days("weekend") == ["sat", "sun"]
    assert parse_days("fri-mon") == ["fri", "sat", "sun", "mon"]
    assert parse_days("mon,wed") == ["mon", "wed"]
