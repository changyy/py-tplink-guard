import json

import pytest

from tplink_guard import cli, gateway
from tplink_guard.registry import Device, Registry, home, load_routers

from .test_cli import fake, run  # noqa: F401  (fixture + helper)

HOME_MAC = "00-00-5E-00-53-AA"   # the fake router's lan_macaddr
OTHER_MAC = "00-00-5E-00-53-BB"


def config():
    return json.loads((home() / "config.json").read_text())


def test_unconfigured_is_router_default(fake, capsys):  # noqa: F811
    code, out, _ = run(capsys, "--json", "router", "list")
    [r] = json.loads(out)
    assert code == 0 and r["name"] == "default" and r["default"] is True and r["host"] == "https://192.168.0.1"


def test_legacy_flat_config_is_default(fake, capsys):  # noqa: F811
    (home() / "config.json").write_text(json.dumps({"host": "https://10.0.0.1", "username": "root"}))
    data = load_routers()
    assert data["default"] == "default" and data["routers"]["default"]["host"] == "https://10.0.0.1"
    _, out, _ = run(capsys, "--json", "config")
    assert json.loads(out)["host"] == "https://10.0.0.1" and json.loads(out)["router"] == "default"


def test_router_set_use_remove(fake, capsys):  # noqa: F811
    assert run(capsys, "--json", "router", "set", "grandma")[0] == 2           # new router needs --host
    assert run(capsys, "--json", "router", "set", "bad name!", "--set-host", "10.0.0.1")[0] == 2
    assert run(capsys, "router", "set", "grandma", "--set-host", "192.168.0.1", "--username", "root")[0] == 0
    run(capsys, "router", "use", "grandma")
    assert config()["default"] == "grandma"
    _, out, _ = run(capsys, "--json", "router", "current")
    assert json.loads(out)["router"] == "grandma" and json.loads(out)["reason"] == "default router"
    run(capsys, "router", "remove", "grandma")
    assert "grandma" not in config()["routers"] and config()["default"] == "default"
    assert run(capsys, "--json", "--router", "nope", "devices")[0] == 5


def _two_homes(capsys):
    run(capsys, "router", "set", "default", "--set-host", "192.168.0.1", "--gateway-mac", HOME_MAC)
    run(capsys, "router", "set", "grandma", "--set-host", "192.168.0.1", "--gateway-mac", OTHER_MAC)


@pytest.mark.parametrize("gw_mac, expect, reason", [
    (OTHER_MAC, "grandma", "gateway MAC"),
    (HOME_MAC, "default", "gateway MAC"),
    ("00-00-5E-00-53-CC", "default", "default router"),
    (None, "default", "default router"),
])
def test_auto_select_by_gateway_mac(fake, capsys, monkeypatch, gw_mac, expect, reason):  # noqa: F811
    _two_homes(capsys)
    monkeypatch.setattr(gateway, "detect", lambda: ("192.168.0.1", gw_mac))
    _, out, _ = run(capsys, "--json", "router", "current")
    info = json.loads(out)
    assert info["router"] == expect and info["reason"].startswith(reason)


def test_explicit_router_beats_detection(fake, capsys, monkeypatch):  # noqa: F811
    _two_homes(capsys)
    monkeypatch.setattr(gateway, "detect", lambda: ("192.168.0.1", OTHER_MAC))
    _, out, _ = run(capsys, "--json", "--router", "default", "router", "current")
    assert json.loads(out)["router"] == "default"


def test_registry_and_keychain_are_per_router(fake, capsys):  # noqa: F811
    _two_homes(capsys)
    run(capsys, "device", "add", "kid", "--mac", "02:00:00:00:00:01")
    run(capsys, "--router", "grandma", "device", "add", "cousin", "--mac", "02:00:00:00:00:02")
    assert list(Registry.load("default").devices) == ["kid"]
    assert list(Registry.load("grandma").devices) == ["cousin"]
    assert (home() / "devices.json").exists() and (home() / "devices-grandma.json").exists()
    _, out, _ = run(capsys, "--json", "--router", "grandma", "password", "status")
    assert json.loads(out)["account"] == "grandma/admin@192.168.0.1"
    _, out, _ = run(capsys, "--json", "password", "status")
    assert json.loads(out)["account"] == "admin@192.168.0.1"


def test_learns_gateway_mac_on_first_login(fake, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setattr(gateway, "default_gateway", lambda: "192.168.0.1")
    assert run(capsys, "--json", "devices")[0] == 0
    assert config()["routers"]["default"]["gateway_mac"] == HOME_MAC


def test_does_not_learn_on_other_network_or_host_override(fake, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setattr(gateway, "default_gateway", lambda: "10.0.0.1")
    run(capsys, "--json", "devices")
    assert not (home() / "config.json").exists()
    monkeypatch.setattr(gateway, "default_gateway", lambda: "192.168.0.1")
    run(capsys, "router", "set", "default", "--set-host", "192.168.0.1")
    run(capsys, "--json", "--host", "192.168.0.1:8443", "devices")
    assert "gateway_mac" not in config()["routers"]["default"]


def test_changing_host_forgets_gateway_mac(fake, capsys):  # noqa: F811
    run(capsys, "router", "set", "default", "--set-host", "192.168.0.1", "--gateway-mac", HOME_MAC)
    run(capsys, "router", "set", "default", "--set-host", "192.168.1.1")
    assert "gateway_mac" not in config()["routers"]["default"]
