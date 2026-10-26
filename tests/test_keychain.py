import json
import subprocess

import pytest

from tplink_guard import cli, keychain

from .test_cli import fake, run  # noqa: F401  (fixture + helper)


class FakeSecurity:
    """Stands in for /usr/bin/security; never touches the real Keychain."""

    def __init__(self):
        self.items = {}
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        cmd, opts = argv[1], argv[2:]
        acct = opts[opts.index("-a") + 1]
        if cmd == "find-generic-password":
            if acct not in self.items:
                return subprocess.CompletedProcess(argv, 44, "", "not found")
            return subprocess.CompletedProcess(argv, 0, self.items[acct] + "\n", "")
        if cmd == "add-generic-password":
            assert opts[-1] == "-w", "password must be prompted for, never passed in argv"
            self.items[acct] = "from-prompt"
            return subprocess.CompletedProcess(argv, 0)
        if cmd == "delete-generic-password":
            if self.items.pop(acct, None) is None:
                return subprocess.CompletedProcess(argv, 44, "", "not found")
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)


@pytest.fixture
def security(monkeypatch, tmp_path):
    sec = FakeSecurity()
    monkeypatch.setattr(keychain, "available", lambda: True)
    monkeypatch.setattr(keychain, "_run", lambda args, **kw: sec(["security", *args], **kw))
    monkeypatch.setenv("TPLINK_GUARD_HOME", str(tmp_path))
    monkeypatch.delenv(cli.PASSWORD_ENV, raising=False)
    return sec


def target(name="default"):
    return cli.Target(name=name, host="https://192.168.0.1", username="admin", scheme="auto",
                      timeout=15, gateway_mac=None, reason="test")


def test_account_name():
    assert keychain.account("admin", "https://192.168.0.1") == "admin@192.168.0.1"
    assert keychain.account("admin", "https://192.168.0.1", "grandma") == "grandma/admin@192.168.0.1"


def test_get_missing_returns_none(security):
    assert keychain.get("admin@192.168.0.1") is None


def test_set_status_delete(security, capsys):
    code, out, _ = run(capsys, "--json", "password", "set")
    assert code == 0 and json.loads(out)["stored"] is True
    assert "from-prompt" not in " ".join(sum(security.calls, []))
    _, out, _ = run(capsys, "--json", "password", "status")
    assert json.loads(out)["source"] == "keychain"
    _, out, _ = run(capsys, "--json", "password", "delete")
    assert json.loads(out)["deleted"] is True
    _, out, _ = run(capsys, "--json", "password", "delete")
    assert json.loads(out)["deleted"] is False


def test_lookup_order_env_then_keychain(security, monkeypatch):
    security.items["admin@192.168.0.1"] = "kc-pass"
    assert cli._password(target()) == "kc-pass"
    monkeypatch.setenv(cli.PASSWORD_ENV, "env-pass")
    assert cli._password(target()) == "env-pass"


def test_no_password_non_interactive(security, monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    with pytest.raises(cli.CliError, match="password set"):
        cli._password(target())


def test_locked_keychain_is_a_clean_error(security, monkeypatch):
    monkeypatch.setattr(
        keychain, "_run",
        lambda args, **kw: subprocess.CompletedProcess(args, 36, "", "User interaction is not allowed."),
    )
    with pytest.raises(cli.CliError, match="User interaction"):
        cli._password(target())


def test_keychain_used_to_log_in(fake, security, capsys, monkeypatch):  # noqa: F811
    from .fake_router import PASSWORD

    security.items["admin@192.168.0.1"] = PASSWORD
    code, out, _ = run(capsys, "--json", "devices")
    assert code == 0 and json.loads(out)
