import json

import pytest

from tplink_guard.session import AuthError, RouterError, Session, normalize_host

from .fake_router import PASSWORD, FakeRouter


def ok(data):
    return lambda params: {"success": True, "data": data}


@pytest.mark.parametrize("scheme", ["classic", "sg"])
def test_login_and_request_roundtrip(scheme):
    fake = FakeRouter(scheme)
    fake.handlers[("admin/status?form=all", "read")] = ok({"lan_ipv4_ipaddr": "192.168.0.1"})
    with Session("192.168.0.1", PASSWORD, transport=fake) as s:
        assert s.scheme == scheme
        assert s.request("admin/status?form=all", {"operation": "read"}) == {"lan_ipv4_ipaddr": "192.168.0.1"}
    assert fake.calls[-1][0] == "admin/system?form=logout"


def test_wrong_password():
    with pytest.raises(AuthError):
        Session("192.168.0.1", "nope", transport=FakeRouter()).login()


def test_classic_keeps_operation_out_of_url():
    fake = FakeRouter("classic")
    fake.handlers[("admin/dhcps?form=reservation", "load")] = ok([])
    s = Session("192.168.0.1", PASSWORD, transport=fake)
    s.login()
    assert s.request("admin/dhcps?form=reservation", "operation=load") == []
    with pytest.raises(RouterError):
        s.request("admin/dhcps?form=reservation", {"operation": "load"}, op_in_url=True)


def test_sg_sends_json_body():
    fake = FakeRouter("sg")
    fake.handlers[("admin/x?form=y", "insert")] = ok({})
    s = Session("192.168.0.1", PASSWORD, transport=fake)
    s.login()
    s.request("admin/x?form=y", {"operation": "insert", "new": json.dumps({"a": 1})})
    assert fake.calls[-1][1] == {"operation": "insert", "new": '{"a": 1}'}


def test_error_reply_raises_unless_raw():
    fake = FakeRouter()
    s = Session("192.168.0.1", PASSWORD, transport=fake)
    s.login()
    with pytest.raises(RouterError):
        s.request("admin/nope?form=x", {"operation": "read"})
    assert s.request("admin/nope?form=x", {"operation": "read"}, raw=True)["success"] is False


@pytest.mark.parametrize(
    "given, expected",
    [("192.168.0.1", "https://192.168.0.1"), ("https://10.0.0.1:8443/", "https://10.0.0.1:8443")],
)
def test_normalize_host(given, expected):
    assert normalize_host(given) == expected


def test_plain_http_refused():
    with pytest.raises(ValueError):
        normalize_host("http://192.168.0.1")
