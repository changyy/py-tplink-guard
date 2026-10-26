import pytest

from tplink_guard import gateway


@pytest.fixture(autouse=True)
def no_real_network_probe(monkeypatch):
    """Tests must not depend on the machine's real gateway / ARP table."""
    monkeypatch.setattr(gateway, "default_gateway", lambda: None)
    monkeypatch.setattr(gateway, "mac_of", lambda ip: None)
    monkeypatch.setattr(gateway, "detect", lambda: (None, None))
