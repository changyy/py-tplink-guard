"""
tplink-guard: per-device firewall / parental control for TP-Link routers.

Talks to the router's local admin CGI over HTTPS using only the Python
standard library (AES and RSA are implemented in ``tplink_guard.crypto``).
"""

from __future__ import annotations

from ._version import __version__

__all__ = ["__version__"]
