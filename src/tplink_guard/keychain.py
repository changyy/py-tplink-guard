"""
Router password in the macOS Keychain, via the built-in ``security`` tool.

Items are generic passwords with service ``tplink-guard`` and account
``<username>@<host>`` (router ``default``) or ``<router>/<username>@<host>``,
so several routers, even behind the same IP, can be stored side by side.
On other platforms (or without ``security``) everything reports
"unavailable" and the CLI falls back to the environment / a prompt.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

SERVICE = "tplink-guard"
NOT_FOUND = 44  # errSecItemNotFound, as returned by `security`


class KeychainError(Exception):
    pass


def available() -> bool:
    return sys.platform == "darwin" and shutil.which("security") is not None


def account(username: str, host: str, router: str = "default") -> str:
    """``admin@192.168.0.1`` for router ``default``; ``NAME/admin@...`` otherwise,
    so two homes behind the same IP keep separate passwords."""
    base = f"{username}@{host.split('://', 1)[-1]}"
    return base if router == "default" else f"{router}/{base}"


def _run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(["security", *args], **kwargs)


def get(acct: str) -> str | None:
    """The stored password, or ``None`` if there is none (or no Keychain)."""
    if not available():
        return None
    proc = _run(["find-generic-password", "-s", SERVICE, "-a", acct, "-w"], capture_output=True, text=True)
    if proc.returncode == NOT_FOUND:
        return None
    if proc.returncode != 0:
        # e.g. the keychain is locked and no UI is available (ssh, launchd)
        raise KeychainError(f"cannot read Keychain item {SERVICE}/{acct}: {proc.stderr.strip()}")
    return proc.stdout.rstrip("\n")


def set_interactive(acct: str) -> None:
    """
    Store or replace the password. ``security`` asks for it on the terminal
    (``-w`` as the last option), so it never appears in argv or ``ps``.
    """
    if not available():
        raise KeychainError("macOS Keychain is not available on this system")
    proc = _run(
        ["add-generic-password", "-U", "-s", SERVICE, "-a", acct, "-l", f"tplink-guard ({acct})", "-w"],
    )
    if proc.returncode != 0:
        raise KeychainError(f"could not store the password (security exit {proc.returncode})")


def delete(acct: str) -> bool:
    """Remove the item; ``False`` if there was nothing to remove."""
    if not available():
        raise KeychainError("macOS Keychain is not available on this system")
    proc = _run(["delete-generic-password", "-s", SERVICE, "-a", acct], capture_output=True, text=True)
    if proc.returncode == NOT_FOUND:
        return False
    if proc.returncode != 0:
        raise KeychainError(f"could not delete Keychain item: {proc.stderr.strip()}")
    return True
