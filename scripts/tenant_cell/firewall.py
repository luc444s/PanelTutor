"""Host firewall plumbing for the unprivileged edge relay.

The relay binds ``40000+index`` on the proxy-network gateway and only accepts
connections from Traefik. The host firewall still has to allow that port before
Traefik can reach it: with the default DROP input policy a new cell otherwise
looks healthy inside the cell but every route times out.

This module is deliberately small and fail-safe: it only mutates UFW when it is
installed, active and running as root. Other firewall managers are reported as
skipped instead of guessed at.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

RELAY_PORT_BASE = 40000
DEFAULT_TRAEFIK_CONTAINER = "traefik"
DEFAULT_PROXY_NETWORK = "proxy"


@dataclass(frozen=True)
class FirewallResult:
    provider: str
    active: bool
    changed: bool
    port: int
    rule: str = ""
    reason: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "active": self.active,
            "changed": self.changed,
            "port": self.port,
            "rule": self.rule,
            "reason": self.reason,
            "error": self.error,
        }


def _run(argv: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, check=False, timeout=timeout
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None


def detect_traefik_ip(container: str = DEFAULT_TRAEFIK_CONTAINER) -> str:
    fmt = '{{(index .NetworkSettings.Networks "%s").IPAddress}}' % (
        DEFAULT_PROXY_NETWORK,
    )
    checked = _run(["docker", "inspect", "-f", fmt, container])
    if checked is None or checked.returncode != 0:
        return ""
    return checked.stdout.strip()


def _ufw_active() -> bool:
    checked = _run(["ufw", "status"])
    return (
        checked is not None
        and checked.returncode == 0
        and "Status: active" in checked.stdout
    )


def _base(index: int) -> tuple[int, FirewallResult]:
    port = RELAY_PORT_BASE + int(index)
    return port, FirewallResult(
        provider="ufw", active=False, changed=False, port=port
    )


def ensure_relay_ingress(
    index: int,
    *,
    traefik_ip: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Allow Traefik to reach this cell's relay port (idempotent)."""
    port, result = _base(index)
    if os.geteuid() != 0:
        result = FirewallResult(provider="ufw", active=False, changed=False,
                                port=port, reason="requires root")
        return result.to_dict()
    if shutil.which("ufw") is None:
        result = FirewallResult(provider="ufw", active=False, changed=False,
                                port=port, reason="ufw is not installed")
        return result.to_dict()
    if not _ufw_active():
        result = FirewallResult(provider="ufw", active=False, changed=False,
                                port=port, reason="ufw is not active")
        return result.to_dict()

    ip = traefik_ip or detect_traefik_ip()
    if not ip:
        result = FirewallResult(
            provider="ufw",
            active=True,
            changed=False,
            port=port,
            error="cannot detect the Traefik IP in the proxy network",
        )
        return result.to_dict()

    argv = [
        "ufw",
        "allow",
        "from",
        ip,
        "to",
        "any",
        "port",
        str(port),
        "proto",
        "tcp",
    ]
    rule = " ".join(argv)
    if dry_run:
        return FirewallResult(
            provider="ufw", active=True, changed=False, port=port, rule=rule
        ).to_dict()

    checked = _run(argv)
    if checked is None or checked.returncode != 0:
        detail = (
            (checked.stderr or checked.stdout).strip()
            if checked is not None
            else "ufw did not run"
        )
        result = FirewallResult(
            provider="ufw",
            active=True,
            changed=False,
            port=port,
            rule=rule,
            error=detail[:300],
        )
        return result.to_dict()

    output = f"{checked.stdout} {checked.stderr}".lower()
    changed = "skipping" not in output
    return FirewallResult(
        provider="ufw", active=True, changed=changed, port=port, rule=rule
    ).to_dict()


def remove_relay_ingress(
    index: int,
    *,
    traefik_ip: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Remove the per-cell relay rule; safe when it was never added."""
    port, result = _base(index)
    if os.geteuid() != 0:
        return FirewallResult(provider="ufw", active=False, changed=False,
                              port=port, reason="requires root").to_dict()
    if shutil.which("ufw") is None or not _ufw_active():
        return FirewallResult(provider="ufw", active=False, changed=False,
                              port=port, reason="ufw is not available").to_dict()

    ip = traefik_ip or detect_traefik_ip()
    if not ip:
        return FirewallResult(
            provider="ufw",
            active=True,
            changed=False,
            port=port,
            error="cannot detect the Traefik IP in the proxy network",
        ).to_dict()

    argv = [
        "ufw",
        "delete",
        "allow",
        "from",
        ip,
        "to",
        "any",
        "port",
        str(port),
        "proto",
        "tcp",
    ]
    rule = " ".join(argv)
    if dry_run:
        return FirewallResult(
            provider="ufw", active=True, changed=False, port=port, rule=rule
        ).to_dict()

    checked = _run(argv)
    if checked is None:
        return FirewallResult(provider="ufw", active=True, changed=False,
                              port=port, rule=rule,
                              error="ufw did not run").to_dict()
    output = f"{checked.stdout} {checked.stderr}".lower()
    removed = checked.returncode == 0 and "could not delete" not in output
    return FirewallResult(
        provider="ufw", active=True, changed=removed, port=port, rule=rule
    ).to_dict()


__all__ = [
    "RELAY_PORT_BASE",
    "detect_traefik_ip",
    "ensure_relay_ingress",
    "remove_relay_ingress",
]
