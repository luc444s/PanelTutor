"""Unit tests for the edge-relay host firewall helper."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tenant_cell import firewall


class FakeRun:
    def __init__(self, *, status: str = "Status: active", allow: str = "Rule added") -> None:
        self.status = status
        self.allow = allow
        self.calls: list[list[str]] = []

    def __call__(self, argv, *, timeout=30):
        self.calls.append(list(argv))
        if argv == ["ufw", "status"]:
            return subprocess.CompletedProcess(argv, 0, self.status, "")
        if argv[:2] == ["ufw", "allow"] or argv[:2] == ["ufw", "delete"]:
            return subprocess.CompletedProcess(argv, 0, self.allow, "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "172.18.0.4\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")


def _ready(monkeypatch, **kwargs):
    fake = FakeRun(**kwargs)
    monkeypatch.setattr(firewall, "_run", fake)
    monkeypatch.setattr(firewall.shutil, "which", lambda name: "/usr/sbin/ufw")
    monkeypatch.setattr(firewall.os, "geteuid", lambda: 0)
    return fake


def test_opens_the_cell_relay_port_from_traefik(monkeypatch) -> None:
    fake = _ready(monkeypatch)
    result = firewall.ensure_relay_ingress(1, traefik_ip="172.18.0.4")
    assert result["active"] is True
    assert result["changed"] is True
    assert result["port"] == 40001
    assert fake.calls[-1] == [
        "ufw",
        "allow",
        "from",
        "172.18.0.4",
        "to",
        "any",
        "port",
        "40001",
        "proto",
        "tcp",
    ]


def test_existing_rule_is_reported_as_unchanged(monkeypatch) -> None:
    _ready(monkeypatch, allow="Skipping adding existing rule")
    result = firewall.ensure_relay_ingress(1, traefik_ip="172.18.0.4")
    assert result["changed"] is False
    assert result["active"] is True


def test_inactive_ufw_is_skipped(monkeypatch) -> None:
    fake = _ready(monkeypatch, status="Status: inactive")
    result = firewall.ensure_relay_ingress(1, traefik_ip="172.18.0.4")
    assert result["active"] is False
    assert "not active" in result["reason"]
    assert not any(call[:2] == ["ufw", "allow"] for call in fake.calls)


def test_missing_root_is_skipped(monkeypatch) -> None:
    _ready(monkeypatch)
    monkeypatch.setattr(firewall.os, "geteuid", lambda: 1000)
    result = firewall.ensure_relay_ingress(1, traefik_ip="172.18.0.4")
    assert result["active"] is False
    assert "root" in result["reason"]


def test_dry_run_does_not_mutate(monkeypatch) -> None:
    fake = _ready(monkeypatch)
    result = firewall.ensure_relay_ingress(1, traefik_ip="172.18.0.4", dry_run=True)
    assert result["rule"].startswith("ufw allow from 172.18.0.4")
    assert not any(call[:2] == ["ufw", "allow"] for call in fake.calls)


def test_removes_the_per_cell_rule(monkeypatch) -> None:
    fake = _ready(monkeypatch, allow="Rule deleted")
    result = firewall.remove_relay_ingress(1, traefik_ip="172.18.0.4")
    assert result["changed"] is True
    assert fake.calls[-1][:3] == ["ufw", "delete", "allow"]
