from __future__ import annotations

import json
import stat

import pytest

from scripts import install_tenant_agents as mod


class FakeRun:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.active = False

    def __call__(self, argv, *, timeout=60, dry_run=False):
        self.calls.append(list(argv))
        if argv[:2] == ["docker", "inspect"]:
            return mod.Output(0, "\n")
        if argv[:2] == ["docker", "exec"]:
            return mod.Output(0, "0\n")
        if argv[:2] == ["systemctl", "is-active"]:
            return mod.Output(
                0 if self.active else 3, "active\n" if self.active else "inactive\n"
            )
        if argv[:2] == ["systemctl", "show"]:
            return mod.Output(0, "loaded\n")
        return mod.Output(0, "")


@pytest.fixture
def installer(tmp_path, monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(mod, "run", fake)
    monkeypatch.setattr(mod, "_user_exists", lambda uid: True)
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(mod, "wait_socket", lambda path, timeout=10.0: True)
    return mod.Installer(
        repo=mod.ROOT,
        data_root="/var/lib/spanel",
        app_container="spanel-app-1",
        traefik_uid=1000,
        traefik_ip="172.18.0.4",
        etc_dir=tmp_path / "etc",
        unit_dir=tmp_path / "units",
        runtime_dir=tmp_path / "run",
        tmpfiles_dir=tmp_path / "tmpfiles",
        python="/usr/bin/python3",
    ), fake


def test_inspect_reports_missing_units_and_sockets(installer) -> None:
    inst, _fake = installer
    payload = inst.inspect()
    assert payload["ok"] is True
    assert payload["app_uid"] == 0
    assert payload["traefik_uid"] == 1000
    assert payload["token"]["exists"] is False
    assert payload["units"][mod.PLAN_UNIT]["installed"] is False
    assert payload["units"][mod.RECONCILE_TIMER]["installed"] is False
    assert payload["sockets"]["plan_agent_exists"] is False


def test_render_reconcile_units_uses_repo_and_python(installer) -> None:
    _inst, _fake = installer
    service, timer = mod.render_reconcile_units(mod.ROOT, "/opt/spanel/host-venv/bin/python")
    assert "/opt/spanel/host-venv/bin/python" in service
    assert str(mod.ROOT / "scripts" / "install_tenant_agents.py") in service
    assert "<python>" not in service and "<repo>" not in service
    assert "OnBootSec=2min" in timer


def test_dry_run_does_not_write(installer) -> None:
    inst, _fake = installer
    payload = inst.install(dry_run=True, start=False)
    assert payload["ok"] is True
    assert payload["token"] == "would-create"
    assert not inst.token_path.exists()
    assert not (inst.unit_dir / mod.PLAN_UNIT).exists()


def test_install_creates_token_and_renders_units(installer) -> None:
    inst, _fake = installer
    payload = inst.install(start=False)
    assert payload["ok"] is True
    assert payload["token"] == "created"
    assert stat.S_IMODE(inst.token_path.stat().st_mode) == 0o600
    plan = (inst.unit_dir / mod.PLAN_UNIT).read_text()
    relay = (inst.unit_dir / mod.RELAY_UNIT).read_text()
    assert "ExecStart=/usr/bin/python3" in plan
    assert "spanel_tenant.py plan-agent --data-root /var/lib/spanel" in plan
    assert "Environment=SPANEL_PLAN_AGENT_ALLOWED_UIDS=0" in plan
    caps = (
        "CAP_SETUID CAP_SETGID CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE "
        "CAP_NET_ADMIN CAP_SYS_ADMIN CAP_MAC_ADMIN"
    )
    assert f"CapabilityBoundingSet={caps}" in plan
    assert f"AmbientCapabilities={caps}" in plan
    # A.SPEC 0118: provisioning needs AF_NETLINK (nft), /etc (groupadd) and
    # home dirs (cell XDG_RUNTIME_DIR); the plan-only sandbox broke all three.
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK" in plan
    assert "ProtectSystem=off" in plan
    assert "ProtectHome=false" in plan
    assert "User=1000" in relay
    # /run/spanel is managed by the tmpfiles.d entry owned by root:traefik-gid.
    # None of the units may declare RuntimeDirectory (systemd would chown it).
    assert "RuntimeDirectory=" not in plan
    assert "RuntimeDirectory=" not in relay
    assert "Environment=SPANEL_EDGE_RELAY_SOURCES=172.18.0.4" in relay
    reconcile = (inst.unit_dir / mod.RECONCILE_UNIT).read_text()
    timer = (inst.unit_dir / mod.RECONCILE_TIMER).read_text()
    assert "install_tenant_agents.py --force --json" in reconcile
    assert str(mod.ROOT) in reconcile
    assert "Unit=spanel-agents-reconcile.service" in timer
    assert "WantedBy=timers.target" in timer
    runtime = (inst.tmpfiles_path).read_text()
    assert "d /run/spanel 0770 root 1000 -" in runtime
    # The human renderer must accept both install and --check payloads.
    mod._print_human(payload)


def test_install_restarts_units_it_rewrote(installer) -> None:
    inst, fake = installer
    inst.install(start=True)
    assert ["systemctl", "restart", mod.PLAN_UNIT] in fake.calls
    assert ["systemctl", "restart", mod.RELAY_UNIT] in fake.calls
    assert ["systemctl", "enable", mod.RECONCILE_TIMER] in fake.calls
    assert ["systemctl", "restart", mod.RECONCILE_TIMER] in fake.calls
    assert any(call[:2] == ["systemctl", "daemon-reload"] for call in fake.calls)


def test_install_restarts_agents_when_only_code_changed(installer) -> None:
    """A Python-only deploy must not leave the old modules loaded."""
    inst, fake = installer
    # First install writes the units and the payload stamp.
    inst.install(start=True)
    assert (inst.etc_dir / mod.CODE_STAMP).read_text().strip() == (
        mod.agent_payload_digest(inst.repo)
    )
    fake.calls.clear()

    # Same units, same code: only start, never restart.
    inst.install(start=True)
    assert ["systemctl", "start", mod.PLAN_UNIT] in fake.calls
    assert ["systemctl", "restart", mod.PLAN_UNIT] not in fake.calls

    # Simulate a patched checkout: digest mismatch forces a restart.
    (inst.etc_dir / mod.CODE_STAMP).write_text("stale\n", encoding="utf-8")
    fake.calls.clear()
    payload = inst.install(start=True)
    assert payload["code"]["changed"] is True
    assert ["systemctl", "restart", mod.PLAN_UNIT] in fake.calls
    assert ["systemctl", "restart", mod.RELAY_UNIT] in fake.calls


def test_install_reports_the_inspection_error_instead_of_none(
    installer, monkeypatch
) -> None:
    inst, _fake = installer
    real_inspect = inst.inspect
    calls = {"n": 0}

    def flaky_inspect():
        calls["n"] += 1
        if calls["n"] == 1:
            return real_inspect()
        return {"ok": False, "error": "capacity check failed: denied"}

    monkeypatch.setattr(inst, "inspect", flaky_inspect)
    payload = inst.install(start=False)
    assert payload["ok"] is False
    assert payload["error"] == "capacity check failed: denied"


def test_install_never_rotates_an_existing_token(installer) -> None:
    inst, _fake = installer
    inst.etc_dir.mkdir(parents=True)
    inst.token_path.write_text("existing-secret\n", encoding="utf-8")
    inst.token_path.chmod(0o600)
    payload = inst.install(start=False)
    assert payload["token"] == "existing"
    assert inst.token_path.read_text(encoding="utf-8") == "existing-secret\n"


def test_install_refuses_to_replace_custom_unit_without_force(installer) -> None:
    inst, _fake = installer
    inst.unit_dir.mkdir(parents=True)
    path = inst.unit_dir / mod.PLAN_UNIT
    path.write_text("[Unit]\nDescription=custom\n", encoding="utf-8")
    with pytest.raises(mod.InstallError):
        inst.install(start=False)
    payload = inst.install(start=False, force=True)
    assert payload["ok"] is True
    assert "Description=Spanel host plan agent" in path.read_text()


def test_cli_json_check(installer, monkeypatch, capsys) -> None:
    inst, _fake = installer
    monkeypatch.setattr(
        mod,
        "Installer",
        lambda **_kwargs: inst,
    )
    code = mod.main(
        [
            "--check",
            "--json",
            "--etc-dir",
            str(inst.etc_dir),
            "--unit-dir",
            str(inst.unit_dir),
            "--runtime-dir",
            str(inst.runtime_dir),
            "--traefik-uid",
            "1000",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
