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
        etc_dir=tmp_path / "etc",
        unit_dir=tmp_path / "units",
        runtime_dir=tmp_path / "run",
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
    assert payload["sockets"]["plan_agent_exists"] is False


def test_dry_run_does_not_write(installer) -> None:
    inst, _fake = installer
    payload = inst.install(dry_run=True, start=False)
    assert payload["ok"] is True
    assert payload["token"] == "would-create"
    assert not inst.token_path.exists()
    assert not (inst.unit_dir / mod.PLAN_UNIT).exists()


def test_install_creates_token_and_renders_units(installer) -> None:
    inst, fake = installer
    payload = inst.install(start=False)
    assert payload["ok"] is True
    assert payload["token"] == "created"
    assert stat.S_IMODE(inst.token_path.stat().st_mode) == 0o600
    plan = (inst.unit_dir / mod.PLAN_UNIT).read_text()
    relay = (inst.unit_dir / mod.RELAY_UNIT).read_text()
    assert "ExecStart=/usr/bin/python3" in plan
    assert "spanel_tenant.py plan-agent --data-root /var/lib/spanel" in plan
    assert "Environment=SPANEL_PLAN_AGENT_ALLOWED_UIDS=0" in plan
    assert "User=1000" in relay
    assert any(call[:2] == ["systemctl", "daemon-reload"] for call in fake.calls)


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
