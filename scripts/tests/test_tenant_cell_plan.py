"""A.SPEC 0108: plans apply to the existing user manager in place."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tenant_cell import alloc, cli, materializer, plans


@pytest.fixture(autouse=True)
def gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(plans.MUTATION_GATE, "1")


class FakeExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.effective = {"memory_max": "", "cpu_max": "", "pids_max": ""}

    def read_plan_state(self, uid: int) -> dict[str, Any]:
        self.calls.append(("read", uid))
        return {
            "slice": f"user-{uid}.slice",
            "properties": {"MemoryMax": self.effective["memory_max"]},
            "effective": dict(self.effective),
            "owner_uid": str(uid),
            "cgroup_path": f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service",
        }

    def apply_plan_in_place(self, uid: int, plan: dict[str, Any]) -> None:
        self.calls.append(("set-property", plans.set_property_args(uid, plan)))
        self.effective = plans.expected_probe_limits(plan)

    def reset_plan_properties(self, uid: int) -> None:
        self.calls.append(("revert", plans.reset_property_args(uid)))

    def run_plan_probe(self, slug, uid, plan, memory_mb=64, seconds=3):
        self.calls.append(("probe", (slug, uid, memory_mb, seconds)))
        return {
            "ok": True,
            "slice": f"user-{uid}.slice",
            "owner_uid": str(uid),
            "properties": {},
            "cgroup_path": f"/user.slice/user-{uid}.slice/user@{uid}.service",
            **plans.expected_probe_limits(plan),
        }


def cell(tmp_path: Path) -> None:
    alloc.allocate(tmp_path, "acme")
    alloc.update_allocation(tmp_path, "acme", state="ready", cgroup_driver="systemd")


def service(tmp_path: Path) -> tuple[materializer.PlanMaterializer, FakeExecutor]:
    executor = FakeExecutor()
    return materializer.PlanMaterializer(executor, tmp_path), executor


def test_set_property_render_and_plan_keys_are_stable() -> None:
    assert plans.PLAN_KEYS == {"memory", "cpus", "pids", "cpuset"}
    assert plans.set_property_args(
        60000, {"memory": "512M", "cpus": 0.5, "pids": 128}
    ) == [
        "systemctl", "set-property", "user@60000.service",
        "MemoryMax=512M", "CPUQuota=50%", "TasksMax=128",
    ]


def test_apply_is_in_place_idempotent_and_reports_owner(tmp_path: Path) -> None:
    cell(tmp_path)
    svc, executor = service(tmp_path)
    first = svc.apply("acme", "512M", 0.5, 128)
    second = svc.apply("acme", "512M", 0.5, 128)

    mutations = [call for call in executor.calls if call[0] == "set-property"]
    assert len(mutations) == 1
    assert first["slice"] == second["slice"] == "user-60000.slice"
    assert first["owner_uid"] == "60000"
    assert not any("tenant-acme.slice" in json.dumps(call) for call in executor.calls)


def test_remove_uses_systemctl_revert(tmp_path: Path) -> None:
    cell(tmp_path)
    svc, executor = service(tmp_path)
    svc.apply("acme", "256M", 1, 64)
    executor.calls.clear()
    result = svc.remove("acme")
    assert executor.calls == [(
        "revert",
        ["systemctl", "revert", "user@60000.service"],
    )]
    assert result["restored_slice"] == "user-60000.slice"


def test_plan_apply_dry_run_never_calls_materializer_or_writes(tmp_path: Path, monkeypatch) -> None:
    cell(tmp_path)
    registry_before = (tmp_path / "registry.json").read_bytes()
    monkeypatch.setattr(cli, "_plan_service", lambda _root: pytest.fail("must not build service"))
    result = CliRunner().invoke(cli.app, [
        "plan", "apply", "--slug", "acme", "--memory", "256M",
        "--cpus", "0.5", "--pids", "128", "--dry-run", "--json",
        "--data-root", str(tmp_path),
    ])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["mutation"] is False
    assert payload["slice"] == "user-60000.slice"
    assert (tmp_path / "registry.json").read_bytes() == registry_before
    assert not plans.plans_path(tmp_path).exists()


def test_provision_dry_run_is_a_blueprint_without_registry_write(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cli, "_service", lambda _root: pytest.fail("must not provision"))
    result = CliRunner().invoke(cli.app, [
        "provision", "--slug", "acme", "--dry-run", "--json",
        "--data-root", str(tmp_path),
    ])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["uid"] == 60000
    assert payload["mutation"] is False
    assert payload["slice"] == "user-60000.slice"
    assert not (tmp_path / "registry.json").exists()


def test_mutation_gate_blocks_apply(tmp_path: Path, monkeypatch) -> None:
    cell(tmp_path)
    monkeypatch.delenv(plans.MUTATION_GATE)
    svc, executor = service(tmp_path)
    with pytest.raises(plans.MutationDisabled):
        svc.apply("acme", "512M", 1, 64)
    assert executor.calls == []
