"""Unit tests for tenant resource plans (A.SPEC 0100).

A fake Executor records every host mutation: no test creates a slice, writes a
drop-in, restarts a user manager, or probes a real cgroup.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tenant_cell import alloc, audit, cli, plans
from scripts.tenant_cell.executor import Executor

GATE = "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS"
OK_EVIDENCE = {
    "ok": True,
    "cpu_delta_usec": 1_500_000,
    "memory_max": "536870912",
    "cpu_max": "50000 100000",
    "pids_max": "128",
}


@pytest.fixture(autouse=True)
def _gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(GATE, "1")


class FakePlanExecutor(Executor):
    """Records plan host mutations and returns canned kernel evidence."""

    def __init__(self, evidence: dict[str, Any] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.evidence = dict(evidence or OK_EVIDENCE)

    def _rec(self, action: str, **kwargs: object) -> None:
        self.calls.append((action, dict(kwargs)))

    def install_tenant_slice(self, slug, plan):
        self._rec("install_tenant_slice", slug=slug, plan=plan)

    def remove_tenant_slice(self, slug):
        self._rec("remove_tenant_slice", slug=slug)

    def install_user_manager_dropin(self, slug, uid):
        self._rec("install_user_manager_dropin", slug=slug, uid=uid)

    def remove_user_manager_dropin(self, slug, uid):
        self._rec("remove_user_manager_dropin", slug=slug, uid=uid)

    def restart_user_manager(self, uid):
        self._rec("restart_user_manager", uid=uid)

    def run_plan_probe(self, slug, uid, plan):
        self._rec("run_plan_probe", slug=slug, uid=uid, plan=plan)
        return dict(self.evidence)

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


def _cell(
    tmp_path: Path, slug: str = "acme", driver: str = "systemd"
) -> dict[str, Any]:
    alloc.allocate(str(tmp_path), slug)
    alloc.update_allocation(
        str(tmp_path), slug, state="ready", cgroup_driver=driver
    )
    return alloc.load_registry(str(tmp_path))["allocations"][slug]


def _service(
    tmp_path: Path, evidence: dict[str, Any] | None = None
) -> tuple[plans.PlanService, FakePlanExecutor]:
    executor = FakePlanExecutor(evidence)
    return plans.PlanService(executor, tmp_path), executor


def test_validate_plan_rejects_nonpositive_values_before_any_write(tmp_path) -> None:
    svc, executor = _service(tmp_path)

    bad_plans = [
        (0, 0.5, 128),
        ("512M", 0, 128),
        ("512M", -1, 128),
        ("512M", 0.5, 0),
        ("512M", 0.5, -3),
        ("0M", 0.5, 128),
        ("", 0.5, 128),
        ("512M", 0.5, 1.5),
        (True, 0.5, 128),
    ]
    for memory, cpus, pids in bad_plans:
        with pytest.raises(plans.InvalidPlan):
            svc.set("acme", memory, cpus, pids)

    assert executor.calls == []
    assert not plans.plans_path(tmp_path).exists()
    assert not (tmp_path / "registry.json").exists()


def test_set_installs_slice_dropin_and_persists_plan_atomically(tmp_path) -> None:
    _cell(tmp_path)
    svc, executor = _service(tmp_path)

    result = svc.set("acme", "512M", 0.5, 128)

    assert executor.names() == [
        "install_tenant_slice",
        "install_user_manager_dropin",
        "restart_user_manager",
    ]
    assert result["slug"] == "acme"
    assert result["slice"] == "tenant-acme.slice"
    assert result["cgroup_path"] == "/tenant.slice/tenant-acme.slice"
    assert result["plan"] == {"memory": "512M", "cpus": 0.5, "pids": 128}
    assert result["dropin"] == (
        "/etc/systemd/system/user@60000.service.d/tenant-plan.conf"
    )

    slice_kw = next(kw for name, kw in executor.calls if name == "install_tenant_slice")
    rendered = plans.render_slice("acme", slice_kw["plan"])
    assert "MemoryMax=512M" in rendered
    assert "CPUQuota=50%" in rendered
    assert "TasksMax=128" in rendered
    dropin_kw = next(
        kw for name, kw in executor.calls if name == "install_user_manager_dropin"
    )
    assert dropin_kw["uid"] == 60000
    assert plans.render_dropin("acme") == "[Service]\nSlice=tenant-acme.slice\n"

    path = plans.plans_path(tmp_path)
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["version"] == plans.PLAN_VERSION
    assert stored["plans"]["acme"]["plan"]["pids"] == 128
    assert not path.with_name("plans.json.tmp").exists()  # atomic replace

    record = audit.read_audit(tmp_path)[-1]
    assert record["verb"] == "plan_set"
    assert record["exit_code"] == 0


def test_set_requires_the_local_mutation_gate(tmp_path, monkeypatch) -> None:
    _cell(tmp_path)
    monkeypatch.delenv(GATE)
    svc, executor = _service(tmp_path)

    with pytest.raises(plans.MutationDisabled):
        svc.set("acme", "512M", 0.5, 128)

    assert executor.calls == []
    assert not plans.plans_path(tmp_path).exists()


def test_set_rejects_missing_cell_and_legacy_driver_without_writes(tmp_path) -> None:
    svc, executor = _service(tmp_path)

    with pytest.raises(plans.PlanCellMissing):
        svc.set("ghost", "512M", 0.5, 128)

    _cell(tmp_path, driver="cgroupfs")
    with pytest.raises(plans.PlanDriverError):
        svc.set("acme", "512M", 0.5, 128)

    assert executor.calls == []
    assert not plans.plans_path(tmp_path).exists()
    assert audit.read_audit(tmp_path) == []


def test_show_returns_saved_plan_and_effective_slice(tmp_path) -> None:
    _cell(tmp_path)
    svc, executor = _service(tmp_path)
    svc.set("acme", "1G", 1.25, 256)
    executor.calls.clear()

    shown = svc.show("acme")

    assert shown["plan"] == {"memory": "1G", "cpus": 1.25, "pids": 256}
    assert shown["slice"] == "tenant-acme.slice"
    assert shown["cgroup_path"] == "/tenant.slice/tenant-acme.slice"
    assert shown["uid"] == 60000
    assert executor.calls == []  # show never touches the host


def test_plan_operations_on_one_tenant_leave_others_untouched(tmp_path) -> None:
    _cell(tmp_path, "acme")
    _cell(tmp_path, "beta")
    svc, executor = _service(tmp_path)

    svc.set("acme", "512M", 0.5, 128)
    svc.set("beta", "256M", 1, 64)
    before_remove_calls = len(executor.calls)
    registry_before = json.loads((tmp_path / "registry.json").read_text(encoding="utf-8"))

    svc.remove("acme")

    suffix = executor.calls[before_remove_calls:]
    assert all(kw.get("slug") != "beta" for _, kw in suffix)
    assert all(kw.get("uid") != 60001 for _, kw in suffix)
    registry_after = json.loads((tmp_path / "registry.json").read_text(encoding="utf-8"))
    assert registry_after["allocations"] == registry_before["allocations"]
    stored = plans.load_plans(tmp_path)["plans"]
    assert "acme" not in stored
    assert stored["beta"]["plan"] == {"memory": "256M", "cpus": 1.0, "pids": 64}


def test_remove_restores_default_user_slice_and_deletes_plan(tmp_path) -> None:
    _cell(tmp_path)
    svc, executor = _service(tmp_path)
    svc.set("acme", "512M", 0.5, 128)
    executor.calls.clear()

    result = svc.remove("acme")

    assert executor.names() == [
        "remove_user_manager_dropin",
        "remove_tenant_slice",
        "restart_user_manager",
    ]
    assert result == {
        "slug": "acme",
        "removed": True,
        "restored_slice": "user-60000.slice",
    }
    assert plans.load_plans(tmp_path)["plans"] == {}
    record = audit.read_audit(tmp_path)[-1]
    assert record["verb"] == "plan_remove"
    assert record["restored_slice"] == "user-60000.slice"


def test_remove_without_a_plan_is_refused(tmp_path) -> None:
    svc, executor = _service(tmp_path)
    with pytest.raises(plans.PlanNotFound):
        svc.remove("acme")
    assert executor.calls == []


@pytest.mark.parametrize("ok", [True, False])
def test_verify_reports_kernel_evidence_from_both_sides(tmp_path, ok: bool) -> None:
    _cell(tmp_path)
    evidence = dict(OK_EVIDENCE)
    evidence["ok"] = ok
    if not ok:
        evidence["error"] = "kernel did not apply the limits"
    svc, executor = _service(tmp_path, evidence)
    svc.set("acme", "512M", 0.5, 128)
    executor.calls.clear()

    result = svc.verify("acme")

    assert result["ok"] is ok
    assert result["evidence"]["ok"] is ok
    assert result["cgroup_path"] == "/tenant.slice/tenant-acme.slice"
    assert "run_plan_probe" in executor.names()
    record = audit.read_audit(tmp_path)[-1]
    assert record["verb"] == "plan_verify"
    assert record["exit_code"] == (0 if ok else 1)


def test_render_paths_limits_and_slug_validation() -> None:
    assert plans.slice_name("acme") == "tenant-acme.slice"
    assert plans.slice_cgroup_path("acme") == "/tenant.slice/tenant-acme.slice"
    assert plans.user_slice(60008) == "user-60008.slice"
    assert plans.dropin_path(60000) == (
        "/etc/systemd/system/user@60000.service.d/tenant-plan.conf"
    )
    assert plans.cpu_quota(2) == "200%"
    assert plans.cpu_quota(1.25) == "125%"
    assert plans.expected_probe_limits(
        {"memory": "512M", "cpus": 0.5, "pids": 128}
    ) == {
        "memory_max": "536870912",
        "cpu_max": "50000 100000",
        "pids_max": "128",
    }
    with pytest.raises(alloc.InvalidSlug):
        plans.slice_name("acme\n  deny /etc/** rw,")


def test_cli_plan_help_lists_all_subcommands() -> None:
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(cli.app, ["plan", "--help"])
    assert result.exit_code == 0, result.output
    for subcommand in ("set", "show", "remove", "verify"):
        assert subcommand in result.output

    set_help = runner.invoke(cli.app, ["plan", "set", "--help"])
    assert set_help.exit_code == 0, set_help.output
    for option in ("--memory", "--cpus", "--pids"):
        assert option in set_help.output


def test_cli_set_and_show_use_the_injected_plan_service(tmp_path, monkeypatch) -> None:
    from typer.testing import CliRunner

    _cell(tmp_path)
    svc, _ = _service(tmp_path)
    monkeypatch.setattr(cli, "_plan_service", lambda data_root: svc)
    runner = CliRunner()

    set_result = runner.invoke(
        cli.app,
        [
            "plan", "set", "--slug", "acme", "--memory", "512M",
            "--cpus", "0.5", "--pids", "128", "--json", "--data-root", str(tmp_path),
        ],
    )
    assert set_result.exit_code == 0, set_result.output
    assert json.loads(set_result.output)["slice"] == "tenant-acme.slice"

    show_result = runner.invoke(
        cli.app, ["plan", "show", "--slug", "acme", "--json"]
    )
    assert show_result.exit_code == 0, show_result.output
    assert json.loads(show_result.output)["plan"]["pids"] == 128
