"""Simulated cgroups-v2 and CLI probe tests for A.SPEC 0108."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tenant_cell import alloc, cli, materializer, plans


def test_reads_effective_cgroups_v2_files(tmp_path: Path) -> None:
    (tmp_path / "memory.max").write_text("268435456\n", encoding="utf-8")
    (tmp_path / "cpu.max").write_text("50000 100000\n", encoding="utf-8")
    (tmp_path / "pids.max").write_text("128\n", encoding="utf-8")
    assert plans.read_cgroup_limits(tmp_path) == {
        "memory_max": "268435456",
        "cpu_max": "50000 100000",
        "pids_max": "128",
    }


def test_user_manager_cgroup_path_stays_in_default_slice() -> None:
    path = plans.user_manager_cgroup_path(60004)
    assert path.endswith("/user.slice/user-60004.slice/user@60004.service")
    assert "tenant-" not in path


def test_materializer_probe_and_verify_remain_callable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(plans.MUTATION_GATE, "1")
    alloc.allocate(tmp_path, "acme")
    alloc.update_allocation(tmp_path, "acme", state="ready", cgroup_driver="systemd")
    plans.save_plans(tmp_path, {
        "version": plans.PLAN_VERSION,
        "plans": {
            "acme": {
                "slug": "acme",
                "uid": 60000,
                "plan": {"memory": "256M", "cpus": 0.5, "pids": 128},
            }
        },
    })

    class Executor:
        def run_plan_probe(self, slug, uid, plan, memory_mb=64, seconds=3):
            return {"ok": True, "slice": f"user-{uid}.slice", "owner_uid": str(uid)}

    service = materializer.PlanMaterializer(Executor(), tmp_path, probe=object())

    assert callable(service.probe)
    assert callable(service.verify)
    assert service.probe("acme")["ok"] is True
    assert service.verify("acme")["ok"] is True


class ProbeService:
    def __init__(self, ok: bool) -> None:
        self.ok = ok

    def probe(self, slug: str, *, memory_mb: int, seconds: int):
        return {
            "slug": slug,
            "ok": self.ok,
            "slice": "user-60000.slice",
            "owner_uid": "60000",
            "memory_max": "268435456",
            "cpu_max": "50000 100000",
            "pids_max": "128",
            "eperm": False,
            "memory_mb": memory_mb,
            "seconds": seconds,
        }


def test_probe_cli_reports_measurements_and_success(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_plan_service", lambda _root: ProbeService(True))
    result = CliRunner().invoke(cli.app, [
        "plan", "probe", "--slug", "acme", "--memory-mb", "32",
        "--seconds", "2", "--json",
    ])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["owner_uid"] == "60000"
    assert payload["eperm"] is False


def test_probe_cli_exits_one_on_failed_evidence(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_plan_service", lambda _root: ProbeService(False))
    result = CliRunner().invoke(cli.app, [
        "plan", "probe", "--slug", "acme", "--json",
    ])
    assert result.exit_code == 1
    assert json.loads(result.output)["ok"] is False


def _probe_state(**overrides):
    state = {"slice": plans.user_slice(60000), "owner_uid": "60000"}
    state.update(overrides)
    return state


def _probe_evidence(**overrides):
    evidence = {
        "expected": plans.expected_probe_limits(
            {"memory": "256M", "cpus": 0.5, "pids": 128}
        ),
        "memory_max": "268435456",
        "cpu_max": "50000 100000",
        "pids_max": "128",
        "cpu_delta_usec": 1_000_000,
        "eperm": False,
    }
    evidence.update(overrides)
    return evidence


def test_probe_mismatches_is_empty_when_every_check_matches() -> None:
    assert plans.probe_mismatches(
        60000, _probe_state(), _probe_evidence()
    ) == []


def test_probe_mismatches_names_the_legacy_slice_and_values() -> None:
    problems = plans.probe_mismatches(
        60000,
        _probe_state(slice="tenant-demo.slice"),
        _probe_evidence(memory_max="536870912", cpu_delta_usec=0),
    )
    joined = "; ".join(problems)
    assert "slice differs" in joined
    assert "tenant-demo.slice" in joined
    assert "memory_max differs" in joined
    assert "cpu accounting" in joined


def test_probe_mismatches_reports_owner_and_eperm() -> None:
    problems = plans.probe_mismatches(
        60000,
        _probe_state(owner_uid=""),
        _probe_evidence(eperm=True),
    )
    joined = "; ".join(problems)
    assert "OwnerUID differs" in joined
    assert "EPERM" in joined

