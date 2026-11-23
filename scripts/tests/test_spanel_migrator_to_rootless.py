from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import spanel_migrator_to_rootless as mod


class RecordingConsole(mod.Console):
    def __init__(self, *, interactive: bool = False) -> None:
        super().__init__(json_mode=False, interactive=interactive)
        self.lines: list[str] = []

    def step(self, message: str) -> None:
        self.lines.append(message)

    def info(self, message: str) -> None:
        self.lines.append(message)

    def ok(self, message: str) -> None:
        self.lines.append(message)

    def warn(self, message: str) -> None:
        self.lines.append(message)

    def fail(self, message: str) -> None:
        self.lines.append(message)


class FakeOperator:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.site_plans: list[dict] = [
            {
                "ok": True,
                "site_id": "s1",
                "kind": "static",
                "from_runtime": "rootful",
                "to_runtime": "rootless",
                "state": "planned",
                "inventory": {"domain": "example.test"},
            }
        ]
        self.migrate_result: dict = {
            "ok": True,
            "site_id": "s1",
            "operation_id": "op-1",
            "state": "retained",
            "rollback_available": True,
        }
        self.finalize_result: dict = {"ok": True, "state": "finalized"}
        self.rollback_result: dict = {"ok": True, "state": "rolled_back"}
        self.plan_apply_result: dict = {"ok": True}
        self.plan_verify_result: dict = {"ok": True}
        self.doctor_result: dict = {"ok": True, "ready": True}
        self.provision_result: dict = {"ok": True, "state": "ready"}
        self.services_active = True
        self.mode = "local"

    def capacity(self):
        return {
            "memory_bytes": 8 * 1024**3,
            "cpus": 4.0,
            "storage_bytes": 100 * 1024**3,
            "storage_available_bytes": 50 * 1024**3,
        }

    def tenant(self, *args, timeout=120):
        self.calls.append(("tenant", args))
        if args and args[0] == "doctor":
            return self.doctor_result
        if args[:2] == ("plan", "show"):
            return {"ok": True, "plan": {"memory": "512M", "cpus": 1.0, "pids": 256}}
        raise AssertionError(f"unexpected tenant call: {args}")

    def provision(self, slug, *, dry_run=False, timeout=240.0, sleep=None):
        self.calls.append(("provision", slug, dry_run))
        return self.provision_result

    def plan_apply(self, slug, *, memory, cpus, pids, dry_run=False):
        self.calls.append(("plan_apply", slug, memory, cpus, pids, dry_run))
        return self.plan_apply_result

    def plan_verify(self, slug):
        self.calls.append(("plan_verify", slug))
        return self.plan_verify_result

    def plan_show(self, slug):
        self.calls.append(("plan_show", slug))
        return {"ok": True, "plan": {"memory": "512M", "cpus": 1.0, "pids": 256}}

    def hosting_sites(self, tenant, kinds, site_ids=()):
        self.calls.append(("hosting_sites", tenant, kinds, site_ids))
        return list(self.site_plans)

    def hosting_migrate(self, site_id):
        self.calls.append(("hosting_migrate", site_id))
        return dict(self.migrate_result)

    def hosting_finalize(self, site_id, operation_id, domain):
        self.calls.append(("hosting_finalize", site_id, operation_id, domain))
        return dict(self.finalize_result)

    def hosting_rollback(self, site_id, operation_id):
        self.calls.append(("hosting_rollback", site_id, operation_id))
        return dict(self.rollback_result)

    def hosting_status(self, site_id):
        self.calls.append(("hosting_status", site_id))
        return {"ok": True, "site_id": site_id, "state": "retained"}

    def install_agents(self, *, traefik_uid=None, dry_run=False):
        self.calls.append(("install_agents", traefik_uid, dry_run))
        return {"ok": True}

    def migrate_apps(
        self,
        tenant,
        *,
        api_url,
        token_file,
        env_file=None,
        app_ids=(),
        timeout=1800,
        verify_cell=True,
        dry_run=False,
    ):
        self.calls.append(("migrate_apps", tenant, app_ids, dry_run))
        return {"ok": True, "results": []}

    def service_active(self, unit):
        return self.services_active

    def unit_loaded(self, unit):
        return True

    def start_service(self, unit):
        self.calls.append(("start_service", unit))

    def socket_exists(self, path):
        return True

    def hosting_mode_effective(self):
        return self.mode

    def allocation(self, slug):
        return {"slug": slug, "index": 1}

    def ufw_active(self):
        return False


def make_plan(**overrides) -> mod.MigrationPlan:
    base = {
        "tenant": "demo",
        "memory": "1G",
        "cpus": 1.0,
        "pids": 256,
        "storage": "10G",
        "storage_bytes": 10 * 1024**3,
    }
    base.update(overrides)
    return mod.MigrationPlan(**base)


def make_migrator(tmp_path, ops=None, plan=None, interactive=False):
    ops = ops or FakeOperator()
    console = RecordingConsole(interactive=interactive)
    journal = mod.Journal(
        path=tmp_path / "state.json",
        payload={"tool": "test"},
    )
    migrator = mod.Migrator(
        plan or make_plan(),
        ops,
        console,
        journal,
        sleep=lambda _seconds: None,
    )
    return migrator, ops, console, journal


@pytest.fixture(autouse=True)
def allow_preflight(monkeypatch):
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(mod.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(mod, "AGENT_SOCKET", _AlwaysExists())
    monkeypatch.setattr(mod, "RELAY_SOCKET", _AlwaysExists())


def test_parse_size_accepts_systemd_and_binary_units() -> None:
    assert mod.parse_size("512M", what="memory") == 512 * 1024**2
    assert mod.parse_size("1.5G", what="memory") == int(1.5 * 1024**3)
    assert mod.parse_size("2GiB", what="memory") == 2 * 1024**3
    assert mod.parse_size(4096, what="memory") == 4096
    with pytest.raises(mod.UsageError):
        mod.parse_size("0G", what="memory")
    with pytest.raises(mod.UsageError):
        mod.parse_size("nope", what="memory")


def test_happy_path_orders_phases_and_finalizes(tmp_path) -> None:
    migrator, ops, _console, journal = make_migrator(
        tmp_path, plan=make_plan(finalize=True)
    )
    payload = migrator.run()
    assert payload["ok"] is True
    actions = [call[0] for call in ops.calls]
    assert actions[:6] == [
        "tenant",
        "install_agents",
        "provision",
        "plan_apply",
        "plan_verify",
        "hosting_sites",
    ]
    assert "hosting_finalize" in actions
    assert "hosting_status" in actions
    assert journal.path.is_file()
    assert json.loads(journal.path.read_text())["ok"] is True


def test_site_plan_skips_already_rootless(tmp_path) -> None:
    ops = FakeOperator()
    ops.site_plans = [
        {
            "ok": False,
            "site_id": "old",
            "from_runtime": "rootless",
            "state": "retained",
        }
    ]
    migrator, _ops, _console, _journal = make_migrator(tmp_path, ops=ops)
    migrator.preflight()
    migrator.provision()
    migrator.apply_plan()
    sites = migrator.plan_sites()
    assert sites == []
    assert ops.site_plans[0]["site_id"] in {row["site_id"] for row in migrator.skipped}


def test_migration_failure_stops_and_keeps_previous_sites(tmp_path) -> None:
    ops = FakeOperator()
    ops.migrate_result = {"ok": False, "site_id": "s1", "error": "boom"}
    migrator, _ops, _console, journal = make_migrator(tmp_path, ops=ops)
    with pytest.raises(mod.MigratorError):
        migrator.run()
    assert not any(call[0] == "hosting_finalize" for call in ops.calls)
    assert journal.events
    assert journal.events[-1]["phase"] == "report" or any(
        event["action"] == "migrate" and event["ok"] is False
        for event in journal.events
    )


def test_rollback_on_failure_rolls_back_migrated_sites(tmp_path) -> None:
    ops = FakeOperator()
    ops.site_plans = [
        {
            "ok": True,
            "site_id": "s1",
            "kind": "static",
            "from_runtime": "rootful",
            "inventory": {"domain": "a.test"},
        },
        {
            "ok": True,
            "site_id": "s2",
            "kind": "wordpress",
            "from_runtime": "rootful",
            "inventory": {"domain": "b.test"},
        },
    ]
    first = {
        "ok": True,
        "site_id": "s1",
        "operation_id": "op-1",
        "state": "retained",
    }
    second = {"ok": False, "site_id": "s2", "error": "boom"}
    results = {("hosting_migrate", "s1"): first, ("hosting_migrate", "s2"): second}
    original = ops.hosting_migrate

    def migrate(site_id):
        ops.calls.append(("hosting_migrate", site_id))
        return dict(results[("hosting_migrate", site_id)])

    ops.hosting_migrate = migrate  # type: ignore[method-assign]
    migrator, _ops, _console, _journal = make_migrator(
        tmp_path, ops=ops, plan=make_plan(rollback_on_failure=True)
    )
    with pytest.raises(mod.MigratorError):
        migrator.run()
    assert ("hosting_rollback", "s1", "op-1") in ops.calls
    del original


def test_dry_run_does_not_migrate_or_finalize(tmp_path) -> None:
    migrator, ops, _console, _journal = make_migrator(
        tmp_path, plan=make_plan(dry_run=True, finalize=True)
    )
    payload = migrator.run()
    assert payload["ok"] is True
    assert not any(call[0] == "hosting_migrate" for call in ops.calls)
    assert not any(call[0] == "hosting_finalize" for call in ops.calls)


def test_apps_phase_runs_and_can_fail_the_run(tmp_path) -> None:
    token = tmp_path / "token"
    token.write_text("secret\n", encoding="utf-8")
    plan = make_plan(
        migrate_apps=True,
        apps_api_url="https://panel.test",
        apps_token_file=token,
        apps_ids=("app-1",),
    )
    migrator, ops, _console, _journal = make_migrator(tmp_path, plan=plan)
    payload = migrator.run()
    assert payload["ok"] is True
    assert ("migrate_apps", "demo", ("app-1",), False) in ops.calls
    assert payload["apps"] == {"ok": True, "results": []}

    failing = FakeOperator()
    failing.migrate_apps = lambda *args, **kwargs: {"ok": False, "results": []}
    migrator, _ops, _console, _journal = make_migrator(tmp_path, ops=failing, plan=plan)
    payload = migrator.run()
    assert payload["ok"] is False


def test_plan_verify_failure_aborts_before_sites(tmp_path) -> None:
    ops = FakeOperator()
    ops.plan_verify_result = {"ok": False, "error": "not enforced"}
    migrator, _ops, _console, _journal = make_migrator(tmp_path, ops=ops)
    with pytest.raises(mod.MigratorError):
        migrator.run()
    assert not any(call[0] == "hosting_migrate" for call in ops.calls)


def test_build_plan_requires_values_in_non_interactive_mode() -> None:
    args = mod._parser().parse_args(["--non-interactive", "--tenant", "demo"])
    console = RecordingConsole(interactive=False)
    ops = FakeOperator()
    with pytest.raises(mod.UsageError):
        mod.build_plan(args, ops, console)


def test_build_plan_rejects_invalid_tenant() -> None:
    args = mod._parser().parse_args(
        [
            "--non-interactive",
            "--tenant",
            "Bad Slug",
            "--memory",
            "1G",
            "--cpus",
            "1",
            "--pids",
            "128",
        ]
    )
    with pytest.raises(mod.UsageError):
        mod.build_plan(args, FakeOperator(), RecordingConsole())


def test_operator_container_mode_copies_and_execs(monkeypatch, tmp_path) -> None:
    calls: list[list[str]] = []

    def runner(argv, env, timeout):
        calls.append(argv)
        if argv[:2] == ["docker", "inspect"]:
            return mod.CommandOutput(0, "true\n")
        return mod.CommandOutput(0, '{"ok": true, "results": []}\n')

    ops = mod.Operator(root=tmp_path, runner=runner, hosting_mode="container")
    monkeypatch.setattr(ops, "_container_running", lambda: True)
    payload = ops.hosting("plan", "--tenant", "demo", "--all")
    assert payload["ok"] is True
    assert any(call[:2] == ["docker", "cp"] for call in calls)
    final = calls[-1]
    assert final[0] == "docker" and final[1] == "exec"
    assert "spanel-app-1" in final
    assert final[-1] == "--json"


def test_operator_local_mode_uses_host_script(tmp_path) -> None:
    calls: list[list[str]] = []

    def runner(argv, env, timeout):
        calls.append(argv)
        return mod.CommandOutput(0, '{"ok": true}\n')

    ops = mod.Operator(root=tmp_path, runner=runner, hosting_mode="local")
    ops.hosting("status", "--site", "s1")
    assert calls[-1][0] == ops.python
    assert str(tmp_path / "scripts" / "hosting_migrate_rootless.py") == calls[-1][1]
    assert env_gate(ops) == "1"


def env_gate(ops: mod.Operator) -> str:
    return ops._env()["SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS"]


def test_operator_provision_retries_until_ready(monkeypatch, tmp_path) -> None:
    responses = iter(
        [
            {"ok": True, "state": "degraded"},
            {"ok": True, "state": "ready"},
        ]
    )
    calls: list[tuple] = []

    def runner(argv, env, timeout):
        calls.append(tuple(argv))
        return mod.CommandOutput(0, json.dumps(next(responses)) + "\n")

    ops = mod.Operator(root=tmp_path, runner=runner, hosting_mode="local")
    monkeypatch.setattr(ops, "cell_socket", lambda slug: _AlwaysExists())
    payload = ops.provision("demo", sleep=lambda _seconds: None)
    assert payload["state"] == "ready"
    assert len(calls) == 2


class _AlwaysExists:
    def exists(self) -> bool:
        return True


def test_main_json_dry_run(monkeypatch, tmp_path, capsys) -> None:
    fake = FakeOperator()
    monkeypatch.setattr(mod, "Operator", lambda **_kwargs: fake)
    code = mod.main(
        [
            "--non-interactive",
            "--dry-run",
            "--json",
            "--skip-service-check",
            "--tenant",
            "demo",
            "--memory",
            "1G",
            "--cpus",
            "1",
            "--pids",
            "128",
            "--storage",
            "1G",
            "--state-file",
            str(tmp_path / "run.json"),
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["ok"] is True
    assert payload["dry_run"] is True
    assert (tmp_path / "run.json").is_file()


def test_journal_survives_unwritable_path(tmp_path) -> None:
    journal = mod.Journal(path=Path("/proc/forbidden/state.json"), payload={})
    journal.event("x", "y", ok=True)
    assert journal.events[0]["ok"] is True
