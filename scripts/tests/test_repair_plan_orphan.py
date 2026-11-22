"""Tests for scripts/repair_plan_orphan.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "repair_plan_orphan.py"

spec = importlib.util.spec_from_file_location("repair_plan_orphan", SCRIPT)
assert spec is not None and spec.loader is not None
repair = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = repair
spec.loader.exec_module(repair)

OPERATION = "23351f6b-89e3-4ccf-a979-2a255cfcf5cc"


def test_report_sql_is_read_only_and_scoped() -> None:
    sql = repair.report_sql()
    assert "apps_operations" in sql
    assert "apps_tenant_plans" in sql
    assert "status IN ('queued', 'running')" in sql
    assert "UPDATE" not in sql
    assert ":'tenant'" in sql


def test_repair_sql_keeps_every_guard() -> None:
    sql = repair.repair_sql()
    for fragment in (
        "o.kind = :'kind'",
        "o.subject_type = :'subject'",
        "o.status = 'queued'",
        "o.message_id IS NULL",
        "o.finished_at IS NULL",
        "interval '1 second' * :'min_age'::int",
        "status = 'interrupted'",
        repair.ORPHAN_ERROR_CODE,
        "RETURNING",
    ):
        assert fragment in sql


def test_psql_command_never_uses_the_host_psql() -> None:
    command = repair.psql_command(
        Path("/srv/spanel/docker-compose.yml"),
        repair.Database(user="spanel", name="spanel"),
    )
    assert command[:7] == [
        "docker",
        "compose",
        "-f",
        "/srv/spanel/docker-compose.yml",
        "exec",
        "-T",
        "postgres",
    ]
    assert command[7] == "psql"
    assert "-v" in command and "ON_ERROR_STOP=1" in command


def test_run_psql_passes_variables_and_parses_rows() -> None:
    captured: dict[str, object] = {}

    class Result:
        returncode = 0
        stdout = "miltonarquez\t2f9a\t0\t" + OPERATION + "\tplan_set\tqueued\n"
        stderr = ""

    def fake_runner(command: list[str], **kwargs: object) -> Result:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return Result()

    rows = repair.run_psql(
        "SELECT 1",
        {"tenant": "miltonarquez"},
        compose_file=Path("docker-compose.yml"),
        database=repair.Database(user="spanel", name="spanel"),
        runner=fake_runner,
    )
    command = captured["command"]
    assert isinstance(command, list)
    assert "tenant=miltonarquez" in command
    assert command[-2:] == ["-f", "-"]
    assert captured["kwargs"] == {
        "input": "SELECT 1",
        "capture_output": True,
        "text": True,
        "check": False,
    }
    assert rows[0][0] == "miltonarquez"


def test_run_psql_surfaces_failures() -> None:
    class Result:
        returncode = 1
        stdout = ""
        stderr = "ERROR: relation does not exist\n"

    with pytest.raises(repair.RepairError, match="relation does not exist"):
        repair.run_psql(
            "SELECT 1",
            {},
            compose_file=Path("docker-compose.yml"),
            database=repair.Database(user="spanel", name="spanel"),
            runner=lambda *args, **kwargs: Result(),
        )


def test_parse_report_maps_columns() -> None:
    parsed = repair.parse_report(
        [
            [
                "miltonarquez",
                "2f9a",
                "0",
                OPERATION,
                "plan_set",
                "queued",
                "queued",
                "",
                "",
                "now",
            ],
        ]
    )
    assert parsed == [
        {
            "tenant_slug": "miltonarquez",
            "tenant_id": "2f9a",
            "plan_rows": 0,
            "operation_id": OPERATION,
            "kind": "plan_set",
            "status": "queued",
            "phase": "queued",
            "message_id": None,
            "error_code": None,
            "created_at": "now",
        }
    ]


def test_apply_requires_confirm_and_operation() -> None:
    assert repair.main(["--tenant", "miltonarquez", "--apply"]) == 1


def test_apply_reports_guard_rejection(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_run(
        sql: str, variables: dict[str, str], **kwargs: object
    ) -> list[list[str]]:
        if "UPDATE apps_operations" in sql:
            return []
        return [
            [
                "miltonarquez",
                "2f9a",
                "0",
                OPERATION,
                "plan_set",
                "queued",
                "queued",
                "",
                "",
                "now",
            ]
        ]

    monkeypatch.setattr(repair, "run_psql", fake_run)
    monkeypatch.setattr(
        repair,
        "resolve_database",
        lambda path: repair.Database(user="spanel", name="spanel"),
    )
    code = repair.main(
        [
            "--tenant",
            "miltonarquez",
            "--apply",
            "--operation-id",
            OPERATION,
            "--confirm",
            "yes",
        ]
    )
    assert code == 3
    assert "guard rejected" in capsys.readouterr().out


def test_read_env_file_does_not_execute(tmp_path: Path) -> None:
    env = tmp_path / ".env.docker"
    env.write_text(
        "POSTGRES_USER=spanel\n# comment\nPOSTGRES_DB='panel'\n", encoding="utf-8"
    )
    values = repair.read_env_file(env)
    assert values == {"POSTGRES_USER": "spanel", "POSTGRES_DB": "panel"}
