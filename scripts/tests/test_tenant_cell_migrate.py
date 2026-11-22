"""Sequential rootless migration orchestration tests for A.SPEC 0108."""

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

from scripts.tenant_cell import cli, plans


class Backend(cli.MigrationBackend):
    def __init__(self, resources: list[dict[str, Any]], fail: str = "") -> None:
        self.rows = resources
        self.fail = fail
        self.events: list[tuple[str, str, str | None]] = []
        self.runtimes = {
            str(row["resource_id"]): str(row.get("runtime", "rootful"))
            for row in resources
        }

    def resources(self):
        return list(self.rows)

    def runtime(self, resource):
        return self.runtimes[str(resource["resource_id"])]

    def migrate(self, resource):
        resource_id = str(resource["resource_id"])
        self.events.append(("migrate", resource_id, None))
        return f"undo:{resource_id}"

    def verify(self, resource):
        resource_id = str(resource["resource_id"])
        self.events.append(("verify", resource_id, None))
        return resource_id != self.fail

    def set_runtime(self, resource, runtime):
        resource_id = str(resource["resource_id"])
        self.events.append(("runtime", resource_id, runtime))
        self.runtimes[resource_id] = runtime

    def rollback(self, resource, token):
        self.events.append(("rollback", str(resource["resource_id"]), token))


ROWS = [
    {"kind": "app", "resource_id": "a1", "name": "App"},
    {"kind": "wordpress", "resource_id": "w1", "name": "WP"},
    {"kind": "static", "resource_id": "s1", "name": "Static"},
    {"kind": "app", "resource_id": "core1", "name": "Traefik", "labels": {"role": "core"}},
    {"kind": "static", "resource_id": "pma", "container_name": "phpmyadmin"},
]


def test_dry_run_orders_resources_excludes_core_and_never_mutates() -> None:
    backend = Backend(ROWS)
    result = cli.MigrationService(backend).run(
        dry_run=True, only=None, exclude=set(), stop_on_failure=True
    )
    assert [row["resource_id"] for row in result["order"]] == ["s1", "w1", "a1"]
    assert backend.events == []
    assert all(row["mutation"] is False for row in result["order"])


def test_dry_run_excludes_spanel_mail_without_core_labels() -> None:
    backend = Backend([
        {
            "kind": "app",
            "resource_id": "dms-0108",
            "name": "spanel-mail",
            "container_name": "spanel-mail",
        },
        {"kind": "app", "resource_id": "tenant-app", "name": "Tenant App"},
    ])

    result = cli.MigrationService(backend).run(
        dry_run=True, only=None, exclude=set(), stop_on_failure=True
    )

    assert [row["resource_id"] for row in result["order"]] == ["tenant-app"]
    assert backend.events == []


def test_apply_is_sequential_and_persists_only_after_verification(monkeypatch) -> None:
    monkeypatch.setenv("SPANEL_TENANTS_ROOTLESS", "true")
    backend = Backend(ROWS[:3])
    result = cli.MigrationService(backend).run(
        dry_run=False, only=None, exclude=set(), stop_on_failure=True
    )
    assert result["ok"] is True
    for resource_id in ("s1", "w1", "a1"):
        assert backend.events.index(("verify", resource_id, None)) < backend.events.index(
            ("runtime", resource_id, "rootless")
        )


def test_stop_on_failure_rolls_back_and_does_not_start_later_resource(monkeypatch) -> None:
    monkeypatch.setenv("SPANEL_TENANTS_ROOTLESS", "true")
    backend = Backend(ROWS[:3], fail="w1")
    result = cli.MigrationService(backend).run(
        dry_run=False, only=None, exclude=set(), stop_on_failure=True
    )
    assert result["ok"] is False
    assert ("rollback", "w1", "undo:w1") in backend.events
    assert backend.runtimes["w1"] == "rootful"
    assert not any(event[1] == "a1" for event in backend.events)


def test_flag_blocks_apply_but_not_dry_run_and_keeps_registered_runtime(monkeypatch) -> None:
    monkeypatch.setenv("SPANEL_TENANTS_ROOTLESS", "false")
    row = {"kind": "app", "resource_id": "a1", "runtime": "rootless"}
    backend = Backend([row])
    with pytest.raises(plans.MutationDisabled):
        cli.MigrationService(backend).run(
            dry_run=False, only=None, exclude=set(), stop_on_failure=True
        )
    result = cli.MigrationService(backend).run(
        dry_run=True, only=None, exclude=set(), stop_on_failure=True
    )
    assert result["order"][0]["status"] == "already_rootless"
    assert backend.runtimes["a1"] == "rootless"


def test_migrate_cli_all_is_mutually_exclusive(monkeypatch) -> None:
    result = CliRunner().invoke(cli.app, [
        "migrate", "--all", "--slug", "acme", "--dry-run", "--json",
    ])
    assert result.exit_code == 2
    assert "mutually exclusive" in json.loads(result.output)["error"]
