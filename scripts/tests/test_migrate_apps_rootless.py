"""Operational script: arguments, ledger and dry-run inventory."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI

ROOT = Path(__file__).resolve().parents[2]
for entry in (
    str(ROOT),
    str(ROOT / "vendor/systutor-core"),
    str(ROOT / "vendor/systutor-core/src"),
):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from systutor.contracts.app_hosts import (
    AppHost,
    register_app_host_provider,
)

from scripts.migrate_apps_rootless import (
    AppsRootlessMigrator,
    OperationLedger,
    build_parser,
    resolve_tenant_id,
)


def _parser():
    return build_parser()


def test_defaults_are_a_dry_run_for_one_tenant() -> None:
    args = _parser().parse_args(["--tenant", "milton"])

    assert args.dry_run is True
    assert args.stop_rootful is False
    assert args.apps == []


def test_apply_and_stop_rootful_are_explicit() -> None:
    args = _parser().parse_args(
        ["--tenant", "milton", "--apply", "--stop-rootful", "--app", "a1"]
    )

    assert args.dry_run is False
    assert args.stop_rootful is True
    assert args.apps == ["a1"]


def test_ledger_roundtrip_is_idempotent(tmp_path: Path) -> None:
    ledger = OperationLedger(tmp_path / "ops.json")
    ledger.record("apps-rootless:a1", {"application_id": "a1"})
    ledger.record("apps-rootless:a1", {"application_id": "a1", "stopped": []})

    assert ledger.get("apps-rootless:a1") == {
        "application_id": "a1", "stopped": []
    }
    assert ledger.get("missing") is None


class _Db:
    def __init__(self, deployment):
        self.deployment = deployment
        self.rolled_back = False

    def get(self, _model, _key):
        return self.deployment

    def rollback(self) -> None:
        self.rolled_back = True

    def commit(self) -> None:
        return None


def test_dry_run_inventories_hosts_and_containers(tmp_path: Path) -> None:
    app = FastAPI()
    register_app_host_provider(
        app,
        "fake",
        lambda _db, _tenant, _application: [
            AppHost("a1:web", "a1", "web", "editores.systutor.com", True, 8080)
        ],
    )
    deployment = SimpleNamespace(
        manifest={"containers": {"web": "cid"}, "container_names": {"web": "web-1"}}
    )
    application = SimpleNamespace(
        id="a1", slug="editores", active_deployment_id="d1",
        runtime_project="app-14aaf",
    )
    migrator = AppsRootlessMigrator(
        _Db(deployment), app, tenant_id="milton", dry_run=True,
        ledger=OperationLedger(tmp_path / "ops.json"),
    )

    result = migrator.migrate_app(application)

    assert result.ok is True
    assert result.dry_run is True
    assert result.domains == ["editores.systutor.com"]
    assert result.containers == ["web-1"]
    assert [step.phase for step in result.steps] == ["inventory", "inventory", "preflight"]
    assert result.steps[-1].status == "pending"


def test_tenant_accepts_slug_or_id(tmp_path: Path) -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from systutor.kernel.tenants.models import Tenant

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'tenants.db'}")
    try:
        Tenant.__table__.create(engine)
        with Session(engine) as db:
            db.add(Tenant(id="tenant-uuid", name="Milton", slug="milton"))
            db.commit()
            assert resolve_tenant_id(db, "milton") == "tenant-uuid"
            assert resolve_tenant_id(db, "tenant-uuid") == "tenant-uuid"
    finally:
        engine.dispose()
