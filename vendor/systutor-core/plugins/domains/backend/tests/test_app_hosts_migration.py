"""Migration 006 restores the AppHost that rootless ingress requires."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "migrations"
    / "006_backfill_app_hosts_from_routes.py"
)


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "domains_migration_006", MIGRATION_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _seed(engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE domains_routes ("
                "id TEXT PRIMARY KEY, tenant_id TEXT, domain TEXT, path TEXT, "
                "site_id TEXT, https BOOLEAN, updated_at TIMESTAMP)"
            )
        )
        connection.execute(
            text(
                "CREATE TABLE domains_app_hosts ("
                "id TEXT PRIMARY KEY, tenant_id TEXT, application_id TEXT, "
                "service TEXT, domain TEXT, https BOOLEAN, "
                "created_at TIMESTAMP, updated_at TIMESTAMP)"
            )
        )
        connection.execute(
            text(
                "CREATE TABLE apps_applications ("
                "id TEXT PRIMARY KEY, deleted_at TIMESTAMP)"
            )
        )
        connection.execute(
            text("INSERT INTO apps_applications (id) VALUES ('app-1')")
        )
        connection.execute(
            text(
                "INSERT INTO apps_applications (id, deleted_at) "
                "VALUES ('app-deleted', '2026-01-01')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO domains_routes "
                "(id, tenant_id, domain, path, site_id, https, updated_at) VALUES "
                "('r1', 't1', 'Editores.Systutor.com.', '/', 'app-1:frontend', 1, '2026-01-02'),"
                "('r2', 't1', 'deleted.example.com', '/', 'app-deleted:frontend', 1, '2026-01-02'),"
                "('r3', 't1', 'hosting.example.com', '/', 'hosting-site-uuid', 1, '2026-01-02'),"
                "('r4', 't1', 'editores.systutor.com', '/api', 'app-1:frontend', 1, '2026-01-03')"
            )
        )


def test_upgrade_backfills_only_live_app_root_routes_and_is_idempotent() -> None:
    migration = _load()
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        _seed(engine)
        with Session(engine) as session:
            migration.upgrade(session)
            session.commit()
            migration.upgrade(session)
            session.commit()
        with engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT tenant_id, application_id, service, domain, https "
                    "FROM domains_app_hosts"
                )
            ).mappings().all()
        assert [dict(row) for row in rows] == [
            {
                "tenant_id": "t1",
                "application_id": "app-1",
                "service": "frontend",
                "domain": "editores.systutor.com",
                "https": 1,
            }
        ]
    finally:
        engine.dispose()


def test_upgrade_skips_when_required_tables_are_missing() -> None:
    migration = _load()
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        with Session(engine) as session:
            migration.upgrade(session)
            session.commit()
    finally:
        engine.dispose()
