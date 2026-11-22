from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import Column, MetaData, String, Table, create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import systutor.kernel.models  # noqa: F401
from plugins.tenant.backend.models import TenantResourceRuntime
from plugins.tenant.backend.service import get_runtime, list_runtimes, set_runtime
from systutor.core.database import Base
from systutor.kernel.tenants.models import Tenant


def _migration():
    path = Path(__file__).parents[2] / "migrations/004_tenant_resource_runtimes.py"
    spec = importlib.util.spec_from_file_location("tenant_migration_004", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_upgrade_downgrade_upgrade_preserves_other_tables() -> None:
    engine = create_engine("sqlite://")
    metadata = MetaData()
    tenants = Table("tenants", metadata, Column("id", String(36), primary_key=True))
    applications = Table(
        "apps_applications", metadata, Column("id", String(36), primary_key=True)
    )
    sites = Table("hosting_sites", metadata, Column("id", String(36), primary_key=True))
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(tenants.insert().values(id="t1"))
        connection.execute(applications.insert().values(id="a1"))
        connection.execute(sites.insert().values(id="s1"))
    migration = _migration()
    with Session(engine) as db:
        migration.upgrade(db)
        assert "tenant_resource_runtimes" in inspect(engine).get_table_names()
        migration.downgrade(db)
        assert "tenant_resource_runtimes" not in inspect(engine).get_table_names()
        migration.upgrade(db)
    with engine.connect() as connection:
        assert connection.execute(tenants.select()).one().id == "t1"
        assert connection.execute(applications.select()).one().id == "a1"
        assert connection.execute(sites.select()).one().id == "s1"


def test_default_set_get_list_and_unique_constraint() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Tenant(id="t1", name="Tenant", slug="tenant"))
        db.commit()
        assert get_runtime(db, "t1", "app", "a1:web") == "rootful"
        assert list_runtimes(db, "t1") == []
        row = set_runtime(db, "t1", "app", "a1:web", "rootless")
        db.commit()
        assert row.runtime == "rootless"
        assert get_runtime(db, "t1", "app", "a1:web") == "rootless"
        db.add(
            TenantResourceRuntime(
                id="duplicate",
                tenant_id="t1",
                kind="app",
                resource_id="a1:web",
                runtime="rootful",
            )
        )
        with pytest.raises(IntegrityError):
            db.commit()
