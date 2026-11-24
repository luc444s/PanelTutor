"""Domains-owned app Hosts: migration, contract and tenant ownership."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace

from fastapi import FastAPI
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateTable

from plugins.domains.backend.models import DomainAppHost, DomainRoute
from plugins.domains.backend.schemas import AppHostCreate
from plugins.domains.backend.service import DomainsService, provide_app_hosts
from systutor.contracts.app_hosts import (
    list_app_hosts,
    register_app_host_provider,
    resolve_app_host,
)
from systutor.contracts.domain_namespace import register_domain_providers
from systutor.kernel.tenants.context import TenantContext
from systutor.kernel.tenants.models import Tenant

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2] / "migrations" / "005_rootless_app_hosts.py"
)


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("domains_migration_005", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_upgrade_downgrade_upgrade_backfills_legacy_host() -> None:
    migration = _migration()
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        Tenant.__table__.create(engine)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE apps_applications ("
                    "id VARCHAR(36) PRIMARY KEY, tenant_id VARCHAR(36) NOT NULL, "
                    "ingress_service VARCHAR(255) NOT NULL, domain VARCHAR(253))"
                )
            )
        with Session(engine) as db:
            db.add(Tenant(id="t1", name="One", slug="one"))
            db.commit()
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO apps_applications VALUES "
                    "('a1', 't1', 'web', 'Legacy.Example.')"
                )
            )
        for expected_present in (True, False, True):
            with Session(engine) as db:
                (migration.upgrade if expected_present else migration.downgrade)(db)
                db.commit()
            assert (
                "domains_app_hosts" in inspect(engine).get_table_names()
            ) is expected_present
        with engine.connect() as connection:
            assert connection.execute(
                text(
                    "SELECT application_id, service, domain, https "
                    "FROM domains_app_hosts"
                )
            ).all() == [("a1", "web", "legacy.example", 1)]
            assert connection.execute(
                text("SELECT domain FROM apps_applications WHERE id='a1'")
            ).scalar_one() == "Legacy.Example."
    finally:
        engine.dispose()


def test_migration_boolean_default_is_valid_postgresql() -> None:
    ddl = str(
        CreateTable(_migration().app_hosts).compile(dialect=postgresql.dialect())
    ).lower()

    assert "default false" in ddl
    assert "default 1" not in ddl


def test_contract_resolves_registered_domains_provider() -> None:
    app = FastAPI()
    register_app_host_provider(app, "domains", provide_app_hosts)
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        Tenant.__table__.create(engine)
        DomainAppHost.__table__.create(engine)
        DomainRoute.__table__.create(engine)
        with Session(engine) as db:
            db.add(Tenant(id="t1", name="One", slug="one"))
            db.add(
                DomainAppHost(
                    tenant_id="t1", application_id="a1", service="web",
                    domain="app.example", https=True,
                )
            )
            db.commit()
            assert [row.domain for row in list_app_hosts(app, db, "t1")] == [
                "app.example"
            ]
            assert resolve_app_host(app, db, "t1", "a1", "web").site_id == "a1:web"
    finally:
        engine.dispose()


def test_service_claims_and_releases_only_the_current_tenant(monkeypatch) -> None:
    app = FastAPI()
    owned: dict[str, str] = {}
    register_domain_providers(
        app,
        "fake",
        list_domains=lambda _db, tenant: [d for d, owner in owned.items() if owner == tenant],
        owner=lambda _db, domain: owned.get(domain),
        claim=lambda _db, tenant, domain: owned.setdefault(domain, tenant),
        release=lambda _db, tenant, domain: (
            owned.pop(domain) if owned.get(domain) == tenant else None
        ),
    )
    monkeypatch.setattr(
        "plugins.domains.backend.service.resolve_site",
        lambda _app, _db, tenant, site: SimpleNamespace(
            tenant_id=tenant, site_id=site, container="app-web"
        ),
    )
    monkeypatch.setattr(
        DomainsService, "_audit", lambda self, *_args, **_kwargs: self._db.commit()
    )
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        Tenant.__table__.create(engine)
        DomainAppHost.__table__.create(engine)
        DomainRoute.__table__.create(engine)
        with Session(engine) as db:
            db.add(Tenant(id="t1", name="One", slug="one"))
            db.commit()
            context = TenantContext("t1", None, "u1", (), None)
            service = DomainsService(db, app)
            item = service.add_app_host(
                context,
                AppHostCreate(
                    application_id="a1", service="web", domain="App.Example"
                ),
            )
            assert item.site_id == "a1:web"
            assert owned == {"app.example": "t1"}
            service.remove_app_host(context, "a1", "web")
            assert owned == {}
    finally:
        engine.dispose()
