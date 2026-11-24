"""Save and publish on a rootless App must update the cell ingress, not Traefik."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

import systutor.kernel.models  # noqa: F401
from plugins.domains.backend import service as service_module
from plugins.domains.backend.models import DomainAppHost, DomainRoute
from plugins.domains.backend.proxy import CertificateInfo, PathRoute
from plugins.domains.backend.schemas import RouteCreate, RouteUpdate
from plugins.domains.backend.service import DomainsService
from systutor.contracts.domain_namespace import register_domain_providers
from systutor.contracts.domain_ownership import OwnedSite, register_site_provider
from systutor.contracts.rootless_ingress import (
    RootlessIngress,
    register_rootless_ingress,
)
from systutor.core.database import Base
from systutor.core.errors import AppError
from systutor.kernel.tenants.context import TenantContext


class FakeOps:
    def __init__(self) -> None:
        self.documents: dict[str, list[PathRoute]] = {}

    def managed_domains(self):
        return []

    def write_route_document(
        self, domain, routes, *, validate_runtime=True, connect_network=True
    ):
        self.documents[domain] = list(routes)

    def remove_route_document(self, domain):
        self.documents.pop(domain, None)
        return True

    def path_conflict(self, domain, prefix):
        return False

    def probe_route(self, domain, path="/"):
        return CertificateInfo("active", issuer="CN=Test", verified=True), 200


def context() -> TenantContext:
    return TenantContext(
        current_tenant_id="t1",
        current_branch_id=None,
        current_user_id="user-1",
        current_permissions=("domains.domains.read", "domains.domains.manage"),
        current_warehouse_ids=None,
    )


@pytest.fixture()
def setup(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'domains.db'}")
    Base.metadata.create_all(engine)
    db = Session(engine, expire_on_commit=False)
    app = FastAPI()
    owned = {"t1": {"api.example.com"}}
    register_site_provider(
        app,
        "apps",
        lambda _db, tenant_id: [OwnedSite("app-1:web", "t1", "legacy-container", None)],
    )
    register_domain_providers(
        app,
        "tenant",
        list_domains=lambda _db, tenant_id: sorted(owned.get(tenant_id, set())),
        owner=lambda _db, domain: next(
            (tenant for tenant, domains in owned.items() if domain in domains), None
        ),
        claim=lambda _db, tenant_id, domain: owned.setdefault(
            tenant_id, set()
        ).add(domain),
        release=lambda _db, tenant_id, domain: owned.get(tenant_id, set()).discard(
            domain
        ),
    )
    calls: list[tuple] = []
    register_rootless_ingress(
        app,
        "apps",
        RootlessIngress(
            is_rootless=lambda _db, _tenant, site: site == "app-1:web",
            refresh=lambda _db, tenant, site: calls.append(("refresh", tenant, site)),
            remove=lambda _db, tenant, site, domain: calls.append(
                ("remove", tenant, site, domain)
            ),
        ),
    )
    ops = FakeOps()
    service = DomainsService(db, app)
    service._operations = lambda: ops  # type: ignore[method-assign]
    service._ready = lambda: ops  # type: ignore[method-assign]
    service._settings = lambda: SimpleNamespace(  # type: ignore[method-assign]
        profile="internal", entrypoint_http="web", entrypoint_https="websecure"
    )
    monkeypatch.setattr(service_module, "record_audit", lambda _db, **kwargs: None)
    monkeypatch.setattr(
        service_module,
        "get_domains_settings",
        lambda: SimpleNamespace(middlewares=()),
    )
    try:
        yield service, db, ops, calls, owned
    finally:
        db.close()
        engine.dispose()


def _host(db: Session) -> DomainAppHost | None:
    return db.scalar(select(DomainAppHost))


def test_save_root_route_publishes_ingress_and_creates_the_app_host(setup):
    service, db, ops, calls, owned = setup

    item = service.create_route(
        context(),
        RouteCreate(
            domain="api.example.com",
            site_id="app-1:web",
            path="/",
            port=8080,
            https=True,
        ),
    )

    assert item.port == 8080
    assert ops.documents == {}, "rootless must not write a container document"
    assert calls == [("refresh", "t1", "app-1:web")]
    host = _host(db)
    assert host is not None
    assert (host.application_id, host.service, host.domain) == (
        "app-1",
        "web",
        "api.example.com",
    )


def test_rootless_route_editor_rejects_non_root_paths(setup):
    service, _, ops, calls, _owned = setup

    with pytest.raises(AppError) as error:
        service.create_route(
            context(),
            RouteCreate(
                domain="api.example.com",
                site_id="app-1:web",
                path="/api",
                port=8080,
            ),
        )

    assert error.value.code == "domains.rootless_path_unsupported"
    assert ops.documents == {} and calls == []


def test_domain_edit_updates_the_app_host_and_refreshes(setup):
    service, db, ops, calls, owned = setup
    item = service.create_route(
        context(),
        RouteCreate(domain="api.example.com", site_id="app-1:web", port=8080),
    )
    owned["t1"].add("new.example.com")

    service.update_route(
        context(), item.id, RouteUpdate(domain="new.example.com", port=9090)
    )

    host = _host(db)
    assert host is not None and host.domain == "new.example.com"
    assert ops.documents == {}
    assert calls[-1] == ("refresh", "t1", "app-1:web")


def test_domain_add_page_cannot_publish_a_rootless_container_route(setup):
    service, _, ops, calls, owned = setup
    owned["t1"].add("extra.example.com")

    with pytest.raises(AppError) as error:
        service.add(
            context(),
            site_id="app-1:web",
            domain="extra.example.com",
            www=False,
        )

    assert error.value.code == "domains.rootless_ingress_required"
    assert ops.documents == {} and calls == []


def test_delete_removes_the_app_host_and_the_relay_document(setup):
    service, db, ops, calls, owned = setup
    item = service.create_route(
        context(),
        RouteCreate(domain="api.example.com", site_id="app-1:web", port=8080),
    )

    service.delete_route(context(), item.id)

    assert db.scalar(select(DomainRoute)) is None
    assert _host(db) is None
    assert ops.documents == {}
    assert ("remove", "t1", "app-1:web", "api.example.com") in calls
