from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import systutor.kernel.models  # noqa: F401
from plugins.apps.backend.models import Application, Deployment
from plugins.apps.backend.register import resolve_apps_resources
from plugins.hosting.backend.models import HostingSite, StaticProfile
from plugins.hosting.backend.register import resolve_hosting_resources
from plugins.tenant.backend.register import register
from plugins.tenant.backend.router import inventory_router
from plugins.tenant.backend.service import list_runtimes, set_runtime
from systutor.api.deps import get_db_session
from systutor.contracts.resource_runtime import ManagedResource, register_resource_provider
from systutor.core.database import Base
from systutor.kernel.auth.dependencies import get_current_tenant_context, get_current_user
from systutor.kernel.tenants.context import TenantContext
from systutor.kernel.tenants.models import Tenant


def _resource(resource_id: str) -> ManagedResource:
    return ManagedResource(
        kind="app",
        resource_id=resource_id,
        name=resource_id,
        container_name=f"container-{resource_id}",
        domain=None,
        state="unknown",
        image="unknown",
        endpoint=None,
    )


@pytest.fixture()
def inventory() -> Iterator[tuple[TestClient, sessionmaker[Session], FastAPI]]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as db:
        db.add_all(
            [
                Tenant(id="t1", name="One", slug="one"),
                Tenant(id="t2", name="Two", slug="two"),
            ]
        )
        db.commit()
    app = FastAPI()
    app.include_router(inventory_router, prefix="/api/v1/plugins/tenant")
    register_resource_provider(
        app,
        "fake",
        lambda _db, tenant_id: [_resource(f"{tenant_id}:web")],
    )
    context = TenantContext(
        "t1",
        None,
        "u1",
        ("tenant.tenants.read", "tenant.tenants.manage", "apps.applications.manage"),
        None,
    )

    def sessions() -> Iterator[Session]:
        with factory() as db:
            yield db

    app.dependency_overrides[get_db_session] = sessions
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id="u1")
    app.dependency_overrides[get_current_tenant_context] = lambda: context
    with TestClient(app) as client:
        yield client, factory, app
    engine.dispose()


def test_scope_provider_and_missing_runtime_defaults_without_insert(inventory) -> None:
    client, factory, _app = inventory
    response = client.get("/api/v1/plugins/tenant/tenants/t1/resources")
    assert response.status_code == 200
    assert response.json()["resources"][0]["resource_id"] == "t1:web"
    assert response.json()["resources"][0]["runtime"] == "rootful"
    assert client.get("/api/v1/plugins/tenant/tenants/t2/resources").status_code == 404
    with factory() as db:
        assert list_runtimes(db) == []


def test_dry_run_uses_registered_runtime_without_mutation(inventory) -> None:
    client, factory, _app = inventory
    with factory() as db:
        set_runtime(db, "t1", "app", "t1:web", "rootless")
        db.commit()
    response = client.post(
        "/api/v1/plugins/tenant/tenants/t1/resources/app/t1:web/actions/remove?dry_run=1"
    )
    assert response.status_code == 200
    assert response.json()["dry_run"] is True
    assert response.json()["runtime"] == "rootless"
    with factory() as db:
        assert len(list_runtimes(db)) == 1


def test_platform_admin_can_read_another_tenant(inventory) -> None:
    client, _factory, app = inventory
    app.dependency_overrides[get_current_tenant_context] = lambda: TenantContext(
        "t1",
        None,
        "u1",
        ("tenant.tenants.read", "core.platform.admin"),
        None,
    )
    response = client.get("/api/v1/plugins/tenant/tenants/t2/resources")
    assert response.status_code == 200
    assert response.json()["resources"][0]["resource_id"] == "t2:web"


def test_apps_and_hosting_providers_inventory_active_rows() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Tenant(id="t1", name="One", slug="one"))
        db.add(
            Application(
                id="a1",
                tenant_id="t1",
                name="Demo",
                slug="demo",
                repository="org/repo",
                branch="main",
                source_connection_user_id="u1",
                runtime_project="demo-project",
                status="running",
                active_deployment_id="d1",
                ingress_service="web",
                domain="demo.test",
            )
        )
        db.add(
            Deployment(
                id="d1",
                application_id="a1",
                operation_id="o1",
                repository="org/repo",
                branch="main",
                status="active",
                manifest={
                    "containers": {"web": "cid"},
                    "container_names": {"web": "demo-web"},
                    "images": {"web": "demo:latest"},
                },
            )
        )
        db.add(
            StaticProfile(
                id="nginx",
                name="Nginx",
                image="nginx:alpine",
                web_root="/usr/share/nginx/html",
                container_port=80,
            )
        )
        db.add(
            HostingSite(
                id="s1",
                tenant_id="t1",
                container_name="static-one",
                domain="static.test",
                kind="static",
                profile_id="nginx",
            )
        )
        db.commit()
        apps = resolve_apps_resources(db, "t1")
        hosting = resolve_hosting_resources(db, "t1")
    assert [(row.kind, row.image) for row in apps] == [("app", "demo:latest")]
    assert [(row.kind, row.image) for row in hosting] == [("static", "nginx:alpine")]


def test_inventory_router_flag_defaults_off(monkeypatch) -> None:
    app = FastAPI()
    context = SimpleNamespace(
        routers=[],
        router_registry=app,
        register_router=lambda router: context.routers.append(router),
    )
    monkeypatch.delenv("SPANEL_TENANT_RESOURCE_INVENTORY", raising=False)
    register(context)
    assert inventory_router not in context.routers
    context.routers.clear()
    monkeypatch.setenv("SPANEL_TENANT_RESOURCE_INVENTORY", "true")
    register(context)
    assert inventory_router in context.routers
