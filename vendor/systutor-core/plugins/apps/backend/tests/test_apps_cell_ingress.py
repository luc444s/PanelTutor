"""Apps cell ingress: Domains Hosts, service containers and cleanup."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from plugins.apps.backend.cell_ingress import AppsIngress, AppsIngressError
from systutor.contracts.app_hosts import AppHost, register_app_host_provider
from systutor.kernel.cell_ingress import NETWORK, CellIngress, TenantIngressRoute

TENANT = "t1"
APP = "a1"


class FakeHandle:
    runtime = "rootless"

    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def inspect(self, kind: str, name: str):
        if kind == "network":
            return {}
        if name == "spanel-cell-ingress":
            return {"Config": {"Labels": {"spanel.role": "cell-infra"}}}
        return {
            "State": {"Running": True},
            "NetworkSettings": {"Networks": {NETWORK: {}}},
            "Config": {
                "Labels": {"spanel.managed": "true", "spanel.tenant": TENANT}
            },
        }

    def command(self, args: tuple[str, ...], *, input: bytes | None = None) -> bytes:
        self.commands.append(args)
        return b""

    def write_private(self, relative_path: str, content: bytes) -> str:
        return f"/private/{relative_path}"

    def remove_private(self, relative_path: str) -> None:
        return None

    def health(self):
        return type("Health", (), {"publish_port": 20020})()


def _app(*hosts: AppHost) -> FastAPI:
    app = FastAPI()
    register_app_host_provider(
        app, "fake", lambda _db, _tenant, _application: list(hosts)
    )
    return app


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    TenantIngressRoute.__table__.create(engine)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def test_reconcile_upserts_every_domains_host(db: Session) -> None:
    host = AppHost("a1:web", APP, "web", "app.example.test", True, 8080)
    ingress = AppsIngress(_app(host), db, handle=FakeHandle())
    ingress._containers = lambda _application_id: {"web": "web-1"}

    domains = ingress.reconcile(TENANT, APP)

    assert domains == ["app.example.test"]
    cell = CellIngress(db, FakeHandle())
    routes = cell.routes(TENANT, "apps")
    assert [(row.owner_id, row.service, row.port) for row in routes] == [
        (APP, "web", 8080)
    ]


def test_reconcile_commits_the_route_outside_the_worker_session(db: Session) -> None:
    host = AppHost("a1:web", APP, "web", "app.example.test", True, 8080)
    ingress = AppsIngress(_app(host), db, handle=FakeHandle())
    ingress._containers = lambda _application_id: {"web": "web-1"}

    ingress.reconcile(TENANT, APP)
    db.close()

    with Session(ingress.db.get_bind()) as other:
        routes = CellIngress(other, FakeHandle()).routes(TENANT, "apps")
        assert [route.domain for route in routes] == ["app.example.test"]


def test_non_root_path_fails_the_preflight(db: Session) -> None:
    host = AppHost(
        "a1:web", APP, "web", "app.example.test", True, 8080,
        unsupported_paths=True,
    )
    ingress = AppsIngress(_app(host), db, handle=FakeHandle())

    with pytest.raises(AppsIngressError) as error:
        ingress.reconcile(TENANT, APP)

    assert error.value.code == "apps_ingress_path_unsupported"
    assert CellIngress(db, FakeHandle()).routes(TENANT) == []


def test_missing_container_fails_before_publishing(db: Session) -> None:
    host = AppHost("a1:web", APP, "web", "app.example.test", True, 8080)
    ingress = AppsIngress(_app(host), db, handle=FakeHandle())
    ingress._containers = lambda _application_id: {}

    with pytest.raises(AppsIngressError) as error:
        ingress.reconcile(TENANT, APP)

    assert error.value.code == "apps_ingress_unavailable"
    assert CellIngress(db, FakeHandle()).routes(TENANT) == []


def test_unlabeled_target_fails_with_redeploy_guidance(db: Session) -> None:
    class UnlabeledHandle(FakeHandle):
        def inspect(self, kind: str, name: str):
            info = super().inspect(kind, name)
            if kind == "container" and name != "spanel-cell-ingress":
                info = {
                    **(info or {}),
                    "Config": {"Labels": {"spanel.owned": "legacy"}},
                }
            return info

    host = AppHost("a1:web", APP, "web", "app.example.test", True, 8080)
    ingress = AppsIngress(_app(host), db, handle=UnlabeledHandle())
    ingress._containers = lambda _application_id: {"web": "web-1"}

    with pytest.raises(AppsIngressError) as error:
        ingress.reconcile(TENANT, APP)

    assert error.value.code == "apps_ingress_unavailable"
    assert "--redeploy-rootless" in str(error.value)
    assert CellIngress(db, FakeHandle()).routes(TENANT) == []


def test_remove_deletes_rows_and_regenerates_the_file(db: Session) -> None:
    host = AppHost("a1:web", APP, "web", "app.example.test", True, 8080)
    handle = FakeHandle()
    ingress = AppsIngress(_app(host), db, handle=handle)
    ingress._containers = lambda _application_id: {"web": "web-1"}
    ingress.reconcile(TENANT, APP)

    removed = ingress.remove(TENANT, APP)

    assert removed == [f"apps:{APP}:web"]
    assert CellIngress(db, handle).routes(TENANT) == []


def test_no_domains_host_is_inert(db: Session) -> None:
    ingress = AppsIngress(_app(), db, handle=FakeHandle())

    assert ingress.reconcile(TENANT, APP) == []
    assert CellIngress(db, FakeHandle()).routes(TENANT) == []
