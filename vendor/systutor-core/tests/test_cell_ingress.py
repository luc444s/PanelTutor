"""Kernel cell ingress: mixed render, ownership and nginx validation."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from systutor.kernel.cell_ingress import (
    APPS_CONFIG,
    HOSTING_CONFIG,
    NETWORK,
    CellIngress,
    IngressConflict,
    RouteSpec,
    TenantIngressRoute,
    render_routes,
)

REVISION = (
    Path(__file__).resolve().parents[1]
    / "migrations/versions/20261123_0012_cell_ingress_routes.py"
)


def _route(route_id: str, domain: str, *, kind: str = "apps", target: str = "web") -> RouteSpec:
    return RouteSpec(
        route_id=route_id,
        tenant_id="t1",
        owner_kind=kind,
        owner_id=route_id.split(":")[1],
        service="web" if kind == "apps" else None,
        domain=domain,
        target=target,
        port=8080,
    )


class FakeHandle:
    runtime = "rootless"

    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.writes: dict[str, bytes] = {}
        self.removed: list[str] = []

    def inspect(self, kind: str, name: str):
        if kind == "network":
            return {}
        if name == "spanel-cell-ingress":
            return {
                "Config": {"Labels": {"spanel.role": "cell-infra"}},
            }
        return {
            "State": {"Running": True},
            "NetworkSettings": {"Networks": {NETWORK: {}}},
            "Config": {
                "Labels": {"spanel.managed": "true", "spanel.tenant": "t1"}
            },
        }

    def command(self, args: tuple[str, ...], *, input: bytes | None = None) -> bytes:
        self.commands.append(args)
        return b""

    def write_private(self, relative_path: str, content: bytes) -> str:
        self.writes[relative_path] = content
        return f"/private/{relative_path}"

    def remove_private(self, relative_path: str) -> None:
        self.removed.append(relative_path)

    def health(self):
        return type("Health", (), {"publish_port": 20020})()

    def export_volume(self, name: str):
        return iter(())

    def import_volume(self, name: str, chunks) -> None:
        return None


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


def test_render_keeps_one_default_server_and_separates_apps() -> None:
    hosting = [_route("hosting:s1", "one.example.test", kind="hosting")]
    apps = [_route("apps:a1:web", "app.example.test")]

    hosting_conf = render_routes(hosting, default_server=True).decode()
    apps_conf = render_routes(apps, default_server=False).decode()

    assert "listen 80 default_server" in hosting_conf
    assert "server_name one.example.test" in hosting_conf
    assert "proxy_pass http://web:8080" in hosting_conf
    assert "default_server" not in apps_conf
    assert "server_name app.example.test" in apps_conf
    assert "X-Forwarded-Proto $http_x_forwarded_proto" in apps_conf


def test_domain_collision_is_rejected_before_rendering(db: Session) -> None:
    handle = FakeHandle()
    cell = CellIngress(db, handle)
    cell.upsert(_route("hosting:s1", "same.example.test", kind="hosting"))

    with pytest.raises(IngressConflict):
        cell.upsert(_route("apps:a1:web", "same.example.test"))

    assert [row.route_id for row in cell.routes("t1")] == ["hosting:s1"]


def test_reconcile_renders_both_files_and_runs_nginx_test(db: Session) -> None:
    handle = FakeHandle()
    cell = CellIngress(db, handle)
    cell.upsert(_route("hosting:s1", "one.example.test", kind="hosting"))
    cell.upsert(_route("apps:a1:web", "app.example.test"))

    cell.reconcile("t1")

    assert "default_server" in handle.writes[f"ingress/{HOSTING_CONFIG}"].decode()
    assert "default_server" not in handle.writes[f"ingress/{APPS_CONFIG}"].decode()
    assert any(
        command[:2] == ("run", "--rm") and "nginx" in command
        and command[-1] == "-t"
        for command in handle.commands
    )
    assert ("exec", "spanel-cell-ingress", "nginx", "-s", "reload") in handle.commands
    assert f"ingress/{HOSTING_CONFIG}.candidate" in handle.removed
    assert f"ingress/{APPS_CONFIG}.candidate" in handle.removed


def test_kernel_revision_copies_hosting_rows() -> None:
    spec = importlib.util.spec_from_file_location("kernel_migration_0012", REVISION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE tenants (id VARCHAR(36) PRIMARY KEY)"))
            connection.execute(
                text(
                    "CREATE TABLE hosting_rootless_routes ("
                    "site_id VARCHAR(36) PRIMARY KEY, tenant_id VARCHAR(36), "
                    "domain VARCHAR(255), target VARCHAR(255), port INTEGER, "
                    "updated_at DATETIME)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO hosting_rootless_routes VALUES "
                    "('s1', 't1', 'one.example.test', 'wordpress-1', 80, "
                    "CURRENT_TIMESTAMP)"
                )
            )
        with engine.connect() as connection:
            context = MigrationContext.configure(connection)
            with Operations.context(context):
                module.upgrade()
            connection.commit()
        with engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT route_id, owner_kind, owner_id, domain, target, port "
                    "FROM tenant_ingress_routes"
                )
            ).all()
        assert rows == [
            ("hosting:s1", "hosting", "s1", "one.example.test", "wordpress-1", 80)
        ]
        with engine.connect() as connection:
            context = MigrationContext.configure(connection)
            with Operations.context(context):
                module.downgrade()
            connection.commit()
        assert "tenant_ingress_routes" not in inspect(engine).get_table_names()
    finally:
        engine.dispose()
