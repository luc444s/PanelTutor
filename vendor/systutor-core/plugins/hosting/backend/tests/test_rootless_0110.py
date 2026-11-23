from __future__ import annotations

import importlib.util
import inspect as python_inspect
import urllib.error
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from plugins.hosting.backend.provisioner import Provisioner, SiteNames
from plugins.hosting.backend.rootless_ingress import (
    RootlessIngress,
    RootlessRoutePublisher,
    RouteSpec,
)
from plugins.hosting.backend.runtime import HostingRuntimeResolver
from plugins.hosting.backend.service import HostingService
from plugins.hosting.backend.settings import HostingSettings
from systutor.contracts.container_runtime import RuntimeHealth, register_container_runtime
from systutor.contracts.resource_runtime import (
    read_resource_runtime,
    register_resource_runtime_provider,
)


def _runtime_callbacks():
    def read(*_args):
        return None

    def write(*_args):
        return None

    return read, write


def test_resource_runtime_registration_is_idempotent() -> None:
    read1, write1 = _runtime_callbacks()
    read2, write2 = _runtime_callbacks()
    app = FastAPI()
    register_resource_runtime_provider(app, "tenant", read=read1, write=write1)
    # Re-registering the same provider identity (new closures, same qualname)
    # must be tolerated, as in the other contract registries.
    register_resource_runtime_provider(app, "tenant", read=read2, write=write2)
    assert read_resource_runtime(app, object(), "t1", "static", "s1") is None


def test_resource_runtime_registration_rejects_a_different_provider() -> None:
    read, write = _runtime_callbacks()
    app = FastAPI()
    register_resource_runtime_provider(app, "tenant", read=read, write=write)

    def other_read(*_args):
        return "rootful"

    try:
        register_resource_runtime_provider(app, "tenant", read=other_read, write=write)
    except ValueError:
        pass
    else:
        raise AssertionError("a different provider under an occupied name must be rejected")


class Handle:
    runtime = "rootless"

    def health(self):
        return RuntimeHealth("rootless", "ready", "acme", 101001, 20001)


def test_resolver_keeps_registered_rootless_when_flag_is_off(monkeypatch) -> None:
    monkeypatch.setenv("SPANEL_TENANTS_ROOTLESS", "false")
    app = FastAPI()
    register_resource_runtime_provider(
        app, "test", read=lambda *_: "rootless", write=lambda *_: None
    )
    handle = Handle()
    register_container_runtime(app, "rootless", lambda *_: handle)
    assert HostingRuntimeResolver(app, object()).resolve("t1", "static", "s1") is handle


def test_ingress_config_multiplexes_hosts_without_paths_or_argv() -> None:
    content = RootlessIngress.render(
        [
            RouteSpec("s2", "t1", "two.example.test", "spanel-two-web", 8080),
            RouteSpec("s1", "t1", "one.example.test", "spanel-one-web", 80),
        ]
    ).decode()
    assert "server_name one.example.test" in content
    assert "proxy_pass http://spanel-two-web:8080" in content
    assert "X-Forwarded-Proto $http_x_forwarded_proto" in content
    assert "X-Forwarded-Proto $scheme" not in content
    assert content.index("one.example.test") < content.index("two.example.test")
    assert "listen 80 default_server" in content


def test_rootless_migration_schema_is_runtime_reversible(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'migration.sqlite'}")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE tenants (id VARCHAR(36) PRIMARY KEY)")
        connection.exec_driver_sql("CREATE TABLE hosting_sites (id VARCHAR(36) PRIMARY KEY)")
    path = Path(__file__).parents[2] / "migrations/005_rootless_migration_operations.py"
    spec = importlib.util.spec_from_file_location("hosting_migration_005", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with Session(engine) as db:
        module.upgrade(db)
        assert "hosting_rootless_migrations" in inspect(engine).get_table_names()
        assert "hosting_rootless_routes" in inspect(engine).get_table_names()
        module.downgrade(db)
        assert "hosting_rootless_migrations" not in inspect(engine).get_table_names()


def test_cell_inspect_treats_not_found_as_absent(monkeypatch) -> None:
    from plugins.tenant.backend.container_runtime import RootlessCellHandle
    from systutor.contracts.container_runtime import ContainerRuntimeError

    handle = RootlessCellHandle("demo", 60070, 70, Path("/var/lib/spanel"))

    def boom(*_args, **_kwargs):
        raise ContainerRuntimeError(
            "Error response from daemon: network spanel-hosting not found"
        )

    monkeypatch.setattr(handle, "command", boom)
    assert handle.inspect("network", "spanel-hosting") is None


def test_hosting_route_publisher_propagates_plain_http_flag() -> None:
    published = []

    class Publisher:
        def publish(self, domain, bind, port, *, https):
            published.append((domain, bind, port, https))

    class Routes:
        publisher = Publisher()
        slug_resolver = staticmethod(lambda _db, _tenant_id: "demo")

        @staticmethod
        def endpoint(_slug):
            return type("Endpoint", (), {"bind": "127.1.2.3", "relay_port": 20003})()

        @staticmethod
        def _https():
            return False

    app = FastAPI()
    app.state.rootless_routes = Routes()
    assert (
        RootlessRoutePublisher(app, object()).publish(
            "tenant-1", "site.example.test"
        )
        is False
    )
    assert published == [("site.example.test", "127.1.2.3", 20003, False)]


def test_external_verification_uses_the_published_scheme(monkeypatch) -> None:
    seen = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    def urlopen(request, **_kwargs):
        seen.append(request.full_url)
        return Response()

    monkeypatch.setattr(
        "plugins.hosting.backend.rootless_ingress.urllib.request.urlopen", urlopen
    )
    HostingService._verify_external("site.test", https=True)
    HostingService._verify_external("site.test", https=False)
    assert seen == ["https://site.test/", "http://site.test/"]


def test_external_verification_retries_until_route_is_ready(monkeypatch) -> None:
    attempts = 0
    sleeps = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    def urlopen(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise urllib.error.HTTPError("http://site.test/", 404, "Not Found", {}, None)
        return Response()

    monkeypatch.setattr(
        "plugins.hosting.backend.rootless_ingress.urllib.request.urlopen", urlopen
    )
    monkeypatch.setattr("plugins.hosting.backend.rootless_ingress.time.sleep", sleeps.append)
    HostingService._verify_external("site.test", deadline_seconds=5)
    assert attempts == 3
    assert sleeps == [0.25, 0.5]


def test_external_verification_stops_at_deadline(monkeypatch) -> None:
    attempts = 0

    def urlopen(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        raise urllib.error.HTTPError("http://site.test/", 404, "Not Found", {}, None)

    monkeypatch.setattr(
        "plugins.hosting.backend.rootless_ingress.urllib.request.urlopen", urlopen
    )
    try:
        HostingService._verify_external("site.test", deadline_seconds=0)
    except RuntimeError as exc:
        assert "before deadline" in str(exc)
    else:
        raise AssertionError("verification must fail once its deadline expires")
    assert attempts == 1


def test_delete_purges_migration_history_before_the_site() -> None:
    from sqlalchemy.dialects import postgresql

    from plugins.hosting.backend.models import RootlessMigrationOperation

    executed = []

    class Db:
        def execute(self, statement):
            executed.append(
                str(statement.compile(dialect=postgresql.dialect()))
            )

    service = object.__new__(HostingService)
    service._db = Db()
    service._purge_migration_history("site-1")
    assert len(executed) == 1
    assert "DELETE FROM hosting_rootless_migrations" in executed[0]
    assert "hosting_rootless_migrations.site_id" in executed[0]
    assert RootlessMigrationOperation.__tablename__ == "hosting_rootless_migrations"


def test_migration_cleanup_selects_the_site_provisioner(monkeypatch) -> None:
    from plugins.hosting.backend import rootless_migration

    calls = []

    class StaticCleaner:
        def __init__(self, _settings, runtime):
            self.runtime = runtime

        def cleanup(self, names, tenant_id):
            calls.append(("static", names.container, tenant_id, self.runtime))
            return []

    class WordPressCleaner:
        def __init__(self, _settings, runtime):
            self.runtime = runtime

        def cleanup(self, names, tenant_id):
            calls.append(("wordpress", names.wp, tenant_id, self.runtime))
            return []

    monkeypatch.setattr(rootless_migration, "StaticProvisioner", StaticCleaner)
    monkeypatch.setattr(rootless_migration, "Provisioner", WordPressCleaner)
    service = object.__new__(rootless_migration.RootlessMigrationService)
    service.settings = HostingSettings()
    runtime = object()
    static = SimpleNamespace(
        kind="static", container_name="spanel-legacy-web", tenant_id="t1"
    )
    wordpress = SimpleNamespace(
        kind="wordpress", container_name="spanel-blog-wp", tenant_id="t1"
    )
    assert service._cleanup_runtime(static, runtime) == []
    assert service._cleanup_runtime(wordpress, runtime) == []
    assert calls == [
        ("static", "spanel-legacy-web", "t1", runtime),
        ("wordpress", "spanel-blog-wp", "t1", runtime),
    ]


def test_migration_removes_rootful_route_before_rootless_publish() -> None:
    from plugins.hosting.backend.rootless_migration import RootlessMigrationService

    source = python_inspect.getsource(RootlessMigrationService.migrate)
    unpublish = source.index("rootful_publisher.unpublish(site.domain)")
    publish = source.index("RootlessRoutePublisher(self.app, self.db).publish")
    assert unpublish < publish


def test_wordpress_migration_retries_database_readiness() -> None:
    from plugins.hosting.backend.rootless_migration import RootlessMigrationService

    source = python_inspect.getsource(RootlessMigrationService._wordpress)
    assert 'candidate._wait(' in source
    assert '"migrated WordPress database"' in source


def test_rootless_wordpress_cleanup_removes_containers_before_network(monkeypatch) -> None:
    commands = []

    class Runtime:
        runtime = "rootless"

        def command(self, args, *, input=None):
            commands.append(args)
            return b""

    provisioner = Provisioner(HostingSettings(docker_transport="local"), Runtime())
    monkeypatch.setattr(provisioner, "_owned", lambda *_args: True)
    assert provisioner.cleanup(SiteNames("example"), "tenant-1") == []
    assert commands[:3] == [
        ("rm", "-f", "spanel-example-wp"),
        ("rm", "-f", "spanel-example-db"),
        ("network", "rm", "spanel-example-private"),
    ]
