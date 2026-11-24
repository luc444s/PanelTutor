from __future__ import annotations

import inspect
from types import SimpleNamespace

from plugins.hosting.backend.rootless_migration import (
    RootlessMigrationService,
    shared_network_name,
)


def test_shared_network_name_is_stable_and_bounded() -> None:
    assert shared_network_name("milton") == "spanel-milton-shared-db"
    long = "a" * 63
    name = shared_network_name(long)
    assert len(name) <= 63
    assert name.startswith("spanel-")
    assert shared_network_name(long) == name


def test_wordpress_accepts_an_explicit_shared_database() -> None:
    signature = inspect.signature(RootlessMigrationService._wordpress)
    assert "shared_db" in signature.parameters
    assert signature.parameters["shared_db"].default is None


def test_migrate_accepts_an_explicit_shared_database() -> None:
    signature = inspect.signature(RootlessMigrationService.migrate)
    assert "shared_db" in signature.parameters
    assert signature.parameters["shared_db"].default is None


def test_database_name_uses_the_shared_alias_resolver(monkeypatch) -> None:
    """WORDPRESS_DB_HOST=db is a network alias, not a container name."""
    service = object.__new__(RootlessMigrationService)
    site = SimpleNamespace(kind="wordpress", container_name="legalattorney-clean")
    info = {"Config": {"Env": ["WORDPRESS_DB_HOST=db:3306"]}}

    class Source:
        def inspect(self, kind, name):
            if name == site.container_name:
                return info
            if name == "legalattorney-clean-db":
                return {"State": {"Running": True}}
            return None

        def command(self, args, *, input=None):
            return b""

    seen: dict[str, object] = {}

    def fake_resolve(env, container_name, payload, *, inspector, resolve_alias, **kwargs):
        seen["runtime"] = env.get("_SPANEL_RUNTIME_HANDLE")
        seen["payload"] = payload
        assert container_name == site.container_name
        assert inspector("db") is None
        return ("db:3306", "legalattorney-clean-db", "wp_clean", "user", "pw")

    monkeypatch.setattr(
        "plugins.hosting.backend.rootless_migration.resolve_database_binding",
        fake_resolve,
    )

    assert service._database_name(site, Source()) == "legalattorney-clean-db"
    assert seen["runtime"] is not None
    assert seen["payload"] == info


def test_database_name_falls_back_when_the_alias_is_ambiguous(monkeypatch) -> None:
    """Several containers may declare `db`; the site-named container wins."""
    service = object.__new__(RootlessMigrationService)
    site = SimpleNamespace(kind="wordpress", container_name="legalattorney-clean")
    info = {"Config": {"Env": ["WORDPRESS_DB_HOST=db"]}}

    class Source:
        def inspect(self, kind, name):
            if name == site.container_name:
                return info
            if name == "legalattorney-clean-db":
                return {"State": {"Running": True}}
            return None

        def command(self, args, *, input=None):
            return b""

    monkeypatch.setattr(
        "plugins.hosting.backend.rootless_migration.resolve_database_binding",
        lambda *_a, **_k: ("db", "db", "wp_clean", "user", "pw"),
    )

    assert service._database_name(site, Source()) == "legalattorney-clean-db"


def test_database_name_is_none_for_non_wordpress() -> None:
    service = object.__new__(RootlessMigrationService)
    site = SimpleNamespace(kind="static", container_name="legalattorney-static")
    assert service._database_name(site, object()) is None


class FakeTarget:
    def __init__(self) -> None:
        self.commands: list[tuple] = []
        self.containers: dict[str, dict] = {}
        self.networks: set[str] = set()
        self.volumes: set[str] = set()
        self.imports: list[str] = []
        self.writes: dict[str, bytes] = {}

    def inspect(self, kind: str, name: str):
        if kind == "container":
            return self.containers.get(name)
        if kind == "network":
            return {} if name in self.networks else None
        if kind == "volume":
            return {} if name in self.volumes else None
        return None

    def command(self, args: tuple) -> bytes:
        self.commands.append(args)
        if args[:2] == ("network", "create"):
            self.networks.add(args[-1])
        if args[:2] == ("volume", "create"):
            self.volumes.add(args[-1])
        if args[:2] == ("run", "-d"):
            self.containers[args[args.index("--name") + 1]] = {
                "State": {"Running": True}
            }
        return b""

    def write_private(self, path: str, content: bytes) -> str:
        self.writes[path] = content
        return f"/private/{path}"

    def import_volume(self, name: str, chunks) -> None:
        self.imports.append(name)
        list(chunks)


class FakeSource:
    def __init__(self) -> None:
        self.stopped: list[tuple] = []

    def command(self, args: tuple) -> bytes:
        self.stopped.append(args)
        return b""

    def export_volume(self, name: str):
        return iter([b"snapshot"])


def shared_service() -> RootlessMigrationService:
    service = object.__new__(RootlessMigrationService)
    service.settings = SimpleNamespace(db_image="mariadb:11")
    service._stop_shared_db_consumers = lambda *_args: None  # type: ignore[method-assign]
    service._wait_container = lambda *_args: None  # type: ignore[method-assign]
    return service


def test_shared_database_is_copied_once_and_started_on_its_network() -> None:
    service = shared_service()
    target = FakeTarget()
    source = FakeSource()
    site = SimpleNamespace(tenant_id="tenant-1", container_name="spanel-demo-wp")
    database = {
        "Config": {
            "Env": ["MYSQL_ROOT_PASSWORD=secret"],
            "Image": "mariadb:11.7",
        },
        "Mounts": [
            {
                "Type": "volume",
                "Name": "mariadb_data",
                "Destination": "/var/lib/mysql",
            }
        ],
    }
    service._ensure_shared_database(
        "mariadb",
        source,
        target,
        site,
        database,
        "spanel-milton-shared-db",
    )
    assert ("stop", "mariadb") in source.stopped
    assert "mariadb_data" in target.imports
    assert "spanel-milton-shared-db" in target.networks
    run = next(args for args in target.commands if args[:2] == ("run", "-d"))
    assert "--name" in run and run[run.index("--name") + 1] == "mariadb"
    assert run[run.index("--network") + 1] == "spanel-milton-shared-db"
    assert "mariadb/db.env" in target.writes

    # A second WordPress site reuses the running shared database.
    target.imports.clear()
    service._ensure_shared_database(
        "mariadb",
        source,
        target,
        site,
        database,
        "spanel-milton-shared-db",
    )
    assert target.imports == []
