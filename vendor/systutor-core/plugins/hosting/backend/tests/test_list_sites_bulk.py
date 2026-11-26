"""The site list does one Docker inspect per daemon, not one per site (A.SPEC 0121)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import systutor.kernel.models  # noqa: F401
from plugins.hosting.backend import inspection as inspection_module
from plugins.hosting.backend import runtime as runtime_module
from plugins.hosting.backend import service as service_module
from plugins.hosting.backend.inspection import inspect_many_containers
from plugins.hosting.backend.models import HostingSite
from plugins.hosting.backend.service import HostingService
from plugins.hosting.backend.settings import HostingSettings
from plugins.hosting.backend.transport import build_docker_argv
from plugins.tenant.backend import container_runtime
from plugins.tenant.backend.container_runtime import RootlessCellProvider
from systutor.contracts.container_runtime import ContainerRuntimeError, RuntimeHealth
from systutor.core.database import Base
from systutor.kernel.tenants.models import Tenant

NAMES = ["spanel-alpha", "spanel-beta", "spanel-gamma"]


def inspect_payload(name: str, *, status: str = "running", managed: str = "true") -> dict:
    return {
        "Name": f"/{name}",
        "Config": {
            "Image": "wordpress:latest",
            "Labels": {"spanel.site": name, "spanel.managed": managed},
        },
        "State": {"Status": status},
    }


class BulkHandle:
    runtime = "rootful"

    def __init__(self, payloads: dict[str, dict], *, absent: set[str] | None = None) -> None:
        self.payloads = payloads
        self.absent = absent or set()
        self.bulk_calls: list[list[str]] = []
        self.inspect_calls: list[str] = []
        self.health_calls = 0

    def inspect_many(self, names: list[str]) -> dict[str, dict | None]:
        self.bulk_calls.append(list(names))
        return {
            name: None if name in self.absent else self.payloads[name] for name in names
        }

    def inspect(self, _kind: str, name: str) -> dict | None:
        self.inspect_calls.append(name)
        return None if name in self.absent else self.payloads.get(name)

    def health(self) -> RuntimeHealth:
        self.health_calls += 1
        return RuntimeHealth("rootful", "ready")


class PerSiteHandle:
    """A third-party handle that still only implements single `inspect`."""

    runtime = "rootful"

    def __init__(self, payloads: dict[str, dict]) -> None:
        self.payloads = payloads
        self.inspect_calls: list[str] = []

    def inspect(self, _kind: str, name: str) -> dict | None:
        self.inspect_calls.append(name)
        return self.payloads.get(name)


class _Db:
    def __init__(self, slug: str) -> None:
        self._tenant = SimpleNamespace(slug=slug)

    def get(self, _model, _key):
        return self._tenant


def install_resolver(monkeypatch, handle) -> list[tuple[str, str, str, bool]]:
    calls: list[tuple[str, str, str, bool]] = []

    class Resolver:
        def __init__(self, _app, _db) -> None:
            pass

        def resolve(self, tenant_id, kind, site_id, *, check_health=True):
            calls.append((tenant_id, kind, site_id, check_health))
            return handle

    monkeypatch.setattr(service_module, "HostingRuntimeResolver", Resolver)
    return calls


def app_with_runtime_registry() -> FastAPI:
    app = FastAPI()
    app.state.resource_runtime_registry_providers = {"test": object()}
    return app


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'bulk.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Tenant(id="t1", name="Tenant", slug="tenant"))
        session.commit()
        yield session
    engine.dispose()


@pytest.fixture(autouse=True)
def clear_registry_cache():
    container_runtime._registry_cache.clear()
    yield
    container_runtime._registry_cache.clear()


def seed_sites(db: Session, names: list[str]) -> None:
    for index, name in enumerate(names):
        db.add(
            HostingSite(
                id=f"s{index}",
                tenant_id="t1",
                container_name=name,
                domain=f"{name}.test",
                kind="wordpress",
            )
        )
    db.commit()


def test_bulk_inspect_maps_names_and_tolerates_a_partial_exit() -> None:
    stdout = "\n".join(
        json.dumps(payload) for payload in (inspect_payload("a"), inspect_payload("b"))
    )

    def runner(args: tuple[str, ...]) -> tuple[int, str]:
        assert args[:3] == ("inspect", "--format", "{{json .}}")
        return 1, stdout  # docker exits 1 when one requested name is missing

    result = inspect_many_containers(["a", "b", "gone"], command=runner)

    assert list(result) == ["a", "b", "gone"]
    assert result["a"]["Name"] == "/a"
    assert result["b"]["State"]["Status"] == "running"
    assert result["gone"] is None


def test_bulk_inspect_splits_names_in_batches_of_fifty() -> None:
    batches: list[int] = []

    def runner(args: tuple[str, ...]) -> tuple[int, str]:
        batches.append(len(args) - 3)
        return 0, ""

    names = [f"site-{index}" for index in range(51)]
    result = inspect_many_containers(names, command=runner)

    assert batches == [50, 1]
    assert all(value is None for value in result.values())


def test_bulk_inspect_uses_one_command_over_the_rootful_transport(monkeypatch) -> None:
    argv_calls: list[list[str]] = []

    def fake_run(argv, *, env, timeout=30, input=None):
        argv_calls.append(argv)
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(inspect_payload("a")) + "\n",
        )
        return completed

    monkeypatch.setattr(inspection_module, "run", fake_run)

    result = inspect_many_containers(["a", "b"], env={"SPANEL_DOCKER_TRANSPORT": "local"})

    assert argv_calls == [["sh", "-c", "docker inspect --format '{{json .}}' a b"]]
    assert result["a"]["Name"] == "/a"
    assert result["b"] is None


def test_list_sites_resolves_once_and_inspects_once_per_tenant(db, monkeypatch) -> None:
    seed_sites(db, NAMES)
    payloads = {name: inspect_payload(name) for name in NAMES[:2]}
    handle = BulkHandle(payloads, absent={NAMES[2]})
    resolve_calls = install_resolver(monkeypatch, handle)
    service = HostingService(
        db,
        settings=HostingSettings(docker_transport="local"),
        app=app_with_runtime_registry(),
    )

    listed = service.list_sites("t1")

    assert resolve_calls == [("t1", "wordpress", "s0", False)]
    assert handle.bulk_calls == [NAMES]
    assert handle.inspect_calls == []
    assert handle.health_calls == 0
    by_name = {site.container_name: site for site in listed.sites}
    assert by_name[NAMES[0]].status == "running"
    assert by_name[NAMES[0]].managed is True
    assert by_name[NAMES[0]].kind == "wordpress"
    assert by_name[NAMES[1]].status == "running"
    assert by_name[NAMES[2]].status == "missing"
    assert by_name[NAMES[2]].managed is False


def test_list_sites_falls_back_to_per_site_inspect_for_a_plain_handle(db, monkeypatch) -> None:
    seed_sites(db, NAMES)
    handle = PerSiteHandle({name: inspect_payload(name) for name in NAMES})
    install_resolver(monkeypatch, handle)
    service = HostingService(
        db,
        settings=HostingSettings(docker_transport="local"),
        app=app_with_runtime_registry(),
    )

    listed = service.list_sites("t1")

    assert handle.inspect_calls == NAMES
    assert [site.status for site in listed.sites] == ["running"] * 3


def test_resolve_skips_health_when_asked_but_keeps_it_by_default(monkeypatch) -> None:
    handle = BulkHandle({})
    monkeypatch.setattr(runtime_module, "read_resource_runtime", lambda *args, **kwargs: "rootless")
    monkeypatch.setattr(runtime_module, "resolve_container_runtime", lambda *args, **kwargs: handle)
    resolver = runtime_module.HostingRuntimeResolver(FastAPI(), object())

    assert resolver.resolve("t1", "wordpress", "s1", check_health=False) is handle
    assert handle.health_calls == 0

    assert resolver.resolve("t1", "wordpress", "s1") is handle
    assert handle.health_calls == 1


def test_registry_cache_reads_once_until_the_mtime_changes(tmp_path, monkeypatch) -> None:
    registry = {"allocations": {"tenant": {"uid": 60001, "index": 1}}}
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    reads: list[Path] = []
    original = Path.read_text

    def counting_read(self, *args, **kwargs):
        reads.append(self)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counting_read)
    provider = RootlessCellProvider(str(tmp_path))

    assert provider(_Db("tenant"), "t1")._slug == "tenant"
    assert provider(_Db("tenant"), "t1")._slug == "tenant"
    assert len(reads) == 1

    path.write_text(json.dumps(registry), encoding="utf-8")
    future = path.stat().st_mtime_ns + 1_000_000_000
    os.utime(path, ns=(future, future))

    assert provider(_Db("tenant"), "t1")._slug == "tenant"
    assert len(reads) == 2


def test_registry_cache_fails_closed_when_the_file_disappears(tmp_path) -> None:
    registry = {"allocations": {"tenant": {"uid": 60001, "index": 1}}}
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    provider = RootlessCellProvider(str(tmp_path))
    assert provider(_Db("tenant"), "t1")._slug == "tenant"

    path.unlink()

    with pytest.raises(ContainerRuntimeError):
        provider(_Db("tenant"), "t1")


def test_build_docker_argv_without_control_path_is_unchanged(monkeypatch) -> None:
    monkeypatch.delenv("SPANEL_DOCKER_SSH_CONTROL_PATH", raising=False)
    env = {
        "MAIL_SERVER_PASSWORD": "secret",
        "SPANEL_DOCKER_SSH_HOST": "docker.example",
        "SPANEL_DOCKER_SSH_USER": "spanel",
        "SPANEL_DOCKER_SSH_PORT": "2222",
    }

    assert build_docker_argv("docker ps", env=env) == [
        "sshpass",
        "-e",
        "ssh",
        "-p",
        "2222",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "LogLevel=ERROR",
        "spanel@docker.example",
        "docker ps",
    ]


def test_build_docker_argv_reuses_the_ssh_connection(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("SPANEL_DOCKER_SSH_CONTROL_PATH", raising=False)
    control = tmp_path / "ssh" / "cm"
    env = {
        "MAIL_SERVER_PASSWORD": "secret",
        "SPANEL_DOCKER_SSH_HOST": "docker.example",
        "SPANEL_DOCKER_SSH_USER": "spanel",
        "SPANEL_DOCKER_SSH_PORT": "2222",
        "SPANEL_DOCKER_SSH_CONTROL_PATH": str(control),
    }

    argv = build_docker_argv("docker ps", env=env)

    assert "ControlMaster=auto" in argv
    assert f"ControlPath={control}" in argv
    assert any(part.startswith("ControlPersist=") for part in argv)
    assert "secret" not in argv
    assert "secret" not in " ".join(argv)
    assert (tmp_path / "ssh").stat().st_mode & 0o777 == 0o700
