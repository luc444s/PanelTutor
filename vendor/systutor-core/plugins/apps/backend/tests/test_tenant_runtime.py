from __future__ import annotations

import json
from pathlib import Path

import pytest

from plugins.apps.backend.runtime import tenant_runtime as tr
from plugins.apps.backend.runtime.tenant_runtime import (
    DockerRootlessRuntime,
    FakeTenantRuntime,
    TenantRuntime,
    TenantRuntimeRegistry,
    validate_slug,
)
from plugins.apps.backend.runtime.types import AppDeployError


class FakeRunner:
    def __init__(self, transport: str = "local", environ: dict[str, str] | None = None):
        self.transport = transport
        self.environ = dict(environ or {})
        self.calls: list[list[str]] = []

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        return argv


def _runtime(tmp_path: Path, runner_factory=FakeRunner) -> DockerRootlessRuntime:
    return DockerRootlessRuntime("cell-g", str(tmp_path), runner_factory)


def test_slug_validation_is_strict() -> None:
    assert validate_slug("cell-g") == "cell-g"
    for bad in ("../etc", "CELL", "cell_g", "", "a" * 63, 7):
        with pytest.raises(AppDeployError):
            validate_slug(bad)


def test_socket_and_environment_are_derived_only_from_slug(tmp_path) -> None:
    runtime = _runtime(tmp_path)
    assert runtime.socket_path == f"{tmp_path}/cells/cell-g/docker.sock"
    assert runtime.environment()["DOCKER_HOST"] == f"unix://{runtime.socket_path}"
    assert "/var/run/docker.sock" not in runtime.socket_path


def test_cross_tenant_call_is_refused(tmp_path) -> None:
    runtime = _runtime(tmp_path)
    with pytest.raises(AppDeployError):
        runtime.status("cell-h")
    with pytest.raises(AppDeployError):
        runtime.exec_probe("cell-h", ["docker", "ps"])


def test_status_is_degraded_without_live_evidence(tmp_path) -> None:
    (tmp_path / "registry.json").write_text(
        json.dumps({"allocations": {"cell-g": {"uid": 60008}}})
    )
    runtime = _runtime(tmp_path)
    status = runtime.status()
    assert status["state"] == "degraded"
    assert status["apparmor"]["effective"] is False
    assert status["uid_map"] == []


def test_status_reports_effective_only_with_real_proc_evidence(tmp_path, monkeypatch) -> None:
    (tmp_path / "registry.json").write_text(
        json.dumps({"allocations": {"cell-g": {"uid": 60008}}})
    )
    runtime = _runtime(tmp_path)
    monkeypatch.setattr(tr, "_main_pid", lambda slug: 4242)
    monkeypatch.setattr(tr, "_dockerd_pid", lambda pid: 4243)
    monkeypatch.setattr(
        tr,
        "_uid_map",
        lambda pid: [{"inner_id": 0, "host_id": 60008, "count": 1}],
    )
    real_read = tr._read

    def fake_read(path: Path) -> str:
        if str(path) == "/proc/4242/attr/current":
            return "spanel-cell-cell-g (enforce)\n"
        return real_read(path)

    monkeypatch.setattr(tr, "_read", fake_read)
    status = runtime.status()
    assert status["state"] == "ready"
    assert status["apparmor"]["effective"] is True
    assert status["apparmor"]["profile"] == "spanel-cell-cell-g"
    assert status["uid_map"][0]["host_id"] == 60008


def test_runtime_delegates_docker_commands_to_its_socket(tmp_path) -> None:
    runners: list[FakeRunner] = []

    def factory(transport="local", environ=None):
        runner = FakeRunner(transport, environ)
        runners.append(runner)
        return runner

    runtime = _runtime(tmp_path, factory)
    runtime.build("cell-g", Path("/tmp/release"), "img:tag")
    runtime.up("cell-g", [Path("compose.yml")], {"x": 1})
    runtime.down("cell-g", "proj")
    runtime.logs("cell-g", "proj", "web")
    runtime.exec_probe("cell-g", ["docker", "inspect", "web"])
    assert len(runners) == 5
    assert all(r.calls[0][0] == "docker" for r in runners)
    assert all(r.environ["DOCKER_HOST"] == f"unix://{runtime.socket_path}" for r in runners)


def test_fake_runtime_records_calls() -> None:
    fake = FakeTenantRuntime("cell-g")
    assert isinstance(fake, TenantRuntime)
    fake.up("cell-g", [Path("c.yml")])
    fake.exec_probe("cell-g", ["true"])
    assert [verb for verb, _ in fake.calls] == ["up", "exec_probe"]


def test_registry_validates_slug_and_binds_data_root(tmp_path) -> None:
    registry = TenantRuntimeRegistry(str(tmp_path), FakeRunner)
    runtime = registry.for_tenant("tenant-1", "cell-g")
    assert runtime.socket_path == f"{tmp_path}/cells/cell-g/docker.sock"
    with pytest.raises(AppDeployError):
        registry.for_tenant("tenant-1", "../escape")


def test_worker_default_runner_is_unchanged() -> None:
    from plugins.apps.backend.worker import AppsWorker

    captured: list[str] = []

    def factory(transport: str = "local"):
        captured.append(transport)
        return FakeRunner(transport)

    worker = AppsWorker(lambda: None, None, runner_factory=factory)
    worker._runner("tenant-1")
    assert captured == ["local"]


def test_worker_uses_registry_for_authenticated_tenant(tmp_path, monkeypatch) -> None:
    from plugins.apps.backend import worker as worker_module

    registry = TenantRuntimeRegistry(str(tmp_path), FakeRunner)
    monkeypatch.setattr(worker_module, "tenant_slug", lambda db, tid: "cell-g")

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    worker = worker_module.AppsWorker(_Session, None, runtime_registry=registry)
    runner = worker._runner("tenant-1")
    assert runner.environ["DOCKER_HOST"] == f"unix://{tmp_path}/cells/cell-g/docker.sock"
