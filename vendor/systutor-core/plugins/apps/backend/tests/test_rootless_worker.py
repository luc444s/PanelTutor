from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from plugins.apps.backend.runtime import AppDeployError
from plugins.apps.backend.runtime.tenant_runtime import TenantRuntimeRegistry
from plugins.apps.backend.settings import AppsSettings
from plugins.apps.backend.worker import AppsWorker


class FakeRunner:
    def __init__(self, transport="local", environ=None):
        self.transport = transport
        self.environ = dict(environ or {})


def test_runner_selection_follows_injected_gate(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SPANEL_TENANTS_ROOTLESS", "false")
    assert AppsSettings.from_env().tenants_rootless is False
    global_runner = FakeRunner()
    worker = AppsWorker(lambda: None, None, runner_factory=lambda *_a: global_runner)
    assert worker._runner("t1") is global_runner

    monkeypatch.setenv("SPANEL_TENANTS_ROOTLESS", "true")
    registry = TenantRuntimeRegistry(str(tmp_path), FakeRunner)
    monkeypatch.setattr("plugins.apps.backend.worker.tenant_slug", lambda _db, _tid: "cell-a")
    worker = AppsWorker(lambda: nullcontext(None), None, runtime_registry=registry)
    runner = worker._runner("t1")
    assert runner.environ["DOCKER_HOST"] == f"unix://{tmp_path}/cells/cell-a/docker.sock"
    assert "/var/run/docker.sock" not in runner.environ["DOCKER_HOST"]


class FakeSession:
    def __init__(self, rows):
        self.rows = rows
        self.commits = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def get(self, model, key):
        return self.rows.get((model.__name__, key))

    def commit(self):
        self.commits += 1


class Routes:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.refreshed = []
        self.cleaned = []

    def refresh(self, _db, tenant_id, application_id):
        self.refreshed.append((tenant_id, application_id))
        return {"published": [] if self.fail else ["app.example.test"]}

    def cleanup(self, _db, tenant_id, application_id):
        self.cleaned.append((tenant_id, application_id))


def _cutover_worker(*, fail_route=False, recorder=None):
    app = SimpleNamespace(
        tenant_id="t1", active_deployment_id="old", status="running",
        domain="app.example.test",
    )
    deployment = SimpleNamespace(id="new", manifest={"containers": {"web": "cid"}})
    rows = {
        ("Application", "a1"): app,
        ("Deployment", "new"): deployment,
    }
    sessions = []

    def factory():
        session = FakeSession(rows)
        sessions.append(session)
        return session

    routes = Routes(fail=fail_route)
    restored_routes = []
    worker = AppsWorker(
        factory,
        None,
        runtime_registry=object(),
        runtime_recorder=recorder,
        rootless_routes=routes,
        route_refresh=lambda _db, tenant, application: restored_routes.append(
            (tenant, application)
        ),
    )
    worker._source_operation = lambda *_args: {
        "deployment_id": "new", "status": "running"
    }
    # Simulate the release executor's successful activation.
    def deploy(*_args):
        app.active_deployment_id = "new"
        return {"deployment_id": "new", "status": "running"}

    worker._source_operation = deploy
    return worker, app, routes, restored_routes


def test_runtime_is_persisted_only_after_verified_route() -> None:
    recorded = []

    def recorder(_db, tenant_id, resources, runtime):
        recorded.append((tenant_id, resources, runtime))
        return {resource: "rootful" for resource in resources}

    worker, _app, routes, _restored = _cutover_worker(recorder=recorder)
    worker._rootless_deploy("op1", "a1")
    assert routes.refreshed == [("t1", "a1")]
    assert recorded == [("t1", ["a1:web"], "rootless")]


def test_route_failure_rolls_back_without_deleting_runtime_resources() -> None:
    recorded = []
    worker, app, routes, restored = _cutover_worker(
        fail_route=True, recorder=lambda *_args: recorded.append(_args)
    )
    worker._runner = lambda _tenant: pytest.fail("rollback must not delete containers")

    with pytest.raises(AppDeployError, match="route publication"):
        worker._rootless_deploy("op1", "a1")

    assert app.active_deployment_id == "old"
    assert app.status == "running"
    assert recorded == []
    assert routes.cleaned == [("t1", "a1")]
    assert restored == [("t1", "a1")]


def test_disabled_flag_does_not_rewrite_registered_runtime(monkeypatch) -> None:
    monkeypatch.setenv("SPANEL_TENANTS_ROOTLESS", "false")
    from plugins.apps.backend.register import build_runtime_recorder

    registered = {"a1:web": "rootless"}
    recorder = build_runtime_recorder(AppsSettings.from_env())
    assert recorder is None
    assert registered == {"a1:web": "rootless"}
