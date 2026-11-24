from __future__ import annotations

import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from plugins.apps.backend.plans_client import CellEndpoint
from plugins.apps.backend.rootless_routes import RootlessRoutes
from plugins.apps.backend.runtime import AppDeployError
from plugins.apps.backend.runtime.probes import (
    MAX_APP_MEMORY,
    check_isolation,
)
from plugins.apps.backend.runtime.tenant_plan import (
    TenantPlan,
    bind_tenant_plan,
    service_limits,
)
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
    assert runner.environ["SPANEL_APPS_PROBE_BASELINE"] == "rootless"
    assert "/var/run/docker.sock" not in runner.environ["DOCKER_HOST"]


def test_ingress_publish_comes_from_the_cell_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(
        "plugins.apps.backend.worker.tenant_slug", lambda _db, _tid: "cell-a"
    )
    worker = AppsWorker(
        lambda: nullcontext(None), None, rootless_routes=Routes()
    )
    assert worker._ingress_publish("t1") == ("127.9.1.1", 20020)


def test_ingress_publish_is_inert_without_a_route_client() -> None:
    worker = AppsWorker(lambda: nullcontext(None), None, rootless_routes=object())
    assert worker._ingress_publish("t1") is None


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
        from fastapi import FastAPI

        from systutor.contracts.app_hosts import AppHost, register_app_host_provider

        self.fail = fail
        self.refreshed = []
        self.cleaned = []
        self.app = FastAPI()
        register_app_host_provider(
            self.app,
            "fake",
            lambda _db, _tenant, _application: [
                AppHost(
                    "a1:web", "a1", "web", "app.example.test", True, 8080
                )
            ],
        )

    def endpoint(self, slug):
        return CellEndpoint(
            slug=slug,
            loopback_address="127.9.1.1",
            publish_port=20020,
            relay_port=40020,
            bind="172.25.0.1",
        )

    def refresh(self, _db, tenant_id, application_id):
        self.refreshed.append((tenant_id, application_id))
        return {"published": [] if self.fail else ["app.example.test"]}

    def cleanup(self, _db, tenant_id, application_id):
        self.cleaned.append((tenant_id, application_id))


def _cutover_worker(*, fail_route=False, recorder=None):
    app = SimpleNamespace(
        tenant_id="t1", active_deployment_id="old", status="running",
    )
    deployment = SimpleNamespace(id="new", manifest={"containers": {"web": "cid"}})
    rows = {
        ("Application", "a1"): app,
        ("Deployment", "new"): deployment,
        ("Tenant", "t1"): SimpleNamespace(slug="cell-a"),
    }
    sessions = []

    def factory():
        session = FakeSession(rows)
        sessions.append(session)
        return session

    routes = Routes(fail=fail_route)
    restored_routes = []
    ingress = []
    worker = AppsWorker(
        factory,
        None,
        runtime_registry=object(),
        runtime_recorder=recorder,
        rootless_routes=routes,
        apps_ingress=lambda _db, tenant, application: ingress.append(
            (tenant, application)
        ),
        route_refresh=lambda _db, tenant, application: restored_routes.append(
            (tenant, application)
        ),
    )
    worker._source_operation = lambda *_args: {
        "deployment_id": "new", "status": "running"
    }
    # Simulate the release executor's successful activation.
    def deploy(*_args, **_kwargs):
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


def test_rollback_restores_route_and_never_records_runtime() -> None:
    """A real cutover failure must restore route + runtime before recording."""
    recorded = []
    worker, app, routes, restored = _cutover_worker(
        recorder=lambda db, tenant, resources, runtime: recorded.append(
            (tenant, list(resources), runtime)
        )
    )

    def fail_refresh(*_args):
        raise AppDeployError("route publication failed")

    worker.rootless_routes.refresh = fail_refresh

    with pytest.raises(AppDeployError, match="route publication"):
        worker._rootless_deploy("op1", "a1")

    assert app.active_deployment_id == "old"  # previous deployment restored
    assert app.status == "running"
    assert recorded == []  # runtime was never switched to rootless
    assert routes.cleaned == [("t1", "a1")]
    assert restored == [("t1", "a1")]  # rootful route refreshed again


# --- A.SPEC 0109-R3: aggregate 2 GiB plan and public Host publication --------


class _IsolationRunner:
    """Minimal runner that reports one running container to the probe."""

    transport = "local"

    def __init__(self, memory_bytes: int) -> None:
        self.memory_bytes = memory_bytes

    def run(self, argv, **_kwargs):
        if argv[:3] == ["docker", "container", "inspect"]:
            payload = [{
                "State": {"Status": "running", "RestartCount": 0},
                "HostConfig": {
                    "Privileged": False,
                    "Devices": [],
                    "PortBindings": {},
                    "PidMode": "",
                    "NetworkMode": "proj_default",
                    "CapDrop": ["ALL"],
                    "SecurityOpt": [
                        "no-new-privileges:true", "apparmor=docker-default",
                        "seccomp=builtin",
                    ],
                    "Runtime": "runc",
                    "PidsLimit": 256,
                    "Memory": self.memory_bytes,
                    "NanoCpus": 1_000_000_000,
                    "ReadonlyRootfs": False,
                },
                "AppArmorProfile": "docker-default",
                "Config": {"User": "10001:10002"},
                "Mounts": [],
                "NetworkSettings": {"Networks": {"proj_default": {}}},
            }]
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload))
        if argv[:2] == ["docker", "top"]:
            return SimpleNamespace(returncode=0, stdout="PID UID\n1 10001\n")
        if argv[:3] == ["docker", "network", "inspect"]:
            return SimpleNamespace(returncode=0, stdout="true")
        return SimpleNamespace(returncode=0, stdout="")


def test_aggregate_2gb_plan_allows_a_three_service_deploy_from_the_start() -> None:
    plan = TenantPlan(
        memory_bytes=2147483648, cpus=1.0, pids=512, tenant_slug="acme"
    )
    services = {name: {} for name in ("backend", "database", "frontend")}
    derived = service_limits(plan, services)
    per_service = derived["backend"]["mem_limit"]

    # The split itself is unchanged: three equal shares within the aggregate.
    assert per_service > MAX_APP_MEMORY
    assert sum(item["mem_limit"] for item in derived.values()) <= plan.memory_bytes
    assert derived["backend"] == derived["database"] == derived["frontend"]

    runner = _IsolationRunner(per_service)
    # Without a plan the platform injects no limits, so the probe does not
    # require them (A.SPEC 0109-R removed the fixed defaults).
    assert check_isolation(runner, {"backend": "cid"})
    # With the tenant plan bound for the deploy, the 2 GiB aggregate is the
    # ceiling, so the very first deploy is accepted (no lab re-deploy at 1.4 GB).
    with bind_tenant_plan(plan):
        evidence = check_isolation(runner, {"backend": "cid"})
    assert evidence["backend"]["limits"]["memory"] == per_service
    assert evidence["backend"]["memory_budget_bytes"] == 2147483648


def test_public_surface_domain_is_published_as_the_host() -> None:
    published = []

    class Publisher:
        def publish(self, domain, bind, relay_port, https=True):
            published.append((domain, bind, relay_port, https))

        def unpublish(self, domain):
            return True

    class Client:
        def endpoint(self, slug):
            return CellEndpoint(
                slug=slug,
                loopback_address="127.9.1.1",
                publish_port=20020,
                relay_port=40020,
                bind="172.25.0.1",
            )

    from fastapi import FastAPI

    from systutor.contracts.app_hosts import AppHost, register_app_host_provider

    app = FastAPI()
    register_app_host_provider(
        app,
        "fake",
        lambda _db, _tenant, _application: [
            AppHost("a1:web", "a1", "web", "editor.lab", False, 8080)
        ],
    )
    routes = RootlessRoutes(
        Client(), Publisher(), slug_resolver=lambda _db, _t: "acme",
        https=False, app=app,
    )
    result = routes.refresh(SimpleNamespace(), "t1", "a1")

    assert published == [("editor.lab", "172.25.0.1", 40020, False)]
    assert result["host"] == "editor.lab"
    assert result["published"] == ["editor.lab"]

    # No Host assigned in Domains -> nothing is published.
    published.clear()
    routes = RootlessRoutes(
        Client(), Publisher(), slug_resolver=lambda _db, _t: "acme", https=False
    )
    routes.refresh(SimpleNamespace(), "t1", "a1")
    assert published == []
