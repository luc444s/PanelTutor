"""A.SPEC 0104: rootless route publication and worker hooks.

The render test uses a real ``ProxyOperations`` with an injected local file
backend and a fake runner, proving that no container validation happens. The
hook tests use fakes and never touch a database or a socket.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from plugins.apps.backend.plans_client import CellEndpoint, PlanAgentUnavailable
from plugins.apps.backend.rootless_routes import RootlessRoutes
from plugins.domains.backend.publisher import RootlessRoutePublisher
from plugins.domains.backend.proxy.config import Settings
from plugins.domains.backend.proxy.core import PathRoute
from plugins.domains.backend.proxy.detect import Detection
from plugins.domains.backend.proxy.files import LocalFiles
from plugins.domains.backend.proxy.operations import ProxyOperations
from plugins.domains.backend.proxy.transport import CommandResult

DOMAIN = "rootless-e2e.lab"


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, argv: Any, **_kwargs: object) -> CommandResult:
        argv = list(argv)
        self.calls.append(argv)
        return CommandResult(argv, 1, "", "docker is not available")


def _operations(tmp_path: Path) -> tuple[ProxyOperations, FakeRunner]:
    config = tmp_path / "dynamic"
    config.mkdir(parents=True, exist_ok=True)
    settings = Settings.from_env(
        "internal", env={"SPANEL_PROXY_CONFIG_DIR": str(config)}
    )
    runner = FakeRunner()
    operations = ProxyOperations(settings, runner, files=LocalFiles(config))
    operations._detection = Detection(
        transport="local", reason="test", config_dir=config
    )
    return operations, runner


def test_rootless_route_renders_relay_ip_without_container_validation(
    tmp_path: Path,
) -> None:
    operations, runner = _operations(tmp_path)
    publisher = RootlessRoutePublisher(operations)

    target = publisher.publish(DOMAIN, "172.18.0.1", 40003)
    assert target is not None
    text = target.read_text(encoding="utf-8")
    assert "# managed-by: spanel" in text
    assert f"Host(`{DOMAIN}`)" in text
    assert "servers:" in text and "http://172.18.0.1:40003" in text
    assert runner.calls == []  # no docker inspect / network connect at all
    assert target.name.startswith("spanel-route-") and target.suffix == ".yml"

    # Re-publishing is idempotent and unpublish is per-domain and removable.
    assert publisher.publish(DOMAIN, "172.18.0.1", 40003) == target
    assert publisher.unpublish(DOMAIN) is True
    assert publisher.unpublish(DOMAIN) is False
    assert not target.exists()


class RecordingOperations:
    def __init__(self, conflict: bool = False) -> None:
        self.conflict = conflict
        self.written: list[tuple[str, list[PathRoute], dict[str, Any]]] = []
        self.removed: list[str] = []

    def path_conflict(self, domain: str, prefix: str) -> bool:
        assert prefix == "/"
        return self.conflict

    def write_route_document(
        self, domain: str, routes: list[PathRoute], **kwargs: Any
    ) -> Path:
        self.written.append((domain, routes, kwargs))
        return Path(domain)

    def remove_route_document(self, domain: str) -> bool:
        self.removed.append(domain)
        return True


def test_publisher_calls_write_route_document_with_runtime_checks_off() -> None:
    operations = RecordingOperations()
    publisher = RootlessRoutePublisher(operations)

    publisher.publish(DOMAIN, "172.18.0.1", 40007)

    domain, routes, kwargs = operations.written[-1]
    assert domain == DOMAIN
    assert routes == [PathRoute(prefix="/", container="172.18.0.1", port=40007)]
    assert kwargs == {"validate_runtime": False, "connect_network": False}


def test_publisher_refuses_a_host_that_already_has_a_route() -> None:
    publisher = RootlessRoutePublisher(RecordingOperations(conflict=True))
    with pytest.raises(ValueError, match="already has a managed route"):
        publisher.publish(DOMAIN, "172.18.0.1", 40007)
    with pytest.raises(ValueError):
        publisher.publish(DOMAIN, "", 40007)
    with pytest.raises(ValueError):
        publisher.publish(DOMAIN, "172.18.0.1", 70000)


# --- apps plugin hooks -------------------------------------------------------


class FakeClient:
    def __init__(
        self, endpoint: CellEndpoint | None = None, error: Exception | None = None
    ) -> None:
        self.endpoint_value = endpoint
        self.error = error
        self.slugs: list[str] = []

    def endpoint(self, slug: str) -> CellEndpoint:
        self.slugs.append(slug)
        if self.error is not None:
            raise self.error
        assert self.endpoint_value is not None
        return self.endpoint_value


class FakePublisher:
    def __init__(self) -> None:
        self.published: list[tuple[str, str, int]] = []
        self.removed: list[str] = []

    def publish(self, domain: str, bind: str, relay_port: int) -> None:
        self.published.append((domain, bind, relay_port))

    def unpublish(self, domain: str) -> bool:
        self.removed.append(domain)
        return True


class _App:
    domain = DOMAIN


class _Db:
    def get(self, _model: Any, _application_id: str) -> _App:
        return _App()


def test_rootless_routes_refresh_and_cleanup_use_the_resolved_endpoint() -> None:
    endpoint = CellEndpoint(
        slug="acme",
        loopback_address="127.0.0.1",
        publish_port=20003,
        relay_port=40003,
        bind="172.18.0.1",
        allowed_sources=("172.18.0.4",),
    )
    client = FakeClient(endpoint)
    publisher = FakePublisher()
    routes = RootlessRoutes(client, publisher, slug_resolver=lambda _db, _t: "acme")

    result = routes.refresh(_Db(), "t1", "app1")

    assert result["published"] == [DOMAIN]
    assert client.slugs == ["acme"]
    assert publisher.published == [(DOMAIN, "172.18.0.1", 40003)]
    routes.cleanup(_Db(), "t1", "app1")
    assert publisher.removed == [DOMAIN]


def test_rootless_routes_fails_closed_when_the_cell_has_no_endpoint() -> None:
    client = FakeClient(error=PlanAgentUnavailable("no cell endpoint"))
    publisher = FakePublisher()
    routes = RootlessRoutes(client, publisher, slug_resolver=lambda _db, _t: "ghost")

    result = routes.refresh(_Db(), "t1", "app1")

    assert result["published"] == []
    assert client.slugs == ["ghost"]
    assert publisher.published == []
