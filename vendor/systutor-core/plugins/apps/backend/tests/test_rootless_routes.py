"""A.SPEC 0106: opt-in HTTPS for rootless-backed app routes.

Settings and propagation are tested with fakes only: no socket, no database,
no Traefik and no cell endpoint is touched.
"""

from __future__ import annotations

from typing import Any

import pytest

from plugins.apps.backend.plans_client import CellEndpoint, PlanAgentUnavailable
from plugins.apps.backend.rootless_routes import RootlessRoutes
from plugins.apps.backend.settings import AppsSettings

DOMAIN = "rootless-tls.lab"
FLAG = "SPANEL_ROOTLESS_ROUTES_HTTPS"


class FakeClient:
    def __init__(
        self, endpoint: CellEndpoint | None = None, error: Exception | None = None
    ) -> None:
        self.endpoint_value = endpoint
        self.error = error

    def endpoint(self, _slug: str) -> CellEndpoint:
        if self.error is not None:
            raise self.error
        assert self.endpoint_value is not None
        return self.endpoint_value


class FakePublisher:
    def __init__(self) -> None:
        self.published: list[tuple[str, str, int, bool]] = []
        self.removed: list[str] = []

    def publish(
        self, domain: str, bind: str, relay_port: int, https: bool = True
    ) -> None:
        self.published.append((domain, bind, relay_port, https))

    def unpublish(self, domain: str) -> bool:
        self.removed.append(domain)
        return True


class _App:
    domain = DOMAIN


class _Db:
    def get(self, _model: Any, _application_id: str) -> _App:
        return _App()


def _endpoint() -> CellEndpoint:
    return CellEndpoint(
        slug="acme",
        loopback_address="127.9.1.1",
        publish_port=20020,
        relay_port=40020,
        bind="172.25.0.1",
        allowed_sources=("172.25.0.3",),
    )


def _routes(
    client: FakeClient, publisher: FakePublisher, **kwargs: Any
) -> RootlessRoutes:
    return RootlessRoutes(
        client, publisher, slug_resolver=lambda _db, _t: "acme", **kwargs
    )


# --- configuration -----------------------------------------------------------


def test_https_flag_defaults_to_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FLAG, raising=False)
    assert AppsSettings.from_env().rootless_routes_https is True


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "on"])
def test_https_flag_accepts_true_values(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    monkeypatch.setenv(FLAG, raw)
    assert AppsSettings.from_env().rootless_routes_https is True


@pytest.mark.parametrize("raw", ["0", "false", "FALSE", "no", "off"])
def test_https_flag_accepts_false_values(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    monkeypatch.setenv(FLAG, raw)
    assert AppsSettings.from_env().rootless_routes_https is False


@pytest.mark.parametrize("raw", ["", "other"])
def test_https_flag_falls_back_to_default_for_invalid_values(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    monkeypatch.setenv(FLAG, raw)
    assert AppsSettings.from_env().rootless_routes_https is True


# --- propagation -------------------------------------------------------------


def test_refresh_propagates_explicit_https() -> None:
    publisher = FakePublisher()
    routes = _routes(FakeClient(_endpoint()), publisher, https=True)

    result = routes.refresh(_Db(), "t1", "app1")

    assert result["published"] == [DOMAIN]
    assert publisher.published == [(DOMAIN, "172.25.0.1", 40020, True)]


def test_refresh_propagates_https_from_host_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(FLAG, "true")
    publisher = FakePublisher()
    routes = _routes(FakeClient(_endpoint()), publisher)

    routes.refresh(_Db(), "t1", "app1")

    assert publisher.published == [(DOMAIN, "172.25.0.1", 40020, True)]


def test_refresh_defaults_to_https_without_the_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(FLAG, raising=False)
    publisher = FakePublisher()
    routes = _routes(FakeClient(_endpoint()), publisher)

    routes.refresh(_Db(), "t1", "app1")

    assert publisher.published == [(DOMAIN, "172.25.0.1", 40020, True)]


def test_no_endpoint_never_publishes_even_with_https() -> None:
    publisher = FakePublisher()
    client = FakeClient(error=PlanAgentUnavailable("no cell endpoint"))
    routes = _routes(client, publisher, https=True)

    result = routes.refresh(_Db(), "t1", "app1")

    assert result["published"] == []
    assert publisher.published == []
