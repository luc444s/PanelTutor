from __future__ import annotations

from types import SimpleNamespace

import pytest

from plugins.hosting.backend import phpmyadmin_session
from plugins.hosting.backend.service import HostingService
from plugins.hosting.backend.settings import HostingSettings
from systutor.contracts.container_runtime import RuntimeHealth
from systutor.core.errors import AppError


def service_with(settings: HostingSettings) -> HostingService:
    service = object.__new__(HostingService)
    service._settings = settings
    return service


def rootless_runtime(slug: str = "demo") -> SimpleNamespace:
    return SimpleNamespace(
        runtime="rootless",
        health=lambda: RuntimeHealth("rootless", "ready", slug, 60070, 20070),
    )


def test_rootless_relay_uses_the_cell_slug_and_returns_only_host_port(monkeypatch) -> None:
    calls = {}

    class Client:
        def __init__(self, socket, token, *, timeout):
            calls["client"] = (str(socket), str(token), timeout)

        def open(self, **kwargs):
            calls["open"] = kwargs
            return {
                "relay_id": "pma-abc",
                "broker_host": "172.23.0.1",
                "broker_port": 41010,
            }

    monkeypatch.setattr(
        "plugins.hosting.backend.service.PmaBrokerClient", Client
    )
    settings = HostingSettings(
        phpmyadmin_arbitrary=True,
        phpmyadmin_rootless_broker=True,
        phpmyadmin_source_ip="172.25.0.20",
        phpmyadmin_broker_socket="/run/spanel/plan-agent.sock",
        phpmyadmin_broker_token_file="/run/secrets/plan_agent_token",
    )
    service = service_with(settings)
    service._audit_site = lambda *args, **kwargs: None
    monkeypatch.setattr(service, "_runtime_for", lambda site: rootless_runtime())
    site = SimpleNamespace(id="site-1", tenant_id="tenant-1", kind="wordpress")
    relay = service.phpmyadmin_relay_server(site, SimpleNamespace(), "session-1")
    assert relay == {
        "relay_id": "pma-abc",
        "server": "172.23.0.1:41010",
        "tenant_slug": "demo",
        "runtime": "rootless",
    }
    assert calls["open"]["tenant"] == "demo"
    assert calls["open"]["tenant_id"] == "tenant-1"
    assert calls["open"]["site_id"] == "site-1"
    assert calls["open"]["pma_session_id"] == "session-1"
    assert calls["open"]["source_ip"] == "172.25.0.20"
    assert calls["open"]["ttl"] == settings.phpmyadmin_session_ttl


def test_rootful_site_keeps_the_legacy_path(monkeypatch) -> None:
    service = service_with(HostingSettings())
    monkeypatch.setattr(
        service, "_runtime_for", lambda site: SimpleNamespace(runtime="rootful")
    )
    site = SimpleNamespace(id="s", tenant_id="t", kind="wordpress")
    assert service.phpmyadmin_relay_server(site, SimpleNamespace(), "x") is None


def test_disabled_broker_fails_closed(monkeypatch) -> None:
    service = service_with(
        HostingSettings(phpmyadmin_rootless_broker=False, phpmyadmin_arbitrary=True)
    )
    monkeypatch.setattr(service, "_runtime_for", lambda site: rootless_runtime())
    site = SimpleNamespace(id="s", tenant_id="t", kind="wordpress")
    with pytest.raises(AppError) as exc:
        service.phpmyadmin_relay_server(site, SimpleNamespace(), "x")
    assert exc.value.code == "hosting_phpmyadmin_unavailable"


def test_rootless_requires_arbitrary_server_mode(monkeypatch) -> None:
    service = service_with(
        HostingSettings(phpmyadmin_rootless_broker=True, phpmyadmin_arbitrary=False)
    )
    monkeypatch.setattr(service, "_runtime_for", lambda site: rootless_runtime())
    site = SimpleNamespace(id="s", tenant_id="t", kind="wordpress")
    with pytest.raises(AppError) as exc:
        service.phpmyadmin_relay_server(site, SimpleNamespace(), "x")
    assert exc.value.code == "hosting_phpmyadmin_unavailable"


def test_static_site_is_rejected_before_opening_a_relay(monkeypatch) -> None:
    service = service_with(
        HostingSettings(phpmyadmin_rootless_broker=True, phpmyadmin_arbitrary=True)
    )
    monkeypatch.setattr(
        service,
        "_runtime_for",
        lambda site: pytest.fail("runtime must not be resolved for a static site"),
    )

    with pytest.raises(AppError) as exc:
        service.phpmyadmin_relay_server(
            SimpleNamespace(
                id="s", tenant_id="t", kind="static", container_name="spanel-static-web"
            ),
            SimpleNamespace(),
            "x",
        )

    assert exc.value.code == "hosting_site_wrong_kind"


def test_login_with_relay_server_skips_the_rootful_database_network(monkeypatch) -> None:
    service = service_with(HostingSettings(phpmyadmin_arbitrary=True))
    service._require_wordpress = lambda site: None
    service._require_site = lambda site: ({"State": {"Running": True}}, True)
    service._database_binding_for = (
        lambda site, info: (None, "spanel-demo-db", "wp", "wp_user", "secret")
    )
    service._inspect_for = lambda site, host: {"State": {"Running": True}}
    service._audit_site = lambda *args, **kwargs: None
    monkeypatch.setattr(
        "plugins.hosting.backend.service.estado_del_contenedor",
        lambda info: "running",
    )

    def network_must_not_run(*_args, **_kwargs):
        raise AssertionError("rootless phpMyAdmin must not join the rootful network")

    service._ensure_database_network = network_must_not_run
    seen = {}

    class Client:
        def login(self, user, password, server=None):
            seen["login"] = (user, password, server)
            return {"pma": "cookie"}

    cookies = service.phpmyadmin_login_credentials(
        SimpleNamespace(id="s", tenant_id="t"),
        SimpleNamespace(),
        Client(),
        server="172.23.0.1:41010",
    )
    assert cookies == {"pma": "cookie"}
    assert seen["login"] == ("wp_user", "secret", "172.23.0.1:41010")


def test_proxy_rejects_browser_selected_server_or_port() -> None:
    from plugins.hosting.backend.router import _forbidden_pma_post

    form = "application/x-www-form-urlencoded"
    assert _forbidden_pma_post(b"server=1&pma_servername=evil:3306", form)
    assert _forbidden_pma_post(b"host=evil", form)
    assert _forbidden_pma_post(b"port=3307", form)
    assert _forbidden_pma_post(b"pma_username=root&pma_password=x", form)
    assert not _forbidden_pma_post(b"server=1&db=wp", form)
    assert _forbidden_pma_post(
        b"--x\r\nContent-Disposition: form-data; name=\"pma_servername\"\r\n\r\nevil\r\n--x--\r\n",
        "multipart/form-data; boundary=x",
    )


def test_invalidating_a_relay_session_closes_it(monkeypatch) -> None:
    closed = []
    monkeypatch.setattr(
        phpmyadmin_session,
        "_close_relay",
        lambda session: closed.append((session.tenant_slug, session.relay_id)),
    )
    session, _ = phpmyadmin_session.create_session(
        "user", "tenant", "site", {"pma": "x"}, 60,
        relay_id="pma-1", tenant_slug="demo", session_id="opaque",
    )
    assert session.id == "opaque"
    phpmyadmin_session.invalidate(session)
    assert closed == [("demo", "pma-1")]
