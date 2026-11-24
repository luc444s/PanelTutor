"""Rootless app route publishing through the unprivileged edge relay.

The apps plugin resolves a tenant's cell endpoint through the same bounded
HMAC/UDS client used for plans, then asks the domains publisher to write a
managed ``spanel-*.yml`` whose backend is the relay. No container in the root
daemon is inspected and no Docker network is touched.

This module only exposes refresh/cleanup callables that hook into the existing
route lifecycle of :class:`AppsWorker`. It is inert unless the host configured
the plan-agent socket (fail-closed).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from plugins.apps.backend.plans_client import (
    CellEndpoint,
    HostPlanMaterializerClient,
    PlanAgentError,
)

logger = logging.getLogger(__name__)


def _default_slug_resolver(db: Any, tenant_id: str) -> str:
    from .runtime.tenant_runtime import tenant_slug

    return tenant_slug(db, tenant_id)


class RootlessRoutes:
    """Resolve endpoints and drive the rootless route publisher."""

    def __init__(
        self,
        endpoint_client: Any,
        publisher: Any,
        *,
        slug_resolver: Callable[[Any, str], str] | None = None,
        https: bool | None = None,
        app: Any | None = None,
    ) -> None:
        self.endpoint_client = endpoint_client
        self.publisher = publisher
        self.slug_resolver = slug_resolver or _default_slug_resolver
        # ``None`` means "resolve from host settings at refresh time"; an
        # explicit value lets the worker capture the boot-time configuration.
        self.https = https
        self.app = app

    def _https(self) -> bool:
        """Return the configured TLS flag (default True, preserves HEAD)."""
        if self.https is not None:
            return self.https
        from plugins.apps.backend.settings import AppsSettings

        return AppsSettings.from_env().rootless_routes_https

    def _domains(
        self, db: Any, tenant_id: str, application_id: str
    ) -> list[Any]:
        """Domains is the only source of truth for an App Host."""
        from systutor.contracts.app_hosts import list_app_hosts

        return list(list_app_hosts(self.app, db, tenant_id, application_id))

    def endpoint(self, slug: str) -> CellEndpoint:
        """Resolve the cell relay endpoint; the plan-agent is the only source."""
        return self.endpoint_client.endpoint(slug)

    def refresh(self, db: Any, tenant_id: str, application_id: str) -> dict[str, Any]:
        """Publish every Domains Host to the relay; no endpoint means no route."""
        hosts = self._domains(db, tenant_id, application_id)
        if not hosts:
            return {"published": []}
        slug = self.slug_resolver(db, tenant_id)
        try:
            endpoint: CellEndpoint = self.endpoint_client.endpoint(slug)
        except PlanAgentError as exc:
            # Fail closed: without a live cell endpoint nothing is published.
            logger.warning(
                "rootless_route_no_endpoint slug=%s error=%s", slug, exc
            )
            return {"published": [], "slug": slug, "error": str(exc)}
        published: list[str] = []
        for host in hosts:
            domain, https = host.domain, host.https
            self.publisher.publish(domain, endpoint.bind, endpoint.relay_port, https=https)
            published.append(domain)
            # A.SPEC 0109-R3: make the published Host observable in the
            # cutover evidence; the relay endpoint is the only backend.
            logger.info(
                "rootless_route_host_published",
                extra={
                    "domain": domain,
                    "slug": slug,
                    "bind": endpoint.bind,
                    "relay_port": endpoint.relay_port,
                    "https": https,
                },
            )
        expected = [host.domain for host in hosts]
        return {
            "published": published,
            "complete": sorted(published) == sorted(expected),
            "host": published[0] if published else None,
            "slug": slug,
            "endpoint": endpoint.as_dict(),
        }

    def unpublish(self, domain: str) -> bool:
        """Remove only the relay document of one Host."""
        return self.publisher.unpublish(domain)

    def cleanup(self, db: Any, tenant_id: str, application_id: str) -> dict[str, Any]:
        """Remove the App's kernel ingress rows and its relay documents."""
        removed: list[str] = []
        hosts = self._domains(db, tenant_id, application_id)
        try:
            from .cell_ingress import AppsIngress

            AppsIngress(self.app, db).remove(tenant_id, application_id)
        except Exception:  # noqa: BLE001 - relay cleanup must still run
            logger.warning(
                "rootless_ingress_cleanup_failed",
                extra={"application_id": application_id},
                exc_info=True,
            )
        for host in hosts:
            if self.publisher.unpublish(host.domain):
                removed.append(host.domain)
        return {"removed": removed, "tenant_id": tenant_id}


def build_rootless_routes(app: Any | None = None) -> RootlessRoutes | None:
    """Build the collaborator from host configuration, or stay inert.

    Both the web process (via ``register``) and the worker (via ``AppsWorker``)
    call this with the same environment. An empty socket path or any
    misconfiguration leaves the feature disabled, never half-configured.
    """
    try:
        from plugins.apps.backend.settings import AppsSettings
        from plugins.domains.backend.proxy import build_runner
        from plugins.domains.backend.proxy.operations import ProxyOperations
        from plugins.domains.backend.publisher import RootlessRoutePublisher
        from plugins.domains.backend.settings import get_domains_settings

        settings = AppsSettings.from_env()
        if not str(settings.plan_agent_socket):
            return None
        from systutor.contracts.cell_ingress import register_cell_ingress_provider
        from systutor.contracts.container_runtime import resolve_container_runtime

        def cell_ingress_handle(db, tenant_id):
            if app is None:  # pragma: no cover - only registered with an app
                raise ValueError("cell ingress requires the host application")
            return resolve_container_runtime(app, db, tenant_id, "rootless")

        if app is not None:
            register_cell_ingress_provider(app, "apps", cell_ingress_handle)
        client = HostPlanMaterializerClient(
            settings.plan_agent_socket,
            settings.plan_agent_token_file,
            timeout=settings.plan_agent_timeout,
        )
        proxy = get_domains_settings().proxy_settings()
        publisher = RootlessRoutePublisher(
            ProxyOperations(proxy, build_runner(proxy))
        )
        return RootlessRoutes(
            client, publisher, https=settings.rootless_routes_https, app=app
        )
    except Exception:  # noqa: BLE001 - fail closed, never block the worker boot
        logger.warning("rootless_routes_unavailable", exc_info=True)
        return None


__all__ = ["RootlessRoutes", "build_rootless_routes"]
