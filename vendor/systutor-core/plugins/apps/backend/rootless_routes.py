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
    ) -> None:
        self.endpoint_client = endpoint_client
        self.publisher = publisher
        self.slug_resolver = slug_resolver or _default_slug_resolver

    def _domains(self, db: Any, application_id: str) -> list[str]:
        from .models import Application

        app = db.get(Application, application_id)
        if app is None or not app.domain:
            return []
        return [app.domain]

    def refresh(self, db: Any, tenant_id: str, application_id: str) -> dict[str, Any]:
        """Publish the app domain to the relay; no endpoint means no route."""
        domains = self._domains(db, application_id)
        if not domains:
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
        for domain in domains:
            self.publisher.publish(domain, endpoint.bind, endpoint.relay_port)
            published.append(domain)
        return {
            "published": published,
            "slug": slug,
            "endpoint": endpoint.as_dict(),
        }

    def cleanup(self, db: Any, tenant_id: str, application_id: str) -> dict[str, Any]:
        """Remove only the rootless documents this hook owns."""
        domains = self._domains(db, application_id)
        removed: list[str] = []
        for domain in domains:
            if self.publisher.unpublish(domain):
                removed.append(domain)
        return {"removed": removed, "tenant_id": tenant_id}


def build_rootless_routes() -> RootlessRoutes | None:
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
        client = HostPlanMaterializerClient(
            settings.plan_agent_socket,
            settings.plan_agent_token_file,
            timeout=settings.plan_agent_timeout,
        )
        proxy = get_domains_settings().proxy_settings()
        publisher = RootlessRoutePublisher(
            ProxyOperations(proxy, build_runner(proxy))
        )
        return RootlessRoutes(client, publisher)
    except Exception:  # noqa: BLE001 - fail closed, never block the worker boot
        logger.warning("rootless_routes_unavailable", exc_info=True)
        return None


__all__ = ["RootlessRoutes", "build_rootless_routes"]
