"""Publisher of a site's primary domain through the Traefik file provider.

The hosting plugin only knows the contract; this module is the domains side.
``publish`` writes one managed YAML for the container (no certificate wait and
no WordPress URL rewrite), while ``unpublish`` removes the domain and is
idempotent when the route is already gone.
"""

from __future__ import annotations

import logging

from plugins.domains.backend.proxy import ProxyError, ProxyOperations, build_runner
from plugins.domains.backend.proxy.core import PathRoute
from plugins.domains.backend.settings import get_domains_settings
from systutor.contracts.site_domain_publisher import SiteDomainPublisher
from systutor.sdk.context import PluginContext

logger = logging.getLogger(__name__)


class ProxySitePublisher:
    """Adapt ``ProxyOperations`` to the ``SiteDomainPublisher`` contract."""

    def __init__(self, operations: ProxyOperations | None = None) -> None:
        self._operations = operations

    @property
    def operations(self) -> ProxyOperations:
        if self._operations is None:
            settings = get_domains_settings().proxy_settings()
            self._operations = ProxyOperations(settings, build_runner(settings))
        return self._operations

    def publish(self, container: str, domain: str, port: int = 80) -> None:
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        self.operations.add(
            container,
            domain,
            port=port,
            wait=0,
            set_wordpress_url=False,
        )

    def unpublish(self, domain: str) -> None:
        try:
            self.operations.remove(domain)
        except ProxyError as exc:
            # Deleting a site must not fail because its route was already
            # removed by an operator. Any other proxy error still surfaces.
            if "is not managed by spanel" in str(exc):
                logger.info("domains_unpublish_missing_route", extra={"domain": domain})
                return
            raise


class RootlessRoutePublisher:
    """Publish a rootless cell route through the existing file-provider.

    The backend is the unprivileged relay on the proxy gateway, not a cell
    container in the root daemon, so ``write_route_document`` is called with
    runtime validation and network connection disabled. Marker, file name and
    one-owner-per-Host semantics stay exactly the same as for rootful routes.
    """

    def __init__(self, operations: ProxyOperations | None = None) -> None:
        self._operations = operations

    @property
    def operations(self) -> ProxyOperations:
        if self._operations is None:
            settings = get_domains_settings().proxy_settings()
            self._operations = ProxyOperations(settings, build_runner(settings))
        return self._operations

    def publish(self, domain: str, bind: str, relay_port: int) -> object:
        if not bind.strip():
            raise ValueError("relay bind is required")
        if not 1 <= relay_port <= 65535:
            raise ValueError("relay_port must be between 1 and 65535")
        operations = self.operations
        if operations.path_conflict(domain, "/"):
            raise ValueError(f"the domain {domain} already has a managed route")
        route = PathRoute(prefix="/", container=bind, port=relay_port)
        return operations.write_route_document(
            domain,
            [route],
            validate_runtime=False,
            connect_network=False,
        )

    def unpublish(self, domain: str) -> bool:
        return self.operations.remove_route_document(domain)


def register_domains_publisher(context: PluginContext) -> None:
    app = context.router_registry
    if app is None:
        return
    from systutor.contracts.site_domain_publisher import register_site_domain_publisher

    register_site_domain_publisher(app, "domains", ProxySitePublisher())


__all__ = [
    "ProxySitePublisher",
    "RootlessRoutePublisher",
    "register_domains_publisher",
    "SiteDomainPublisher",
]
