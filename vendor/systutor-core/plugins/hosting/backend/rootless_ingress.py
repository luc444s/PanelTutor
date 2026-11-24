"""Declarative Host-multiplexing ingress inside one tenant cell.

The nginx render and the bounded cell operations live in the kernel
(``systutor.kernel.cell_ingress``); Hosting only contributes its site ownership
check and the legacy-compatible ``RouteSpec`` shape.
"""

from __future__ import annotations

import os
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from fastapi import FastAPI
from sqlalchemy.orm import Session

from systutor.contracts.container_runtime import (
    ContainerRuntimeError,
    ContainerRuntimeHandle,
)
from systutor.kernel.cell_ingress import (
    CellIngress,
    render_routes,
)
from systutor.kernel.cell_ingress import (
    RouteSpec as KernelRouteSpec,
)

from .models import HostingSite

INGRESS = "spanel-cell-ingress"
NETWORK = "spanel-hosting"
DOMAIN_RE = re.compile(
    r"(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+"
)


def _tls_context() -> ssl.SSLContext:
    """Trust the same proxy CA the Domains publisher uses, when configured.

    Public deployments keep the system trust store; the lab overrides it with
    the internal CA so HTTPS verification does not fall back to an unverified
    connection.
    """
    cafile = os.environ.get("SPANEL_PROXY_CA_FILE", "").strip()
    if cafile:
        try:
            return ssl.create_default_context(cafile=cafile)
        except (OSError, ssl.SSLError):
            pass
    return ssl.create_default_context()


def verify_external_route(
    domain: str,
    *,
    https: bool = True,
    deadline_seconds: float = 30.0,
    initial_backoff: float = 0.25,
    max_backoff: float = 2.0,
) -> None:
    """Wait boundedly for a published route to become observable.

    The probe uses the route's real scheme: with HTTPS the HTTP entry only
    redirects, so following that redirect would verify the wrong thing (and,
    for an internal CA, fail on an unknown issuer).
    """
    scheme = "https" if https else "http"
    request = urllib.request.Request(
        f"{scheme}://{domain}/", headers={"Host": domain}
    )
    context = _tls_context() if https else None
    deadline = time.monotonic() + max(0.0, deadline_seconds)
    delay = max(0.0, initial_backoff)
    last_error: Exception | None = None
    while True:
        remaining = deadline - time.monotonic()
        try:
            kwargs = {"timeout": max(0.1, min(5.0, remaining))}
            if context is not None:
                kwargs["context"] = context
            with urllib.request.urlopen(request, **kwargs) as response:  # noqa: S310
                if response.status == 200:
                    return
                last_error = RuntimeError(f"external HTTP returned {response.status}")
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(
                f"external HTTP was not ready before deadline: {last_error}"
            ) from last_error
        sleep_for = min(delay, remaining)
        if sleep_for > 0:
            time.sleep(sleep_for)
        delay = min(max_backoff, max(delay * 2, 0.01))


@dataclass(frozen=True)
class RouteSpec:
    site_id: str
    tenant_id: str
    domain: str
    target: str
    port: int


def _server_names(domain: str) -> str:
    """Apex routes also answer the conventional www alias."""
    names = [domain]
    if not domain.startswith("www."):
        try:
            import ipaddress

            ipaddress.ip_address(domain)
        except ValueError:
            names.append(f"www.{domain}")
    return " ".join(names)


def _kernel_route(route: RouteSpec) -> KernelRouteSpec:
    return KernelRouteSpec(
        route_id=f"hosting:{route.site_id}",
        tenant_id=route.tenant_id,
        owner_kind="hosting",
        owner_id=route.site_id,
        domain=route.domain,
        target=route.target,
        port=route.port,
    )


class RootlessIngress:
    def __init__(self, db: Session, runtime: ContainerRuntimeHandle) -> None:
        if runtime.runtime != "rootless":
            raise ValueError("cell ingress requires a rootless runtime")
        self.db = db
        self.runtime = runtime
        self.cell = CellIngress(db, runtime)

    def _validate(self, route: RouteSpec) -> None:
        if not DOMAIN_RE.fullmatch(route.domain) or not 1 <= route.port <= 65535:
            raise ValueError("invalid cell ingress route")
        site = self.db.get(HostingSite, route.site_id)
        if site is not None and site.tenant_id != route.tenant_id:
            raise ValueError("route tenant does not own site")

    def routes(self, tenant_id: str) -> list[RouteSpec]:
        return [
            RouteSpec(
                row.owner_id, row.tenant_id, row.domain, row.target, row.port
            )
            for row in self.cell.routes(tenant_id, "hosting")
        ]

    @staticmethod
    def render(routes: list[RouteSpec]) -> bytes:
        return render_routes(
            [_kernel_route(route) for route in routes], default_server=True
        )

    def _network(self) -> None:
        self.cell.ensure_network()

    def reconcile(
        self, tenant_id: str, extra: RouteSpec | None = None
    ) -> None:
        if extra is not None:
            self._validate(extra)
            self.cell.upsert(_kernel_route(extra))
        self.cell.reconcile(tenant_id, "hosting")

    def upsert(self, route: RouteSpec) -> None:
        self._validate(route)
        self.cell.upsert(_kernel_route(route))
        self.cell.reconcile(route.tenant_id, "hosting")

    def remove(self, site_id: str, tenant_id: str) -> None:
        self.cell.remove(f"hosting:{site_id}")
        self.cell.reconcile(tenant_id, "hosting")


class RootlessRoutePublisher:
    """Publish a Hosting Host to the stable relay already owned by the cell."""

    def __init__(self, app: FastAPI, db: Session) -> None:
        self.routes = getattr(app.state, "rootless_routes", None)
        self.db = db

    def publish(self, tenant_id: str, domain: str) -> bool:
        """Publish the Host and return the effective TLS flag for verification."""
        if self.routes is None:
            raise ContainerRuntimeError("rootless relay publisher is not registered")
        slug = self.routes.slug_resolver(self.db, tenant_id)
        endpoint = self.routes.endpoint(slug)
        resolve_https = getattr(self.routes, "_https", None)
        https = resolve_https() if callable(resolve_https) else True
        self.routes.publisher.publish(
            domain, endpoint.bind, endpoint.relay_port, https=https
        )
        return bool(https)

    def unpublish(self, domain: str) -> None:
        if self.routes is None:
            raise ContainerRuntimeError("rootless relay publisher is not registered")
        self.routes.publisher.unpublish(domain)
