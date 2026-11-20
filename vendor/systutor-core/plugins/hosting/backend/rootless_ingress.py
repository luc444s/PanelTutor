"""Declarative Host-multiplexing ingress inside one tenant cell."""

from __future__ import annotations

import os
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session

from systutor.contracts.container_runtime import (
    ContainerRuntimeError,
    ContainerRuntimeHandle,
)

from .models import HostingSite, RootlessHostingRoute

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


class RootlessIngress:
    def __init__(self, db: Session, runtime: ContainerRuntimeHandle) -> None:
        if runtime.runtime != "rootless":
            raise ValueError("cell ingress requires a rootless runtime")
        self.db = db
        self.runtime = runtime

    def _validate(self, route: RouteSpec) -> None:
        if not DOMAIN_RE.fullmatch(route.domain) or not 1 <= route.port <= 65535:
            raise ValueError("invalid cell ingress route")
        site = self.db.get(HostingSite, route.site_id)
        if site is not None and site.tenant_id != route.tenant_id:
            raise ValueError("route tenant does not own site")
        info = self.runtime.inspect("container", route.target)
        labels = ((info or {}).get("Config") or {}).get("Labels") or {}
        if labels.get("spanel.tenant") != route.tenant_id or labels.get("spanel.managed") != "true":
            raise ValueError("route target is not owned by tenant")

    def routes(self, tenant_id: str) -> list[RouteSpec]:
        rows = self.db.scalars(
            select(RootlessHostingRoute)
            .where(RootlessHostingRoute.tenant_id == tenant_id)
            .order_by(RootlessHostingRoute.domain)
        )
        return [RouteSpec(r.site_id, r.tenant_id, r.domain, r.target, r.port) for r in rows]

    @staticmethod
    def render(routes: list[RouteSpec]) -> bytes:
        blocks = ["server { listen 80 default_server; server_name _; return 404; }"]
        for route in sorted(routes, key=lambda item: item.domain):
            blocks.append(
                "server { listen 80; "
                f"server_name {route.domain}; "
                "location / { "
                f"proxy_pass http://{route.target}:{route.port}; "
                "proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto $scheme; "
                "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; } }"
            )
        return ("\n".join(blocks) + "\n").encode()

    def _network(self) -> None:
        if self.runtime.inspect("network", NETWORK) is None:
            self.runtime.command(
                ("network", "create", "--label", "spanel.role=cell-infra", NETWORK)
            )

    def reconcile(self, tenant_id: str, extra: RouteSpec | None = None) -> None:
        routes = [
            route
            for route in self.routes(tenant_id)
            if extra is None or route.site_id != extra.site_id
        ]
        if extra is not None:
            self._validate(extra)
            routes.append(extra)
        content = self.render(routes)
        self._network()
        candidate = self.runtime.write_private("ingress/routes.candidate.conf", content)
        try:
            self.runtime.command(
                (
                    "run",
                    "--rm",
                    "--network",
                    NETWORK,
                    "-v",
                    f"{candidate}:/etc/nginx/conf.d/default.conf:ro",
                    "nginx:alpine",
                    "nginx",
                    "-t",
                )
            )
        except Exception:
            self.runtime.remove_private("ingress/routes.candidate.conf")
            raise
        final = self.runtime.write_private("ingress/routes.conf", content)
        self.runtime.remove_private("ingress/routes.candidate.conf")
        config_directory = final.rsplit("/", 1)[0]
        info = self.runtime.inspect("container", INGRESS)
        if info is None:
            port = self.runtime.health().publish_port
            if port is None:
                raise ContainerRuntimeError("cell publish port unavailable")
            self.runtime.command(
                (
                    "run",
                    "-d",
                    "--name",
                    INGRESS,
                    "--restart",
                    "unless-stopped",
                    "--network",
                    NETWORK,
                    "--label",
                    "spanel.role=cell-infra",
                    "--label",
                    "spanel.managed=true",
                    "-p",
                    f"{port}:80",
                    "-v",
                    f"{config_directory}:/etc/nginx/conf.d:ro",
                    "nginx:alpine",
                )
            )
        else:
            labels = (info.get("Config") or {}).get("Labels") or {}
            if labels.get("spanel.role") != "cell-infra":
                raise ContainerRuntimeError("foreign cell ingress container")
            self.runtime.command(("exec", INGRESS, "nginx", "-s", "reload"))

    def upsert(self, route: RouteSpec) -> None:
        self.reconcile(route.tenant_id, route)
        row = self.db.get(RootlessHostingRoute, route.site_id)
        if row is None:
            row = RootlessHostingRoute(site_id=route.site_id)
        row.tenant_id = route.tenant_id
        row.domain = route.domain
        row.target = route.target
        row.port = route.port
        self.db.add(row)
        self.db.flush()

    def remove(self, site_id: str, tenant_id: str) -> None:
        row = self.db.get(RootlessHostingRoute, site_id)
        if row is not None:
            self.db.delete(row)
            self.db.flush()
        self.reconcile(tenant_id)


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
