"""Declarative Host-multiplexing ingress shared by every cell plugin.

The kernel owns the neutral route table (``tenant_ingress_routes``), the nginx
render and the bounded operations against the cell handle.  Hosting and Apps
only describe their routes; neither plugin persists a private route table.

A tenant cell keeps a single ``default_server`` (Hosting) while Apps writes a
separate ``apps-routes.conf``.  Both files are validated with ``nginx -t`` in an
ephemeral container before the live configuration is replaced.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Integer, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from systutor.contracts.container_runtime import (
    ContainerRuntimeError,
    ContainerRuntimeHandle,
)
from systutor.core.database import Base
from systutor.kernel.auth.models import utc_now

INGRESS = "spanel-cell-ingress"
NETWORK = "spanel-hosting"
HOSTING_CONFIG = "default.conf"
APPS_CONFIG = "apps-routes.conf"
OWNER_KINDS = ("hosting", "apps")
DOMAIN_RE = re.compile(
    r"(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+"
)


class CellIngressError(RuntimeError):
    """A route cannot be represented safely by the cell ingress."""

    code = "cell_ingress_unavailable"


class IngressConflict(CellIngressError):
    """A Host already belongs to another owner."""

    code = "cell_ingress_domain_conflict"


class TenantIngressRoute(Base):
    """One Host served by one tenant cell, regardless of the owning plugin."""

    __tablename__ = "tenant_ingress_routes"
    __table_args__ = (UniqueConstraint("tenant_id", "domain"),)

    route_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    owner_kind: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    owner_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    service: Mapped[str | None] = mapped_column(String(255))
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        default=utc_now, onupdate=utc_now
    )


@dataclass(frozen=True)
class RouteSpec:
    """Neutral ingress route shared by Hosting and Apps."""

    route_id: str
    tenant_id: str
    owner_kind: str
    owner_id: str
    domain: str
    target: str
    port: int
    service: str | None = None


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


def render_routes(routes: list[RouteSpec], *, default_server: bool = False) -> bytes:
    """Render one nginx file; only Hosting may declare the default server."""
    blocks: list[str] = []
    if default_server:
        blocks.append("server { listen 80 default_server; server_name _; return 404; }")
    for route in sorted(routes, key=lambda item: item.domain):
        blocks.append(
            "server { listen 80; "
            f"server_name {_server_names(route.domain)}; "
            "location / { "
            f"proxy_pass http://{route.target}:{route.port}; "
            "proxy_set_header Host $host; "
            # Traefik terminates TLS and already sends the real scheme.
            # Do not overwrite it with $scheme (the relay hop is HTTP):
            # the upstream would see HTTP and redirect to HTTPS every time.
            "proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto; "
            "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; } }"
        )
    return ("\n".join(blocks) + "\n").encode()


def _config_name(owner_kind: str) -> str:
    if owner_kind == "hosting":
        return HOSTING_CONFIG
    if owner_kind == "apps":
        return APPS_CONFIG
    raise CellIngressError("invalid ingress owner kind")


class CellIngress:
    """Persist, render and reload the ingress of one tenant cell."""

    def __init__(self, db: Session, handle: ContainerRuntimeHandle) -> None:
        if handle.runtime != "rootless":
            raise ValueError("cell ingress requires a rootless runtime")
        self.db = db
        self.handle = handle

    # -- persistence -------------------------------------------------------

    def routes(
        self, tenant_id: str, owner_kind: str | None = None
    ) -> list[RouteSpec]:
        stmt = select(TenantIngressRoute).where(
            TenantIngressRoute.tenant_id == tenant_id
        )
        if owner_kind is not None:
            stmt = stmt.where(TenantIngressRoute.owner_kind == owner_kind)
        rows = self.db.scalars(
            stmt.order_by(TenantIngressRoute.owner_kind, TenantIngressRoute.domain)
        )
        return [
            RouteSpec(
                route_id=row.route_id,
                tenant_id=row.tenant_id,
                owner_kind=row.owner_kind,
                owner_id=row.owner_id,
                domain=row.domain,
                target=row.target,
                port=row.port,
                service=row.service,
            )
            for row in rows
        ]

    def get(self, route_id: str) -> RouteSpec | None:
        row = self.db.get(TenantIngressRoute, route_id)
        if row is None:
            return None
        return RouteSpec(
            route_id=row.route_id,
            tenant_id=row.tenant_id,
            owner_kind=row.owner_kind,
            owner_id=row.owner_id,
            domain=row.domain,
            target=row.target,
            port=row.port,
            service=row.service,
        )

    def _validate(self, route: RouteSpec) -> None:
        if route.owner_kind not in OWNER_KINDS:
            raise CellIngressError("invalid ingress owner kind")
        if not DOMAIN_RE.fullmatch(route.domain) or not 1 <= route.port <= 65535:
            raise CellIngressError("invalid cell ingress route")
        if not route.route_id or not route.owner_id or not route.target:
            raise CellIngressError("incomplete cell ingress route")
        # One Host has exactly one owner.  A row for another owner is a
        # conflict, never a silent takeover (which would serve the wrong
        # upstream).
        existing = self.db.scalar(
            select(TenantIngressRoute).where(
                TenantIngressRoute.tenant_id == route.tenant_id,
                TenantIngressRoute.domain == route.domain,
            )
        )
        if existing is not None and existing.route_id != route.route_id:
            raise IngressConflict(
                f"{route.domain} is already owned by {existing.owner_kind}"
            )
        self._validate_target(route.tenant_id, route.target)

    def _validate_target(self, tenant_id: str, target: str) -> None:
        info = self.handle.inspect("container", target)
        labels = ((info or {}).get("Config") or {}).get("Labels") or {}
        if (
            labels.get("spanel.tenant") != tenant_id
            or labels.get("spanel.managed") != "true"
        ):
            raise CellIngressError("route target is not owned by tenant")

    def upsert(self, route: RouteSpec) -> None:
        self._validate(route)
        row = self.db.get(TenantIngressRoute, route.route_id)
        if row is None:
            row = TenantIngressRoute(route_id=route.route_id)
        row.tenant_id = route.tenant_id
        row.owner_kind = route.owner_kind
        row.owner_id = route.owner_id
        row.service = route.service
        row.domain = route.domain
        row.target = route.target
        row.port = route.port
        self.db.add(row)
        self.db.flush()

    def remove(self, route_id: str) -> bool:
        row = self.db.get(TenantIngressRoute, route_id)
        if row is None:
            return False
        self.db.delete(row)
        self.db.flush()
        return True

    def remove_owner(
        self, tenant_id: str, owner_kind: str, owner_id: str
    ) -> list[str]:
        rows = list(
            self.db.scalars(
                select(TenantIngressRoute).where(
                    TenantIngressRoute.tenant_id == tenant_id,
                    TenantIngressRoute.owner_kind == owner_kind,
                    TenantIngressRoute.owner_id == owner_id,
                )
            )
        )
        removed = [row.route_id for row in rows]
        for row in rows:
            self.db.delete(row)
        if rows:
            self.db.flush()
        return removed

    # -- rendering and publication ----------------------------------------

    @staticmethod
    def render(routes: list[RouteSpec], *, default_server: bool = False) -> bytes:
        return render_routes(routes, default_server=default_server)

    @staticmethod
    def render_file(owner_kind: str, routes: list[RouteSpec]) -> bytes:
        return render_routes(routes, default_server=owner_kind == "hosting")

    def ensure_network(self) -> None:
        if self.handle.inspect("network", NETWORK) is None:
            self.handle.command(
                ("network", "create", "--label", "spanel.role=cell-infra", NETWORK)
            )

    def _active_routes(self, routes: list[RouteSpec]) -> list[RouteSpec]:
        """A stopped container cannot resolve on the cell network.

        Hosting keeps the other hosts of the tenant serving during a lifecycle;
        Apps validates its own targets before asking for reconciliation.
        """
        active: list[RouteSpec] = []
        for route in routes:
            info = self.handle.inspect("container", route.target)
            if not isinstance(info, dict) or not (info.get("State") or {}).get(
                "Running"
            ):
                continue
            networks = (info.get("NetworkSettings") or {}).get("Networks") or {}
            if NETWORK not in networks:
                self.handle.command(("network", "connect", NETWORK, route.target))
            active.append(route)
        return active

    def reconcile(self, tenant_id: str, owner_kind: str | None = None) -> None:
        """Regenerate both tenant files and reload nginx after ``nginx -t``."""
        if owner_kind is not None:
            _config_name(owner_kind)
        hosting = self._active_routes(self.routes(tenant_id, "hosting"))
        apps = self._active_routes(self.routes(tenant_id, "apps"))
        contents = {
            HOSTING_CONFIG: render_routes(hosting, default_server=True),
            APPS_CONFIG: render_routes(apps, default_server=False),
        }
        self.ensure_network()
        candidate_paths = {name: f"ingress/{name}.candidate" for name in contents}
        candidates = {
            name: self.handle.write_private(path, contents[name])
            for name, path in candidate_paths.items()
        }
        try:
            args = ["run", "--rm", "--network", NETWORK]
            for name, path in candidates.items():
                args += ["-v", f"{path}:/etc/nginx/conf.d/{name}:ro"]
            args += ["nginx:alpine", "nginx", "-t"]
            self.handle.command(tuple(args))
        except Exception:
            for path in candidate_paths.values():
                self.handle.remove_private(path)
            raise
        final = {
            name: self.handle.write_private(f"ingress/{name}", content)
            for name, content in contents.items()
        }
        for path in candidate_paths.values():
            self.handle.remove_private(path)
        # Retire the legacy single-file render from A.SPEC 0110.  Leaving it
        # mounted would declare a second default_server after the migration.
        self.handle.remove_private("ingress/routes.conf")
        self.handle.remove_private("ingress/routes.candidate.conf")
        config_directory = final[HOSTING_CONFIG].rsplit("/", 1)[0]
        info = self.handle.inspect("container", INGRESS)
        if info is None:
            port = self.handle.health().publish_port
            if port is None:
                raise ContainerRuntimeError("cell publish port unavailable")
            self.handle.command(
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
            self.handle.command(("exec", INGRESS, "nginx", "-s", "reload"))


__all__ = [
    "APPS_CONFIG",
    "HOSTING_CONFIG",
    "CellIngress",
    "CellIngressError",
    "IngressConflict",
    "RouteSpec",
    "TenantIngressRoute",
    "render_routes",
]
