"""Apps routes on the kernel cell ingress (A.SPEC 0114).

Domains owns the Host; this module only maps each ``AppHost`` to the active
deployment container and asks the kernel to persist, render and reload the
route.  Relay publication stays in :mod:`rootless_routes` so the order is
always: legacy document removed, ingress rendered, relay published.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from systutor.contracts.app_hosts import AppHost, list_app_hosts
from systutor.contracts.cell_ingress import resolve_cell_ingress
from systutor.contracts.container_runtime import (
    ContainerRuntimeError,
    ContainerRuntimeHandle,
    resolve_container_runtime,
)
from systutor.contracts.site_domain_publisher import get_site_domain_publisher
from systutor.kernel.cell_ingress import CellIngress, RouteSpec

from .models import Application, Deployment


class AppsIngressError(RuntimeError):
    """Fail-closed ingress failure with a stable operation error code."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class AppsIngress:
    def __init__(
        self,
        app: Any,
        db: Session,
        *,
        handle: ContainerRuntimeHandle | None = None,
    ) -> None:
        self.app = app
        self.db = db
        self.handle = handle

    # -- collaborators -----------------------------------------------------

    def _handle(self, tenant_id: str) -> ContainerRuntimeHandle:
        if self.handle is not None:
            return self.handle
        if self.app is None:
            raise AppsIngressError(
                "Cell ingress is unavailable", code="apps_ingress_unavailable"
            )
        try:
            return resolve_container_runtime(
                self.app, self.db, tenant_id, "rootless"
            )
        except ContainerRuntimeError as exc:
            raise AppsIngressError(
                "Cell ingress is unavailable", code="apps_ingress_unavailable"
            ) from exc

    def _cell(self, tenant_id: str) -> CellIngress:
        if self.app is not None:
            try:
                return resolve_cell_ingress(self.app, self.db, tenant_id)
            except (ValueError, KeyError):
                pass
        return CellIngress(self.db, self._handle(tenant_id))

    # -- inventory ---------------------------------------------------------

    def hosts(self, tenant_id: str, application_id: str) -> list[AppHost]:
        return list_app_hosts(self.app, self.db, tenant_id, application_id)

    def _containers(self, application_id: str) -> dict[str, str]:
        app = self.db.get(Application, application_id)
        if app is None or not app.active_deployment_id:
            raise AppsIngressError(
                "App has no active deployment", code="apps_ingress_unavailable"
            )
        deployment = self.db.get(Deployment, app.active_deployment_id)
        manifest = (
            deployment.manifest
            if deployment is not None and isinstance(deployment.manifest, dict)
            else {}
        )
        containers = manifest.get("containers")
        names = manifest.get("container_names")
        if not isinstance(containers, dict):
            raise AppsIngressError(
                "App has no verified containers", code="apps_ingress_unavailable"
            )
        names = names if isinstance(names, dict) else {}
        return {
            str(service): str(names.get(service) or container)
            for service, container in containers.items()
            if container
        }

    def _route(
        self,
        tenant_id: str,
        application_id: str,
        host: AppHost,
        containers: dict[str, str],
        cell: CellIngress,
    ) -> RouteSpec:
        if host.unsupported_paths:
            raise AppsIngressError(
                "Only the / path is supported by the cell ingress",
                code="apps_ingress_path_unsupported",
            )
        target = containers.get(host.service)
        if not target:
            raise AppsIngressError(
                f"Service {host.service} has no container in the manifest",
                code="apps_ingress_unavailable",
            )
        if not isinstance(host.port, int) or not 1 <= host.port <= 65535:
            raise AppsIngressError(
                f"Host {host.domain} has no root route port",
                code="apps_ingress_unavailable",
            )
        info = cell.handle.inspect("container", target)
        if not isinstance(info, dict) or not (info.get("State") or {}).get(
            "Running"
        ):
            raise AppsIngressError(
                f"Target {target} is not running in the cell",
                code="apps_ingress_unavailable",
            )
        labels = (info.get("Config") or {}).get("Labels") or {}
        if (
            labels.get("spanel.managed") != "true"
            or labels.get("spanel.tenant") != tenant_id
        ):
            # Docker labels are immutable: the only fix is recreating the
            # container from the signed release with the new override.
            raise AppsIngressError(
                f"Target {target} predates the spanel.managed/spanel.tenant "
                "labels; redeploy the App with "
                "migrate_tenant_apps.py --redeploy-rootless",
                code="apps_ingress_unavailable",
            )
        return RouteSpec(
            route_id=f"apps:{application_id}:{host.service}",
            tenant_id=tenant_id,
            owner_kind="apps",
            owner_id=application_id,
            service=host.service,
            domain=host.domain,
            target=target,
            port=host.port,
        )

    # -- lifecycle ---------------------------------------------------------

    def reconcile(self, tenant_id: str, application_id: str) -> list[str]:
        """Upsert every Domains Host and reload the cell ingress."""
        hosts = self.hosts(tenant_id, application_id)
        if not hosts:
            return []
        if any(host.unsupported_paths for host in hosts):
            raise AppsIngressError(
                "Only the / path is supported by the cell ingress",
                code="apps_ingress_path_unsupported",
            )
        cell = self._cell(tenant_id)
        containers = self._containers(application_id)
        routes = [
            self._route(tenant_id, application_id, host, containers, cell)
            for host in hosts
        ]
        for route in routes:
            cell.upsert(route)
        # The legacy document points at the rootful container; remove it before
        # the relay document (same managed name) is republished.
        publisher = get_site_domain_publisher(self.app) if self.app is not None else None
        if publisher is not None:
            for host in hosts:
                try:
                    publisher.unpublish(host.domain)
                except Exception:  # noqa: BLE001 - absence is not a failure
                    pass
        cell.reconcile(tenant_id, "apps")
        # Every caller owns an ephemeral session (worker, refresh script,
        # migration); the rows must survive the session or the rendered file
        # and ``tenant_ingress_routes`` would disagree after the next reconcile.
        self.db.commit()
        return [host.domain for host in hosts]

    def remove(self, tenant_id: str, application_id: str) -> list[str]:
        """Delete the App's rows and regenerate the ingress without them."""
        cell = self._cell(tenant_id)
        removed = cell.remove_owner(tenant_id, "apps", application_id)
        if removed:
            cell.reconcile(tenant_id, "apps")
            self.db.commit()
        return removed


__all__ = ["AppsIngress", "AppsIngressError"]
