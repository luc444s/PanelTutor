# ruff: noqa: E501
"""Apps plugin registration and lazy infrastructure resources."""

from __future__ import annotations

import os
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from plugins.apps.backend.crypto import TokenCipher
from plugins.apps.backend.dispatcher import DramatiqDispatcher
from plugins.apps.backend.github import GithubClient, UrllibGithubClient
from plugins.apps.backend.models import Application, Deployment
from plugins.apps.backend.plans_client import HostPlanMaterializerClient
from plugins.apps.backend.public_url import PublicUrlError, parse_public_url
from plugins.apps.backend.rootless_routes import build_rootless_routes
from plugins.apps.backend.router import router
from plugins.apps.backend.runtime.tenant_runtime import TenantRuntimeRegistry
from plugins.apps.backend.settings import AppsSettings
from plugins.apps.backend.states import OneTimeStates
from systutor.contracts.domain_ownership import OwnedSite, register_site_provider
from systutor.contracts.resource_runtime import (
    ManagedResource,
    register_resource_provider,
)
from systutor.sdk.context import PluginContext


@dataclass
class AppsResources:
    settings: AppsSettings
    dispatcher: object
    github: GithubClient
    _cipher: TokenCipher | None = None
    _states: OneTimeStates | None = None
    # Injected by the host: the real (gated) root/systemd materializer. Without
    # it the plan API fails loudly with 503 instead of faking success.
    plan_materializer: object | None = None
    # A.SPEC 0104: read-only relay endpoint client + rootless route publisher.
    rootless_routes: object | None = None
    # A.SPEC 0109: generic collaborators keep Apps independent from Tenant's
    # persistence model. They are absent while the migration gate is disabled.
    runtime_registry: object | None = None
    runtime_recorder: object | None = None

    def cipher(self) -> TokenCipher:
        if self._cipher is None:
            value = self.settings.read_secret(self.settings.encryption_key_file)
            self._cipher = TokenCipher.from_text(value, self.settings.key_version)
        return self._cipher

    def states(self) -> OneTimeStates:
        if self._states is None:
            import redis

            self._states = OneTimeStates(redis.Redis.from_url(self.settings.redis_url))
        return self._states


def resolve_apps_sites(db: Session, tenant_id: str | None) -> list[OwnedSite]:
    """Stable service identities for Domains routes.

    The site id is ``<application_id>:<service>`` and never a container name.
    Domains resolves the active container from the deployment manifest every
    time it publishes or reads a route, so redeploys can replace containers
    without changing route ownership.
    """
    stmt = select(Application).where(Application.deleted_at.is_(None))
    if tenant_id is not None:
        stmt = stmt.where(Application.tenant_id == tenant_id)
    result: list[OwnedSite] = []
    for app in db.scalars(stmt):
        if not app.active_deployment_id:
            continue
        deployment = db.get(Deployment, app.active_deployment_id)
        manifest = (deployment.manifest or {}) if deployment is not None else {}
        containers = manifest.get("containers", {})
        names = manifest.get("container_names", {})
        for service, container_id in sorted(containers.items()):
            container = names.get(service) or container_id
            if not container:
                continue
            result.append(
                OwnedSite(
                    f"{app.id}:{service}",
                    app.tenant_id,
                    container,
                    app.domain if service == app.ingress_service else None,
                )
            )
    return result


def resolve_apps_resources(
    db: Session, tenant_id: str | None
) -> list[ManagedResource]:
    stmt = select(Application).where(Application.deleted_at.is_(None))
    if tenant_id is not None:
        stmt = stmt.where(Application.tenant_id == tenant_id)
    resources: list[ManagedResource] = []
    for application in db.scalars(stmt):
        if not application.active_deployment_id:
            continue
        deployment = db.get(Deployment, application.active_deployment_id)
        manifest = deployment.manifest if deployment is not None else None
        manifest = manifest if isinstance(manifest, dict) else {}
        containers = manifest.get("containers")
        names = manifest.get("container_names")
        images = manifest.get("images")
        containers = containers if isinstance(containers, dict) else {}
        names = names if isinstance(names, dict) else {}
        images = images if isinstance(images, dict) else {}
        for service, container_id in sorted(containers.items()):
            container = str(names.get(service) or container_id or "").strip()
            if not container:
                continue
            state = str(application.status or "unknown").strip() or "unknown"
            image = str(images.get(service) or "unknown").strip() or "unknown"
            domain = application.domain if service == application.ingress_service else None
            resources.append(
                ManagedResource(
                    kind="app",
                    resource_id=f"{application.id}:{service}",
                    name=f"{application.name} / {service}",
                    container_name=container,
                    domain=domain,
                    state=state,
                    image=image,
                    endpoint=f"https://{domain}" if domain else None,
                )
            )
    return resources


def _build_plan_materializer(settings: AppsSettings) -> HostPlanMaterializerClient | None:
    """Wire the bounded socket client when the operator configured the agent.

    An empty socket path means no client at all, so the plans API stays
    fail-closed with ``503 apps.materializer_unavailable``. Removing this
    injection rolls back to the 0101 behaviour without touching any data.
    """
    if not str(settings.plan_agent_socket):
        return None
    return HostPlanMaterializerClient(
        settings.plan_agent_socket,
        settings.plan_agent_token_file,
        timeout=settings.plan_agent_timeout,
    )


def build_runtime_registry(settings: AppsSettings) -> TenantRuntimeRegistry | None:
    if not settings.tenants_rootless:
        return None
    return TenantRuntimeRegistry(str(settings.tenants_data_root))


def build_runtime_recorder(settings: AppsSettings):
    """Return an injected callback; import Tenant persistence only on use."""
    if not settings.tenants_rootless:
        return None

    def record(db: Session, tenant_id: str, resource_ids: list[str], runtime: str):
        from plugins.tenant.backend.service import get_runtime, set_runtime

        previous = {
            resource_id: get_runtime(db, tenant_id, "app", resource_id)
            for resource_id in resource_ids
        }
        for resource_id in resource_ids:
            set_runtime(db, tenant_id, "app", resource_id, runtime)
        return previous

    return record


def register(context: PluginContext) -> None:
    settings = AppsSettings.from_env()
    production = os.environ.get("SYSTUTOR_ENV") == "production"
    if production and settings.public_url:
        try:
            parse_public_url(settings.public_url, production=True)
        except PublicUrlError as exc:
            raise RuntimeError(str(exc)) from exc
    context.register_router(router)
    app = context.router_registry
    if app is not None:
        rootless = build_rootless_routes()
        runtime_registry = build_runtime_registry(settings)
        app.state.apps_resources = AppsResources(
            settings,
            DramatiqDispatcher(),
            UrllibGithubClient(),
            plan_materializer=_build_plan_materializer(settings),
            rootless_routes=rootless,
            runtime_registry=runtime_registry,
            runtime_recorder=build_runtime_recorder(settings),
        )
        app.state.rootless_routes = rootless
        register_site_provider(app, "apps", resolve_apps_sites)
        register_resource_provider(app, "apps", resolve_apps_resources)
