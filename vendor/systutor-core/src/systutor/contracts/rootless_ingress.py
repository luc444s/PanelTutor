"""Rootless ingress delegation for plugins that own Hosts.

Domains owns ``domains_app_hosts`` and the route editor, but the effective
Traefik document for a rootless App must point at the tenant cell relay, never
at a container name. Apps registers this bounded provider so Domains can ask
whether a site is rootless and delegate the ingress refresh/removal without
importing Apps or writing a legacy container route.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from fastapi import FastAPI
from sqlalchemy.orm import Session

IsRootless = Callable[[Session, str, str], bool]
Refresh = Callable[[Session, str, str], None]
Remove = Callable[[Session, str, str, str], None]


@dataclass(frozen=True)
class RootlessIngress:
    is_rootless: IsRootless
    refresh: Refresh
    # ``remove`` receives the Host so the relay document can be unpublished.
    remove: Remove


def register_rootless_ingress(
    app: FastAPI, name: str, ingress: RootlessIngress
) -> None:
    providers: dict[str, RootlessIngress] | None = getattr(
        app.state, "rootless_ingress_providers", None
    )
    if providers is None:
        providers = {}
        app.state.rootless_ingress_providers = providers
    existing = providers.get(name)
    if existing is not None and (
        existing.is_rootless.__module__,
        existing.is_rootless.__qualname__,
    ) != (
        ingress.is_rootless.__module__,
        ingress.is_rootless.__qualname__,
    ):
        raise ValueError(f"Duplicate rootless ingress provider: {name}")
    providers[name] = ingress


def _provider(app: FastAPI | None) -> RootlessIngress | None:
    if app is None:
        return None
    providers: dict[str, RootlessIngress] = getattr(
        app.state, "rootless_ingress_providers", {}
    )
    return next(iter(providers.values()), None)


def is_rootless_site(
    app: FastAPI | None, db: Session, tenant_id: str, site_id: str
) -> bool:
    provider = _provider(app)
    return provider is not None and provider.is_rootless(db, tenant_id, site_id)


def refresh_rootless_site(
    app: FastAPI | None, db: Session, tenant_id: str, site_id: str
) -> None:
    provider = _provider(app)
    if provider is None:
        raise RuntimeError("rootless ingress provider is not registered")
    provider.refresh(db, tenant_id, site_id)


def remove_rootless_site(
    app: FastAPI | None, db: Session, tenant_id: str, site_id: str, domain: str
) -> None:
    provider = _provider(app)
    if provider is None:
        raise RuntimeError("rootless ingress provider is not registered")
    provider.remove(db, tenant_id, site_id, domain)


__all__ = [
    "RootlessIngress",
    "is_rootless_site",
    "refresh_rootless_site",
    "register_rootless_ingress",
    "remove_rootless_site",
]
