"""Public app-host registry owned by the Domains plugin.

Apps consumes this contract without importing Domains persistence. While the
legacy ``apps_applications.domain`` column exists, consumers may use it only as
a fallback when no provider row exists. Removing that fallback requires an
explicit future decision; it has no date-based expiry.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from fastapi import FastAPI
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class AppHost:
    site_id: str
    application_id: str
    service: str
    domain: str
    https: bool


AppHostProvider = Callable[[Session, str, str | None], Sequence[AppHost]]


def register_app_host_provider(
    app: FastAPI, name: str, provider: AppHostProvider
) -> None:
    providers: dict[str, AppHostProvider] | None = getattr(
        app.state, "app_host_providers", None
    )
    if providers is None:
        providers = {}
        app.state.app_host_providers = providers
    existing = providers.get(name)
    if existing is not None and (
        existing.__module__, existing.__qualname__
    ) != (provider.__module__, provider.__qualname__):
        raise ValueError(f"Duplicate app host provider: {name}")
    providers[name] = provider


def list_app_hosts(
    app: FastAPI | None,
    db: Session,
    tenant_id: str,
    application_id: str | None = None,
) -> list[AppHost]:
    if app is None:
        return []
    providers: dict[str, AppHostProvider] = getattr(
        app.state, "app_host_providers", {}
    )
    rows: list[AppHost] = []
    for provider in providers.values():
        rows.extend(provider(db, tenant_id, application_id))
    return rows


def resolve_app_host(
    app: FastAPI | None,
    db: Session,
    tenant_id: str,
    application_id: str,
    service: str,
) -> AppHost | None:
    return next(
        (
            row
            for row in list_app_hosts(app, db, tenant_id, application_id)
            if row.service == service
        ),
        None,
    )
