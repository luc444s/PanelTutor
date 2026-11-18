"""Application-local inventory of tenant managed resources.

Providers expose stable resource identities and public metadata only.  Daemon
addresses and socket paths deliberately do not belong to this contract.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from fastapi import FastAPI
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class ManagedResource:
    kind: str
    resource_id: str
    name: str
    container_name: str
    domain: str | None
    state: str
    image: str
    endpoint: str | None


ResourceProvider = Callable[[Session, str | None], Sequence[ManagedResource]]


def register_resource_provider(
    app: FastAPI, name: str, provider: ResourceProvider
) -> None:
    providers: dict[str, ResourceProvider] | None = getattr(
        app.state, "tenant_resource_providers", None
    )
    if providers is None:
        providers = {}
        app.state.tenant_resource_providers = providers
    existing = providers.get(name)
    if existing is not None and (
        existing.__module__, existing.__qualname__
    ) != (provider.__module__, provider.__qualname__):
        raise ValueError(f"Duplicate resource provider: {name}")
    providers[name] = provider


def list_resources(
    app: FastAPI, db: Session, tenant_id: str | None
) -> list[ManagedResource]:
    providers: dict[str, ResourceProvider] = getattr(
        app.state, "tenant_resource_providers", {}
    )
    resources: list[ManagedResource] = []
    for name in sorted(providers):
        resources.extend(providers[name](db, tenant_id))
    return sorted(resources, key=lambda row: (row.kind, row.name, row.resource_id))
