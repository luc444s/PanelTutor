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
RuntimeReader = Callable[[Session, str, str, str], str | None]
RuntimeWriter = Callable[[Session, str, str, str, str], None]


@dataclass(frozen=True)
class ResourceRuntimeProvider:
    read: RuntimeReader
    write: RuntimeWriter


def _callable_identity(value: Callable) -> tuple[str | None, str | None]:
    return (getattr(value, "__module__", None), getattr(value, "__qualname__", None))


def register_resource_runtime_provider(
    app: FastAPI, name: str, *, read: RuntimeReader, write: RuntimeWriter
) -> None:
    providers: dict[str, ResourceRuntimeProvider] | None = getattr(
        app.state, "resource_runtime_registry_providers", None
    )
    if providers is None:
        providers = {}
        app.state.resource_runtime_registry_providers = providers
    previous = providers.get(name)
    # Re-registering the same provider must stay idempotent, as in the other
    # contract registries: plugin register() hooks can run more than once on
    # the same app (e.g. tests toggling a feature flag). A genuinely different
    # provider under an occupied name is still rejected.
    if previous is not None and (
        _callable_identity(previous.read) != _callable_identity(read)
        or _callable_identity(previous.write) != _callable_identity(write)
    ):
        raise ValueError(f"Duplicate resource runtime provider: {name}")
    providers[name] = ResourceRuntimeProvider(read=read, write=write)


def _runtime_provider(app: FastAPI) -> ResourceRuntimeProvider:
    providers: dict[str, ResourceRuntimeProvider] = getattr(
        app.state, "resource_runtime_registry_providers", {}
    )
    if len(providers) != 1:
        raise RuntimeError("resource runtime registry is not registered unambiguously")
    return next(iter(providers.values()))


def read_resource_runtime(
    app: FastAPI, db: Session, tenant_id: str, kind: str, resource_id: str
) -> str | None:
    """Return the explicit assignment; absence is not synonymous with rootful."""
    value = _runtime_provider(app).read(db, tenant_id, kind, resource_id)
    if value not in {None, "rootful", "rootless"}:
        raise RuntimeError("invalid resource runtime value")
    return value


def write_resource_runtime(
    app: FastAPI,
    db: Session,
    tenant_id: str,
    kind: str,
    resource_id: str,
    runtime: str,
) -> None:
    if runtime not in {"rootful", "rootless"}:
        raise ValueError("runtime must be rootful or rootless")
    _runtime_provider(app).write(db, tenant_id, kind, resource_id, runtime)


def register_resource_provider(app: FastAPI, name: str, provider: ResourceProvider) -> None:
    providers: dict[str, ResourceProvider] | None = getattr(
        app.state, "tenant_resource_providers", None
    )
    if providers is None:
        providers = {}
        app.state.tenant_resource_providers = providers
    existing = providers.get(name)
    if existing is not None and (existing.__module__, existing.__qualname__) != (
        provider.__module__,
        provider.__qualname__,
    ):
        raise ValueError(f"Duplicate resource provider: {name}")
    providers[name] = provider


def list_resources(app: FastAPI, db: Session, tenant_id: str | None) -> list[ManagedResource]:
    providers: dict[str, ResourceProvider] = getattr(app.state, "tenant_resource_providers", {})
    resources: list[ManagedResource] = []
    for name in sorted(providers):
        resources.extend(providers[name](db, tenant_id))
    return sorted(resources, key=lambda row: (row.kind, row.name, row.resource_id))
