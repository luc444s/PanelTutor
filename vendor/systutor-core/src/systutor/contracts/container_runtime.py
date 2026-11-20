"""Opaque, application-local access to registered container runtimes.

The handle deliberately exposes bounded operations instead of a daemon socket.
Plugins resolve it server-side after resolving tenant ownership.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from fastapi import FastAPI
from sqlalchemy.orm import Session


class ContainerRuntimeError(RuntimeError):
    """A requested runtime is absent, unhealthy, or ambiguous."""


@dataclass(frozen=True)
class RuntimeHealth:
    runtime: str
    state: str
    tenant_slug: str | None = None
    cell_uid: int | None = None
    publish_port: int | None = None


@runtime_checkable
class ContainerRuntimeHandle(Protocol):
    runtime: str

    def command(self, args: tuple[str, ...], *, input: bytes | None = None) -> bytes: ...
    def inspect(self, kind: str, name: str) -> dict[str, Any] | None: ...
    def export_volume(self, name: str) -> Iterator[bytes]: ...
    def import_volume(self, name: str, chunks: Iterator[bytes]) -> None: ...
    def write_private(self, relative_path: str, content: bytes) -> str: ...
    def remove_private(self, relative_path: str) -> None: ...
    def health(self) -> RuntimeHealth: ...


RuntimeProvider = Callable[[Session, str], ContainerRuntimeHandle]


def register_container_runtime(app: FastAPI, name: str, provider: RuntimeProvider) -> None:
    providers: dict[str, RuntimeProvider] | None = getattr(
        app.state, "container_runtime_providers", None
    )
    if providers is None:
        providers = {}
        app.state.container_runtime_providers = providers
    previous = providers.get(name)
    identity = lambda value: (  # noqa: E731 - compact stable callable identity
        getattr(value, "__module__", value.__class__.__module__),
        getattr(value, "__qualname__", value.__class__.__qualname__),
    )
    if previous is not None and identity(previous) != identity(provider):
        raise ValueError(f"Duplicate container runtime provider: {name}")
    providers[name] = provider


def resolve_container_runtime(
    app: FastAPI, db: Session, tenant_id: str, runtime: str
) -> ContainerRuntimeHandle:
    if runtime not in {"rootful", "rootless"}:
        raise ContainerRuntimeError("unknown container runtime")
    providers: dict[str, RuntimeProvider] = getattr(app.state, "container_runtime_providers", {})
    provider = providers.get(runtime)
    if provider is None:
        raise ContainerRuntimeError(f"{runtime} container runtime is not registered")
    handle = provider(db, tenant_id)
    if handle.runtime != runtime:
        raise ContainerRuntimeError("container runtime provider mismatch")
    return handle
