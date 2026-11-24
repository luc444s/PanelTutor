"""Public access to the kernel cell-ingress service.

Plugins never construct a cell handle for ingress themselves: they register a
bounded provider (normally the tenant's rootless runtime) and resolve the
kernel service through this contract.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI
from sqlalchemy.orm import Session

from systutor.contracts.container_runtime import ContainerRuntimeHandle
from systutor.kernel.cell_ingress import CellIngress

CellIngressProvider = Callable[[Session, str], ContainerRuntimeHandle]


def register_cell_ingress_provider(
    app: FastAPI, name: str, provider: CellIngressProvider
) -> None:
    providers: dict[str, CellIngressProvider] | None = getattr(
        app.state, "cell_ingress_providers", None
    )
    if providers is None:
        providers = {}
        app.state.cell_ingress_providers = providers
    previous = providers.get(name)
    if previous is not None and (
        getattr(previous, "__module__", None), getattr(previous, "__qualname__", None)
    ) != (
        getattr(provider, "__module__", None),
        getattr(provider, "__qualname__", None),
    ):
        raise ValueError(f"Duplicate cell ingress provider: {name}")
    providers[name] = provider


def resolve_cell_ingress(
    app: FastAPI, db: Session, tenant_id: str, name: str | None = None
) -> CellIngress:
    providers: dict[str, CellIngressProvider] = getattr(
        app.state, "cell_ingress_providers", {}
    )
    if name is not None:
        providers = {name: providers[name]} if name in providers else {}
    else:
        providers = dict(providers)
    if not providers:
        raise ValueError("cell ingress provider is not registered")
    provider = next(iter(providers.values()))
    return CellIngress(db, provider(db, tenant_id))


__all__ = [
    "CellIngressProvider",
    "register_cell_ingress_provider",
    "resolve_cell_ingress",
]
