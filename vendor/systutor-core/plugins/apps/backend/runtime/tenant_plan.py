"""Resource-plan policy: split a tenant aggregate across Compose services.

The plan is the ceiling for the tenant, not a multiplier per service.  Values
explicitly declared in the Compose file win; whatever is missing is shared in
equal parts and the sum of derived limits never exceeds the plan total.  This
module is pure (no host I/O) so the policy can be tested without systemd.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from .tenant_runtime import validate_slug

_MEMORY_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([KMGT]?)B?$", re.IGNORECASE)
_UNIT_MULT = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}


@dataclass(frozen=True)
class TenantPlan:
    """An effective plan resolved from ``apps_tenant_plans`` for one deploy."""

    memory_bytes: int
    cpus: float
    pids: int
    tenant_slug: str | None = None
    cpuset: str | None = None
    # A.SPEC 0111: declared storage limit. It never reaches the host payload.
    storage_bytes: int | None = None

    @property
    def slice(self) -> str:
        """The systemd slice the deploy's containers are placed under."""
        return f"tenant-{validate_slug(self.tenant_slug)}.slice"

    @property
    def cgroup_path(self) -> str:
        return f"/tenant.slice/{self.slice}"

    def as_dict(self) -> dict[str, Any]:
        """Payload accepted by the host ``PlanMaterializer``.

        The payload stays exactly memory/cpus/pids/cpuset: storage is a
        declared limit and systemd cannot apply it (A.SPEC 0111).
        """
        return {
            "memory": self.memory_bytes,
            "cpus": self.cpus,
            "pids": self.pids,
            "cpuset": self.cpuset,
        }

    def desired_dict(self) -> dict[str, Any]:
        """Hashable desired state, including the declared storage limit."""
        return {**self.as_dict(), "storage_bytes": self.storage_bytes}

    @classmethod
    def from_row(cls, row: Any, tenant_slug: str) -> TenantPlan:
        storage = getattr(row, "storage_bytes", None)
        return cls(
            memory_bytes=int(row.memory_bytes),
            cpus=float(row.cpus),
            pids=int(row.pids),
            tenant_slug=tenant_slug,
            cpuset=row.cpuset,
            storage_bytes=None if storage is None else int(storage),
        )


def memory_bytes(value: object) -> int | None:
    """Parse a Compose ``mem_limit`` into bytes; ``None`` for absent/invalid."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        match = _MEMORY_RE.fullmatch(value.strip())
        if match is None or float(match.group(1)) <= 0:
            return None
        return int(float(match.group(1)) * _UNIT_MULT[match.group(2).upper()])
    return None


def _allocate(total: float, declared: Mapping[str, object]) -> dict[str, float]:
    """Declared values win (capped to the budget); the rest is split equally."""
    remaining = float(total)
    missing: list[str] = []
    result: dict[str, float] = {}
    for service, value in declared.items():
        if value is None:
            missing.append(service)
            continue
        share = min(float(value), remaining)  # type: ignore[arg-type]
        result[service] = share
        remaining -= share
    if missing:
        share = remaining / len(missing)
        for service in missing:
            result[service] = share
    return result


def service_limits(
    plan: TenantPlan, services: Mapping[str, Mapping[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Derive per-service Docker limits from the tenant aggregate.

    ``services`` is the raw Compose ``services`` mapping.  A key declared by a
    service is preserved (that service's own value wins); keys the service did
    not declare are filled from the plan's equal split.
    """
    memory_declared: dict[str, object] = {}
    cpu_declared: dict[str, object] = {}
    pids_declared: dict[str, object] = {}
    cpuset_declared: dict[str, object] = {}
    for service, config in services.items():
        source = config if isinstance(config, Mapping) else {}
        memory_declared[service] = memory_bytes(source.get("mem_limit"))
        cpus = source.get("cpus")
        cpu_declared[service] = (
            float(cpus)
            if isinstance(cpus, (int, float)) and not isinstance(cpus, bool) and cpus > 0
            else None
        )
        pids = source.get("pids_limit")
        pids_declared[service] = (
            int(pids)
            if isinstance(pids, int) and not isinstance(pids, bool) and pids > 0
            else None
        )
        cpuset_declared[service] = source.get("cpuset") or None

    memory = _allocate(plan.memory_bytes, memory_declared)
    cpus = _allocate(plan.cpus, cpu_declared)
    pids = _allocate(plan.pids, pids_declared)

    result: dict[str, dict[str, Any]] = {}
    for service in services:
        limits: dict[str, Any] = {
            "mem_limit": int(memory[service]),
            "cpus": round(cpus[service], 6),
            "pids_limit": int(pids[service]),
        }
        cpuset = cpuset_declared[service] or plan.cpuset
        if cpuset:
            limits["cpuset"] = str(cpuset)
        result[service] = limits
    return result


_current_plan: ContextVar[TenantPlan | None] = ContextVar(
    "apps_tenant_plan", default=None
)


@contextmanager
def bind_tenant_plan(plan: TenantPlan | None) -> Iterator[None]:
    """Scope a resolved plan to the deploy that consumes it."""
    token = _current_plan.set(plan)
    try:
        yield
    finally:
        _current_plan.reset(token)


def current_tenant_plan() -> TenantPlan | None:
    return _current_plan.get()
