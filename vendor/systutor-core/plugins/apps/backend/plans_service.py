"""Plan lifecycle: validate -> persist -> materialize -> audit.

A.SPEC 0102: the plan row is the single source of truth and carries an explicit
lifecycle state. It is written as ``pending`` before the host agent is called,
moves to ``applied`` only after real materialization, and stays ``failed`` with
``last_error`` when the agent rejects or fails the operation. A failed row is
recoverable by retrying ``apply`` or by ``reconcile``. With no client
configured the API stays fail-closed with a loud 503.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from systutor.core.errors import AppError

from .models import AppsTenantPlan, new_id
from .operations import create_operation, request_hash
from .plans_client import (
    PlanAgentAuthError,
    PlanAgentDenied,
    PlanAgentUnavailable,
)
from .runtime.tenant_plan import TenantPlan
from .runtime.tenant_runtime import tenant_slug
from .schemas import TenantPlanRequest
from .service import audit


class PlanMaterializer(Protocol):
    """Host adapter registered on ``AppsResources`` by the operator."""

    def apply(self, tenant_slug: str, plan: dict[str, Any]) -> dict[str, Any]: ...

    def remove(self, tenant_slug: str) -> dict[str, Any]: ...

    def verify(self, tenant_slug: str, plan: dict[str, Any]) -> dict[str, Any]: ...

    def reconcile(self, desired: list[dict[str, Any]]) -> dict[str, Any]: ...

    def capacity(self) -> dict[str, Any]: ...


def _now() -> datetime:
    return datetime.now(UTC)


def get_plan(db: Session, tenant_id: str) -> AppsTenantPlan | None:
    return db.scalar(
        select(AppsTenantPlan).where(AppsTenantPlan.tenant_id == tenant_id)
    )


def plan_view(db: Session, tenant_id: str) -> dict[str, Any] | None:
    """Public representation, or ``None`` when the tenant has no plan."""
    row = get_plan(db, tenant_id)
    if row is None:
        return None
    slug = tenant_slug(db, tenant_id)
    effective = TenantPlan.from_row(row, slug)
    return {
        "tenant_id": tenant_id,
        "tenant_slug": slug,
        "memory_bytes": int(row.memory_bytes),
        "cpus": float(row.cpus),
        "pids": int(row.pids),
        "cpuset": row.cpuset,
        "storage_bytes": (
            None if row.storage_bytes is None else int(row.storage_bytes)
        ),
        "status": row.status,
        "applied_at": row.applied_at,
        "last_error": row.last_error,
        "updated_at": row.updated_at,
        "slice": effective.slice,
        "cgroup_path": effective.cgroup_path,
    }


def _operation(
    db: Session,
    *,
    tenant_id: str,
    actor: str,
    kind: str,
    payload: dict[str, Any],
    correlation_id: str | None,
) -> Any:
    operation, _created = create_operation(
        db,
        application=None,
        actor_user_id=actor,
        kind=kind,
        idempotency_key=f"plan:{kind}:{tenant_id}:{new_id()}",
        payload=payload,
        correlation_id=correlation_id,
        tenant_id=tenant_id,
        subject_type="tenant_plan",
        subject_id=tenant_id,
    )
    return operation


def _complete(operation: Any, *, ok: bool, error: str | None = None) -> None:
    operation.status = "succeeded" if ok else "failed"
    if error is not None:
        operation.error_code = "apps.plan_materialization_failed"
        operation.public_error = error[:500]
    operation.phase = "done"
    operation.finished_at = _now()


def _materializer(materializer: PlanMaterializer | None) -> PlanMaterializer:
    if materializer is None:
        raise AppError(
            "Apps plan materializer is unavailable",
            status_code=503,
            code="apps.materializer_unavailable",
        )
    return materializer


def _host_failure(verb: str, exc: Exception) -> AppError:
    """Map typed client failures to a controlled public error (never a 500)."""
    code = "apps.plan_materialization_failed"
    if isinstance(exc, PlanAgentAuthError):
        code = "apps.plan_agent_auth_failed"
    elif isinstance(exc, PlanAgentDenied):
        code = "apps.plan_agent_denied"
    elif isinstance(exc, PlanAgentUnavailable):
        code = "apps.plan_agent_unavailable"
    return AppError(f"Plan {verb} failed", status_code=502, code=code)


def _mark_failed(
    db: Session,
    operation: Any,
    row: AppsTenantPlan | None,
    *,
    tenant_id: str,
    actor: str,
    action: str,
    exc: Exception,
    commit: bool = True,
) -> None:
    """Keep a recoverable failed row; never leave an orphan or ambiguous state."""
    if row is not None:
        row.status = "failed"
        row.last_error = str(exc)[:500]
        row.applied_at = None
    audit(
        db, action, tenant_id=tenant_id, actor=actor, entity_id=tenant_id,
        result="failure", details={"error": str(exc)[:500]},
    )
    _complete(operation, ok=False, error=str(exc))
    if commit:
        db.commit()
    else:
        db.flush()


def set_plan(
    db: Session,
    *,
    tenant_id: str,
    actor: str,
    body: TenantPlanRequest,
    materializer: PlanMaterializer | None,
    correlation_id: str | None = None,
    commit: bool = True,
    commit_failure: bool = True,
) -> dict[str, Any]:
    """Persist a pending plan, materialize it, then mark it applied/failed."""
    adapter = _materializer(materializer)
    operation = _operation(
        db, tenant_id=tenant_id, actor=actor, kind="plan_set",
        payload=body.model_dump(), correlation_id=correlation_id,
    )
    slug = tenant_slug(db, tenant_id)
    row = get_plan(db, tenant_id)
    if row is None:
        row = AppsTenantPlan(tenant_id=tenant_id)
        db.add(row)
    row.memory_bytes = body.memory_bytes
    row.cpus = body.cpus
    row.pids = body.pids
    row.cpuset = body.cpuset
    row.storage_bytes = body.storage_bytes
    row.status = "pending"
    row.last_error = None
    row.applied_at = None
    db.flush()
    effective = TenantPlan.from_row(row, slug)
    payload = effective.as_dict()
    # A storage-only edit changes the auditable hash but never the host payload.
    row.desired_hash = request_hash(effective.desired_dict())
    try:
        adapter.apply(slug, payload)
    except Exception as exc:  # noqa: BLE001 - host failure must not raise a 500
        _mark_failed(
            db, operation, row, tenant_id=tenant_id, actor=actor,
            action="apps.plan.set", exc=exc, commit=commit_failure,
        )
        raise _host_failure("materialization", exc) from exc
    row.status = "applied"
    row.applied_at = _now()
    row.last_error = None
    audit(
        db, "apps.plan.set", tenant_id=tenant_id, actor=actor,
        entity_id=tenant_id, details={
            "slice": TenantPlan.from_row(row, slug).slice,
            "storage_bytes": row.storage_bytes,
        },
    )
    _complete(operation, ok=True)
    if commit:
        db.commit()
    else:
        db.flush()
    view = plan_view(db, tenant_id)
    assert view is not None
    return view


def remove_plan(
    db: Session,
    *,
    tenant_id: str,
    actor: str,
    materializer: PlanMaterializer | None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Dematerialize the plan and delete its row; failures stay recoverable."""
    adapter = _materializer(materializer)
    row = get_plan(db, tenant_id)
    if row is None:
        raise AppError("Tenant has no plan", status_code=404, code="apps.plan_not_found")
    operation = _operation(
        db, tenant_id=tenant_id, actor=actor, kind="plan_remove",
        payload={}, correlation_id=correlation_id,
    )
    slug = tenant_slug(db, tenant_id)
    row.status = "pending"
    row.last_error = None
    db.flush()
    try:
        result = adapter.remove(slug)
    except Exception as exc:  # noqa: BLE001
        _mark_failed(
            db, operation, row, tenant_id=tenant_id, actor=actor,
            action="apps.plan.remove", exc=exc,
        )
        raise _host_failure("dematerialization", exc) from exc
    storage_bytes = row.storage_bytes
    db.delete(row)
    audit(
        db, "apps.plan.remove", tenant_id=tenant_id, actor=actor,
        entity_id=tenant_id, details={**result, "storage_bytes": storage_bytes},
    )
    _complete(operation, ok=True)
    db.commit()
    return {"tenant_id": tenant_id, "tenant_slug": slug, **result}


def verify_plan(
    db: Session,
    *,
    tenant_id: str,
    actor: str,
    materializer: PlanMaterializer | None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Ask the host for kernel evidence and reconcile the row with reality."""
    adapter = _materializer(materializer)
    row = get_plan(db, tenant_id)
    if row is None:
        raise AppError("Tenant has no plan", status_code=404, code="apps.plan_not_found")
    operation = _operation(
        db, tenant_id=tenant_id, actor=actor, kind="plan_verify",
        payload={}, correlation_id=correlation_id,
    )
    slug = tenant_slug(db, tenant_id)
    payload = TenantPlan.from_row(row, slug).as_dict()
    try:
        result = adapter.verify(slug, payload)
    except Exception as exc:  # noqa: BLE001
        _mark_failed(
            db, operation, row, tenant_id=tenant_id, actor=actor,
            action="apps.plan.verify", exc=exc,
        )
        raise _host_failure("verification", exc) from exc
    ok = bool(result.get("ok"))
    if ok:
        row.status = "applied"
        row.last_error = None
        if row.applied_at is None:
            row.applied_at = _now()
    else:
        row.status = "failed"
        row.last_error = str(result.get("error") or "kernel evidence differs")[:500]
    audit(
        db, "apps.plan.verify", tenant_id=tenant_id, actor=actor,
        entity_id=tenant_id, result="success" if ok else "failure",
        details={"ok": ok},
    )
    _complete(operation, ok=ok)
    db.commit()
    return {"tenant_id": tenant_id, "tenant_slug": slug, **result}


def capacity(
    db: Session,
    *,
    tenant_id: str,
    materializer: PlanMaterializer | None,
) -> dict[str, Any]:
    """Read-only host totals plus the sum of every persisted plan.

    Overcommit is intentionally not judged here: the totals are informational
    and ``set_plan`` never rejects a plan for exceeding them (A.SPEC 0111).
    """
    if materializer is None:
        raise AppError(
            "Host capacity is unavailable",
            status_code=503,
            code="apps.capacity_unavailable",
        )
    try:
        host = materializer.capacity()
    except Exception as exc:  # noqa: BLE001 - the UI needs one stable 503
        raise AppError(
            "Host capacity is unavailable",
            status_code=503,
            code="apps.capacity_unavailable",
        ) from exc
    rows = list(db.scalars(select(AppsTenantPlan)))
    allocated_memory = sum(int(row.memory_bytes) for row in rows)
    allocated_cpus = sum(float(row.cpus) for row in rows)
    allocated_pids = sum(int(row.pids) for row in rows)
    allocated_storage = sum(
        int(row.storage_bytes) for row in rows if row.storage_bytes is not None
    )
    unbounded_storage = sum(1 for row in rows if row.storage_bytes is None)
    return {
        "tenant_id": tenant_id,
        "host": {
            "memory_bytes": int(host["memory_bytes"]),
            "cpus": float(host["cpus"]),
            "storage_bytes": int(host["storage_bytes"]),
            "storage_available_bytes": int(host.get("storage_available_bytes", 0)),
            "read_at": host.get("read_at"),
            "source": host.get("source"),
            "data_root": host.get("data_root"),
        },
        "allocated": {
            "memory_bytes": allocated_memory,
            "cpus": allocated_cpus,
            "pids": allocated_pids,
            "storage_bytes": allocated_storage,
        },
        "unbounded_storage": unbounded_storage,
    }


def reconcile(
    db: Session,
    *,
    materializer: PlanMaterializer | None,
    actor: str = "system",
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Compare every persisted plan with the host and repair differences.

    The desired set comes from PostgreSQL only; ``plans.json`` is never read as
    truth. This is safe to call after a VPS restart and recovers ``failed``
    rows when the host now enforces their plan.
    """
    adapter = _materializer(materializer)
    rows = list(db.scalars(select(AppsTenantPlan).order_by(AppsTenantPlan.tenant_id)))
    desired: list[dict[str, Any]] = []
    by_slug: dict[str, AppsTenantPlan] = {}
    for row in rows:
        slug = tenant_slug(db, row.tenant_id)
        by_slug[slug] = row
        desired.append({
            "tenant": row.tenant_id,
            "slug": slug,
            **TenantPlan.from_row(row, slug).as_dict(),
            "status": row.status,
            "desired_hash": row.desired_hash,
        })

    try:
        result = adapter.reconcile(desired)
    except Exception as exc:  # noqa: BLE001
        if rows:
            audit(
                db, "apps.plan.reconcile", tenant_id=rows[0].tenant_id, actor=actor,
                entity_id="*", result="failure",
                details={"error": str(exc)[:500]},
            )
        db.commit()
        raise _host_failure("reconciliation", exc) from exc

    updated = 0
    for item in result.get("results", []):
        row = by_slug.get(str(item.get("slug")))
        if row is None:
            continue
        updated += 1
        if item.get("ok"):
            row.status = "applied"
            row.last_error = None
            if row.applied_at is None:
                row.applied_at = _now()
        else:
            row.status = "failed"
            row.last_error = str(item.get("error") or "host state differs")[:500]
    ok = bool(result.get("ok"))
    if rows:
        audit(
            db, "apps.plan.reconcile", tenant_id=rows[0].tenant_id, actor=actor,
            entity_id="*", result="success" if ok else "failure",
            details={"checked": updated, "ok": ok},
        )
    db.commit()
    return {
        "ok": ok,
        "checked": updated,
        "results": result.get("results", []),
        "removed": result.get("removed", []),
    }
