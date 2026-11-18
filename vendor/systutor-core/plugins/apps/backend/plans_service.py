"""Plan lifecycle: validate -> persist -> materialize -> audit.

The DB row is written only after the host materializer succeeds.  If the
materializer raises, the transaction is rolled back (no orphan plan row) and a
failed audit record plus a failed Operation are persisted instead.
"""

from __future__ import annotations

from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from systutor.core.errors import AppError

from .models import AppsTenantPlan, new_id
from .operations import create_operation
from .runtime.tenant_plan import TenantPlan
from .runtime.tenant_runtime import tenant_slug
from .schemas import TenantPlanRequest
from .service import audit


class PlanMaterializer(Protocol):
    """Host adapter registered on ``AppsResources`` by the operator."""

    def apply(self, tenant_slug: str, plan: dict[str, Any]) -> dict[str, Any]: ...

    def remove(self, tenant_slug: str) -> dict[str, Any]: ...

    def verify(self, tenant_slug: str, plan: dict[str, Any]) -> dict[str, Any]: ...


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
    from datetime import UTC, datetime

    operation.status = "succeeded" if ok else "failed"
    if error is not None:
        operation.error_code = "apps.plan_materialization_failed"
        operation.public_error = error[:500]
    operation.phase = "done"
    operation.finished_at = datetime.now(UTC)


def _materializer(materializer: PlanMaterializer | None) -> PlanMaterializer:
    if materializer is None:
        raise AppError(
            "Apps plan materializer is unavailable",
            status_code=503,
            code="apps.materializer_unavailable",
        )
    return materializer


def _failed(
    db: Session,
    operation: Any,
    *,
    tenant_id: str,
    actor: str,
    action: str,
    exc: Exception,
) -> None:
    db.rollback()
    audit(
        db,
        action,
        tenant_id=tenant_id,
        actor=actor,
        entity_id=tenant_id,
        result="failure",
        details={"error": str(exc)[:500]},
    )
    _complete(operation, ok=False, error=str(exc))
    db.commit()


def set_plan(
    db: Session,
    *,
    tenant_id: str,
    actor: str,
    body: TenantPlanRequest,
    materializer: PlanMaterializer | None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Persist a plan and materialize it; revert on a materializer failure."""
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
    db.flush()
    payload = TenantPlan.from_row(row, slug).as_dict()
    try:
        adapter.apply(slug, payload)
    except Exception as exc:  # noqa: BLE001 - host failure must not leave a row
        _failed(
            db, operation, tenant_id=tenant_id, actor=actor,
            action="apps.plan.set", exc=exc,
        )
        raise AppError(
            "Plan materialization failed",
            status_code=502,
            code="apps.plan_materialization_failed",
        ) from exc
    audit(
        db, "apps.plan.set", tenant_id=tenant_id, actor=actor,
        entity_id=tenant_id, details={"slice": TenantPlan.from_row(row, slug).slice},
    )
    _complete(operation, ok=True)
    db.commit()
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
    """Dematerialize the plan and delete its row."""
    adapter = _materializer(materializer)
    row = get_plan(db, tenant_id)
    if row is None:
        raise AppError("Tenant has no plan", status_code=404, code="apps.plan_not_found")
    operation = _operation(
        db, tenant_id=tenant_id, actor=actor, kind="plan_remove",
        payload={}, correlation_id=correlation_id,
    )
    slug = tenant_slug(db, tenant_id)
    try:
        result = adapter.remove(slug)
    except Exception as exc:  # noqa: BLE001
        _failed(
            db, operation, tenant_id=tenant_id, actor=actor,
            action="apps.plan.remove", exc=exc,
        )
        raise AppError(
            "Plan dematerialization failed",
            status_code=502,
            code="apps.plan_materialization_failed",
        ) from exc
    db.delete(row)
    audit(
        db, "apps.plan.remove", tenant_id=tenant_id, actor=actor,
        entity_id=tenant_id, details=result,
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
    """Ask the host for kernel evidence that the plan is really enforced."""
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
        _failed(
            db, operation, tenant_id=tenant_id, actor=actor,
            action="apps.plan.verify", exc=exc,
        )
        raise AppError(
            "Plan verification failed",
            status_code=502,
            code="apps.plan_materialization_failed",
        ) from exc
    ok = bool(result.get("ok"))
    audit(
        db, "apps.plan.verify", tenant_id=tenant_id, actor=actor,
        entity_id=tenant_id, result="success" if ok else "failure",
        details={"ok": ok},
    )
    _complete(operation, ok=ok)
    db.commit()
    return {"tenant_id": tenant_id, "tenant_slug": slug, **result}
