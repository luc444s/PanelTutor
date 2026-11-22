"""Tenant resource plan API, governed only by ``apps.plans.manage``."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from systutor.api.deps import get_db_session
from systutor.core.errors import AppError
from systutor.kernel.auth.dependencies import get_current_tenant_context, require_permission
from systutor.kernel.auth.models import User
from systutor.kernel.tenants.context import TenantContext

from . import plans_service
from .schemas import TenantPlanRequest, TenantPlanView

router = APIRouter(tags=["apps-plans"])


def _resources(request: Request):
    resources = getattr(request.app.state, "apps_resources", None)
    if resources is None:
        raise AppError("Apps is unavailable", status_code=503, code="apps.unavailable")
    return resources


def _tenant(context: TenantContext, tenant_id: str | None) -> str:
    """Platform may target any tenant; a tenant may only target itself."""
    if tenant_id is None:
        return context.current_tenant_id
    if not context.is_platform and tenant_id != context.current_tenant_id:
        raise AppError(
            "Cannot manage a plan for another tenant",
            status_code=403,
            code="apps.plan_scope_forbidden",
        )
    return tenant_id


@router.post(
    "/plan",
    response_model=TenantPlanView,
    status_code=201,
    description=(
        "Set the public tenant resource plan. The existing AppsTenantPlan "
        "contract accepts memory_bytes=2147483648 for a 2 GiB plan."
    ),
)
def put_plan(
    body: TenantPlanRequest,
    request: Request,
    tenant_id: str | None = None,
    db: Session = Depends(get_db_session),
    context: TenantContext = Depends(get_current_tenant_context),
    user: User = Depends(require_permission("apps.plans.manage")),
) -> dict:
    """Persist the public plan, including 2 GiB RAM, and return effective limits."""
    return plans_service.set_plan(
        db,
        tenant_id=_tenant(context, tenant_id),
        actor=user.id,
        body=body,
        materializer=_resources(request).plan_materializer,
        correlation_id=request.headers.get("X-Request-ID"),
    )


@router.get("/plan", response_model=TenantPlanView | None)
def get_plan(
    tenant_id: str | None = None,
    db: Session = Depends(get_db_session),
    context: TenantContext = Depends(get_current_tenant_context),
    _user: User = Depends(require_permission("apps.plans.manage")),
) -> dict | None:
    """Return the saved plan or ``null``; never reads the host JSON cache."""
    return plans_service.plan_view(db, _tenant(context, tenant_id))


@router.get("/plan/capacity")
def get_plan_capacity(
    request: Request,
    tenant_id: str | None = None,
    db: Session = Depends(get_db_session),
    context: TenantContext = Depends(get_current_tenant_context),
    _user: User = Depends(require_permission("apps.plans.manage")),
) -> dict:
    """Return real host totals and the sum of every assigned plan."""
    return plans_service.capacity(
        db,
        tenant_id=_tenant(context, tenant_id),
        materializer=_resources(request).plan_materializer,
    )


@router.delete("/plan")
def delete_plan(
    request: Request,
    tenant_id: str | None = None,
    db: Session = Depends(get_db_session),
    context: TenantContext = Depends(get_current_tenant_context),
    user: User = Depends(require_permission("apps.plans.manage")),
) -> dict:
    """Dematerialize the slice and drop-in, then delete the DB row."""
    return plans_service.remove_plan(
        db,
        tenant_id=_tenant(context, tenant_id),
        actor=user.id,
        materializer=_resources(request).plan_materializer,
        correlation_id=request.headers.get("X-Request-ID"),
    )


@router.post("/plan/verify")
def verify_plan(
    request: Request,
    tenant_id: str | None = None,
    db: Session = Depends(get_db_session),
    context: TenantContext = Depends(get_current_tenant_context),
    user: User = Depends(require_permission("apps.plans.manage")),
) -> dict:
    """Return kernel evidence that the plan's limits are really applied."""
    return plans_service.verify_plan(
        db,
        tenant_id=_tenant(context, tenant_id),
        actor=user.id,
        materializer=_resources(request).plan_materializer,
        correlation_id=request.headers.get("X-Request-ID"),
    )
