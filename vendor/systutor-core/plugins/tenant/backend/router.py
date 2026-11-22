from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from plugins.tenant.backend.schemas import (
    AddTenantDomainRequest,
    AssignUserRequest,
    CreateTenantRequest,
    CreateUserInTenantRequest,
    ReassignUserRequest,
    TenantDomainItem,
    TenantDomainsResponse,
    TenantListResponse,
    TenantResourceActionResponse,
    TenantResourceResponse,
    TenantResourcesResponse,
    TenantResponse,
    TenantUserResponse,
    TenantUsersResponse,
    UpdateTenantDomainRequest,
)
from plugins.tenant.backend.service import (
    add_managed_domain,
    assign_user_to_tenant,
    create_tenant,
    create_user_for_tenant,
    get_runtime,
    get_site_suffix_for_tenant,
    get_tenant_by_id,
    list_managed_domains,
    list_tenants,
    list_users_for_tenant,
    remove_managed_domain,
    remove_user_from_tenant,
)
from plugins.tenant.backend.service import (
    update_tenant as update_tenant_settings,
)
from systutor.api.deps import get_db_session
from systutor.contracts.resource_runtime import ManagedResource, list_resources
from systutor.core.errors import AppError
from systutor.kernel.auth.dependencies import (
    get_current_tenant_context,
    require_permission,
)
from systutor.kernel.auth.models import User
from systutor.kernel.auth.service import get_user_by_id
from systutor.kernel.permissions.service import list_user_role_names
from systutor.kernel.tenants.context import TenantContext
from systutor.kernel.tenants.models import Tenant

router = APIRouter(prefix="/tenants", tags=["tenants"])
inventory_router = APIRouter(prefix="/tenants", tags=["tenant-resources"])


def _user_response(db: Session, user: User) -> TenantUserResponse:
    return TenantUserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        branch_id=user.branch_id,
        roles=list_user_role_names(db, tenant_id=user.tenant_id, user_id=user.id),
    )


def _tenant_response(db: Session, tenant: Tenant) -> TenantResponse:
    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        domain=tenant.domain,
        site_suffix=get_site_suffix_for_tenant(db, tenant.id),
        is_active=tenant.is_active,
    )


def _resource_response(
    db: Session, tenant_id: str, resource: ManagedResource
) -> TenantResourceResponse:
    return TenantResourceResponse(
        **resource.__dict__,
        runtime=get_runtime(db, tenant_id, resource.kind, resource.resource_id),
    )


def _resource_scope(context: TenantContext, tenant_id: str) -> None:
    if not context.is_platform and tenant_id != context.current_tenant_id:
        raise HTTPException(status_code=404, detail="Resource not found")


def _find_resource(
    request: Request,
    db: Session,
    tenant_id: str,
    kind: str,
    resource_id: str,
) -> ManagedResource:
    for resource in list_resources(request.app, db, tenant_id):
        if resource.kind == kind and resource.resource_id == resource_id:
            return resource
    raise HTTPException(status_code=404, detail="Resource not found")


def _require_resource_permission(
    context: TenantContext, kind: str, action: str
) -> None:
    if kind == "app":
        permission = "apps.applications.manage"
        platform_only = False
    else:
        permission = "hosting.sites.delete" if action == "remove" else "hosting.sites.manage"
        platform_only = action == "remove"
    if not context.has_permission(permission) or (platform_only and not context.is_platform):
        raise HTTPException(status_code=403, detail="Permission denied")


def _dispatch_rootful(
    request: Request,
    db: Session,
    context: TenantContext,
    user: User,
    resource: ManagedResource,
    action: str,
) -> dict[str, object]:
    if resource.kind == "app":
        from plugins.apps.backend.router import application_action
        from plugins.apps.backend.schemas import ActionRequest

        application_id, service = resource.resource_id.split(":", 1)
        mapped = "down" if action == "remove" else action
        operation = application_action(
            application_id,
            mapped,
            request,
            ActionRequest(service=None if mapped == "down" else service),
            None,
            db,
            context,
            user,
        )
        return operation.model_dump()

    from plugins.hosting.backend.models import HostingSite
    from plugins.hosting.backend.service import HostingService

    site = db.scalar(
        select(HostingSite).where(
            HostingSite.id == resource.resource_id,
            HostingSite.tenant_id == context.current_tenant_id
            if not context.is_platform
            else HostingSite.tenant_id.is_not(None),
        )
    )
    if site is None:
        raise HTTPException(status_code=404, detail="Resource not found")
    service = HostingService(db)
    if action == "remove":
        service.delete_site(site, context, app=request.app)
        db.commit()
        return {"status": "removed"}
    result = getattr(service, f"{action}_site")(site, context)
    db.commit()
    return result.model_dump()


def _dispatch_rootless(
    request: Request,
    db: Session,
    tenant_id: str,
    resource: ManagedResource,
    action: str,
) -> dict[str, object]:
    from plugins.apps.backend.runtime.tenant_runtime import (
        TenantRuntimeRegistry,
        tenant_slug,
    )

    registry = getattr(request.app.state, "tenant_runtime_registry", None)
    if registry is None:
        registry = TenantRuntimeRegistry()
    slug = tenant_slug(db, tenant_id)
    runtime = registry.for_tenant(tenant_id, slug)
    verb = "rm" if action == "remove" else action
    result = runtime.exec_probe(slug, ["docker", "container", verb, resource.container_name])
    return {
        "status": "dispatched",
        "returncode": getattr(result, "returncode", 0),
    }


@inventory_router.get("/{tenant_id}/resources", response_model=TenantResourcesResponse)
def list_tenant_resources(
    tenant_id: str,
    request: Request,
    db: Session = Depends(get_db_session),
    context: TenantContext = Depends(get_current_tenant_context),
    _current_user: User = Depends(require_permission("tenant.tenants.read")),
) -> TenantResourcesResponse:
    _resource_scope(context, tenant_id)
    if db.get(Tenant, tenant_id) is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return TenantResourcesResponse(
        resources=[
            _resource_response(db, tenant_id, resource)
            for resource in list_resources(request.app, db, tenant_id)
        ]
    )


@inventory_router.get(
    "/{tenant_id}/resources/{kind}/{resource_id}",
    response_model=TenantResourceResponse,
)
def get_tenant_resource(
    tenant_id: str,
    kind: str,
    resource_id: str,
    request: Request,
    db: Session = Depends(get_db_session),
    context: TenantContext = Depends(get_current_tenant_context),
    _current_user: User = Depends(require_permission("tenant.tenants.read")),
) -> TenantResourceResponse:
    _resource_scope(context, tenant_id)
    return _resource_response(
        db, tenant_id, _find_resource(request, db, tenant_id, kind, resource_id)
    )


@inventory_router.post(
    "/{tenant_id}/resources/{kind}/{resource_id}/actions/{action}",
    response_model=TenantResourceActionResponse,
)
def act_on_tenant_resource(
    tenant_id: str,
    kind: str,
    resource_id: str,
    action: str,
    request: Request,
    dry_run: int = Query(default=0),
    db: Session = Depends(get_db_session),
    context: TenantContext = Depends(get_current_tenant_context),
    current_user: User = Depends(require_permission("tenant.tenants.manage")),
) -> TenantResourceActionResponse:
    _resource_scope(context, tenant_id)
    if action not in {"start", "stop", "restart", "remove"}:
        raise HTTPException(status_code=404, detail="Action not found")
    resource = _find_resource(request, db, tenant_id, kind, resource_id)
    _require_resource_permission(context, kind, action)
    dispatch_context = context
    if context.is_platform and context.current_tenant_id != tenant_id:
        dispatch_context = TenantContext(
            current_tenant_id=tenant_id,
            current_branch_id=context.current_branch_id,
            current_user_id=context.current_user_id,
            current_permissions=context.current_permissions,
            current_warehouse_ids=context.current_warehouse_ids,
        )
    runtime = get_runtime(db, tenant_id, kind, resource_id)
    response_resource = _resource_response(db, tenant_id, resource)
    if dry_run == 1:
        return TenantResourceActionResponse(
            action=action,
            dry_run=True,
            runtime=runtime,
            resource=response_resource,
            result={"dispatch": runtime},
        )
    result = (
        _dispatch_rootful(request, db, dispatch_context, current_user, resource, action)
        if runtime == "rootful"
        else _dispatch_rootless(request, db, tenant_id, resource, action)
    )
    return TenantResourceActionResponse(
        action=action,
        dry_run=False,
        runtime=runtime,
        resource=response_resource,
        result=result,
    )


@router.get("", response_model=TenantListResponse)
def list_all_tenants(
    db: Session = Depends(get_db_session),
    _current_user: User = Depends(require_permission("tenant.tenants.read", platform_only=True)),
) -> TenantListResponse:
    tenants = list_tenants(db)
    return TenantListResponse(
        tenants=[_tenant_response(db, tenant) for tenant in tenants]
    )


@router.post("", response_model=TenantResponse, status_code=201)
def create_new_tenant(
    body: CreateTenantRequest,
    db: Session = Depends(get_db_session),
    _current_user: User = Depends(require_permission("tenant.tenants.manage", platform_only=True)),
) -> TenantResponse:
    try:
        tenant = create_tenant(db, name=body.name, slug=body.slug, domain=body.domain)
        create_user_for_tenant(
            db,
            tenant_id=tenant.id,
            email=body.user_email,
            password=body.user_password,
            full_name=body.user_full_name,
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise AppError(
            "The domain, slug, or email is already in use",
            status_code=409,
            code="tenant_conflict",
        ) from exc
    return _tenant_response(db, tenant)


@router.put("/{tenant_id}", response_model=TenantResponse)
def update_tenant(
    tenant_id: str,
    body: UpdateTenantDomainRequest,
    db: Session = Depends(get_db_session),
    _current_user: User = Depends(require_permission("tenant.tenants.manage", platform_only=True)),
) -> TenantResponse:
    tenant = get_tenant_by_id(db, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    fields = body.model_fields_set
    if not fields:
        raise AppError(
            "There is nothing to update",
            status_code=422,
            code="tenant_update_empty",
        )

    updates: dict[str, str | None] = {}
    if "domain" in fields:
        updates["domain"] = body.domain
    if "site_suffix" in fields:
        updates["site_suffix"] = body.site_suffix

    try:
        updated = update_tenant_settings(db, tenant=tenant, **updates)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if "site_suffix" in fields:
            raise AppError(
                "The suffix is already assigned to another tenant",
                status_code=409,
                code="tenant_site_suffix_conflict",
            ) from exc
        raise AppError(
            "The domain is already assigned to another tenant",
            status_code=409,
            code="tenant_domain_conflict",
        ) from exc
    return _tenant_response(db, updated)


@router.get("/{tenant_id}/domains", response_model=TenantDomainsResponse)
def list_tenant_domains(
    tenant_id: str,
    db: Session = Depends(get_db_session),
    _current_user: User = Depends(require_permission("tenant.tenants.read", platform_only=True)),
) -> TenantDomainsResponse:
    tenant = get_tenant_by_id(db, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return TenantDomainsResponse(
        domains=[TenantDomainItem(domain=domain) for domain in list_managed_domains(db, tenant_id)]
    )


@router.post("/{tenant_id}/domains", response_model=TenantDomainItem, status_code=201)
def add_tenant_domain(
    tenant_id: str,
    body: AddTenantDomainRequest,
    request: Request,
    db: Session = Depends(get_db_session),
    _current_user: User = Depends(require_permission("tenant.tenants.manage", platform_only=True)),
) -> TenantDomainItem:
    tenant = get_tenant_by_id(db, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    try:
        row, _created = add_managed_domain(
            db, tenant=tenant, domain=body.domain, app=request.app
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise AppError(
            "The domain is already assigned to another tenant",
            status_code=409,
            code="tenant_domain_conflict",
        ) from exc
    return TenantDomainItem(domain=row.domain)


@router.delete("/{tenant_id}/domains/{domain}", status_code=204)
def delete_tenant_domain(
    tenant_id: str,
    domain: str,
    request: Request,
    db: Session = Depends(get_db_session),
    _current_user: User = Depends(require_permission("tenant.tenants.manage", platform_only=True)),
) -> Response:
    tenant = get_tenant_by_id(db, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    try:
        remove_managed_domain(db, tenant=tenant, domain=domain, app=request.app)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return Response(status_code=204)


@router.get("/{tenant_id}/users", response_model=TenantUsersResponse)
def list_tenant_users(
    tenant_id: str,
    db: Session = Depends(get_db_session),
    _current_user: User = Depends(require_permission("tenant.tenants.read", platform_only=True)),
) -> TenantUsersResponse:
    tenant = get_tenant_by_id(db, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    users = list_users_for_tenant(db, tenant_id)
    return TenantUsersResponse(
        users=[_user_response(db, user) for user in users]
    )


@router.post("/{tenant_id}/users", response_model=TenantUserResponse, status_code=201)
def create_user_in_tenant(
    tenant_id: str,
    body: CreateUserInTenantRequest,
    db: Session = Depends(get_db_session),
    _current_user: User = Depends(require_permission("tenant.tenants.manage", platform_only=True)),
) -> TenantUserResponse:
    tenant = get_tenant_by_id(db, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    user = create_user_for_tenant(
        db,
        tenant_id=tenant_id,
        email=body.email,
        password=body.password,
        full_name=body.full_name,
    )
    db.commit()
    return _user_response(db, user)


@router.post("/{tenant_id}/users/assign", response_model=TenantUserResponse, status_code=201)
def assign_existing_user(
    tenant_id: str,
    body: AssignUserRequest,
    db: Session = Depends(get_db_session),
    _current_user: User = Depends(require_permission("tenant.tenants.manage", platform_only=True)),
) -> TenantUserResponse:
    tenant = get_tenant_by_id(db, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    user = get_user_by_id(db, body.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        updated = assign_user_to_tenant(db, user=user, tenant_id=tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    return _user_response(db, updated)


@router.put("/{tenant_id}/users/{user_id}", response_model=TenantUserResponse)
def reassign_user(
    tenant_id: str,
    user_id: str,
    body: ReassignUserRequest,
    db: Session = Depends(get_db_session),
    _current_user: User = Depends(require_permission("tenant.tenants.manage", platform_only=True)),
) -> TenantUserResponse:
    tenant = get_tenant_by_id(db, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    target_tenant = get_tenant_by_id(db, body.target_tenant_id)
    if target_tenant is None:
        raise HTTPException(status_code=404, detail="Target tenant not found")
    user = get_user_by_id(db, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="User not in this tenant")
    updated = remove_user_from_tenant(db, user=user, target_tenant_id=body.target_tenant_id)
    db.commit()
    return _user_response(db, updated)
