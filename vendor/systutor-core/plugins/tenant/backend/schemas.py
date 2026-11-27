from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from plugins.apps.backend.schemas import TenantPlanRequest
from systutor.contracts.tenant_slugs import CELL_SLUG_RE


class CreateTenantResourcePlan(TenantPlanRequest):
    """A new tenant cannot use the legacy unbounded-storage plan shape."""

    model_config = ConfigDict(extra="forbid")

    storage_bytes: int = Field(gt=0, le=2**63 - 1, strict=True)


class CreateTenantRequest(BaseModel):
    name: str
    slug: str
    domain: str | None = None
    user_email: str
    user_password: str
    user_full_name: str = ""
    resource_plan: CreateTenantResourcePlan

    @field_validator("slug")
    @classmethod
    def _canonical_slug(cls, value: str) -> str:
        """Only canonical slugs: the cell name is derived from this value.

        Accepting dots, accents or uppercase makes the kernel slug diverge
        from the canonical cell slug, which breaks host-side lookups such as
        the phpMyAdmin database relay.
        """
        slug = value.strip()
        if not CELL_SLUG_RE.fullmatch(slug):
            raise ValueError(
                "slug must match [a-z0-9][a-z0-9-]{0,61} (lowercase, digits, hyphens)"
            )
        return slug


class UpdateTenantDomainRequest(BaseModel):
    domain: str | None = None
    site_suffix: str | None = None


class TenantResponse(BaseModel):
    id: str
    name: str
    slug: str
    domain: str | None
    site_suffix: str | None = None
    is_active: bool


class TenantListResponse(BaseModel):
    tenants: list[TenantResponse]


class AssignUserRequest(BaseModel):
    user_id: str


class CreateUserInTenantRequest(BaseModel):
    email: str
    password: str
    full_name: str = ""


class ReassignUserRequest(BaseModel):
    target_tenant_id: str


class TenantUserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    is_active: bool
    branch_id: str | None
    roles: list[str] = []


class TenantUsersResponse(BaseModel):
    users: list[TenantUserResponse]


class TenantRoleResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    permissions: list[str]
    active: bool
    created_at: datetime
    updated_at: datetime


class TenantRolesResponse(BaseModel):
    roles: list[TenantRoleResponse]


class TenantPermissionResponse(BaseModel):
    id: str
    name: str
    description: str | None
    created_at: datetime


class TenantPermissionsResponse(BaseModel):
    permissions: list[TenantPermissionResponse]


class ReplaceTenantUserRoleRequest(BaseModel):
    role_id: str


class UpdateTenantRoleRequest(BaseModel):
    permission_names: list[str]


class TenantDomainItem(BaseModel):
    domain: str


class TenantDomainsResponse(BaseModel):
    domains: list[TenantDomainItem]


class AddTenantDomainRequest(BaseModel):
    domain: str


class TenantResourceResponse(BaseModel):
    kind: str
    resource_id: str
    name: str
    container_name: str
    domain: str | None
    state: str
    image: str
    endpoint: str | None
    runtime: str


class TenantResourcesResponse(BaseModel):
    resources: list[TenantResourceResponse]


class TenantResourceActionResponse(BaseModel):
    action: str
    dry_run: bool
    runtime: str
    resource: TenantResourceResponse
    result: dict[str, object] | None = None
