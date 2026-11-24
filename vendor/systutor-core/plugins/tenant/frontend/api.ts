import { apiRequest, getApiBaseUrl } from "@systutor/shell/api/client";

export type TenantResponse = {
  id: string;
  name: string;
  slug: string;
  domain: string | null;
  site_suffix: string | null;
  is_active: boolean;
};

export type TenantListResponse = {
  tenants: TenantResponse[];
};

export type TenantUserResponse = {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  branch_id: string | null;
  roles: string[];
};

export type TenantUsersResponse = {
  users: TenantUserResponse[];
};

export type TenantRoleResponse = {
  id: string;
  tenant_id: string;
  name: string;
  permissions: string[];
  active: boolean;
  created_at: string;
  updated_at: string;
};

export type TenantRolesResponse = { roles: TenantRoleResponse[] };

export type TenantPermissionResponse = {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
};

export type TenantPermissionsResponse = { permissions: TenantPermissionResponse[] };

export type TenantDomainItem = {
  domain: string;
};

export type TenantDomainsResponse = {
  domains: TenantDomainItem[];
};

export type TenantResource = {
  kind: string;
  resource_id: string;
  name: string;
  container_name: string;
  domain: string | null;
  state: string;
  image: string;
  endpoint: string | null;
  runtime: "rootful" | "rootless";
};

export type TenantResourcesResponse = { resources: TenantResource[] };

export type TenantResourceActionResponse = {
  action: "start" | "stop" | "restart" | "remove";
  dry_run: boolean;
  runtime: "rootful" | "rootless";
  resource: TenantResource;
  result: Record<string, unknown> | null;
};

export type TenantPlan = {
  tenant_id: string;
  tenant_slug: string;
  memory_bytes: number;
  cpus: number;
  pids: number;
  cpuset: string | null;
  storage_bytes: number | null;
  status: "applied" | "pending" | "failed";
  applied_at: string | null;
  last_error: string | null;
  updated_at: string | null;
  slice: string;
  cgroup_path: string;
};

export type TenantPlanPayload = {
  memory_bytes: number;
  cpus: number;
  pids: number;
  cpuset?: string | null;
  storage_bytes?: number | null;
};

export type TenantPlanCapacity = {
  tenant_id: string;
  host: {
    memory_bytes: number;
    cpus: number;
    storage_bytes: number;
    storage_available_bytes: number;
    read_at: string | null;
    source: string | null;
    data_root: string | null;
  };
  allocated: {
    memory_bytes: number;
    cpus: number;
    pids: number;
    storage_bytes: number;
  };
  unbounded_storage: number;
};

export type CreateTenantPayload = {
  name: string;
  slug: string;
  domain?: string;
  user_email: string;
  user_password: string;
  user_full_name?: string;
  resource_plan: {
    memory_bytes: number;
    cpus: number;
    pids: number;
    storage_bytes: number;
  };
};

export type UpdateTenantPayload = {
  domain?: string | null;
  site_suffix?: string | null;
};

export type AssignUserPayload = {
  user_id: string;
};

export type CreateUserInTenantPayload = {
  email: string;
  password: string;
  full_name?: string;
};

export type ReassignUserPayload = {
  target_tenant_id: string;
};

export const tenantKeys = {
  tenants: ["tenant", "tenants"] as const,
  users: (tenantId: string) => ["tenant", tenantId, "users"] as const,
  roles: (tenantId: string) => ["tenant", tenantId, "roles"] as const,
  permissions: (tenantId: string) => ["tenant", tenantId, "permissions"] as const,
  domains: (tenantId: string) => ["tenant", tenantId, "domains"] as const,
  resources: (tenantId: string) => ["tenant", tenantId, "resources"] as const,
  plan: (tenantId: string) => ["tenant", tenantId, "plan"] as const,
  capacity: (tenantId: string) => ["tenant", tenantId, "capacity"] as const,
};

export function listTenants() {
  return apiRequest<TenantListResponse>("/api/v1/plugins/tenant/tenants");
}

export function createTenant(payload: CreateTenantPayload) {
  return apiRequest<TenantResponse>("/api/v1/plugins/tenant/tenants", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function updateTenant(tenantId: string, payload: UpdateTenantPayload) {
  return apiRequest<TenantResponse>(`/api/v1/plugins/tenant/tenants/${tenantId}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function listTenantUsers(tenantId: string) {
  return apiRequest<TenantUsersResponse>(`/api/v1/plugins/tenant/tenants/${tenantId}/users`);
}

export function listTenantRoles(tenantId: string) {
  return apiRequest<TenantRolesResponse>(`/api/v1/plugins/tenant/tenants/${tenantId}/roles`);
}

export function listTenantPermissions(tenantId: string) {
  return apiRequest<TenantPermissionsResponse>(`/api/v1/plugins/tenant/tenants/${tenantId}/permissions`);
}

export function replaceTenantUserRole(tenantId: string, userId: string, roleId: string) {
  return apiRequest<TenantUserResponse>(
    `/api/v1/plugins/tenant/tenants/${tenantId}/users/${userId}/role`,
    { method: "PUT", body: JSON.stringify({ role_id: roleId }) },
  );
}

export function updateTenantRolePermissions(
  tenantId: string,
  roleId: string,
  permissionNames: string[],
) {
  return apiRequest<TenantRoleResponse>(
    `/api/v1/plugins/tenant/tenants/${tenantId}/roles/${roleId}`,
    { method: "PATCH", body: JSON.stringify({ permission_names: permissionNames }) },
  );
}

export function listTenantDomains(tenantId: string) {
  return apiRequest<TenantDomainsResponse>(`/api/v1/plugins/tenant/tenants/${tenantId}/domains`);
}

export function addTenantDomain(tenantId: string, domain: string) {
  return apiRequest<TenantDomainItem>(`/api/v1/plugins/tenant/tenants/${tenantId}/domains`, {
    method: "POST",
    body: JSON.stringify({ domain }),
  });
}

export function removeTenantDomain(tenantId: string, domain: string) {
  return apiRequest<void>(
    `/api/v1/plugins/tenant/tenants/${tenantId}/domains/${encodeURIComponent(domain)}`,
    { method: "DELETE" }
  );
}

export function listTenantResources(tenantId: string) {
  return apiRequest<TenantResourcesResponse>(
    `/api/v1/plugins/tenant/tenants/${tenantId}/resources`,
  );
}

export function actOnTenantResource(
  tenantId: string,
  resource: Pick<TenantResource, "kind" | "resource_id">,
  action: "start" | "stop" | "restart" | "remove",
  dryRun = false,
) {
  const kind = encodeURIComponent(resource.kind);
  const resourceId = encodeURIComponent(resource.resource_id);
  return apiRequest<TenantResourceActionResponse>(
    `/api/v1/plugins/tenant/tenants/${tenantId}/resources/${kind}/${resourceId}/actions/${action}?dry_run=${dryRun ? 1 : 0}`,
    { method: "POST" },
  );
}

function planQuery(tenantId: string) {
  return `?tenant_id=${encodeURIComponent(tenantId)}`;
}

export function getTenantPlan(tenantId: string) {
  return apiRequest<TenantPlan | null>(
    `/api/v1/plugins/apps/plan${planQuery(tenantId)}`,
  );
}

export function setTenantPlan(tenantId: string, payload: TenantPlanPayload) {
  return apiRequest<TenantPlan>(
    `/api/v1/plugins/apps/plan${planQuery(tenantId)}`,
    { method: "POST", body: JSON.stringify(payload) },
  );
}

export function deleteTenantPlan(tenantId: string) {
  return apiRequest<Record<string, unknown>>(
    `/api/v1/plugins/apps/plan${planQuery(tenantId)}`,
    { method: "DELETE" },
  );
}

export function verifyTenantPlan(tenantId: string) {
  return apiRequest<Record<string, unknown>>(
    `/api/v1/plugins/apps/plan/verify${planQuery(tenantId)}`,
    { method: "POST" },
  );
}

export function getTenantPlanCapacity(tenantId: string) {
  return apiRequest<TenantPlanCapacity>(
    `/api/v1/plugins/apps/plan/capacity${planQuery(tenantId)}`,
  );
}

/**
 * Absolute SSE URL for the live metrics stream. `EventSource` cannot send an
 * `Authorization` header, so the panel uses `fetch` with this URL and the
 * bearer token from the auth store.
 */
export function tenantMetricsStreamUrl(tenantId: string, intervalMs = 1000) {
  const path = `/api/v1/plugins/tenant/tenants/${encodeURIComponent(tenantId)}/metrics/stream?interval_ms=${intervalMs}`;
  const baseUrl = getApiBaseUrl();
  return baseUrl.endsWith("/api") ? `${baseUrl}${path.slice(4)}` : `${baseUrl}${path}`;
}

export function assignUserToTenant(tenantId: string, payload: AssignUserPayload) {
  return apiRequest<TenantUserResponse>(`/api/v1/plugins/tenant/tenants/${tenantId}/users/assign`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function createUserInTenant(tenantId: string, payload: CreateUserInTenantPayload) {
  return apiRequest<TenantUserResponse>(`/api/v1/plugins/tenant/tenants/${tenantId}/users`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function reassignUserFromTenant(tenantId: string, userId: string, payload: ReassignUserPayload) {
  return apiRequest<TenantUserResponse>(`/api/v1/plugins/tenant/tenants/${tenantId}/users/${userId}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}
