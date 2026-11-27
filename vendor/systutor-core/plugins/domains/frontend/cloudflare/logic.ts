import type { CloudflareStatus } from "./types";

export const CLOUDFLARE_PERMISSION = "domains.dns.cloudflare";
export const CLOUDFLARE_REGISTER_PERMISSION = "domains.cloudflare.register";
export const CLOUDFLARE_PLATFORM_PERMISSION = "core.platform.admin";
export const CLOUDFLARE_POLL_INTERVAL_MS = 2000;
export const CLOUDFLARE_FLOW_MAX_MS = 5 * 60 * 1000;
export const CLOUDFLARE_UPSTREAM_VALIDATION = "domains.dns.cloudflare.upstream_validation";
export const CLOUDFLARE_HOST_MANAGED = "domains.dns.cloudflare.host_managed";
export const CLOUDFLARE_ZONE_UNOWNED = "domains.dns.cloudflare.zone_unowned";
export const CLOUDFLARE_ZONE_IN_USE = "domains.dns.cloudflare.zone_in_use";

const IPV4_PATTERN = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IPV6_PATTERN = /^[0-9A-Fa-f:]+$/;

export function canUseCloudflare(permissions: readonly string[]): boolean {
  return permissions.includes(CLOUDFLARE_PERMISSION);
}

export function canManageCloudflareClient(permissions: readonly string[]): boolean {
  return permissions.includes(CLOUDFLARE_REGISTER_PERMISSION);
}

export function isCloudflareHostMode(status: CloudflareStatus | null | undefined): boolean {
  return status?.mode === "single" || status?.managed_by_host === true;
}

export function canManageCloudflareHost(
  permissions: readonly string[],
  status: CloudflareStatus | null | undefined,
): boolean {
  return (
    isCloudflareHostMode(status) &&
    permissions.includes(CLOUDFLARE_PLATFORM_PERMISSION) &&
    permissions.includes(CLOUDFLARE_PERMISSION)
  );
}

/** Whether the tenant button may call the tenant-scoped `/oauth/start`. */
export function canStartTenantCloudflare(
  permissions: readonly string[],
  status: CloudflareStatus | null | undefined,
): boolean {
  return canUseCloudflare(permissions) && !isCloudflareHostMode(status);
}

export function cloudflareHostStateMessage(status: CloudflareStatus | null): string | null {
  if (!isCloudflareHostMode(status)) return null;
  return status?.connected
    ? "Cloudflare is managed by the platform."
    : "Cloudflare is managed by the platform and is not connected yet.";
}

export function needsClientRegistration(
  status: { registered: boolean; needs_repair?: boolean } | null | undefined,
): boolean {
  return status?.registered === false || status?.needs_repair === true;
}

export function canRegisterClient(
  permissions: readonly string[],
  status: { registered: boolean; needs_repair?: boolean } | null | undefined,
): boolean {
  return canManageCloudflareClient(permissions) && needsClientRegistration(status);
}

export function isCloudflareConnected(status: CloudflareStatus | null): boolean {
  return Boolean(status?.connected && status.status === "active");
}

/** Deadline derived from the backend flow expiry, clamped to five minutes. */
export function flowDeadline(expiresAt: string | null | undefined, now: number): number {
  const parsed = expiresAt ? Date.parse(expiresAt) : Number.NaN;
  const limit = now + CLOUDFLARE_FLOW_MAX_MS;
  if (!Number.isFinite(parsed)) {
    return limit;
  }
  return Math.min(parsed, limit);
}

export type PollDecision = "connected" | "expired" | "continue";

export function pollDecision(
  status: CloudflareStatus | null,
  deadline: number,
  now: number,
): PollDecision {
  if (isCloudflareConnected(status)) {
    return "connected";
  }
  return now >= deadline ? "expired" : "continue";
}

export function accountLabel(status: CloudflareStatus | null): string {
  return status?.account_name?.trim() || "Cloudflare";
}

export function scopeNames(status: CloudflareStatus | null): string {
  return (status?.scopes ?? []).join(", ");
}

export function zoneCount(items: readonly unknown[] | null | undefined): number {
  return items?.length ?? 0;
}

/** Placeholder example shown inside the content field, per record type. */
export function recordContentExample(type: string): string {
  switch (type.trim().toUpperCase()) {
    case "A":
      return "203.0.113.10";
    case "AAAA":
      return "2001:db8::1";
    case "CNAME":
    case "MX":
    case "NS":
      return "test2.example.com";
    case "SRV":
      return "10 5 443 service.example.com";
    case "CAA":
      return "0 issue letsencrypt.org";
    case "TXT":
      return "v=spf1 include:example.com ~all";
    default:
      return "";
  }
}

/**
 * Local guard for the two record types whose content format is unambiguous.
 * Other types are left to Cloudflare. Returns a translation key or null.
 */
export function recordContentProblem(type: string, content: string): string | null {
  const value = content.trim();
  if (!value) return null;
  switch (type.trim().toUpperCase()) {
    case "A":
      return IPV4_PATTERN.test(value)
        ? null
        : "An A record requires an IPv4 address (e.g. 203.0.113.10).";
    case "AAAA":
      return IPV6_PATTERN.test(value) && value.includes(":") && !value.includes(":::")
        ? null
        : "An AAAA record requires an IPv6 address (e.g. 2001:db8::1).";
    default:
      return null;
  }
}

/** Strip credential-looking data before showing an upstream validation message. */
export function safeUpstreamDetail(detail: string): string {
  return detail
    .replace(/Bearer\s+\S+/gi, "<redacted>")
    .replace(/\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b/g, "<redacted>")
    .replace(/\b[0-9a-fA-F]{32}\b/g, "<redacted>")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 160);
}

/**
 * Normalized user message for a failed Cloudflare request. Only a sanitized,
 * bounded upstream validation detail may be shown; never a raw body, a token
 * or an account identifier.
 */
export function cloudflareErrorMessage(
  httpStatus: number | null,
  code: string | null = null,
  detail: string | null = null,
): string {
  if (code === CLOUDFLARE_UPSTREAM_VALIDATION && detail) {
    const safe = safeUpstreamDetail(detail);
    if (safe) return safe;
  }
  if (code === "domains.dns.cloudflare.account_id_required") {
    return "Enter the Cloudflare Account ID shown in the account dashboard.";
  }
  if (code === "domains.dns.cloudflare.account_not_found") {
    return "Cloudflare could not find that Account ID. Check it and try again.";
  }
  if (code === CLOUDFLARE_HOST_MANAGED) {
    return "Cloudflare is managed by the platform. A platform administrator must connect or disconnect it.";
  }
  if (code === CLOUDFLARE_ZONE_UNOWNED) {
    return "This zone exists in the platform Cloudflare account but is not assigned to this tenant yet. A platform administrator must adopt it.";
  }
  if (code === CLOUDFLARE_ZONE_IN_USE) {
    return "This Cloudflare zone is assigned to another tenant.";
  }
  switch (httpStatus) {
    case 401:
      return "Your session expired. Sign in again.";
    case 403:
      return "You do not have permission to manage the Cloudflare connection.";
    case 404:
      return "Cloudflare is not connected for this tenant.";
    case 409:
      return "Cloudflare already has a pending authorization or a registered client.";
    case 422:
      return "Cloudflare is not configured correctly on this server. The OAuth client may not be registered yet.";
    case 429:
      return "Cloudflare is rate limiting requests. Try again in a moment.";
    case 502:
      return "Cloudflare returned an invalid response.";
    case 503:
      return "Cloudflare is unavailable right now.";
    case 504:
      return "Cloudflare did not respond in time.";
    default:
      if (code === "domains.dns.cloudflare.conflict") {
        return "Cloudflare already has a pending authorization or a registered client.";
      }
      return "Could not reach Cloudflare. Try again.";
  }
}

/** Convert an unknown thrown value into a normalized message without leaking it. */
export function errorMessageFrom(error: unknown): string {
  if (typeof error === "object" && error !== null) {
    const candidate = error as { status?: unknown; code?: unknown; message?: unknown };
    const status = typeof candidate.status === "number" ? candidate.status : null;
    const code = typeof candidate.code === "string" ? candidate.code : null;
    const message = typeof candidate.message === "string" ? candidate.message : null;
    return cloudflareErrorMessage(status, code, message);
  }
  return cloudflareErrorMessage(null);
}

export function hasZoneWriteScope(status: CloudflareStatus | null): boolean {
  return Boolean(status?.scopes?.some((scope) => /zone\s*write/i.test(scope)));
}

export function canProvisionCloudflare(status: CloudflareStatus | null): boolean {
  return isCloudflareConnected(status) && hasZoneWriteScope(status);
}

export function provisionStateMessage(status: CloudflareStatus | null): string | null {
  if (!status || !isCloudflareConnected(status)) return null;
  if (!hasZoneWriteScope(status)) {
    return "Cloudflare is connected without Zone Write permission. Reconnect to enable provisioning.";
  }
  return null;
}
