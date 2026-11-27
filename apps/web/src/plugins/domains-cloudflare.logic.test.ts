import { describe, expect, it } from "vitest";

import {
  CLOUDFLARE_FLOW_MAX_MS,
  CLOUDFLARE_HOST_MANAGED,
  CLOUDFLARE_PLATFORM_PERMISSION,
  CLOUDFLARE_UPSTREAM_VALIDATION,
  CLOUDFLARE_ZONE_IN_USE,
  CLOUDFLARE_ZONE_UNOWNED,
  canManageCloudflareClient,
  canManageCloudflareHost,
  canProvisionCloudflare,
  canRegisterClient,
  canStartTenantCloudflare,
  canUseCloudflare,
  cloudflareErrorMessage,
  errorMessageFrom,
  flowDeadline,
  hasZoneWriteScope,
  isCloudflareConnected,
  isCloudflareHostMode,
  needsClientRegistration,
  pollDecision,
  provisionStateMessage,
  recordContentExample,
  recordContentProblem,
  safeUpstreamDetail,
  zoneCount,
} from "../../../../vendor/systutor-core/plugins/domains/frontend/cloudflare/logic";

const connected = {
  connected: true,
  tenant_id: "t1",
  account_id: "acct",
  account_name: "Lab",
  scopes: ["Zone Read", "DNS Read", "DNS Write"],
  expires_at: null,
  status: "active",
  updated_at: null,
};

const connectedProvisioning = {
  ...connected,
  scopes: ["Zone Read", "Zone Write", "DNS Read", "DNS Write", "offline_access"],
};

const hostConnected = {
  ...connected,
  tenant_id: null,
  mode: "single" as const,
  managed_by_host: true,
};

describe("Cloudflare panel policy", () => {
  it("is visible only with the plugin permission", () => {
    expect(canUseCloudflare(["domains.dns.read"])).toBe(false);
    expect(canUseCloudflare(["domains.dns.cloudflare"])).toBe(true);
  });

  it("uses a dedicated permission to register the OAuth client", () => {
    const tenant = ["domains.dns.cloudflare"];
    const registrar = [...tenant, "domains.cloudflare.register"];
    expect(canManageCloudflareClient(tenant)).toBe(false);
    expect(canManageCloudflareClient(registrar)).toBe(true);
    expect(needsClientRegistration({ registered: false })).toBe(true);
    expect(needsClientRegistration({ registered: true })).toBe(false);
    expect(needsClientRegistration({ registered: true, needs_repair: true })).toBe(true);
    expect(needsClientRegistration(null)).toBe(false);
    expect(canRegisterClient(tenant, { registered: false })).toBe(false);
    expect(canRegisterClient(registrar, { registered: false })).toBe(true);
    expect(canRegisterClient(registrar, { registered: true })).toBe(false);
  });

  it("treats only an active connection as connected", () => {
    expect(isCloudflareConnected(null)).toBe(false);
    expect(isCloudflareConnected({ ...connected, connected: false })).toBe(false);
    expect(isCloudflareConnected({ ...connected, status: "disconnected" })).toBe(false);
    expect(isCloudflareConnected(connected)).toBe(true);
  });

  it("clamps the polling deadline to the backend expiry and to five minutes", () => {
    const now = Date.parse("2026-11-12T12:00:00Z");
    expect(flowDeadline(null, now)).toBe(now + CLOUDFLARE_FLOW_MAX_MS);
    expect(flowDeadline("2026-11-12T12:01:00Z", now)).toBe(now + 60_000);
    expect(flowDeadline("2026-11-12T12:30:00Z", now)).toBe(now + CLOUDFLARE_FLOW_MAX_MS);
    expect(flowDeadline("not-a-date", now)).toBe(now + CLOUDFLARE_FLOW_MAX_MS);
  });

  it("stops polling only when connected or expired", () => {
    const deadline = 1_000;
    expect(pollDecision(null, deadline, 500)).toBe("continue");
    expect(pollDecision(connected, deadline, 500)).toBe("connected");
    expect(pollDecision(null, deadline, 1_000)).toBe("expired");
  });

  it("maps normalized HTTP statuses to user messages without leaking bodies", () => {
    expect(cloudflareErrorMessage(403)).toMatch(/permission/);
    expect(cloudflareErrorMessage(404)).toMatch(/not connected/);
    expect(cloudflareErrorMessage(409)).toMatch(/pending/);
    expect(cloudflareErrorMessage(422)).toMatch(/configured/);
    expect(cloudflareErrorMessage(429)).toMatch(/rate limiting/);
    expect(cloudflareErrorMessage(502)).toMatch(/invalid response/);
    expect(cloudflareErrorMessage(503)).toMatch(/unavailable/);
    expect(cloudflareErrorMessage(504)).toMatch(/did not respond/);
    expect(cloudflareErrorMessage(null)).toMatch(/Could not reach/);
  });

  it("extracts status and code from thrown API errors", () => {
    expect(errorMessageFrom({ status: 403, code: "domains.dns.cloudflare.forbidden" }))
      .toMatch(/permission/);
    expect(errorMessageFrom(new Error("secret-canary"))).not.toMatch(/secret-canary/);
  });

  it("shows a sanitized upstream validation detail in the toast", () => {
    expect(
      cloudflareErrorMessage(
        422,
        CLOUDFLARE_UPSTREAM_VALIDATION,
        "Invalid DNS record content",
      ),
    ).toBe("Invalid DNS record content");
    expect(
      errorMessageFrom({
        status: 422,
        code: CLOUDFLARE_UPSTREAM_VALIDATION,
        message: "Bearer abc.def.ghi was rejected 8130fe55771d1075944573b85571bd7b",
      }),
    ).toBe("<redacted> was rejected <redacted>");
  });

  it("keeps the generic 422 message when there is no safe detail", () => {
    expect(cloudflareErrorMessage(422)).toMatch(/configured/);
    expect(
      cloudflareErrorMessage(422, CLOUDFLARE_UPSTREAM_VALIDATION, "   "),
    ).toMatch(/configured/);
  });

  it("offers a per-type example in the content placeholder", () => {
    expect(recordContentExample("A")).toBe("203.0.113.10");
    expect(recordContentExample("AAAA")).toBe("2001:db8::1");
    expect(recordContentExample("cname")).toBe("test2.example.com");
    expect(recordContentExample("TXT")).toMatch(/spf1/);
  });

  it("rejects hostnames in A records and IPv4 in AAAA records locally", () => {
    expect(recordContentProblem("A", "test2.systutor.com")).toMatch(/IPv4/);
    expect(recordContentProblem("A", "203.0.113.10")).toBeNull();
    expect(recordContentProblem("AAAA", "203.0.113.10")).toMatch(/IPv6/);
    expect(recordContentProblem("AAAA", "2001:db8::1")).toBeNull();
    expect(recordContentProblem("CNAME", "test2.systutor.com")).toBeNull();
  });

  it("bounds and redacts credential-like upstream details", () => {
    expect(safeUpstreamDetail("x".repeat(500))).toHaveLength(160);
    expect(safeUpstreamDetail("Bearer abcdefghijklmnop bad")).toBe("<redacted> bad");
  });

  it("counts zones defensively", () => {
    expect(zoneCount(undefined)).toBe(0);
    expect(zoneCount([])).toBe(0);
    expect(zoneCount([{ id: "1" }, { id: "2" }])).toBe(2);
  });

  it("detects Zone Write and provisioning eligibility", () => {
    expect(hasZoneWriteScope(null)).toBe(false);
    expect(hasZoneWriteScope(connected)).toBe(false);
    expect(hasZoneWriteScope(connectedProvisioning)).toBe(true);
    expect(canProvisionCloudflare(connected)).toBe(false);
    expect(canProvisionCloudflare(connectedProvisioning)).toBe(true);
    expect(provisionStateMessage(connected)).toMatch(/Zone Write/);
    expect(provisionStateMessage(connectedProvisioning)).toBeNull();
  });

  it("hides tenant OAuth actions in single mode", () => {
    const tenant = ["domains.dns.cloudflare"];
    expect(isCloudflareHostMode(null)).toBe(false);
    expect(isCloudflareHostMode(connected)).toBe(false);
    expect(isCloudflareHostMode(hostConnected)).toBe(true);
    expect(isCloudflareHostMode({ ...connected, managed_by_host: true })).toBe(true);
    expect(canStartTenantCloudflare(tenant, hostConnected)).toBe(false);
    expect(canStartTenantCloudflare(tenant, connected)).toBe(true);
  });

  it("shows host actions only to platform administrators in single mode", () => {
    const tenant = ["domains.dns.cloudflare"];
    const platform = [...tenant, CLOUDFLARE_PLATFORM_PERMISSION];
    expect(canManageCloudflareHost(tenant, hostConnected)).toBe(false);
    expect(canManageCloudflareHost(platform, hostConnected)).toBe(true);
    expect(canManageCloudflareHost(platform, connected)).toBe(false);
  });

  it("explains host-managed and zone ownership errors", () => {
    expect(cloudflareErrorMessage(409, CLOUDFLARE_HOST_MANAGED)).toMatch(/platform/);
    expect(cloudflareErrorMessage(409, CLOUDFLARE_ZONE_UNOWNED)).toMatch(/adopt/);
    expect(cloudflareErrorMessage(409, CLOUDFLARE_ZONE_IN_USE)).toMatch(/another tenant/);
    expect(
      errorMessageFrom({ status: 409, code: CLOUDFLARE_HOST_MANAGED, message: "raw" }),
    ).toMatch(/platform/);
  });
});
