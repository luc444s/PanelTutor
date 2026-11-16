import { describe, expect, it, vi } from "vitest";

import {
  buildHardeningPolicy, canDeploy, canPlatformMutate, groupedFindings,
  hasBlockingFindings, isOwnedByTenant, isTerminalOperation, parseDotenv,
  parseNumericId, policyCoversServices, probeChecksPassed,
  releaseUsable, serviceUserDrafts, validateWritablePath,
} from "./logic";
import type { Finding, ProbeEvidence, Release } from "./types";

const finding = (severity: Finding["severity"]): Finding => ({
  severity, code: `test.${severity}`, service: "web", path: "Dockerfile", line: 1,
  message: "message", remediation: "fix it",
});

describe("Apps frontend safety logic", () => {
  it("stops polling for every terminal status and not while queued", () => {
    expect(isTerminalOperation({ status: "succeeded" })).toBe(true);
    expect(isTerminalOperation({ status: "failed" })).toBe(true);
    expect(isTerminalOperation({ status: "interrupted" })).toBe(true);
    expect(isTerminalOperation({ status: "queued" })).toBe(false);
  });

  it("allows deploy with the RBAC permission only", () => {
    expect(canDeploy(["apps.deployments.create"])).toBe(true);
    expect(canDeploy(["core.platform.admin"])).toBe(false);
    expect(canDeploy([])).toBe(false);
  });

  it("keeps destructive platform mutations double-gated", () => {
    expect(canPlatformMutate(["apps.applications.delete"], "apps.applications.delete")).toBe(false);
    expect(canPlatformMutate(["core.platform.admin"], "apps.applications.delete")).toBe(false);
    expect(canPlatformMutate(["core.platform.admin", "apps.applications.delete"], "apps.applications.delete")).toBe(true);
  });

  it("keeps applications from another tenant read-only", () => {
    expect(isOwnedByTenant("t1", "t1")).toBe(true);
    expect(isOwnedByTenant("t2", "t1")).toBe(false);
    expect(isOwnedByTenant(null, "t1")).toBe(true);
  });

  it("groups findings and treats every error as blocking", () => {
    const findings = [finding("warning"), finding("error"), finding("info")];
    expect(groupedFindings(findings).error).toHaveLength(1);
    expect(hasBlockingFindings(findings)).toBe(true);
    expect(hasBlockingFindings([finding("warning")])).toBe(false);
  });

  it("parses pasted dotenv text without splitting values on equals", () => {
    expect(parseDotenv(`
# deployment values
APP_NAME=editors
export DATABASE_URL=postgresql://user:p=a=s=s@database/editors
EMPTY=
`)).toEqual([
      { name: "APP_NAME", value: "editors" },
      { name: "DATABASE_URL", value: "postgresql://user:p=a=s=s@database/editors" },
      { name: "EMPTY", value: "" },
    ]);
  });

  it("rejects invalid and duplicate dotenv names", () => {
    expect(() => parseDotenv("BAD NAME=value")).toThrow("line 1");
    expect(() => parseDotenv("API_KEY=one\nAPI_KEY=two")).toThrow(
      "Duplicate .env variable: API_KEY",
    );
    expect(() => parseDotenv("APP_DB_PASSWORD=manual")).toThrow(
      "Apps manages APP_DB_PASSWORD automatically",
    );
  });

  it("builds a complete hardening policy with numeric users and safe paths", () => {
    const drafts = serviceUserDrafts([
      { name: "web", compose_user: "10001:10002" },
      { name: "database", compose_user: null, dockerfile_user: "70:70" },
    ]);
    expect(drafts.web).toEqual({ uid: "10001", gid: "10002" });
    expect(drafts.database).toEqual({ uid: "70", gid: "70" });
    const policy = buildHardeningPolicy(
      ["web", "database"],
      { ...drafts, database: { uid: "70", gid: "70" } },
      [{ service: "database", path: "/var/lib/postgresql/data", mode: "0700" }],
    );
    expect(policy.service_users).toEqual({
      web: { uid: 10001, gid: 10002 },
      database: { uid: 70, gid: 70 },
    });
    expect(policyCoversServices(policy, ["web", "database"])).toBe(true);
    expect(policyCoversServices(policy, ["web"])).toBe(false);
  });

  it("requires a policy for every inspected service before deploy", () => {
    expect(() => buildHardeningPolicy([], {}, [])).toThrow("inspection");
    expect(() => buildHardeningPolicy(
      ["web"], { web: { uid: "10001", gid: "" } }, [],
    )).toThrow("UID and GID");
  });

  it("rejects root ids, non-normalized paths and insecure modes", () => {
    expect(() => parseNumericId("0")).toThrow("positive numeric");
    expect(parseNumericId("10001")).toBe(10001);
    expect(() => validateWritablePath("app/data", "0700")).toThrow("absolute");
    expect(() => validateWritablePath("/app/../root", "0700")).toThrow("normalized");
    expect(() => validateWritablePath("/app/data", "777")).toThrow("four octal");
    expect(() => validateWritablePath("/app/data", "0777")).toThrow("world-writable");
    expect(validateWritablePath("/app/data", "0750")).toEqual({
      path: "/app/data", mode: "0750",
    });
  });

  it("never treats an expired release as usable", () => {
    const release = {
      expires_at: "2026-01-01T00:00:00+00:00",
    } as Release;
    expect(releaseUsable(release, Date.parse("2025-12-31T23:59:59Z"))).toBe(true);
    expect(releaseUsable(release, Date.parse("2026-01-02T00:00:00Z"))).toBe(false);
  });

  it("requires every probe family to be green", () => {
    const probes: ProbeEvidence = {
      isolation: { web: { processes: 2, user: "10001:10002" } },
      functional: { checks: [{ returncode: 0, bytes: 42 }] },
      stability: { checks: 3, restart_counts: { web: 0 } },
    };
    expect(probeChecksPassed(probes)).toBe(true);
    expect(probeChecksPassed({ ...probes, stability: { checks: 3, restart_counts: { web: 1 } } }))
      .toBe(false);
    expect(probeChecksPassed({ ...probes, isolation: { web: { processes: 0 } } }))
      .toBe(false);
    expect(probeChecksPassed({ ...probes, functional: { checks: [] } })).toBe(false);
    expect(probeChecksPassed(null)).toBe(false);
  });


});
