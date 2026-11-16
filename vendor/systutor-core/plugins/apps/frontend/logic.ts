import { t } from "@/i18n";

import type {
  Application, EnvironmentEntry, Finding, GithubStatus, HardeningPolicy,
  HardeningWritablePath, Operation, ProbeEvidence, Release,
} from "./types";

export const GITHUB_CARD_STATES = [
  "loading", "unconfigured", "registering", "pending_installation",
  "syncing", "connected", "suspended", "error",
] as const;

export type GithubCardState = (typeof GITHUB_CARD_STATES)[number];

const GITHUB_ORGANIZATION = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MANAGED_ENVIRONMENT_NAMES = new Set([
  "APP_DB_NAME", "APP_DB_USER", "APP_DB_PASSWORD",
]);

export const TERMINAL_STATUSES = new Set(["succeeded", "failed", "interrupted"]);
export const isTerminalOperation = (operation?: Pick<Operation, "status"> | null) =>
  Boolean(operation && TERMINAL_STATUSES.has(operation.status));

export function parseDotenv(text: string): EnvironmentEntry[] {
  const entries: EnvironmentEntry[] = [];
  const names = new Set<string>();
  for (const [index, raw] of text.split(/\r?\n/).entries()) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const line = trimmed.startsWith("export ") ? trimmed.slice(7).trimStart() : raw;
    const separator = line.indexOf("=");
    const name = separator < 0 ? "" : line.slice(0, separator).trim();
    if (!ENVIRONMENT_NAME.test(name)) {
      throw new Error(t("Invalid .env variable on line {line}", { line: index + 1 }));
    }
    if (names.has(name)) {
      throw new Error(t("Duplicate .env variable: {name}", { name }));
    }
    if (MANAGED_ENVIRONMENT_NAMES.has(name)) {
      throw new Error(t("Apps manages {name} automatically", { name }));
    }
    const value = line.slice(separator + 1);
    if (value.includes("\0") || value.length > 8192) {
      throw new Error(t("Invalid .env value for {name}", { name }));
    }
    names.add(name);
    entries.push({ name, value });
  }
  if (entries.length > 100) throw new Error(t("The deployment allows up to 100 variables"));
  return entries;
}

const GITHUB_CARD_LABELS: Record<GithubCardState, string> = {
  loading: "Checking GitHub status…",
  unconfigured: "Not connected",
  registering: "Registering GitHub App…",
  pending_installation: "App registered; install it and choose repositories",
  syncing: "Syncing authorized repositories…",
  connected: "GitHub connected",
  suspended: "Installation suspended",
  error: "Could not read GitHub status",
};

const GITHUB_ERROR_MESSAGE = "Could not read GitHub status";

export function githubCardContent(state: GithubCardState) {
  if (state === "error") {
    return { label: null, alert: t(GITHUB_ERROR_MESSAGE) };
  }
  return { label: t(GITHUB_CARD_LABELS[state]), alert: null };
}

export function githubCardState(input: {
  loading: boolean;
  error: boolean;
  registering: boolean;
  status?: GithubStatus | null;
}): GithubCardState {
  if (input.loading) return "loading";
  if (input.error) return "error";
  if (input.registering) return "registering";
  const state = input.status?.state;
  if (state === "syncing") return "syncing";
  if (state === "pending_installation") return "pending_installation";
  if (state === "connected") return "connected";
  if (state === "suspended") return "suspended";
  if (state === "unconfigured") return "unconfigured";
  return "error";
}

export function validateGithubManifestUrl(value: string, organization: string | null) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.hostname !== "github.com" || url.port) {
      throw new Error("invalid");
    }
    if (url.username || url.password || url.search || url.hash) throw new Error("invalid");
    const path = url.pathname.replace(/\/+$/, "");
    if (!organization) {
      if (path !== "/settings/apps/new") throw new Error("invalid");
    } else {
      if (!GITHUB_ORGANIZATION.test(organization)) throw new Error("invalid");
      if (path !== `/organizations/${organization}/settings/apps/new`) throw new Error("invalid");
    }
    return url.href;
  } catch {
    throw new Error(t("GitHub returned an invalid manifest URL"));
  }
}

export function validateGithubInstallUrl(value: string) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.hostname !== "github.com" || url.port) {
      throw new Error("invalid");
    }
    if (url.username || url.password || url.search || url.hash) throw new Error("invalid");
    if (!/^\/apps\/[A-Za-z0-9-_]+\/installations\/new$/.test(url.pathname)) {
      throw new Error("invalid");
    }
    return url.href;
  } catch {
    throw new Error(t("GitHub returned an invalid installation URL"));
  }
}

export function validateGithubOrganization(value: string) {
  const slug = value.trim();
  if (!GITHUB_ORGANIZATION.test(slug)) {
    throw new Error(t("The GitHub organization slug is not valid"));
  }
  return slug;
}


export function groupedFindings(findings: Finding[]) {
  return {
    error: findings.filter((item) => item.severity === "error"),
    warning: findings.filter((item) => item.severity === "warning"),
    info: findings.filter((item) => item.severity === "info"),
  };
}

export const hasBlockingFindings = (findings: Finding[]) =>
  findings.some((item) => item.severity === "error");

export function actionAllowed(application: Application, action: string, busy: boolean) {
  if (busy || !["running", "stopped", "degraded"].includes(application.status)) return false;
  if (action === "start") return application.status !== "running";
  if (action === "stop") return application.status === "running";
  return true;
}

const NUMERIC_ID = /^[1-9][0-9]{0,9}$/;
const OCTAL_MODE = /^0[0-7]{3}$/;
const MANAGED_SERVICE = /^[A-Za-z0-9_.-]{1,128}$/;

export function parseNumericId(value: string): number {
  const text = value.trim();
  if (!NUMERIC_ID.test(text)) {
    throw new Error(t("UID and GID must be positive numeric identifiers"));
  }
  const number = Number(text);
  if (!Number.isSafeInteger(number) || number > 2 ** 31 - 1) {
    throw new Error(t("UID and GID must be positive numeric identifiers"));
  }
  return number;
}

export function validateWritablePath(path: string, mode: string): { path: string; mode: string } {
  const value = path.trim();
  if (!value.startsWith("/") || value === "/" || value.includes("\0") || value.length > 1024) {
    throw new Error(t("Writable paths must be absolute and normalized"));
  }
  const segments = value.split("/");
  if (segments.some((segment) => segment === ".." || segment === ".") || value.includes("//")) {
    throw new Error(t("Writable paths must be absolute and normalized"));
  }
  const normalized = value.replace(/\/+$/, "") || "/";
  if (normalized !== value) {
    throw new Error(t("Writable paths must be absolute and normalized"));
  }
  if (!OCTAL_MODE.test(mode)) {
    throw new Error(t("Mode must be four octal digits"));
  }
  if (Number.parseInt(mode, 8) & 0o002) {
    throw new Error(t("Writable paths cannot be world-writable"));
  }
  return { path: value, mode };
}

export type ServiceUserDraft = { uid: string; gid: string };

export function serviceUserDrafts(
  services: Array<{
    name: string;
    compose_user: string | null;
    dockerfile_user?: string | null;
  }>,
): Record<string, ServiceUserDraft> {
  const result: Record<string, ServiceUserDraft> = {};
  for (const service of services) {
    const match =
      /^([1-9][0-9]{0,9})(?::([1-9][0-9]{0,9}))?$/.exec(service.compose_user ?? "") ??
      /^([1-9][0-9]{0,9})(?::([1-9][0-9]{0,9}))?$/.exec(service.dockerfile_user ?? "");
    result[service.name] = match
      ? { uid: match[1], gid: match[2] ?? match[1] }
      : { uid: "", gid: "" };
  }
  return result;
}

export function buildHardeningPolicy(
  services: string[],
  drafts: Record<string, ServiceUserDraft>,
  writablePaths: HardeningWritablePath[],
): HardeningPolicy {
  if (services.length === 0) {
    throw new Error(t("Run an inspection before deploying"));
  }
  const serviceUsers: HardeningPolicy["service_users"] = {};
  for (const service of services) {
    if (!MANAGED_SERVICE.test(service)) {
      throw new Error(t("Service name is invalid"));
    }
    const draft = drafts[service];
    if (!draft || !draft.uid.trim() || !draft.gid.trim()) {
      throw new Error(t("Every service requires a UID and GID"));
    }
    serviceUsers[service] = {
      uid: parseNumericId(draft.uid),
      gid: parseNumericId(draft.gid),
    };
  }
  const known = new Set(services);
  const paths = writablePaths.map((item) => {
    if (!known.has(item.service)) {
      throw new Error(t("Writable path references an unknown service"));
    }
    return { service: item.service, ...validateWritablePath(item.path, item.mode) };
  });
  return { service_users: serviceUsers, writable_paths: paths };
}

export function policyCoversServices(policy: HardeningPolicy, services: string[]) {
  const declared = Object.keys(policy.service_users);
  if (declared.length !== services.length) return false;
  return services.every((service) => service in policy.service_users);
}

export function releaseUsable(release: Pick<Release, "expires_at">, now = Date.now()) {
  const expires = Date.parse(release.expires_at);
  return Number.isFinite(expires) && expires > now;
}

export function probeChecksPassed(probes?: ProbeEvidence | null) {
  if (!probes) return false;
  const isolation = Object.values(probes.isolation ?? {});
  if (isolation.length === 0) return false;
  if (isolation.some((item) => !(typeof item.processes === "number" && item.processes > 0))) {
    return false;
  }
  const checks = probes.functional?.checks ?? [];
  if (checks.length === 0) return false;
  if (checks.some((item) => item.returncode !== 0 || !(typeof item.bytes === "number" && item.bytes > 0))) {
    return false;
  }
  const stability = probes.stability;
  if (!stability || !(typeof stability.checks === "number" && stability.checks >= 1)) {
    return false;
  }
  const restarts = Object.values(stability.restart_counts ?? {});
  return restarts.length > 0 && restarts.every((value) => value === 0);
}

export function canDeploy(permissions: string[]) {
  return permissions.includes("apps.deployments.create");
}

export function canPlatformMutate(permissions: string[], permission: string) {
  return permissions.includes(permission) && permissions.includes("core.platform.admin");
}

export function isOwnedByTenant(
  resourceTenantId: string | null | undefined,
  currentTenantId: string | null | undefined,
) {
  return !resourceTenantId || resourceTenantId === currentTenantId;
}
