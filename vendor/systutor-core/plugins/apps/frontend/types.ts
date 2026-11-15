export type GithubStatus = {
  state: "unconfigured" | "pending_installation" | "syncing" | "connected" | "suspended" | "error";
  configured: boolean;
  connected: boolean;
  reconnect_required: boolean;
  login?: string | null;
  provider_count?: number;
  installation_count?: number;
  syncing?: boolean;
  install_url?: string | null;
};

export type GithubProvider = {
  id: string;
  github_app_id: number;
  app_slug: string;
  name: string;
  owner_login: string | null;
  owner_type: string | null;
  status: string;
  created_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
};

export type GithubInstallation = {
  id: string;
  provider_id: string;
  github_installation_id: number;
  account_login: string;
  account_type: string | null;
  repository_selection: string;
  permissions: Record<string, string>;
  status: string;
  repository_count: number;
  installed_at: string | null;
  last_synced_at: string | null;
};

export type GithubRepository = {
  id: string;
  github_repository_id: number;
  full_name: string;
  private: boolean;
  default_branch: string | null;
  archived: boolean;
  disabled: boolean;
  observed_at: string | null;
  removed_at: string | null;
};

export type GithubManifestStart = {
  action_url: string;
  state: string;
  manifest: Record<string, unknown>;
};

export type Application = {
  id: string;
  name: string;
  slug: string;
  repository: string;
  branch: string;
  compose_file: string | null;
  domain: string | null;
  ingress_service: string | null;
  ingress_port: number | null;
  status: string;
  source_installation_id: string | null;
  source_repository_id: string | null;
  source_status: string;
  has_saved_environment?: boolean;
  tenant_id: string | null;
  tenant_name: string | null;
};

export type ApplicationCreate = {
  name: string;
  installation_id: string;
  repository_id: string;
  branch?: string | null;
  compose_file: string | null;
  domain: string | null;
  ingress_service: string | null;
  ingress_port: number | null;
};

export type ApplicationDetail = Application & {
  runtime_project: string;
  active_deployment: DeploymentDetail | null;
  services: string[];
  service_details: InspectedService[];
  last_inspect_at: string | null;
  compose_candidates: string[];
  findings: Finding[];
  deployments: DeploymentDetail[];
};

export type InspectedService = {
  name: string;
  build: boolean;
  dockerfile: string | null;
  image: string | null;
  compose_user: string | null;
};

export type HardeningRuntimeUser = { uid: number; gid: number };

export type HardeningWritablePath = {
  service: string;
  path: string;
  mode: string;
};

export type HardeningPolicy = {
  service_users: Record<string, HardeningRuntimeUser>;
  writable_paths: HardeningWritablePath[];
};

export type DeploymentScope =
  | { type: "global" }
  | { type: "service"; service: string };

export type DeployPayload = {
  environment: Array<[string, string]>;
  hardening?: HardeningPolicy;
  hardened_operation_id?: string;
  scope?: DeploymentScope;
};

export type OperationSummary = {
  operation_id: string;
  application_id: string | null;
  kind: string;
  status: string;
  poll_url: string;
};

export type Finding = {
  severity: "error" | "warning" | "info";
  code: string;
  service: string | null;
  path: string;
  line: number;
  message: string;
  remediation: string;
};

export type AuditReport = {
  compose?: string;
  findings?: Finding[];
  blocking?: boolean;
  compose_candidates?: string[];
};

export type Operation = {
  id: string;
  application_id: string | null;
  subject_type: string | null;
  subject_id: string | null;
  kind: string;
  status: string;
  phase: string;
  report: AuditReport | Record<string, unknown> | null;
  result: Record<string, unknown> | null;
  error_code: string | null;
  public_error: string | null;
  created_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
};

export type Deployment = {
  id: string;
  status: string;
  commit: string | null;
  tree_hash: string | null;
  public_error: string | null;
};

export type DeploymentDetail = Deployment & {
  compose_file: string | null;
  ingress_service: string | null;
  ingress_port: number | null;
  release: string | null;
  release_id: string | null;
  release_summary: ReleaseSummary | null;
  probes: ProbeEvidence | null;
  services: string[];
  service_details: Array<{
    name: string;
    image: string | null;
    status: string;
    health: string;
    user?: string | null;
    ports: number[];
    restart_count: number;
    environment_names: string[];
    environment: ServiceEnvironmentVariable[];
    created_at: string | null;
    started_at?: string | null;
    container_id?: string | null;
    image_id?: string | null;
    release_id?: string | null;
    override?: boolean;
  }>;
  global_release_id?: string | null;
  service_releases?: Record<string, string>;
  overrides?: string[];
  requested_scope?: string | null;
  requested_service?: string | null;
  effective_services?: string[];
  strategy?: string | null;
  fallback_reason?: string | null;
  service_probes?: ProbeEvidence | null;
  preserved?: {
    services?: string[];
    before?: Record<string, unknown>;
    after?: Record<string, unknown>;
  } | null;
  created_at: string | null;
  finished_at: string | null;
};

export type ReleaseSummary = {
  deployment_id?: string;
  release_id?: string;
  operation_id?: string;
  key_id?: string;
  commit?: string;
  repo?: string;
  branch?: string;
  artifact_sha256?: string;
  source_tree_sha256?: string;
  hardened_tree_sha256?: string;
  compose_sha256?: string;
  policy_sha256?: string;
  gate_sha256?: string;
  created_at?: string;
  expires_at?: string;
};

export type ProbeCheck = {
  returncode?: number;
  sha256?: string;
  bytes?: number;
};

export type ProbeEvidence = {
  isolation?: Record<string, { user?: string; networks?: string[]; processes?: number }>;
  functional?: { image?: string; checks?: ProbeCheck[] };
  stability?: {
    checks?: number;
    window_seconds?: number;
    restart_counts?: Record<string, number>;
  };
};

export type Release = {
  release_id: string;
  operation_id: string;
  key_id: string;
  repo: string;
  branch: string;
  commit: string;
  artifact_sha256: string;
  source_tree_sha256: string;
  hardened_tree_sha256: string;
  compose_path: string;
  compose_sha256: string;
  policy_sha256: string;
  gate_sha256: string;
  tool_versions: Record<string, unknown>;
  policy: HardeningPolicy;
  created_at: string;
  expires_at: string;
};

export type ReleaseVerification = {
  status: string;
  release: Release;
  checks: Record<string, boolean>;
};

export type ReleaseEvidence = {
  release: Release;
  operation_result: Record<string, unknown> | null;
};

export type ServiceEnvironmentVariable = {
  name: string;
  source: "managed" | "tenant" | "image";
  secret: boolean;
  revealable: boolean;
};
export type ServiceDetail = DeploymentDetail["service_details"][number];
export type EnvironmentEntry = { name: string; value: string };
export type AppAction = "refresh" | "logs" | "start" | "stop" | "restart" | "down";
