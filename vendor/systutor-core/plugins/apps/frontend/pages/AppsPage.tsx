import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useState } from "react";

import { Alert } from "@systutor/shell/ui/alert";
import { Button } from "@systutor/shell/ui/button";
import { Pagination } from "@systutor/shell/ui/pagination";
import { toast } from "@systutor/shell/ui/toast";
import { useAuthStore } from "../../../../../../apps/web/src/features/auth/store";
import { useT } from "@/i18n/use-i18n";

import { appsKeys, listApplications } from "../api";
import { domainsKeys, listRoutes } from "../../../domains/frontend/api";
import { canDeploy, canPlatformMutate, isOwnedByTenant } from "../logic";
import type { Application, OperationSummary } from "../types";
import { ApplicationDetail } from "../components/ApplicationDetail";
import { CreateApplicationDialog } from "../components/CreateApplicationDialog";
import { GithubConnectionCard } from "../components/GithubConnectionCard";
import { OperationWatcher } from "../components/OperationWatcher";
import { StatusBadge } from "../components/StatusIndicator";
import { useGithubStatus } from "../useGithubStatus";

export default function AppsPage() {
  const t = useT();
  const queryClient = useQueryClient();
  const permissions = useAuthStore((state) => state.permissions);
  const currentTenant = useAuthStore((state) => state.currentTenant);
  const canConnect = permissions.includes("apps.github.connect");
  const canCreate = permissions.includes("apps.applications.create");
  const canManage = permissions.includes("apps.applications.manage");
  const canManageDomains = permissions.includes("domains.domains.manage");
  const canReadDomains = permissions.includes("domains.domains.read");
  const canReveal = permissions.includes("apps.secrets.read");
  const platform = permissions.includes("core.platform.admin");
  const canDeployApp = canDeploy(permissions);
  const canDelete = canPlatformMutate(permissions, "apps.applications.delete");
  const [createOpen, setCreateOpen] = useState(false);
  const [selected, setSelected] = useState<Application | null>(null);
  const [tracked, setTracked] = useState<OperationSummary[]>([]);
  const [page, setPage] = useState(1);
  const APPS_PAGE_SIZE = 9;
  const applications = useQuery({
    queryKey: [...appsKeys.applications, platform ? "all" : "tenant"],
    queryFn: () => listApplications(platform),
  });
  const routesQuery = useQuery({
    queryKey: domainsKeys.routes(),
    queryFn: () => listRoutes(),
    enabled: canReadDomains,
  });
  const routes = routesQuery.data?.items ?? [];
  const githubStatus = useGithubStatus(canConnect);

  useEffect(() => {
    const result = new URLSearchParams(window.location.search).get("github");
    if (result !== "installed" && result !== "connected" && result !== "error") return;
    window.history.replaceState({}, "", window.location.pathname + window.location.hash);
    void queryClient.invalidateQueries({ queryKey: appsKeys.status });
    void queryClient.invalidateQueries({ queryKey: appsKeys.installations });
    if (result === "error") {
      toast.error(t("Could not complete the GitHub connection"));
    } else {
      toast.success(result === "installed"
        ? t("GitHub App installed; syncing repositories")
        : t("GitHub connected"));
    }
  }, [queryClient]);

  function accepted(application: Application) {
    setCreateOpen(false); setSelected(application);
    void queryClient.invalidateQueries({ queryKey: appsKeys.applications });
  }
  function operationAccepted(operation: OperationSummary) {
    setTracked((current) => current.some((item) => item.operation_id === operation.operation_id)
      ? current
      : [...current, operation]);
    void queryClient.invalidateQueries({ queryKey: appsKeys.applications });
    if (operation.application_id) {
      void queryClient.invalidateQueries({ queryKey: appsKeys.detail(operation.application_id) });
      void queryClient.invalidateQueries({ queryKey: appsKeys.operations(operation.application_id) });
    }
  }
  const operationFinalized = useCallback((operationId: string) => {
    setTracked((current) => current.filter((item) => item.operation_id !== operationId));
  }, []);

  useEffect(() => {
    if (!selected || !applications.data) return;
    if (!applications.data.some((application) => application.id === selected.id)) {
      setSelected(null);
    }
  }, [applications.data, selected]);

  const apps = applications.data ?? [];
  const deployingApplications = new Set(
    tracked
      .filter((operation) => ["deploy", "rollback"].includes(operation.kind))
      .map((operation) => operation.application_id)
      .filter((id): id is string => Boolean(id)),
  );
  const totalPages = Math.max(1, Math.ceil(apps.length / APPS_PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pagedApps = apps.slice(
    (currentPage - 1) * APPS_PAGE_SIZE,
    currentPage * APPS_PAGE_SIZE,
  );

  if (applications.isLoading) return <div className="flex min-h-48 items-center justify-center text-sm text-muted-foreground">{t("Loading Apps…")}</div>;
  if (applications.error) return <Alert title={t("Error")}>{t("Could not load applications.")}</Alert>;

  return <section className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div><h1 className="text-lg font-semibold text-foreground">{t("Apps")}</h1><p className="text-sm text-muted-foreground">{t("Async Compose deployments from GitHub")}</p></div>
      {canCreate ? <Button disabled={!githubStatus.data?.connected} onClick={() => setCreateOpen(true)}>{t("New application")}</Button> : null}
    </div>
    <GithubConnectionCard canConnect={canConnect} statusQuery={githubStatus} />

    {apps.length === 0 ? (
      <p className="rounded border border-border p-4 text-sm text-muted-foreground">{t("No applications.")}</p>
    ) : (
      <div className="flex min-h-[32rem] flex-col gap-4 md:min-h-[36rem]">
        <div className="flex-1">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
            {pagedApps.map((application) => {
              const owned = isOwnedByTenant(application.tenant_id, currentTenant?.id);
              const deploying = deployingApplications.has(application.id);
              const status = deploying ? "deploying" : application.status;
              const appRoutes = routes.filter((route) =>
                route.site_id.startsWith(`${application.id}:`));
              const domainLabel = !canReadDomains
                ? t("No domain")
                : routesQuery.isLoading
                  ? t("Loading domains...")
                  : appRoutes.length === 0
                    ? t("No domains")
                    : appRoutes.length === 1
                      ? `${appRoutes[0].domain}${appRoutes[0].path === "/" ? "" : appRoutes[0].path}`
                      : t("{count} domains", { count: appRoutes.length });
              return <button key={application.id} type="button"
                aria-disabled={!owned}
                className={`rounded-md border border-border bg-card p-4 text-left ${owned ? "hover:bg-muted" : "cursor-default"}`}
                onClick={() => { if (owned) setSelected(application); }}>
                <div className="flex items-center justify-between gap-2"><strong>{application.name}</strong><StatusBadge status={status} spinner={deploying} /></div>
                <p className="mt-2 text-sm text-muted-foreground">{application.repository} · {application.branch}</p>
                <p className="mt-1 text-xs text-muted-foreground">{domainLabel}</p>
                {application.tenant_name ? <p className="mt-1 text-xs text-muted-foreground">{t("Tenant")}: {application.tenant_name}</p> : null}
                {!owned ? <p className="mt-2 text-xs font-medium text-muted-foreground">{t("Read only")}</p> : null}
              </button>;
            })}
          </div>
        </div>
        <Pagination page={currentPage} totalPages={totalPages} onChange={setPage} />
      </div>
    )}

    <CreateApplicationDialog open={createOpen} onClose={() => setCreateOpen(false)} onAccepted={accepted} />
    {tracked.map((operation) => <OperationWatcher key={operation.operation_id}
      operationId={operation.operation_id}
      applicationId={operation.application_id ?? undefined}
      onFinalized={operationFinalized} />)}
    <ApplicationDetail key={selected?.id ?? "no-application"} application={selected}
      deploying={selected ? deployingApplications.has(selected.id) : false}
      canCreate={canCreate} canManage={canManage}
      canManageDomains={canManageDomains} canReadDomains={canReadDomains}
      canReveal={canReveal} canDeploy={canDeployApp} canDelete={canDelete}
      onClose={() => setSelected(null)} onAccepted={operationAccepted} />
  </section>;
}
