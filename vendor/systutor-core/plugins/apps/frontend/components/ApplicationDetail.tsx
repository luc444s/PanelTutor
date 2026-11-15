import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";

import { Alert } from "@systutor/shell/ui/alert";
import { Button } from "@systutor/shell/ui/button";
import { Dialog } from "@systutor/shell/ui/dialog";
import { Tabs } from "@systutor/shell/ui/tabs";
import { toast } from "@systutor/shell/ui/toast";
import { useT } from "@/i18n/use-i18n";

import { domainsKeys, listRoutes } from "../../../domains/frontend/api";
import {
  appsKeys, getApplication, inspectApplication, listOperations, newIdempotencyKey,
  runApplicationAction, runServiceAction,
} from "../api";
import { actionAllowed, probeChecksPassed } from "../logic";
import type {
  AppAction, Application, AuditReport, DeploymentDetail, Finding,
  OperationSummary, ProbeEvidence,
} from "../types";
import { DeleteDialog } from "./DeleteDialog";
import { DeployDialog } from "./DeployDialog";
import { FindingsReport } from "./FindingsReport";
import { ReleasesPanel } from "./ReleasesPanel";
import { ServiceCard } from "./ServiceCard";
import { ServiceDialog } from "./ServiceDialog";
import { ServiceOperations } from "./ServiceOperations";
import { SourceDialog } from "./SourceDialog";
import { StatusIndicator } from "./StatusIndicator";

type Tab = "overview" | "audit" | "deployments" | "releases" | "operations";
const ACTIONS: Array<[AppAction, string]> = [
  ["refresh", "Refresh all"], ["down", "Down"],
];

function ProbesSummary({ probes }: { probes: ProbeEvidence | null }) {
  const t = useT();
  if (!probes) return null;
  const functional = probes.functional?.checks ?? [];
  const restartCounts = Object.entries(probes.stability?.restart_counts ?? {});
  const green = probeChecksPassed(probes);
  return <div className="text-xs text-muted-foreground">
    <span className={green ? "text-green-600" : "text-destructive"}>
      {green ? t("Probes green") : t("Probes not green")}
    </span>
    {" · "}
    {t("Functional checks: {value}", { value: String(functional.length) })}
    {" · "}
    {t("Restarts: {value}", {
      value: restartCounts.map(([name, count]) => `${name}=${count}`).join(", ") || "—",
    })}
  </div>;
}

function DeploymentCard({ deployment }: { deployment: DeploymentDetail }) {
  const t = useT();
  const summary = deployment.release_summary;
  return <div className="space-y-2 rounded border border-border p-3 text-sm">
    <div className="flex flex-wrap items-center gap-2">
      <strong>{deployment.status}</strong>
      <span>{t("commit")} <code>{deployment.commit ?? "—"}</code></span>
      {deployment.release_id ? <span className="font-mono text-xs">{deployment.release_id}</span> : null}
    </div>
    <div className="text-muted-foreground">
      {t("Services: {value}", { value: deployment.services.join(", ") || "—" })}
    </div>
    {summary ? <>
      <dl className="grid gap-1 text-xs sm:grid-cols-2">
        <div><dt className="text-muted-foreground">{t("Key")}</dt><dd className="font-mono">{summary.key_id ?? "—"}</dd></div>
        <div><dt className="text-muted-foreground">{t("Expires")}</dt><dd>{summary.expires_at ? new Date(summary.expires_at).toLocaleString() : "—"}</dd></div>
        <div className="sm:col-span-2"><dt className="text-muted-foreground">{t("Artifact hash")}</dt><dd className="break-all font-mono">{summary.artifact_sha256 ?? "—"}</dd></div>
        <div className="sm:col-span-2"><dt className="text-muted-foreground">{t("Compose hash")}</dt><dd className="break-all font-mono">{summary.compose_sha256 ?? "—"}</dd></div>
        <div className="sm:col-span-2"><dt className="text-muted-foreground">{t("Tree hash")}</dt><dd className="break-all font-mono">{summary.hardened_tree_sha256 ?? "—"}</dd></div>
        <div className="sm:col-span-2"><dt className="text-muted-foreground">{t("Gate hash")}</dt><dd className="break-all font-mono">{summary.gate_sha256 ?? "—"}</dd></div>
      </dl>
      <ProbesSummary probes={deployment.probes} />
    </> : <p className="text-xs text-muted-foreground">{t("This deployment has no signed release metadata.")}</p>}
    {deployment.public_error ? <p className="text-xs text-destructive">{deployment.public_error}</p> : null}
  </div>;
}

export function ApplicationDetail({ application, canCreate, canManage, canManageDomains,
  canReadDomains, canReveal, canDeploy, canDelete, onClose, onAccepted }: {
  application: Application | null;
  canCreate: boolean;
  canManage: boolean;
  canManageDomains: boolean;
  canReadDomains: boolean;
  canReveal: boolean;
  canDeploy: boolean;
  canDelete: boolean;
  onClose: () => void;
  onAccepted: (operation: OperationSummary) => void;
}) {
  const queryClient = useQueryClient();
  const t = useT();
  const [tab, setTab] = useState<Tab>("overview");
  const [serviceName, setServiceName] = useState<string | null>(null);
  const [deployOpen, setDeployOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [sourceOpen, setSourceOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const detail = useQuery({
    queryKey: appsKeys.detail(application?.id ?? "idle"),
    queryFn: () => getApplication(application!.id),
    enabled: Boolean(application),
    refetchInterval: (state) => {
      const current = state.state.data;
      return current && ["building", "deploying"].includes(current.status) ? 3_000 : false;
    },
  });
  const routesQuery = useQuery({
    queryKey: domainsKeys.routes(),
    queryFn: () => listRoutes(),
    enabled: Boolean(application) && canReadDomains,
  });
  const operationsQuery = useQuery({
    queryKey: appsKeys.operations(application?.id ?? "idle"),
    queryFn: () => listOperations(application!.id),
    enabled: Boolean(application),
    refetchInterval: 3_000,
  });
  const appOperations = useMemo(() => {
    return [...(operationsQuery.data ?? [])].sort((left, right) =>
      String(right.created_at ?? "").localeCompare(String(left.created_at ?? "")));
  }, [operationsQuery.data]);
  const current = detail.data ? { ...detail.data } : application;
  const busy = appOperations.some((item) => !["succeeded", "failed", "interrupted"].includes(item.status));
  const auditOperation = appOperations.find((item) => {
    const candidate = (item.result ?? item.report) as AuditReport | null;
    return item.kind === "inspect" && Array.isArray(candidate?.findings);
  });
  const report = (auditOperation?.result ?? auditOperation?.report ?? {}) as AuditReport;
  const operationFindings = Array.isArray(report.findings) ? report.findings : null;
  const findings = (operationFindings ?? detail.data?.findings ?? []) as Finding[];
  const hasAuditReport = Boolean(auditOperation);
  const sourceConnected = (current?.source_status ?? "source_reconnect_required") === "connected";
  // The hardening gate is the admission authority. A previous audit with
  // errors is informational and never blocks an otherwise valid deploy.
  const blocked = !sourceConnected;
  const activeDeployment = detail.data?.active_deployment ?? null;
  const inspectedServices = detail.data?.service_details ?? [];
  const services = activeDeployment?.service_details ?? [];
  const selectedService = services.find((service) => service.name === serviceName) ?? null;
  const routes = routesQuery.data?.items ?? [];

  useEffect(() => {
    setServiceName(null);
  }, [application?.id, activeDeployment?.id]);

  if (!application || !current) return null;

  async function accept(
    task: () => Promise<OperationSummary>,
    feedback?: { id: string; accepted: string },
  ) {
    setPending(true);
    try {
      const operation = await task();
      if (feedback) toast.success(feedback.accepted, { id: feedback.id });
      onAccepted(operation);
      await queryClient.invalidateQueries({ queryKey: appsKeys.operations(application!.id) });
      await queryClient.invalidateQueries({ queryKey: appsKeys.detail(application!.id) });
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : t("Could not accept the operation"),
        feedback ? { id: feedback.id } : undefined,
      );
    } finally {
      setPending(false);
    }
  }

  const lastDeploy = activeDeployment?.finished_at ?? activeDeployment?.created_at
    ?? detail.data?.deployments?.[0]?.finished_at ?? null;
  const tabs = [
    {
      value: "overview" as const,
      label: t("Overview"),
      content: <div className="space-y-4">
        <dl className="grid gap-3 text-sm sm:grid-cols-2">
          <div><dt className="text-muted-foreground">{t("Status")}</dt><dd><StatusIndicator status={current.status} /></dd></div>
          <div><dt className="text-muted-foreground">{t("Source")}</dt><dd>GitHub · {sourceConnected ? t("connected") : t("requires reconnection")}</dd></div>
          <div><dt className="text-muted-foreground">{t("Compose")}</dt><dd>{current.compose_file ?? report.compose ?? t("Autodetect")}</dd></div>
          <div><dt className="text-muted-foreground">{t("Active commit")}</dt><dd><code>{activeDeployment?.commit ?? "—"}</code></dd></div>
          <div><dt className="text-muted-foreground">{t("Runtime project")}</dt><dd><code>{detail.data?.runtime_project ?? "—"}</code></dd></div>
          <div><dt className="text-muted-foreground">{t("Last deploy")}</dt><dd>{lastDeploy ? new Date(lastDeploy).toLocaleString() : "—"}</dd></div>
        </dl>
        <div className="space-y-2">
          <h3 className="text-sm font-medium">{t("Services")}</h3>
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
            {services.map((service) => <ServiceCard key={service.name} service={service}
              domainCount={canReadDomains
                ? routes.filter((route) => route.site_id === `${application.id}:${service.name}`).length
                : null}
              onOpen={() => setServiceName(service.name)} />)}
          </div>
          {services.length === 0 ? <p className="text-sm text-muted-foreground">{t("No services in the active deployment.")}</p> : null}
          <p className="text-xs text-muted-foreground">{t("Double-click a card to manage it.")}</p>
        </div>
      </div>,
    },
    {
      value: "audit" as const,
      label: t("Audit"),
      content: findings.length ? <FindingsReport findings={findings} />
        : hasAuditReport ? <Alert title={t("Inspection approved")}>{t("No findings were found.")}</Alert>
          : <Alert title={t("No report")}>{t("Run an inspection to get findings.")}</Alert>,
    },
    {
      value: "deployments" as const,
      label: t("Deployments"),
      content: <div className="space-y-2">
        <Alert title={t("Isolation-only admission")}>
          {t("The app's internal security is the app owner's responsibility; the platform guarantees isolation, signature and probes.")}
        </Alert>
        {(detail.data?.deployments ?? []).map((deployment) =>
          <DeploymentCard key={deployment.id} deployment={deployment} />)}
        {(detail.data?.deployments ?? []).length === 0 ? <p className="text-sm text-muted-foreground">{t("No deployments.")}</p> : null}
      </div>,
    },
    {
      value: "releases" as const,
      label: t("Releases"),
      content: <ReleasesPanel
        applicationId={application.id}
        canDeploy={canDeploy}
        pending={pending || busy}
        deployments={detail.data?.deployments ?? []}
        activeDeploymentId={activeDeployment?.id ?? null}
        onAccepted={onAccepted} />,
    },
    {
      value: "operations" as const,
      label: t("Operations"),
      content: <ServiceOperations operations={appOperations} />,
    },
  ];

  return <>
    <Dialog open title={application.name} description={`${application.repository} · ${application.branch}`}
      maxWidthClassName="max-w-[800px]" onClose={onClose}>
      <div className="space-y-4">
        {!sourceConnected ? <Alert title={t("Source requires reconnection")}>
          {t("The repository is no longer authorized by an active installation. New inspections and deployments are blocked; the existing lifecycle continues.")}
          {canCreate ? <Button className="ml-2" variant="secondary" disabled={pending} onClick={() => setSourceOpen(true)}>{t("Choose source")}</Button> : null}
        </Alert> : null}
        <Tabs value={tab} onChange={(value) => setTab(value as Tab)} tabs={tabs} />

        <div className="flex flex-wrap gap-2 border-t border-border pt-3">
          {canCreate ? <Button variant="secondary" disabled={pending || busy || !sourceConnected} onClick={() => {
            const id = `apps-inspect-${application.id}`;
            toast.loading(t("Sending inspection…"), { id });
            void accept(
              () => inspectApplication(application.id, newIdempotencyKey()),
              { id, accepted: t("Inspection accepted; you can keep working") },
            );
          }}>{t("Inspect")}</Button> : null}
          {canDeploy ? <Button disabled={busy || blocked || !sourceConnected} onClick={() => setDeployOpen(true)}>{t("Deploy")}</Button> : null}
          {canManage ? ACTIONS.map(([action, label]) => <Button key={action} variant="secondary" disabled={pending || !actionAllowed(current, action, busy)} onClick={() => void accept(() => runApplicationAction(application.id, action, newIdempotencyKey()))}>{t(label)}</Button>) : null}
          {canDelete ? <Button variant="secondary" disabled={busy} className="text-destructive" onClick={() => setDeleteOpen(true)}>{t("Delete application")}</Button> : null}
        </div>
      </div>
    </Dialog>
    {selectedService ? <ServiceDialog key={`${application.id}:${selectedService.name}`}
      applicationId={application.id} applicationName={application.name}
      service={selectedService} operations={appOperations}
      canManage={canManage} canReadDomains={canReadDomains}
      canManageDomains={canManageDomains} canReveal={canReveal}
      pending={pending} updatedAt={detail.dataUpdatedAt}
      onClose={() => setServiceName(null)}
      onAction={(action) => void accept(() =>
        runServiceAction(application.id, selectedService.name, action, newIdempotencyKey()))} /> : null}
    <DeployDialog application={current} services={inspectedServices} open={deployOpen} blocked={blocked} onClose={() => setDeployOpen(false)} onAccepted={(operation) => { setDeployOpen(false); onAccepted(operation); }} />
    <DeleteDialog application={current} open={deleteOpen} onClose={() => setDeleteOpen(false)} onAccepted={(operation) => { setDeleteOpen(false); onAccepted(operation); }} />
    <SourceDialog application={current} open={sourceOpen} onClose={() => setSourceOpen(false)} />
  </>;
}
