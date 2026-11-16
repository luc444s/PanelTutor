import { useMemo, useState } from "react";

import { Alert } from "@systutor/shell/ui/alert";
import { Badge } from "@systutor/shell/ui/badge";
import { Button } from "@systutor/shell/ui/button";
import { Dialog } from "@systutor/shell/ui/dialog";
import { toast } from "@systutor/shell/ui/toast";
import { useT } from "@/i18n/use-i18n";

import {
  deployApplication, newIdempotencyKey, rollbackApplication,
} from "../api";
import type { DeploymentDetail, OperationSummary, ServiceDetail } from "../types";

const DATABASE_SERVICE = /(^|[-_])(db|database|postgres|postgresql|mysql|mariadb)($|[-_])/i;

export function ServiceDeployments({
  applicationId, service, deployments, canDeploy, pending, onAccepted,
}: {
  applicationId: string;
  service: ServiceDetail;
  deployments: DeploymentDetail[];
  canDeploy: boolean;
  pending: boolean;
  onAccepted: (operation: OperationSummary) => void;
}) {
  const t = useT();
  const [busy, setBusy] = useState(false);
  const [rollbackTarget, setRollbackTarget] = useState<DeploymentDetail | null>(null);
  const effectiveRelease = service.release_id ?? null;
  const isDatabase = DATABASE_SERVICE.test(service.name);
  const compatible = useMemo(() => deployments.filter((deployment) =>
    Boolean(deployment.release_summary?.release_id)
    && (deployment.services.includes(service.name)
      || Boolean(deployment.service_releases?.[service.name])),
  ), [deployments, service.name]);
  const activeDeployment = deployments.find((deployment) =>
    deployment.service_releases?.[service.name] === effectiveRelease
    && Boolean(effectiveRelease));

  async function run(task: () => Promise<OperationSummary>, accepted: string) {
    setBusy(true);
    try {
      const operation = await task();
      toast.success(accepted);
      onAccepted(operation);
    } catch (reason) {
      toast.error(reason instanceof Error ? reason.message : t("Could not accept the operation"));
    } finally {
      setBusy(false);
    }
  }

  return <div className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div className="space-y-1">
        <h3 className="text-sm font-medium">{t("Service deployments")}</h3>
        <p className="text-xs text-muted-foreground">
          {t("Deploy only this service. The global release stays signed and verifiable.")}
        </p>
      </div>
      <Button disabled={!canDeploy || pending || busy}
        onClick={() => void run(
          () => deployApplication(applicationId, {
            environment: [], scope: { type: "service", service: service.name },
          }, newIdempotencyKey()),
          t("Service deployment accepted; follow progress in Operations"),
        )}>{t("Deploy only this service")}</Button>
    </div>
    <dl className="grid gap-3 text-sm sm:grid-cols-2">
      <div><dt className="text-muted-foreground">{t("Effective release")}</dt>
        <dd className="break-all font-mono text-xs">{effectiveRelease ?? t("No active release")}</dd></div>
      <div><dt className="text-muted-foreground">{t("Scope")}</dt>
        <dd>{service.override ? <Badge>{t("Service override")}</Badge> : <Badge>{t("Global release")}</Badge>}</dd></div>
      {service.runtime_user ? <>
        <div><dt className="text-muted-foreground">{t("Effective runtime user")}</dt>
          <dd className="font-mono text-xs">{service.runtime_user.effective}</dd></div>
        <div><dt className="text-muted-foreground">{t("Runtime user source")}</dt>
          <dd>{service.runtime_user.source}
            {service.runtime_user.volume ? ` · ${service.runtime_user.volume}` : ""}</dd></div>
      </> : null}
      {activeDeployment ? <>
        <div><dt className="text-muted-foreground">{t("Strategy")}</dt>
          <dd>{activeDeployment.strategy ?? "—"}</dd></div>
        <div><dt className="text-muted-foreground">{t("Effective services")}</dt>
          <dd>{(activeDeployment.effective_services ?? []).join(", ") || "—"}</dd></div>
      </> : null}
    </dl>
    {isDatabase ? <Alert title={t("Database rollback does not revert data")}>
      {t("A database service rollback restores image, command, referenced environment and Compose configuration. Volumes and their data are never reverted, replaced or purged.")}
    </Alert> : null}
    <div className="space-y-2">
      <h3 className="text-sm font-medium">{t("Compatible signed deployments")}</h3>
      {compatible.length === 0 ? <p className="text-sm text-muted-foreground">
        {t("No signed deployment includes this service.")}
      </p> : null}
      {compatible.map((deployment) => <div key={deployment.id}
        className="flex flex-wrap items-center justify-between gap-2 rounded border border-border p-2 text-sm">
        <div className="space-y-1">
          <div className="font-mono text-xs">{deployment.release_summary?.release_id ?? deployment.id}</div>
          <div className="text-xs text-muted-foreground">
            {(deployment.release_summary?.commit ?? deployment.commit ?? "").slice(0, 8)}
            {deployment.finished_at ? ` · ${new Date(deployment.finished_at).toLocaleString()}` : ""}
            {` · ${t("Scope")}: ${deployment.requested_scope ?? "global"}`}
            {deployment.strategy ? ` · ${deployment.strategy}` : ""}
          </div>
          {deployment.fallback_reason ? <div className="text-xs text-amber-700">
            {t("Fallback")}: {deployment.fallback_reason}
          </div> : null}
          <div className="text-xs text-muted-foreground">
            {t("Effective services")}: {(deployment.effective_services ?? []).join(", ") || "—"}
          </div>
        </div>
        <Button variant="secondary"
          disabled={!canDeploy || pending || busy
            || deployment.release_summary?.release_id === effectiveRelease}
          onClick={() => setRollbackTarget(deployment)}>{t("Rollback this service")}</Button>
      </div>)}
    </div>
    <Dialog open={rollbackTarget !== null} onClose={() => setRollbackTarget(null)}
      title={t("Rollback {name}", { name: service.name })}
      description={t("Only this service is restored; every other container is preserved.")}
      actions={<div className="flex justify-end gap-2">
        <Button variant="secondary" disabled={busy} onClick={() => setRollbackTarget(null)}>
          {t("Cancel")}
        </Button>
        <Button disabled={busy || !rollbackTarget} onClick={() => {
          const target = rollbackTarget;
          if (!target) return;
          void run(
            () => rollbackApplication(applicationId, target.id, newIdempotencyKey(), {
              type: "service", service: service.name,
            }),
            t("Service rollback accepted; follow progress in Operations"),
          ).then(() => setRollbackTarget(null));
        }}>{t("Confirm service rollback")}</Button>
      </div>}>
      <div className="space-y-3 text-sm">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted-foreground">{t("Current release")}</div>
            <div className="mt-1 break-all font-mono text-xs">{effectiveRelease ?? "—"}</div>
          </div>
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted-foreground">{t("Target release")}</div>
            <div className="mt-1 break-all font-mono text-xs">
              {rollbackTarget?.release_summary?.release_id ?? rollbackTarget?.id}
            </div>
          </div>
        </div>
        {isDatabase ? <Alert title={t("Database rollback does not revert data")}>
          {t("Volumes and database contents are preserved exactly as they are.")}
        </Alert> : null}
      </div>
    </Dialog>
  </div>;
}
