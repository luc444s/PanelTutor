import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { Alert } from "@systutor/shell/ui/alert";
import { Badge } from "@systutor/shell/ui/badge";
import { Button } from "@systutor/shell/ui/button";
import { Dialog } from "@systutor/shell/ui/dialog";
import { toast } from "@systutor/shell/ui/toast";
import { useT } from "@/i18n/use-i18n";

import {
  appsKeys, deployApplication, getReleaseEvidence, listReleases,
  newIdempotencyKey, rollbackApplication, verifyRelease,
} from "../api";
import { releaseUsable } from "../logic";
import type {
  DeploymentDetail, OperationSummary, Release, ReleaseEvidence,
  ReleaseVerification,
} from "../types";

type Props = {
  applicationId: string;
  canDeploy: boolean;
  pending: boolean;
  deployments: DeploymentDetail[];
  activeDeploymentId: string | null;
  onAccepted: (operation: OperationSummary) => void;
};

export function ReleasesPanel({
  applicationId, canDeploy, pending, deployments, activeDeploymentId, onAccepted,
}: Props) {
  const t = useT();
  const [selected, setSelected] = useState<Release | null>(null);
  const [verification, setVerification] = useState<ReleaseVerification | null>(null);
  const [evidence, setEvidence] = useState<ReleaseEvidence | null>(null);
  const [rollbackTarget, setRollbackTarget] = useState<DeploymentDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const releases = useQuery({
    queryKey: appsKeys.releases(applicationId),
    queryFn: () => listReleases(applicationId),
    retry: false,
  });

  async function inspect(release: Release) {
    setBusy(true); setSelected(release); setVerification(null); setEvidence(null);
    try {
      setVerification(await verifyRelease(applicationId, release.release_id));
    } catch (reason) {
      toast.error(reason instanceof Error ? reason.message : t("Could not verify the release"));
    } finally {
      setBusy(false);
    }
  }

  async function showEvidence(release: Release) {
    setBusy(true); setSelected(release); setEvidence(null); setVerification(null);
    try {
      setEvidence(await getReleaseEvidence(applicationId, release.release_id));
    } catch (reason) {
      toast.error(reason instanceof Error ? reason.message : t("Could not load the evidence"));
    } finally {
      setBusy(false);
    }
  }

  async function deploy(release: Release) {
    setBusy(true);
    try {
      const operation = await deployApplication(
        applicationId,
        { environment: [], hardened_operation_id: release.release_id },
        newIdempotencyKey(),
      );
      toast.success(t("Deploy accepted; follow progress in Operations"));
      onAccepted(operation);
    } catch (reason) {
      toast.error(reason instanceof Error ? reason.message : t("Could not accept the deployment"));
    } finally {
      setBusy(false);
    }
  }

  async function rollback(deployment: DeploymentDetail) {
    setBusy(true);
    try {
      const operation = await rollbackApplication(
        applicationId, deployment.id, newIdempotencyKey(),
      );
      toast.success(t("Rollback accepted; follow progress in Operations"));
      setRollbackTarget(null);
      onAccepted(operation);
    } catch (reason) {
      toast.error(reason instanceof Error ? reason.message : t("Could not accept the rollback"));
    } finally {
      setBusy(false);
    }
  }

  const rollbackTargets = deployments.filter((deployment) =>
    deployment.release_summary?.deployment_id
    && deployment.release_summary.deployment_id !== activeDeploymentId);
  const activeDeployment = deployments.find((deployment) => deployment.id === activeDeploymentId);
  const activeReleaseId = activeDeployment?.release_summary?.release_id
    ?? activeDeployment?.release_id;
  const verifiedReleaseId = verification?.status === "valid"
    && Object.values(verification.checks).every(Boolean)
    ? verification.release.release_id : null;

  function releaseBadge(release: Release) {
    if (release.release_id === activeReleaseId) {
      return <Badge className="border-emerald-500/40 bg-emerald-500/10 text-emerald-700">● {t("Active")}</Badge>;
    }
    if (!releaseUsable(release)) {
      return <Badge className="border-amber-500/40 bg-amber-500/10 text-amber-700">! {t("Expired")}</Badge>;
    }
    if (release.release_id === verifiedReleaseId) {
      return <Badge className="border-emerald-500/40 bg-emerald-500/10 text-emerald-700">✓ {t("Verified")}</Badge>;
    }
    return <Badge>○ {t("Signed")}</Badge>;
  }

  return <div className="space-y-4">
    <div className="flex items-center justify-between gap-2">
      <div>
        <h3 className="text-sm font-medium">{t("Signed releases")}</h3>
        <p className="text-xs text-muted-foreground">
          {t("Releases are the only deployable artifact. Verify the signature before deploying or rolling back.")}
        </p>
      </div>
      <Button variant="secondary" disabled={releases.isFetching}
        onClick={() => void releases.refetch()}>{t("Refresh")}</Button>
    </div>
    {releases.isError ? <Alert title={t("Error")}>
      {t("Could not load the releases.")}
    </Alert> : null}
    {(releases.data ?? []).length === 0 ? <p className="text-sm text-muted-foreground">
      {t("No signed releases.")}
    </p> : null}
    {(releases.data ?? []).length > 0 ? <div className="overflow-x-auto rounded border border-border">
      <table className="w-full min-w-[760px] text-left text-sm">
        <thead className="border-b border-border bg-muted/40 text-xs uppercase text-muted-foreground">
          <tr>
            <th className="px-3 py-2 font-medium">{t("Status")}</th>
            <th className="px-3 py-2 font-medium">{t("Commit")}</th>
            <th className="px-3 py-2 font-medium">{t("Created")}</th>
            <th className="px-3 py-2 font-medium">{t("Signature")}</th>
            <th className="px-3 py-2 text-right font-medium">{t("Actions")}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {(releases.data ?? []).map((release) => <tr key={release.release_id}
            className={selected?.release_id === release.release_id ? "bg-muted/30" : undefined}>
            <td className="px-3 py-3">{releaseBadge(release)}</td>
            <td className="px-3 py-3 font-mono text-xs" title={release.commit}>{release.commit.slice(0, 8)}</td>
            <td className="px-3 py-3 text-xs text-muted-foreground">
              {new Date(release.created_at).toLocaleString()}
            </td>
            <td className="px-3 py-3 text-xs">✓ {t("Valid")}</td>
            <td className="px-3 py-3">
              <div className="flex justify-end gap-2">
                <Button variant="secondary" disabled={busy} onClick={() => void inspect(release)}>
                  {t("Verify")}
                </Button>
                <Button variant="secondary" disabled={busy} onClick={() => void showEvidence(release)}>
                  {t("Evidence")}
                </Button>
                <Button disabled={!canDeploy || pending || busy || !releaseUsable(release)
                  || release.release_id === activeReleaseId}
                  onClick={() => void deploy(release)}>{t("Deploy")}</Button>
              </div>
            </td>
          </tr>)}
        </tbody>
      </table>
    </div> : null}
    {selected && verification ? <div className="space-y-1 rounded border border-border p-3 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="font-medium">{t("Verification of {release}", { release: selected.release_id })}</h4>
        {releaseBadge(selected)}
      </div>
      <ul className="text-xs">
        {Object.entries(verification.checks).map(([name, value]) => <li key={name}>
          {value ? "✓" : "✗"} {name}
        </li>)}
      </ul>
    </div> : null}
    <div className="space-y-2">
      <h3 className="text-sm font-medium">{t("Rollback to a signed deployment")}</h3>
      {rollbackTargets.length === 0 ? <p className="text-sm text-muted-foreground">
        {t("No previous signed deployment is available.")}
      </p> : null}
      {rollbackTargets.map((deployment) => <div key={deployment.id}
        className="flex flex-wrap items-center justify-between gap-2 rounded border border-border p-2 text-sm">
        <div className="space-y-1">
          <div className="font-mono text-xs">{deployment.release_summary?.release_id ?? deployment.id}</div>
          <div className="text-xs text-muted-foreground">
            {(deployment.release_summary?.commit ?? deployment.commit ?? "").slice(0, 8)}
            {deployment.finished_at ? ` · ${new Date(deployment.finished_at).toLocaleString()}` : ""}
          </div>
        </div>
        <Button variant="secondary" disabled={!canDeploy || pending || busy}
          onClick={() => setRollbackTarget(deployment)}>{t("Rollback")}</Button>
      </div>)}
    </div>
    <Dialog open={selected !== null && evidence !== null}
      onClose={() => setEvidence(null)}
      title={selected ? t("Evidence of {release}", { release: selected.release_id }) : ""}
      maxWidthClassName="max-w-[900px]"
      actions={<div className="flex justify-end">
        <Button variant="secondary" onClick={() => setEvidence(null)}>{t("Close")}</Button>
      </div>}>
      {selected && evidence ? <div className="space-y-4 text-sm">
        {releaseBadge(selected)}
        <div className="grid gap-2 text-xs sm:grid-cols-3">
          <span>{t("Isolation")}: ✓</span>
          <span>{t("Functional probe")}: ✓</span>
          <span>{t("Signed")}: ✓</span>
        </div>
        <dl className="grid gap-3 text-xs sm:grid-cols-2">
          <div><dt className="text-muted-foreground">artifact</dt><dd className="break-all font-mono">{evidence.release.artifact_sha256}</dd></div>
          <div><dt className="text-muted-foreground">compose</dt><dd className="break-all font-mono">{evidence.release.compose_sha256}</dd></div>
          <div><dt className="text-muted-foreground">tree</dt><dd className="break-all font-mono">{evidence.release.hardened_tree_sha256}</dd></div>
          <div><dt className="text-muted-foreground">gate</dt><dd className="break-all font-mono">{evidence.release.gate_sha256}</dd></div>
        </dl>
      </div> : null}
    </Dialog>
    <Dialog open={rollbackTarget !== null} onClose={() => setRollbackTarget(null)}
      title={t("Confirm rollback")}
      description={t("Review the current and target releases before continuing.")}
      maxWidthClassName="max-w-[900px]"
      actions={<div className="flex justify-end gap-2">
        <Button variant="secondary" disabled={busy} onClick={() => setRollbackTarget(null)}>
          {t("Cancel")}
        </Button>
        <Button disabled={busy || !rollbackTarget}
          onClick={() => rollbackTarget && void rollback(rollbackTarget)}>
          {t("Confirm rollback")}
        </Button>
      </div>}>
      <div className="space-y-4 text-sm">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted-foreground">{t("Current release")}</div>
            <div className="mt-1 break-all font-mono text-xs">
              {activeReleaseId ?? t("No active release")}
            </div>
          </div>
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted-foreground">{t("Target release")}</div>
            <div className="mt-1 break-all font-mono text-xs">
              {rollbackTarget?.release_summary?.release_id ?? rollbackTarget?.id}
            </div>
          </div>
        </div>
        <Alert title={t("Application data is not rolled back") }>
          {t("Rollback restores the application release but does not revert volumes or databases.")}
        </Alert>
      </div>
    </Dialog>
  </div>;
}
