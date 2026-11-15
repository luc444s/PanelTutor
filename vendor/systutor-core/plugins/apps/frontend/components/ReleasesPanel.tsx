import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { Alert } from "@systutor/shell/ui/alert";
import { Button } from "@systutor/shell/ui/button";
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
    {(releases.data ?? []).map((release) => <div key={release.release_id}
      className="space-y-2 rounded border border-border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <strong className="font-mono text-xs">{release.release_id}</strong>
        <span className="text-muted-foreground">{t("commit")} <code>{release.commit}</code></span>
      </div>
      <div className="text-xs text-muted-foreground">
        {t("Expires {value}", { value: new Date(release.expires_at).toLocaleString() })}
      </div>
      <div className="flex flex-wrap gap-2">
        <Button variant="secondary" disabled={busy} onClick={() => void inspect(release)}>
          {t("Verify")}
        </Button>
        <Button variant="secondary" disabled={busy} onClick={() => void showEvidence(release)}>
          {t("Evidence")}
        </Button>
        <Button disabled={!canDeploy || pending || busy || !releaseUsable(release)}
          onClick={() => void deploy(release)}>{t("Deploy release")}</Button>
      </div>
    </div>)}
    {selected && verification ? <div className="space-y-1 rounded border border-border p-3 text-sm">
      <h4 className="font-medium">{t("Verification of {release}", { release: selected.release_id })}</h4>
      <ul className="text-xs">
        {Object.entries(verification.checks).map(([name, value]) => <li key={name}>
          {value ? "✓" : "✗"} {name}
        </li>)}
      </ul>
    </div> : null}
    {selected && evidence ? <div className="space-y-1 rounded border border-border p-3 text-sm">
      <h4 className="font-medium">{t("Evidence of {release}", { release: selected.release_id })}</h4>
      <dl className="grid gap-1 text-xs sm:grid-cols-2">
        <div><dt className="text-muted-foreground">artifact</dt><dd className="font-mono break-all">{evidence.release.artifact_sha256}</dd></div>
        <div><dt className="text-muted-foreground">compose</dt><dd className="font-mono break-all">{evidence.release.compose_sha256}</dd></div>
        <div><dt className="text-muted-foreground">tree</dt><dd className="font-mono break-all">{evidence.release.hardened_tree_sha256}</dd></div>
        <div><dt className="text-muted-foreground">gate</dt><dd className="font-mono break-all">{evidence.release.gate_sha256}</dd></div>
      </dl>
    </div> : null}
    <div className="space-y-2">
      <h3 className="text-sm font-medium">{t("Rollback to a signed deployment")}</h3>
      {rollbackTargets.length === 0 ? <p className="text-sm text-muted-foreground">
        {t("No previous signed deployment is available.")}
      </p> : null}
      {rollbackTargets.map((deployment) => <div key={deployment.id}
        className="flex flex-wrap items-center justify-between gap-2 rounded border border-border p-2 text-sm">
        <span className="font-mono text-xs">{deployment.release_summary?.release_id ?? deployment.id}</span>
        <Button variant="secondary" disabled={!canDeploy || pending || busy}
          onClick={() => void rollback(deployment)}>{t("Rollback")}</Button>
      </div>)}
    </div>
  </div>;
}
