import { useQuery } from "@tanstack/react-query";
import { FormEvent, useEffect, useState } from "react";

import { Alert } from "@systutor/shell/ui/alert";
import { Button } from "@systutor/shell/ui/button";
import { Dialog } from "@systutor/shell/ui/dialog";
import { Input } from "@systutor/shell/ui/input";
import { Select } from "@systutor/shell/ui/select";
import { useT } from "@/i18n/use-i18n";

import {
  appsKeys, createApplication, inspectApplication, listInstallations,
  listInstallationRepositories, newIdempotencyKey,
} from "../api";
import type { Application, OperationSummary } from "../types";

type Props = {
  open: boolean;
  onClose: () => void;
  onAccepted: (application: Application, operation: OperationSummary) => void;
};

export function CreateApplicationDialog({ open, onClose, onAccepted }: Props) {
  const t = useT();
  const [installationId, setInstallationId] = useState("");
  const [repositoryId, setRepositoryId] = useState("");
  const [name, setName] = useState("");
  const [branch, setBranch] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const installations = useQuery({
    queryKey: appsKeys.installations, queryFn: listInstallations,
    enabled: open, retry: false,
  });
  const repositories = useQuery({
    queryKey: appsKeys.repositories(installationId || "idle"),
    queryFn: () => listInstallationRepositories(installationId),
    enabled: open && Boolean(installationId), retry: false,
  });
  const activeInstallations = (installations.data ?? []).filter(
    (item) => item.status === "active",
  );
  const selectedRepository = repositories.data?.find((item) => item.id === repositoryId);

  useEffect(() => {
    if (selectedRepository) setBranch(selectedRepository.default_branch || "main");
  }, [selectedRepository]);

  function selectInstallation(value: string) {
    setInstallationId(value);
    setRepositoryId("");
    setBranch("");
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (!installationId || !repositoryId) return setError(t("Choose an authorized installation and repository"));
    setPending(true);
    try {
      const application = await createApplication({
        name: name.trim(),
        installation_id: installationId,
        repository_id: repositoryId,
        branch: branch.trim() || null,
        compose_file: null,
        domain: null,
        ingress_service: null,
        ingress_port: null,
      });
      const operation = await inspectApplication(application.id, newIdempotencyKey());
      setName("");
      setInstallationId(""); setRepositoryId(""); setBranch("");
      onAccepted(application, operation);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : t("Could not create and inspect the application"));
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} title={t("Create and inspect application")} onClose={onClose}>
      <form className="space-y-3" onSubmit={(event) => void submit(event)}>
        <p className="text-xs text-muted-foreground">{t("Authorized source · create · async inspection")}</p>
        <label className="block space-y-1 text-sm">
          <span>{t("GitHub installation")}</span>
          <Select
            value={installationId}
            onChange={selectInstallation}
            options={activeInstallations.map((item) => ({
              value: item.id,
              label: t("@{account} · {count} repos", {
                account: item.account_login, count: item.repository_count,
              }),
            }))}
            placeholder={installations.isLoading ? t("Loading…") : t("Choose installation")}
          />
        </label>
        <label className="block space-y-1 text-sm">
          <span>{t("Authorized repository")}</span>
          <Select
            value={repositoryId}
            onChange={setRepositoryId}
            options={(repositories.data ?? []).map((item) => ({
              value: item.id, label: item.full_name,
            }))}
            placeholder={repositories.isLoading ? t("Loading…") : t("Choose repository")}
          />
        </label>
        {repositories.data?.length === 0 ? (
          <Alert title={t("No repositories")}>{t("The installation does not expose authorized repositories. Sync or review the selection on GitHub.")}</Alert>
        ) : null}
        <label className="block space-y-1 text-sm"><span>{t("Name")}</span><Input required value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label className="block space-y-1 text-sm"><span>{t("Branch")}</span><Input required value={branch} onChange={(e) => setBranch(e.target.value)} /></label>
        {error ? <Alert title={t("Error")}>{error}</Alert> : null}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" disabled={pending} onClick={onClose}>{t("Cancel")}</Button>
          <Button type="submit" disabled={pending || !installationId || !repositoryId}>{pending ? t("Creating…") : t("Create and inspect")}</Button>
        </div>
      </form>
    </Dialog>
  );
}
