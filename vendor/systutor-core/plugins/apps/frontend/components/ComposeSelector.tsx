import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronRight } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@systutor/shell/ui/button";
import { Select } from "@systutor/shell/ui/select";
import { toast } from "@systutor/shell/ui/toast";
import { useT } from "@/i18n/use-i18n";

import { appsKeys, listComposeFiles, updateApplicationCompose } from "../api";
import type { Application } from "../types";

export function ComposeSelector({ application, disabled }: {
  application: Application;
  disabled: boolean;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState(application.compose_file ?? "");
  const [saving, setSaving] = useState(false);
  const installationId = application.source_installation_id;
  const repositoryId = application.source_repository_id;
  const candidates = useQuery({
    queryKey: appsKeys.composeFiles(
      installationId ?? "idle", repositoryId ?? "idle", application.branch,
    ),
    queryFn: () => listComposeFiles(installationId!, repositoryId!, application.branch),
    enabled: Boolean(installationId && repositoryId),
    retry: false,
  });

  useEffect(() => {
    setDraft(application.compose_file ?? "");
  }, [application.compose_file]);

  const options = [
    { value: "", label: t("Autodetect") },
    ...(candidates.data ?? []).map((path) => ({ value: path, label: path })),
  ];
  if (draft && !options.some((option) => option.value === draft)) {
    options.push({ value: draft, label: draft });
  }
  const changed = draft !== (application.compose_file ?? "");

  async function save() {
    setSaving(true);
    try {
      await updateApplicationCompose(application.id, draft || null);
      await queryClient.invalidateQueries({ queryKey: appsKeys.detail(application.id) });
      await queryClient.invalidateQueries({ queryKey: appsKeys.applications });
      toast.success(t("Compose file updated"));
    } catch (reason) {
      toast.error(reason instanceof Error
        ? reason.message
        : t("Could not update the compose file"));
    } finally {
      setSaving(false);
    }
  }

  return <details className="group">
    <summary className="flex cursor-pointer list-none items-center gap-1 text-xs text-muted-foreground marker:hidden [&::-webkit-details-marker]:hidden">
      <ChevronRight aria-hidden="true" className="h-3 w-3 shrink-0 transition-transform group-open:rotate-90" />
      <span>{application.compose_file ?? t("Autodetect")}</span>
    </summary>
    <div className="mt-2 w-full max-w-sm space-y-2">
      <Select
        value={draft}
        onChange={setDraft}
        options={options}
        placeholder={candidates.isLoading ? t("Loading…") : t("Autodetect")}
      />
      <Button variant="secondary" disabled={saving || disabled || !changed}
        onClick={() => void save()}>
        {t("Save")}
      </Button>
    </div>
  </details>;
}
