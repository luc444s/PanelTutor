import { useEffect, useState } from "react";

import { Alert } from "@systutor/shell/ui/alert";
import { Button } from "@systutor/shell/ui/button";
import { Dialog } from "@systutor/shell/ui/dialog";
import { Input, Textarea } from "@systutor/shell/ui/input";
import { Select } from "@systutor/shell/ui/select";
import { toast } from "@systutor/shell/ui/toast";
import { useT } from "@/i18n/use-i18n";

import {
  buildHardeningPolicy, parseDotenv, serviceUserDrafts,
  type ServiceUserDraft,
} from "../logic";
import { deployApplication, newIdempotencyKey } from "../api";
import type {
  Application, DeployPayload, HardeningWritablePath, InspectedService,
  OperationSummary,
} from "../types";

export function DeployDialog({ application, services, open, blocked, onClose, onAccepted }: {
  application: Application;
  services: InspectedService[];
  open: boolean;
  blocked: boolean;
  onClose: () => void;
  onAccepted: (operation: OperationSummary) => void;
}) {
  const t = useT();
  const [dotenv, setDotenv] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [users, setUsers] = useState<Record<string, ServiceUserDraft>>({});
  const [paths, setPaths] = useState<HardeningWritablePath[]>([]);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [intent, setIntent] = useState<{ key: string; body: DeployPayload } | null>(null);
  const serviceSignature = services
    .map((service) => `${service.name}:${service.compose_user ?? ""}`)
    .join("|");

  useEffect(() => {
    if (!open) return;
    setUsers(serviceUserDrafts(services));
    setPaths([]);
    setIntent(null);
    setError(null);
  }, [open, serviceSignature]);

  function clearIntent() {
    setIntent(null);
    setError(null);
  }

  async function submit() {
    if (blocked || confirmation !== application.slug) return;
    let request = intent;
    if (!request) {
      try {
        const policy = buildHardeningPolicy(
          services.map((service) => service.name),
          users,
          paths,
        );
        const environment = parseDotenv(dotenv).map(
          (item) => [item.name, item.value] as [string, string],
        );
        request = {
          key: newIdempotencyKey(),
          body: { environment, hardening: policy },
        };
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : t("The hardening policy is not valid"));
        return;
      }
    }
    setIntent(request);
    setPending(true); setError(null);
    const toastId = `apps-deploy-${application.id}`;
    toast.loading(t("Sending deployment…"), { id: toastId });
    try {
      const operation = await deployApplication(application.id, request.body, request.key);
      // Secrets are destroyed immediately after the server accepts the job.
      setDotenv(""); setConfirmation(""); setIntent(null);
      toast.success(t("Deployment accepted; follow progress in Operations"), { id: toastId });
      onAccepted(operation);
    } catch (reason) {
      // Keep the same in-memory key/body only for an explicit retry of this uncertain request.
      const message = reason instanceof Error ? reason.message : t("Could not accept the deployment");
      setError(message);
      toast.error(message, { id: toastId });
    } finally {
      setPending(false);
    }
  }

  function close() {
    setDotenv(""); setConfirmation(""); setIntent(null); setError(null);
    onClose();
  }

  function updateUser(service: string, field: keyof ServiceUserDraft, value: string) {
    setUsers((current) => ({
      ...current,
      [service]: { ...(current[service] ?? { uid: "", gid: "" }), [field]: value },
    }));
    clearIntent();
  }

  function updatePath(index: number, patch: Partial<HardeningWritablePath>) {
    setPaths((current) => current.map((item, position) =>
      position === index ? { ...item, ...patch } : item));
    clearIntent();
  }

  const ready = services.length > 0 && !blocked && confirmation === application.slug;

  return <Dialog open={open} title={t("Deploy {name}", { name: application.name })} onClose={close}>
    <div className="space-y-4">
      <Alert title={t("Untrusted code")}>{t("Docker build will run code from the repository. The hardening gate is the authority; if it fails, nothing is deployed.")}</Alert>
      <dl className="grid grid-cols-2 gap-2 text-sm">
        <div><dt className="text-muted-foreground">{t("Domain")}</dt><dd>{application.domain ?? t("Not published")}</dd></div>
        <div><dt className="text-muted-foreground">{t("Ingress")}</dt><dd>{application.ingress_service ? `${application.ingress_service}:${application.ingress_port}` : t("No ingress")}</dd></div>
      </dl>

      <section className="space-y-2 rounded-md border border-border p-3">
        <div>
          <h3 className="text-sm font-medium">{t("Runtime policy by service")}</h3>
          <p className="text-xs text-muted-foreground">{t("Every inspected service needs a positive UID and GID. The hardener applies them and the probes verify the effective user.")}</p>
        </div>
        {services.length === 0 ? <Alert title={t("Inspection required")}>
          {t("Run an inspection before deploying so the runtime policy can cover every service.")}
        </Alert> : null}
        {services.map((service) => <div key={service.name}
          className="grid gap-2 border-t border-border pt-2 sm:grid-cols-[1fr_auto_auto]">
          <div className="min-w-0 text-sm">
            <div className="truncate font-medium">{service.name}</div>
            <div className="truncate text-xs text-muted-foreground">
              {service.build
                ? `${t("Build")} · ${service.dockerfile ?? "Dockerfile"}`
                : `${t("Image")} · ${service.image ?? t("Unknown")}`}
              {service.compose_user ? ` · user ${service.compose_user}` : ""}
            </div>
          </div>
          <label className="block space-y-1 text-xs">
            <span>{t("UID")}</span>
            <Input inputMode="numeric" autoComplete="off" className="w-24"
              value={users[service.name]?.uid ?? ""}
              onChange={(event) => updateUser(service.name, "uid", event.target.value)} />
          </label>
          <label className="block space-y-1 text-xs">
            <span>{t("GID")}</span>
            <Input inputMode="numeric" autoComplete="off" className="w-24"
              value={users[service.name]?.gid ?? ""}
              onChange={(event) => updateUser(service.name, "gid", event.target.value)} />
          </label>
        </div>)}
      </section>

      <section className="space-y-2 rounded-md border border-border p-3">
        <div className="flex items-start justify-between gap-2">
          <div>
            <h3 className="text-sm font-medium">{t("Writable paths (optional)")}</h3>
            <p className="text-xs text-muted-foreground">{t("Absolute normalized paths with a four-digit octal mode; never world-writable.")}</p>
          </div>
          <Button variant="secondary" disabled={services.length === 0 || pending}
            onClick={() => {
              setPaths((current) => [...current, {
                service: services[0]?.name ?? "", path: "", mode: "0750",
              }]);
              clearIntent();
            }}>{t("Add path")}</Button>
        </div>
        {paths.map((item, index) => <div key={index}
          className="grid gap-2 border-t border-border pt-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto_auto]">
          <Select value={item.service}
            onChange={(value) => updatePath(index, { service: value })}
            options={services.map((service) => ({ value: service.name, label: service.name }))}
            placeholder={t("Service")} />
          <Input value={item.path} placeholder="/var/lib/app/data" autoComplete="off"
            onChange={(event) => updatePath(index, { path: event.target.value })} />
          <Input value={item.mode} inputMode="numeric" autoComplete="off" className="w-24"
            onChange={(event) => updatePath(index, { mode: event.target.value })} />
          <Button variant="secondary" disabled={pending}
            onClick={() => {
              setPaths((current) => current.filter((_, position) => position !== index));
              clearIntent();
            }}>{t("Remove path")}</Button>
        </div>)}
      </section>

      <div className="space-y-2 rounded-md border border-border p-3">
        <label className="block space-y-2 text-sm">
          <span className="font-medium">{t("Variables in .env format")}</span>
          <Textarea
            className="min-h-48 font-mono text-xs"
            value={dotenv}
            onChange={(event) => { setDotenv(event.target.value); clearIntent(); }}
            placeholder={application.has_saved_environment
              ? t("Leave empty to reuse the saved variables, or paste a new block to replace them.")
              : "DATABASE_URL=protocol://${APP_DB_USER}:${APP_DB_PASSWORD}@database:1234/${APP_DB_NAME}\nVITE_API_BASE_URL=https://api.example"}
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        {application.has_saved_environment ? <p className="text-xs text-muted-foreground">
          {t("This deployment has saved variables. If you leave the field empty they are reused; if you paste a block, it replaces the previous ones. Values are not shown again.")}
        </p> : <p className="text-xs text-muted-foreground">
          {t("You can paste a complete .env file. When accepted, the block is stored encrypted for future deployments.")}
        </p>}
        <p className="text-xs text-muted-foreground">
          {t("Apps generates and keeps APP_DB_NAME, APP_DB_USER and APP_DB_PASSWORD encrypted. Do not include them here; Compose can reference them from any engine.")}
        </p>
      </div>
      <label className="block space-y-1 text-sm"><span>{t("Type {slug} to confirm", { slug: application.slug })}</span><Input value={confirmation} onChange={(e) => setConfirmation(e.target.value)} /></label>
      {blocked ? <Alert title={t("Deployment blocked")}>{t("The application source is not connected or another operation is active.")}</Alert> : null}
      {error ? <Alert title={t("Error")}>{error}</Alert> : null}
      <div className="flex justify-end gap-2">
        <Button variant="secondary" disabled={pending} onClick={close}>{t("Cancel")}</Button>
        <Button disabled={pending || !ready} onClick={() => void submit()}>{pending ? t("Accepting…") : intent ? t("Retry same request") : t("Deploy")}</Button>
      </div>
    </div>
  </Dialog>;
}
