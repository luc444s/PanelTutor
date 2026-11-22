import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { useAuthStore } from "@/features/auth/store";
import { useT } from "@/i18n/use-i18n";
import { Alert } from "@systutor/shell/ui/alert";
import { Button } from "@systutor/shell/ui/button";
import { Input } from "@systutor/shell/ui/input";

import {
  deleteTenantPlan,
  getTenantPlan,
  getTenantPlanCapacity,
  setTenantPlan,
  tenantKeys,
  verifyTenantPlan,
  type TenantPlan,
  type TenantResponse,
} from "../api";

export const BYTES_PER_GIB = 1024 ** 3;

/** Pure GiB/byte conversions shared with the UI and the unit tests. */
export function bytesToGib(bytes: number | null | undefined): number | null {
  return bytes === null || bytes === undefined ? null : bytes / BYTES_PER_GIB;
}

export function gibToBytes(gib: number): number {
  return Math.round(gib * BYTES_PER_GIB);
}

export function parseDecimal(value: string): number {
  return Number(value.trim().replace(",", "."));
}

export function parsePositive(value: string): number | null {
  const parsed = parseDecimal(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

const SUGGESTED = { ramGiB: "2", cpus: "1", storageGiB: "20", pids: "256" };

function formatNumber(value: number, digits = 1): string {
  try {
    return new Intl.NumberFormat("es-ES", {
      minimumFractionDigits: digits,
      maximumFractionDigits: digits,
    }).format(value);
  } catch {
    return value.toFixed(digits);
  }
}

function isUnavailable(error: unknown): boolean {
  const message = (error as Error | undefined)?.message ?? "";
  return /503|capacity_unavailable|materializer_unavailable|agent|unavailable/i.test(message);
}

function statusLabel(t: (key: string) => string, status: TenantPlan["status"]): string {
  if (status === "applied") return t("Applied");
  if (status === "pending") return t("Pending");
  return t("Failed");
}

export function TenantResourcePlanPanel({ tenant }: { tenant: TenantResponse }) {
  const t = useT();
  const queryClient = useQueryClient();
  const permissions = useAuthStore((state) => state.permissions ?? []);
  const canManage = permissions.includes("apps.plans.manage");
  const tenantId = tenant.id;

  const planQuery = useQuery({
    queryKey: tenantKeys.plan(tenantId),
    queryFn: () => getTenantPlan(tenantId),
    enabled: Boolean(tenantId),
  });
  const capacityQuery = useQuery({
    queryKey: tenantKeys.capacity(tenantId),
    queryFn: () => getTenantPlanCapacity(tenantId),
    enabled: Boolean(tenantId),
    retry: false,
  });

  const [ramGiB, setRamGiB] = useState(SUGGESTED.ramGiB);
  const [cpus, setCpus] = useState(SUGGESTED.cpus);
  const [storageGiB, setStorageGiB] = useState(SUGGESTED.storageGiB);
  const [pids, setPids] = useState(SUGGESTED.pids);
  const [formError, setFormError] = useState<string | null>(null);

  useEffect(() => {
    const plan = planQuery.data;
    if (plan) {
      setRamGiB(String(bytesToGib(plan.memory_bytes) ?? ""));
      setCpus(String(plan.cpus));
      setStorageGiB(
        plan.storage_bytes === null ? "" : String(bytesToGib(plan.storage_bytes) ?? ""),
      );
      setPids(String(plan.pids));
    } else if (planQuery.isSuccess) {
      setRamGiB(SUGGESTED.ramGiB);
      setCpus(SUGGESTED.cpus);
      setStorageGiB(SUGGESTED.storageGiB);
      setPids(SUGGESTED.pids);
    }
  }, [planQuery.data, planQuery.isSuccess]);

  async function refresh() {
    await queryClient.invalidateQueries({ queryKey: tenantKeys.plan(tenantId) });
    await queryClient.invalidateQueries({ queryKey: tenantKeys.capacity(tenantId) });
  }

  const saveMutation = useMutation({
    mutationFn: () => {
      const ram = parsePositive(ramGiB);
      const cpu = parsePositive(cpus);
      const processLimit = parsePositive(pids);
      const storage = storageGiB.trim() === "" ? null : parsePositive(storageGiB);
      if (ram === null) throw new Error(t("RAM must be greater than zero"));
      if (cpu === null) throw new Error(t("CPU must be greater than zero"));
      if (processLimit === null) throw new Error(t("PIDs must be greater than zero"));
      if (storage === null && storageGiB.trim() !== "") {
        throw new Error(t("Storage must be greater than zero"));
      }
      return setTenantPlan(tenantId, {
        memory_bytes: gibToBytes(ram),
        cpus: cpu,
        pids: processLimit,
        storage_bytes: storage === null ? null : gibToBytes(storage),
      });
    },
    onSuccess: async () => {
      await refresh();
      setFormError(null);
      toast.success(t("Plan saved"));
    },
    onError: (error: Error) => setFormError(error.message),
  });

  const verifyMutation = useMutation({
    mutationFn: () => verifyTenantPlan(tenantId),
    onSuccess: async () => {
      await refresh();
      toast.success(t("Plan verified"));
    },
    onError: (error: Error) => setFormError(error.message),
  });

  const removeMutation = useMutation({
    mutationFn: () => deleteTenantPlan(tenantId),
    onSuccess: async () => {
      await refresh();
      setFormError(null);
      toast.success(t("Plan removed"));
    },
    onError: (error: Error) => setFormError(error.message),
  });

  const capacity = capacityQuery.data;
  const plan = planQuery.data;
  const busy = saveMutation.isPending || verifyMutation.isPending || removeMutation.isPending;
  const capacityReady = capacityQuery.isSuccess;

  if (planQuery.isLoading || capacityQuery.isLoading) {
    return <p className="text-sm text-muted-foreground">{t("Loading plan...")}</p>;
  }

  const host = capacity?.host;
  const allocated = capacity?.allocated;

  return (
    <div className="space-y-4">
      {capacityQuery.error ? (
        <Alert title={t("Could not read the host capacity")}>
          {isUnavailable(capacityQuery.error)
            ? t("The plan agent is not responding. The plan cannot be saved until it returns.")
            : (capacityQuery.error as Error).message}
        </Alert>
      ) : null}

      {plan ? (
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <span className="inline-flex items-center gap-2 font-medium text-foreground">
            <span
              aria-hidden="true"
              className={`h-2 w-2 rounded-full ${
                plan.status === "applied"
                  ? "bg-success"
                  : plan.status === "pending"
                    ? "bg-warning"
                    : "bg-destructive"
              }`}
            />
            {t("Plan {status}", { status: statusLabel(t, plan.status) })}
          </span>
          {plan.applied_at ? (
            <span className="text-xs text-muted-foreground">
              {t("Updated {date}", { date: new Date(plan.applied_at).toLocaleString("es-ES") })}
            </span>
          ) : null}
          <span className="font-mono text-xs text-muted-foreground">{plan.slice}</span>
        </div>
      ) : planQuery.isSuccess ? (
        <p className="text-sm text-muted-foreground">
          {t("This tenant does not have a resource plan yet.")}
        </p>
      ) : null}

      {plan?.last_error ? (
        <Alert title={t("Last plan error")}>{plan.last_error}</Alert>
      ) : null}

      {host ? (
        <section className="space-y-2">
          <h3 className="text-xs font-semibold uppercase text-muted-foreground">
            {t("Host capacity")}
          </h3>
          <div className="grid gap-2 sm:grid-cols-3">
            <div className="rounded-md border border-border px-3 py-2">
              <p className="text-xs uppercase text-muted-foreground">{t("RAM")}</p>
              <p className="text-sm font-medium text-foreground">
                {formatNumber(bytesToGib(host.memory_bytes) ?? 0)} GiB
              </p>
              <p className="text-xs text-muted-foreground">
                {t("{value} assigned", {
                  value: `${formatNumber(bytesToGib(allocated?.memory_bytes) ?? 0)} GiB`,
                })}
              </p>
            </div>
            <div className="rounded-md border border-border px-3 py-2">
              <p className="text-xs uppercase text-muted-foreground">{t("CPU")}</p>
              <p className="text-sm font-medium text-foreground">
                {formatNumber(host.cpus)} cores
              </p>
              <p className="text-xs text-muted-foreground">
                {t("{value} assigned", {
                  value: `${formatNumber(allocated?.cpus ?? 0)} cores`,
                })}
              </p>
            </div>
            <div className="rounded-md border border-border px-3 py-2">
              <p className="text-xs uppercase text-muted-foreground">{t("Disk")}</p>
              <p className="text-sm font-medium text-foreground">
                {formatNumber(bytesToGib(host.storage_bytes) ?? 0)} GiB
              </p>
              <p className="text-xs text-muted-foreground">
                {t("{value} assigned", {
                  value: `${formatNumber(bytesToGib(allocated?.storage_bytes) ?? 0)} GiB`,
                })}
              </p>
            </div>
          </div>
        </section>
      ) : null}

      <section className="space-y-2">
        <h3 className="text-xs font-semibold uppercase text-muted-foreground">
          {t("Tenant plan")}
        </h3>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block space-y-1 text-sm text-foreground">
            <span>{t("Memory RAM")}</span>
            <div className="flex items-center gap-2">
              <Input
                inputMode="decimal"
                value={ramGiB}
                disabled={!canManage}
                onChange={(event) => { setRamGiB(event.target.value); setFormError(null); }}
              />
              <span className="text-xs text-muted-foreground">GiB</span>
            </div>
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>{t("CPU cores")}</span>
            <div className="flex items-center gap-2">
              <Input
                inputMode="decimal"
                value={cpus}
                disabled={!canManage}
                onChange={(event) => { setCpus(event.target.value); setFormError(null); }}
              />
              <span className="text-xs text-muted-foreground">cores</span>
            </div>
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>{t("Storage")}</span>
            <div className="flex items-center gap-2">
              <Input
                inputMode="decimal"
                value={storageGiB}
                disabled={!canManage}
                onChange={(event) => { setStorageGiB(event.target.value); setFormError(null); }}
              />
              <span className="text-xs text-muted-foreground">GiB</span>
            </div>
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>{t("Processes (PIDs)")}</span>
            <div className="flex items-center gap-2">
              <Input
                inputMode="numeric"
                value={pids}
                disabled={!canManage}
                onChange={(event) => { setPids(event.target.value); setFormError(null); }}
              />
              <span className="text-xs text-muted-foreground">procs</span>
            </div>
          </label>
        </div>
      </section>

      {formError ? (
        <Alert title={t("Error")}>
          {isUnavailable(formError)
            ? t("The plan agent is not responding. The plan cannot be saved until it returns.")
            : formError}
        </Alert>
      ) : null}

      {canManage ? (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3">
          <Button
            type="button"
            size="sm"
            variant="secondary"
            disabled={busy || !plan}
            onClick={() => {
              if (window.confirm(t("Delete this tenant plan?"))) removeMutation.mutate();
            }}
          >
            {t("Delete plan")}
          </Button>
          <div className="flex gap-2">
            <Button
              type="button"
              size="sm"
              variant="secondary"
              disabled={busy || !plan}
              onClick={() => verifyMutation.mutate()}
            >
              {t("Verify")}
            </Button>
            <Button
              type="button"
              size="sm"
              disabled={busy || !capacityReady}
              onClick={() => saveMutation.mutate()}
            >
              {t("Save plan")}
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
