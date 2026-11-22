import { useEffect, useState } from "react";

import { getApiBaseUrl } from "@systutor/shell/api/client";

import { useAuthStore } from "../../features/auth/store";
import { useT } from "../../i18n/use-i18n";
import {
  cacheMemoryBytes,
  effectiveMemoryBytes,
  formatMemoryBytes,
  memoryPercent,
  parseMetricsEvent,
  parseSseChunk,
  reconnectDelay,
  type CellMetricsSample,
} from "../../plugins/tenant-metrics.logic";

const STREAM_INTERVAL_MS = 2000;

type LiveStatus = "live" | "reconnecting" | "offline";

/**
 * Same URL contract as `tenantMetricsStreamUrl` in the tenant plugin. Kept
 * local so the shell sidebar does not import plugin frontend code.
 */
function tenantMetricsStreamUrl(tenantId: string): string {
  const path = `/api/v1/plugins/tenant/tenants/${encodeURIComponent(tenantId)}/metrics/stream?interval_ms=${STREAM_INTERVAL_MS}`;
  const baseUrl = getApiBaseUrl();
  return baseUrl.endsWith("/api") ? `${baseUrl}${path.slice(4)}` : `${baseUrl}${path}`;
}

function useTenantRam(tenantId: string | null, enabled: boolean) {
  const token = useAuthStore((state) => state.token);
  const [sample, setSample] = useState<CellMetricsSample | null>(null);
  const [status, setStatus] = useState<LiveStatus>("offline");

  useEffect(() => {
    if (!enabled || !tenantId || !token) {
      setSample(null);
      setStatus("offline");
      return;
    }

    let cancelled = false;
    let controller: AbortController | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let attempt = 0;

    setSample(null);
    setStatus("reconnecting");

    const connect = async () => {
      if (cancelled) return;
      controller = new AbortController();
      try {
        const response = await fetch(tenantMetricsStreamUrl(tenantId), {
          headers: {
            Accept: "text/event-stream",
            Authorization: `Bearer ${token}`,
          },
          signal: controller.signal,
        });

        if (!response.ok || response.body === null) {
          // A missing plugin or a forbidden user will not recover on retry.
          if ([401, 403, 404].includes(response.status)) {
            setStatus("offline");
            return;
          }
          throw new Error(`HTTP ${response.status}`);
        }

        attempt = 0;
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (!cancelled) {
          const { value, done } = await reader.read();
          if (done) break;
          const parsed = parseSseChunk(buffer, decoder.decode(value, { stream: true }));
          buffer = parsed.buffer;
          for (const event of parsed.events) {
            if (event.event === "error") throw new Error("metrics stream error");
            const next = parseMetricsEvent(event);
            if (next) {
              setSample(next);
              setStatus("live");
            }
          }
        }
        throw new Error("metrics stream closed");
      } catch (error) {
        if (cancelled || (error instanceof DOMException && error.name === "AbortError")) return;
        setStatus("reconnecting");
        const delay = reconnectDelay(attempt);
        attempt += 1;
        if (!cancelled) timer = setTimeout(() => { void connect(); }, delay);
      }
    };

    void connect();

    return () => {
      cancelled = true;
      controller?.abort();
      if (timer !== null) clearTimeout(timer);
    };
  }, [enabled, tenantId, token]);

  return { sample, status };
}

/**
 * Minimal per-tenant RAM gauge for the bottom of the sidebar. Every user of
 * the tenant sees the same cell limit and usage; it consumes the tenant
 * metrics SSE stream scoped to the authenticated user's own tenant.
 */
export function TenantRamWatcher() {
  const t = useT();
  const tenantId = useAuthStore((state) => state.currentTenant?.id ?? null);
  const enabled = Boolean(tenantId);
  const { sample, status } = useTenantRam(tenantId, enabled);

  if (!enabled) return null;

  const percent = sample ? memoryPercent(sample) : null;
  const roundedPercent = percent === null ? null : Math.round(percent);
  const used = sample ? effectiveMemoryBytes(sample) : undefined;
  const cache = sample ? cacheMemoryBytes(sample) : null;
  const limit = sample?.memory.max_bytes;
  const statusLabel = status === "live" ? t("Live") : status === "reconnecting" ? t("Reconnecting…") : t("No connection");
  const barTone =
    roundedPercent === null
      ? "bg-border"
      : roundedPercent >= 90
        ? "bg-destructive"
        : roundedPercent >= 75
          ? "bg-warning"
          : "bg-primary";

  return (
    <div className="space-y-1.5" aria-label={t("RAM")}>
      <div className="flex items-center justify-between text-xs">
        <span className="font-semibold uppercase tracking-wide text-sidebar-muted">{t("RAM")}</span>
        <span className="inline-flex items-center gap-1.5 text-sidebar-foreground/70" title={statusLabel}>
          <span
            aria-hidden="true"
            className={`h-1.5 w-1.5 rounded-full ${
              status === "live"
                ? "bg-success"
                : status === "reconnecting"
                  ? "bg-warning"
                  : "bg-destructive"
            }`}
          />
          <span>{roundedPercent === null ? "—" : `${roundedPercent} %`}</span>
        </span>
      </div>
      <div
        className="h-1.5 w-full overflow-hidden rounded-full bg-border"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={roundedPercent ?? undefined}
      >
        <div
          className={`h-full rounded-full transition-[width] duration-500 ${barTone}`}
          style={{ width: `${percent ?? 0}%` }}
        />
      </div>
      <p
        className="text-[11px] text-sidebar-muted"
        title={cache === null ? undefined : `${t("Cache")}: ${formatMemoryBytes(cache)}`}
      >
        {formatMemoryBytes(used)} / {formatMemoryBytes(limit)}
        {cache !== null && cache > 0 ? ` · ${formatMemoryBytes(cache)}` : ""}
      </p>
    </div>
  );
}
