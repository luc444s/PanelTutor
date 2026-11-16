import { Loader2 } from "lucide-react";

import { cn } from "@systutor/shell/ui/cn";

const POSITIVE_STATUSES = new Set([
  "active", "connected", "healthy", "ready", "running", "succeeded", "up",
]);
const NEGATIVE_STATUSES = new Set([
  "blocked", "dead", "deleted", "down", "error", "exited", "failed", "missing",
  "stop", "stopped", "unhealthy",
]);
const TRANSITIONAL_STATUSES = new Set([
  "building", "created", "degraded", "deploying", "paused", "pending", "queued",
  "restarting", "starting", "stopping",
]);

type StatusTone = "positive" | "negative" | "transitional" | "neutral";

export function statusTone(status: string): StatusTone {
  const normalized = status.trim().toLowerCase();
  if (POSITIVE_STATUSES.has(normalized)) return "positive";
  if (NEGATIVE_STATUSES.has(normalized)) return "negative";
  if (TRANSITIONAL_STATUSES.has(normalized)) return "transitional";
  return "neutral";
}

export function statusDotTone(status: string): string {
  const tones: Record<StatusTone, string> = {
    positive: "text-emerald-500",
    negative: "text-red-500",
    transitional: "text-amber-500",
    neutral: "text-zinc-400",
  };
  return tones[statusTone(status)];
}

const BADGE_TONES: Record<StatusTone, string> = {
  positive: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  negative: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400",
  transitional: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400",
  neutral: "border-border bg-muted text-muted-foreground",
};

export function statusBadgeTone(status: string): string {
  return BADGE_TONES[statusTone(status)];
}

export function StatusBadge({ status, label, spinner = false, className }: {
  status: string;
  label?: string;
  spinner?: boolean;
  className?: string;
}) {
  return <span className={cn(
    "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium",
    statusBadgeTone(status),
    className,
  )}>
    {spinner
      ? <Loader2 aria-hidden="true" className="h-3 w-3 shrink-0 animate-spin" />
      : <span aria-hidden="true" className="h-1.5 w-1.5 shrink-0 rounded-full bg-current" />}
    <span>{label ?? status}</span>
  </span>;
}

export function StatusIndicator({ status, className }: { status: string; className?: string }) {
  const normalized = status.trim().toLowerCase();
  const tone = statusDotTone(status);
  return <span className={cn("inline-flex items-center gap-1.5", className)}>
    {normalized === "deploying"
      ? <Loader2 aria-hidden="true" className={cn("h-3 w-3 shrink-0 animate-spin", tone)} />
      : <svg aria-hidden="true" viewBox="0 0 8 8" className={cn("h-2 w-2 shrink-0 fill-current", tone)}>
        <circle cx="4" cy="4" r="4" />
      </svg>}
    <span className={tone}>{status}</span>
  </span>;
}
