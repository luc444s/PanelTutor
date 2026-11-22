/**
 * Pure helpers for the live cell metrics section (A.SPEC 0113).
 *
 * No React, no DOM, no chart library: the SSE parser, the 60-sample ring
 * buffer and the SVG sparkline are testable in isolation.
 */

export type PressureValue = {
  some_avg10: number;
  full_avg10: number;
};

export type CellMetricsSample = {
  ts_ms: number;
  slug: string;
  uid: number;
  interval_ms: number;
  warmup: boolean;
  memory: {
    current_bytes: number;
    peak_bytes: number | null;
    max_bytes: number | null;
    oom_kill: number;
  };
  cpu: {
    usage_usec: number;
    cores: number;
    quota_usec: number | null;
    period_usec: number | null;
    nr_throttled: number;
  };
  pids: {
    current: number;
    max: number | null;
  };
  pressure: {
    cpu: PressureValue;
    memory: PressureValue;
    io: PressureValue;
  };
  io: {
    read_bytes: number;
    write_bytes: number;
    read_bytes_per_s: number | null;
    write_bytes_per_s: number | null;
  };
};

export type SseEvent = {
  event: string;
  data: string;
};

export type SseParseResult = {
  buffer: string;
  events: SseEvent[];
};

export const METRICS_HISTORY = 60;
export const RECONNECT_DELAYS_MS = [1000, 2000, 5000, 10000] as const;

/** Parse one opaque `event:`/`data:` block; comments and `retry:` are ignored. */
export function parseSseBlock(block: string): SseEvent | null {
  let event = "message";
  const data: string[] = [];

  for (const rawLine of block.split("\n")) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (line === "" || line.startsWith(":")) continue;

    const separator = line.indexOf(":");
    const field = separator === -1 ? line : line.slice(0, separator);
    let value = separator === -1 ? "" : line.slice(separator + 1);
    if (value.startsWith(" ")) value = value.slice(1);

    if (field === "event") {
      event = value;
    } else if (field === "data") {
      data.push(value);
    }
  }

  if (data.length === 0) return null;
  return { event, data: data.join("\n") };
}

/** Incremental SSE parser: keep `buffer`, consume only complete blocks. */
export function parseSseChunk(buffer: string, chunk: string): SseParseResult {
  // Normalize CRLF, but a trailing lone CR may be the first half of a CRLF
  // split across chunks: keep it in the buffer instead of treating it as \n.
  let combined = (buffer + chunk).replace(/\r\n/g, "\n");
  const trailingCarriageReturn = combined.endsWith("\r");
  if (trailingCarriageReturn) combined = combined.slice(0, -1);

  const blocks = combined.split("\n\n");
  const remainder = (blocks.pop() ?? "") + (trailingCarriageReturn ? "\r" : "");
  const events: SseEvent[] = [];

  for (const block of blocks) {
    const event = parseSseBlock(block);
    if (event) events.push(event);
  }

  return { buffer: remainder, events };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isPressureValue(value: unknown): boolean {
  return isRecord(value) && isNumber(value.some_avg10) && isNumber(value.full_avg10);
}

function isOptionalNumber(value: unknown): boolean {
  return value === null || isNumber(value);
}

/** Structural guard for one 0112 JSON line. */
export function isCellMetricsSample(value: unknown): value is CellMetricsSample {
  if (!isRecord(value)) return false;
  if (!isNumber(value.ts_ms) || typeof value.slug !== "string") return false;
  if (!isNumber(value.uid) || !isNumber(value.interval_ms)) return false;

  const memory = value.memory;
  if (!isRecord(memory)) return false;
  if (!isNumber(memory.current_bytes)) return false;
  if (!isOptionalNumber(memory.peak_bytes) || !isOptionalNumber(memory.max_bytes)) return false;
  if (!isNumber(memory.oom_kill)) return false;

  const cpu = value.cpu;
  if (!isRecord(cpu)) return false;
  if (!isNumber(cpu.usage_usec) || !isNumber(cpu.cores)) return false;
  if (!isOptionalNumber(cpu.quota_usec) || !isOptionalNumber(cpu.period_usec)) return false;
  if (!isNumber(cpu.nr_throttled)) return false;

  const pids = value.pids;
  if (!isRecord(pids) || !isNumber(pids.current) || !isOptionalNumber(pids.max)) return false;

  const pressure = value.pressure;
  if (!isRecord(pressure)) return false;
  if (!isPressureValue(pressure.cpu)) return false;
  if (!isPressureValue(pressure.memory)) return false;
  if (!isPressureValue(pressure.io)) return false;

  const io = value.io;
  if (!isRecord(io)) return false;
  if (!isNumber(io.read_bytes) || !isNumber(io.write_bytes)) return false;
  if (!isOptionalNumber(io.read_bytes_per_s)) return false;
  if (!isOptionalNumber(io.write_bytes_per_s)) return false;

  return true;
}

/** Parse a `data:` event into a sample; error/retry/unrelated events are null. */
export function parseMetricsEvent(event: SseEvent): CellMetricsSample | null {
  if (event.event !== "message" && event.event !== "sample") return null;
  try {
    const payload: unknown = JSON.parse(event.data);
    return isCellMetricsSample(payload) ? payload : null;
  } catch {
    return null;
  }
}

/** Append a sample and keep only the newest `capacity` entries. */
export function pushSample(
  samples: readonly CellMetricsSample[],
  sample: CellMetricsSample,
  capacity = METRICS_HISTORY,
): CellMetricsSample[] {
  if (capacity <= 0) return [];
  const next = [...samples, sample];
  return next.length > capacity ? next.slice(next.length - capacity) : next;
}

/** Bounded reconnect backoff: 1 s, 2 s, 5 s, 10 s, then 10 s. */
export function reconnectDelay(attempt: number): number {
  const index = Math.min(Math.max(attempt, 0), RECONNECT_DELAYS_MS.length - 1);
  return RECONNECT_DELAYS_MS[index];
}

/** Percentage clamped to 0..100, or null when there is no usable limit. */
export function percentOf(
  used: number | null | undefined,
  limit: number | null | undefined,
): number | null {
  if (used === null || used === undefined || limit === null || limit === undefined) return null;
  if (!Number.isFinite(used) || !Number.isFinite(limit) || limit <= 0) return null;
  return Math.max(0, Math.min(100, (used / limit) * 100));
}

const MIB = 1024 * 1024;
const GIB = 1024 ** 3;

/** Compact human-readable size for the sidebar watcher; `—` when unknown. */
export function formatMemoryBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return "—";
  if (bytes >= GIB) return `${(bytes / GIB).toFixed(2)} GiB`;
  return `${Math.round(bytes / MIB)} MiB`;
}

export function cpuLimitCores(sample: CellMetricsSample): number | null {
  const { quota_usec: quota, period_usec: period } = sample.cpu;
  if (quota === null || period === null || period <= 0) return null;
  return quota / period;
}

export function cpuPercent(sample: CellMetricsSample): number | null {
  const limit = cpuLimitCores(sample);
  if (limit === null) return null;
  return percentOf(sample.cpu.cores, limit);
}

export function memoryPercent(sample: CellMetricsSample): number | null {
  return percentOf(sample.memory.current_bytes, sample.memory.max_bytes);
}

export type SparklinePoint = { x: number; y: number };

/**
 * Points for an SVG sparkline. `ceiling` keeps the vertical scale stable
 * (percentages are drawn against 100 %, never against the local maximum).
 */
export function sparklinePoints(
  values: readonly number[],
  width: number,
  height: number,
  ceiling = 100,
): SparklinePoint[] {
  if (values.length === 0 || width <= 0 || height <= 0) return [];
  const max = Math.max(ceiling, ...values, 1);
  const step = values.length === 1 ? 0 : width / (values.length - 1);
  return values.map((value, index) => {
    const clamped = Math.max(0, Math.min(value, max));
    return {
      x: index * step,
      y: height - (clamped / max) * height,
    };
  });
}

function roundCoordinate(value: number): string {
  return String(Math.round(value * 100) / 100);
}

export function sparklinePath(
  values: readonly number[],
  width: number,
  height: number,
  ceiling = 100,
): string {
  const points = sparklinePoints(values, width, height, ceiling);
  return points
    .map((point, index) => `${index === 0 ? "M" : "L"}${roundCoordinate(point.x)},${roundCoordinate(point.y)}`)
    .join(" ");
}
