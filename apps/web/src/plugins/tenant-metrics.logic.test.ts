import { describe, expect, it } from "vitest";

import {
  METRICS_HISTORY,
  cpuLimitCores,
  cpuPercent,
  formatMemoryBytes,
  isCellMetricsSample,
  memoryPercent,
  parseMetricsEvent,
  parseSseBlock,
  parseSseChunk,
  percentOf,
  pushSample,
  reconnectDelay,
  sparklinePath,
  sparklinePoints,
  type CellMetricsSample,
} from "./tenant-metrics.logic";

function sample(overrides: Partial<CellMetricsSample> = {}): CellMetricsSample {
  return {
    ts_ms: 1795314600000,
    slug: "demo",
    uid: 60070,
    interval_ms: 1000,
    warmup: false,
    memory: {
      current_bytes: 1024,
      peak_bytes: 2048,
      max_bytes: 4096,
      oom_kill: 0,
    },
    cpu: {
      usage_usec: 1000,
      cores: 0.5,
      quota_usec: 50000,
      period_usec: 100000,
      nr_throttled: 0,
    },
    pids: { current: 4, max: 64 },
    pressure: {
      cpu: { some_avg10: 1, full_avg10: 0 },
      memory: { some_avg10: 0.5, full_avg10: 0 },
      io: { some_avg10: 0.1, full_avg10: 0 },
    },
    io: {
      read_bytes: 10,
      write_bytes: 20,
      read_bytes_per_s: 1,
      write_bytes_per_s: 2,
    },
    ...overrides,
  };
}

describe("SSE parser", () => {
  it("keeps partial events in the buffer until the blank separator arrives", () => {
    const first = parseSseChunk("", "retry: 3000\n\ndata: {\"ts_ms\":");
    expect(first.events).toEqual([]);
    expect(first.buffer).toBe('data: {"ts_ms":');

    const second = parseSseChunk(first.buffer, "1}\n\n");
    expect(second.buffer).toBe("");
    expect(second.events).toEqual([{ event: "message", data: '{"ts_ms":1}' }]);
  });

  it("joins multiple data lines and honours the event name", () => {
    expect(parseSseBlock("event: error\ndata: {\"code\":\"x\"}")).toEqual({
      event: "error",
      data: '{"code":"x"}',
    });
    expect(parseSseBlock("data: one\ndata: two")).toEqual({
      event: "message",
      data: "one\ntwo",
    });
  });

  it("ignores comments, retry and CRLF line endings", () => {
    const parsed = parseSseChunk("", ": keepalive\r\nretry: 3000\r\ndata: {}\r\n\r\n");
    expect(parsed.events).toEqual([{ event: "message", data: "{}" }]);
    expect(parsed.buffer).toBe("");
  });

  it("returns null for a block without data", () => {
    expect(parseSseBlock("retry: 3000")).toBeNull();
    expect(parseSseBlock(": comment")).toBeNull();
  });
});

describe("sample parsing", () => {
  it("accepts a complete 0112 sample", () => {
    expect(isCellMetricsSample(sample())).toBe(true);
    expect(parseMetricsEvent({ event: "message", data: JSON.stringify(sample()) })).toEqual(
      sample(),
    );
  });

  it("rejects malformed JSON, non-objects and truncated samples", () => {
    expect(parseMetricsEvent({ event: "message", data: "not json" })).toBeNull();
    expect(parseMetricsEvent({ event: "message", data: "[]" })).toBeNull();
    expect(parseMetricsEvent({ event: "message", data: '{"ts_ms":1}' })).toBeNull();
    const broken = sample();
    delete (broken.memory as { current_bytes?: number }).current_bytes;
    expect(isCellMetricsSample(broken)).toBe(false);
  });

  it("does not treat error events as samples", () => {
    expect(
      parseMetricsEvent({
        event: "error",
        data: JSON.stringify(sample()),
      }),
    ).toBeNull();
  });
});

describe("ring buffer", () => {
  it("keeps the newest 60 samples in order", () => {
    let samples: CellMetricsSample[] = [];
    for (let index = 0; index < 65; index += 1) {
      samples = pushSample(samples, sample({ ts_ms: index }));
    }
    expect(samples).toHaveLength(METRICS_HISTORY);
    expect(samples[0].ts_ms).toBe(5);
    expect(samples[samples.length - 1].ts_ms).toBe(64);
  });

  it("does not mutate the previous array", () => {
    const base = [sample({ ts_ms: 1 })];
    const next = pushSample(base, sample({ ts_ms: 2 }));
    expect(base).toHaveLength(1);
    expect(next).toHaveLength(2);
  });
});

describe("reconnect backoff", () => {
  it("sequences 1 s, 2 s, 5 s and 10 s, then caps at 10 s", () => {
    expect([0, 1, 2, 3, 4, 9].map(reconnectDelay)).toEqual([
      1000, 2000, 5000, 10000, 10000, 10000,
    ]);
  });
});

describe("percentages", () => {
  it("clamps to 0..100 and returns null without a limit", () => {
    expect(percentOf(512, 1024)).toBe(50);
    expect(percentOf(2048, 1024)).toBe(100);
    expect(percentOf(-1, 1024)).toBe(0);
    expect(percentOf(1, null)).toBeNull();
    expect(percentOf(1, 0)).toBeNull();
  });

  it("derives the CPU limit from quota/period", () => {
    const value = sample();
    expect(cpuLimitCores(value)).toBe(0.5);
    expect(cpuPercent(value)).toBe(100);
    expect(memoryPercent(value)).toBe(25);
  });

  it("returns null when the plan has no CPU quota", () => {
    const value = sample({ cpu: { ...sample().cpu, quota_usec: null, period_usec: null } });
    expect(cpuLimitCores(value)).toBeNull();
    expect(cpuPercent(value)).toBeNull();
  });
});

describe("memory formatting", () => {
  it("renders MiB/GiB and a dash for unknown values", () => {
    expect(formatMemoryBytes(null)).toBe("—");
    expect(formatMemoryBytes(undefined)).toBe("—");
    expect(formatMemoryBytes(Number.NaN)).toBe("—");
    expect(formatMemoryBytes(128 * 1024 * 1024)).toBe("128 MiB");
    expect(formatMemoryBytes(2 * 1024 ** 3)).toBe("2.00 GiB");
  });
});

describe("sparkline", () => {
  it("returns an empty path without values", () => {
    expect(sparklinePath([], 100, 20)).toBe("");
    expect(sparklinePoints([], 100, 20)).toEqual([]);
  });

  it("draws one point per value inside the viewport", () => {
    const points = sparklinePoints([0, 50, 100], 100, 20);
    expect(points).toEqual([
      { x: 0, y: 20 },
      { x: 50, y: 10 },
      { x: 100, y: 0 },
    ]);
    expect(sparklinePath([0, 50, 100], 100, 20)).toBe("M0,20 L50,10 L100,0");
  });

  it("keeps a stable 0..100 scale for percentages", () => {
    const points = sparklinePoints([25], 100, 40);
    expect(points).toHaveLength(1);
    expect(points[0].y).toBe(30);
  });
});
