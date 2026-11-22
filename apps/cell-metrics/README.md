# spanel-cell-metrics (A.SPEC 0112)

Colector de solo lectura de métricas de una celda desde **cgroups v2**. Lee los
dos árboles de la celda, suma sus contadores de uso (RAM, CPU, PIDs, eventos e
I/O) y toma el límite más restrictivo para `memory.max`, `cpu.max` y
`pids.max`. Emite un snapshot JSON por línea. No escribe cgroups, no abre red y
no ejecuta comandos externos.

## Build

Requiere Rust y no tiene dependencias externas de Cargo:

```bash
cd apps/cell-metrics
cargo build --release
```

## Run

```bash
./target/release/spanel-cell-metrics --slug demo --uid 60070 --once --json
./target/release/spanel-cell-metrics --slug demo --uid 60070 --watch --interval-ms 1000 --json
```

- `--once` hace un warmup corto de 250 ms y emite un snapshot con CPU/I/O reales.
- `--watch` emite una línea por intervalo hasta `SIGINT`; la primera línea es
  warmup y las siguientes ya traen CPU/I/O reales.
- `--interval-ms` acepta 250–60000 (defecto 1000).
- `--cgroup-root` existe solo para tests con un árbol falso.

El script `scripts/cell_metrics_cli.py` resuelve el uid desde
`/var/lib/spanel/registry.json`, localiza este binario y dibuja la tabla.

## JSON por línea

```json
{
  "ts_ms": 1795314600000,
  "slug": "demo",
  "uid": 60070,
  "interval_ms": 1000,
  "warmup": false,
  "memory": { "current_bytes": 1524629504, "peak_bytes": 1729629504, "max_bytes": 2147483648, "oom_kill": 0 },
  "cpu": { "usage_usec": 123456789, "cores": 0.62, "quota_usec": 100000, "period_usec": 100000, "nr_throttled": 0 },
  "pids": { "current": 118, "max": 256 },
  "pressure": {
    "cpu": { "some_avg10": 3.1, "full_avg10": 0.0 },
    "memory": { "some_avg10": 0.4, "full_avg10": 0.0 },
    "io": { "some_avg10": 0.0, "full_avg10": 0.0 }
  },
  "io": { "read_bytes": 12345678, "write_bytes": 87654321, "read_bytes_per_s": 1200.5, "write_bytes_per_s": 3400.0 }
}
```

`null` significa ausente o sin límite. Un snapshot `--once` ya hizo warmup, así
que `warmup` es `false` y `cpu.cores`/rates son reales. En `--watch` la primera
línea es warmup (`cpu.cores: 0.0`, rates `null`).
