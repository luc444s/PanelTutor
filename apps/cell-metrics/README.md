# spanel-cell-metrics (A.SPEC 0112 / 0113)

Colector de solo lectura de métricas de una celda desde **cgroups v2**. Lee los
dos árboles de la celda, suma sus contadores de uso (RAM, CPU, PIDs, eventos e
I/O) y toma el límite más restrictivo para `memory.max`, `cpu.max` y
`pids.max`. Emite un snapshot JSON por línea. No escribe cgroups, no abre red y
no ejecuta comandos externos.

Desde A.SPEC 0113 el mismo binario tiene un modo **daemon** (`--serve`) que
escucha en un socket Unix (`AF_UNIX`, nunca TCP), autentica por token y
`SO_PEERCRED`, y sirve el mismo JSON por petición. El CLI de 0112 sigue igual.


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

En el host, `scripts/install_cell_metrics.py` automatiza la compilación, el
token persistente en `/etc/spanel/cell_metrics_token`, la unidad systemd y la
verificación `PING`/`SNAPSHOT`:

```bash
python3 scripts/install_cell_metrics.py --check
python3 scripts/install_cell_metrics.py --slug demo
```

## Modo daemon (`--serve`)

```bash
sudo install -m 0750 target/release/spanel-cell-metrics /usr/local/bin/spanel-cell-metrics
sudo install -d -m 0755 /run/spanel
sudo install -d -m 0755 /etc/spanel
sudo install -m 0600 /dev/null /etc/spanel/cell_metrics_token
# escribe un token de una sola palabra, sin espacios ni saltos internos
sudo systemctl enable --now spanel-cell-metrics.service
```

```bash
spanel-cell-metrics --serve \
  --socket /run/spanel/cell-metrics.sock \
  --token-file /etc/spanel/cell_metrics_token \
  --allowed-uids 0 \
  [--cgroup-root /sys/fs/cgroup] \
  [--passwd /etc/passwd]
```

Garantías del daemon:

- escucha **solo** en `AF_UNIX`; no hay ningún puerto TCP;
- crea el socket con modo `0600` y elimina un socket huérfano al arrancar (un
  fichero normal con esa ruta nunca se borra);
- `--allowed-uids` es una lista separada por comas de uids de peer permitidos
  vía `SO_PEERCRED` (defecto `0`);
- `--token-file` es un fichero de solo lectura con un token de una palabra; se
  lee al arrancar y se compara en tiempo constante;
- el uid de la celda se resuelve leyendo `<passwd>` y buscando
  `spanel-<slug>`; no se parsea `registry.json`;
- `slug`, `interval_ms` (250–60000), token y uid se validan **antes** de abrir
  cualquier cgroup;
- cada conexión tiene su propio `Sampler`; no se comparte estado;
- solo lectura: no escribe cgroups, no abre red y no ejecuta comandos.

### Protocolo por líneas

```text
SUBSCRIBE <slug> <interval_ms> <token>\n
SNAPSHOT <slug> <token>\n
PING\n
```

- `SUBSCRIBE`: una línea JSON por intervalo hasta que el cliente cierre.
- `SNAPSHOT`: un warmup de 250 ms, una línea JSON y cierre.
- `PING`: `{"ok":true,"pong":true}\n`.
- Error: `ERROR <code> <message>\n` y cierre. Códigos: `unauthorized`,
  `peer_denied`, `invalid_slug`, `invalid_interval`, `unknown_user`,
  `unavailable`, `sampling_failed`, `invalid_request`.

El JSON es exactamente el de la sección siguiente. Ejemplo con `socat`:

```bash
printf 'SNAPSHOT demo %s\n' "$(sudo cat /etc/spanel/cell_metrics_token)" \
  | socat - UNIX-CONNECT:/run/spanel/cell-metrics.sock
```

La unidad de referencia `spanel-cell-metrics.service` aplica
`ProtectSystem=strict`, `ProtectControlGroups=yes`,
`RestrictAddressFamilies=AF_UNIX`, `MemoryMax=64M` y `CPUQuota=10%`.


## JSON por línea

```json
{
  "ts_ms": 1795314600000,
  "slug": "demo",
  "uid": 60070,
  "interval_ms": 1000,
  "warmup": false,
  "memory": {
    "current_bytes": 1524629504,
    "peak_bytes": 1729629504,
    "max_bytes": 2147483648,
    "oom_kill": 0,
    "anon_bytes": 889192448,
    "file_bytes": 623820800,
    "kernel_bytes": 8323072,
    "slab_bytes": 3796992
  },
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

El desglose de `memory` sale de `memory.stat`: `anon_bytes + kernel_bytes` es el
consumo no reclamable de la celda, mientras que `file_bytes` es page cache
(binarios compartidos, imágenes y ficheros) que el kernel reclama bajo presión.
`slab_bytes` es un subconjunto de `kernel_bytes`. Para capacidad se debe usar
`anon_bytes + kernel_bytes`; `current_bytes` incluye la caché y sobreestima el
consumo real.
