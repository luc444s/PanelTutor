# A.SPEC 0112 — Métricas vivas de una celda: colector Rust y CLI v1

> `risk: medium` — añade un binario Rust de solo lectura y un CLI que lee
> cgroups v2 del host. No muta límites, no crea servicios ni toca la UI.
> Requiere `approver:` humano y E2E en laboratorio.

## WHY

La pestaña de recursos de A.SPEC 0111 muestra la capacidad del host y el plan
declarado, pero no el consumo real. Para operar una celda hace falta ver, en
vivo y con datos reales:

- cuánta RAM está usando;
- cuántos cores está consumiendo;
- cuántos procesos/PIDs tiene;
- si hay presión o throttling;
- cuánto I/O está haciendo.

El probe de `plan verify` no sustituye a esto: solo ejecuta una carga puntual y
en el lab puede devolver `ok=false` aunque los límites estén bien aplicados. La
meta de la v1 es **simple y verificable**: un colector Rust que lee cgroups v2 y
un script Python que lo invoca y muestra los datos reales por terminal.

La UI, el socket, el SSE y Prometheus quedan para una fase posterior.

## WHAT

**Existe un binario Rust `spanel-cell-metrics` en `apps/cell-metrics/` que
muestrea una celda desde cgroups v2 y emite snapshots JSON; un script Python
`scripts/cell_metrics_cli.py` resuelve el uid del tenant, invoca el binario y
muestra una tabla legible con los datos reales, en modo `--once` o `--watch`.**

No hay daemon, ni socket, ni servicio systemd, ni endpoint HTTP, ni UI en esta
spec. El binario se ejecuta desde el CLI.

## SCOPE

### A. Colector Rust en `apps/cell-metrics/`

Proyecto Cargo independiente, **sin dependencias externas** (solo `std`):

```text
apps/cell-metrics/
  Cargo.toml
  .gitignore          # /target/
  README.md
  src/lib.rs          # parseo, muestreo y cálculo (testable)
  src/main.rs         # CLI: argumentos, JSON y watch
```

#### Argumentos

```text
spanel-cell-metrics \
  --slug <slug> \
  --uid <uid> \
  [--cgroup-root /sys/fs/cgroup] \
  [--interval-ms 1000] \
  [--once] \
  [--watch] \
  [--json]
```

- `--slug` y `--uid` son obligatorios en producción.
- `--cgroup-root` existe **solo para tests** (árbol falso); por defecto
  `/sys/fs/cgroup`.
- `--once` emite un snapshot y termina.
- `--watch` emite una línea JSON por intervalo hasta SIGINT.
- `--interval-ms` mínimo 250, máximo 60000; por defecto 1000.
- `--json` es el formato de salida; en v1 el binario **siempre** emite JSON por
  stdout (el Python es quien dibuja la tabla). El flag se acepta por claridad.

#### Cgroups que suma

Una celda rootless tiene dos árboles separados:

```text
/sys/fs/cgroup/system.slice/spanel-cell-<slug>.service
/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service
```

- Si ambos existen, se suman.
- Si uno no existe, se trata como cero.
- Si ninguno existe, el binario falla con código distinto de cero y un mensaje
  claro.
- Si una ruta es prefijo de la otra, solo se cuenta la ruta padre para no
  duplicar.
- Los **contadores de uso** se suman entre árboles; los **límites**
  (`memory.max`, `cpu.max`, `pids.max`) se toman del árbol más restrictivo. El
  slice del sistema suele estar en `max`; el plan vive en el user manager.
- La presión (`*.pressure`) se reporta como el máximo de los árboles, no como
  una suma (sumar porcentajes no tiene sentido).
- No se usan `docker stats`, `ps`, `systemd-cgtop` ni `du`.

#### Métricas

| Campo | Fuente | Cálculo |
|---|---|---|
| `memory.current_bytes` | `memory.current` | instantáneo |
| `memory.peak_bytes` | `memory.peak` | opcional; `null` si no existe |
| `memory.max_bytes` | `memory.max` | `null` si es `max` |
| `memory.oom_kill` | `memory.events` | contador acumulado |
| `cpu.usage_usec` | `cpu.stat` | acumulado |
| `cpu.cores` | `usage_usec` | delta / tiempo transcurrido / 1e6 |
| `cpu.quota_usec` / `cpu.period_usec` | `cpu.max` | `null` si es `max` |
| `cpu.nr_throttled` | `cpu.stat` | acumulado |
| `pids.current` / `pids.max` | `pids.current` / `pids.max` | instantáneo |
| `pressure.*.some_avg10` | `*.pressure` | `some avg10` |
| `pressure.*.full_avg10` | `*.pressure` | `full avg10` |
| `io.read_bytes` / `io.write_bytes` | `io.stat` | suma de dispositivos, acumulado |
| `io.read_bytes_per_s` / `write_bytes_per_s` | `io.stat` | delta / tiempo; `null` en el primer sample |

- En `--watch`, el primer snapshot emitido tiene `cpu.cores=0.0` y
  `warmup=true`, y los rates de I/O son `null`; los siguientes son reales.
- En `--once` se toma un warmup interno de 250 ms y se emite directamente el
  snapshot real (`warmup=false`).
- Los contadores son acumulados; el consumidor calcula lo que quiera con ellos.
- No se lee ni se escribe ningún otro fichero del sistema.
- La memoria no se guarda en disco; el proceso solo mantiene el sample anterior.

#### Salida JSON

Una línea por snapshot:

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
    "oom_kill": 0
  },
  "cpu": {
    "usage_usec": 123456789,
    "cores": 0.62,
    "quota_usec": 100000,
    "period_usec": 100000,
    "nr_throttled": 0
  },
  "pids": { "current": 118, "max": 256 },
  "pressure": {
    "cpu": { "some_avg10": 3.1, "full_avg10": 0.0 },
    "memory": { "some_avg10": 0.4, "full_avg10": 0.0 },
    "io": { "some_avg10": 0.0, "full_avg10": 0.0 }
  },
  "io": {
    "read_bytes": 12345678,
    "write_bytes": 87654321,
    "read_bytes_per_s": 1200.5,
    "write_bytes_per_s": 3400.0
  }
}
```

- `ts_ms` es epoch en milisegundos, del reloj del sistema.
- Los números son JSON válidos; `null` para ausentes.
- `slug` se valida (minúsculas, dígitos y guiones) antes de construir rutas.
- El binario no imprime logs en stdout; los errores van a stderr.

#### Seguridad y límites

- Solo lectura: no abre ficheros en modo escritura ni llama a systemd.
- No recibe rutas arbitrarias en producción: `--cgroup-root` es de test.
- No abre red.
- No ejecuta comandos.
- No sigue symlinks fuera del cgroup root.
- Límite de memoria del propio proceso: sin buffers crecientes; un sample
  anterior y una línea JSON.
- En v1 se ejecuta manualmente; no hay unidad systemd ni socket.

### B. CLI Python `scripts/cell_metrics_cli.py`

- Resuelve el `uid` desde `/var/lib/spanel/registry.json`:

  ```python
  allocations[slug]["uid"]
  ```

  Si el slug no existe, termina con error claro.
- Localiza el binario:
  1. `--bin <path>`;
  2. `SPANEL_CELL_METRICS_BIN`;
  3. `apps/cell-metrics/target/release/spanel-cell-metrics`;
  4. `apps/cell-metrics/target/debug/spanel-cell-metrics`.
- Invoca el binario:
  - `--once --json` para un snapshot;
  - `--watch --json --interval-ms N` para el modo vivo.
- Modos:
  - `--once`: imprime una tabla y termina.
  - `--watch` (por defecto): limpia pantalla y redibuja cada intervalo.
  - `--json`: imprime las líneas JSON crudas, sin tabla.
  - `--no-clear`: no usa secuencias ANSI (para tests/logs).
  - `--interval-ms`: se pasa al binario.
  - `--data-root`: por defecto `/var/lib/spanel`.
- Formato de tabla (ejemplo):

```text
Cell demo · uid 60070 · 2026-11-22 03:30:00Z · intervalo 1.0s

  RAM        1,42 GiB / 2,00 GiB    71 %   pico 1,61 GiB
  CPU        0,62 cores / 1,00      62 %   throttled 0
  PIDs       118 / 256
  Presión    CPU 3,1 % · RAM 0,4 % · IO 0,0 %
  I/O        lectura 1,2 MB/s · escritura 3,4 MB/s

  Ctrl-C para salir.
```

- Si el binario no existe, sugiere `cd apps/cell-metrics && cargo build
  --release`.
- Si el binario falla, propaga stderr y el código de salida.
- No usa dependencias fuera de la biblioteca estándar de Python.

### C. Pruebas

- Rust:
  - parseo de `memory.current`, `memory.max`, `cpu.stat`, `cpu.max`,
    `pids.current`, `memory.events`, `*.pressure` e `io.stat` con un árbol
    cgroup falso en un directorio temporal;
  - suma de los dos árboles y deduplicación por prefijo;
  - cálculo puro de cores y rates;
  - slug inválido y ausencia de cgroups → error;
  - primer sample → `warmup=true`.
- Python:
  - `resolve_uid` con un `registry.json` temporal;
  - render de un snapshot JSON a tabla (sin binario real);
  - `--once --json` con un binario falso que emite una línea;
  - binario ausente → error con instrucción de build.
- E2E de laboratorio:
  - `sudo python3 scripts/cell_metrics_cli.py --slug demo --once` sobre la
    celda `demo` del lab, con datos reales;
  - `--once --json` guardado en
    `artifacts/0112-cell-metrics-cli-e2e.json`;
  - `--watch` durante 3–5 segundos, verificando que los valores cambian y no
    hay crash.

## OUT OF SCOPE

- Daemon, Unix socket, token HMAC, `SO_PEERCRED` o servicio systemd.
- SSE, WebSocket, API HTTP, UI o gráficas.
- Prometheus, Grafana, histórico, alertas o retención.
- eBPF, perf, ftrace o lectura de `/proc/<pid>` para atribución por proceso.
- Medición de espacio ocupado en disco (`du`), cuotas o `io.stat` como
  “almacenamiento usado”.
- Aplicar o verificar límites; eso sigue siendo del plan agent.
- Cambiar `scripts/tenant_cell/host_agent.py`, la API de planes, la UI o la DB.
- Dependencias externas de Cargo o de Python.
- Tocar contenedores, Traefik, MariaDB, phpMyAdmin, PowerDNS, Mailserver o
  producción.

## CONTRACT

**Precondiciones**:

- host Linux con cgroups v2 (`/sys/fs/cgroup/cgroup.controllers`);
- celda existente en `/var/lib/spanel/registry.json` con `slug` y `uid`;
- binario Rust compilado;
- permisos de lectura sobre los ficheros cgroup de la celda (root o usuario
  con lectura).

**Postcondiciones**:

1. `spanel-cell-metrics --slug demo --uid 60070 --once --json` hace un warmup
   corto de 250 ms y emite un JSON con RAM, CPU, PIDs, presión e I/O reales, y
   termina con código 0.
2. `--watch --interval-ms 1000` emite una línea por segundo, con deltas de CPU
   e I/O correctos y sin crecimiento de memoria.
3. `scripts/cell_metrics_cli.py --slug demo --once` muestra la tabla con los
   datos del binario; `--json` imprime el JSON crudo.
4. `scripts/cell_metrics_cli.py --slug demo` redibuja en vivo y termina limpio
   con Ctrl-C.
5. Un slug inexistente o un cgroup ausente produce un error claro y código
   distinto de cero.
6. No se escribe ningún fichero, no se abre red y no se llama a systemd.

## INVARIANTS

```yaml
invariants:
  - "El colector es de solo lectura: no escribe cgroups, ficheros ni estado."
  - "No hay daemon, socket, HTTP, SSE, UI ni servicio systemd en esta spec."
  - "No se usan dependencias externas de Cargo ni de Python."
  - "No se usan docker stats, ps, systemd-cgtop, du ni comandos externos."
  - "Solo se leen rutas bajo el cgroup root; --cgroup-root es exclusivo de tests."
  - "Se suman los contadores de uso de los dos árboles sin duplicar prefijos; los límites se toman del árbol más restrictivo y la presión es el máximo."
  - "CPU e I/O se calculan con deltas y reloj monótono; --once precalienta 250 ms y --watch emite la primera línea como warmup."
  - "Un slug inválido no se interpola en rutas."
  - "El plan agent y la API de planes no cambian."
  - "No se toca Core ni producción."
```

## VERIFICATION

```bash
# Rust
cd apps/cell-metrics
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test

# Python
cd ../..
PYTHONPATH=vendor/systutor-core:. python3 -m pytest scripts/tests/test_cell_metrics_cli.py -q
python3 scripts/cell_metrics_cli.py --help

# Laboratorio (celda demo)
sudo python3 scripts/cell_metrics_cli.py --slug demo --once
sudo python3 scripts/cell_metrics_cli.py --slug demo --once --json
sudo timeout 5 python3 scripts/cell_metrics_cli.py --slug demo --interval-ms 1000 --no-clear
```

El E2E de laboratorio se guarda en
`artifacts/0112-cell-metrics-cli-e2e.json` con el JSON real de `--once`, el
resultado de `--watch` y la comparación de dos muestras consecutivas.

## ROLLBACK

- Borrar `apps/cell-metrics/` y `scripts/cell_metrics_cli.py` elimina la
  funcionalidad; no hay esquema, estado, servicio ni socket que deshacer.
- No se altera ningún límite, contenedor ni dato de tenant.
- Si se añadió una entrada a `.gitignore`, revertirla es inocuo.

## Change Surface

```yaml
change_surface:
  allowed:
    - apps/cell-metrics/Cargo.toml
    - apps/cell-metrics/Cargo.lock
    - apps/cell-metrics/.gitignore
    - apps/cell-metrics/README.md
    - apps/cell-metrics/src/lib.rs
    - apps/cell-metrics/src/main.rs
    - scripts/cell_metrics_cli.py
    - scripts/tests/test_cell_metrics_cli.py
    - aspecs/0112-live-cell-metrics-cli-rust-agent.md
    - artifacts/0112-cell-metrics-cli-e2e.json
  prohibited:
    - scripts/tenant_cell/**
    - vendor/systutor-core/plugins/apps/backend/**
    - vendor/systutor-core/plugins/tenant/frontend/**
    - apps/web/**
    - docker-compose.yml
    - scripts/phpmyadmin_up.sh
    - scripts/traefik-lab.sh
    - scripts/powerdns-lab.sh
    - /etc/systemd/**
    - /etc/fstab
    - /opt/stacks/**
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - nuevo binario Rust local
    - nuevo CLI Python
  indirect:
    - futura spec de daemon/SSE/UI
  must_not_affect:
    - plan agent y API de planes
    - límites cgroup aplicados
    - contenedores y datos de tenants
    - Traefik, MariaDB, phpMyAdmin, PowerDNS, Mailserver
    - producción
```

## Composition

```yaml
composition:
  requires_aspecs:
    - "0108-rootless-userspace-ram-dry-run"
    - "0111-tenant-resource-plan-ui-and-capacity"
  must_compose_with:
    - "0109-apps-rootless-sandbox"
  systemic_invariants:
    - "El plan agent sigue siendo el único que muta límites."
    - "El colector de métricas no gana privilegios de escritura."
    - "La medición es de cgroups v2, no de Docker ni de /proc."
  composition_checks:
    - "cd apps/cell-metrics && cargo test"
    - "PYTHONPATH=vendor/systutor-core:. python3 -m pytest scripts/tests/test_cell_metrics_cli.py -q"
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: una responsabilidad coherente y una razón principal de cambio
  entrypoints_must_stay_thin: true
  review_threshold_lines: 500
  extraction_threshold_lines: 800
  preferred_new_logic_locations:
    - apps/cell-metrics/src/lib.rs
    - scripts/cell_metrics_cli.py
```

## Traceability

- Requirement: ver en vivo RAM, CPU, PIDs, presión e I/O reales de una celda;
  v1 CLI-first, agente Rust en `apps/`, script Python que lo invoca.
- owner: lucas
- approver: lucas
- Evidence: `artifacts/0112-cell-metrics-cli-e2e.json` (pendiente de la
  implementación y ceremonia en laboratorio).
- Deployment: laboratorio `spanel.lab`; sin producción.

## Definition of Done

- [ ] Objetivo satisfecho
- [ ] Scope respetado
- [ ] Contrato satisfecho
- [ ] Verdad falsable e independiente disponible ahora (lecturas reales de cgroups)
- [ ] Invariantes preservados
- [ ] Verificación Rust/Python ejecutada
- [ ] Rollback honesto (borrado de binario/script, sin estado)
- [ ] Checks de composición ejecutados
- [ ] Sin cambios no relacionados
- [ ] Restricciones estructurales respetadas
- [ ] Trazabilidad establecida
- [ ] E2E black-box en laboratorio con `--once` y `--watch`
- [ ] Core intacto
