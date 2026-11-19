# A.SPEC 0108 — Apply RAM limits in place and add dry-run sequential migration

> `risk: high` — toca el host, systemd/cgroups y la frontera de privilegios; exige
> `approver:` humano. Rollback por `reset-property` y bandera; blast radius multi-tenant.

## WHY

Hoy el plan de RAM **no se puede aplicar**: el materializador (A.SPEC 0100–0103)
reparenta `user@<uid>.service` al slice del tenant y eso rompe `runc` (GAP‑1,
`artifacts/0105-gap1-rootless-detection-experiment.json`). Sin arreglo, cualquier
migración a rootless dejaría el contenedor muerto con `EPERM`. Además no hay forma de
previsualizar la provisión ni de migrar en lotes con seguridad.

### Analogía (lenguaje sencillo)

Imagina el servidor como un **edificio de apartamentos**:

- Cada tenant es un **apartamento** (su userspace), con su propio **dueño** (un uid) y
  su propio **portero automático** (el daemon Docker rootless), que mete y saca muebles
  (contenedores).
- El admin del edificio (PanelTutor Core) pone los **medidores de agua y luz** (RAM y CPU).
- El problema actual: para poner el límite, se **muda el medidor a un sótano nuevo**
  (reparentar al slice del tenant). Al hacerlo desaparece la **placa del dueño**
  (`OwnerUID`). El cerrajero (`runc`) ya no reconoce el apartamento, va a la puerta
  principal del edificio (`/run/systemd/private`), que está cerrada con llave, y recibe
  **EPERM**. Resultado: el contenedor no arranca.
- La solución: **no muevas nada**. Deja el apartamento donde está y gira la **perilla del
  medidor que ya existe** (`systemctl set-property`). La placa sigue visible, el
  cerrajero abre la puerta y el contenedor arranca con su límite. Es cambiar el caudal
  sin desarmar la tubería.
- No basta con que el medidor *diga* 512 MB: hay que **abrir el grifo y medir el agua que
  sale de verdad** (cgroups v2 con carga real).
- `--dry-run` es el **presupuesto antes de la obra**: muestra uid, subuids, slice,
  AppArmor, socket y límites, pero no toca nada.
- `migrate --all` es una **mudanza por turnos**: uno a la vez, con vista previa, sin
  tocar los servicios del edificio (Core) y parando en seco si algo falla.
- Esta spec es el **vuelo de prueba**: si el cerrajero no entra con los límites puestos,
  no se muda ninguna app ni ningún WordPress (0109/0110 siguen bloqueados).

## WHAT

**El plan de RAM de un tenant se aplica sobre la unidad existente (`set-property`, sin
reparentar), con `OwnerUID` conservado y cuotas demostradas en cgroups v2 bajo carga
real; la provisión y la migración tienen vista previa y la migración es secuencial,
excluye Core y se detiene ante el primer fallo. Sin esto no se migran apps ni sitios.**

## SCOPE

### 1. Materialización en el lugar (sin reparentar)

- `scripts/tenant_cell/materializer.py`: `apply()` deja de instalar
  `tenant-<slug>.slice` y el drop-in que reparenta `user@<uid>.service`. En su lugar
  ejecuta `systemctl set-property user@<uid>.service MemoryMax=… CPUQuota=… TasksMax=…`
  sobre la unidad en su slice por defecto (`user-<uid>.slice`). Idempotente.
- `remove()` usa `systemctl reset-property` para devolver los valores por defecto; no
  elimina slices ni drop-in nuevos (los antiguos, si existen de specs previas, se
  limpian en reconciliación sin reparentar).
- `show()`/`verify()`/`reconcile()` reportan el slice efectivo, las properties y el
  `OwnerUID` observado.
- `scripts/tenant_cell/plans.py`: helpers para construir los argumentos de
  `set-property`, mapear a rutas cgroups v2 (`memory.max`, `cpu.max`, `pids.max`) y
  leer el estado efectivo. La validación actual (`validate_plan`) y `PLAN_KEYS` se
  conservan (`memory`, `cpus`, `pids`, `cpuset`).

### 2. Comandos CLI nuevos / modificados (`scripts/tenant_cell/cli.py`)

Interfaz real (Typer, prefijo `spanel-tenant`):

```text
# Vista previa de provisión: NO crea usuario, slice, socket ni escribe registry
spanel-tenant provision --slug <slug> --dry-run [--json] [--data-root <path>]

# Aplica el plan EN EL LUGAR (set-property), sin reparentar ni reiniciar el manager
spanel-tenant plan apply --slug <slug> --memory <size> --cpus <n> --pids <n> [--dry-run] [--json] [--data-root <path>]

# Prueba real con carga: cgroups v2 efectivos + OwnerUID + sin EPERM
spanel-tenant plan probe --slug <slug> [--memory-mb <n>] [--seconds <n>] [--json] [--data-root <path>]

# Migración secuencial de recursos del tenant a rootless
spanel-tenant migrate --all \
    [--dry-run] \
    [--only static|wordpress|app] \
    [--exclude <resource-id>] \
    [--stop-on-failure/--continue-on-failure] \
    [--json] [--data-root <path>]
```

Comportamiento de cada uno:

- `provision --dry-run`: imprime `{uid, subuid_range, subgid_range, slice, apparmor_profile,
  docker_socket, limits, mutation: false, would_create: [...]}`. No llama a
  `CellService.provision`, no escribe en `/var/lib/spanel/registry.json`, no crea unidades.
  Sin `--dry-run`, el comportamiento actual no cambia.
- `plan apply`: reemplaza la acción reparentante de `plan set`. `plan set` queda como
  alias que delega en `plan apply` (misma bandera de mutación
  `SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS=1`). Con `--dry-run`, imprime las properties que
  se aplicarían sin ejecutar `systemctl`.
- `plan probe`: ejecuta una carga controlada dentro de un contenedor rootless desechable,
  lee `memory.max`/`cpu.max`/`pids.max` del cgroup v2, verifica que `busctl --user status`
  conserva `OwnerUID`, y que no aparece `EPERM` en logs. Salida `ok: bool` + mediciones;
  `exit code 1` si falla. **No** instala ni modifica nada permanente.
- `migrate --all`: exclusivo con `--slug`/`--driver` (la migrate actual de driver de
  cgroups queda intacta). Orden fijo **estático → wordpress → app**, usando el runtime
  registrado por 0107 (`set_runtime` solo tras verificación correcta). Omite explícitamente
  la infraestructura Core (Traefik, MariaDB compartida, phpMyAdmin, PowerDNS, Docker
  Mailserver) por denylist de nombres y por etiqueta `core`. Por defecto
  `--stop-on-failure`: al primer fallo restaura rutas y runtime, reporta y para. Requiere
  `SPANEL_TENANTS_ROOTLESS=true` para aplicar; con `false` solo permite `--dry-run`.
  La bandera **nunca** cambia el runtime de recursos ya migrados (corrección 2).

### 3. Frontera de privilegios

- `scripts/tenant_cell/host_agent.py`: ampliar `PLAN_KEYS` con las operaciones nuevas
  (`apply_in_place`, `probe`, `migrate_all`) manteniendo HMAC sobre UDS, `SO_PEERCRED` y
  el gate `SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS=1` **solo en el proceso host**. Sin
  dry-run silencioso que escriba en disco ni llame a systemd.

### 4. Pruebas y evidencia

- `scripts/tests/test_tenant_cell_plan.py` (existente): extender con render de
  `set-property`, idempotencia, `reset-property`, y `--dry-run` sin mutación.
- `scripts/tests/test_tenant_cell_plan_probe.py`, `scripts/tests/test_tenant_cell_migrate.py`
  (nuevos): verificación de cgroups v2 simulada, orden secuencial, exclusión Core,
  `stop-on-failure`, persistencia de runtime y bandera.
- Artefacto E2E black-box en laboratorio: `artifacts/0108-rootless-userspace-ram-dry-run-e2e.json`.

## OUT OF SCOPE

- Reparentar `user@<uid>.service` a `tenant-<slug>.slice` ni instalar drop-in que lo haga.
- GPU/VRAM/`device_requests` (la corrección fue RAM, no VRAM).
- Migrar apps o sitios de verdad (0109/0110); cambiar el runtime de recursos ya migrados;
  inventario/UI de 0107; AppArmor, seccomp, relay, Traefik ni certificados.
- Tocar `vendor/systutor-core/**`, `apps/web/**`, `scripts/phpmyadmin_up.sh`, PowerDNS,
  Traefik, Docker Mailserver ni su hardening; DNS, certificados ni correo.
- Cambiar permisos RBAC de planes ni el 503 fail-closed de la API de planes.
- Eliminar contenedores o volúmenes rootful existentes; tocar producción.

## CONTRACT

**Precondiciones:** host con cgroups v2, systemd y `runc` del laboratorio; gate
`SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS=1` solo en el agente host; celda aprovisionada;
plan válido (`memory`, `cpus`, `pids`).

**Postcondiciones:**

1. Tras `plan apply`, `systemctl show user@<uid>.service` expone `MemoryMax`, `CPUQuota`
   y `TasksMax` con los valores pedidos, y `Slice=user-<uid>.slice` (sin reparentar).
2. `busctl --user --no-pager status` sigue mostrando `OwnerUID=<uid>` antes y después.
3. Un contenedor rootless arranca con los límites aplicados; `plan probe` devuelve
   `ok: true` con lecturas reales de `memory.max`/`cpu.max`/`pids.max` y sin `EPERM`.
4. `provision --dry-run` y `plan apply --dry-run` no escriben en disco, no crean
   unidades ni llaman a systemd; el registry queda byte-idéntico.
5. `migrate --all --dry-run` imprime el orden estático→wordpress→app, omite Core y no
   cambia ningún runtime; sin `--dry-run`, aplica secuencialmente y persiste el runtime
   solo tras verificación, parando y revirtiendo ante el primer fallo.
6. Con `SPANEL_TENANTS_ROOTLESS=false`, un recurso ya markado `rootless` sigue
   resolviéndose como `rootless` (0107) y `migrate --all` no aplica cambios.
7. `plan remove` / `reset-property` devuelve el sistema al estado anterior sin borrar
   datos de la celda ni contenedores.

## INVARIANTS

```yaml
invariants:
  - "Nunca se reparenta user@<uid>.service: Slice sigue siendo user-<uid>.slice."
  - "OwnerUID permanece visible en busctl --user status antes y despues de aplicar el plan."
  - "Los limites se aplican con systemctl set-property sobre la unidad existente, nunca creando tenant-<slug>.slice ni drop-in nuevos."
  - "Ningun contenedor rootless muere con EPERM ni cae al bus root /run/systemd/private."
  - "Los limites efectivos se demuestran en cgroups v2 con carga real, no solo por configuracion escrita."
  - "dry-run no muta: cero escrituras en registry, cero unidades systemd, cero properties."
  - "SPANEL_TENANTS_ROOTLESS=false no reescribe el runtime de recursos ya migrados ( verdad de 0107 )."
  - "migrate --all es secuencial, excluye Core y para ante el primer fallo restaurando rutas y runtime."
  - "Traefik, MariaDB compartida, phpMyAdmin, PowerDNS y Docker Mailserver permanecen en Core, sin cambios de config ni PID."
  - "El gate de mutacion vive solo en el proceso host; el backend no gana privilegios."
  - "El 503 fail-closed de la API de planes no cambia."
  - "No se eliminan contenedores ni volumenes rootful existentes; sin produccion."
```

## VERIFICATION

```bash
# Logica del host y del plan (a ejecutar cuando se implemente; NO ejecutado en esta entrega)
python3 -m pytest scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_plan_probe.py scripts/tests/test_tenant_cell_migrate.py -q
ruff check scripts/tenant_cell/materializer.py scripts/tenant_cell/plans.py scripts/tenant_cell/host_agent.py scripts/tenant_cell/cli.py scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_plan_probe.py scripts/tests/test_tenant_cell_migrate.py

# Smoking de CLI: dry-run no debe mutar (se ejecuta en el host de pruebas)
spanel-tenant provision --slug cell-e2e-0108 --dry-run --json
spanel-tenant plan apply --slug cell-e2e-0108 --memory 256M --cpus 0.5 --pids 128 --dry-run --json
spanel-tenant migrate --all --dry-run --json
```

E2E black-box (fase laboratorio): `artifacts/0108-rootless-userspace-ram-dry-run-e2e.json`
debe mostrar, sobre una celda desechable: `Slice=user-<uid>.slice`, `OwnerUID` antes y
después, `MemoryMax`/`CPUQuota`/`TasksMax` efectivos en cgroups v2 bajo carga, contenedor
rootless `rc=0` sin `EPERM`, registry byte-idéntico tras los tres `--dry-run`, orden
`static→wordpress→app` con Core excluido y parada ante fallo simulado, y PID/hashes del
Core sin cambios. Rollback demostrado con `reset-property` y `SPANEL_TENANTS_ROOTLESS=false`.

## ROLLBACK

- `plan remove` / `systemctl reset-property user@<uid>.service` restaura los valores por
  defecto; no se borran datos ni contenedores.
- Sin esquema nuevo: no hay downgrade de migración en esta spec (la migración 004 es de
  0107 y no se toca).
- `migrate --all` revierte `set_runtime` y rutas del recurso que falló y se detiene; los
  recursos migrados antes conservan su runtime registrado (corrección 2).
- Bandera `SPANEL_TENANTS_ROOTLESS=false` bloquea nuevas migraciones sin afectar a las
  ya realizadas.

## Change Surface

```yaml
change_surface:
  allowed:
    - scripts/tenant_cell/materializer.py
    - scripts/tenant_cell/plans.py
    - scripts/tenant_cell/host_agent.py
    - scripts/tenant_cell/cli.py
    - scripts/tests/test_tenant_cell_plan.py
    - scripts/tests/test_tenant_cell_plan_probe.py
    - scripts/tests/test_tenant_cell_migrate.py
    - artifacts/0108-rootless-userspace-ram-dry-run-e2e.json
  prohibited:
    - scripts/tenant_cell/cells.py
    - scripts/tenant_cell/executor.py
    - scripts/tenant_cell/apparmor.py
    - scripts/tenant_cell/network.py
    - scripts/tenant_cell/relay.py
    - scripts/tenant_cell/deploy/**
    - vendor/systutor-core/**
    - apps/web/**
    - scripts/phpmyadmin_up.sh
    - scripts/powerdns-lab.sh
    - scripts/traefik-lab.sh
    - docker-compose.yml
    - /opt/stacks/**
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - materializacion del plan de tenant (set-property en vez de reparentar)
    - comandos CLI provision/plan/migrate
    - protocolo UDS del agente host
  indirect:
    - arranque de contenedores rootless
    - futuras migraciones 0109/0110
  must_not_affect:
    - OwnerUID y la deteccion rootless de runc
    - inventario y runtime registrado por 0107
    - AppArmor, seccomp, relay y rutas publicadas
    - Traefik, MariaDB compartida, phpMyAdmin, PowerDNS, Docker Mailserver
    - contenedores y volumenes rootful existentes
    - produccion
```

## Composition

```yaml
composition:
  requires_aspecs:
    - "0100-apps-tenant-resource-plan"
    - "0107-tenant-resource-runtime-and-inventory"
  must_compose_with:
    - "0109-apps-rootless-daemon"
    - "0110-hosting-rootless-phpmyadmin"
  systemic_invariants:
    - "PanelTutor Core conserva su capacidad privilegiada de administracion."
    - "El runtime persistido manda sobre la bandera global."
    - "Ninguna migacion toca la infraestructura Core."
  composition_checks:
    - "python3 -m pytest scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_plan_probe.py scripts/tests/test_tenant_cell_migrate.py -q"
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: one coherent responsibility and one main reason to change
  entrypoints_must_stay_thin: true
  review_threshold_lines: 500
  extraction_threshold_lines: 800
  preferred_new_logic_locations:
    - scripts/tenant_cell/materializer.py
    - scripts/tenant_cell/plans.py
```

## Traceability

- Requirement: corrección 1 (GAP‑1: set-property sin reparentar, OwnerUID, cgroups v2 con
  carga real, compuerta para 0109/0110) y corrección 2 (`migrate --all` secuencial,
  `dry-run`, exclusión Core, parada ante fallos).
- owner: lucas
- approver: lucas
- Commit: `5d88462` (implementación, reparación de gaps, spec, plan y artefacto E2E).
- Evidence: `artifacts/0108-rootless-userspace-ram-dry-run-e2e.json` (PASS 8/8, 0 gaps;
  OwnerUID y slice preservados, cgroups v2 efectivos bajo carga vía CLI `plan probe`,
  contenedor rootless sin EPERM, dry-run sin mutación, `spanel-mail` excluido, rollback con
  `systemctl revert` y Core intacto).
- Deployment: laboratorio `spanel.lab` (BD clonada desechable); sin producción.

## Definition of Done

- [x] Objective satisfied
- [x] Scope respected
- [x] Contract satisfied
- [x] Independent falsable truth exists now
- [x] Invariants preserved
- [x] Verification passed
- [x] Rollback / compensation is honest (`systemctl revert` demostrado en laboratorio)
- [x] Composition checks passed when applicable
- [x] No unrelated changes
- [x] Structural constraints respected
- [x] Traceability established
- [x] E2E black-box de RAM real, OwnerUID y migración secuencial ejecutado en laboratorio
