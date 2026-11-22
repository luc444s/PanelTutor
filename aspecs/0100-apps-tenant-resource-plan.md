# A.SPEC 0100 — Aplicar plan de recursos por tenant mediante cgroups

> `risk: high` — Cambia la ubicación (`Slice=`) del user manager de una celda,
> reinicia ese daemon y afecta al presupuesto de varios contenedores. Exige
> `approver:` humano en Traceability (SPECIFICATION §4.1).

## WHY

Los límites actuales son por contenedor (`mem_limit`, `cpus`, `pids_limit` en el
override de deploy). Un tenant con WordPress + MariaDB rootful y Apps rootless
puede exceder en conjunto el RAM/vCPU contratado aunque cada contenedor
individual esté limitado.

El experimento de laboratorio registrado en
`artifacts/0100-tenant-slice-aggregate-experiment.json` demostró que un slice
personalizado (`tenant-lab.slice`, colocado por systemd bajo `tenant.slice`)
agrega límites reales de un contenedor rootful vía `--cgroup-parent` y de un user
manager rootless vía drop-in `Slice=`, sin modificar la jerarquía de `user.slice`.

## WHAT

Guardado un plan de tenant (`memory`, `cpus`, `pids`), el sistema materializa
`tenant-<slug>.slice` con esos límites y conecta el user manager de la celda a
ese slice; un comando de verificación demuestra ahora mismo que el kernel
estrangula tanto a un contenedor rootful de prueba como al subárbol rootless
bajo el mismo slice.

## SCOPE

- Persistencia atómica y validada de planes en `/var/lib/spanel/plans.json`.
- Comandos CLI `plan set|show|remove|verify`.
- Renderizado e instalación de `tenant-<slug>.slice` con `MemoryMax`, `CPUQuota`
  y `TasksMax`.
- Drop-in `Slice=tenant-<slug>.slice` en `user@<uid>.service` y reinicio
  controlado del user manager, con restauración en `plan remove`.
- Verificación del cgroup real: contenedor rootful con `--cgroup-parent` y
  subárbol rootless, con lectura de `memory.max`, `cpu.max`, `pids.max` y
  `memory.events`/`cpu.stat`.
- Registro de auditoría para toda mutación de plan.
- Tests unitarios con `Executor`/`HostProbe` falsos: ningún test escribe en un
  host real.

## OUT OF SCOPE

- Inyectar `cgroup_parent` automáticamente en el override generado por
  `vendor/systutor-core/.../runtime/deployment.py` (integración futura del host).
- Migrar WordPress, MariaDB, phpMyAdmin o sitios estáticos a rootless (opción 1).
- Modificar `vendor/systutor-core`, el daemon Docker rootful, Traefik,
  phpMyAdmin, MariaDB ni la configuración de ningún sitio.
- Mover `user.slice`, `user-60008.slice` ni la jerarquía por defecto de systemd.
- Tocar `cell-g`, `cell-h` o producción sin autorización explícita.
- Facturación/contabilidad de uso ni UI.
- Alembic en desarrollo (prohibido por AGENTS.md).

## CONTRACT

**Precondiciones**: cgroup v2, systemd con `DelegateSubgroup=init.scope` en
`user@.service`, celda existente en el registry con `cgroup_driver=systemd`,
perfil AppArmor efectivo y gate `SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS=1` para
mutaciones.

**Postcondiciones**:

- `plan show` devuelve el plan guardado y el slice efectivo.
- `tenant-<slug>.slice` existe con `MemoryMax=<memory>`, `CPUQuota=<cpus*100>%`,
  `TasksMax=<pids>` y su cgroup está bajo `/tenant.slice/`.
- El user manager de la celda tiene `Slice=tenant-<slug>.slice` y sus procesos
  (y los de sus contenedores) residen bajo ese slice.
- `plan verify` devuelve `ok=true` con evidencia de ambos lados; `ok=false` si
  el kernel no aplica los límites.
- `plan remove` borra el plan, el drop-in y el slice, y devuelve el user manager
  a `user-<uid>.slice`.

## INVARIANTS

```yaml
invariants:
  - "plan set/remove nunca cambia el cgroup_driver guardado ni debilita AppArmor en ninguna celda."
  - "Una operación de plan para el tenant A no modifica registry, unidad, slice ni perfil del tenant B."
  - "Ninguna mutación de plan ocurre sin SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS=1."
  - "Las celdas sin plan conservan user-<uid>.slice bajo user.slice y su configuración actual."
  - "No se modifica vendor/systutor-core, la configuración del daemon rootful ni los perfiles AppArmor."
  - "La propiedad y exclusividad del socket docker.sock de cada celda no cambian."
  - "memory>0, cpus>0 y pids>0 se validan antes de cualquier escritura en el host."
  - "plan remove restaura Slice=user-<uid>.slice y elimina tenant-<slug>.slice."
  - "Correr repair/provision sobre una celda con plan no revierte ni el plan ni el driver."
```

## VERIFICATION

```bash
python3 -m pytest scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_provision.py scripts/tests/test_tenant_cell_doctor.py -q
ruff check scripts/tenant_cell scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_provision.py scripts/tests/test_tenant_cell_doctor.py
python3 scripts/spanel_tenant.py plan --help
```

La prueba de kernel en laboratorio ya está registrada como evidencia ejecutada en
`artifacts/0100-tenant-slice-aggregate-experiment.json`; los tests unitarios
demuestran el renderizado, la persistencia, la validación, el no-afectado a
otras celdas y la reversión (`plan remove`) con ejecutores falsos.

## ROLLBACK

`spanel-tenant plan remove --tenant <slug>` elimina el slice, el drop-in y la
entrada del plan, reinicia el user manager para devolverlo a
`user-<uid>.slice`, y escribe la auditoría. La reversión del experimento de lab
ya se ejecutó y se verificó: usuario de prueba, contenedor, drop-in y slice
eliminados; Traefik, phpMyAdmin y MariaDB continuaron `Up`.

## Change Surface

```yaml
change_surface:
  allowed:
    - scripts/tenant_cell/plans.py
    - scripts/tenant_cell/cells.py
    - scripts/tenant_cell/cli.py
    - scripts/tenant_cell/executor.py
    - scripts/tests/test_tenant_cell_plan.py
    - scripts/tests/test_tenant_cell_provision.py
  prohibited:
    - vendor/**
    - aspecs/**
    - artifacts/**
    - /etc/**
    - /run/**
    - scripts/e2e_*.py
    - scripts/tenant_cell/apparmor.py
    - scripts/tenant_cell/doctor.py
    - scripts/tenant_cell/network.py
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - /var/lib/spanel/plans.json
    - /etc/systemd/system/tenant-<slug>.slice
    - /etc/systemd/system/user@<uid>.service.d/tenant-plan.conf
    - CLI spanel-tenant plan
  indirect:
    - reinicio del user manager de la celda al aplicar/quitar el plan
    - registro JSONL de auditoría
  must_not_affect:
    - cell-g
    - cell-h
    - celdas sin plan
    - configuración del daemon Docker rootful
    - Traefik / phpMyAdmin / MariaDB / sitios estáticos
    - perfiles AppArmor de las celdas
    - jerarquía user.slice / user-<uid>.slice
    - vendor/systutor-core
```

## Composition

```yaml
composition:
  requires_aspecs:
    - "0099-apps-rootless-systemd-cgroup-driver"
  must_compose_with:
    - "0099-apps-rootless-systemd-cgroup-driver"
  systemic_invariants:
    - "Los límites por contenedor de A.SPEC 0099 siguen aplicándose tras aplicar un plan."
    - "AppArmor sigue en enforce en el daemon y en los contenedores tras el reinicio del user manager."
  composition_checks:
    - "python3 -m pytest scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_provision.py -q"
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: one coherent responsibility and one main reason to change
  entrypoints_must_stay_thin: true
  review_threshold_lines: 400
  extraction_threshold_lines: 600
  preferred_new_logic_locations:
    - scripts/tenant_cell/plans.py
```

## Traceability

- Requirement: Objetivo 2 (fase 1 / opción 2) — plan de recursos por tenant con cgroups personalizados.
- owner: lucas
- approver: lucas
- Commit:
- Deployment: laboratorio `spanel.lab`; sin producción hasta aprobación.

## Definition of Done

- [ ] Objective satisfied
- [ ] Scope respected
- [ ] Contract satisfied
- [ ] Independent falsable truth exists now
- [ ] Invariants preserved
- [ ] Verification passed
- [ ] Rollback / compensation is honest
- [ ] Composition checks passed when applicable
- [ ] No unrelated changes
- [ ] Structural constraints respected
- [ ] Traceability established
