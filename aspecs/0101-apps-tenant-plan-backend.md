# A.SPEC 0101 — Integrar el plan de recursos por tenant en el backend de Apps

> `risk: high` — Migración de esquema en un plugin, ruta API nueva, cambio en el
> camino de deploy y migración de la CLI host. Exige `approver:` humano.

## WHY

A.SPEC 0100 entregó el plan por tenant en el host (`plans.json`, CLI
`spanel-tenant plan`, slice `tenant-<slug>.slice`) y validó en laboratorio que
agrega límites reales de contenedores rootful y rootless. Pero el backend de
Apps no conoce ese plan: el override de deploy sigue usando los defaults fijos
`mem_limit=512m`, `cpus=1.0`, `pids_limit=256` y no inyecta `cgroup_parent`.

Mientras haya dos dueños del dato (JSON del host y futuro dato de DB) habrá
divergencia. Además, el usuario aclaró que la regla "prohibido Alembic en
desarrollo" no prohíbe el **runtime migrador de systutor-core**, así que el plan
puede y debe vivir en la DB del plugin con su migración 006.

## WHAT

El plan de recursos por tenant pasa a ser un dato persistido en la DB del plugin
Apps, administrable por API y leído por el pipeline de deploy, el cual inyecta
`cgroup_parent=tenant-<slug>.slice` y límites por servicio en el override; la CLI
host deja de ser la fuente de verdad y se convierte en materializador/cliente.

## SCOPE

- Modelo `AppsTenantPlan` en `plugins/apps/backend/models.py` (tenant_id,
  memory_bytes, cpus, pids, cpuset opcional, updated_at).
- Migración `plugins/apps/migrations/006_add_tenant_resource_plans.py` con
  `revision`, `upgrade(db)` y `downgrade(db)`, ejecutada por el runtime migrador
  de systutor-core (`upgrade_plugin_migrations`). Sin CLI de Alembic.
- API nueva en `router_plans.py` (include de una línea desde `router.py`):
  alta/baja/consulta/verify del plan, con permiso **`apps.plans.manage`** en
  `plugin.json`, schemas en `schemas.py`, `Operation` y `service.audit`.
- Servicio `plans_service.py`: valida → persiste → llama a un `PlanMaterializer`
  inyectado en `AppsResources` → audita; si falla la materialización, revierte
  la transacción y audita el fallo.
- Módulo `runtime/tenant_plan.py`: política de reparto — lo declarado en el
  Compose gana; lo faltante se reparte en partes iguales entre servicios y nunca
  excede el total del plan. Sin plan, `_override` conserva los defaults actuales.
- Threading del plan: `ReleaseExecution.trusted_deploy` resuelve
  `AppsTenantPlan` por `tenant_id` y `tenant_slug(tenant_id)`, y lo pasa por
  `deploy_scoped` hasta `_override(..., plan=...)`.
- Migración de la CLI host: `scripts/tenant_cell/plans.py` se recorta (fuera
  persistencia/validación), `materializer.py` nuevo con `apply/remove/verify`
  (root/systemd), `cli.py` con comandos finos y `plan import --from plans.json`.
  `plans.json` pasa a ser caché del último estado aplicado; **sin fallback
  silencioso** a DB.
- Tests nuevos y adaptados en ambos lados (plugin y host).
- `AGENTS.md` con la aclaración de migraciones ya redactada se incluye en este
  cambio.

## OUT OF SCOPE

- Conectar apps aisladas con el Traefik padre (próxima A.SPEC).
- Aplicar `cgroup_parent` a WordPress/MariaDB/phpMyAdmin rootful (A.SPEC posterior, host-side).
- Nueva pestaña de recursos en la UI de Tenants (fase frontend posterior).
- Cambios en `src/systutor/**` (kernel), en `Settings` del kernel ni permisos
  `core.*`.
- Tocar `cell-g`, `cell-h`, Docker rootful, Traefik, phpMyAdmin, MariaDB ni
  producción.
- Invocar el CLI de Alembic en desarrollo (prohibido por AGENTS.md).
- Eliminar backwards compatibility: el import de `plans.json` es explícito y
  obligatorio.

## CONTRACT

**Precondiciones**: migración 006 aplicada por el runtime del core; permiso
`apps.plans.manage`; `TenantContext.is_platform` o ámbito de tenant válido; el
host registra un `PlanMaterializer` real en `AppsResources`.

**Postcondiciones**:

- `POST .../plan` persiste el plan, materializa slice/drop-in, audita y devuelve
  el plan efectivo; si la materialización falla, no queda fila de plan nueva.
- `GET .../plan` devuelve el plan guardado o `null`.
- `DELETE .../plan` elimina el plan, desmaterializa y devuelve el user manager a
  `user-<uid>.slice`.
- Un deploy de app con plan genera un override con
  `cgroup_parent: tenant-<slug>.slice` y límites derivados del plan; sin plan, el
  override es byte-idéntico al actual.
- Ninguna ruta ni servicio del plugin importa módulos de `scripts/tenant_cell`.
- `plan import` migra el JSON al modelo y marca el JSON como caché.

## INVARIANTS

```yaml
invariants:
  - "Sin plan, _override conserva pids_limit=256, mem_limit=512m y cpus=1.0 (test_no_invasive_hardening sigue verde)."
  - "El plan se persiste solo en la DB del plugin apps; plans.json nunca vuelve a ser fuente de verdad."
  - "Ningún archivo bajo src/systutor/ ni la Settings del kernel se modifica."
  - "Solo el permiso de plugin apps.plans.manage gobierna la API de planes; no se crean permisos core.*."
  - "Una operación de plan para el tenant A no altera planes, cgroups ni unidades del tenant B."
  - "Si el materializador falla, la transacción de DB se revierte y se audita el fallo."
  - "cell-g y cell-h no se tocan; sus cgroups, AppArmor y sockets quedan igual."
  - "Traefik, phpMyAdmin, MariaDB y WordPress no se modifican."
  - "El import de planes.json es explícito: no hay lectura silenciosa del JSON como plan activo."
  - "La migración 006 usa el runtime migrador del core, nunca el CLI de Alembic."
```

## VERIFICATION

```bash
PYTHONPATH=vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/apps/backend/tests/test_plans.py vendor/systutor-core/plugins/apps/backend/tests/test_no_invasive_hardening.py vendor/systutor-core/plugins/apps/backend/tests/test_scoped_planner.py scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_provision.py -q
ruff check vendor/systutor-core/plugins/apps/backend vendor/systutor-core/plugins/apps/migrations scripts/tenant_cell scripts/tests/test_tenant_cell_plan.py
python3 scripts/spanel_tenant.py plan --help
```

La evidencia de laboratorio de A.SPEC 0100 (`artifacts/0100-tenant-slice-aggregate-experiment.json`)
sigue siendo la prueba de kernel de que el slice agrega límites; esta A.SPEC
demuestra la integración backend con tests unitarios y de composición.

## ROLLBACK

`DELETE .../plan` desmaterializa y elimina la fila. Para revertir el esquema se
usa `downgrade()` de la migración 006 **ejecutado por el runtime del core**, no
por Alembic a mano. Ante un fallo del deploy con plan, basta no enviar `plan`:
`_override` vuelve a los defaults anteriores. `plans.json` conserva el último
estado aplicado para recuperación manual del host.

## Change Surface

```yaml
change_surface:
  allowed:
    - AGENTS.md
    - vendor/systutor-core/plugins/apps/plugin.json
    - vendor/systutor-core/plugins/apps/migrations/006_add_tenant_resource_plans.py
    - vendor/systutor-core/plugins/apps/backend/models.py
    - vendor/systutor-core/plugins/apps/backend/router.py
    - vendor/systutor-core/plugins/apps/backend/router_plans.py
    - vendor/systutor-core/plugins/apps/backend/schemas.py
    - vendor/systutor-core/plugins/apps/backend/plans_service.py
    - vendor/systutor-core/plugins/apps/backend/register.py
    - vendor/systutor-core/plugins/apps/backend/runtime/tenant_plan.py
    - vendor/systutor-core/plugins/apps/backend/runtime/deployment.py
    - vendor/systutor-core/plugins/apps/backend/runtime/scoped_execution.py
    - vendor/systutor-core/plugins/apps/backend/releases/execution.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_plans.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_no_invasive_hardening.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_scoped_planner.py
    - scripts/tenant_cell/plans.py
    - scripts/tenant_cell/materializer.py
    - scripts/tenant_cell/cli.py
    - scripts/tests/test_tenant_cell_plan.py
    - scripts/tests/test_tenant_cell_provision.py
  prohibited:
    - vendor/systutor-core/src/**
    - vendor/systutor-core/migrations/**
    - vendor/systutor-core/plugins/hosting/**
    - vendor/systutor-core/plugins/domains/**
    - vendor/systutor-core/plugins/tenant/**
    - vendor/systutor-core/app/**
    - apps/web/**
    - /etc/**
    - /run/**
    - scripts/e2e_*.py
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - tabla apps_tenant_plans (migración 006)
    - API apps.plans.* y permiso plugin.json
    - override de deploy (_override) y sus tests
    - CLI host plan y plans.json como caché
  indirect:
    - materialización de slice tenant-<slug>.slice y drop-in user@<uid>.service
    - registros de auditoría y Operation
  must_not_affect:
    - kernel systutor (src/systutor)
    - cell-g y cell-h
    - Traefik / phpMyAdmin / MariaDB / WordPress
    - defaults de límites cuando no hay plan
    - jerarquía user.slice
    - producción
```

## Composition

```yaml
composition:
  requires_aspecs:
    - "0100-apps-tenant-resource-plan"
    - "0099-apps-rootless-systemd-cgroup-driver"
  must_compose_with:
    - "0100-apps-tenant-resource-plan"
  systemic_invariants:
    - "Los límites por contenedor siguen aplicándose con o sin plan."
    - "AppArmor sigue en enforce tras cualquier materialización del plan."
    - "El socket rootless de cada celda sigue siendo exclusivo del tenant."
  composition_checks:
    - "PYTHONPATH=vendor/systutor-core:. python3 -m pytest scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_provision.py -q"
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: one coherent responsibility and one main reason to change
  entrypoints_must_stay_thin: true
  review_threshold_lines: 1200
  extraction_threshold_lines: 2000
  preferred_new_logic_locations:
    - vendor/systutor-core/plugins/apps/backend/runtime/tenant_plan.py
    - vendor/systutor-core/plugins/apps/backend/plans_service.py
    - scripts/tenant_cell/materializer.py
```

Nota: por instrucción explícita del usuario, el tamaño en líneas no es un
bloqueante para esta A.SPEC; la regla primaria de cohesión y los gates de
VERIFICATION gobiernan. Los umbrales se elevan solo como señal informativa.

## Traceability

- Requirement: Integrar el plan de recursos por tenant en el backend de Apps,
  con DB como fuente de verdad y CLI host migrada a materializador.
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
