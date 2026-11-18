# A.SPEC 0102 — Host Plan Materializer Wiring

> `risk: high` — introduce una frontera de privilegios (socket Unix), un servicio
> systemd con privilegios controlados y cambios de estado persistentes. Exige
> `approver:` humano.

## WHY

A.SPEC 0101 dejó la implementación correcta pero la integración operativa
pendiente: `register.py` declara `plan_materializer` pero no inyecta nada y la
API responde `503 apps.materializer_unavailable` por diseño fail-closed. El
GENERATOR hizo lo correcto: respetó `change_surface.allowed`, no tocó el host
por su cuenta y dejó visible la dependencia operativa.

La arquitectura definitiva elegida es la opción 2: un **agente host con
privilegios controlados** detrás de un **Unix Domain Socket**, al que el backend
(contenedor sin privilegios) llama mediante un **cliente de protocolo acotado**.
La opción 1 (inyección directa en el proceso de la app) queda reservada
**exclusivamente a pruebas de laboratorio**. La opción 3 (fail-closed 503) se
conserva como comportamiento de seguridad cuando no hay materializador
configurado.

Regla fundamental: **el backend decide qué plan corresponde a cada tenant; el
agente del host materializa únicamente operaciones autorizadas.**

## WHAT

El backend deja de depender de un materializador ausente: pasa a invocar un
cliente acotado que habla con un agente host privilegiado, con autenticación de
par, operaciones específicas de planes, estados explícitos y reconciliación
tras reinicios; el socket es una frontera de privilegios, no una autorización
por sí mismo.

## SCOPE

- `register.py`: inyección explícita de `HostPlanMaterializerClient` construido
  desde settings (ruta del socket y archivo de token), sin tocar `app/**`.
- `plans_client.py` (nuevo): cliente del protocolo con `apply/remove/verify`,
  timeouts, errores tipados y cero lógica de host.
- **Host Agent** (nuevo): servicio systemd con privilegios controlados que
  expone un Unix Domain Socket con un protocolo restringido a
  `apply`/`remove`/`verify`/`reconcile`. Reutiliza `PlanMaterializer` existente.
- `plans_service.py`: conserva el `503` fail-closed cuando no hay cliente;
  mapea errores tipados del cliente; gestiona estados `pending`/`applied`/
  `failed` y expone reconciliación.
- Modelo `AppsTenantPlan` + migración **007** (runtime migrador del core) para
  `status`, `applied_at`, `last_error` y `desired_hash`.
- `plans.json` queda **exclusivamente como caché local del agente y para el
  import legacy**: nunca se lee para decidir el plan activo ni compite con
  PostgreSQL.
- Gate `SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS=1` **solo en el proceso del agente
  host**, nunca como permiso general del backend.
- Wiring directo (opción 1) **solo en código de prueba de laboratorio**,
  separado y marcado como no producción.
- Tests de integración con socket falso, autenticación, autorización, parámetros,
  fallos, estados y reconciliación tras reinicio.

## OUT OF SCOPE

- Montar el socket Docker del host en el contenedor de la app.
- Endpoint genérico para ejecutar comandos, escribir archivos o reiniciar
  servicios arbitrarios.
- Conectar apps aisladas con el Traefik padre (A.SPEC posterior).
- `cgroup_parent` para WordPress/MariaDB/phpMyAdmin rootful.
- Pestaña de recursos en la UI de Tenants.
- Cambios en `src/systutor/**`, en `Settings` del kernel ni permisos `core.*`.
- Tocar `cell-g`, `cell-h`, Traefik, phpMyAdmin, MariaDB, WordPress ni
  producción.
- Invocar el CLI de Alembic (prohibido; las migraciones usan el runtime del core).

## CONTRACT

**Precondiciones**: la app corre sin privilegios; el socket del agente se
comparte solo con el contenedor de la app; el token compartido existe en ambos
lados; la migración 007 está aplicada por el runtime del core.

**Postcondiciones**:

- `POST/DELETE .../plan` y `verify` funcionan **solo** si hay cliente
  configurado; si no, siguen devolviendo `503 apps.materializer_unavailable`.
- El agente valida en cada llamada: identidad del proceso par (`SO_PEERCRED`
  uid/gid), token de capacidad con `tenant`/`slug`/`operación`/expiración,
  autorización del tenant, y parámetros (`memory>0`, `cpus>0`, `pids>0`, slug
  válido). **No acepta rutas ni nombres de unidad arbitrarios**: el nombre del
  slice se deriva del slug dentro del agente.
- El agente expone únicamente `apply`/`remove`/`verify`/`reconcile` sobre
  planes; nunca ejecución genérica.
- `apply` deja la fila en `applied` solo cuando la materialización real
  sucede; ante fallo queda `failed` con `last_error`, sin filas huérfanas ni
  estado ambiguo; `pending` se usa mientras la operación está en curso.
- `reconcile(desired)` compara los planes activos de la DB contra el estado real
  de systemd/cgroups y repara diferencias; se puede invocar tras reiniciar la
  VPS sin leer `plans.json` como verdad.
- El gate de mutación local solo existe en el entorno del agente.

## INVARIANTS

```yaml
invariants:
  - "El contenedor de la app nunca recibe el socket Docker del host."
  - "El agente no ofrece ejecución genérica: solo apply/remove/verify/reconcile de planes."
  - "El socket Unix es una frontera de privilegios: se validan SO_PEERCRED, token, tenant y parámetros en cada llamada."
  - "El agente nunca acepta paths ni nombres de unidad del cliente; deriva tenant-<slug>.slice desde el slug validado."
  - "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS=1 existe solo en el proceso del agente host."
  - "Sin cliente configurado, plans_service sigue respondiendo 503 fail-closed."
  - "PostgreSQL es la única fuente de verdad del plan; plans.json nunca decide el plan activo."
  - "Todo plan persistido tiene estado pending/applied/failed y es recuperable tras un fallo del agente."
  - "Tras reiniciar el host, un plan applied se puede verificar contra systemd/cgroups con reconcile."
  - "No se modifican cell-g, cell-h, Traefik, phpMyAdmin, MariaDB ni producción."
  - "No se toca src/systutor, Settings del kernel ni se crean permisos core.*."
```

## VERIFICATION

```bash
PYTHONPATH=vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/apps/backend/tests/test_plans.py vendor/systutor-core/plugins/apps/backend/tests/test_plans_client.py vendor/systutor-core/plugins/apps/backend/tests/test_plans_agent.py vendor/systutor-core/plugins/apps/backend/tests/test_no_invasive_hardening.py vendor/systutor-core/plugins/apps/backend/tests/test_scoped_planner.py scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_provision.py -q
ruff check vendor/systutor-core/plugins/apps/backend vendor/systutor-core/plugins/apps/migrations scripts/tenant_cell scripts/tests/test_tenant_cell_plan.py
python3 scripts/spanel_tenant.py plan --help
```

La evidencia de kernel sigue siendo `artifacts/0100-tenant-slice-aggregate-experiment.json`;
esta A.SPEC demuestra la frontera de privilegios con tests de integración sobre
socket falso, autenticación, estados y reconciliación.

## ROLLBACK

Quitar el cliente de `register.py` devuelve el sistema al `503` fail-closed de
0101 sin tocar datos. La migración 007 tiene `downgrade()` ejecutado por el
runtime del core. El agente systemd puede deshabilitarse sin afectar el deploy:
sin plan, `_override` conserva los defaults `512m/1.0/256`. El estado `failed`
es recuperable reintentando `apply` o `reconcile`.

## Change Surface

```yaml
change_surface:
  allowed:
    - vendor/systutor-core/plugins/apps/backend/register.py
    - vendor/systutor-core/plugins/apps/backend/settings.py
    - vendor/systutor-core/plugins/apps/backend/plans_client.py
    - vendor/systutor-core/plugins/apps/backend/plans_service.py
    - vendor/systutor-core/plugins/apps/backend/models.py
    - vendor/systutor-core/plugins/apps/backend/schemas.py
    - vendor/systutor-core/plugins/apps/migrations/007_add_tenant_plan_status.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_plans.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_plans_client.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_plans_agent.py
    - scripts/tenant_cell/host_agent.py
    - scripts/tenant_cell/deploy/spanel-plan-agent.service
    - scripts/tenant_cell/materializer.py
    - scripts/tenant_cell/host_wiring_lab.py
    - scripts/tenant_cell/cli.py
    - scripts/tests/test_tenant_cell_plan.py
    - scripts/tests/test_tenant_cell_provision.py
  prohibited:
    - vendor/systutor-core/src/**
    - vendor/systutor-core/migrations/**
    - vendor/systutor-core/app/**
    - vendor/systutor-core/plugins/hosting/**
    - vendor/systutor-core/plugins/domains/**
    - vendor/systutor-core/plugins/tenant/**
    - apps/web/**
    - /etc/**
    - /run/**
    - scripts/e2e_*.py
```

Nota: el unit file systemd del agente se entrega como Plantilla de origen en el
repositorio (`scripts/tenant_cell/deploy/spanel-plan-agent.service` dentro del
mismo cambio); el GENERATOR no escribe `/etc/**` directamente.

## Blast Radius

```yaml
blast_radius:
  direct:
    - inyección del cliente en AppsResources
    - protocolo y agente host (socket Unix + systemd)
    - estados de AppsTenantPlan y migración 007
  indirect:
    - mutaciones de slice tenant-<slug>.slice y drop-in user@<uid>.service
    - auditoría/Operation y caché local del agente
  must_not_affect:
    - kernel systutor
    - contenedor de la app sin privilegios
    - cell-g y cell-h
    - Traefik / phpMyAdmin / MariaDB / WordPress
    - comportamiento fail-closed 503 sin materializador
    - producción
```

## Composition

```yaml
composition:
  requires_aspecs:
    - "0101-apps-tenant-plan-backend"
    - "0100-apps-tenant-resource-plan"
  must_compose_with:
    - "0101-apps-tenant-plan-backend"
  systemic_invariants:
    - "Sin plan, _override sigue usando 512m/1.0/256."
    - "AppArmor sigue en enforce en daemon y contenedores tras cualquier materialización."
    - "El socket rootless de cada celda sigue siendo exclusivo del tenant."
  composition_checks:
    - "PYTHONPATH=vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/apps/backend/tests/test_plans.py scripts/tests/test_tenant_cell_plan.py -q"
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: one coherent responsibility and one main reason to change
  entrypoints_must_stay_thin: true
  review_threshold_lines: 1200
  extraction_threshold_lines: 2000
  preferred_new_logic_locations:
    - vendor/systutor-core/plugins/apps/backend/plans_client.py
    - scripts/tenant_cell/host_agent.py
    - scripts/tenant_cell/host_wiring_lab.py
```

Por instrucción del usuario, el tamaño en líneas no es bloqueante para esta
A.SPEC; gobiernan la cohesión y la VERIFICATION.

## Traceability

- Requirement: Frontera de privilegios para materializar planes de tenant: cliente acotado + agente host + estados + reconciliación.
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
