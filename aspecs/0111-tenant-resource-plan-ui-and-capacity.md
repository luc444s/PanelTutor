# A.SPEC 0111 — Plan de recursos por tenant en la UI y capacidad informativa

> `risk: high` — añade una migración de esquema, amplía la API de planes y
> cambia el modal de Usuarios. Requiere `approver:` humano y E2E en laboratorio.

## WHY

A.SPEC 0101–0108 dejaron el plan de recursos por tenant implementado y probado
en el host: tabla `apps_tenant_plans`, API `POST/GET/DELETE /plan`,
`POST /plan/verify`, agente host por UDS, CLI `spanel-tenant plan` y límites
reales de memoria/CPU/PIDs en cgroups v2. A.SPEC 0102 dejó explícitamente fuera
de alcance la pestaña de recursos en la UI.

Hoy el administrador de plataforma solo puede fijar esos límites por API o CLI.
En el flujo real de Tenants no hay forma de ver ni ajustar la potencia
contratada desde el panel, y el botón **Resources** existente abre el inventario
de contenedores (start/stop/restart/remove), no el plan.

Además:

- El plan actual no tiene **almacenamiento**: no existe `storage_bytes`.
- No hay **visibilidad de la capacidad del host** ni de cuánto suman los planes
  ya asignados.
- La **sobreventa está permitida**: un servidor de 8 GiB puede tener seis
  tenants de 2 GiB (12 GiB declarados). Los cgroups siguen limitando a cada
  tenant por separado; el host reparte la potencia real cuando hay contención.
  Esta spec **no bloquea ni advierte** por sobreventa: solo guarda el plan.
- El **uso real** (RAM/CPU/disco consumidos) se medirá en una fase posterior,
  cuando existan los workers de medición. Esta spec **no** muestra ni calcula
  consumo actual: solo capacidad del host y capacidad declarada.

## WHAT

**La pestaña “Recursos” dentro del modal de Usuarios permite ver y editar el
plan por tenant (RAM, cores, PIDs y almacenamiento), muestra la capacidad total
del host y lo ya asignado, y permite guardar aunque la suma exceda el host. El
almacenamiento queda como límite declarado; su uso real y su aplicación como
cuota se harán en una spec posterior.**

## SCOPE

### A. Persistencia del plan con almacenamiento

- Migración de plugin `plugins/apps/migrations/008_add_tenant_plan_storage.py`
  (runtime migrador de systutor-core, **nunca** CLI de Alembic):
  - `apps_tenant_plans.storage_bytes BIGINT NULL`;
  - `NULL` = tenant sin almacenamiento declarado (compatibilidad con filas
    0101–0107);
  - `> 0` = límite declarado de disco en bytes;
  - `downgrade` elimina la columna.
- `AppsTenantPlan.storage_bytes` en `models.py`.
- `TenantPlanRequest.storage_bytes: int | None` (`gt=0`; `None` permitido por
  compatibilidad) en `schemas.py`.
- `TenantPlanView.storage_bytes: int | None`.
- `runtime/tenant_plan.py`:
  - `TenantPlan.storage_bytes` para consumidores del backend;
  - **no** incluir `storage` en `as_dict()`: el payload del agente host sigue
    siendo `{memory, cpus, pids, cpuset}` y `storage` no se aplica por systemd;
  - incluir `storage_bytes` en `desired_hash` para que un cambio solo de
    almacenamiento quede registrado y auditable.
- `plans_service.plan_view()` devuelve `storage_bytes`.
- `set_plan`/`remove_plan` auditan el valor de almacenamiento sin secretos.

### B. Capacidad real del host y suma de planes

- Nuevo op read-only `capacity` en el agente host (sujeto global `*`, mismo
  modelo de capability que `reconcile`):
  - RAM total: `MemTotal` de `/proc/meminfo`;
  - cores: `os.cpu_count()`/`nproc`;
  - almacenamiento: `statvfs(data_root)` (total y disponible);
  - `read_at`, `source`, `data_root`.
- `HostPlanMaterializerClient.capacity()` y método `capacity()` en el protocolo
  `PlanMaterializer`; los fakes de tests se adaptan.
- `GET /api/v1/plugins/apps/plan/capacity?tenant_id=...`:
  - `host`: total real de RAM, CPU y disco;
  - `allocated`: suma de los planes de todos los tenants;
  - `unbounded_storage`: planes sin `storage_bytes`;
  - responde `503 apps.capacity_unavailable` si el agente no está disponible.
- `set_plan` **no rechaza ni advierte** por capacidad:
  - persiste y materializa el plan aunque la suma exceda el host;
  - no calcula ratios de sobreventa ni los audita;
  - no usa lock de capacidad: dos guardados concurrentes son válidos.
- `verify_plan` conserva su contrato actual (cgroup). No verifica almacenamiento
  porque todavía no hay medición de uso.

### C. UI: pestaña “Recursos” en el modal de Usuarios

- `TenantUsersDialog` pasa de dos pestañas a tres:
  `Perfil`, `Roles`, `Recursos`.
- Nuevo componente `TenantResourcePlanPanel.tsx` en el plugin tenant:
  - formulario con RAM (GiB), cores, almacenamiento (GiB) y PIDs (avanzado);
  - resumen del host: total y asignado;
  - estado del plan: `applied`, `pending`, `failed`, `last_error`, `applied_at`;
  - botones `Guardar plan`, `Verificar` y `Eliminar plan` (con confirmación);
  - errores 503 (agente caído) mapeados a `Alert` legibles y guardar
    deshabilitado solo si no se puede materializar;
  - **sin sección de uso actual, sin barras de consumo, sin workers**.
- Cuando el tenant no tiene plan, se muestran valores sugeridos y solo el botón
  de guardar.
- `frontend/api.ts` del plugin tenant añade:
  - `getTenantPlan`, `setTenantPlan`, `deleteTenantPlan`, `verifyTenantPlan`,
    `getTenantPlanCapacity`;
  - `tenantKeys.plan/capacity`.
- El tab solo es editable con `apps.plans.manage` (permiso de plataforma). Sin
  ese permiso se muestra en modo lectura o se oculta; el backend sigue siendo
  la autoridad.
- Invalidaciones tras guardar/verificar/eliminar: plan y capacidad.
- i18n en `apps/web/src/i18n/es/tenant.ts` (inglés = clave).

### D. Desambiguar inventario y plan

- El botón actual **Resources** de `TenantsPage` pasa a **Inventory**.
- `TenantResourcesDialog` pasa a título `Inventory — {name}`.
- La pestaña nueva se llama **Resources** y su contenido es el plan, no el
  inventario.
- No se cambian las acciones start/stop/restart/remove del inventario.

### E. Pruebas y evidencia

- Backend:
  - migración 008 `up/down/up`;
  - esquema acepta/rechaza `storage_bytes`;
  - `set_plan` persiste storage y lo incluye en el hash;
  - `set_plan` **acepta** un plan que exceda la capacidad del host, sin error y
    sin campos de sobreventa;
  - `GET /plan/capacity` devuelve total real y suma asignada;
  - `503` sin agente;
  - `plan_view` devuelve storage; `verify` sigue siendo solo cgroup.
- Host:
  - `capacity` autoriza, devuelve valores reales y falla cerrado si no puede
    leerlos;
  - no se añade `usage` ni `du`.
- Frontend:
  - helpers puros de conversión (GiB↔bytes) con vitest;
  - build TypeScript (`npm run build`) y `npm test`.
- E2E de laboratorio: `artifacts/0111-tenant-resource-plan-e2e.json` con:
  - plan creado desde la UI/API para un tenant desechable;
  - `verify.ok=true` (cgroup);
  - planes que suman más que el host (`6 × 2 GiB` sobre un host de `8 GiB` o
    equivalente simulado) **aceptados**, sin advertencia ni rechazo;
  - edición de storage sin tocar el cgroup;
  - eliminación del plan y limpieza;
  - Core (Traefik, MariaDB, phpMyAdmin, PowerDNS, Mailserver) con PID/hash
    sin cambios.

## OUT OF SCOPE

- **Uso actual**: no se mide ni se muestra RAM/CPU/disco consumidos.
- **Workers de medición**: no se añaden tareas periódicas ni históricos.
- **Bloqueo por capacidad**: la sobreventa se permite siempre; no hay 409 por
  exceder el host.
- **Cuota blanda aplicada**: no se bloquean subidas, despliegues ni altas por
  superar el almacenamiento declarado. Esa lógica necesita medición y va en una
  spec posterior.
- **Cuota dura de kernel**: ext4 project quotas, XFS, `tune2fs`, remount de `/`,
  LVM, loopback o filesystem dedicado.
- Facturación, gráficas, alertas o borrado automático por cuota.
- Cambiar los límites por servicio del override de deploy (0101 ya lo hace).
- Cambiar la semántica de `plan apply` en el host: `storage` no se pasa a
  systemd ni se añade a `PLAN_KEYS`.
- Migrar apps o sitios a rootless (0109/0110), AppArmor, seccomp, relay,
  Traefik, DNS, certificados, correo o phpMyAdmin.
- Dar `apps.plans.manage` a administradores de tenant: el plan es potestad de
  plataforma.
- Invocar el CLI de Alembic (prohibido por AGENTS.md).

## CONTRACT

**Precondiciones**:

- migración 008 aplicada por el runtime migrador del core;
- agente host `spanel-plan-agent` activo y socket/token disponibles;
- usuario con `apps.plans.manage`;
- celda del tenant existente para materializar el plan cgroup (un tenant sin
  celda recibe un error explícito del agente, no un 500).

**Postcondiciones**:

1. `POST /plan` persiste `storage_bytes` junto a RAM/CPU/PIDs, audita y
   devuelve el plan con almacenamiento.
2. `GET /plan/capacity` devuelve capacidad real y suma asignada para el tenant
   consultado.
3. `set_plan` **acepta** planes que excedan la capacidad del host; no existe
   rechazo 409 ni cálculo de sobreventa.
4. La pestaña **Recursos** del modal de Usuarios muestra y edita el plan y la
   capacidad, sin avisos de sobreventa y sin uso actual.
5. El botón de inventario se llama **Inventory** y sigue funcionando.
6. Sin plan o sin `storage_bytes`, el comportamiento anterior no cambia.
7. El plan sigue aplicándose por `systemctl set-property` sin reparentar
   (0108) y sin incluir `storage` en el payload del host.
8. `POST /plan/verify` mantiene su contrato cgroup; no promete verificar disco.

## UI (ASCII)

**Con plan:**

```text
┌──────────────────────────────────────────────────────────────────────┐
│  Usuarios — Demo Tenant                                         [×]  │
│  Administración del tenant · demo                                    │
│                                                                      │
│    Perfil          Roles          [ Recursos ]                       │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ● Plan aplicado     Actualizado 21/11/2026 06:45    Celda demo      │
│                                                                      │
│  CAPACIDAD DEL HOST                                                  │
│  ┌────────────────┐ ┌────────────────┐ ┌────────────────┐           │
│  │ RAM            │ │ CPU            │ │ DISCO          │           │
│  │ 8,0 GiB        │ │ 4,0 cores      │ │ 160 GiB        │           │
│  │ 12,0 asignados │ │ 6,0 asignados  │ │ 120 asignados  │           │
│  └────────────────┘ └────────────────┘ └────────────────┘           │
│                                                                      │
│  PLAN DEL TENANT                                                     │
│                                                                      │
│  Memoria RAM                   Cores de CPU                          │
│  ┌──────────────────┐          ┌──────────────────┐                  │
│  │ 2            GiB │          │ 1          cores │                  │
│  └──────────────────┘          └──────────────────┘                  │
│                                                                      │
│  Almacenamiento                Procesos (PIDs)                       │
│  ┌──────────────────┐          ┌──────────────────┐                  │
│  │ 20           GiB │          │ 256        procs │                  │
│  └──────────────────┘          └──────────────────┘                  │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│  [ Eliminar plan ]                         [ Verificar ] [ Guardar ] │
└──────────────────────────────────────────────────────────────────────┘
```

**Sin plan:**

```text
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│  Este tenant todavía no tiene un plan de recursos.                   │
│                                                                      │
│  Valores sugeridos:                                                  │
│    RAM              2 GiB                                            │
│    CPU              1 core                                           │
│    Almacenamiento   20 GiB                                           │
│    PIDs             256                                              │
│                                                                      │
│  Host: 8,0 GiB RAM · 4 cores · 160 GiB disco                         │
│  Asignado: 10,0 GiB RAM · 5,0 cores · 100 GiB disco                  │
│                                                                      │
│                                              [ Guardar plan ]        │
└──────────────────────────────────────────────────────────────────────┘
```

**Agente no disponible:**

```text
┌──────────────────────────────────────────────────────────────────────┐
│  ⚠  No se pudo leer la capacidad del host                            │
│                                                                      │
│  El agente de planes no responde. No se puede guardar el plan        │
│  hasta que vuelva.                                                   │
│                                                                      │
│  Memoria RAM                   Cores de CPU                          │
│  ┌──────────────────┐          ┌──────────────────┐                  │
│  │ 2            GiB │          │ 1          cores │                  │
│  └──────────────────┘          └──────────────────┘                  │
│                                                                      │
│                                              [ Guardar plan ]        │
│                                              (deshabilitado)         │
└──────────────────────────────────────────────────────────────────────┘
```

## INVARIANTS

```yaml
invariants:
  - "storage_bytes es un límite declarado en el plan, no una cuota aplicada ni una cuota de kernel."
  - "No se mide uso real ni se ejecutan workers/du en esta spec."
  - "La sobreventa de RAM/CPU/disco está permitida y nunca se rechaza por capacidad."
  - "La UI no muestra avisos, ratios ni proyecciones de sobreventa; solo total del host y asignado."
  - "El payload que recibe el materializador host sigue siendo exactamente memory/cpus/pids/cpuset."
  - "La capacidad se lee del host real, no de valores hardcodeados ni de la configuración del panel."
  - "El plan sigue siendo propiedad de plataforma: apps.plans.manage no se concede a tenant_admin."
  - "La migración 008 se ejecuta por el runtime del core; nunca por el CLI de Alembic."
  - "El inventario (start/stop/restart/remove) no cambia de comportamiento."
  - "Traefik, MariaDB, phpMyAdmin, PowerDNS, Mailserver y el resto de Core quedan intactos."
```

## VERIFICATION

```bash
# Backend
PYTHONPATH=vendor/systutor-core:. python3 -m pytest \
  vendor/systutor-core/plugins/apps/backend/tests/test_plans.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_plans_client.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_plans_agent.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_migration.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_schemas.py -q

# Host / agente
PYTHONPATH=vendor/systutor-core:. python3 -m pytest \
  scripts/tests/test_tenant_cell_plan.py \
  scripts/tests/test_tenant_cell_capacity.py -q

# Frontend
cd apps/web && npm test && npm run build

# Lint
ruff check scripts/tenant_cell/host_agent.py \
  vendor/systutor-core/plugins/apps/backend
```

E2E de laboratorio: `artifacts/0111-tenant-resource-plan-e2e.json` debe demostrar
plan creado y aplicado, capacidad real, plan por encima del host aceptado sin
aviso, edición de storage, eliminación limpia y Core sin cambios.

## ROLLBACK

- Revertir código + `downgrade` de la migración 008 elimina `storage_bytes`;
  los planes de RAM/CPU/PIDs siguen intactos.
- Al revertir, la pestaña Recursos desaparece y el comportamiento de Tenants
  vuelve al anterior; no se borran datos ni contenedores.
- `plan remove` sigue desmaterializando el cgroup del tenant sin tocar datos.
- No hay estado de medición ni de cuota que deshacer.

## Change Surface

```yaml
change_surface:
  allowed:
    - vendor/systutor-core/plugins/apps/backend/models.py
    - vendor/systutor-core/plugins/apps/backend/schemas.py
    - vendor/systutor-core/plugins/apps/backend/plans_service.py
    - vendor/systutor-core/plugins/apps/backend/plans_client.py
    - vendor/systutor-core/plugins/apps/backend/register.py
    - vendor/systutor-core/plugins/apps/backend/router_plans.py
    - vendor/systutor-core/plugins/apps/backend/runtime/tenant_plan.py
    - vendor/systutor-core/plugins/apps/migrations/008_add_tenant_plan_storage.py
    - vendor/systutor-core/plugins/apps/backend/tests/**
    - scripts/tenant_cell/host_agent.py
    - scripts/tests/test_tenant_cell_capacity.py
    - vendor/systutor-core/plugins/tenant/frontend/api.ts
    - vendor/systutor-core/plugins/tenant/frontend/pages/TenantsPage.tsx
    - vendor/systutor-core/plugins/tenant/frontend/components/TenantUsersDialog.tsx
    - vendor/systutor-core/plugins/tenant/frontend/components/TenantResourcePlanPanel.tsx
    - vendor/systutor-core/plugins/tenant/frontend/components/TenantResourcesDialog.tsx
    - apps/web/src/i18n/es/tenant.ts
    - artifacts/0111-tenant-resource-plan-e2e.json
  prohibited:
    - vendor/systutor-core/plugins/apps/backend/runtime/deployment.py
    - vendor/systutor-core/plugins/apps/backend/runtime/tenant_runtime.py
    - vendor/systutor-core/src/systutor/contracts/tenant_quota.py
    - vendor/systutor-core/plugins/hosting/backend/**
    - vendor/systutor-core/plugins/filemanager/backend/**
    - scripts/tenant_cell/cells.py
    - scripts/tenant_cell/executor.py
    - scripts/tenant_cell/materializer.py
    - scripts/tenant_cell/apparmor.py
    - scripts/tenant_cell/network.py
    - scripts/tenant_cell/relay.py
    - scripts/tenant_cell/deploy/**
    - scripts/phpmyadmin_up.sh
    - scripts/traefik-lab.sh
    - scripts/powerdns-lab.sh
    - docker-compose.yml
    - /etc/fstab
    - /etc/systemd/**
    - /opt/stacks/**
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - esquema apps_tenant_plans (columna storage_bytes)
    - API de planes (POST/GET/DELETE/verify + capacity)
    - protocolo UDS del agente (op capacity, solo lectura)
    - modal de Usuarios del plugin tenant
  indirect:
    - experiencia de administración de tenants
    - futura spec de medición y cuota
  must_not_affect:
    - materialización cgroup existente (0108)
    - inventario y runtime registrado (0107)
    - contenedores y datos de tenants
    - Traefik, MariaDB compartida, phpMyAdmin, PowerDNS, Mailserver
    - producción y filesystem del host
```

## Composition

```yaml
composition:
  requires_aspecs:
    - "0101-apps-tenant-plan-backend"
    - "0102-apps-host-plan-materializer-wiring"
    - "0107-tenant-resource-runtime-and-inventory"
    - "0108-rootless-userspace-ram-dry-run"
  must_compose_with:
    - "0109-apps-rootless-sandbox"
    - "0110-a-hosting-rootless-sites-and-migration"
  systemic_invariants:
    - "PostgreSQL es la fuente de verdad del plan; plans.json es solo caché del host."
    - "El agente host materializa operaciones acotadas; el backend no gana privilegios."
    - "La sobreventa es una decisión operativa; no se muestra ni se bloquea en el panel."
  composition_checks:
    - "PYTHONPATH=vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/apps/backend/tests/test_plans.py scripts/tests/test_tenant_cell_plan.py -q"
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: una responsabilidad coherente y una razón principal de cambio
  entrypoints_must_stay_thin: true
  review_threshold_lines: 500
  extraction_threshold_lines: 800
  preferred_new_logic_locations:
    - vendor/systutor-core/plugins/apps/backend/plans_service.py
    - scripts/tenant_cell/host_agent.py
    - vendor/systutor-core/plugins/tenant/frontend/components/TenantResourcePlanPanel.tsx
```

## Traceability

- Requirement: plan de recursos visible y editable desde Tenants; RAM, cores,
  PIDs y almacenamiento declarado; mostrar capacidad total del host y lo
  asignado, sin avisos de sobreventa. El uso real y la cuota aplicada se
  posponen a una spec posterior.
- owner: lucas
- approver: lucas
- Evidence: `artifacts/0111-tenant-resource-plan-e2e.json` (pendiente de la
  implementación y ceremonia en laboratorio).
- Deployment: laboratorio `spanel.lab`; sin producción.

## Definition of Done

- [ ] Objetivo satisfecho
- [ ] Scope respetado
- [ ] Contrato satisfecho
- [ ] Verdad falsable e independiente disponible ahora (capacidad real del host)
- [ ] Invariantes preservados
- [ ] Verificación backend/host/frontend ejecutada
- [ ] Rollback honesto (código + downgrade 008, sin estado de medición)
- [ ] Checks de composición ejecutados
- [ ] Sin cambios no relacionados
- [ ] Restricciones estructurales respetadas
- [ ] Trazabilidad establecida
- [ ] E2E black-box en laboratorio con plan sobrevendido aceptado y sin uso actual
- [ ] Core intacto (PID/hash)
