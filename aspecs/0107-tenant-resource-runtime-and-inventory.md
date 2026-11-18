# A.SPEC 0107 — Track per-resource runtime and inventory tenant containers

> `risk: high` — toca persistencia, superficie de administración y UI; exige `approver:`
> humano. Rollback por bandera + downgrade de migración; blast radius multi-tenant.

## WHY

Hoy no existe ninguna verdad que diga **en qué daemon corre cada recurso** de un tenant.
Todo es rootful global y el panel solo ve un dominio publicado (relay → Traefik, 0104/0106):
no puede enumerar ni gestionar los sitios WordPress, sitios estáticos y apps del tenant.
Sin un runtime registrado por recurso, dos cosas fallarían en cuanto se migrase algo a
rootless: (a) apagar la bandera global haría perder la administración de lo ya migrado, y
(b) el panel quedaría ciego. Esta A.SPEC establece la verdad y la superficie que hacen
posible el resto de la v1 sin comprometer la infraestructura Core.

## WHAT

**Todo recurso administrado por un tenant (app, WordPress, estático) tiene un runtime
registrado (`rootful`|`rootless`) en PostgreSQL y spanel lo lista y gestiona resolviendo
cada acción por ese runtime; la bandera global solo habilita migraciones nuevas y nunca
cambia dónde se resuelve un recurso ya registrado.**

## SCOPE

- Contrato `systutor.contracts.resource_runtime`: `ManagedResource(kind, resource_id,
  name, container_name, domain, state, image, endpoint)` y registro de providers
  `register_resource_provider(app, name, provider)` / `list_resources(app, db, tenant_id)`.
  El contrato **no** expone sockets ni rutas a daemon.
- Plugin `tenant`: migración `004_tenant_resource_runtimes.py` con tabla
  `tenant_resource_runtimes` (`tenant_id`, `kind`, `resource_id`, `runtime`, `updated_at`,
  unique `(tenant_id, kind, resource_id)`, CHECK `runtime in ('rootful','rootless')`);
  modelo `TenantResourceRuntime`; servicio `ensure_runtime`, `get_runtime`, `set_runtime`,
  `list_runtimes`; resolución por defecto `rootful` cuando no hay fila (verdad actual).
- Registro de providers: `apps` inventaría aplicaciones/despliegues activos; `hosting`
  inventaría `HostingSite` (`wordpress`/`static`). El inventario ensambla recursos +
  runtime. `state`/`image` son best-effort desde BD/manifest; si no están disponibles se
  devuelve `unknown`, nunca un error.
- Nota de ruta: el runtime del core monta los routers de plugin bajo
  `/api/v1/plugins/<plugin-id>`; por eso las rutas navegables son las del prefijo
  `/api/v1/plugins/tenant/tenants/...` (coherente con los tests existentes del plugin).
- API en el plugin `tenant` (bandera `SPANEL_TENANT_RESOURCE_INVENTORY`, default `false`):
  `GET /api/v1/plugins/tenant/tenants/{tenant_id}/resources` (lista filtrada por tenant/plataforma),
  `GET .../resources/{kind}/{resource_id}`, y
  `POST .../resources/{kind}/{resource_id}/actions/{start|stop|restart|remove}` con
  query `?dry_run=1`. El despacho usa el runtime registrado: rootful → servicios
  existentes de `hosting`/`apps`; rootless → `TenantRuntimeRegistry` / celda. `dry_run=1`
  devuelve el plan sin ejecutar nada.
- UI: componente `TenantResourcesDialog.tsx` en el plugin `tenant`, acción en
  `TenantsPage.tsx`, tipos/funciones en `frontend/api.ts`, y claves en el catálogo
  español `apps/web/src/i18n/es/tenant.ts` (inglés = clave, según convenio).
- Tests unitarios de migración up/down/up, contrato, servicio, API, scope por tenant,
  dry-run y despacho por runtime. Artefacto E2E black-box (fase laboratorio, después del
  GENERATOR): `artifacts/0107-tenant-resource-runtime-e2e.json`.

## OUT OF SCOPE

- Migrar apps o sitios a rootless (0109/0110); materializar planes RAM o tocar cgroups
  (0108); tocar `scripts/tenant_cell/**`, AppArmor, seccomp, relay o systemd.
- Eliminar, renombrar o mover contenedores/volúmenes rootful existentes; cambiar rutas
  publicadas por dominio (0104/0106).
- Traefik, MariaDB compartida, phpMyAdmin, PowerDNS, Docker Mailserver ni su
  configuración/hardening; DNS, certificados, backups, correo.
- Cambiar la selección de runner de producción (`tasks.py`), el Provisioner de hosting,
  el normalizador/hardener (retirados), ni añadir campos a los modelos de `apps`/`hosting`.
- Exponer `docker.sock` al frontend ni al contrato; ampliar permisos RBAC existentes.

## CONTRACT

**Precondiciones:** existe al menos un tenant; los providers de `apps` y `hosting` están
registrados; la migración 004 se aplicó con el runtime migrador del core; la bandera
`SPANEL_TENANT_RESOURCE_INVENTORY=true` habilita API y UI.

**Postcondiciones:**
1. `list_resources(app, db, tenant_id)` devuelve los recursos del tenant enriquecidos con
   `runtime`; una fila ausente se resuelve como `rootful` sin mutar la BD.
2. `GET .../resources` para tenant A nunca incluye recursos de tenant B; un admin de
   plataforma ve todos.
3. Ninguna acción con `dry_run=1` muta contenedores, rutas ni la tabla de runtimes; sin
   `dry_run`, la acción se despacha por el `runtime` registrado del recurso.
4. `set_runtime(kind, id, 'rootless')` persiste el cambio; al poner la bandera global en
   `false`, ese recurso sigue resolviéndose como `rootless`.
5. Con la bandera de inventario en `false`, el router no está montado y la UI no muestra
   la acción; los flujos anteriores siguen intactos.
6. La migración 004 es reversible: `upgrade → downgrade → upgrade` deja la tabla y los
   datos de `tenants`, `apps_applications` y `hosting_sites` intactos.

## INVARIANTS

```yaml
invariants:
  - "SPANEL_TENANTS_ROOTLESS no altera la resolucion de recursos ya registrados; solo habilita migraciones nuevas."
  - "El runtime se persiste por recurso y se lee desde la BD; una fila ausente significa rootful, nunca rootless."
  - "Un tenant nunca ve ni gestiona recursos de otro tenant; los admins de plataforma conservan acceso total."
  - "Ningun docker.sock (global o de celda) se expone al frontend, al contrato ni en respuestas HTTP."
  - "Traefik, MariaDB compartida, phpMyAdmin, PowerDNS y Docker Mailserver siguen en Core, intactos y no inventariados como recursos del tenant."
  - "Ningun contenedor ni volumen rootful preexistente se elimina, renombra o mueve."
  - "La bandera SPANEL_TENANT_RESOURCE_INVENTORY=false deja API y UI exactamente como hoy."
  - "dry_run=1 no muta nada; sin dry_run las acciones despachan por el runtime registrado."
  - "El 503 fail-closed del agente de planes de la API de planes no cambia."
  - "No se reintroduce hardening invasivo en Dockerfiles ni codigo de aplicaciones."
  - "Los permisos RBAC existentes de tenant y plataforma no se amplian."
```

## VERIFICATION

```bash
# Migracion (incluye downgrade EJECUTADO, no solo presence) y logica del contrato/servicio/API
PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/tenant/backend/tests -q
PYTHONPATH=vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/apps/backend/tests/test_migration.py vendor/systutor-core/plugins/hosting/backend/tests/test_migration.py -q
ruff check vendor/systutor-core/src/systutor/contracts/resource_runtime.py vendor/systutor-core/plugins/tenant/backend/models.py vendor/systutor-core/plugins/tenant/backend/schemas.py vendor/systutor-core/plugins/tenant/backend/service.py vendor/systutor-core/plugins/tenant/backend/router.py vendor/systutor-core/plugins/tenant/backend/register.py vendor/systutor-core/plugins/tenant/backend/tests/test_resource_runtimes.py vendor/systutor-core/plugins/tenant/backend/tests/test_resource_inventory_api.py vendor/systutor-core/plugins/apps/backend/register.py vendor/systutor-core/plugins/hosting/backend/register.py
PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -c "from systutor.contracts.resource_runtime import ManagedResource, list_resources; from plugins.tenant.backend.service import set_runtime, get_runtime; print('ok')"
cd apps/web && node node_modules/typescript/bin/tsc --noEmit
```

E2E black-box (fase laboratorio, **después** de que el GENERATOR termine; lo ejecuta un
subagente E2E separado): `artifacts/0107-tenant-resource-runtime-e2e.json` debe mostrar,
con `SPANEL_TENANTS_ROOTLESS=false`, un tenant con un WP, un estático y una app listados
con `runtime=rootful`; `dry_run=1` en `remove` sin mutación; y el lock de scopes
(tenant A no ve recursos de tenant B). El rollback se verifica apagando
`SPANEL_TENANT_RESOURCE_INVENTORY` y ejecutando el downgrade de la migración 004 (ya
cubierto por el primer comando pytest).

## ROLLBACK

- `SPANEL_TENANT_RESOURCE_INVENTORY=false`: el router no se monta y la UI oculta la
  acción; ningún flujo previo se modifica.
- Migración 004 es aditiva y reversible: `downgrade` elimina solo
  `tenant_resource_runtimes`. El test `upgrade → downgrade → upgrade` se ejecuta en
  VERIFICATION; sin cambios en tablas de apps/hosting ni en contenedores.
- Si una acción despachada falla, se devuelve el error y no se escribe el runtime: el
  estado anterior queda intacto (no se borra nada).

## Change Surface

```yaml
change_surface:
  allowed:
    - vendor/systutor-core/src/systutor/contracts/resource_runtime.py
    - vendor/systutor-core/plugins/tenant/migrations/004_tenant_resource_runtimes.py
    - vendor/systutor-core/plugins/tenant/backend/models.py
    - vendor/systutor-core/plugins/tenant/backend/schemas.py
    - vendor/systutor-core/plugins/tenant/backend/service.py
    - vendor/systutor-core/plugins/tenant/backend/router.py
    - vendor/systutor-core/plugins/tenant/backend/register.py
    - vendor/systutor-core/plugins/tenant/backend/tests/test_resource_runtimes.py
    - vendor/systutor-core/plugins/tenant/backend/tests/test_resource_inventory_api.py
    - vendor/systutor-core/plugins/tenant/frontend/api.ts
    - vendor/systutor-core/plugins/tenant/frontend/components/TenantResourcesDialog.tsx
    - vendor/systutor-core/plugins/tenant/frontend/pages/TenantsPage.tsx
    - apps/web/src/i18n/es/tenant.ts
    - vendor/systutor-core/plugins/apps/backend/register.py
    - vendor/systutor-core/plugins/hosting/backend/register.py
  prohibited:
    - scripts/tenant_cell/**
    - vendor/systutor-core/src/systutor/kernel/**
    - vendor/systutor-core/app/**
    - vendor/systutor-core/migrations/**
    - vendor/systutor-core/plugins/apps/backend/tasks.py
    - vendor/systutor-core/plugins/apps/backend/worker.py
    - vendor/systutor-core/plugins/apps/backend/models.py
    - vendor/systutor-core/plugins/hosting/backend/provisioner.py
    - vendor/systutor-core/plugins/hosting/backend/static.py
    - vendor/systutor-core/plugins/hosting/backend/models.py
    - vendor/systutor-core/plugins/hosting/backend/service.py
    - vendor/systutor-core/plugins/domains/**
    - vendor/systutor-core/plugins/mail/**
    - scripts/phpmyadmin_up.sh
    - docker-compose.yml
    - /opt/stacks/**
    - apps/web/src/i18n/es/apps.ts
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - tabla tenant_resource_runtimes y su migracion
    - contrato resource_runtime y providers de apps/hosting
    - API y UI de inventario/control del tenant
  indirect:
    - resolucion de runtime para futuras migraciones 0109/0110
    - vision del panel sobre los recursos del tenant
  must_not_affect:
    - seleccion de runner de apps en produccion (tasks.py/worker.py)
    - contenedores y volumenes rootful existentes
    - rutas publicadas por dominio (0104/0106)
    - API de planes y su 503 fail-closed
    - Traefik, MariaDB compartida, phpMyAdmin, PowerDNS, Docker Mailserver
    - produccion
```

## Composition

```yaml
composition:
  requires_aspecs:
    - "0104-apps-rootless-edge-routes"
    - "0106-apps-rootless-route-tls"
  must_compose_with:
    - "0108-rootless-userspace-ram-dry-run"
    - "0109-apps-rootless-daemon"
    - "0110-hosting-rootless-phpmyadmin"
  systemic_invariants:
    - "PanelTutor Core conserva su capacidad privilegiada de administracion."
    - "El runtime persistido manda sobre la bandera global para recursos ya migrados."
    - "La infraestructura Core no se inventaria ni se gestiona desde el tenant."
  composition_checks:
    - "PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/tenant/backend/tests -q"
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: one coherent responsibility and one main reason to change
  entrypoints_must_stay_thin: true
  review_threshold_lines: 500
  extraction_threshold_lines: 800
  preferred_new_logic_locations:
    - vendor/systutor-core/plugins/tenant/backend/service.py
    - vendor/systutor-core/src/systutor/contracts/resource_runtime.py
```

## Traceability

- Requirement: corrección 2 (persistencia del runtime y rollback por aplicación) y req. 1
  (compatibilidad visual: spanel ve/gestiona los contenedores del tenant).
- owner: lucas
- approver: lucas
- Commit: (pendiente; cambios en el working tree sobre `remove-hardener`)
- Evidence: `artifacts/0107-tenant-resource-runtime-e2e.json` (PASS, 7/7 checks black-box).
- Deployment: laboratorio `spanel.lab` (BD clonada desechable); sin producción.

## Definition of Done

- [ ] Objective satisfied
- [ ] Scope respected
- [ ] Contract satisfied
- [ ] Independent falsable truth exists now
- [ ] Invariants preserved
- [ ] Verification passed (incluye downgrade ejecutado)
- [ ] Rollback / compensation is honest
- [ ] Composition checks passed when applicable
- [ ] No unrelated changes
- [ ] Structural constraints respected
- [ ] Traceability established
- [x] E2E black-box del inventario ejecutado en laboratorio
