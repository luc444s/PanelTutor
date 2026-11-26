# A.SPEC 0123 — El owner del tenant puede borrar sus propios contenedores

## Problema

Junto con A.SPEC 0122 (nuevos tenants sin Users/Roles/Branches), el owner no
puede borrar los contenedores de su propio tenant. Los permisos de borrado
están hardcodeados como **platform-only** en los manifests:

- `plugins/hosting/plugin.json:25-28`: `hosting.sites.delete` en
  `platform_permissions`, ausente de `tenant_admin_permissions` (líneas 18-24).
  Además `hosting/backend/router.py:387` exige
  `require_permission("hosting.sites.delete", platform_only=True)`.
- `plugins/apps/plugin.json:26-30`: `apps.applications.delete` en
  `platform_permissions`, ausente de `tenant_admin_permissions` (líneas 19-25).
  `apps/backend/router.py:632-633` además rechaza explícitamente cualquier
  contexto no platform con `403 apps.platform_required`.
- `plugins/apps/frontend/pages/AppsPage.tsx:35` usa `canPlatformMutate()`, que
  exige además `core.platform.admin` (`frontend/logic.ts:281-283`).

El resultado: aunque el owner tiene `hosting.sites.manage` y
`apps.applications.manage`, no puede eliminar sitios ni aplicaciones propias.

## Contrato

1. Mover `hosting.sites.delete` de `platform_permissions` a
   `tenant_admin_permissions` en `plugins/hosting/plugin.json`. Mantenerlo en
   `permissions`. `hosting.profiles.manage` permanece platform-only.
2. Mover `apps.applications.delete` de `platform_permissions` a
   `tenant_admin_permissions` en `plugins/apps/plugin.json`. Mantenerlo en
   `permissions`. `apps.deployments.create` y `apps.plans.manage` permanecen
   platform-only.
3. `hosting/backend/router.py:387`: quitar `platform_only=True`. La ruta ya
   depende de `get_owned_site` (línea 385), que restringe el sitio al tenant
   del contexto: el owner solo puede borrar **sus** sitios.
4. `apps/backend/router.py:632-633`: eliminar el bloque
   `if not context.is_platform: raise AppError(...)`. La llamada a
   `catalog.get_application(db, context.current_tenant_id, application_id)`
   (línea 634) ya restringe la aplicación al tenant actual, así que no hay
   escalada cross-tenant. El `body.confirm == app.slug` y el audit siguen
   igual.
5. `apps/frontend/pages/AppsPage.tsx:35`: usar
   `permissions.includes("apps.applications.delete")` en vez de
   `canPlatformMutate(...)`. La función `canPlatformMutate` se conserva (sus
   tests siguen pasando), pero deja de usarse para este botón.
6. No se cambia `TENANT_ADMIN_BASE_PERMISSIONS` de la A.SPEC 0122, no hay
   cambios de esquema, Alembic ni migraciones.

## Criterios de aceptación

- Un tenant nuevo recibe `hosting.sites.delete` y `apps.applications.delete`
  en su rol `tenant_admin` (vía los `tenant_admin_permissions` declarados).
- El owner puede borrar un sitio Hosting o una aplicación propios desde el
  panel; un tenant no puede borrar recursos de otro tenant (queda garantizado
  por `get_owned_site` y por `catalog.get_application(..., current_tenant_id, ...)`).
- Las acciones platform-only restantes (`hosting.profiles.manage`,
  `apps.deployments.create`, `apps.plans.manage`, `tenant.tenants.manage`)
  siguen sin concederse al tenant_admin.
- La intersección entre `platform_permissions` y `tenant_admin_permissions`
  sigue vacía (INVARIANTE I6).

## Pruebas

- Actualizar `vendor/systutor-core/tests/test_plugin_permission_runtime_sync.py:107`:
  `hosting.sites.delete` debe estar en `tenant_admin_permissions` y **no** en
  `platform_permissions`; `hosting.profiles.manage` sigue en platform.
- Añadir un test para el manifest de `apps` con las mismas comprobaciones.
- Añadir un test de RBAC: un `tenant_admin` con los permisos declarados puede
  invocar el borrado de un sitio propio y no el de otro tenant.
- Añadir un test en `apps/frontend/logic.test.ts` o el test equivalente del
  botón de borrado para confirmar que el guard ya no exige
  `core.platform.admin`.
- Ejecutar `python3 -m pytest vendor/systutor-core/tests -q` y
  `python3 -m pytest vendor/systutor-core/plugins/hosting/backend/tests -q`.

## Notas

- No hacer commit: el revisor integra y commitea.
- No desplegar en producción; validar en `spanel.lab` primero.
- Los tenants existentes **no reciben** automáticamente estos permisos: el sync
  de manifests es aditivo sobre la base, pero los roles ya creados solo se
  actualizan en el arranque según lo declarado. Verificar en el lab que el
  backfill ocurre; si no, aplicar `replace_role_permissions` por tenant.
