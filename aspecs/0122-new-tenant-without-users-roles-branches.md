# A.SPEC 0122 — Tenants nuevos sin Users, Roles ni Branches

## Problema

Al crear un tenant nuevo, el owner recibe el rol `tenant_admin`, cuyo conjunto
base incluye `core.users.read`, `core.roles.read`, `core.roles.manage` y
`core.branches.read`. El sidebar y el router del frontend comprueban exactamente
esas claves (`apps/web/src/features/shell/navigation.ts:50-64` y
`apps/web/src/app/router.tsx:87-103`), así que aparecen **Users**, **Roles** y
**Branches** en el menú del tenant.

La lista está hardcodeada en el kernel:

```python
# vendor/systutor-core/src/systutor/kernel/permissions/service.py:300-309
TENANT_ADMIN_BASE_PERMISSIONS = (
    "core.plugin.runtime.read",
    "core.users.read",
    "core.users.create",
    "core.users.update",
    "core.users.disable",
    "core.roles.read",
    "core.roles.manage",
    "core.branches.read",
)
```

`sync_tenant_admin_role()` (mismo archivo, líneas 312-373) la une con los
permisos declarados por los manifests de plugins. Ningún plugin declara
permisos `core.*` en `tenant_admin_permissions` (el contrato exige el namespace
del plugin), así que esta tupla es la única fuente.

## Contrato

1. Reducir `TENANT_ADMIN_BASE_PERMISSIONS` a:

   ```python
   TENANT_ADMIN_BASE_PERMISSIONS = ("core.plugin.runtime.read",)
   ```

   `core.plugin.runtime.read` se conserva: sin él el frontend no carga la
   navegación de plugins (A.SPEC 0012).

2. `BASE_PERMISSIONS` de `src/systutor/api/seed.py:20-44` **no se toca**: el
   administrador de plataforma sigue teniendo Users, Roles y Branches.

3. `sync_tenant_admin_role()` sigue siendo **aditivo e idempotente**
   (A.SPEC 0012/0045): no revoca permisos. Por tanto los tenants **existentes**
   conservan Users/Roles/Branches; el cambio afecta solo a tenants creados
   después del deploy. Si se quiere quitar también a los existentes, se hará
   explícitamente con `PATCH /core/roles/{id}` o con la API de RBAC de tenant,
   en una operación separada.

4. Quitar permisos de la base del tenant_admin implica también que los
   endpoints `/core/users`, `/core/roles` y `/core/branches` dejan de estar
   autorizados para el owner; no es solo ocultar el menú. Los permisos
   específicos de plugins (`hosting.users.read`, `mail.accounts.*`, etc.) no
   se tocan.

5. No hay cambios de esquema, migraciones ni banderas nuevas.

## Criterios de aceptación

- Un tenant creado después del deploy recibe `tenant_admin` con solo
  `core.plugin.runtime.read` más los `tenant_admin_permissions` declarados por
  plugins; no recibe `core.users.*`, `core.roles.*` ni `core.branches.*`.
- En el sidebar de ese tenant no aparecen Users, Roles ni Branches, y las rutas
  `/app/settings/users`, `/app/settings/roles` y `/app/settings/branches` son
  inaccesibles por `PermissionBoundary`.
- Un tenant existente con esos permisos no los pierde al reiniciar la app
  (`sync` aditivo).
- El administrador de plataforma conserva todos los permisos de
  `BASE_PERMISSIONS`.

## Pruebas

- Actualizar `vendor/systutor-core/tests/test_hosting_core_foundation.py:182`:
  en vez de exigir `{"core.users.read", "core.roles.manage"} <= granted`,
  exigir que **no** estén en `granted`.
- Añadir en `vendor/systutor-core/tests/test_tenant_admin_role_sync.py` un test
  que cree un tenant, llame a `sync_tenant_admin_role` sin `permissions` y
  verifique que el rol resultante no contiene `core.users.*`, `core.roles.*` ni
  `core.branches.*`, pero sí `core.plugin.runtime.read`.
- El test existente `test_application_boot_does_not_rewrite_existing_tenant_role`
  sigue pasando (no revocación).
- Ejecutar `python3 -m pytest vendor/systutor-core/tests -q` y
  `ruff check vendor/systutor-core/src/systutor/kernel/permissions/service.py vendor/systutor-core/tests/test_tenant_admin_role_sync.py vendor/systutor-core/tests/test_hosting_core_foundation.py`.

## Notas

- No hacer commit: el revisor integra y commitea.
- No desplegar en producción; validar en `spanel.lab`.
- Este cambio modifica una constante pública del namespace `systutor.kernel`;
  por la regla de `vendor/systutor-core/AGENTS.md` va acompañado de esta A.SPEC
  y tests.
