# A.SPEC 0109-R — Unblock the rootless black-box E2E

> `risk: high` — toca esquema del kernel, red de celdas y superficie pública; exige
> `approver:`. Objetivo: que el **E2E black-box** contra `spanel.lab` pueda pasar de verdad.

## WHY

Los dos E2E de 0109 terminaron en FAIL/BLOCKED con evidencia real:

- `artifacts/0109-apps-rootless-sandbox-e2e.json`: FAIL 3/5. La compuerta del usuario
  (**estrés aislado**) pasó, pero el deploy por API falló: el daemon rootless no tiene
  red/DNS y el build del fixture (`npm install` → `vite`) muere.
- `artifacts/0109-spanel-lab-blackbox-e2e.json`: BLOCKED. El login funciona, pero crear
  tenant devuelve 409 siempre. **Causa raíz diagnosticada en el lab**: `users.is_superadmin`
  es `NOT NULL` sin `DEFAULT` en la BD del lab (drift), el modelo actual ya no mapea esa
  columna legacy, y el `INSERT` de `create_user_for_tenant` la omite →
  `NotNullViolation` → el router lo disfraza de `tenant_conflict`.

Sin estos tres arreglos el black-box no puede pasar, aunque el código de 0109 sea correcto.

## WHAT

**Crear un tenant nuevo funciona, el daemon rootless puede resolver DNS para builds, y el
plan de RAM se puede pedir por superficie pública; con eso el E2E black-box de editor en
2 GB puede ejecutarse de extremo a extremo.**

## SCOPE

### 1. Drift de `users.is_superadmin` (bloqueante del 409)

- Nueva migración **del kernel** en `vendor/systutor-core/migrations/versions/` que:
  - `ALTER TABLE users ALTER COLUMN is_superadmin SET DEFAULT false`, y
  - rellena nulos con `false` si los hubiera.
- El modelo `systutor.kernel.auth.models.User` **sigue sin mapear** `is_superadmin`
  (regla del core: legado, prohibido usarlo para autorización). La BD aporta el default.
- La migración se ejecuta con el **runtime migrador del kernel** (`alembic.ini` +
  `vendor/systutor-core/migrations/`), **nunca con el CLI de Alembic a mano** en desarrollo.
- Test: crear tenant + usuario en BD con el esquema migrado → 201, sin 409.

### 2. Red/DNS para builds en la celda rootless

- `scripts/tenant_cell/network.py` / `executor.py`: pasar `--dns` a `rootlesskit` (resolver
  del host o el del lab, configurable por entorno) y permitir egress controlado para
  `registry.npmjs.org` y el registry de imágenes, sin exponer el host.
- Verificación: `docker run --rm alpine wget https://registry.npmjs.org/vite` dentro del
  socket de la celda → éxito. Sin cambios al daemon global ni a Traefik.

### 3. Pedir RAM por superficie pública

- Exponer el plan de memoria del tenant/app en la API pública (reutilizar
  `AppsTenantPlan` / `POST /plan` de 0101; si no está visible en OpenAPI, añadir el alias
  público correspondiente) para poder solicitar **2 GB** (`memory_bytes=2147483648`) al
  crear el recurso.
- Sin nuevos campos en modelos de `hosting`/`tenant`; el plan ya existe.

## OUT OF SCOPE

- Cambiar `app_deploy.py` (queda para spec de cierre, §8 del plan).
- Quitar los controles anti-root (0112); migrar hosting (0110); correo (0111).
- Cambiar Traefik, PMA, MariaDB, PowerDNS, Docker Mailserver ni su hardening.
- Producción. Repetir los E2E sí entra: GENERATOR + verificación, y el E2E black-box lo
  corre un subagente de laboratorio después.

## CONTRACT

1. `POST /api/v1/plugins/tenant/tenants` con payload único devuelve **201** y el usuario
   se crea con `is_superadmin=false` implícito.
2. La celda rootless resuelve DNS y el build del fixture llega a `running`.
3. La API pública permite pedir `memory_bytes=2147483648`; el cgroup efectivo muestra
   `memory.max=2147483648`.
4. El E2E black-box de `spanel.lab` puede ejecutar: login → tenant nuevo → editor en
   2 GB → HTTP 200 → cgroups → aislamiento → limpieza.

## INVARIANTS

```yaml
invariants:
  - "is_superadmin sigue siendo legado: no se mapea en el modelo ni se usa para autorizacion."
  - "La migracion se ejecuta por el runtime migrador del kernel, nunca por Alembic CLI manual."
  - "El DNS de la celda no expone el daemon global ni permite trafico arbitrario desde el host."
  - "El plan de RAM reutiliza AppsTenantPlan; no se crea un modelo duplicado."
  - "Traefik, MariaDB, PMA, PowerDNS y Docker Mailserver quedan intactos."
  - "El E2E decide PASS/FAIL solo con evidencia externa; no se parchea la app para que pase."
  - "Sin produccion; el tenant de prueba se elimina al final."
```

## VERIFICATION

```bash
PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/tenant/backend/tests -q
python3 -m pytest scripts/tests/test_tenant_cell_provision.py scripts/tests/test_tenant_cell_plan.py -q
ruff check src/systutor/kernel/auth/models.py scripts/tenant_cell/network.py scripts/tenant_cell/executor.py
```

E2E black-box (laboratorio, subagente aparte): `artifacts/0109-spanel-lab-blackbox-e2e.json`
debe pasar con `result: PASS` y `cleanup_verified: true`.

## ROLLBACK

- La migración del kernel es aditiva: revertir el `DEFAULT` devuelve el esquema anterior.
- El DNS de celda se desactiva por entorno; sin él se vuelve al comportamiento actual.
- El alias público del plan se puede desmontar sin tocar datos.

## Change Surface

```yaml
change_surface:
  allowed:
    - vendor/systutor-core/migrations/versions/<nueva>_users_is_superadmin_default.py
    - vendor/systutor-core/src/systutor/kernel/auth/models.py
    - vendor/systutor-core/plugins/apps/backend/router_plans.py
    - scripts/tenant_cell/network.py
    - scripts/tenant_cell/executor.py
    - scripts/tests/test_tenant_cell_provision.py
    - artifacts/0109-spanel-lab-blackbox-e2e.json
  prohibited:
    - vendor/systutor-core/plugins/hosting/**
    - vendor/systutor-core/plugins/tenant/**
    - scripts/phpmyadmin_up.sh
    - docker-compose.yml
    - /opt/stacks/**
```

## Traceability

- Requirement: hacer pasar el E2E black-box de 0109; correcciones 1/2/4 del plan general.
- owner: lucas
- approver: lucas
- Commit: (pendiente de asignar al commitear esta spec).
- Evidence: `artifacts/0109-spanel-lab-blackbox-e2e.json` (**PASS 9/9**,
  `cleanup_verified: true`) — login 200, tenant 201 (antes 409), migración kernel aplicada
  (`20261119_0011`, `is_superadmin DEFAULT false`), deploy real por API con DNS/NAT en la
  celda, editor HTTP 200, `memory.max=2147483648`, socket de celda, uids no-root, Core con
  PID/hash idénticos y limpieza byte-a-byte. 7 gaps de laboratorio documentados en el
  artefacto (cap 512 MB por servicio, NAT adicional, AppArmor de build, DENIED en fases de
  preparación, worker dramatiq, catálogo GitHub tenant-scoped y puente TCP temporal).
- Deployment: laboratorio `spanel.lab`; sin producción.

## Definition of Done

- [x] Objective satisfied (black-box PASS 9/9)
- [x] Contract satisfied
- [x] Invariants preserved
- [x] Verification passed (79 + 40 tests, ruff)
- [x] Rollback honest (entorno restaurado byte-a-byte)
- [x] Evidence artifact PASS + cleanup_verified
