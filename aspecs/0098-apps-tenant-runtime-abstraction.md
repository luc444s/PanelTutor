# A.SPEC 0098 — Abstracción TenantRuntime para Apps (Fase 2)

> `risk: medium` — añade una capa de abstracción en el plugin Apps. No cambia el
> comportamiento por defecto del worker ni del pipeline de releases.

## WHY

La Fase 1 (A.SPEC 0097) ya produce celdas rootless reales con socket propio,
AppArmor efectivo y contenedores con UID 0 funcionando, pero el backend de Apps
sigue usando un `Runner` global que hereda `DOCKER_HOST` del entorno del
worker. Sin una abstracción por tenant, un despliegue no puede seleccionar el
socket de su celda ni aportar evidencia del runtime como parte de la firma de
release.

## WHAT

Existe una abstracción `TenantRuntime` en el plugin Apps que, para un `slug`
validado, expone el socket de su celda, ejecuta comandos contra él y devuelve
el estado observable de la celda (uid map, AppArmor efectivo, hash del perfil).
El worker puede recibir un registro de runtimes inyectado y usar el runtime del
tenant autenticado sin cambiar su comportamiento cuando no se inyecta nada.

## SCOPE

- `vendor/systutor-core/plugins/apps/backend/runtime/tenant_runtime.py`:
  `TenantRuntime` (Protocol), `DockerRootlessRuntime`, `FakeTenantRuntime`,
  `TenantRuntimeRegistry`, resolución `tenant_id -> tenants.slug` desde DB.
- Inyección opcional en `vendor/systutor-core/plugins/apps/backend/worker.py`
  (`runtime_registry`) y en `backend/tasks.py` (parámetro por defecto `None`).
- Tests unitarios en
  `vendor/systutor-core/plugins/apps/backend/tests/test_tenant_runtime.py`.

## OUT OF SCOPE

- Cambiar el comportamiento productivo por defecto del worker o de releases.
- Modificar `probes.py`, `deployment.py`, `releases/*`, `router.py` ni migraciones.
-修改 Compose/Dockerfile, hardener, kernel, stack Docker ni secretos.
- `migrate-legacy` (Fase 3b) y E2E completo.

## CONTRACT

- `TenantRuntime` expone: `slug`, `socket_path`, `environment()`, `status()`,
  `build()`, `up()`, `down()`, `logs()`, `exec_probe()`.
- `DockerRootlessRuntime` deriva la ruta del socket solo de un `slug` validado
  con `^[a-z0-9][a-z0-9-]{0,61}$` y de un `data_root` inyectado; nunca acepta
  rutas arbitrarias ni el socket rootful.
- `status()` lee evidencia real: `uid_map` de `/proc`, AppArmor de
  `/proc/<pid>/attr/current` y el `MainPID` vivo de systemd. Nunca报告
  `effective: true` sin esa evidencia.
- `FakeTenantRuntime` registra llamadas y devuelve estados configurables; no
  ejecuta procesos ni toca filesystem.
- `TenantRuntimeRegistry.for_tenant(tenant_id, slug)` valida el slug y devuelve
  un runtime; el `slug` se resuelve desde la tabla `tenants` de la DB, nunca
  desde el body de una request.
- El worker solo usa el registry cuando se le inyecta; sin él, mantiene
  exactamente el `runner_factory` y transport actuales.
- Ningún archivo nuevo supera 400 líneas. Sin stack traces ni secretos en logs.

## INVARIANTS

```yaml
invariants:
  - "El comportamiento por defecto del worker y de ReleaseExecution permanece byte-idéntico salvo la adición de un parámetro opcional."
  - "slug se valida antes de derivar cualquier ruta; un tenant no puede alcanzar el socket de otro."
  - "status.apparmor.effective es true solo si /proc/<pid>/attr/current contiene el perfil de la celda en enforce."
  - "Se respeta la regla del repo: prohibido Alembic; no se crean migraciones en esta fase."
  - "El runtime inyectado nunca sustituye la firma/verificación de releases, RBAC ni auditoría."
```

## VERIFICATION

```bash
.venv/bin/python -m ruff check vendor/systutor-core/plugins/apps/backend/runtime/tenant_runtime.py vendor/systutor-core/plugins/apps/backend/worker.py vendor/systutor-core/plugins/apps/backend/tasks.py vendor/systutor-core/plugins/apps/backend/tests/test_tenant_runtime.py
PYTHONPATH=vendor/systutor-core:. .venv/bin/python -m pytest vendor/systutor-core/plugins/apps/backend/tests -q
PYTHONPATH=vendor/systutor-core:. .venv/bin/python -m pytest scripts/tests/test_tenant_cell_doctor.py scripts/tests/test_tenant_cell_provision.py -q
```
