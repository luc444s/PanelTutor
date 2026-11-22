# Informe final — A.SPEC 0109-R4: deploy rootless de software para editores

Fecha: 2026-11-19
Rama: `remove-hardener`
Commit base: `672b0ca` — `feat(apps): A.SPEC 0109-R4 rootless deploy, owned hosts and probe fix`
Laboratorio: `spanel.lab` (Docker 29.1.3, cgroups v2, AppArmor enforce)

## 1. Resumen ejecutivo

Se ejecutó un **E2E black-box scriptado** en una **celda rootless real** que
despliega `luc444s/software-de-gestion-para-editores@feature/workflow-diseno`
a través de la API HTTP y el worker Dramatiq reales, y verifica de forma
independiente los cuatro checks del A.SPEC, el downgrade de la migración 005 y
la restauración del estado del host.

**Resultado: PASS completo (4/4 checks + downgrade 005 + limpieza verificada).**

- Check 1: egreso dentro de la celda con NAT propio (`172.17.0.0/16`), sin regla
  nueva en el host, `NET_OK`, 8 reglas de auditoría AppArmor preservadas y delta
  real de denegaciones 0.
- Check 2: plan de 2 GiB aplicado antes del primer deploy, 3 servicios en la
  celda, `715827882` bytes por servicio y cgroup con `memory.max=2147483648`,
  `cpu.max=100000 100000`, `pids.max=512`.
- Check 3: Host de Dominios publicado sin puente TCP manual: app-host `201`,
  outbox real procesó 13 eventos, listener de la celda en
  `127.71.1.1:20070`, listener del relay en `172.25.0.1:40070`, YAML gestionado
  válido y `HTTP 200` con `Host: editores-e2e0109r4v12.lab`.
- Check 4: segundo deploy real, rollback a la **misma release firmada**, ruta y
  runtimes restaurados, fixture rootful intacto y reinicio con
  `SPANEL_TENANTS_ROOTLESS=false` que **no reescribe** las filas de runtime.
- Downgrade 005: ejecutado con el runtime migrador del kernel; versión vuelve a
  `004_create_cloudflare_oauth`, `domains_app_hosts` desaparece y el campo legacy
  `apps_applications.domain` sigue presente con los mismos valores.
- Limpieza: celda/BD/usuarios/agentes retirados; los 5 hashes de estado del host
  idénticos antes/después; Core y fixture rootful intactos; sin errores.

Evidencia oficial:
`artifacts/0109-r4-host-nat-and-domains-owned-hosts-e2e.json`
(`ok: true`, `result: PASS`).

## 2. Objetivo y método

Objetivo: probar de punta a punta que el software real de editores se ejecuta en
**su entorno rootless correspondiente**, sin fabricar PASS ni inferir evidencia.

Método: un único script (`scripts/e2e_0109_r4_blackbox.py`) con fases
`setup`/`run`/`cleanup` y un ambiente desechable:

1. Clona la BD viva en una BD desechable y cambia el slug del tenant demo al
   slug de la celda.
2. Provisiona una celda rootless real con la CLI (`provision --slug`).
3. Levanta API, worker Dramatiq, Redis, plan-agent y edge-relay desechables; el
   worker monta el socket de la celda y ejecuta con
   `SPANEL_TENANTS_ROOTLESS=true`.
4. Hace login real, crea la aplicación, inspecciona el repositorio y despliega
   por la API/worker reales.
5. Ejecuta los 4 checks, el downgrade 005 y el borrado de la aplicación por API.
6. Retira los agentes, la celda, la BD desechable y restaura el estado del host.

El estado del host (registro de celdas, planes, auditoría, `/etc/subuid`,
`/etc/subgid`) se respalda antes de empezar y se compara por hash al final.

## 3. Causas raíz corregidas en esta fase

### 3.1 Check 3 — publicación real del ingress

El producto no publicaba el puerto de la celda en el ingress. Se añadió
publicación real desde el worker:

- `rootless_routes.endpoint(slug)` expone loopback/puerto de la celda.
- `worker._ingress_publish()` propaga `(service, host, port, target_port)` a
  deploy y rollback.
- `deployment._override()` inyecta el binding loopback y una red dedicada
  `spanel-ingress`; `scoped_execution` construye el publish.

Causa raíz del listener ausente: el port-driver de rootlesskit **no abre
listener** cuando el contenedor está en una red Docker `internal: true`. Se
verificó manualmente en el laboratorio (`NO_LISTENER` vs `LISTEN ...
rootlesskit`). La solución mantiene backend/database en la red interna y pone
solo el frontend/ingress en `spanel-ingress`, no interna. `probes.py` autoriza
bindings loopback únicamente en baseline rootless y lee también las redes del
`override.yaml`.

### 3.2 Check 3 — YAML inválido para Traefik

Una ruta HTTP-only se renderizaba con `middlewares: {}`. Traefik rechaza ese
mapa vacío como elemento standalone y **descarta el fichero entero**, por lo que
devolvía 404 aunque los dos listeners estuvieran arriba. El renderer ahora omite
la clave cuando no hay middlewares. Regresión en `test_routes_render.py` y
`test_rootless_routes.py`.

### 3.3 Check 4 — rollback sin plan de recursos

El rollback reutiliza el override del primer deploy (con límites de 2 GiB), pero
la ejecución del rollback no vinculaba el `resource_plan` del tenant. El probe
volvía al presupuesto por defecto de 512 MB y rechazaba el backend. Ahora
`ReleaseExecution._resource_plan()` se usa tanto en deploy como en rollback.
Regresión cubierta por la suite de apps.

### 3.4 Limpieza de la ruta al borrar la aplicación

El worker construía `RootlessRoutes` sin el objeto `app`, así que no podía
resolver los `app-host` de Dominios y su cleanup no retiraba el YAML gestionado.
`tasks.py` ahora inyecta `build_rootless_routes(app)`. El check verifica
`route_removed_by_product: true`.

### 3.5 Harness

- El dispatcher del outbox se invoca como `/stage/dispatch_outbox.py` (ruta
  montada dentro de la app), no como ruta del host.
- Tras cada reinicio con bandera `false`/`true` se espera a que los plugins
  vuelvan a estar habilitados antes de consultar la API.
- El check de dmesg usa el delta real `max(0, after-before)`.
- El rollback se compara por **release firmada**, no por id de fila.
- `E2E` hereda de `Exception`: un fallo nunca produce `ok: true`.

## 4. Entorno del E2E

| Elemento | Valor |
|---|---|
| Host | `lucas-ThinkPad-E570`, cgroups v2, AppArmor enforce |
| Aislamiento | BD clonada, API/worker/Redis/agentes desechables, celda rootless real, fixture GitHub real |
| Fixture | `luc444s/software-de-gestion-para-editores` @ `feature/workflow-diseno`, `docker-compose.dokploy.yml` |
| Commit del fixture | `ae33f9d10f6263d975bcb1bfdb8650a7021dff23` |
| Celda | `e2e0109r4v12`, `state=ready`, AppArmor efectivo, uid/gid 60070 |
| BD desechable | `sysadmin_e2e0109r4v12` (eliminada al final) |
| App temporal | `a291b616-0292-4beb-a1f7-31469a6897b3` (`e2e-software-editores-bfcff340`) |
| Release | `66db4f7f-4c5f-494c-92b2-b60247ec0f35` |
| Primer deployment | `ec6166e4-fc8c-47b2-bbaf-51b9e9a2dde7` (operación `succeeded/complete`) |
| Rollback | deployment restaurado `20873c0f-118e-4455-8d3d-0bbae9c347ab`, misma release |

## 5. Resultados por check

### 5.1 Check 1 — egreso sin NAT manual

- `dockerd` de la celda: PID `265099`, netns `net:[4026532709]`; host
  `net:[4026531833]`.
- POSTROUTING dentro de la celda:
  `-A POSTROUTING -s 172.17.0.0/16 -j MASQUERADE`.
- `host_rule_absent: true` (ninguna regla nueva en el host).
- Egreso desde la celda: exit 0, salida `NET_OK`.
- AppArmor: 8 reglas de auditoría preservadas; dmesg pass 4 → 4, delta 0.
- Unidad: `/etc/systemd/user/spanel-cell-e2e0109r4v12.service`, sin
  `ExecStartPost` manual.

### 5.2 Check 2 — plan agregado de 2 GiB desde el primer deploy

Plan aplicado antes del deploy:

- `memory_bytes: 2147483648`, `cpus: 1.0`, `pids: 512`.
- Slice `tenant-e2e0109r4v12.slice`, estado `applied`.
- Cgroup del runtime: `memory.max=2147483648`, `cpu.max=100000 100000`,
  `pids.max=512`.

Deploy:

- 3 servicios: `backend`, `database`, `frontend`.
- Memoria por servicio: `715827882` bytes en los tres.
- Todos en la celda rootless, `user_namespace: true`, `runtime: runc`.
- `frontend` en `default` + `spanel-ingress` (no interna); backend y database
  solo en la red interna `app-..._default`.

Nota: `/plan/verify` devolvió un 502 transitorio y el harness lo reintenta sin
bloquear; la evidencia autoritativa del check es el plan aplicado + cgroups +
manifiesto, que sí convergen.

### 5.3 Check 3 — Host de Dominios sin puente TCP

- `POST /plugins/domains/app-hosts` → `201`.
- Outbox real: 13 eventos procesados, 0 fallos.
- Dominio: `editores-e2e0109r4v12.lab`.
- Listener de celda: `127.71.1.1:20070` (`rootlesskit`).
- Listener del relay: `172.25.0.1:40070`, fuente `172.25.0.3`.
- Documento gestionado `spanel-route-*.yml` con router `web`, sin TLS y sin
  `middlewares` vacío.
- `curl -H 'Host: editores-e2e0109r4v12.lab' http://127.0.0.1:9080/` →
  **HTTP 200**, cuerpo de 394 bytes, título `Panel Editor`.
- `manual_tcp_bridge: false`.

### 5.4 Check 4 — rollback, fixture rootful y bandera `false`

- Segundo deploy real (`succeeded/complete`), fila de deployment nueva.
- Rollback `succeeded/complete` hacia la **misma release firmada**
  (`66db4f7f…`) y el mismo commit `ae33f9d…`.
- Ruta y runtimes restaurados; los 3 contenedores siguen en la celda.
- Fixture rootful intacto antes/después (mismos ids y estados).
- Reinicio con `SPANEL_TENANTS_ROOTLESS=false`:
  - filas de runtime antes y después idénticas
    (`backend/database/frontend = rootless`);
  - contenedores de la celda siguen `Up (... healthy)`;
  - release activa visible por API;
  - sin error de API (`flag_false_api_error: null`).

### 5.5 Downgrade 005

Ejecutado con el runtime migrador del kernel (`downgrade_plugin`) dentro de la
app, no con Alembic CLI:

- `domains_app_hosts` antes: 1 fila; después: tabla inexistente
  (`to_regclass` vacío).
- `plugin_registry.migration_version`: `004_create_cloudflare_oauth`.
- Columna legacy `apps_applications.domain`: presente; valores antes/después
  idénticos (vacíos en el clon).

Observación: el endpoint HTTP legacy
`/api/v1/plugin-runtime/domains/migrate/downgrade` responde 200 pero su refresh
posterior vuelve a subir el plugin a 005. El A.SPEC exige el **runtime
migrador**; el E2E ejerce `downgrade_plugin()` directamente, que es la
superficie correcta y no re-sube la migración.

### 5.6 Limpieza verificada

- Celda retirada (`state=retired`, `data_kept=false`), BD eliminada, usuario y
  directorios eliminados.
- Agentes `plan-agent` y `edge-relay` detenidos sin procesos residuales.
- Ruta gestionada retirada por el producto (`route_removed_by_product: true`).
- `cleanup_verified: true`, `cleanup_errors: []`.
- `core_intact: true`, `rootful_fixture_intact: true`, `gaps: []`.
- Hashes idénticos antes/después:

| Fichero | SHA-256 |
|---|---|
| `/var/lib/spanel/registry.json` | `a3503ea9dcb53aab65945d2338c7493b90fb3bec539a932f57fe7f53f8dac6e6` |
| `/var/lib/spanel/plans.json` | `dc2a7b9b3c39489c74560313c649da499e5a991b368311e052232b687f8f831f` |
| `/var/lib/spanel/audit.jsonl` | `42660f20de2e3ac590575b0c0992a01d54b54c06fe4825968d427682dba98bfd` |
| `/etc/subuid` | `a295d25cb1976270021673a8612ed9d49f5131b9245097d29915f77da427d113` |
| `/etc/subgid` | `a295d25cb1976270021673a8612ed9d49f5131b9245097d29915f77da427d113` |

## 6. Calidad

- Suite focal (apps rootless/planes/probes/worker, dominios rutas/app-hosts,
  provisión/plan/relay de celda): **227 passed**.
- `py_compile` de todos los módulos tocados y del script E2E: OK.
- `git diff --check`: OK.
- `ruff` no está disponible en Termux; gate no ejecutable en este entorno
  (limitación de herramienta, no del cambio).

## 7. Reproducción

```bash
# En el laboratorio, como root, con el árbol de trabajo en
# /var/tmp/spanel-e2e-0109r4
python3 scripts/e2e_0109_r4_blackbox.py \
  --stage /var/tmp/spanel-e2e-0109r4 \
  --slug e2e0109r4v12 \
  --phase all \
  --evidence /var/tmp/0109-r4-final-v12.json
```

El script hace `setup + run + cleanup`. Si un paso falla, el estado se escribe
en el JSON de evidencia y no se declara PASS.

## 8. Limitaciones y pendientes

- El commit es local; **no se ha hecho push**.
- Los documentos de R3 (`aspecs/0109-r3-*`, `artifacts/0109-r3-*`) quedan fuera
  del commit por pertenecer a otra fase.
- El endpoint HTTP legacy de downgrade tiene el comportamiento de re-subida
  descrito en 5.5; el runtime migrador directo es el que usa y exige el A.SPEC.
- El E2E usa el directorio dinámico del Traefik del laboratorio y agentes
  desechables; no toca producción.

## 9. Cierre operativo posterior (R5)

Los drills operativos de Apps (concurrencia, reinicio de worker, soak con
retención, OOM, HTTPS y backup/restore) se cerraron en una fase posterior:

- Informe: `artifacts/0109-r5-informe-operativo.md`
- Evidencia: `artifacts/0109-r5-operations-e2e.json` (`ok: true`, 6/6 drills)
- Base operativa: commit `3aaee3a`

## 10. Referencias

- Evidencia oficial (PASS):
  `artifacts/0109-r4-host-nat-and-domains-owned-hosts-e2e.json`
- Evidencia E2E acotada previa:
  `artifacts/0109-r4-editors-rootless-blackbox-e2e.json`
- Progreso y diagnóstico: `artifacts/0109-r4-progress.md`
- A.SPEC: `aspecs/0109-r4-host-nat-and-domains-owned-hosts.md`
- Script: `scripts/e2e_0109_r4_blackbox.py`
