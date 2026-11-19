# Informe final — A.SPEC 0109-R4: deploy rootless de software para editores

Fecha: 2026-11-19
Rama: `remove-hardener`
Commit: `672b0ca` — `feat(apps): A.SPEC 0109-R4 rootless deploy, owned hosts and probe fix`
Laboratorio: `spanel.lab` (`lucas@100.67.5.50`, Docker 29.1.3, cgroups v2, AppArmor enforce)

## 1. Resumen ejecutivo

Se ejecutó un **E2E black-box scriptado** que despliega
`luc444s/software-de-gestion-para-editores@feature/workflow-diseno` a través de
la API HTTP y el worker Dramatiq reales, en una **celda rootless real**, y
verifica de forma independiente qué daemon ejecuta cada contenedor.

**Resultado: PASS acotado.**

- Los 3 servicios de la release (`backend`, `database`, `frontend`) quedaron
  `running`/`healthy` en el daemon de la celda.
- Ninguno de los 3 existía en el daemon rootful.
- Un probe independiente desde dentro de la celda devolvió **HTTP 200**.
- Un segundo deploy activó una fila nueva y el **rollback restauró la misma
  release firmada**, con los contenedores todavía en la celda.
- La limpieza eliminó BD/colas/celda/usuarios y restauró los ficheros de estado
  del host **byte a byte** (5/5 hashes).

Evidencia: `artifacts/0109-r4-editors-rootless-blackbox-e2e.json`.

> **Alcance:** este E2E es acotado. **No sustituye** al artefacto oficial de 4
> checks (`artifacts/0109-r4-host-nat-and-domains-owned-hosts-e2e.json`), que
> sigue `BLOCKED 2/4`: los checks 3 y 4 y el downgrade de la migración 005 no
> se re-ejecutaron en este run.

## 2. Objetivo y método

Objetivo: probar de punta a punta que el software real de editores se ejecuta
en **su entorno rootless correspondiente**, sin fabricar PASS ni inferir
evidencia.

Método: un único script (`scripts/e2e_0109_r4_blackbox.py`) con fases
`setup`/`run`/`cleanup`:

1. Clona la BD viva en una BD desechable y cambia el slug del tenant demo al
   slug de la celda.
2. Provisiona una celda rootless real con la CLI (`provision --slug`).
3. Levanta API, worker Dramatiq y Redis desechables; el worker monta el socket
   de la celda y ejecuta con `SPANEL_TENANTS_ROOTLESS=true`.
4. Hace login real, crea la aplicación, inspecciona el repositorio y despliega
   por la API/worker reales.
5. Verifica contenedores, probe HTTP, segundo deploy y rollback.
6. Borra la aplicación, retira la celda, elimina la BD desechable y restaura el
   estado del host.

El estado del host (registro de celdas, planes, auditoría, `/etc/subuid`,
`/etc/subgid`) se respalda antes de empezar y se compara por hash al final.

## 3. Causa raíz corregida

El bloqueo previo del check 3 **no** era un problema de runtimes mezclados:
deploy y probe comparten el mismo `Runner` tenant-scoped y el mismo
`runner.environ` (verificado en código y en la celda).

La causa real era la política del probe: se ejecutaba con `--read-only`, y el
remount de `/` que eso provoca es denegado por AppArmor dentro de la celda:

```
error setting rootfs as readonly: ... MS_RDONLY|MS_REMOUNT|MS_BIND: permission denied
```

El probe moría con exit 126 antes de `curl`; el reintento de 180 s mantenía la
operación en `running/claim`.

Corrección:

- `runtime/probes.py`: el baseline `rootless` usa un rootfs escribible efímero
  conservando digest fijado, uid 65534, `cap-drop ALL`, `no-new-privileges` y
  límites. El baseline hardened/rootful conserva `--read-only`. La evidencia
  registra el valor efectivo de `read_only`.
- `runtime/tenant_runtime.py`: `DockerRootlessRuntime.environment()` fija
  juntos `DOCKER_HOST` (socket de la celda) y
  `SPANEL_APPS_PROBE_BASELINE=rootless`, para que no puedan contradecirse.
- Regresión en `test_probes.py`, `test_tenant_runtime.py` y
  `test_rootless_worker.py`.

## 4. Cambios incluidos en el commit

- **Celda/red**: `scripts/tenant_cell/{cells,executor,host_agent,network}.py`
  — NAT de egreso por celda usando el PID real de dockerd, hosts propios,
  ciclo de vida y perfiles.
- **Apps backend**: `register.py`, `rootless_routes.py`,
  `runtime/{probes,tenant_runtime}.py` — runner tenant-scoped, publicación de
  rutas rootless y política de probe por baseline.
- **Dominios**: plugin `domains` (modelos, router, schemas, servicio, README) y
  migración `005_rootless_app_hosts.py` + contrato
  `systutor/contracts/app_hosts.py` para hosts de aplicación propios.
- **E2E**: `scripts/e2e_rootless_cell.py` (probe real de readiness) y nuevos
  `scripts/e2e_0109_r4_blackbox.py` + `scripts/e2e_dramatiq_worker.py`.
- **Docs/evidencia**: A.SPEC 0109-R4, artefacto oficial (BLOCKED 2/4),
  informe de progreso y nuevo artefacto del E2E acotado.

## 5. Entorno del E2E

| Elemento | Valor |
|---|---|
| Host | `lucas-ThinkPad-E570`, kernel 7.0.0-28, cgroups v2, AppArmor enforce |
| Aislamiento | BD clonada, API/worker/Redis desechables, celda rootless real, fixture GitHub real |
| Fixture | `luc444s/software-de-gestion-para-editores` @ `feature/workflow-diseno`, `docker-compose.dokploy.yml` |
| Commit del fixture | `ae33f9d10f6263d975bcb1bfdb8650a7021dff23` |
| Celda | `e2e0109r4v3`, `state=ready`, AppArmor efectivo, `uid_map` observado |
| BD desechable | `sysadmin_e2e0109r4v3` (eliminada al final) |
| Release | `9e5b0e3e-8593-4730-8324-3e388a558336` |
| Deploy (operación) | `9e5b0e3e-8593-4730-8324-3e388a558336`, `succeeded/complete` |
| Ventana deploy | 2026-11-19T20:28:03Z → 2026-11-19T20:28:49Z |

## 6. Resultados y evidencia

### 6.1 Deploy y aislamiento

Aplicación temporal `8fafb6fb-a67b-44dc-9a89-1062067945c3`
(`e2e-software-editores-2653fc5f`, tenant demo clonado).

| Servicio | Contenedor | Estado | Health | ¿En rootful? |
|---|---|---|---|---|
| backend | `05d8422f…ba6` | running | healthy | no |
| database | `db3b9f05…2b2` | running | healthy | no |
| frontend | `52afb1f1…098` | running | healthy | no |

Red de la release: `app-8b10e0362844481bb5f3afb0_default`.
Daemon de los 3 contenedores:
`/var/lib/spanel/cells/e2e0109r4v3/docker.sock`.

La comprobación de ausencia en el daemon rootful se hizo con
`docker inspect <id>` contra el socket rootful: los 3 devolvieron "no such
object".

### 6.2 Probe independiente

```
docker -H unix:///var/lib/spanel/cells/e2e0109r4v3/docker.sock run --rm \
  --network app-8b10e0362844481bb5f3afb0_default --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 64 --memory 128m \
  --cpus 1 --user 65534:65534 curlimages/curl@sha256:d9b4541e… \
  curl -sS -o /dev/null -w '%{http_code}' http://frontend:8080/
```

Resultado: **`200`**.

### 6.3 Rollback

- Primer deploy → deployment `91748ee3-1838-4b32-b53d-7a20cf1a799f`.
- Segundo deploy → deployment `fea1662e-52f1-4602-9cf1-32083e113271`.
- Rollback (`dec4b40b-feb4-4ed1-a56e-b9cfdbeb9083`,
  `succeeded/complete`) hacia `91748ee3…`.
- El rollback crea una **fila de deployment nueva**
  (`2ebc6753-3848-45f2-8cd9-419a9024f36e`) que reutiliza la **misma release
  firmada** y el mismo commit. La verificación compara la release firmada, no
  el id de fila.
- Los 3 contenedores siguen en la celda tras el rollback.

### 6.4 Limpieza verificada

- `deprovision --purge-data` → `state=retired`, `data_kept=false`.
- Eliminados: home, `/run/user/<uid>`, directorio de celda, usuario huérfano y
  los 4 `/run/user` residuales de probes anteriores.
- BD `sysadmin_e2e0109r4v3` eliminada.
- Contenedores desechables (`app`, `worker`, `redis`) eliminados.
- Sin celdas, usuarios ni contenedores `e2e` restantes.
- Hashes restaurados (idénticos antes/después):

| Fichero | SHA-256 |
|---|---|
| `/var/lib/spanel/registry.json` | `a3503ea9dcb53aab65945d2338c7493b90fb3bec539a932f57fe7f53f8dac6e6` |
| `/var/lib/spanel/plans.json` | `dc2a7b9b3c39489c74560313c649da499e5a991b368311e052232b687f8f831f` |
| `/var/lib/spanel/audit.jsonl` | `42660f20de2e3ac590575b0c0992a01d54b54c06fe4825968d427682dba98bfd` |
| `/etc/subuid` | `8a0a1343bb0126dbc43686512b3ccb5d2abb0ec1ddbb215957d8a8f1a995940d` |
| `/etc/subgid` | `8a0a1343bb0126dbc43686512b3ccb5d2abb0ec1ddbb215957d8a8f1a995940d` |

## 7. Calidad

- Tests focales (probes, runtime, worker rootless, rutas rootless, app hosts,
  provisión de celda): **117 passed**.
- `py_compile` de todos los módulos tocados: OK.
- `git diff --check`: OK.
- `ruff` no está disponible en Termux; gate no ejecutable en este entorno
  (limitación de herramienta, no del cambio).

## 8. Incidencias del harness y correcciones

Durante la construcción del script aparecieron fallos **del propio harness**,
corregidos antes de la evidencia final:

1. El worker no importaba `systutor.contracts.app_hosts`: el `PYTHONPATH`
   apuntaba a una ruta del host no visible dentro del contenedor. Se corrigió
   el montaje/`PYTHONPATH`.
2. El límite de 600 s de Dramatiq abortaba builds fríos. Se añadió
   `scripts/e2e_dramatiq_worker.py`, que eleva solo el `TimeLimit` (sin quitar
   middleware).
3. Una re-provisión sobre una celda ya degradada no reiniciaba el daemon
   (`applied.daemon=true`). El script ahora reintenta `provision` de forma
   idempotente y la limpieza para el `user@<uid>` antes de `userdel`.
4. La primera aserción de rollback comparaba ids de fila; el rollback crea una
   fila nueva con la misma release. Se corrigió para comparar la **release
   firmada**.
5. `E2E` heredaba de `BaseException`, por lo que un fallo podía escribirse como
   `ok: true`. Ahora hereda de `Exception` y un fallo nunca produce PASS.

## 9. Reproducción

```bash
# En el laboratorio, como root, con el árbol de trabajo en /var/tmp/spanel-e2e-0109r4
python3 scripts/e2e_0109_r4_blackbox.py \
  --stage /var/tmp/spanel-e2e-0109r4 \
  --phase all \
  --evidence /var/tmp/0109-r4-run.json
```

El script hace `setup + run + cleanup`. Si un paso falla, el estado se escribe
en el JSON de evidencia y no se declara PASS.

## 10. Limitaciones y pendientes

- El artefacto oficial de 4 checks sigue **`BLOCKED 2/4`**. Este informe cubre
  el deploy real en celda rootless, el probe y el rollback, pero **no** los
  checks 3/4 completos ni el downgrade de la migración 005.
- Los documentos de R3 (`aspecs/0109-r3-*`, `artifacts/0109-r3-*`) quedan
  fuera del commit por pertenecer a otra fase.
- El commit es local (`672b0ca`); no se ha hecho push.

## 11. Referencias

- Evidencia E2E acotada:
  `artifacts/0109-r4-editors-rootless-blackbox-e2e.json`
- Artefacto oficial (BLOCKED 2/4):
  `artifacts/0109-r4-host-nat-and-domains-owned-hosts-e2e.json`
- Progreso y diagnóstico: `artifacts/0109-r4-progress.md`
- A.SPEC: `aspecs/0109-r4-host-nat-and-domains-owned-hosts.md`
- Script: `scripts/e2e_0109_r4_blackbox.py`
