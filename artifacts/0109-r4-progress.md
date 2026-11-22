# Informe E2E black-box 0109-R4 (reintento; diagnóstico cerrado + E2E acotado PASS)

Fecha: 2026-11-19. Laboratorio `spanel.lab` (`lucas@100.67.5.50`), slug desechable
`e2e0109r4v2`, BD clonada `sysadmin_e2e0109r4v2`. Working tree `remove-hardener`
sin commitear copiado a `/var/tmp/spanel-e2e-0109r4v2/stage` (hashes de los 6
archivos reparados verificados idénticos al repo local). API desechable en
`127.0.0.1:3010` con `Host: spanel.lab`, worker dramatiq `apps` y `events`,
plan-agent y relay privilegiados. **No se ha modificado código de la aplicación**;
sólo entorno desechable y preparación del harness (documentada abajo).

## 1) Checks ejecutados y resultado real hasta ahora

- **Check 1 `egress_without_manual_nat` — PASS (evidencia firme).** `provision
  --slug e2e0109r4v2 --json` → `state=ready`, `uid=60070`,
  `apparmor.effective=true`, unidad `active/running`. El PID principal del unit
  es `3566749` (rootlesskit, en `net:[4026531833]` = netns del host), pero el
  **dockerd real de la celda es `3566797`** (y su padre `3566766`) en
  `net:[4026535904]`, inode distinto. Dentro de ese netns existe
  `-A POSTROUTING -s 172.17.0.0/16 -j MASQUERADE`; en el host **no** aparece
  regla simple nueva (sólo la preexistente `172.17.0.0/16 ! -o docker0`).
  `docker run --rm alpine wget -q -O /dev/null https://registry.npmjs.org/vite`
  vía el socket de la celda → **NET_OK**, sin MASQUERADE manual. `delta_denied=0`
  desde el primer arranque; 8 `audit deny` intactas. El bug de R4 (regla en el
  host por usar el PID rootlesskit) NO se reproduce.

- **Check 2 `aggregate_2gb_from_first_deploy` — PASS (evidencia firme).**
  `POST /api/v1/plugins/apps/plan {memory_bytes:2147483648,cpus:1,pids:512}`
  **antes** del deploy → HTTP 201 `status=applied`; cgroup
  `memory.max=2147483648`, `cpu.max=100000 100000`, `pids.max=512` (verificado
  otra vez tras el deploy). App creada HTTP 201 (`domain=null`, como exige el
  contrato). Deploy exitoso: operación `61284bcd-…` `status=succeeded`,
  `phase=complete`, `result.status=running`,
  `effective_services=[backend,database,frontend]`,
  `memory_budget_bytes=2147483648` y per-servicio `715827882` (1/3 de 2 GiB).
  **No apareció** `service backend memory limit is invalid`.

- **Check 3 `published_route_no_bridge` — EN CURSO / parcial.** Migración 005
  aplicada por el runtime migrador (ver §3). `POST /api/v1/plugins/domains/app-hosts`
  con `{application_id,service:"frontend",domain:"editores-0109r4v2.lab"}`
  → **HTTP 201**, `site_id=<appid>:frontend`, y la fila en `domains_app_hosts`
  tiene `tenant_id=658e5ca2-…` (propiedad del tenant correcta). El evento
  `domains.domain.added` se emitió y se procesó por el dispatcher del producto.
  La llamada directa al método propio del producto
  `app.state.rootless_routes.refresh(...)` devolvió
  `{'published':['editores-0109r4v2.lab'], ..., 'endpoint':{slug:'e2e0109r4v2',
  loopback_address:'127.71.1.1', publish_port:20070, relay_port:40070,
  bind:'172.18.0.1'}}` y escribió
  `dynamic/spanel-route-216c23962cadb4f85f0a.yml` apuntando al relay.
  **Aún NO demostrado**: listener `127.71.1.1:20070`, relay `172.25.0.1:40070`
  con HTTP 200 del editor. Causa identificada y en corrección: (a) el bind del
  plan-agent era `172.18.0.1` pero el relay real escucha `172.25.0.1`
  (corregido: plan-agent reiniciado con `SPANEL_EDGE_RELAY_BIND=172.25.0.1`);
  (b) el relay preexistente tenía el ejecutable borrado y se reinició desde el
  stage con el mismo `--bind 172.25.0.1`, ya registra el endpoint de la celda;
  (c) el laboratorio corre en modo **rootful** por defecto
  (`SPANEL_TENANTS_ROOTLESS` no está fijado en el stack vivo) y el primer deploy
  creó los contenedores en el daemon root, no en la celda. Se ha activado
  `SPANEL_TENANTS_ROOTLESS=true` en el entorno desechable y se está
  re-desplegando para que el runtime rootless publique `20070`.

- **Check 4 `rollback_rehearsal` — NO EJECUTADO aún**. Requiere el deploy
  rootless real de check 3. Pendiente.

## 2) Bucle `running claim` sostenido — relación con GAP-0109R-5

Sí hubo un `running/claim` sostenido (~10 min) en el deploy
`f4f8a08c-…`: el worker dramatiq lanzó `docker compose up -d --no-recreate`
y el middleware `dramatiq.middleware.time_limit.TimeLimit` abortó el hilo a los
600 s (*Time limit exceeded*), dejando la operación colgada. Es el mismo
drenaje asíncrono del broker **GAP-0109R-5** (dramatiq/outbox) del labouratorio:
el stack vivo tampoco tiene worker de la cola `events` y su `event_outbox`
tiene 974 eventos `pending`. Yo levanté workers desechables de `apps` y
`events` y drené el outbox con la propia función del producto
(`_dispatch_pending_events_impl()`), sin parchear código. El deploy posterior
con caché de capas caliente ya no se colgó. Este fue un problema de
preparación/harness, **no** la causa de ningún PASS.

## 3) Evidencia concreta ya recolectada

- NAT: netns host `net:[4026531833]` vs dockerd de celda `net:[4026535904]`;
  regla sólo dentro; host sin regla nueva; `NET_OK`.
- Migración 005: el runtime migrador la aplicó al habilitar `domains` →
  `plugin_registry.migration_version='005_rootless_app_hosts'`, `state=enabled`,
  tabla `domains_app_hosts` creada con `https BOOLEAN DEFAULT false`
  (la reparación del `BOOLEAN DEFAULT 1`); `POST/GET /app-hosts` montados
  (presentes en OpenAPI). El **downgrade 005 sigue pendiente de ejecutar**.
- Dominio por API pública de `domains`: HTTP 201 + propiedad del tenant
  verificada en BD.

## 4) Qué queda por ejecutar

1. Re-desplegar con `SPANEL_TENANTS_ROOTLESS=true` → contenedores en la celda.
2. Verificar listener real `127.71.1.1:20070` y relay `172.25.0.1:40070`.
3. Publicar ruta con `https=false` si procede, y `curl -H 'Host: …'
   http://127.0.0.1:9080/` → **HTTP 200** sin puente TCP.
4. Fallback legacy: app con `apps_applications.domain` histórico y sin fila
   nueva, ver que sigue publicando; y que tras migración 005 gana la fila nueva.
5. Downgrade de 005 por la API del runtime migrador, sin tocar legacy.
6. Check 4 rollback real: ruta/runtime previos restaurados, contenedor rootful
   conservado, y flag `false` no reescribe runtime migrado.
7. Verificar Core (6 PIDs/hashes), otro tenant, `delta_denied=0`.
8. Limpieza total y byte-a-byte; sobrescribir el artefacto oficial.

**Resultado provisional: 2 PASS confirmados (checks 1 y 2), check 3 en curso,
check 4 pendiente.** El veredicto final puede cambiar; se reportará con
salida real, sin inferencias.

---

## ACTUALIZACIÓN FINAL AL PAUSAR (petición del usuario)

Se detuvieron todos los bucles de poll y no se iniciaron nuevos deploys.
El último `deploy_poll.sh` agotó sus 20 iteraciones en `running/claim`
(operación `be6a638a-d55f-4ca2-9160-315afc930dfb`) sin converger.

### Estado al pausar

- Checks **1 y 2: PASS confirmados** con la evidencia descrita arriba (NAT en
  el netns correcto con `NET_OK` y cero reglas nuevas en el host; plan 2 GiB
  aplicado antes del deploy con `memory.max=2147483648` y deploy de 3 servicios
  `succeeded` sin `service backend memory limit is invalid`).
- Check **3: EN CURSO, NO PASS.** Evidencia real del último intento: con
  `SPANEL_TENANTS_ROOTLESS=true` los contenedores del release se crearon en el
  **daemon rootless de la celda** (`frontend/backend/database` en
  `/var/lib/spanel/cells/e2e0109r4v2/docker.sock`, `Up`, healthy), pero la
  operación se quedó en `running/claim`. El proceso observable del worker en
  ese momento fue:
  `docker run --rm --network app-60fa545254874f45b836fbb9_default --read-only
  --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 --memory
  128m --cpus 1 --user 65534:65534 curlimages/curl@sha256:d9b45… curl -sS -o
  /dev/null --write-out %{http_code} --connect-timeout 5 --max-time 10
  http://frontend:8080/`
  Es decir, el probe de readiness usa la red **`app-<id>_default` del daemon
  rootful**, mientras el deploy rootless puso los contenedores en el daemon de
  la celda.
- **Sospecha a verificar (NO conclusión):** posibles *runtimes mezclados en un
  mismo deploy* (deploy en runtime rootless + probe en runtime rootful). Si
  `frontend` no existe en esa red rootful, el probe no converge y explicaría el
  `running/claim` sostenido. No se ha demostrado; hace falta comparar el
  `runner` usado por el probe frente al del deploy con el mismo `runtime_project`.
- Check **4: NO EJECUTADO** (depende de un deploy rootless convergido).
- Downgrade de la migración 005: **NO EJECUTADO** (la ruta no convergió).

### Incidentes de harness (no atribuibles a la app)

- JWT expirado a mitad del poll → el bucle consultó `/operations/` con OPSID
  vacío y devolvió `None` repetidamente. Corregido con re-login y guard de
  OPSID/HTTP antes de entrar al bucle.
- `SPANEL_TENANTS_ROOTLESS`, `SPANEL_APPS_PROBE_BASELINE=rootless`, el mount del
  socket de celda en el worker y el reinicio del relay fueron **configuración
  del entorno desechable**, no parches de código. El relay preexistente tenía
  su ejecutable borrado antes de este run (ya documentado en el artefacto R4
  anterior) y se relanzó desde el stage con el mismo `--bind 172.25.0.1`.

### Estado del artefacto oficial

`artifacts/0109-r4-host-nat-and-domains-owned-hosts-e2e.json` **fue sobrescrito
con el estado real de este run**: `result: BLOCKED`, checks 1 y 2 `pass:true`,
checks 3 y 4 `pass:false` con salida real, `cleanup_verified: true`. No se ha
escrito ningún PASS inventado. El veredicto de este reintento es
**BLOQUEADO / incompleto: 2 checks confirmados, 2 sin completar**.

### Limpieza ejecutada y verificada

Celda `e2e0109r4v2` retirada por CLI (`state=retired`); usuario uid 60070,
home, `/run/user/60070`, unidad, perfil AppArmor y tabla nft eliminados; BD
clonada `sysadmin_e2e0109r4v2` eliminada; app/worker/events/plan-agent
detenidos; YAML publicado retirado; stage y temporales borrados. Los 5 archivos
de estado se restauraron byte-a-byte con sus hashes originales. El relay se
restauró en su ruta original `/home/lucas/.local/lib/spanel-edge-relay` (su
ejecutable ya estaba borrado antes de este run) con 17 listeners y el bind
`172.25.0.1`, sin el slug desechable. Los 6 Core siguen running con PID y hash
idénticos; otros 10 usuarios de celda y el iptables baseline del host intactos.

## Cierre posterior (2026-11-19)

### Causa raíz del bloqueo del check 3

No hubo runtimes mezclados: deploy y probe comparten el mismo `Runner`
tenant-scoped y el mismo `runner.environ` (verificado en el código y en la
celda). El fallo real era la política del probe: se ejecutaba con
`--read-only`, lo que provoca un remount de `/` que AppArmor deniega en la
celda (`MS_RDONLY|MS_REMOUNT|MS_BIND: permission denied`). El probe moría con
exit 126 antes de `curl`; el reintento de 180 s mantenía la operación en
`running/claim`.

### Corrección aplicada

- `runtime/probes.py`: el baseline `rootless` usa rootfs escribible efímero
  (manteniendo digest, uid 65534, `cap-drop ALL`, `no-new-privileges` y
  límites); el baseline hardened/rootful conserva `--read-only`. La evidencia
  del probe registra `read_only`.
- `runtime/tenant_runtime.py`: `DockerRootlessRuntime.environment()` fija
  juntos `DOCKER_HOST` (socket de la celda) y
  `SPANEL_APPS_PROBE_BASELINE=rootless`.
- Regresión en `tests/test_probes.py`, `test_tenant_runtime.py` y
  `test_rootless_worker.py` (117 tests focales en verde).

### E2E black-box scriptado (PASS acotado)

`scripts/e2e_0109_r4_blackbox.py` crea un entorno desechable (BD clonada,
API/worker/redis desechables, celda rootless real, fixture GitHub real),
despliega `luc444s/software-de-gestion-para-editores@feature/workflow-diseno`
por la API/worker reales y verifica:

- los 3 servicios (`backend`, `database`, `frontend`) `running/healthy` en el
  daemon de la celda y **ausentes** del daemon rootful;
- probe independiente desde dentro de la celda → HTTP 200;
- segundo deploy + rollback que restaura la misma release firmada, con los
  contenedores todavía en la celda;
- limpieza: BD desechable eliminada, celda retirada, usuario huérfano
  eliminado y los 5 archivos de estado restaurados byte-a-byte.

Evidencia: `artifacts/0109-r4-editors-rootless-blackbox-e2e.json` (`PASS`).
Este E2E es **acotado** y no sustituye al artefacto oficial de 4 checks
(`artifacts/0109-r4-host-nat-and-domains-owned-hosts-e2e.json`), que sigue
`BLOCKED 2/4`; los checks 3/4 y el downgrade de la migración 005 no se
re-ejecutaron en este run.
