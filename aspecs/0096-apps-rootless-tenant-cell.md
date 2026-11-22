# A.SPEC 0096 — Apps: celda de runtime rootless por tenant

Estado: propuesto (2026-11-17). Sin código aún.

## 1. Contexto

El hardener invasivo fue retirado (commits `3a1d7d4`, `89b114b`, `17749c9`,
rama `remove-hardener`). Como consecuencia, las aplicaciones cuyo Compose
publica puertos o cuyo Dockerfile termina en `USER root` son rechazadas con
`compose_published_port` y `dockerfile_final_user_root`. Ese rechazo es
correcto mientras el único límite sea una validación estática sobre el código
fuente, porque no existe un aislamiento real detrás.

Este spec sustituye ese modelo por una **celda de runtime por tenant**: una
unidad única de aislamiento formada por usuario de sistema, subuids/subgids,
cgroup v2 delegado, daemon Docker rootless con su propio socket Unix y perfil
AppArmor que confina a ese daemon. No se reintroduce ninguna transformación
del Compose ni del Dockerfile del desarrollador. **No se usa hardening a partir
de aquí.**

## 2. Objetivos

1. Cada tenant (`slug`) posee su propia celda, con un `dockerd-rootless.sh`
   real, un socket Unix rootless real y un cgroup propio.
2. El worker de Apps deja de usar `/var/run/docker.sock` compartido: cada
   operación usa el socket de la celda del tenant correspondiente.
3. El aislamiento efectivo es por **usuario + cgroup + namespace + socket**,
   no por el contenido de la imagen.
4. Una app puede ejecutarse con **UID 0 dentro de su celda**: el user namespace
   lo mapea a una identidad sin privilegios del host. El mapeo efectivo **se
   verifica** (`/proc/<pid>/uid_map`, `docker inspect`) y no se asume: según la
   configuración, UID 0 puede corresponder al UID real del usuario de la celda
   mientras los demás UID usan el rango subordinado. No afecta a otros tenants.
5. AppArmor por tenant confina al proceso daemon de la celda (rootless no
   puede aplicar perfiles a contenedores); seccomp/caps/límites confinan al
   contenedor.
6. La CLI y el backend son Python. La CLI usa el `slug` del tenant como clave,
   nunca un input libre de la request.

## 3. No objetivos

- No reintroducir normalización de Compose, inyección de `USER`,
  `ports`→`expose`, `chown`/`chmod`, ni el paquete `scripts/dangerous_build/`.
- No modificar el kernel (`src/systutor`): esto es lógica de negocio del
  plugin Apps y del host application.
- No migrar despliegues existentes en la Fase 1: se hacen en la Fase 3b con
  `migrate-legacy`, bajo feature flag por tenant.
- No DinD con socket compartido, ni daemon rootful global.

## 4. Arquitectura de la celda

Para `slug = "acme"`:

```
 usuario del host:      spanel-acme          (uid U, gid G)
 subuid/subgid:         U:65536..U+131071    (bloque exclusivo, nunca reutilizado)
 mapeo efectivo:        verificado en /proc/<pid>/uid_map; NO asumir UID 0 = primer subuid
 cgroup v2:             /system.slice/spanel-cell-acme.scope  (Delegate=yes)
 runtime dir:           /var/lib/spanel/cells/acme/           (0700, owner U:G)
 socket Docker:         /var/lib/spanel/cells/acme/docker.sock (0600, owner U:G, sin root)
 AppArmor:              spanel-cell-acme     (perfil cargado por root, attach al wrapper)
 datos de apps:         /var/lib/spanel/cells/acme/apps/      (dentro del data root)
 cgroup de contenedores: subárbol delegado a spanel-cell-acme.scope
 red:                    bridge propia del daemon + publish en loopback dedicado
                         + reglas nftables por UID hacia el Traefik central
```

La celda está **lista** solo cuando `doctor` verifica los seis elementos. Si
falla el perfil AppArmor, `provision` revierte y no marca la celda como activa.

### 4.1 Identidad y asignación

- `slug` se valida con `^[a-z0-9][a-z0-9-]{0,61}$` (mismo espíritu que
  `PROJECT_RE`), se normaliza a minúsculas y se rechaza cualquier otra forma.
- El slug se toma de la fila `tenants.slug` (DB), nunca del body de una request.
- Asignación persistida en tabla nueva del plugin:
  `apps_tenant_cells(slug PK, tenant_id FK, uid, gid, subuid_base, subgid_base,
  cgroup_path, socket_path, apparmor_profile, apparmor_hash, state,
  created_at, updated_at)`.
- Los bloques de uid se asignan desde un rango configurable y **nunca se
  reutilizan** (tombstone en la fila al dar de baja). Esto evita que un tenant
  nuevo herede archivos del anterior.
- Tras `provision` se registra el mapeo real leído de `/proc/<pid>/uid_map` y
  `gid_map` del daemon. **No se asume** que UID 0 equivalga al primer subuid:
  Docker rootless puede mapearlo al UID real del usuario de la celda. El mapeo
  observado se guarda en el evidence del release y se usa para las
  comprobaciones de propiedad de archivos, nunca una fórmula fija.
- Migración: `plugins/apps/migrations/005_apps_tenant_cells.py`, siguiendo el
  patrón de migraciones del plugin. **Sin Alembic** (regla del repo raíz).

### 4.2 El socket es el límite

- **Red decidida**: publish en loopback + **un único Traefik central** (no un
  proxy por tenant). El registrar del control plane escribe las rutas dinámicas
  hacia la IP/puerto loopback asignados a cada celda.
- `127.0.0.1` evita acceso remoto directo, **pero no aísla entre tenants**:
  cualquier proceso local podría conectar. Cada celda recibe una dirección de
  loopback dedicada (alias en `lo`) y se instalan reglas `nftables` en el hook
  `output` con matching por UID de socket (`skuid`): solo el UID de la celda y
  el UID del Traefik central pueden alcanzar ese puerto; el resto se descarta.
  Si el kernel no soporta matching por owner, se cae a un namespace de red por
  celda con veth hacia el Traefik central.
- El backend no monta `/var/run/docker.sock`. Monta los sockets de celdas en
  `/var/lib/spanel/cells/<slug>/docker.sock` y selecciona `DOCKER_HOST` por
  operación, derivado del `tenant_id` autenticado.
- El CLI expone un socket de control root-only (`SO_PEERCRED`, uid 0 o el
  usuario de servicio) con verbos allowlist; el backend lo usa para
  provisionar/verificar/destruir celdas, no para operar contenedores.
- Ningún comando acepta rutas arbitrarias: las rutas se derivan del slug
  validado y de la fila de la DB.

### 4.3 AppArmor y usuario root

- Perfil `spanel-cell-<slug>` generado desde un template fijo con sustitución
  de prefijos validada; cargado por root con `apparmor_parser -r`.
- AppArmor sobre el daemon es **una defensa adicional, no una barrera
  completa**: no sustituye el confinamiento individual de cada contenedor ni
  autoriza a relajar seccomp/caps/límites.
- Se valida el **perfil efectivo**, no solo que esté cargado: `aa-status`,
  `/proc/<pid>/attr/current` del daemon en ejecución y comparación del hash con
  el registrado en la DB. Si el perfil efectivo no coincide, la celda pasa a
  `degraded` y se bloquean nuevos deploys.
- Del contenedor se comprueba en el **runtime real**, no solo en el override
  declarado: `HostConfig.SecurityOpt`, `CapDrop`, `Privileged`, namespaces,
  binds y límites. Además se ejecuta una sonda de comportamiento que intenta
  escalada de privilegios y lectura de una ruta prohibida, verificando que
  **falla**. Declarar `no-new-privileges` o `seccomp=builtin` no basta.
- Reglas: acceso solo al data root y runtime dir de la celda; deny a
  `/var/run/docker.sock`, `/etc/subuid`, `/etc/subgid`, otras celdas y
  `/run/secrets/**`; deny `mount`, `ptrace`, señales entre celdas, raw sockets.
- `USER root` en la imagen se acepta: el usuario namespace lo mapea fuera del
  host. Se mantiene el rechazo de `privileged`, dispositivos host, namespaces
  host, binds sensibles y socket Docker. Se reevalúa `compose_published_port`:
  solo se permiten publishes en loopback asignados por el control plane.

## 5. Componentes

### 5.1 CLI Python — `scripts/spanel_tenant.py`

Basada en `typer` (ya disponible en el venv). Comandos:

```
doctor                         verifica kernel, apparmor, cgroup v2, subuid, ip_forward
                               (OBLIGATORIO antes de cualquier provision)
provision --slug <slug>        crea usuario, bloque uid, dirs, systemd user, rootless dockerd, AppArmor
migrate-legacy --slug <slug>   re-inspecciona y re-firma una app legacy con root,
                               la despliega en la celda, verifica y cambia la ruta
status    --slug <slug>        estado de la celda + hash del perfil + socket
list                           todas las celdas
repair    --slug <slug>        re-crea socket/perfil sin tocar datos
deprovision --slug <slug>      baja el daemon y la unidad systemd; --keep-data conserva datos
apparmor install|verify|remove --slug <slug>
shell     --slug <slug>        exec en el daemon rootless para diagnóstico (auditado)
```

Salida JSON en `--json`, con `tenant_slug`, `verb`, `exit_code`; audit log
JSONL local sin secretos. Errores imprimibles, sin stack traces al backend.

Cada archivo Python del CLI por debajo de 400 líneas (regla del kernel para
todo el repo): `cli.py`, `cells.py`, `apparmor.py`, `alloc.py`, `doctor.py`.

### 5.2 Backend — `plugins/apps/backend/runtime/`

Nueva abstracción, en el plugin (no en el kernel):

```
TenantRuntime (Protocol)
  status(slug) -> CellStatus
  build(slug, release_dir, tag)
  up(slug, compose_files, override)
  down(slug, project)
  logs(slug, project, service)
  exec_probe(slug, ...)
DockerRootlessRuntime(TenantRuntime)   # habla con el socket de la celda
FakeTenantRuntime                      # tests
```

`worker.py` sustituye el `Runner` global por `runtime.for_tenant(tenant_id)`
y mantiene: firma de releases, verificación, outbox, RBAC y auditoría.

`probes.py` adopta un baseline consciente del runtime:

- rootless: exige seccomp, `no-new-privileges`, `cap_drop: ALL`, pids/mem/cpu,
  **verificados en el contenedor en ejecución**; AppArmor del contenedor se
  registra como `unconfined (rootless)` y el perfil de la celda se anota como
  defensa adicional, nunca como sustituto del confinamiento individual.
- legacy rootful: mantiene `apparmor=docker-default` hasta su desmantelamiento.

## 6. Fases y criterios de salida

| Fase | Entregable | Salida |
|---|---|---|
| 0 | Este spec + prerequisitos de red/cgroup/AppArmor | Aprobado |
| 1 | `doctor` en el lab, luego `provision`/`status`/`deprovision` | `doctor` verde antes de provisionar; 2 tenants, perfil efectivo verificado, socket rootless real |
| 2 | `TenantRuntime` + fake + tests unitarios | 100% tests del plugin, sin tocar producción |
| 3 | Worker usa celda por tenant bajo feature flag | app nueva desplegable en lab con UID 0 |
| 3b | `migrate-legacy` para apps con USER root | app legacy migrada a su celda con rollback probado |
| 4 | E2E rootless (incluye test negativo cross-tenant) | verde en `https://spanel.lab` |
| 5 | Canary en producción: 1 tenant, solo app nueva | rollback en < 5 min |
| 6 | Retiro del socket compartido y código legacy | sin referencias a hardener |

## 7. Seguridad y tests negativos

- Tenant A no puede leer/escribir la celda de B ni su socket.
- Tenant A no puede alcanzar `/var/run/docker.sock` ni `/etc/subuid`.
- `privileged`, dispositivos, `network_mode: host`, socket Docker y binds
  sensibles siguen rechazados por `audit_project`.
- El perfil AppArmor **efectivo** (no solo cargado) se verifica por hash antes
  de cada deploy; si no coincide, el deploy se bloquea.
- Un tenant no puede conectar al puerto loopback de otro: la regla nftables por
  UID se prueba con un proceso de otro tenant (debe fallar) y con el Traefik
  central (debe funcionar).
- La sonda activa confirma que seccomp, `no-new-privileges` y `cap_drop: ALL`
  están aplicados en el contenedor en ejecución, no solo declarados.
- Los límites de cgroup se comprueban con un proceso que intenta excederlos.
- `USER root` dentro de la celda pasa; root en el host no existe para esa app.

## 8. Decisiones cerradas y prerequisitos

Cerradas: red = publish loopback + **Traefik central**; `doctor` se ejecuta en
el lab antes de cada `provision`; migración = apps nuevas **y** script
`migrate-legacy` para las apps que quedaron con root.

Prerequisitos que `doctor` debe confirmar en el host antes de la Fase 1:
- cgroup v2 con `Delegate=yes` en la unidad systemd del usuario de la celda.
- AppArmor activo (`/sys/module/apparmor/parameters/enabled`) y
  `apparmor_parser` disponible.
- `nftables` con soporte de matching por UID de socket, o alternativa de
  namespace de red por celda.
Si alguno falta, la celda no se marca `ready` y no se despliega nada.
