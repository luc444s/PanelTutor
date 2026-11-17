# A.SPEC 0096 — Tenant-Rootless Docker Socket Runtime (aislamiento extremo)

> `risk: high` — desplaza la frontera de aislamiento del contenedor al daemon,
> introduce cambios a nivel de host (AppArmor, nftables, cgroups, systemd user,
> `runsc`) y sustituye el hardener para un perfil de runtime. Requiere aprobación
> humana, spike validado y E2E real antes de declarar compatibilidad general.

## STATUS

**Propuesta. No implementada.** Spike de viabilidad ejecutado en `spanel.lab` el
2026-11-17 con resultados positivos (ver VERIFICATION). Hasta que se implemente,
el perfil por defecto sigue siendo `hardened` (0083/0087/0094/0095).

No se toca ningún repositorio de aplicación. La compatibilidad deja de depender
de reescribir el Compose: el perfil `tenant-rootless` despliega el Compose
original, sin normalización destructiva ni inyección de archivos.

## WHY

El hardener resuelve la compatibilidad **recortando** el Compose de la app:
-quita binds, puertos, capabilities y topología, y luego vuelve a inyectar lo
mínimo (archivos firmados, redes, healthchecks). Cada app real que aparece
descubre un caso nuevo: healthchecks en un directorio enlazado, perfiles
inactivos, volúmenes non-root, redes multiple. Los últimos seis fixes de esta
semana son síntomas de ese modelo, no de las apps.

La alternativa es cambiar la frontera: en lugar de un daemon root compartido
que hay que desarmar para cada app, **un daemon rootless por tenant**, con un
socket privado, un usuario de sistema distinto, su propio user namespace, su
propia red y su propio perfil AppArmor. Dentro de ese daemon el Compose de la
app se ejecuta tal cual: binds y puertos funcionan, no hay que reescribir nada.

"Aislamiento extremo" significa que la contención no depende de un solo mecanismo:

1. **User namespace rootless**: root dentro del contenedor mapea a un UID
   deleado del tenant, nunca a UID 0 del host.
2. **Daemon por tenant**: no existe un socket compartido que pueda usarse para
   alcanzar otros tenants o la infraestructura del panel.
3. **AppArmor estricto e independiente**: el daemon corre confinado bajo un
   perfil propio por tenant; todos sus contenedores heredan ese perfil.
4. **gVisor (`runsc`)**: syscalls de la app mediadas por un kernel en user
   space, sin acceso directo al kernel del host.
5. **Red y firewall**: bridges separados, puertos publicados solo en una IP
   administrada y al alcance del proxy; nftables default-deny entre tenants.
6. **Fail-closed**: si falta cualquier pieza, el deploy falla. Nunca hay
   degradación silenciosa a `runc`, al daemon compartido ni al hardener.

## WHAT

PanelTutor ofrece un segundo perfil de runtime, seleccionable por **tenant** (no
por app, para no requerir una migración SQL):

```yaml
SPANEL_APPS_RUNTIME=hardened        # default actual, sin cambios
SPANEL_APPS_RUNTIME=tenant-rootless # nuevo
```

Verdad nueva y falsable: **una app desplegada bajo `tenant-rootless` corre con
su Compose original firmado, dentro del daemon rootless de su tenant, confinada
por el perfil AppArmor del tenant y por `runsc`, sin poder alcanzar el host, el
socket del panel, otros tenants ni la infraestructura.**

El perfil `hardened` queda intacto y sigue siendo el default. Este A.SPEC no
hace cutover.

## SCOPE

- Un `dockerd` rootless por tenant: usuario de sistema dedicado, subuid/subgid
  disjointos, `rootlesskit` + `slirp4netns`/`pasta`, data-root y exec-root
  privados, socket `unix:/run/spanel/tenants/<tenant>/docker.sock` (0660,
  propietario `spanel:<tenant>`).
- Gestión del ciclo de vida del daemon: unidad `systemd --user` por tenant,
  arranque/parada/reinicio y verificación de salud del socket.
- Factory de `Runner` por tenant: toda operación de apps usa el socket del
  tenant dueño de la app; se elimina el `transport()` global para este perfil.
- Perfil AppArmor por tenant: plantilla default-deny + allowlist generada,
  cargada con `apparmor_parser -r -W`, daemon arrancado con
  `aa-exec -p spanel-tenant-<tenant> -- dockerd-rootless.sh ...`.
- Runtime `runsc` obligatorio dentro del daemon rootless; preflight y
  verificación post-deploy. Sin `runsc`, falla cerrado.
- Admisión **sin hardener** para este perfil: auditoría estricta del Compose
  original (sin `privileged`, devices, host namespaces, `docker.sock`, rutas
  fuera del tenant, `network_mode: host`, seccomp unconfined, capabilities
  amplias) + firma del Compose original + digests de imagen.
- Ingress multi-socket: el registro de rutas sondea todos los sockets tenant y
  agrega rutas; el proxy alcanza cada tenant por una IP/puerto administrado.
- Firewall por tenant: nftables limita los puertos publicados del tenant a la IP
  del proxy y bloquea el tráfico entre tenants.
- Cuotas por tenant: cgroup parent delegado con límites de CPU, memoria y PIDs.
- Probes de perfil: verifica `rootless`, label de AppArmor, runtime `runsc`,
  mapeo de UID, separación de red, reachability del ingress y `RestartCount`.
- Evidencia JSON por deploy con tenant, socket, perfil, hashes, runtime, label
  AppArmor, UID mapping y resultado de probes.
- Tests unitarios, integración, E2E y rollback.

## OUT OF SCOPE

- Cambiar el perfil `hardened`, el hardener, el normalizador ni sus releases
  firmadas (0083/0087/0094/0095 quedan intactos).
- Cutover: `hardened` sigue siendo el default. La migración de apps existentes
  se decide en otra A.SPEC.
- Cambios de esquema SQL o Alembic (está prohibido en desarrollo). La selección
  de perfil es configuración de plataforma/tenant, no columna nueva.
- Repositorios de aplicación: no se modifica ningún Compose de app.
- SSH, terminal web o gateway de acceso a los tenants.
- Política de egress a Internet por allowlist (se hereda: sin salida salvo la
  red autorizada por el administrador).
- MicroVM (Kata/Firecracker). gVisor es la frontera de syscalls elegida.
- Cuotas de disco avanzadas (quotas XFS/project); se usan límites de cgroup y
  data-root por tenant.

## CONTRACT

### Precondiciones

- Kernel con user namespaces, AppArmor en `enforce`, cgroup v2 con delegación a
  `user.slice`, `runsc` instalado y registrado como runtime Docker.
- `rootlesskit`, `slirp4netns` o `pasta`, `apparmor_parser` y `aa-exec`
  disponibles.
- Rango subuid/subgid disjunto por tenant y usuario de sistema `spanel-t-*
  creado por el operador.
- Reglas nftables administradas por root del host, no por el tenant.

### Postcondiciones

- `docker -H unix:/run/spanel/tenants/<tenant>/docker.sock info` reporta
  `SecurityOptions` con `name=rootless` y el daemon corre bajo el perfil
  `spanel-tenant-<tenant> (enforce)`.
- Cada contenedor de la app reporta `HostConfig.Runtime == "runsc"` y
  `/proc/self/attr/current == spanel-tenant-<tenant> (enforce)`.
- `docker inspect` del Compose desplegado es idéntico al Compose firmado
  (mismo hash): no hay mutación del hardener.
- El servicio es alcanzable solo desde el proxy a través de la IP/puerto
  administrado; desde otro tenant la conexión es rechazada.
- Falla cerrado si falta `runsc`, el perfil AppArmor, la delegación de cgroups
  o las reglas de firewall.

### Reglas del envelope `tenant-rootless`

| Elemento | Comportamiento |
|---|---|
| Compose de la app | se despliega sin reescribir; binds y puertos permitidos dentro del tenant |
| Usuario dentro del contenedor | el que diga la imagen/Compose, incluido root; mapea a subuid del tenant |
| Runtime | `runsc` obligatorio; `runc` prohibido |
| Daemon | rootless, por tenant, sin socket compartido |
| AppArmor | perfil del tenant, heredado por todos los contenedores |
| `privileged` / devices / host namespaces | prohibido (auditoría + AppArmor + runsc) |
| `docker.sock` montado | prohibido (auditoría + AppArmor) |
| Rutas de bind | solo dentro del home/data-root del tenant; el resto es denegado por AppArmor |
| Puertos publicados | solo en la IP administrada; nunca `0.0.0.0` irrestricto |
| Redes | bridge privado por tenant; `network_mode: host` prohibido |
| `no-new-privileges` | obligatorio |
| Límites CPU/RAM/PIDs | obligatorios por tenant |
| Firma | del Compose original y de los digests de imagen; sin `hardened_tree_sha256` |

### Selección de perfil

- `SPANEL_APPS_RUNTIME` es configuración global con default `hardened`.
- Un tenant puede fijar `tenant-rootless` en su configuración; un app hereda el
  perfil de su tenant. No hay override por servicio ni por Compose.
- Cambiar el perfil de un tenant exige una operación de deploy nueva; no se
  reescriben releases ya firmadas.

## INVARIANTS

```yaml
invariants:
  - I1: "Ningún contenedor puede alcanzar el socket Docker del host ni el del panel: todo intento falla."
  - I2: "Ningún contenedor puede leer archivos del host fuera del data-root del tenant, aunque estén bind-montados: AppArmor lo deniega por la ruta vista dentro del contenedor."
  - I3: "Un tenant no puede alcanzar contenedores, redes ni puertos publicados de otro tenant: nftables default-deny y netns separados."
  - I4: "Root dentro del contenedor mapea a un subuid del tenant; el proceso en el host nunca es UID 0."
  - I5: "Todo contenedor del tenant reporta el perfil AppArmor spanel-tenant-<tenant> (enforce) en /proc/self/attr/current."
  - I6: "Todo contenedor corre con runtime runsc; no existe fallback a runc y ausencia de runsc falla cerrado."
  - I7: "El Compose desplegado es byte-idéntico al Compose firmado: hash del release == hash deployado."
  - I8: "El perfil hardened y sus releases firmadas siguen funcionando sin cambios; el default sigue siendo hardened."
  - I9: "Cambiar de perfil no reescribe releases ni destruye volúmenes: los datos sobreviven."
  - I10: "Ningún puerto de tenant queda expuesto en 0.0.0.0; solo la IP del proxy puede conectarse."
  - I11: "Los límites de CPU, memoria y PIDs por tenant son efectivos y verificables vía cgroup."
  - I12: "El daemon rootless no requiere privilegios de host fuera de su usuario: no SETUID propio, no root, no montajes del host."
  - I13: "Los probes siguen siendo autoridad: healthcheck fallido o RestartCount > 0 produce rollback."
  - I14: "Falta de cualquier prerrequisito (runsc, AppArmor, cgroup, firewall, rootlesskit) bloquea el deploy."
  - I15: "La admision no evalua contenido de la app (CVEs, estilo de Dockerfile): hereda 0087."
```

## VERIFICATION

### Spike ya ejecutado (evidencia real en `spanel.lab`, 2026-11-17)

Estos comandos se ejecutaron y sus resultados son la prueba de viabilidad:

```bash
# 1. Daemon rootless con socket propio
export XDG_RUNTIME_DIR=/run/user/1000
export DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=0
export DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SANDBOX=false
export DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SECCOMP=false
nohup dockerd-rootless.sh --iptables=false --ip6tables=false \
  --data-root=$HOME/.local/share/docker \
  --exec-root=/run/user/1000/docker \
  --host=unix:///run/user/1000/docker.sock > /tmp/rootless-dockerd.log 2>&1 &

export DOCKER_HOST=unix:///run/user/1000/docker.sock
docker info --format '{{.ServerVersion}} {{.SecurityOptions}} {{.Driver}}'
# => 29.1.3 [name=seccomp,profile=builtin name=rootless name=cgroupns] overlayfs

# 2. Compose ORIGINAL, sin hardener: bind + puerto 80 interno
cd /home/lucas/spike-rootless   # nginx:alpine, ports 18085:80, bind ./html
docker compose up -d
curl -fsS http://127.0.0.1:18085/
# => <h1>ROOTLESS TENANT SOCKET OK</h1>

# 3. Ingress: contenedor rootful alcanza el puerto publicado
docker run --rm curlimages/curl -fsS http://192.168.18.11:18085/
# => <h1>ROOTLESS TENANT SOCKET OK</h1>

# 4. AppArmor por tenant confinando el DAEMON (el flag por container se ignora)
aa-exec -p spanel-tenant-spike-dockerd -- dockerd-rootless.sh ...
docker run --rm alpine cat /proc/self/attr/current
# => spanel-tenant-spike-dockerd (enforce)

# 5. Denegacion efectiva (la regla se escribe contra la ruta vista por el container)
# perfil: deny /secret/** rwk,
docker run --rm -v /home/lucas/.ssh:/secret:ro alpine \
  sh -c 'cat /secret/* >/dev/null 2>&1 && echo LEAK || echo DENIED'
# => DENIED
```

Nota del spike: con `DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=1` la creación
de puentes falla con `netlink: operation not permitted`; con `=0` funciona. Con
`--bridge=none` Compose no puede crear su red. El perfil del daemon necesita
`dbus,` para `StartTransientUnit` de cgroups. Estos son requisitos de arranque,
no opcionales.

### Unitarias e integración (a ejecutar al implementar)

- Factory de Runner: dos tenants distintos producen dos `DOCKER_HOST`
  distintos; nunca cae al socket global.
- Generador de perfil AppArmor: allowlist mínima, sin `ix` en reglas `deny`,
  `dbus,` presente, paths generados desde el data-root del tenant.
- Preflight: sin `runsc`, sin perfil, sin cgroup delegado o sin reglas nftables →
  `AppDeployError` antes de cualquier `compose up`.
- Admisión: Compose con `privileged`, devices, host namespace, `docker.sock`,
  ruta fuera del tenant o `network_mode: host` → rechazo; Compose con binds y
  puertos internos del tenant → aceptado sin mutación.
- Probes: label AppArmor ausente, runtime `runc`, UID 0 en host, puerto en
  `0.0.0.0`, `RestartCount > 0` → rollback.
- Ingress: el registro agrega rutas de N sockets y el proxy alcanza cada IP;
  un tenant no ve la ruta de otro.
- Evidencia: contiene tenant, socket, perfil, runtime, label, UID y hashes.

### E2E real en el lab (a ejecutar al implementar)

1. Preflight de host: `userns`, AppArmor, `runsc`, cgroup v2, nftables.
2. Crear dos tenants con usuarios/subuids disjuntos y sus perfiles AppArmor.
3. Desplegar `luc444s/example-voting-app` sin hardener en el tenant A; verificar
   healthchecks, binds, 5 servicios activos y `seed` con perfil inactivo.
4. Desplegar `software-de-gestion-para-editores` en el tenant B; verificar que
   su Compose firmado llega sin mutaciones (mismo hash).
5. Verificar por tenant: `rootless`, label AppArmor, `runsc`, mapeo de UID,
   cgroup quotas, puerto solo en IP del proxy.
6. Negativos: leer `/etc/shadow`, el socket del panel, `.ssh` del host, el
   home del tenant B y el puerto publicado del tenant B → todo DENIED.
7. Retirar `runsc` y reintentar deploy → falla cerrado, sin `runc`.
8. Apagar un daemon tenant → las apps de los otros tenants siguen vivas.
9. Migrar una app de `hardened` a `tenant-rootless` y volver: datos intactos,
   releases antiguas sin reescribir.
10. Guardar evidencia en `artifacts/0096-tenant-rootless-e2e.json`.

## ROLLBACK

- Por app/tenant: fijar `SPANEL_APPS_RUNTIME=hardened` (o el valor del tenant)
  y hacer un deploy nuevo desde el mismo repo; el hardener produce una release
  firmada distinta, sin tocar la anterior.
- Los volúmenes y data-root del tenant se conservan; no se destruyen datos.
- Perfil AppArmor: `apparmor_parser -R` solo después de parar el daemon del
  tenant y sus contenedores.
- Daemon tenant: parada de la unidad `systemd --user`; no afecta a otros
  tenants ni al daemon del panel.
- Reglas nftables y usuario de sistema: se retiran con un script de operador;
  son cambios de host, no migraciones de aplicación.
- No hay downgrade de esquema ni migración física que demostrar (no se crea
  ninguna columna ni tabla).

## Change Surface

```yaml
change_surface:
  allowed:
    - aspecs/0096-tenant-rootless-docker-socket.md
    - vendor/systutor-core/plugins/apps/backend/runtime/tenant_daemon.py
    - vendor/systutor-core/plugins/apps/backend/runtime/runner_factory.py
    - vendor/systutor-core/plugins/apps/backend/runtime/probes.py
    - vendor/systutor-core/plugins/apps/backend/releases/admission.py
    - vendor/systutor-core/plugins/apps/backend/releases/scoped_execution.py
    - vendor/systutor-core/plugins/apps/backend/worker.py
    - vendor/systutor-core/plugins/apps/backend/catalog.py
    - vendor/systutor-core/plugins/apps/backend/router.py
    - vendor/systutor-core/plugins/apps/frontend/**
    - scripts/tests/test_tenant_rootless.py
    - scripts/tests/test_e2e_apps_voting_live.py
    - scripts/e2e_apps_trusted_deploy.py
    - scripts/tenant-rootless/*.sh
    - scripts/tenant-rootless/apparmor/*.in
    - scripts/tenant-rootless/nftables/*.nft
    - artifacts/0096-tenant-rootless-e2e.json
  prohibited:
    - repositorios de aplicaciones externas
    - scripts/dangerous_build/compose.py
    - scripts/dangerous_build/compose_normalizer.py
    - vendor/systutor-core/plugins/apps/backend/hardening/**
    - vendor/systutor-core/plugins/apps/backend/models.py
    - vendor/systutor-core/plugins/apps/backend/migrations/**
    - Dockerfile
    - docker-compose.yml
    - .env*
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - runtime de apps (seleccion de socket y daemon por tenant)
    - admision y firma de releases del perfil tenant-rootless
    - probes de aislamiento
    - ingress y firewall por tenant
    - host: systemd user, AppArmor, nftables, cgroups, runsc
  indirect:
    - UI de deployments (perfil/runtime/estado del tenant)
    - evidencia y auditoria
  must_not_affect:
    - perfil hardened y sus releases firmadas
    - normalizador y hardener (0087/0094/0095)
    - apps ya desplegadas mientras su tenant siga en hardened
    - modelos SQL y migraciones
    - repositorios de aplicaciones
    - panel, correo, hosting y dominios (otros plugins)
```

## Composition

```yaml
composition:
  requires_aspecs:
    - 0083-apps-trusted-deployment-pipeline.md
    - 0087-isolation-only-admission-policy.md
    - 0090-apps-gvisor-sandbox-profile.md
  must_compose_with:
    - 0094-apps-compose-normalizer.md
    - 0095-apps-network-topology-preservation.md
  systemic_invariants:
    - nunca existe un único socket compartido para apps
    - la admision no evalua contenido de la app, solo aislamiento
    - falla cerrado ante la ausencia de cualquier mecanismo de aislamiento
  composition_checks:
    - perfil hardened sigue desplegando con el hardener y su firma actual
    - perfil tenant-rootless despliega sin hardener y con runsc
    - un mismo repo desplegado en dos tenants distintos no comparte daemon
    - las releases firmadas de hardened no se reescriben al activar el perfil nuevo
```

Nota de alcance con 0090: se reutiliza su preflight de `runsc` y su requisito de
fail-closed, pero su envelope "sin binds ni puertos" aplica al perfil
`hardened`. En `tenant-rootless` la frontera de aislamiento es el daemon del
tenant (userns + AppArmor + firewall), por lo que binds y puertos dentro del
tenant son parte de este contrato y no una regresión de 0090.

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: una sola responsabilidad: dar al tenant un daemon aislado y verificar su confinamiento
  entrypoints_must_stay_thin: true
  review_threshold_lines: 400
  extraction_threshold_lines: 600
  preferred_new_logic_locations:
    - vendor/systutor-core/plugins/apps/backend/runtime/tenant_daemon.py
    - vendor/systutor-core/plugins/apps/backend/runtime/runner_factory.py
    - scripts/tenant-rootless/
```

## Traceability

- Requirement: ofrecer compatibilidad máxima con Compose reales sin relajar el
  aislamiento; aislamiento extremo por tenant.
- owner: Lucas (operador del lab y del server privado)
- approver: **PENDIENTE — requerido humano por `risk: high`**
- Commit: (se llena al integrar; el spike no tiene commit de plataforma)
- Deployment: lab `spanel.lab` → posteriormente `root@vmi3461574:/opt/spanel`

## Definition of Done

- [ ] Spike de viabilidad documentado y reproducible (ya ejecutado).
- [ ] Factory de Runner por tenant con socket privado y fail-closed.
- [ ] Daemon rootless por tenant bajo perfil AppArmor propio, verificado.
- [ ] `runsc` obligatorio, sin fallback a `runc`, verificado.
- [ ] Admisión del Compose original sin hardener, con firma y digests.
- [ ] Ingress multi-socket y firewall default-deny entre tenants.
- [ ] Cuotas cgroup por tenant efectivas.
- [ ] Invariantes I1–I15 verificados con comandos/tests.
- [ ] E2E real con dos tenants y sus casos negativos; evidencia guardada.
- [ ] Perfil `hardened` intacto y default; releases antiguas sin reescribir.
- [ ] Rollback ejecutado en lab con datos intactos.
- [ ] Aprobación humana registrada (risk: high).
- [ ] Suites, ruff y `git diff --check` en verde.
