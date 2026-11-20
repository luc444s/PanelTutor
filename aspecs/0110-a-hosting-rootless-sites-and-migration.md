# A.SPEC 0110-A — Hosting rootless: altas nuevas y migración de sitios

> `risk: high` — mueve datos persistentes de WordPress/MariaDB entre daemons,
> cambia el runtime de todas las operaciones de Hosting y realiza un cutover de
> tráfico. Requiere `approver:` y E2E con rollback real antes de producción.

## WHY

Las celdas rootless por tenant y el registro `tenant_resource_runtimes` ya
existen, pero Hosting continúa conectado a un único Docker global:

- `Provisioner`, `StaticProvisioner`, inspección, logs, configuración, archivos
  y backups usan `HostingSettings` / `docker_env()` sin resolver el runtime del
  sitio;
- `spanel-tenant migrate --all` solo tiene un `MigrationBackend` vacío en
  producción: ordena recursos en tests, pero no copia datos ni cambia rutas;
- cada celda publica un único endpoint. Vincular directamente cada sitio al
  mismo `127.x.y.z:20000+` no permite varios sitios o aplicaciones por tenant;
- los sitios nuevos todavía nacen rootful, aunque el tenant ya tenga una celda
  lista;
- mover solamente los contenedores perdería los volúmenes de estáticos,
  `wp-content`, MariaDB, secretos, backups y la capacidad de rollback.

La unidad de aislamiento sigue siendo el **tenant**: Hosting debe reutilizar el
UID, daemon rootless, plan y endpoint de la celda existente. No se crea un
segundo userspace para Hosting ni un daemon por sitio.

## WHAT

**Hosting obtiene un resolver de runtime común para todas sus operaciones; las
altas nuevas se crean en la celda rootless cuando la bandera lo permite; un
ingress interno de la celda multiplexa los dominios; y un CLI real migra
estáticos y WordPress mediante copia sombra, verificación, cutover y retención
del original rootful hasta `finalize`.**

La entrega es deliberadamente **backend + CLI**. No requiere cambios de UI.

## SCOPE

### A. Contrato opaco de ejecución por tenant

- Añadir `systutor.contracts.container_runtime`, sin importar modelos entre
  plugins. El contrato registra/resuelve un proveedor y devuelve un handle
  opaco con operaciones acotadas (`command`, `inspect`, transferencia por
  stream y datos públicos de salud); no entrega un socket a una petición HTTP.
- La integración de celdas registra el proveedor rootless reutilizando el
  `TenantRuntimeRegistry` y el slug real del tenant. El fallback registrado es
  el runtime rootful actual.
- Hosting añade `HostingRuntimeResolver`, que decide usando
  `(tenant_id, kind, site.id)` y `tenant_resource_runtimes`:
  - recurso registrado `rootless` → celda, aunque la feature flag esté apagada;
  - recurso registrado `rootful` → Docker global;
  - alta aún no registrada + `SPANEL_TENANTS_ROOTLESS=true` + celda `ready` →
    candidato rootless;
  - cualquier ambigüedad/fallo de celda → fail closed, nunca caída silenciosa al
    daemon rootful.
- Extender el contrato de runtime/recorder existente para leer, fijar y restaurar
  runtime sin que Hosting importe `plugins.tenant.backend.models`.
- `SPANEL_TENANTS_ROOTLESS=false` bloquea nuevas altas/migraciones rootless,
  pero no cambia cómo se administran sitios ya marcados `rootless`.

### B. Todo Hosting usa el resolver

Inyectar el runtime resuelto en:

- creación, preflight, cleanup y eliminación;
- inspect/listado/estado, start/stop/restart y logs;
- configuración, lectura de `wp-config.php`, usuarios y reset de contraseña;
- resolución de la base y rotación de secretos;
- file manager;
- export/import de backups;
- publicación/retirada de rutas.

`Provisioner` y `StaticProvisioner` dejan de construir internamente un único
`docker_env`; reciben un executor/runtime explícito. Las rutas HTTP resuelven el
sitio y su tenant antes de cualquier operación Docker.

### C. Ingress compatible con varios sitios por celda

- Crear dentro de cada daemon rootless un único `spanel-cell-ingress`, marcado
  `spanel.role=cell-infra`, y la red `spanel-hosting`.
- El único puerto publicado de la celda apunta al ingress, no directamente a un
  sitio. El ingress enruta por `Host` hacia contenedores de esa misma celda.
- Hosting mantiene rutas declarativas `{site_id, domain, target, port}` mediante
  un backend que valida dominio, pertenencia y labels. No acepta paths o argv
  desde el cliente.
- WordPress, su MariaDB y los estáticos usan redes internas rootless. Solo el
  contenedor web se conecta a `spanel-hosting`; MariaDB nunca se conecta al
  ingress ni publica `3306`.
- `RootlessRoutePublisher` publica cada dominio de Hosting al relay estable de
  la celda. Traefik central no se une a redes rootless ni inspecciona sus
  contenedores.
- La reconciliación del ingress es idempotente, atómica y recuperable tras
  reinicio. Un archivo inválido no reemplaza la última configuración válida.
- Apps podrá consumir este ingress mediante el mismo contrato en una entrega
  posterior; 0110-A garantiza varios sitios Hosting sin cambiar Apps.

### D. Altas nuevas cell-compatible

- `POST /plugins/hosting/sites` genera el `site.id` antes del provisioning y
  selecciona runtime candidato mediante `HostingRuntimeResolver`.
- Con rootless habilitado:
  1. exige celda `ready` y plan efectivo;
  2. crea volúmenes/contenedores en el daemon de la celda;
  3. registra la ruta en el ingress interno;
  4. publica el dominio hacia el relay;
  5. verifica DB/HTTP por el runtime candidato;
  6. inserta `hosting_sites`, reclama el dominio y persiste `rootless` en la
     misma transacción de aplicación;
  7. audita runtime, celda y resultado sin secretos.
- Si falla cualquier paso se retira ruta/publicación y se eliminan únicamente
  los recursos candidatos con labels exactas. No se crea una fila ni un runtime
  mentiroso.
- Sin bandera, la creación rootful existente conserva comportamiento y contrato.

### E. Migrador backend real

Crear `plugins/hosting/backend/rootless_migration.py` con una máquina de estados
persistente/auditable:

```text
planned → copying → candidate_ready → cutover → verified → retained → finalized
                     │                 │
                     └──── failed/rolled_back ────┘
```

La operación se identifica por `operation_id`; reintentar el mismo paso es
idempotente. Un lock por `site.id` impide dos migraciones, restore, delete o
rotación concurrentes.

#### Estáticos

1. Inspeccionar labels, volumen, perfil, dominio y runtime rootful.
2. Crear volumen y contenedor sombra con los mismos nombres en el daemon
   rootless (los namespaces de ambos daemons son independientes).
3. Transferir el volumen como stream `tar` rootful → rootless, sin extraerlo en
   una ruta arbitraria del host.
4. Verificar marcador/perfil, ownership, health e HTTP interno.
5. Hacer cutover y verificación externa.

#### WordPress

1. Resolver `wp`, MariaDB, ambos volúmenes, credenciales y labels; abortar si la
   DB es externa/no gestionada o la asociación es ambigua.
2. Crear un backup de recuperación usando el formato validado de Hosting.
3. Hacer copia inicial de `/var/www/html` y dump consistente de MariaDB.
4. Crear WordPress y MariaDB sombra dentro de la celda, sin ruta pública.
5. Entrar en una ventana breve de mantenimiento, hacer dump/copia final y
   mantener los mismos nombres DNS internos (`<slug>-db`) dentro del daemon
   destino.
6. Importar DB, restaurar archivos y comprobar:
   `wp core is-installed`, prefijo/tablas, URL, uploads y HTTP interno.
7. Aplicar ruta/cutover, persistir runtime y comprobar HTTP externo.
8. Salir de mantenimiento. El original rootful queda detenido pero retenido.

Las contraseñas no aparecen en argv, stdout, JSON, auditoría ni artefactos. Los
env files rootless viven bajo el estado de la celda con dueño UID de la celda y
modo `0600`, nunca en `/tmp`.

### F. CLI/script de operador

Crear el script ejecutable **`scripts/hosting_migrate_rootless.py`** como wrapper
del mismo servicio backend (sin duplicar lógica Docker):

```bash
# Plan puro: inventario, capacidad, datos y acciones; cero mutaciones
python3 scripts/hosting_migrate_rootless.py plan \
  --site <site-id> --json
python3 scripts/hosting_migrate_rootless.py plan \
  --tenant <tenant-slug> --kind static|wordpress --all --json

# Migración secuencial; por defecto para ante el primer fallo
python3 scripts/hosting_migrate_rootless.py migrate \
  --site <site-id> [--dry-run] [--json]
python3 scripts/hosting_migrate_rootless.py migrate \
  --tenant <tenant-slug> --all \
  [--kind static|wordpress] \
  [--exclude <site-id>] \
  [--stop-on-failure|--continue-on-failure] [--json]

# Recuperación y retiro explícitos
python3 scripts/hosting_migrate_rootless.py rollback \
  --site <site-id> --operation <operation-id> --json
python3 scripts/hosting_migrate_rootless.py finalize \
  --site <site-id> --operation <operation-id> \
  --confirm-domain <domain> --json

# Diagnóstico/reconciliación sin inventar recursos
python3 scripts/hosting_migrate_rootless.py status --site <site-id> --json
python3 scripts/hosting_migrate_rootless.py reconcile --site <site-id> --json
```

- `plan` y `migrate --dry-run` no escriben DB/registry, no crean contenedores,
  no paran sitios y no publican rutas.
- `migrate --all` real reemplaza el `MigrationBackend` vacío para `static` y
  `wordpress`; Apps conserva su migrador propio.
- Orden fijo: `static` → `wordpress`; estable por `site.id`.
- Aplicar exige `SPANEL_TENANTS_ROOTLESS=true` y el gate host existente.
- `finalize` es la única operación que elimina contenedores/volúmenes rootful y
  exige confirmación literal del dominio más backup verificado.
- Salidas JSON tienen `ok`, `operation_id`, `site_id`, `kind`, `from_runtime`,
  `to_runtime`, `state`, `steps`, `rollback_available` y errores redactados.

### G. Backend HTTP de administración

Exponer una superficie platform-only, reutilizando exactamente el servicio del
CLI:

```text
GET  /plugins/hosting/sites/{site_id}/rootless/plan
POST /plugins/hosting/sites/{site_id}/rootless/migrate
POST /plugins/hosting/sites/{site_id}/rootless/rollback
POST /plugins/hosting/sites/{site_id}/rootless/finalize
GET  /plugins/hosting/sites/{site_id}/rootless/status
```

Requiere `hosting.sites.manage` **y** `core.platform.admin`. No se aceptan
container names, sockets, paths, argv ni destinos de red desde la petición.

## OUT OF SCOPE

- phpMyAdmin rootless/compartido: A.SPEC 0110-B.
- Migrar Apps, correo, Traefik, PowerDNS, Docker Mailserver o la DB del panel.
- UI de migraciones.
- Borrar automáticamente originales rootful por tiempo.
- Migrar WordPress con DB externa/no gestionada.
- Cambiar perfiles estáticos o contenido de usuario durante la migración.
- Invocar Alembic CLI manualmente. Cualquier migración del plugin usa el runtime
  migrador de plugins de systutor-core.
- Producción antes del E2E y del simulacro de rollback.

## CONTRACT

1. Con bandera activa y celda lista, un estático y un WordPress nuevos nacen en
   `unix://<data_root>/cells/<slug>/docker.sock`, quedan registrados `rootless`
   solo tras health + publicación + HTTP 200 y todas sus operaciones posteriores
   usan ese runtime.
2. Dos sitios del mismo tenant con Hosts distintos responden simultáneamente por
   el único endpoint/relay de su celda; MariaDB no publica puertos.
3. `plan`/`--dry-run` dejan byte-idénticos DB, registry, rutas, contenedores,
   volúmenes y estado del sitio.
4. Migrar un estático preserva hash del contenido y perfil; migrar WordPress
   preserva DB, usuarios, opciones, plugins/themes y uploads.
5. Runtime cambia a `rootless` únicamente después de verificar candidato y ruta.
6. Hasta `finalize`, el original rootful y un backup válido permiten rollback.
7. Un fallo en copia, DB, ingress, publicación o HTTP restaura ruta/runtime y
   devuelve servicio rootful sin eliminar sus datos.
8. Con feature flag apagada, sitios ya rootless siguen administrables y nuevas
   migraciones se rechazan.

## INVARIANTS

```yaml
invariants:
  - "Un tenant reutiliza una sola celda, UID, daemon rootless, plan y endpoint; Hosting no crea otro userspace."
  - "Toda operacion de Hosting resuelve runtime por tenant/kind/site_id antes de tocar Docker."
  - "Nunca hay fallback silencioso rootless→rootful ante una celda rota."
  - "El ingress de celda multiplexa Hosts; MariaDB permanece interna y sin puerto publicado."
  - "Runtime rootless se persiste solo despues de datos, health, ruta y HTTP verificados."
  - "Rollback conserva contenedores, volumenes, secretos y backup rootful hasta finalize explicito."
  - "Dry-run produce cero mutaciones observables."
  - "No se filtran secretos en argv, logs, auditoria, JSON ni artefactos."
  - "Core y otros tenants conservan PID/config/rutas y no reciben conexiones del tenant migrado."
  - "SPANEL_TENANTS_ROOTLESS=false nunca reescribe recursos ya registrados."
```

## VERIFICATION

```bash
python3 -m pytest \
  scripts/tests/test_hosting_migrate_rootless.py \
  scripts/tests/test_tenant_cell_migrate.py -q

PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -m pytest \
  vendor/systutor-core/plugins/hosting/backend/tests \
  vendor/systutor-core/plugins/tenant/backend/tests/test_resource_runtimes.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_tenant_runtime.py -q

ruff check \
  scripts/hosting_migrate_rootless.py \
  scripts/tenant_cell/cli.py \
  vendor/systutor-core/src/systutor/contracts/container_runtime.py \
  vendor/systutor-core/plugins/hosting/backend/runtime.py \
  vendor/systutor-core/plugins/hosting/backend/rootless_ingress.py \
  vendor/systutor-core/plugins/hosting/backend/rootless_migration.py
```

E2E black-box en `spanel.lab`, con dos tenants desechables:

1. crear dos estáticos y un WordPress nuevo en una celda; tres Hosts HTTP 200;
2. migrar un estático legacy y comparar hashes;
3. migrar WordPress con posts, usuario, plugin y upload fixture; comparar antes y
   después;
4. inducir fallo después del cambio de ruta y demostrar rollback rootful HTTP 200;
5. ejecutar `finalize` solo sobre una migración sana;
6. verificar límites agregados, `delta_denied=0`, cero puertos DB, Core y segundo
   tenant intactos, y cleanup completo.

Artefacto: `artifacts/0110-a-hosting-rootless-sites-e2e.json`.

### Requisitos de despliegue del host

Estos requisitos pertenecen al despliegue del host; no autorizan modificar
`docker-compose.yml` dentro de 0110-A:

- el proceso/contenedor de la aplicación debe recibir
  `SPANEL_TENANTS_ROOTLESS=true`;
- debe montar el registro de celdas `registry.json` y `/var/lib/spanel/cells`
  en las mismas rutas esperadas por el runtime;
- debe montar el token del plan agent y configurar/montar `plan-agent.sock`;
- debe montar `edge-relay.sock` y el directorio `dynamic` usado por el file
  provider de Traefik con permisos de escritura para el publicador;
- el host debe resolver `*.lab` hacia Traefik (DNS wildcard o resolver local
  equivalente) y cada celda debe tener instalado/cargado el perfil AppArmor
  definido por 0105 antes de aprovisionar workloads;
- el relay, plan agent, registro y sockets deben corresponder al mismo
  `data_root`; endpoints o tokens obsoletos bloquean el despliegue en lugar de
  provocar fallback rootful.

Para laboratorios sin DNS wildcard, el E2E puede dirigir las sondas al origen
HTTP de Traefik preservando el `Host`, mediante `--external-base` o
`SPANEL_E2E_EXTERNAL_BASE`. El bearer token puede darse con
`SPANEL_E2E_TOKEN` para no exponerlo en argv.

## Estado transitorio de cierre en laboratorio (2026-11-20)

> Bitácora temporal, no constituye Evidence PASS ni autorización de
> producción. Se retirará o convertirá en trazabilidad final cuando la
> ceremonia complete todos sus checks.

### Avance confirmado

- Corregido `RootlessRoutePublisher.publish()`: propaga el valor efectivo de
  `SPANEL_ROOTLESS_ROUTES_HTTPS` al publisher de Domains. Regresión incluida
  para `https=False`.
- Corregido `_verify_external()`: reintento exponencial acotado por deadline de
  30 s, en vez de una única sonda que competía con el file provider de Traefik.
- El E2E acepta oficialmente `SPANEL_E2E_TOKEN` y
  `SPANEL_E2E_EXTERNAL_BASE`, conservando el header `Host`.
- El E2E limita la lectura de audit del kernel al inicio de la corrida y filtra
  por perfil de la celda; evita bloquearse leyendo el journal histórico.
- Regresiones específicas ejecutadas en el lab: `13 passed`; Ruff sobre los
  archivos modificados: PASS.
- Despliegue del host completado en el lab: mounts de `registry.json`,
  `/var/lib/spanel/cells`, token/socket del plan agent, socket del relay y
  directorio dynamic de Traefik; `SPANEL_TENANTS_ROOTLESS=true`.
- DNS wildcard efectivo: `*.lab -> 172.25.0.3` (Traefik), tanto para el
  contenedor app como para el host mediante `systemd-resolved`.
- Perfil AppArmor `spanel-cell-demo` cargado en enforce; el registry conserva
  `apparmor_effective=true` para `demo`.
- `spanel-plan-agent.service` y `spanel-edge-relay.service` instalados y
  activos. Relay alineado a `172.25.0.1:40070`; endpoint de la celda
  `127.70.0.1:20070`; origen Traefik permitido `172.25.0.3`.

### Corridas y errores encontrados

1. **FAIL antes de mutar**: `journalctl -k` completo agotaba 60 s.
   Solución: ventana temporal + `--grep spanel-cell-demo`; cleanup completo.
2. **FAIL de arranque**: API devolvió 404 mientras el entrypoint aún habilitaba
   plugins. Solución operativa: esperar a que OpenAPI exponga Hosting antes de
   iniciar la ceremonia; no dejó recursos.
3. **FAIL de publicación**: Domains seleccionaba SSH aunque el directorio
   dynamic estaba montado localmente. Solución del lab:
   `SPANEL_PROXY_TRANSPORT=local`.
4. **FAIL con 502**: el plan agent anunciaba el bind por defecto
   `172.18.0.1`, mientras el relay real escuchaba en `172.25.0.1`.
   Solución: fijar `SPANEL_EDGE_RELAY_BIND=172.25.0.1` en agente y relay.
5. **FAIL por source deny**: el relay rechazaba a Traefik
   (`source=172.25.0.3`). Solución:
   `SPANEL_EDGE_RELAY_SOURCES=172.25.0.3` en ambos servicios.
6. **Resuelto**: después de alinear bind/source, dos altas estáticas rootless
   quedaron registradas en `demo` y respondieron HTTP 200 por Traefik:
   `a-1795195517.lab` (`09951f5a-...`) y `b-1795195517.lab`
   (`8bd136a3-...`).
7. **Bloqueante actual**: el alta WordPress creó su MariaDB en la celda, pero
   el cliente E2E agotó su timeout de 60 s durante el primer provisioning. Esto
   reveló que el harness registraba IDs para cleanup solo después de completar
   una comprensión con las tres altas; si la tercera fallaba, perdía los IDs de
   las dos primeras. Solución aplicada: timeout acotado de 300 s únicamente
   para altas y registro incremental de cada site para cleanup.
8. **Confirmación posterior**: WordPress terminó el provisioning en servidor
   después del timeout del cliente. `a-1795195517.lab`,
   `b-1795195517.lab` y `wp-1795195517.lab` devolvieron HTTP 200; los cuatro
   workloads (`static-1`, `static-2`, `wp`, `db`) aparecen únicamente en el
   socket rootless de `demo`. El listener `127.0.0.1:3306` observado en el host
   es preexistente y pertenece al MariaDB compartido del lab; el E2E ahora
   demuestra que la corrida no añade listeners `:3306`, comparando baseline y
   estado final, en vez de atribuir falsamente ese listener a la celda.
9. **Bloqueante de migración identificado**: el CLI heredaba del contenedor
   `SYSTUTOR_PLUGINS_DIR=/app/plugins` al ejecutarse en el host. Esa ruta no
   existe allí, el runtime no registraba Tenant y
   `resource runtime registry is not registered unambiguously`; además podía
   dejar plugins persistentes temporalmente no disponibles. Solución aplicada:
   el CLI conserva una ruta configurada válida, pero reemplaza una ruta
   inexistente por `vendor/systutor-core/plugins` del checkout, con regresión.
   Una primera corrección ejecutaba ese fallback después de importar
   `app.main`; dicho import construye una app a nivel de módulo y cachea los
   settings incorrectos. El fallback se movió antes del import, también cubierto
   por regresión de orden.
10. **Harness legacy**: tras resolver el CLI, una corrida alcanzó la carga del
    fixture estático y recibió 409 porque el nombre fijo de una ejecución
    anterior ya existía. Los nombres de fixture static/WordPress ahora incluyen
     el `suffix` de la corrida; la prueba sigue comparando el mismo contenido
     antes/después sin depender de limpieza histórica.
11. **Contrato JSON del operador**: la migración llegó a
    `candidate_verified`, pero mensajes de bootstrap precedían al JSON en
    stdout. `--json` ahora redirige salida incidental a stderr y reserva stdout
    para un único documento parseable, con regresión.
12. **Cleanup de candidato de migración**: una corrida fallida antes del
    cutover dejó el contenedor static sombra, y el reintento chocó por nombre.
    La recuperación ahora retira ingress y candidato tras restaurar rootful;
    rollback/finalize seleccionan `StaticProvisioner` para estáticos y
    `Provisioner` para WordPress. Regresión incluida para ambos tipos.
13. **Orden de cutover**: el publisher rootless rechazó correctamente el Host
    porque el documento rootful seguía gestionándolo. El migrador ahora retira
    primero la ruta rootful, publica la rootless y verifica; cualquier fallo
    entra en la restauración rootful existente. Regresión de orden incluida.
14. **Race de verificación en migración**: tras `route_cutover`, el migrador
    conservaba otra sonda HTTP única y cayó en 404 mientras Traefik recargaba.
    Altas y migraciones ahora comparten el mismo verificador con backoff y
    deadline; no existen dos políticas de readiness divergentes.
15. **Readiness de MariaDB migrada**: WordPress candidato se validaba apenas el
    contenedor DB estaba `running`, antes de aceptar conexiones, y `wp-cli`
    fallaba con `Error establishing a database connection`. La validación de
    `wp core is-installed` ahora reutiliza el retry acotado de Provisioner hasta
    que la DB importada esté realmente disponible.
16. **Verificación con HTTPS activo**: con `SPANEL_ROOTLESS_ROUTES_HTTPS=true`,
    el alta nueva fallaba: la sonda seguía el 301 de `web` hacia `websecure` y
    no confiaba en la CA interna del lab. El verificador ahora usa el esquema
    efectivo (devuelto por `publish()`) y construye su contexto TLS con
    `SPANEL_PROXY_CA_FILE` cuando existe. Verificado: alta 201 en 6.4 s y
    cadena válida `Spanel Lab CA` (`Verify return code: 0`).
17. **Borrado con historial de migración**: eliminar un sitio con operaciones
    registradas violaba `hosting_rootless_migrations_site_id_fkey` y devolvía
    500. El borrado purga primero esas operaciones propias, con regresión.
18. **Carrera del propio E2E**: tras reiniciar el relay, comprobaba el Host
    legacy con una sola sonda y Traefik aún recargaba. La sonda externa del E2E
    ahora tiene deadline acotado de 30 s; no cambia la semántica de los checks.

La ceremonia se repitió con HTTPS activo (modo por defecto del producto) y
terminó PASS 8/8; el artefacto corresponde al código final.

### Límites y condiciones de la prueba

- La ceremonia se ejecuta en `spanel.lab`, no en Termux.
- El lab usa un override de despliegue no versionado; `docker-compose.yml`
  permanece prohibido y sin cambios por 0110-A.
- El drill de rollback requiere privilegios de operador para detener/arrancar
  `spanel-edge-relay.service`; por eso el E2E se lanza como operador del host.
- Las fixtures legacy existentes son
  `legacy-static-0110a.lab` y `legacy-wp-0110a.lab`; el E2E no alterna flags en
  caliente ni inventa fixtures si faltan.
- El artefacto contiene un PASS real de la ceremonia completa. DoD puede
  marcarse, pero `approver`, `Commit`, `Deployment` de producción y la
  aceptación formal siguen requiriendo revisión humana; este PASS no autoriza
  por sí solo un despliegue productivo.

### Criterio visible para cerrar esta etapa

Antes de declarar terminada 0110-A se mostrará, en la celda `demo`:

1. un sitio estático con Host propio, HTTP 200 y hash de contenido verificado;
2. un WordPress con Host propio, HTTP 200, usuarios y upload verificados;
3. ambos presentes en
   `unix:///var/lib/spanel/cells/demo/docker.sock` y ausentes del daemon
   rootful;
4. MariaDB interna sin listener host `:3306`;
5. E2E PASS con rollback, rollback post-cutover, finalize,
   `delta_denied=0`, Core/segundo tenant intactos y cleanup completo.

### Resultado final de la ceremonia

La ceremonia completa terminó con `result=PASS`, `errors=[]` y
`cleanup_complete=true` en
`artifacts/0110-a-hosting-rootless-sites-e2e.json`, con estos ocho checks:

1. `new_rootless_multi_host`: dos estáticos y un WordPress nuevos, HTTP 200.
2. `static_shadow_copy`: hash idéntico antes/después.
3. `wordpress_shadow_copy`: hash y usuarios preservados.
4. `rollback`: estático restaurado a runtime rootful.
5. `post_cutover_failure_rollback`: relay detenido, migración fallida y
   restauración rootful HTTP 200; operación limpiada.
6. `finalize`: WordPress migrado, original rootful retirado explícitamente.
7. `no_database_publish`: sin listeners `:3306` nuevos.
8. `isolation_and_limits`: `delta_denied=0`, Core y segundo tenant intactos,
   celda `ready`, cleanup completo.

Demostración persistente adicional en la celda `demo` (fuera del E2E
efímero), para inspección manual:

- estático `demo-static-demo0110.lab`, site
  `89f0ff7e-5bac-4f06-9ee5-b1ddd9c20ccb`, contenedor
  `spanel-demo-static-web`, HTTP 200; `demo.html` subido por File Manager,
  HTTP 200, SHA-256 `75fc09ee8d6b75c9d3383080285d6e1e46913ebeb57c2328fc862ba2f89d9093`;
- WordPress `demo-wordpress-demo0110.lab`, site
  `5bf2d8d5-208a-4b32-8f20-d7574da04e7c`, contenedores
  `spanel-demo-wordpress-wp` y `spanel-demo-wordpress-db`, login HTTP 200;
- ambos registrados `rootless`, presentes solo en
  `unix:///var/lib/spanel/cells/demo/docker.sock`, ausentes del Docker
  rootful, y ejecutándose bajo `spanel-cell-demo (enforce)`.

Los dos sitios demo se republicaron además con HTTPS (`SPANEL_ROOTLESS_ROUTES_HTTPS=true`
en el override del lab), usando el `certResolver internal` del laboratorio:
ambos responden 200 por `websecure` con certificado emitido por
`Spanel Lab CA`, y `web` redirige 301 a HTTPS. El contenido servido por HTTPS
conserva el mismo SHA-256 que por HTTP.

Pendiente exclusivamente de proceso humano: asignar `approver`, fijar `Commit`
y describir `Deployment` en Traceability. No se declara producción.

### Por qué Traefik no hace autodiscover de estos sitios

El Traefik del lab usa únicamente el **file provider**
(`providers.file.directory: /etc/traefik/dynamic`, `watch: true`); no tiene
provider Docker. Esto es deliberado y no un olvido:

- Los sitios rootless viven en un `dockerd` rootless distinto por celda. El
  Traefik rootful no puede listar esos contenedores (otro socket), ni unirse a
  `spanel-hosting`, ni resolver sus nombres.
- Habilitar el provider Docker solo vería el daemon rootful. Para ver las
  celdas habría que montar cada socket rootless en Traefik, dándole visibilidad
  y control sobre todos los tenants: ruptura directa del aislamiento.
- Las etiquetas Docker las escribe quien puede crear contenedores. Publicar por
  etiqueta permitiría a cualquier contenedor reclamar un Host ajeno. El
  publisher de Domains valida dominio, propiedad, conflictos y escribe el YAML
  de forma atómica con marcador `managed-by: spanel`.
- Por eso el diseño es: ingress por celda (multiplexa Hosts) → relay
  no privilegiado → un YAML gestionado por dominio en el file provider. Un
  único puerto publicado por celda y Traefik sin acceso al daemon del tenant.

## ROLLBACK

- Antes de cutover: retirar candidato y ruta interna; original sigue sirviendo.
- Después de cutover: restaurar documento de ruta, runtime y sitio rootful;
  retirar candidato de publicación sin borrar su evidencia hasta cerrar operación.
- Alta nueva fallida: cleanup solo por labels exactas del candidato; no fila/runtime.
- `finalize` no tiene rollback automático: exige backup verificado y confirmación.

## Change Surface

```yaml
change_surface:
  allowed:
    - vendor/systutor-core/src/systutor/contracts/container_runtime.py
    - vendor/systutor-core/src/systutor/contracts/resource_runtime.py
    - vendor/systutor-core/src/systutor/contracts/file_targets.py
    - vendor/systutor-core/src/systutor/contracts/README.md
    - vendor/systutor-core/plugins/tenant/backend/**
    - vendor/systutor-core/plugins/hosting/backend/**
    - vendor/systutor-core/plugins/filemanager/backend/**
    - vendor/systutor-core/plugins/hosting/migrations/005_rootless_migration_operations.py
    - vendor/systutor-core/plugins/hosting/README.md
    - scripts/tenant_cell/cli.py
    - scripts/hosting_migrate_rootless.py
    - scripts/tests/test_tenant_cell_migrate.py
    - scripts/tests/test_hosting_migrate_rootless.py
    - scripts/e2e_0110_a_hosting_rootless.py
    - artifacts/0110-a-hosting-rootless-sites-e2e.json
    - aspecs/0110-a-hosting-rootless-sites-and-migration.md
  prohibited:
    - vendor/systutor-core/plugins/mail/**
    - vendor/systutor-core/plugins/apps/backend/catalog.py
    - scripts/tenant_cell/apparmor.py
    - docker-compose.yml
    - apps/web/**
    - /opt/stacks/**
```

## Traceability

- Requirement: Hosting rootful → userspace/celda rootless por tenant, incluyendo
  altas nuevas, estáticos y migrador real de WordPress.
- Depends on: 0107, 0108 y 0109-R4.
- owner: lucas
- approver: pendiente (requiere revisión humana)
- Commit: pendiente
- Evidence: `artifacts/0110-a-hosting-rootless-sites-e2e.json` — PASS en
  `spanel.lab`, 2026-11-20, 8/8 checks, `cleanup_complete=true`.
- Deployment: validado en laboratorio; producción sigue prohibida hasta que un
  approver humano revise el PASS, fije el Commit y confirme los requisitos de
  despliegue del host.

## Definition of Done

- [x] Altas nuevas estáticas y WordPress nacen rootless con rollback de creación.
- [x] Resolver único usado por todas las operaciones de Hosting.
- [x] Ingress sirve múltiples Hosts por celda y DB no expuesta.
- [x] `scripts/hosting_migrate_rootless.py` implementado y probado.
- [x] Migración static + WordPress preserva datos y runtime correcto.
- [x] Rollback post-cutover demostrado con original rootful retenido.
- [x] `finalize` explícito demostrado sobre una copia verificable.
- [x] E2E black-box PASS, `delta_denied=0` y cleanup verificado.

Evidencia: `artifacts/0110-a-hosting-rootless-sites-e2e.json`
(`result=PASS`, `cleanup_complete=true`, `errors=[]`).
