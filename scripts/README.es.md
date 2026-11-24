# Scripts operativos de SPanel

[English](README.md) | Español

Este directorio reúne herramientas de operador, migraciones puntuales,
laboratorios y pruebas E2E. Este documento es el índice para decidir **qué
script usar, dónde ejecutarlo y qué puede modificar**.

Ejecuta los comandos desde la raíz del repositorio, salvo que una sección diga
lo contrario:

```bash
cd /ruta/a/mailadmin
python3 scripts/<script>.py --help
```

## Reglas de seguridad

- Revisa primero `--help` y usa `--dry-run`, modo plan o ejecución sin
  `--apply`/`--execute` cuando exista.
- No confundas **Hosting** con **Apps**. Hosting registra sitios WordPress o
  estáticos existentes; Apps administra proyectos Docker Compose mediante su
  runtime o API.
- Los scripts que usan la base de datos cargan la configuración normal de
  SPanel. Verifica que apunte al entorno correcto antes de ejecutarlos.
- Los scripts Docker actúan sobre el daemon seleccionado por el entorno
  (`DOCKER_HOST` o las variables `SPANEL_DOCKER_SSH_*`, según la herramienta).
- No pases secretos por argumentos salvo que el propio CLI lo requiera. Los
  argumentos pueden quedar visibles en el historial y en la lista de procesos.
- Haz un respaldo antes de cualquier operación marcada como **destructiva**.

### Niveles usados en este documento

| Nivel | Significado |
|---|---|
| **Lectura** | Diagnóstico; no debería cambiar estado. |
| **Plan por defecto** | No escribe hasta agregar `--apply`, `--execute`, `--fix` o `--yes`. |
| **Escritura** | Puede modificar base de datos, configuración, rutas o recursos Docker. |
| **Destructivo** | Puede borrar, reemplazar o restaurar recursos. Requiere revisión especial. |

## Guía rápida

| Necesidad | Script |
|---|---|
| Desplegar o actualizar Spanel | [`deploy.sh`](#deploysh) |
| Dar un permiso a un operador de tenant | [`grant_tenant_permission.py`](#grant_tenant_permissionpy) |
| Adoptar un WordPress concreto | [`hosting_adopt.py`](#hosting_adoptpy) |
| Descubrir y sincronizar todos los sitios publicados | [`hosting_sync.py`](#hosting_syncpy) |
| Completar el dominio de un sitio adoptado | [`hosting_set_domain.py`](#hosting_set_domainpy) |
| Dar de baja un sitio sin borrar su contenedor | [`hosting_down.py`](#hosting_downpy) |
| Eliminar completamente un WordPress gestionado | [`hosting_delete_wordpress.py`](#hosting_delete_wordpresspy) |
| Respaldar o restaurar un sitio | [`site_backup.py`](#site_backuppy) / [`site_restore.py`](#site_restorepy) |
| Operar Apps por HTTP | [`spanel_apps.py`](#spanel_appspy) |
| Provisionar o rotar la firma de releases de Apps | [`configure_apps_release_key.py`](#configure_apps_release_keypy) |
| Auditar o desplegar Compose directamente | [`app_deploy.py`](#app_deploypy) |
| Publicar o retirar un dominio en Traefik | [`proxy_domain.py`](#proxy_domainpy) |
| Refrescar/adoptar el inventario observado | [`domains_sync.py`](#domains_syncpy) / [`domains_adopt.py`](#domains_adoptpy) |
| Diagnosticar/reparar rutas y TLS | [`spanel-repair.py`](#spanel-repairpy) |
| Administrar certificados de correo | [`install_cert_agent.py`](#install_cert_agentpy), [`configure_cert_agent_dms.py`](#configure_cert_agent_dmspy) y [`spanel_cert_agent/`](#spanel_cert_agent) |
| Migrar un tenant a rootless en una sola ejecución | [`spanel-migrator-to-rootless`](#spanel-migrator-to-rootless) |
| Instalar/reparar el plan agent y el edge relay del host | [`install_tenant_agents.py`](#install_tenant_agentspy) |
| Redesplegar Apps en la celda rootless | [`migrate_tenant_apps.py`](#migrate_tenant_appspy) |
| Migrar un App existente al ingress de celda y al relay | [`migrate_apps_rootless.py`](#migrate_apps_rootlesspy) |
| Migrar la pila legacy de milton (binds/BD compartida) | [`migrate_milton_legacy.py`](#migrate_milton_legacypy) |
| Migrar certificados SNI legacy | [`migrate_legacy_sni.py`](#migrate_legacy_snip) |

## Despliegue

### `deploy.sh`

**Escritura.** Ejecuta el despliegue Compose canónico `spanel` con el override
de PowerDNS. Crea la clave de cifrado de forma atómica y con modo `600` cuando
falta, la valida cuando existe y nunca la rota.

```bash
./scripts/deploy.sh
```

Requiere `.env.docker`, `.env.powerdns` y `SPANEL_APPS_PUBLIC_URL` o
`SPANEL_DOMAIN`. Para seleccionar otra ruta de clave, define
`SPANEL_APPS_ENCRYPTION_KEY_PATH` en `.env.docker`.

Antes de construir, comprueba que la imagen de probe de Apps fijada por digest
(por defecto, o `SPANEL_APPS_PROBE_IMAGE`) existe localmente; si no, la
descarga y **aborta sin desplegar** cuando no puede obtenerla.

### `grant_tenant_permission.py`

**Escritura; dispone de dry-run.** Crea un rol durable del tenant y asigna
permisos explícitos sin conceder `core.platform.admin`. Para el operador que
puede registrar el cliente OAuth compartido de Cloudflare:

```bash
python3 scripts/grant_tenant_permission.py \
  --tenant TENANT_SLUG \
  --email operador@example.com \
  --role cloudflare_registrar \
  --permission domains.cloudflare.register \
  --dry-run

# Repetir sin --dry-run después de revisar el plan.
```

Dentro del contenedor de producción usa
`/app/scripts/grant_tenant_permission.py`.

## Hosting y WordPress

### `hosting_adopt.py`

**Plan por defecto con `--dry-run`; escritura sin esa opción.** Adopta un único
contenedor WordPress existente en un tenant. Verifica que sea WordPress y crea
una fila `hosting_sites` más su auditoría. No inicia, detiene ni modifica el
contenedor.

```bash
python3 scripts/hosting_adopt.py \
  --container spanel-demo-wp --tenant demo --domain demo.example --dry-run

# Después de revisar:
python3 scripts/hosting_adopt.py \
  --container spanel-demo-wp --tenant demo --domain demo.example
```

No sirve para adoptar recursos de Apps ni sitios estáticos.

### `hosting_sync.py`

**Plan por defecto; escribe únicamente con `--apply`.** Recorre los
contenedores en ejecución, lee sus labels de Traefik, deduce dominio y tipo,
resuelve el tenant y reconcilia `hosting_sites`. Puede adoptar sitios WordPress
y estáticos o completar datos de filas existentes. Nunca inicia, detiene o
elimina contenedores.

```bash
# Revisar todo
python3 scripts/hosting_sync.py

# Revisar solamente uno y resolver datos ambiguos
python3 scripts/hosting_sync.py \
  --only sitio-web \
  --assign sitio-web=demo \
  --domain sitio-web=www.example.com \
  --kind sitio-web=static

# Aplicar exactamente la misma selección
python3 scripts/hosting_sync.py \
  --only sitio-web \
  --assign sitio-web=demo \
  --domain sitio-web=www.example.com \
  --kind sitio-web=static \
  --apply
```

Usa `--ignore` para excluir un contenedor y `--retire-old` para retirar filas
antiguas configuradas por el script; esto último no borra el contenedor.

### `hosting_set_domain.py`

**Plan por defecto con `--dry-run`; escritura sin esa opción.** Lista sitios o
asigna el dominio primario a un contenedor ya adoptado. Comprueba unicidad,
dominios extra y el sufijo permitido del tenant.

```bash
python3 scripts/hosting_set_domain.py --list
python3 scripts/hosting_set_domain.py \
  --container sitio-web --domain sitio.example.com --dry-run
```

### `hosting_down.py`

**Plan por defecto; destructivo para el registro con `--execute`.** Baja
lógicamente un sitio: retira su ruta administrada y elimina la fila de Hosting,
pero conserva contenedores, imágenes, volúmenes, datos y la reserva del dominio.
Exige confirmación exacta.

```bash
python3 scripts/hosting_down.py --container sitio-web
python3 scripts/hosting_down.py \
  --container sitio-web --execute --confirm sitio-web
```

Si la ruta vive en labels del propio contenedor, el script bloquea la baja. El
flujo de reemplazo puede conservarla temporalmente con
`--keep-labeled-route`.

### `hosting_delete_wordpress.py`

**Plan por defecto; destructivo con `--execute`.** Elimina un WordPress
gestionado, su contenedor y volumen, y borra únicamente su base indicada por
`WORDPRESS_DB_NAME`. No elimina el contenedor, volumen o imagen de MariaDB.
También limpia secretos y, salvo `--keep-domain`, libera el dominio.

```bash
python3 scripts/hosting_delete_wordpress.py --container spanel-demo-wp
python3 scripts/hosting_delete_wordpress.py \
  --container spanel-demo-wp --execute --confirm spanel-demo-wp
```

### `reset_wp_password.py`

**Lectura con `--listar` o `--dry-run`; escritura en el modo normal.** Lista
usuarios o cambia una sola fila de `wp_users` sin detener WordPress. Si no se
proporciona contraseña, genera una y la muestra una sola vez.

```bash
python3 scripts/reset_wp_password.py spanel-demo-wp --listar
python3 scripts/reset_wp_password.py spanel-demo-wp --usuario admin --dry-run
python3 scripts/reset_wp_password.py spanel-demo-wp --usuario admin
```

## Respaldos de sitios

### `site_backup.py`

**Escritura no destructiva.** Genera un ZIP verificable de un WordPress
(archivos y base) o un sitio estático (archivos). Detecta el tipo y evita
guardar credenciales en el manifiesto.

```bash
python3 scripts/site_backup.py --container sitio-web --dry-run
python3 scripts/site_backup.py --container sitio-web --out /root/backups
python3 scripts/site_backup.py --verify /root/backups/wp-sitio-web-FECHA.zip
```

Consulta `--help` para overrides de base de datos. Evita `--db-pass` en shells
compartidos; es preferible que el script resuelva las credenciales desde el
contenedor.

### `site_restore.py`

**Destructivo.** Valida un ZIP producido por `site_backup.py`, crea primero un
respaldo de seguridad del estado actual y restaura archivos y, en WordPress, la
base. Intenta rollback automático si falla.

```bash
python3 scripts/site_restore.py \
  --zip /root/backups/wp-sitio-web-FECHA.zip \
  --container sitio-web \
  --yes
```

### `site_backup_link.py`

**Lectura de un respaldo; abre temporalmente un servidor HTTP/HTTPS.** Sirve un
ZIP válido mediante un enlace de un solo uso y termina tras la descarga o el
TTL. Fuera de loopback exige origen público y, normalmente, TLS.

```bash
python3 scripts/site_backup_link.py \
  --zip /root/backups/wp-sitio-web-FECHA.zip --ttl 600
```

## Apps

### `spanel_apps.py`

**Escritura según el subcomando.** CLI recomendado para operar Apps por la API.
No accede directamente a PostgreSQL, Redis, Docker ni SSH. Requiere la URL y un
token por entorno o entrada estándar:

```bash
export SPANEL_DOMAIN=panel.example.com
export SPANEL_APPS_TOKEN='...'
python3 scripts/spanel_apps.py list
python3 scripts/spanel_apps.py services UUID_APLICACION
python3 scripts/spanel_apps.py --json status UUID_OPERACION
```

Subcomandos disponibles: `providers`, `repositories`, `add`, `inspect`,
`deploy`, `status`, `list`, `services`, `refresh`, `logs`, `start`, `stop`,
`restart`, `down`, `domain-list`, `domain-assign`, `domain-remove`,
`domain-probe` y `delete`. Usa `python3 scripts/spanel_apps.py <comando> --help`
para los argumentos de cada uno.

### `app_deploy.py`

**Escritura/destructivo según el subcomando.** Herramienta de runtime directa
para auditar y desplegar un repositorio Docker Compose sin pasar por la API.
Soporta `inspect`, `deploy`, `status`, `logs` y `down`, con transporte local o
SSH. `down --purge-data` elimina datos y exige confirmación.

```bash
python3 scripts/app_deploy.py inspect --source-dir /ruta/al/checkout
python3 scripts/app_deploy.py deploy --source-dir /ruta/al/checkout \
  --project demo --dry-run
python3 scripts/app_deploy.py status --project demo
```

Los proyectos creados por Apps llevan el label `io.spanel.app.owner`. Este CLI
no tiene un comando de adopción para proyectos Compose ajenos.

### `configure_apps.py`

**Plan con `--dry-run`; escritura en modo normal.** Configura exclusivamente
variables `SPANEL_APPS_*`, crea o valida la clave de cifrado y, con `--restart`,
recrea `app` y `apps-worker` en orden seguro. Nunca ejecuta `docker compose
down` ni imprime la clave.

```bash
python3 scripts/configure_apps.py --public-url https://panel.example.com --dry-run
python3 scripts/configure_apps.py --public-url https://panel.example.com --restart
```

### `configure_apps_release_key.py`

**Solo lectura con `status`/`plan`/`verify`; escritura con `apply`/`rotate`.**
Provisiona `SPANEL_APPS_RELEASE_SIGNING_KEY` (mínimo 32 bytes) y el mapa
opcional `SPANEL_APPS_RELEASE_VERIFY_KEYS` para rotación en el fichero de
entorno del host, y recrea `app` y `apps-worker`. `apply` es idempotente y
nunca reemplaza una clave válida; `rotate` genera una nueva y conserva la
anterior para verificar. Nunca imprime la clave salvo con `--print-key`.

Sin clave activa, el deploy/rollback de Apps falla cerrado con
`apps.release_signing_unavailable` antes de crear el release o tocar
contenedores. Las aplicaciones legacy reciben su primer release firmado en el
siguiente deploy; sus deployments sin firma no pueden ser destino de rollback.

```bash
python3 scripts/configure_apps_release_key.py status
python3 scripts/configure_apps_release_key.py plan
python3 scripts/configure_apps_release_key.py apply --dry-run
python3 scripts/configure_apps_release_key.py apply
python3 scripts/configure_apps_release_key.py verify
python3 scripts/configure_apps_release_key.py rotate --print-key
```

Las opciones `--env-file`, `--compose-file` y `--service` van **después** del
subcomando. Usa `--no-restart` para actualizar el fichero sin recrear servicios.

### `migrate_env.py`

**Plan con `--dry-run`; escritura en base de datos en modo normal.** Migra el
`app.env` de un deployment existente al almacenamiento cifrado reutilizable de
Apps, excluyendo credenciales administradas. Debe ejecutarse **dentro del
contenedor `app`**, donde están disponibles los plugins y la configuración.

```bash
docker compose exec app python3 /app/scripts/migrate_env.py \
  --slug mi-app --dry-run
```

### `refresh_routes.py`

**Plan con `--dry-run`; escritura en modo normal.** Vuelve a renderizar las
rutas de Domains para Apps sin usar la UI ni redesplegar. Debe ejecutarse
**dentro del contenedor `app`**. `--restart-proxy` además reinicia Traefik.
Para un App rootless con hosts en Dominios ya no re-renderiza el target del
contenedor: delega en `AppsIngress.reconcile` y republica el documento del
relay (A.SPEC 0114).

```bash
docker compose exec app python3 /app/scripts/refresh_routes.py --dry-run
docker compose exec app python3 /app/scripts/refresh_routes.py --slug mi-app
```

### Scripts E2E de Apps

| Script | Nivel | Propósito |
|---|---|---|
| `e2e_apps_api.py` | **Destructivo** | E2E black-box contra login, API, worker y Docker reales; crea y limpia una aplicación. |
| `e2e_apps_software_editores.py` | **Destructivo** | E2E aislado directo contra el repositorio Software para Editores; genera artefactos de diagnóstico redactados. |

No son herramientas de administración cotidiana. Úsalos solo en un laboratorio
preparado y revisa sus variables/requisitos con `--help` y sus pruebas en
`scripts/tests/`.

### `configure_powerdns.sh`

Automatiza el laboratorio autoritativo y el despliegue privado del panel. El
plan es de solo lectura; `apply` levanta PowerDNS, genera `.env.powerdns` en
modo `0600`, monta la clave por ruta (nunca por valor), reconstruye el panel y
verifica la API autenticada desde el contenedor `app`.

```bash
scripts/configure_powerdns.sh plan
scripts/configure_powerdns.sh apply
scripts/configure_powerdns.sh status
scripts/configure_powerdns.sh verify
```

## Dominios, proxy y sitios estáticos

### `domains_sync.py`

**Plan por defecto; escribe solo con `--apply`.** Lee una instantánea completa
de los YAML gestionados de Traefik, valida sitio y propiedad del tenant, y
refresca atómicamente la observación PostgreSQL que usa la vista global de
Dominios. Nunca edita Traefik. `--json` produce un informe automatizable.

```bash
python3 scripts/domains_sync.py
python3 scripts/domains_sync.py --apply --json
```

### `domains_adopt.py`

**Plan por defecto; escribe solo con `--apply`.** Reclama la propiedad
administrativa de un dominio ya publicado cuando está libre y el tenant/sitio
coincide con su YAML gestionado. También actualiza la observación, pero nunca
reescribe YAML.

```bash
python3 scripts/domains_adopt.py --domain example.com --tenant demo
python3 scripts/domains_adopt.py --domain example.com --tenant demo --site SITE_ID --apply
```

`benchmark_domains_global.py` mide por separado sincronización y lectura global
proyectada con transporte local o Docker.

### `proxy_domain.py`

**Lectura o escritura según el subcomando.** Diagnostica Traefik y administra
dominios/rutas/certificados mediante `doctor`, `list`, `add`, `status` y
`remove`. El perfil `internal` usa el laboratorio; `public` usa el proxy real.

```bash
python3 scripts/proxy_domain.py --profile public doctor
python3 scripts/proxy_domain.py --profile public add \
  --site sitio-web --domain sitio.example.com
python3 scripts/proxy_domain.py --profile public status --domain sitio.example.com
```

### `spanel-static.py`

**Escritura/destructivo según el subcomando.** Crea y administra sitios
HTML/CSS/JS en nginx con volumen y ruta HTTPS. Ofrece `create`, `list`,
`status`, `delete` y `doctor`, localmente o por SSH.

```bash
python3 scripts/spanel-static.py create \
  --name pagina-demo --domain pagina-demo.spanel
python3 scripts/spanel-static.py list
python3 scripts/spanel-static.py delete --name pagina-demo
```

Documentación detallada: [`spanel_static/README.md`](spanel_static/README.md).

### `spanel-profiles.py`

**Escritura/destructivo según el subcomando.** Aprovisiona y verifica perfiles
estáticos deterministas (`plain`, `react`, `boot`, `astro`) con `up`, `verify`,
`status` y `down`. Está orientado a laboratorio/validación, no a sitios de
clientes.

```bash
python3 scripts/spanel-profiles.py status
python3 scripts/spanel-profiles.py up --only astro
python3 scripts/spanel-profiles.py verify
python3 scripts/spanel-profiles.py down
```

### `spanel-repair.py`

**Plan por defecto; escritura con `--fix`.** Detecta rutas Traefik incorrectas,
certificado por defecto, falta de `certResolver` y archivos huérfanos. Con
`--fix` puede parchear YAML, mover huérfanos y reiniciar Traefik respetando un
cooldown.

```bash
python3 scripts/spanel-repair.py
python3 scripts/spanel-repair.py --json
python3 scripts/spanel-repair.py --fix --only-host sitio.example.com
```

### `traefik-lab.sh`

**Escritura/destructivo dentro del laboratorio.** Crea un Traefik aislado, una
CA ACME local y DNS interno. No toca el Traefik real. `plan` no cambia nada;
`down --purge` elimina también datos y CA del laboratorio.

```bash
./scripts/traefik-lab.sh plan
./scripts/traefik-lab.sh up
./scripts/traefik-lab.sh status
./scripts/traefik-lab.sh down
```

`adopt` solo inspecciona el Traefik real; no lo registra ni modifica.
Documentación detallada: [`traefik-lab/README.md`](traefik-lab/README.md).

### `probe_docker.py`

**Lectura.** Prueba la configuración y conectividad local/SSH con Docker,
ejecuta `docker ps` e identifica candidatos WordPress. Es un diagnóstico; no
adopta ni modifica contenedores.

```bash
python3 scripts/probe_docker.py
python3 scripts/probe_docker.py --env-file otro.env
```

## phpMyAdmin

### `phpmyadmin_up.sh`

**Escritura/destructivo limitado.** Levanta phpMyAdmin como hub interno para
bases existentes, crea la red interna si falta y conecta MariaDB sin sacarlo de
sus redes. `--down` elimina únicamente el contenedor phpMyAdmin.

```bash
./scripts/phpmyadmin_up.sh --host mariadb --dry-run
./scripts/phpmyadmin_up.sh --host mariadb --network mariadb_internal
./scripts/phpmyadmin_up.sh --down --yes
```

`phpmyadmin_arbitrary.php` no es un CLI: es la configuración montada por el
script. Restringe los hosts aceptados a `mariadb` o nombres terminados en
`-db`.

### `configure_phpmyadmin_rootless.py`

**Operación de escritura; ejecutar como root.** Descubre el contenedor
phpMyAdmin compartido, su red/IP/gateway, la dirección de Postgres alcanzable
desde el host y las celdas listas. Después escribe el `EnvironmentFile` del
plan-agent, actualiza `SPANEL_PHPMYADMIN_SOURCE_IP` en `.env.docker`, recrea
app/worker solo si hace falta, abre el rango del broker en UFW y precarga la
imagen conectora fijada por digest. No hay direcciones hardcodeadas; vuelve a
ejecutarlo tras recrear phpMyAdmin o Postgres.

```bash
python3 scripts/configure_phpmyadmin_rootless.py --dry-run
python3 scripts/configure_phpmyadmin_rootless.py
```

El plan-agent recibe `SYSTUTOR_DATABASE_URL`, `SPANEL_DB_BROKER_BIND`,
`SPANEL_DB_BROKER_SOURCES`, `SPANEL_PMA_CONNECTOR_IMAGE`,
`SPANEL_PMA_CONNECTOR_READ_ONLY=false` y
`SPANEL_TENANT_CELL_NET=slirp4netns` mediante
`/etc/spanel/plan-agent.env` (modo `0600`). Este último fija el driver de red
de las celdas: `slirp4netns` es la política del host y `gvisor-tap-vsock` queda
solo como legado, nunca para celdas nuevas.

## Certificados de correo y tareas programadas

### `install_cert_agent.py`

**Plan con `--dry-run`; escritura como root en modo normal.** Descubre linajes
Certbot, genera la configuración del agente privilegiado e instala sus unidades
systemd. Es idempotente.

```bash
sudo python3 scripts/install_cert_agent.py --dry-run
sudo python3 scripts/install_cert_agent.py --allowlist mail.example.com
sudo python3 scripts/install_cert_agent.py --check --json
```

La arquitectura completa está en
[`../docs/certificate-manager.es.md`](../docs/certificate-manager.es.md).

### `configure_cert_agent_dms.py`

**Plan por defecto; escritura y recreación solo con `--apply`.** Adapta el agente
a un Docker Mailserver existente: detecta el mount `/tmp/docker-mailserver`,
separa los hostnames administrados (`sni-spanel`, `spanel-local_name.conf`) de
los legacy, actualiza `postfix-main.cf`, `dovecot.cf` y la configuración del
agente, recrea el servicio con `docker compose up -d --force-recreate` y valida
que ningún hostname se pierda. Los respaldos quedan como
`.spanel-dms-<marca>.bak` y la operación es idempotente.

```bash
sudo python3 scripts/configure_cert_agent_dms.py --json
sudo python3 scripts/configure_cert_agent_dms.py --apply
```

### `migrate_legacy_sni.py`

**Plan por defecto; solo escribe con `--apply`.** Audita un mapa SNI legacy de
Postfix (normalmente `sni-legalattorney`) contra el allowlist del agente, los
lineages de Certbot y los pares instalados. Con `--apply` asegura un router
HTTP-01 de Traefik en el file-provider, añade los hostnames al allowlist,
valida HTTP-01 con el webroot configurado, emite un lineage por hostname, lo
instala con `spanel_cert_agent install`, verifica TLS y, si se pide
`--clean-legacy`, elimina del mapa legacy las líneas migradas. En modo plan no
ejecuta Certbot.

```bash
sudo python3 scripts/migrate_legacy_sni.py
sudo python3 scripts/migrate_legacy_sni.py --apply
sudo python3 scripts/migrate_legacy_sni.py --apply --clean-legacy
sudo python3 scripts/migrate_legacy_sni.py --apply \
  --hostname mail.algisac.com --hostname mail.algima.pe
```

CLI:

```text
usage: migrate_legacy_sni.py [-h] [--config CONFIG]
                             [--config-root CONFIG_ROOT]
                             [--legacy-map LEGACY_MAP] [--hostname HOSTNAME]
                             [--apply] [--skip-http-check] [--skip-verify]
                             [--clean-legacy]
                             [--traefik-config-dir TRAEFIK_CONFIG_DIR]
                             [--acme-router-file ACME_ROUTER_FILE]
                             [--skip-acme-routing] [--json]

  --config CONFIG       TOML del agente (por defecto: /etc/spanel/cert-agent.toml)
  --config-root CONFIG_ROOT
                        directorio del host montado en /tmp/docker-mailserver
                        (por defecto: /opt/stacks/mail/config)
  --legacy-map LEGACY_MAP
                        ruta explícita del mapa SNI legacy (por defecto:
                        autodetecta sni-legalattorney o el primer sni-* excepto
                        sni-spanel)
  --hostname HOSTNAME   migrar solo este hostname (repetible)
  --apply               realizar cambios (sin esto es solo plan)
  --skip-http-check     no probar HTTP-01 antes de emitir
  --skip-verify         omitir las sondas TLS post-instalación
  --clean-legacy        eliminar del mapa legacy los hostnames migrados
                        (backup, postmap -F, postfix reload)
  --traefik-config-dir TRAEFIK_CONFIG_DIR
                        directorio file-provider de Traefik para routers
                        HTTP-01 (por defecto: /opt/stacks/traefik/config)
  --acme-router-file ACME_ROUTER_FILE
                        nombre del YAML gestionado dentro del directorio de
                        Traefik (por defecto: spanel-acme-mail-challenge.yml)
  --skip-acme-routing   no crear/actualizar el router HTTP-01 de Traefik
  --json                imprimir el plan en JSON
```

### `spanel_cert_agent/`

**Escritura privilegiada según el subcomando.** Paquete del agente de
certificados. Su entrada es:

```bash
PYTHONPATH=scripts python3 -m spanel_cert_agent --help
PYTHONPATH=scripts python3 -m spanel_cert_agent \
  --config /etc/spanel/cert-agent.toml status
```

Subcomandos: `run-once`, `refresh`, `status`, `verify`, `audit`, `sync`,
`install` y `rollback`. Normalmente lo invocan las unidades systemd, no un
operador interactivo. `certbot-deploy-hook.sh` es el hook de Certbot y tampoco
se ejecuta manualmente.

### `mail_cert.py`

**Lectura o escritura crítica según el subcomando.** Flujo anterior/específico
para certificados internos de docker-mailserver. `status`, `check` y `audit`
diagnostican; `issue` y `renew` pueden emitir el certificado y recrear el
contenedor DMS desde su inspección, con rollback si la verificación falla.

```bash
python3 scripts/mail_cert.py status
python3 scripts/mail_cert.py audit --json
python3 scripts/mail_cert.py issue --dry-run
python3 scripts/mail_cert.py renew --all --yes
```

`mail-cert.service` y `mail-cert.timer` son unidades específicas del entorno
original y contienen rutas/host concretos. Revísalas y ajústalas antes de
instalarlas; para instalaciones nuevas se prefiere el agente genérico.

### `install_routes_timer.py`

**Plan con `--dry-run`; escritura como root en modo normal.** Instala,
actualiza o elimina el timer systemd que ejecuta `refresh_routes.py` dentro del
contenedor `app`.

```bash
sudo python3 scripts/install_routes_timer.py --dry-run
sudo python3 scripts/install_routes_timer.py --interval-minutes 15
sudo python3 scripts/install_routes_timer.py --uninstall
```

## Tenants y dominios de base de datos

### `sync_tenant_domains.py`

**Plan por defecto; escritura con `--apply`.** Elimina de `tenant_domains` las
filas redundantes que duplican el dominio primario de su propio tenant y
reporta colisiones. Siempre produce un informe JSON. No toca Docker, proxy,
certificados, usuarios ni sitios.

```bash
python3 scripts/sync_tenant_domains.py
python3 scripts/sync_tenant_domains.py --apply
```

### `unify_tenants.py`

**Plan por defecto; escritura con `--apply`; `--purge` es destructivo.**
Consolida dominios, usuarios y sitios en un tenant objetivo, desactiva los
orígenes y guarda un plan JSON reversible. No toca contenedores ni proxy.

```bash
python3 scripts/unify_tenants.py \
  --target-slug demo --from-slug antiguo --move-all-sites

python3 scripts/unify_tenants.py \
  --target-slug demo --from-slug antiguo --move-all-sites --apply

python3 scripts/unify_tenants.py \
  --rollback logs/unify-tenants-FECHA.json --apply
```

## Migración one-run a rootless

### `spanel-migrator-to-rootless`

**Operación de escritura; ejecutar como root en el host.** Orquesta los CLI
existentes `spanel_tenant.py` (celda y plan), `hosting_migrate_rootless.py`
(migración de sitios), `install_tenant_agents.py` (plan-agent/edge-relay) y
`migrate_tenant_apps.py` (releases firmadas de Apps) en un flujo idempotente:
doctor/preflight, instalación de agentes, provisión de celda, plan de recursos,
plan de sitios, migración, Apps opcional, finalize opcional y evidencia.

Asistente interactivo:

```bash
sudo ./scripts/spanel-migrator-to-rootless
```

No interactivo:

```bash
sudo ./scripts/spanel-migrator-to-rootless --tenant demo \
  --memory 1G --cpus 1.5 --pids 512 --storage 10G --yes
```

Migrar también Apps (el token va en fichero, nunca en argv). El origen del
panel se lee automáticamente de `SPANEL_DOMAIN` en `.env.docker`:

```bash
sudo ./scripts/spanel-migrator-to-rootless --tenant demo \
  --memory 1G --cpus 1.5 --pids 512 --storage 10G --yes \
  --apps --apps-token-file /root/spanel-api-token
```

Opciones útiles:

- `--dry-run`: previsualiza todas las fases sin mutar el host.
- `--only static|wordpress` o `--site <id>` (repetible).
- `--shared-db <contenedor>`: MariaDB legacy compartido para WordPress. Para
  todos los WordPress rootful que lo usan y la base, copia el volumen una sola
  vez, lo arranca en la celda y migra los sitios contra él. Es una ventana de
  mantenimiento y nunca se activa automáticamente.
- `--skip-plan` / `--skip-sites`: ejecuciones parciales.
- Tras cada WordPress migrado abre phpMyAdmin por el broker rootless real y
  hace login antes de `--finalize`; si falla, los sitios quedan retained y con
  rollback. `--skip-pma-verify` desactiva esta comprobación.
- `--finalize`: elimina la copia rootful tras migrar. Por defecto el estado es
  **retained**, con backup verificado y rollback disponible.
- `--rollback-on-failure`: revierte todos los sitios migrados en esta ejecución
  si uno posterior falla.
- `--no-install-agents`: usa los agentes ya instalados.
- `--no-start-services`: falla si plan-agent/edge-relay están inactivos en vez
  de arrancarlos.
- `--skip-service-check`: no exige las unidades plan-agent ni edge-relay
  (laboratorio o ejecuciones parciales).
- `--apps`: redespliega las releases firmadas de Apps en la celda.
- `--apps-token-file`, `--app <id>` (repetible), `--apps-timeout`,
  `--apps-no-cell-verify`.
- `--apps-api-url` solo para sobrescribir `SPANEL_DOMAIN`.
- `--hosting-mode auto|local|container`, `--app-container <nombre>`.
- `--state-file <ruta>`, `--json`.

El CLI de hosting se ejecuta dentro de `spanel-app-1` por defecto: la
herramienta lo copia a `/tmp/spanel-migrator` y lo ejecuta con `/app` en
`PYTHONPATH`. Usa `--hosting-mode local` solo cuando el entorno de base de datos
de la app esté disponible en el host.

Las Apps no se copian: cada App seleccionada se redespliega desde su release
firmada ya activa y el worker la coloca en el socket rootless del tenant. Las
Apps sin release firmada se reportan como `requires_hardening`; nunca se
endurecen con usuarios o rutas adivinadas.

Limitación actual de Hosting: el migrador por defecto asume **un MySQL
gestionado por WordPress**. Un MySQL compartido por todo el tenant requiere el
modo explícito `--shared-db <contenedor>`; nunca se autodetecta y está pensado
solo para una base legacy exclusiva del tenant.

`--storage` es un límite **declarado** (A.SPEC 0111), no una cuota de
filesystem. El script lo valida contra el espacio libre y lo registra en el plan
y la evidencia, pero el valor efectivo es el que se guarda desde la pestaña
Recursos (API de planes de Apps).

El `--tenant` es el slug del tenant **tal como aparece en el panel**, no el
dominio ni un nombre inventado: puede contener puntos o mayúsculas (p. ej.
`Legalattorney.pe`). La celda rootless, en cambio, exige un slug canónico
`[a-z0-9][a-z0-9-]{0,61}`. El migrador deriva ese slug de celda de forma
determinista (`Legalattorney.pe` → `legalattorney-pe`) y lo muestra como
`cell slug` en el resumen y en la evidencia. El slug original se guarda en la
asignación de la celda (`registry.json`, campo `tenant_slug`) para que el agente
privilegiado pueda resolverlo en las consultas de base de datos; el slug de la
celda se usa solo para rutas, unidades, cgroups, AppArmor y el socket rootless.
Dos tenants que deriven al mismo slug de celda son rechazados con
`SlugCollision`.

La evidencia se escribe en
`logs/migrator-to-rootless-<tenant>-<UTC>.json` (o `--state-file`).

### `install_tenant_agents.py`

**Operación de escritura; ejecutar como root.** Instalador idempotente de
`spanel-plan-agent.service` y `spanel-edge-relay.service`. Crea
`/etc/spanel/plan_agent_token` en modo `0600` una sola vez (nunca rota),
renderiza las unidades con la ruta real del repo/Python/data root, el UID del
contenedor app, el UID de Traefik y la IP de Traefik (el relay sin privilegios
no puede inspeccionar Docker por sí mismo), las habilita y verifica los sockets
y el op `capacity`.

```bash
python3 scripts/install_tenant_agents.py --check
python3 scripts/install_tenant_agents.py --dry-run
python3 scripts/install_tenant_agents.py --traefik-uid 1000
python3 scripts/install_tenant_agents.py --traefik-ip 172.18.0.4
```

Si una unidad ya existe con contenido distinto, se niega a sobrescribirla;
revisa la diferencia y usa `--force` de forma deliberada.

El provisionado de una celda abre además su puerto de relay (`40000+index`) en
UFW, limitado a la IP de Traefik, y el deprovisionado lo elimina. Si el host usa
otro gestor de firewall, `provision` lo reporta como omitido; abre manualmente
el rango `40000:59999/tcp` desde la IP de Traefik.

### `migrate_tenant_apps.py`

**Operación de escritura** (redespliegue de Apps). Redespliega la release
firmada activa de cada App a través de la API de Apps para que el worker la
ejecute en la celda rootless del tenant. Omite las Apps cuyos contenedores ya
están en la celda. Las Apps sin release firmada se reportan como
`requires_hardening` y no se modifican.

Los contenedores creados antes de A.SPEC 0114 no tienen las labels
`spanel.managed` / `spanel.tenant` que exige el ingress de la celda, y Docker
no permite añadirlas después. `--redeploy-rootless` los recrea desde la misma
release firmada; el plan muestra `managed_labels: false` para saber qué Apps lo
necesitan.

```bash
export SPANEL_APPS_TOKEN=...        # o --token-file
python3 scripts/migrate_tenant_apps.py --tenant demo --dry-run
python3 scripts/migrate_tenant_apps.py --tenant demo --apply
# solo para contenedores anteriores a A.SPEC 0114:
python3 scripts/migrate_tenant_apps.py --tenant demo --redeploy-rootless --apply
```

El origen del panel sale de `SPANEL_DOMAIN` en `.env.docker` (o `--api-url`).

### `migrate_apps_rootless.py`

**Operación de escritura** (cutover del ingress de Apps, A.SPEC 0114). Se
ejecuta **dentro del contenedor `app`**: registra cada Host de Dominios del App
en `tenant_ingress_routes` (`owner_kind='apps'`), renderiza `apps-routes.conf`,
ejecuta `nginx -t`, elimina el documento legacy de Dominios y publica el
documento de Traefik contra el relay de la celda. Por defecto solo inspecciona
(`--dry-run`); `--apply` hace el cutover y `--stop-rootful` retiene y para la
pila rootful antigua.

Requisitos: los contenedores rootless del App deben tener las labels
`spanel.*` (ver `migrate_tenant_apps.py --redeploy-rootless`) y Dominios debe
ser dueño del Host con ruta `/`.

```bash
export SPANEL_DOMAIN=spanel.systutor.com
python3 /app/scripts/migrate_apps_rootless.py --tenant milton --dry-run
python3 /app/scripts/migrate_apps_rootless.py --tenant milton --apply
# tras verificar el 200 externo:
python3 /app/scripts/migrate_apps_rootless.py --tenant milton --apply --stop-rootful
# deshacer una operación registrada en el ledger:
python3 /app/scripts/migrate_apps_rootless.py --tenant milton \
  --rollback apps-rootless:<application_id>
```

Su contrapartida blackbox es `e2e_0114_apps_rootless_ingress.py`; necesita un
host de laboratorio con la celda rootless, el relay y Traefik.

### `migrate_milton_legacy.py`

Migración legacy dedicada al tenant `milton`. La pila original es anterior al
contrato de labels/volúmenes de SPanel: WordPress usa bind mounts, el host de
la base solo está en `wp-config.php`, el MariaDB compartido es un bind mount y
`portafolio` es una imagen estática con el contenido dentro, sin volumen.

Se ejecuta **dentro de `spanel-app-1`** y separa el trabajo por fases:

```bash
# solo estáticos, sin ventana de MariaDB
docker cp scripts/migrate_milton_legacy.py spanel-app-1:/tmp/
docker exec -it -e PYTHONPATH=/app:/app/vendor/systutor-core \
  spanel-app-1 python /tmp/migrate_milton_legacy.py \
  --tenant milton --statics --dry-run

# aplicar estáticos
docker exec -it -e PYTHONPATH=/app:/app/vendor/systutor-core \
  spanel-app-1 python /tmp/migrate_milton_legacy.py \
  --tenant milton --statics --apply --yes

# WordPress + MariaDB compartido (ventana de mantenimiento)
docker exec -it -e PYTHONPATH=/app:/app/vendor/systutor-core \
  spanel-app-1 python /tmp/migrate_milton_legacy.py \
  --tenant milton --wordpress --apply
```

Por defecto es dry-run. `--wordpress` para los cuatro WordPress legacy y
`mariadb`, copia los bind a volúmenes de la celda, arranca el MariaDB
compartido en la celda y hace el cutover de rutas. Los contenedores y datos
rootful quedan disponibles para rollback.

Si un dominio está detrás de Cloudflare, el probe público puede recibir un
challenge de bot (403) aunque el origen esté sano. Usa `--verify-local` para
verificar a través del Traefik local (`Host`/SNI) en lugar del DNS público.

La fase WordPress puede reutilizar una sola imagen stock para todos los sitios
en vez de transferir cada imagen legacy por sitio. El volumen copiado de
`/var/www/html` sigue llevando `wp-content` y `wp-config.php`:

```bash
python /tmp/migrate_milton_legacy.py --tenant milton --wordpress \
  --wordpress-image wordpress:php8.3-apache --apply --yes --verify-local
```

`--wordpress-image` sin valor usa `wordpress:latest`; fija un tag para
despliegues reproducibles.

El preflight renderiza el ingress de la celda antes de tocar datos y aborta si
el `systutor-core` cargado aún no tiene el alias `www` o sigue sustituyendo
`X-Forwarded-Proto` por `$scheme`. Así un core viejo en la imagen se detecta en
segundos, no después de copiar todo y hacer rollback.

La MariaDB compartida hace inseguro un cutover parcial permanente: una copia
completa posterior sobrescribiría la base del sitio ya migrado. Para probar un
solo WordPress, selecciónalo con `--site` y usa `--canary`; el script ejecuta el
cutover real, verifica las rutas y después restaura rootful, dejando constancia
en el fichero de evidencia:

```bash
python /tmp/migrate_milton_legacy.py --tenant milton --wordpress \
  --site gestiongases --canary --apply --yes --verify-local
```

`--site` acepta nombre de contenedor o dominio y es repetible. El cutover real
debe incluir los cuatro WordPress.

## Archivos auxiliares

### Paquetes internos

No se ejecutan archivo por archivo; implementan los entrypoints documentados:

| Directorio | Entry point |
|---|---|
| `spanel_static/` | `python3 scripts/spanel-static.py` |
| `spanel_profiles/` | `python3 scripts/spanel-profiles.py` |
| `spanel_cert_agent/` | `PYTHONPATH=scripts python3 -m spanel_cert_agent` |

### Unidades systemd

`scripts/systemd/` contiene plantillas para:

| Unidad | Función |
|---|---|
| `spanel-cert-agent.path/service/timer` | Procesar solicitudes y refrescar el estado de certificados. |
| `spanel-cert-audit.service/timer` | Auditar periódicamente certificados. |
| `spanel-cert-deploy.service` | Hook de despliegue de certificados. |
| `spanel-repair.service/timer` | Ejecutar reparación periódica de rutas/TLS. |
| `spanel-routes-refresh.service/timer` | Reconciliar rutas de Apps. |

No copies una unidad a producción sin revisar rutas, usuario, permisos y
variables del host. Los instaladores generan o adaptan las unidades cuando
corresponde.

### Pruebas

`scripts/tests/` y `spanel_cert_agent/tests/` contienen pruebas automatizadas;
no son comandos operativos. Las pruebas con `_live` o los E2E pueden requerir
Docker real, SSH, credenciales y recursos de laboratorio. No las ejecutes en
producción sin leer primero el archivo.

Ejemplo de pruebas unitarias sin laboratorio:

```bash
python3 -m pytest scripts/tests/test_hosting_sync.py -q
python3 -m pytest scripts/tests/test_spanel_apps.py -q
```

## Mantenimiento de este índice

Al agregar, renombrar o eliminar un entrypoint dentro de `scripts/`:

1. documenta propósito, contexto de ejecución y nivel de riesgo aquí;
2. incluye un ejemplo seguro o de plan;
3. conserva `--help` como referencia exacta de argumentos;
4. enlaza una guía especializada si el flujo necesita más detalle;
5. actualiza o agrega pruebas del script.
