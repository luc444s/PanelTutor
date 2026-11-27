# A.SPEC 0124 — Modo Cloudflare único por servidor (`SPANEL_CLOUDFLARE_MODE`)

## Problema

Hoy Cloudflare es estrictamente **por tenant**:

- `domains_cloudflare_connections` tiene una conexión OAuth por `tenant_id`
  (clave única), con credenciales cifradas por tenant.
- `domains_cloudflare_oauth_flows` crea un flujo PKCE por tenant.
- El panel muestra **Conectar Cloudflare** a cada tenant y el provisioner usa
  la cuenta Cloudflare de ese tenant.
- PowerDNS sigue siendo la autoridad de RRsets y `domains_dns_zones` registra
  la propiedad zona→tenant.

Eso funciona cuando cada tenant trae su propia cuenta Cloudflare. Pero en
instalaciones donde el operador quiere **una sola cuenta Cloudflare para todo
el servidor**, obligar a cada tenant a autorizar su cuenta es incorrecto y
fragmenta el DNS. Se necesita un interruptor de despliegue que permita usar una
cuenta Cloudflare de plataforma sin romper el modo actual ni la separación de
datos entre tenants.

## Decisión

Agregar el flag de entorno:

```env
SPANEL_CLOUDFLARE_MODE=tenant   # valor por defecto; comportamiento actual
# SPANEL_CLOUDFLARE_MODE=single # una sola cuenta Cloudflare del host
```

También se aceptan los alias `0` (= `tenant`) y `1` (= `single`) para no romper
la expectativa inicial de “flag 0/1”. Los valores no reconocidos fallan con
`CloudflareConfigError` y un mensaje sin secretos.

En `single`:

- Existe **una única conexión OAuth de Cloudflare a nivel host/plataforma**.
- Todos los tenants resuelven credenciales contra esa conexión compartida.
- La separación por tenant **no desaparece**: se mantiene en PostgreSQL
  mediante una tabla de propiedad `tenant → zona Cloudflare`, y todas las
  lecturas/escrituras de zonas y registros la respetan.
- El tenant deja de poder conectar/desconectar Cloudflare; eso pasa a ser una
  operación de plataforma.
- PowerDNS **no cambia**. El flag solo afecta a Cloudflare. `domains_dns_zones`,
  la autoridad de RRsets y los nameservers públicos siguen igual en ambos modos.

“Un solo Cloudflare controle un servidor” significa **una cuenta Cloudflare
compartida para el host**, no una única zona para todos los tenants. Cada tenant
sigue creando/reutilizando sus propias zonas dentro de esa cuenta.

## Contrato

### 1. Configuración

- `CloudflareConfig` incorpora `mode: Literal["tenant", "single"]`, leído de
  `SPANEL_CLOUDFLARE_MODE` en `from_env()`.
- Normalización: `strip()`, minúsculas. Vacío o ausente → `tenant`.
  `tenant`/`0` → `tenant`; `single`/`1` → `single`; cualquier otro valor →
  `CloudflareConfigError`.
- `describe()` incluye `mode` (nunca rutas, claves ni tokens).
- No hay fallback a otro nombre de variable. El flag es de arranque: cambiarlo
  requiere reiniciar el backend.
- Documentar el flag en `.env.example`, `.env.docker.example`,
  `vendor/systutor-core/plugins/domains/README.md` y `README.es.md`, junto al
  resto de variables `SPANEL_CLOUDFLARE_*`.

### 2. Matriz de comportamiento

| Capacidad | `tenant` (0, default) | `single` (1) |
|---|---|---|
| Conexión OAuth | Una por tenant (`domains_cloudflare_connections`) | Una sola del host (`domains_cloudflare_host_connection`) |
| Flujo PKCE | Uno por tenant (`domains_cloudflare_oauth_flows`) | Uno del host (`domains_cloudflare_host_oauth_flows`) |
| `POST /oauth/start` del tenant | Permitido | `409 domains.dns.cloudflare.host_managed` |
| `POST /disconnect` del tenant | Permitido | `409 domains.dns.cloudflare.host_managed` |
| `GET /status` del tenant | 404 si no hay conexión | Siempre 200; `connected=false` si el host no autorizó |
| Zonas visibles al tenant | Todas las de su cuenta | Solo las que tengan fila de propiedad de ese tenant |
| Registros de una zona | Valida cuenta de la conexión | Valida además propiedad `tenant → zone_id` |
| `provision/plan` y `apply` | Credenciales del tenant | Credenciales del host + propiedad de zona |
| PowerDNS / nameservers | Sin cambios | Sin cambios |

Las respuestas de estado exponen `mode` y, en `single`, `managed_by_host=true`.
`ConnectionStatusResponse.tenant_id` pasa a `str | None`; en `single` puede ser
`null`.

### 3. Modelo de datos (solo aditivo)

La migración **no altera** `domains_cloudflare_connections` ni
`domains_cloudflare_oauth_flows`, para que el modo `tenant` y el rollback sigan
siendo triviales y para que la migración funcione igual en PostgreSQL y SQLite.

Nuevas tablas en `vendor/systutor-core/plugins/domains/backend/models.py`:

1. `domains_cloudflare_host_connection` (singleton `id=1`)
   - `id`, `cloudflare_account_id`, `account_name`
   - `access_ciphertext`, `access_nonce`, `refresh_ciphertext`,
     `refresh_nonce`, `key_version`
   - `scopes_json`, `expires_at`, `status`
   - `created_at`, `updated_at`
   - `CHECK (id = 1)`.

2. `domains_cloudflare_host_oauth_flows`
   - Mismas columnas que `CloudflareOAuthFlow` sin `tenant_id`.
   - `state_hash` único; `verifier_ciphertext`, `verifier_nonce`,
     `key_version`, `redirect_uri`, `status`, `error_code`, `expires_at`,
     `consumed_at`, timestamps.

3. `domains_cloudflare_zone_ownership`
   - `id` (UUID), `tenant_id` FK a `tenants.id`
   - `zone_id` (ID de Cloudflare), `zone_name` (normalizado sin punto final,
     minúsculas), `account_id`
   - `created_at`, `updated_at`
   - `UNIQUE (zone_id)`, `UNIQUE (zone_name)`, índice por `tenant_id`.

`UNIQUE (zone_name)` es deliberado: una zona Cloudflare pertenece a un solo
tenant y sirve para serializar dos applies concurrentes del mismo dominio.

Cifrado:

- Conexión host: identidades AAD fijas `"host"` (access/refresh) en lugar de
  `tenant_id`.
- Flujo host: identidad AAD `"host:<flow_id>"` para el verificador PKCE.
- Se reutilizan `CloudflareCipher`, propósitos y versiones de clave existentes.

### 4. Aislamiento en modo `single`

Reglas obligatorias:

1. `zones_for_tenant()` lista zonas de la cuenta compartida y luego filtra por
   `domains_cloudflare_zone_ownership.tenant_id == tenant actual`.
2. `records_for_tenant()`, `create_record()`, `update_record()` y
   `delete_record()` exigen una fila de propiedad para `zone_id` y el tenant
   actual antes de llamar a Cloudflare. Sin fila → `404
   domains.dns.cloudflare.zone_not_found` (no revelar que la zona existe en
   otra cuenta/tenant).
3. `provision/plan`:
   - Si la zona existe y está asignada al tenant → `reuse`.
   - Si existe y está asignada a otro tenant → `409
     domains.dns.cloudflare.zone_in_use`.
   - Si existe pero no tiene fila de propiedad → `409
     domains.dns.cloudflare.zone_unowned`, con instrucción de adoptarla desde
     la CLI de plataforma. No se auto-reclama una zona preexistente.
   - Si no existe → plan `create_zone` normal.
4. `provision/apply` crea o reutiliza la zona remota y, en la misma transacción
   de dominio, registra/actualiza la propiedad. Para evitar carreras entre dos
   tenants con el mismo dominio se toma un lock de transacción por
   `zone_name` en PostgreSQL (`pg_advisory_xact_lock(hashtext(zone_name))`);
   en SQLite basta el escritor único. Si el `INSERT` choca con
   `UNIQUE (zone_name)`, se devuelve `409 domains.dns.cloudflare.zone_in_use`
   sin exponer la identidad del otro tenant.
5. La desconexión del host **no borra** `domains_cloudflare_zone_ownership`:
   al reconectar, las zonas vuelven a estar disponibles para sus tenants.
6. Nunca se acepta un `tenant_id` de query/body en operaciones Cloudflare. El
   tenant sale de `TenantContext`; el host solo de un contexto de plataforma.

### 5. API

Se mantienen las rutas actuales y se agregan rutas de host. Los códigos nuevos
no sustituyen los existentes en modo `tenant`.

Rutas de tenant (mismo permiso `domains.dns.cloudflare`):

- `GET /dns/cloudflare/status`
  - `single`: 200 con `mode="single"`, `managed_by_host=true` y el estado de la
    conexión host; nunca tokens.
  - `single` sin conexión host: 200 con `connected=false`,
    `status="disconnected"`.
- `POST /dns/cloudflare/oauth/start`
  - `single`: 409 `domains.dns.cloudflare.host_managed`.
- `POST /dns/cloudflare/disconnect`
  - `single`: 409 `domains.dns.cloudflare.host_managed`.
- `GET /dns/cloudflare/zones`, registros y `provision/*`: sin cambios de ruta;
  aplican las reglas de aislamiento anteriores.

Rutas nuevas de host, requieren `core.platform.admin` y
`domains.dns.cloudflare` (el registro OAuth del cliente sigue en
`domains.cloudflare.register`):

- `GET /dns/cloudflare/host/status`
- `POST /dns/cloudflare/host/oauth/start`
- `POST /dns/cloudflare/host/disconnect` (`apply` dry-run/apply como hoy)
- `GET /dns/cloudflare/host/zones?include_unowned=true`
  - inventario de plataforma para adopción; no se expone a tenants.

El callback `GET /dns/cloudflare/oauth/callback` sigue siendo público y sin
tenant. Debe buscar el `state_hash` en la tabla de flujos host y en la de
flujos por tenant; si aparece en ambas (colisión prácticamente imposible),
rechazar. Un flujo host consume y escribe solo la conexión host.

### 6. Servicio y router

- `CloudflareService` acepta `mode` desde `CloudflareConfig`.
- Resolución de credenciales centralizada:
  - `tenant`: `_connection(tenant_id)` actual.
  - `single`: `_host_connection()` singleton; refresh con `SELECT ... FOR
    UPDATE` sobre `id=1`.
- `_refresh_locked` debe funcionar con ambas fuentes sin duplicar la lógica de
  cifrado/refresh; la identidad AAD es el único cambio.
- `status_for_tenant` en `single` devuelve estado host y `tenant_id=None`.
- `start_flow_for_tenant` y `disconnect_for_tenant` lanzan
  `CloudflarePermission("Cloudflare is managed by the platform")` traducido a
  `409 domains.dns.cloudflare.host_managed`.
- `register()` no cambia: el cliente OAuth ya es singleton de plataforma.
- Eventos/auditoría nuevos:
  - `domains.dns.cloudflare_host_connected`
  - `domains.dns.cloudflare_host_disconnected`
  - `domains.dns.cloudflare_zone_adopted`
  - reutilizar los eventos de records/provisioning con `tenant_id` real.
- En modo `tenant` no debe cambiar ningún payload, evento ni consulta SQL
  existente.

### 7. Migración `007_cloudflare_single_mode.py`

- Crea las tres tablas si no existen; es idempotente (se ejecuta en cada boot).
- No modifica tablas existentes ni backfillea datos.
- Debe funcionar con el runner de migraciones de plugins
  (`upgrade_plugin_migrations`) y con SQLite en tests, usando `Table.create` e
  `inspect(bind)` como las migraciones 004–006.
- `downgrade()` elimina en orden: flujos host, conexión host y propiedad de
  zonas. Es seguro porque el modo `tenant` no las consulta.
- No se usa Alembic directamente (regla de `AGENTS.md`).

### 8. CLI (`scripts/spanel_dns.py`)

Comandos nuevos:

```text
python3 scripts/spanel_dns.py cloudflare host status
python3 scripts/spanel_dns.py cloudflare host connect [--wait-seconds 300]
python3 scripts/spanel_dns.py cloudflare host disconnect [--apply]
python3 scripts/spanel_dns.py cloudflare host zones list [--include-unowned]
python3 scripts/spanel_dns.py cloudflare host adopt DOMINIO --tenant SLUG [--apply]
python3 scripts/spanel_dns.py cloudflare host adopt-all --from-tenant-connections [--apply]
```

- `host connect` imprime la URL y espera el callback; nunca recibe tokens.
- `host adopt` verifica que `DOMINIO` exista en la cuenta compartida; sin
  `--apply` es dry-run. Con `--apply` inserta la propiedad y audita.
- `host adopt-all --from-tenant-connections` recorre las conexiones por tenant
  existentes, lista sus zonas y deduce el dueño real de cada zona desde
  `hosting_sites`, `domains_routes` y `tenant_domains`. Solo usa el tenant de
  la conexión antigua cuando no hay evidencia explícita. Con `--apply` crea
  filas nuevas y reasigna filas antiguas mal asignadas. Si dos fuentes dan
  dueños distintos, se detiene con conflicto y no escribe parcialmente. Es la
  vía de migración de una instalación que ya tenía conexiones por tenant.
- En modo `single`, `cloudflare connect|disconnect --tenant` fallan con un
  mensaje claro que apunta a `cloudflare host ...`.
- `zones`, `records` y `provision` por tenant siguen funcionando y aplican el
  aislamiento.

### 9. Panel

- `CloudflareConnectButton` lee `mode` del estado.
- `single`:
  - Usuarios sin permisos de plataforma ven solo el estado (“Cloudflare
    gestionado por la plataforma”) y no ven Conectar/Desconectar.
  - Administradores de plataforma ven las acciones host (conectar/desconectar)
    y el estado del cliente OAuth.
  - No se muestra el botón de tenant que llama a `/oauth/start`.
- `CloudflareDnsPanel` no cambia: sigue operando por `zone.id`; el backend
  aplica la propiedad.
- Al conectar/desconectar el host se invalidan `cloudflareKeys.status`,
  `cloudflareKeys.zones` y las zonas DNS del panel.
- Añadir mensajes i18n para `host_managed`, `zone_unowned` y `zone_in_use`.
- Actualizar tipos frontend (`CloudflareStatus.mode`, `managed_by_host`,
  `tenant_id` opcional) y sus tests de lógica.

## Criterios de aceptación

1. Sin la variable o con `SPANEL_CLOUDFLARE_MODE=tenant` (o `0`), todos los
   tests y flujos actuales pasan sin cambios de comportamiento.
2. Con `SPANEL_CLOUDFLARE_MODE=single` (o `1`):
   - un administrador de plataforma autoriza una sola vez Cloudflare;
   - un tenant sin conexión propia ve el estado del host y sus zonas
     previamente adoptadas;
   - ese tenant no puede iniciar OAuth ni desconectar Cloudflare;
   - no puede listar, leer ni escribir zonas/registros de otro tenant, aunque
     compartan la misma cuenta Cloudflare;
   - `provision/apply` de un dominio nuevo crea la zona y registra la
     propiedad; repetirlo es idempotente;
   - `provision` de una zona de otro tenant devuelve 409 sin filtrar datos;
   - reconectar el host conserva la propiedad de zonas.
3. Un valor inválido de `SPANEL_CLOUDFLARE_MODE` impide construir
   `CloudflareConfig` con un error explícito y sin secretos.
4. La migración 007 es idempotente y reversible; `upgrade` dos veces no falla.
5. PowerDNS, nameservers públicos y `domains_dns_zones` no cambian en ninguno
   de los dos modos.

## Pruebas

Backend (`vendor/systutor-core/plugins/domains/backend/tests/`):

- `test_cloudflare_config.py` (nuevo o ampliado): default, `tenant`, `single`,
  `0`, `1`, mayúsculas/espacios y valores inválidos.
- `test_cloudflare_migration_007.py`: upgrade idempotente, columnas/constraints,
  downgrade y convivencia con las tablas 004.
- `test_cloudflare_single_mode.py`:
  - conexión host y flujo host (cifrado/AAD, single-use, expiración);
  - status de tenant en `single` sin conexión (200, `connected=false`);
  - `oauth/start` y `disconnect` de tenant → 409;
  - aislamiento de zonas/registros entre dos tenants;
  - `provision` con zona ajena → 409; zona unowned → 409;
  - `apply` crea propiedad y es idempotente;
  - refresh de token host con lock.
- Ampliar `test_cloudflare_router.py` y `test_cloudflare_cli.py` con las rutas
  y comandos host, y con el rechazo de las acciones de tenant en `single`.
- Verificar que la suite existente en modo `tenant` sigue verde sin cambios de
  expectativas.

Frontend (`apps/web/src/plugins/`):

- `domains-cloudflare.logic.test.ts`: visibilidad de acciones según `mode` y
  permisos de plataforma; mensajes nuevos.
- Test de `CloudflareConnectButton` (o el equivalente existente) para no
  llamar a `/oauth/start` de tenant en `single`.

Comandos de verificación:

```bash
python3 -m pytest vendor/systutor-core/plugins/domains/backend/tests -q
python3 -m pytest vendor/systutor-core/tests -q
npm --prefix apps/web test
ruff check .
python3 -m pyright
```

## Despliegue y rollback

1. Aplicar la migración 007 con el runtime de plugins (reinicio normal).
2. Elegir el modo en `.env` y reiniciar.
3. Si se pasa a `single`:
   - registrar/verificar el cliente OAuth de plataforma (ya existente);
   - `cloudflare host connect` y completar OAuth como administrador de
     plataforma;
   - `cloudflare host adopt-all --from-tenant-connections` en dry-run;
   - revisar conflictos y repetir con `--apply`;
   - verificar con un tenant que solo ve sus zonas.
4. Rollback: volver a `SPANEL_CLOUDFLARE_MODE=tenant` y reiniciar. Las tablas
   host y de propiedad quedan ignoradas; las conexiones por tenant nunca se
   borraron. No hace falta migración inversa para volver a operar.

## Fuera de alcance

- Cambiar la autoridad de PowerDNS o fusionar zonas.
- Una única zona Cloudflare con subdominios por tenant.
- Rotación automática del cliente OAuth o del bootstrap token.
- Sincronización bidireccional Cloudflare ↔ PowerDNS.
- Provisionar registros MX/TXT de correo desde este flag.

## Notas

- No hacer commit: el revisor integra y commitea.
- No desplegar en producción; validar primero en `spanel.lab`.
- El modo `single` exige una reautorización OAuth del host: no se copian ni
  descifran tokens de las conexiones por tenant. Esas credenciales quedan
  intactas solo para el rollback.
- Mantener la regla de migraciones de `AGENTS.md`: runtime de plugins, nunca
  Alembic directo.
