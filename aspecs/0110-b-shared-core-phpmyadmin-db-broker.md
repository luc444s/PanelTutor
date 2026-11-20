# A.SPEC 0110-B — phpMyAdmin Core compartido para bases rootless

> `risk: high` — abre conectividad temporal desde una herramienta Core hacia
> bases aisladas por tenant. Requiere 0110-A, `approver:` y pruebas explícitas de
> aislamiento cruzado.

## WHY

El phpMyAdmin actual es una herramienta Core compartida y el backend ya crea una
sesión server-side, guarda sus cookies y bloquea el re-login desde el proxy. Al
migrar WordPress a celdas rootless aparece una frontera real:

- un contenedor rootful no puede unirse a una red perteneciente a otro daemon
  Docker rootless;
- conectar phpMyAdmin permanentemente a todas las redes rompería el aislamiento
  incluso si fuera técnicamente posible;
- publicar `3306` de cada tenant en el host convertiría una herramienta de
  administración en una superficie permanente;
- desplegar un phpMyAdmin permanente por tenant duplica infraestructura, parches
  y consumo, y contradice la decisión de conservarlo como herramienta Core.

La restricción por IP no basta por sí sola: todas las sesiones salen del mismo
phpMyAdmin. La autorización debe quedar ligada a una sesión concreta del panel,
un tenant, un sitio, una DB y un TTL.

## WHAT

**Se conserva un único phpMyAdmin Core. Para cada sesión autorizada, Hosting
crea mediante el host-agent un canal DB efímero y acotado hacia la MariaDB
rootless del sitio; phpMyAdmin inicia sesión server-side contra ese canal; el
navegador nunca elige servidor ni recibe credenciales o endpoints internos; el
canal desaparece al cerrar/expirar la sesión.**

```text
navegador autenticado
  → proxy Hosting/PMA
    → phpMyAdmin Core compartido
      → DB broker (listener efímero, solo origen PMA)
        → conector rootless efímero de la celda
          → MariaDB privada del sitio:3306
```

## PRECONDITIONS

- A.SPEC 0110-A en PASS: resolver runtime, sitios WordPress rootless, red interna
  de Hosting y labels exactas de pertenencia.
- phpMyAdmin Core y su proxy actual funcionales.
- Host-agent con UDS, `SO_PEERCRED`, HMAC y gate de mutaciones.
- El contenedor MariaDB no publica puertos y pertenece al mismo tenant/sitio.

## SCOPE

### A. DB broker Core

Crear `scripts/tenant_cell/db_broker.py` como servicio de relay TCP sin parser
SQL ni credenciales. Mantiene listeners efímeros en el gateway de la red Core y
acepta únicamente la IP efectiva del contenedor phpMyAdmin configurado.

Cada entrada contiene:

```text
relay_id, tenant_id, slug, site_id, pma_session_id,
source_ip, listen_port, target_loopback, target_port,
created_at, expires_at, state
```

- Puertos se asignan de un rango dedicado, con lock y detección de colisión.
- Allowlist vacía = deny all. No existe bind `0.0.0.0` ni wildcard de origen.
- El broker no acepta desde la petición paths, comandos, IP destino, puerto
  destino ni nombres de unidad.
- Reinicio carga solo entradas no expiradas que todavía pasan reconciliación;
  el default es cerrar, no reabrir a ciegas.
- Métricas/logs contienen IDs y bytes, nunca payload MySQL ni credenciales.

### B. Conector efímero dentro de la celda

Para alcanzar una DB no publicada, el host-agent crea mediante el runtime
rootless un conector `spanel-pma-<relay-id>`:

- imagen fijada por digest y administrada por Core;
- conectado únicamente a la red interna de la MariaDB destino;
- destino derivado de la fila `hosting_sites` y de nombres/labels inspeccionados;
- publica un puerto asignado solo en el loopback dedicado de la celda;
- `--read-only`, uid no-root, `cap-drop ALL`, sin volúmenes, sin Docker socket,
  límites de memoria/PIDs y TTL;
- no se conecta al ingress HTTP ni a redes de otro tenant.

El flujo TCP queda:

```text
PMA Core → gateway:broker_port
         → 127.<cell>:connector_port
         → <managed-db-container>:3306
```

El contenedor MariaDB original no se recrea ni gana un puerto publicado.

### C. Protocolo host-agent acotado

Añadir operaciones HMAC/UDS:

```text
db_relay_open
db_relay_status
db_relay_close
db_relay_reconcile
```

Request lógico de `open`:

```json
{
  "tenant": "tenant-slug",
  "slug": "tenant-slug",
  "site_id": "uuid",
  "pma_session_id": "opaque-id",
  "ttl": 1500
}
```

El backend nunca envía container name, IP ni puerto. Un callback de Hosting
autorizado resuelve el sitio y devuelve al agente un descriptor firmado/acotado;
el agente vuelve a inspeccionar en el daemon rootless:

- `spanel.tenant == tenant_id`;
- `spanel.site == site slug/id esperado`;
- contenedor DB gestionado y runtime rootless;
- red perteneciente a la misma celda;
- destino fijo `3306`.

`open` devuelve solo `{relay_id, broker_host, broker_port, expires_at}` al
backend. La respuesta nunca llega directamente al navegador.

### D. Sesión phpMyAdmin ligada al relay

- Extender `PmaSession` con `relay_id`, `tenant_id`, `site_id`, runtime y expiry.
- `create_phpmyadmin_session` mantiene ownership/RBAC actual y, para rootless:
  1. crea primero un `PmaSession` provisional/ID opaco;
  2. abre el relay ligado a ese ID;
  3. resuelve credenciales del sitio sin retornarlas al navegador;
  4. llama `PmaClient.login` server-side con host/port del broker;
  5. guarda cookies y activa la sesión solo si login fue correcto.
- Si login falla, cerrar conector y listener antes de responder
  `hosting_phpmyadmin_login_failed`.
- Logout explícito, expiración, detección de cookies expiradas y purga del store
  llaman `db_relay_close` de forma idempotente.
- El proxy continúa bloqueando `pma_username` y `pma_password`; también bloquea
  cualquier intento de cambiar `server`, `host` o `port` desde formularios PMA.
- El browser recibe solo el ticket de un uso y la cookie HttpOnly scoped al
  `site_id` actual.

### E. Rootful y rootless durante transición

El resolver de 0110-A selecciona:

| Runtime del sitio | Camino PMA |
|---|---|
| `rootful` | conexión interna actual, sin broker |
| `rootless` | broker + conector efímero obligatorio |
| ausente/ambiguo/degraded | `409 hosting_phpmyadmin_unavailable` |

No existe fallback de un sitio rootless al host DB global.

### F. CLI de diagnóstico/operación

Extender `spanel-tenant` para operadores; no acepta credenciales ni destinos:

```bash
spanel-tenant db-relay list --slug <tenant> --json
spanel-tenant db-relay status --slug <tenant> --relay <relay-id> --json
spanel-tenant db-relay close --slug <tenant> --relay <relay-id> --json
spanel-tenant db-relay reconcile --json
```

`open` no se expone como CLI general para evitar saltarse RBAC/ownership; solo el
backend Hosting puede emitir la capability ligada a una `PmaSession` válida.

### G. Auditoría

Registrar:

- `hosting.phpmyadmin.relay_opened`;
- `hosting.phpmyadmin.relay_closed`;
- `hosting.phpmyadmin.relay_expired`;
- `hosting.phpmyadmin.relay_rejected`.

Detalles permitidos: tenant/site/user/relay IDs, runtime, timestamps, motivo y
bytes agregados. Prohibidos: password, cookies PMA, queries, dump, IP interna DB
y capability HMAC.

## OUT OF SCOPE

- Una instancia phpMyAdmin por tenant.
- Publicar MariaDB en una IP pública, `0.0.0.0`, Traefik HTTP o el ingress web.
- Unir phpMyAdmin a redes Docker de tenant.
- Elegir servidor/puerto desde navegador o parámetros públicos.
- ProxySQL compartido, análisis SQL, grabación de consultas o credenciales DB
  nuevas.
- Cambiar la migración de sitios de 0110-A.
- UI nueva; se conserva el botón/modal actual.
- Producción antes del E2E de aislamiento.

## CONTRACT

1. Un usuario autorizado abre el phpMyAdmin Core compartido para un WordPress
   rootless y navega/consulta su DB mediante el proxy existente.
2. No hay puerto MariaDB permanente antes, durante ni después; solo existen el
   listener y conector efímeros durante la sesión.
3. El navegador no puede elegir servidor/puerto, reloguearse ni ver password,
   endpoint de celda o capability.
4. Logout, timeout, fallo de login y reinicio/reconcile eliminan listener y
   conector de forma idempotente.
5. Con una sesión del tenant A no se puede conectar, listar ni reutilizar relay,
   cookie o DB del tenant B, aun conociendo sus IDs.
6. Sitios rootful conservan el camino actual; sitios rootless nunca caen a ese
   camino.
7. Una celda o broker no disponible produce error fail-closed sin dejar relay
   huérfano.

## INVARIANTS

```yaml
invariants:
  - "Existe un solo phpMyAdmin Core compartido; no uno permanente por tenant."
  - "phpMyAdmin nunca se une a redes Docker rootless ni recibe un Docker socket."
  - "MariaDB no publica 3306; el acceso rootless existe solo durante una sesion autorizada."
  - "Cada relay queda ligado a tenant, site, user y pma_session con TTL."
  - "El browser no controla target, host, port, container, path ni credenciales."
  - "Allowlist vacia deniega y no existe bind wildcard."
  - "Source IP de PMA es defensa adicional, no sustituto de ownership/sesion."
  - "Fallo o expiracion limpia conector y listener; close es idempotente."
  - "No hay fallback rootless→rootful ni acceso cruzado entre tenants."
  - "Logs/auditoria no contienen credenciales, cookies, queries ni capabilities."
```

## VERIFICATION

```bash
python3 -m pytest \
  scripts/tests/test_tenant_cell_db_broker.py \
  scripts/tests/test_tenant_cell_host_agent.py -q

PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -m pytest \
  vendor/systutor-core/plugins/hosting/backend/tests/test_phpmyadmin_auth.py \
  vendor/systutor-core/plugins/hosting/backend/tests/test_phpmyadmin_proxy.py \
  vendor/systutor-core/plugins/hosting/backend/tests/test_phpmyadmin_concurrency.py \
  vendor/systutor-core/plugins/hosting/backend/tests/test_phpmyadmin_rootless_broker.py -q

ruff check \
  scripts/tenant_cell/db_broker.py \
  scripts/tenant_cell/host_agent.py \
  scripts/tenant_cell/cli.py \
  vendor/systutor-core/plugins/hosting/backend/phpmyadmin_session.py \
  vendor/systutor-core/plugins/hosting/backend/phpmyadmin_proxy.py \
  vendor/systutor-core/plugins/hosting/backend/phpmyadmin_broker.py
```

E2E black-box en `spanel.lab`:

1. dos tenants, un WordPress rootless con datos distintos en cada uno;
2. abrir simultáneamente dos sesiones en el único PMA y demostrar que cada una
   ve solo su DB;
3. intentar reutilizar ticket/cookie/relay A contra site B → rechazo;
4. confirmar cero listener antes, listener/conector acotados durante, y cero
   recursos después de logout y timeout;
5. matar backend/broker durante sesión y ejecutar reconcile → cero huérfanos;
6. sitio rootful sigue funcionando por camino legacy;
7. Core/otros tenants intactos, `delta_denied=0`, cleanup verificado.

Artefacto: `artifacts/0110-b-shared-core-phpmyadmin-e2e.json`.

## ROLLBACK

- Desactivar `SPANEL_HOSTING_ROOTLESS_PMA_BROKER`; rootful mantiene camino actual
  y rootless responde fail-closed (no publica DB como fallback).
- Cerrar/reconciliar todos los relay IDs y remover conectores etiquetados por
  sesión.
- Revertir integración de sesión/proxy sin tocar datos ni contenedores DB.
- El broker no tiene estado de negocio: su store puede reconstruirse cerrando
  todo y partiendo vacío.

## Change Surface

```yaml
change_surface:
  allowed:
    - scripts/tenant_cell/db_broker.py
    - scripts/tenant_cell/host_agent.py
    - scripts/tenant_cell/cli.py
    - scripts/tests/test_tenant_cell_db_broker.py
    - scripts/tests/test_tenant_cell_host_agent.py
    - scripts/e2e_0110_b_shared_pma.py
    - vendor/systutor-core/plugins/hosting/backend/phpmyadmin_broker.py
    - vendor/systutor-core/plugins/hosting/backend/phpmyadmin_session.py
    - vendor/systutor-core/plugins/hosting/backend/phpmyadmin_proxy.py
    - vendor/systutor-core/plugins/hosting/backend/router.py
    - vendor/systutor-core/plugins/hosting/backend/service.py
    - vendor/systutor-core/plugins/hosting/backend/settings.py
    - vendor/systutor-core/plugins/hosting/backend/tests/test_phpmyadmin_*.py
    - vendor/systutor-core/plugins/hosting/README.md
    - artifacts/0110-b-shared-core-phpmyadmin-e2e.json
    - aspecs/0110-b-shared-core-phpmyadmin-db-broker.md
  prohibited:
    - vendor/systutor-core/plugins/mail/**
    - vendor/systutor-core/plugins/apps/**
    - vendor/systutor-core/plugins/domains/**
    - scripts/tenant_cell/apparmor.py
    - docker-compose.yml
    - apps/web/**
    - /opt/stacks/**
```

## Lab execution notes (2026-11-20)

`artifacts/0110-b-shared-core-phpmyadmin-e2e.json` — `result: PARTIAL`,
`cleanup_complete: true`, 13/13 executed checks OK, `delta_denied=0`.

Executed on `spanel.lab` with `SPANEL_HOSTING_ROOTLESS_PMA_BROKER=true`,
`SPANEL_PHPMYADMIN_ARBITRARY=1`, `SPANEL_PHPMYADMIN_SESSION_TTL=30` (only for
the expiry drill), `SPANEL_DB_BROKER_BIND=172.24.0.1`,
`SPANEL_DB_BROKER_SOURCES=172.24.0.3,172.24.0.4` and the connector image pinned
to `alpine/socat@sha256:beb4a68d9e4fe6b0f21ea774a0fde6c31f580dde6368939ed70100c5385b015e`.

Executed checks: two simultaneous rootless WordPress sessions through the single
Core phpMyAdmin (each dashboard sees only its own DB), cross-site ticket and
cookie replay rejected, relay close through the CLI breaks only the target
session, logout cleanup, TTL expiry cleanup, crash/reconcile cleanup, zero
permanent DB port and zero AppArmor denials. Rootful legacy and a second
rootless tenant are reported as **blocked**, not PASS; see the artifact.

Lab platform limits, documented instead of hidden:

- The installed rootless/AppArmor baseline rejects a read-only rootfs
  (`mount dst=/, flags=MS_RDONLY|MS_REMOUNT|MS_BIND: permission denied`), so the
  lab runs `SPANEL_PMA_CONNECTOR_READ_ONLY=0`. Product default stays `1`.
- RootlessKit does not bind a fixed `HostIp` for published ports, and the site
  private network is `internal: true`. The connector therefore joins the cell
  edge network plus the private network and publishes an ephemeral wildcard
  port. No permanent DB port exists; the relay still bounds access by session
  and TTL.
- The Core phpMyAdmin must be reachable from the app; the lab connects it to the
  app network in addition to its own.
- `db_relay_open` is not exposed by the CLI; only the backend can issue the
  session-bound capability.

## Traceability

- Requirement: conservar phpMyAdmin Core como herramienta compartida para DBs
  WordPress rootless sin romper el aislamiento por tenant.
- Depends on: A.SPEC 0110-A.
- owner: lucas
- approver: pendiente
- Commit: pendiente
- Evidence: `artifacts/0110-b-shared-core-phpmyadmin-e2e.json` (PARTIAL,
  cleanup completo; rootful y segundo tenant bloqueados por el lab).
- Deployment: laboratorio primero; producción prohibida hasta PASS.

## Definition of Done

- [ ] Un único PMA Core sirve rootful y rootless por caminos explícitos
      (rootless E2E PASS; rootful sin fixture vivo en el lab, cubierto por tests).
- [x] Broker/conector efímeros ligados a sesión con TTL y cleanup.
- [x] Browser no controla destino ni credenciales.
- [ ] Aislamiento A/B demostrado con sesiones simultáneas y ataques cruzados
      (demostrado entre dos sitios del mismo tenant; falta un segundo tenant
      rootless vivo).
- [x] Logout, timeout, crash y reconcile dejan cero listeners/conectores.
- [x] MariaDB conserva cero puertos permanentes.
- [ ] E2E black-box PASS, `delta_denied=0` y cleanup verificado
      (delta=0 y cleanup OK; resultado PARTIAL por los dos bloqueos anteriores).
