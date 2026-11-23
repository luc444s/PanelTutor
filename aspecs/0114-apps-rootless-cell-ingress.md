# A.SPEC 0114 — Apps rootless: ingress de celda, ruta al relay y muerte del legacy

> `risk: high` — cambia el camino de publicación de hosts de Apps y elimina
> columnas/API legacy. Requiere `approver:` y migración de datos en producción.

## WHY

Hosting ya sirve sus sitios rootless por tres piezas coordinadas
(`hosting/backend/rootless_migration.py`, líneas 668-672):

1. `RootlessIngress.upsert(RouteSpec)` escribe el `server_name` en el nginx
   interno de la celda (`spanel-cell-ingress`, tabla `hosting_rootless_routes`).
2. `get_site_domain_publisher(app).unpublish(domain)` elimina el documento
   legacy de Dominios que apuntaba al contenedor rootful.
3. `RootlessRoutePublisher.publish(...)` reescribe el documento del file-provider
   de Traefik para que apunte al relay `172.18.0.1:<relay_port>`.

Apps solo implementó (3) y además la condicionó a la columna legacy
`apps_applications.domain`:

```python
# apps/backend/worker.py::_publish_deploy_cutover
if app.domain:
    published = self.rootless_routes.refresh(db, tenant_id, application_id)
```

Consecuencias observadas en producción (tenant `milton`):

- `editores.systutor.com` tiene su host en Dominios, no en la columna legacy
  (`domain` → `null`), así que nunca se publicó la ruta del relay.
- El documento `spanel-route-*.yml` seguía apuntando a
  `http://app-14aaf…-frontend-1:8080`, un contenedor del daemon rootful.
- El nginx de la celda no conoce ningún host de Apps (no existe equivalente a
  `hosting_rootless_routes`), por lo que reenviar el relay tampoco serviría.
- Resultado: al parar el stack rootful, 502 y la app quedó migrada de facto
  (contenedores en la celda, panel con `already_rootless: true`) pero sin
  tráfico público.

Además el "legacy" de Apps sigue vivo: columnas `domain`, `ingress_service`,
`ingress_port` en `apps_applications` y `apps_deployments`, expuestas por la
API (`schemas.ApplicationView`), usadas por `resolve_apps_sites()` y por el
`_domains()` de `RootlessRoutes`. Hosting ya demostró que Dominios es la única
fuente de verdad del Host; mantener dos fuentes es la raíz del fallo.

## WHAT

1. Dar a Apps el mismo ciclo rootless que Hosting:
   - registro de sus rutas en la tabla del kernel con `owner_kind='apps'`,
   - render de `apps-routes.conf` en el mismo directorio
     `/etc/nginx/conf.d` del ingress de la celda,
   - publicación de la ruta de Traefik al relay para **todos** los hosts de
     Dominios del App (no solo la columna legacy),
   - limpieza simétrica en undeploy/rollback.
2. Reutilizar, no duplicar, el motor de ingress:
   - el render y las operaciones (`write_private`, `exec nginx -s reload`,
     validación de target/tenant) se extraen del plugin Hosting a un módulo
     compartido sin estado por plugin: `systutor/kernel/cell_ingress.py`,
     expuesto como contrato, con el render parametrizable por archivo.
   - Hosting y Apps lo consumen; el `default_server` queda en Hosting
     (`default.conf`) y Apps escribe `apps-routes.conf`.
3. Eliminar el legacy de Apps por completo:
   - quitar el fallback `apps_applications.domain` de `RootlessRoutes._domains`
     y de `resolve_apps_sites()`;
   - quitar el gate `if app.domain` del cutover;
   - quitar `domain`, `ingress_service`, `ingress_port` de ambos modelos, de
     `schemas.ApplicationView`/`ApplicationCreate` y de todos los `SELECT`/`tuple`
     del runtime;
   - migración de plugin `010_drop_apps_legacy_ingress.py` que hace `DROP COLUMN`
     de las seis columnas.
4. Script de migración operativo `scripts/migrate_apps_rootless.py` para las
   Apps existentes (Gitea y Editores en `milton`): registra hosts en el ingress
   de la celda, publica el relay, elimina el documento legacy y, opcionalmente,
   retiene o retira el stack rootful.

## SCOPE

- `vendor/systutor-core/src/systutor/kernel/cell_ingress.py` (nuevo):
  - modelo SQLAlchemy neutro `TenantIngressRoute` (`tenant_ingress_routes`:
    `route_id` PK, `tenant_id`, `owner_kind` ∈ {hosting, apps}, `owner_id`,
    `service`, `domain`, `target`, `port`, `updated_at`, único
    `(tenant_id, domain)`).
  - servicio `CellIngress(handle)` con `reconcile(tenant_id, owner_kind)`,
    `upsert(route)`, `remove(route_id)`, `render(...)`.
  - render de dos archivos: `default.conf` (hosting, con `default_server`) y
    `apps-routes.conf` (apps, sin `default_server`), validado con
    `nginx -t` en un contenedor efímero antes de publicar.
- `vendor/systutor-core/src/systutor/contracts/cell_ingress.py` (nuevo):
  contrato `register_cell_ingress_provider` / `resolve_cell_ingress`.
- Revisión del kernel `vendor/systutor-core/migrations/versions/2026xxxx_0012_cell_ingress_routes.py`
  (ejecutada por el runtime migrador, nunca por el CLI de Alembic): crea
  `tenant_ingress_routes` y **copia** las filas de `hosting_rootless_routes`
  con `owner_kind='hosting'`.
- Migración de plugin Hosting `006_use_kernel_cell_ingress.py`:
  - deja de escribir `hosting_rootless_routes` (se elimina el modelo),
  - adapta `RootlessIngress` para delegar en el servicio del kernel,
  - elimina la tabla `hosting_rootless_routes` (ya copiada).
- Migración de plugin Apps `009_drop_apps_legacy_ingress.py`:
  `DROP COLUMN` de `apps_applications.{domain,ingress_service,ingress_port}` y
  de `apps_deployments.{ingress_service,ingress_port}`. Apps no necesita tabla
  propia: sus rutas viven en `tenant_ingress_routes` con
  `owner_kind='apps'` y `owner_id=<application_id>` (sin duplicar estado).
- `vendor/systutor-core/plugins/apps/backend/cell_ingress.py` (nuevo):
  - `AppsIngress(reconcile, remove)` que resuelve el handle rootless del tenant
    vía `resolve_container_runtime(app, db, tenant_id, "rootless")`,
  - para cada `AppHost` de Dominios construye `(domain, container, port)` con
    el manifest del deployment activo y el `port` de la ruta de Dominios,
  - upsert en el `cell_ingress` del kernel (`owner_kind='apps'`),
  - publica relay y hace `unpublish` del documento legacy antes de publicar,
  - limpieza en undeploy/down/delete.
- `vendor/systutor-core/plugins/apps/backend/rootless_routes.py`:
  - `_domains()` solo lee `list_app_hosts` (sin fallback legacy),
  - `refresh()` publica todos los hosts y exige publicación completa,
  - `cleanup()` borra ingress + relay.
- `vendor/systutor-core/plugins/apps/backend/worker.py`:
  - el cutover de deploy llama `apps_ingress.reconcile(...)` y
    `rootless_routes.refresh(...)` siempre que haya hosts de Dominios,
    fallando el deploy si alguno no queda publicado,
  - `_publish_deploy_cutover` deja de recibir `app.domain`,
  - rollback: `apps_ingress.remove` + unpublish relay.
- `vendor/systutor-core/plugins/apps/backend/deployment.py` / `runtime/deployment.py`:
  - etiquetas `spanel.managed=true` y `spanel.tenant=<tenant_id>` en cada
    contenedor (las exige la validación de target, igual que Hosting).
- `vendor/systutor-core/plugins/apps/backend/register.py` +
  `vendor/systutor-core/plugins/apps/backend/catalog.py` + `schemas.py`:
  - fuera `domain`/`ingress_*` de vistas, creación, `resolve_apps_sites()` y
    proveedor de recursos.
- `vendor/systutor-core/src/systutor/contracts/app_hosts.py::AppHost` +
  `vendor/systutor-core/plugins/domains/backend/service.py::provide_app_hosts`:
  añadir `port` (desde `DomainRoute.port` para `path == "/"`) para no consultar
  Dominios desde Apps fuera del contrato. `domains_app_hosts` sigue siendo la
  tabla de asignación de host (ya existe, con `UNIQUE(domain)`).
- `scripts/refresh_routes.py`: deja de re-renderizar hosts de Apps rootless con
  el target de contenedor (sobrescribiría el documento del relay). Para un App
  rootless delega en `AppsIngress.reconcile` + `RootlessRoutes.refresh`; el
  render legacy de Dominios queda solo para Apps rootful (se elimina en la
  fase final del legacy).
- `scripts/migrate_apps_rootless.py` (nuevo): ver §MIGRACIÓN.
- `scripts/e2e_0114_apps_rootless_ingress.py` (nuevo): blackbox.
- Tests unitarios:
  - `vendor/systutor-core/tests/test_cell_ingress.py` (render mixto, colisión
    de dominio, `nginx -t`, migración de filas),
  - `vendor/systutor-core/plugins/apps/backend/tests/test_apps_cell_ingress.py`,
  - `vendor/systutor-core/plugins/apps/backend/tests/test_rootless_worker.py`
    (cutover exige publicación, legacy ausente),
  - `scripts/tests/test_migrate_apps_rootless.py`.

## OUT OF SCOPE

- Cambiar Traefik, su red, su compose o el certificado/ACME.
- Mover el relay, sus puertos o el `nft skuid`.
- Tocar el ingress de Hosting más allá de la extracción mecánica al kernel
  (mismo render, mismo `default_server`, mismos dominios).
- Añadir dominios a Apps desde la UI de Apps: se siguen asignando en Dominios.
- Reescribir el frontend de Apps salvo quitar los campos legacy del contrato.

## CONTRACT

**Precondiciones**

- `SPANEL_TENANTS_ROOTLESS=true` y el plan-agent disponible (el relay y el
  ingress existen y están sanos).
- El App tiene `active_deployment` rootless verificado (`status=running`) con
  manifest de contenedores.
- El host destino está registrado en Dominios para el `site_id`
  `<application_id>:<service>` (única fuente de verdad).

**Postcondiciones (deploy)**

- `tenant_ingress_routes` contiene una fila por `(app, service, domain)` con
  `owner_kind='apps'`, `owner_id=<application_id>`, `target=<container>` y
  `port=<port de Dominios>`.
- `/var/lib/spanel/cells/<slug>/private/ingress/apps-routes.conf` incluye
  `server_name <domain>` con `proxy_pass http://<container>:<port>` y pasa
  `nginx -t`.
- El documento de Traefik para `<domain>` apunta a `<bind>:<relay_port>` y ya
  no a `http://<container>:<port>`.
- El documento legacy previo fue eliminado (mismo nombre por dominio, se
  reescribe una sola vez).
- `GET https://<domain>/` responde 200 desde la celda.

**Postcondiciones (undeploy/delete/rollback)**

- Se eliminan las filas de `tenant_ingress_routes` del `owner_id` del App.
- Se regenera `apps-routes.conf` (sin ese host) y se recarga nginx.
- Se elimina el documento del relay para el host; si el App sigue vivo en
  rootful, se republica el documento legacy desde Dominios.

**Fail-closed**

- Sin handle rootless, sin endpoint de relay, con un target que no corre en la
  celda o sin `nginx -t` válido: no se publica nada y el deploy falla con
  `apps_ingress_unavailable` / `apps_route_publication_failed`.
- Un dominio ya reclamado por Hosting (u otro `owner_kind`) no se reescribe:
  error de conflicto, nunca se sirve el upstream equivocado.
- **Solo se soporta path `/`.** Si el host del App tiene rutas con otro `path`
  en Dominios, el preflight falla con `apps_ingress_path_unsupported` (no se
  publica un ingress que respondería 404 a esas rutas).
- Un App sin `active_deployment` rootless verificado, o con un servicio sin
  contenedor en el manifest, no publica ingress ni relay.

## INVARIANTS

```yaml
invariants:
  - "Dominios es la única fuente de verdad del host de un App; no se lee ni escribe apps_applications.domain."
  - "Un Host tiene un solo dueno: la unicidad (tenant_id, domain) se valida en la tabla del kernel antes de renderizar."
  - "El relay solo se usa con validate_runtime=False y connect_network=False; Traefik nunca recibe socket Docker de celda."
  - "El ingress de la celda conserva un unico default_server (Hosting) y Apps escribe un archivo separado (apps-routes.conf)."
  - "Ningun target se publica si no corre y no tiene spanel.managed=true y spanel.tenant=<tenant_id>."
  - "Solo se publica el path /: una ruta de Dominios con otro path falla el preflight en vez de servirse a medias."
  - "nginx -t corre en un contenedor efimero antes de reemplazar la configuracion viva."
  - "El deploy falla si el host existe en Dominios y no queda publicado; no se deja trafico apuntando a un contenedor parado."
  - "Rollback y delete son simetricos: filas, archivo de ingress, documento de relay y documento legacy."
  - "No queda ningun camino de codigo que publique rutas de Apps desde apps_applications.domain/ingress_service/ingress_port."
  - "Un Host de App rootless no se re-renderiza con el target de contenedor: refresh_routes y Dominios no sobreescriben el documento del relay."
```

## DATA MODEL

```text
tenant_ingress_routes (kernel, única fuente de rutas de ingress)
  route_id     text  PK        -- "hosting:<site_id>" | "apps:<application_id>:<service>"
  tenant_id    text  NOT NULL
  owner_kind   text  NOT NULL  -- hosting | apps
  owner_id     text  NOT NULL  -- site_id de Hosting | application_id de Apps
  service      text  NULL      -- solo Apps (servicio Compose)
  domain       text  NOT NULL
  target       text  NOT NULL
  port         int   NOT NULL
  updated_at   timestamptz
  UNIQUE (tenant_id, domain)
```

No hay tabla de rutas en Apps: `DELETE FROM tenant_ingress_routes WHERE
owner_kind='apps' AND owner_id=:application_id` es el cleanup completo.

## MIGRACIÓN (script `scripts/migrate_apps_rootless.py`)

Corre dentro del contenedor `spanel-app-1` (necesita DB, Dominios y el handle
de celda); no habla con Docker rootful salvo para retener/parar contenedores.

```bash
export SPANEL_DOMAIN=spanel.systutor.com
python3 /app/scripts/migrate_apps_rootless.py --tenant milton --dry-run
python3 /app/scripts/migrate_apps_rootless.py --tenant milton --apply
```

Fases por App (`--app <id>` repetible):

1. **inventory**: hosts de Dominios (`site_id=<app>:<service>`), deployment
   activo, manifest, runtime registrado, contenedores rootful detectados por
   nombre de proyecto.
2. **preflight**: handle rootless `ready`, endpoint de relay, `nginx -t`.
3. **ingress**: upsert en el `cell_ingress` del kernel y
   recarga del ingress.
4. **cutover**: `unpublish` legacy → `publish` relay.
5. **verify**: `GET https://<domain>/` con reintento acotado; misma ventana que
   Hosting (`verify_external_route`).
6. **retain/stop rootful**: `--stop-rootful` (opt-in) para parar el proyecto
   rootful; por defecto solo se reporta.
7. **result**: JSON con `ok`, `apps[]` y `steps[]`; código 0/1/2.

Opciones: `--dry-run` (default), `--apply`, `--app`, `--tenant`, `--stop-rootful`,
`--timeout`, `--json`, `--rollback <operation_id>`.

**Rollback** (`--rollback`): elimina filas e ingress, unpublish relay, republica
el documento legacy desde Dominios y (si `--stop-rootful` se usó) arranca los
contenedores rootful retenidos. Idempotente.

**Orden de despliegue**

1. Migraciones runtime del kernel + plugins (automáticas al arrancar; nunca
   Alembic CLI, ver AGENTS.md).
2. `git pull` + `scripts/deploy.sh app apps-worker`.
3. `migrate_apps_rootless.py --tenant milton --dry-run` → revisar.
4. `--apply`.
5. Parar rootful de las Apps migradas solo tras verificar 200 externo.
6. Opcional: `DELETE` de contenedores/volúmenes rootful retenidos.

## E2E (blackbox)

`scripts/e2e_0114_apps_rootless_ingress.py`:

1. Crea un App fixture con `compose.yaml` (nginx estático) y lo despliega
   rootless en una celda de laboratorio.
2. Asigna host en Dominios al `site_id` y ejecuta el hook (deploy o script).
3. Verifica: fila en `tenant_ingress_routes`, `server_name` en
   `apps-routes.conf`, documento Traefik con `bind:relay_port`, `nginx -t` OK.
4. `curl https://<domain>` → 200 y cuerpo esperado.
5. Simula caída del relay: el deploy falla; nada queda publicado.
6. Ejecuta `--rollback`: ingress y relay desaparecen y el documento legacy
   vuelve a publicarse; `curl` responde desde rootful.

## ACCEPTANCE

- Tras `--apply` en `milton`: `editores.systutor.com` responde **200 desde la
  celda** con el stack rootful parado (`docker ps` rootful sin los tres
  contenedores de `app-14aaf…`) y el documento de Traefik apuntando a
  `172.18.0.1:400xx`.
- `apps-routes.conf` contiene `server_name editores.systutor.com` y
  `proxy_pass http://app-14aaf…-frontend-1:8080`.
- `migrate_tenant_apps.py --dry-run` sigue mostrando `already_rootless: true`.
- Ya no existe ninguna referencia a `apps_applications.domain`,
  `ingress_service` o `ingress_port` en el backend, los schemas ni la web.
- Tests: kernel cell ingress + apps ingress + worker + migración + E2E en verde.
- Hosting sigue sirviendo sus 4 sitios sin cambios de comportamiento
  (regresión cubierta por `e2e_0110_c`).
