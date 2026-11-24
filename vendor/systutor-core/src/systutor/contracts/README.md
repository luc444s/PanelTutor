# packages/contracts

Espacio para contratos compartidos entre backend, frontend, plugins y tooling interno.

## `domain_ownership`

Namespace único de dominios entre plugins, sin imports cruzados:

- `register_site_provider(app, name, provider)` — un plugin publica los sitios de
  un tenant (`OwnedSite`: `site_id`, `tenant_id`, `container`,
  `primary_domain`). Lo registra Hosting.
- `register_extra_claims(app, name, checker)` — un plugin responde si un dominio
  ya lo publica como ruta extra. Lo registra el plugin `domains`.
- `list_sites` / `resolve_site` — consultas acotadas al tenant.
- `is_primary_domain` — consulta global: un dominio primario no se puede
  reclamar en ningún tenant.
- `is_extra_claimed` — consulta global: Hosting no crea un sitio con un dominio
  que ya publica otro plugin.

## `domain_namespace`

Propiedad explícita por tenant: lista, dueño, reclamo y liberación.

- `register_domain_providers(app, name, *, list_domains, owner, claim=None,
  release=None)` — `tenant` es el dueño del dato y registra los cuatro.
- `claim_domain` reclama un dominio libre; `release_domain(app, db, tenant_id,
  domain) -> bool` libera una reserva (devuelve `False` si ningún provider la
  implementa; el dueño del dato responde `AppError` si el dominio está en uso).
- `list_tenant_domains` / `domain_owner` son las consultas de solo lectura.

Los duplicados con otra implementación fallan en el registro. El registro vive
en `app.state`, así que las pruebas no comparten estado entre procesos.

## `app_hosts`

Contrato de Hosts de aplicaciones propiedad de `domains`, sin importar sus
modelos desde Apps:

- `register_app_host_provider(app, name, provider)` registra el inventario.
- `list_app_hosts(app, db, tenant_id, application_id=None)` lista Hosts con
  scope de tenant.
- `resolve_app_host(app, db, tenant_id, application_id, service)` resuelve un
  `AppHost(site_id, application_id, service, domain, https, port,
  unsupported_paths)`.

`port` sale de la ruta `/` de Dominios y `unsupported_paths` marca un sitio con
rutas adicionales: el ingress de la celda solo publica `/`. Dominios es la única
fuente del Host; no existe fallback a `apps_applications.domain`.

## `cell_ingress`

- `register_cell_ingress_provider(app, name, provider)` registra el handle
  rootless que el kernel usa para escribir y recargar el ingress.
- `resolve_cell_ingress(app, db, tenant_id)` devuelve un `CellIngress` ligado a
  ese handle. Hosting y Apps publican sus rutas en `tenant_ingress_routes`
  (`owner_kind`); solo Hosting declara el `default_server`.

## `container_runtime` y `resource_runtime`

- `container_runtime` registra handles opacos `rootful`/`rootless`. Un handle
  permite comandos acotados, inspect y transferencia de volúmenes por stream;
  nunca expone el socket a una petición HTTP.
- `resource_runtime` registra una única fuente de verdad para leer y fijar la
  asignación explícita `(tenant, kind, resource_id)`. La ausencia se devuelve
  como `None`: el consumidor decide altas legacy o falla cerrado, sin confundir
  ausencia con una asignación rootful.
