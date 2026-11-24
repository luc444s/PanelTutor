# A.SPEC 0116 — Ingress rootless de Apps: backfill y fallo visible

## WHY

Tras A.SPEC 0114, el ingress de una app rootless se alimenta de
`domains_app_hosts`. Las apps migradas antes del contrato solo conservaban
`domains_routes`; sin AppHost, `AppsIngress.reconcile()` no publicaba nada y
Traefik seguía apuntando al contenedor rootful parado → **502**.

Además:

- añadir un dominio después del deploy solo refrescaba el relay, sin crear la
  ruta nginx de la celda;
- `refresh_routes.py` decidía rootless/rootful por heurística, no por el
  runtime persistido, y reportaba éxito aunque la publicación fallara.

## WHAT

1. Migración de datos del plugin Domains: backfill de `domains_app_hosts`
   desde `domains_routes` (solo rutas `/` de apps vivas), idempotente.
2. El handler de `domains.domain.added` reconcilia el ingress de la celda antes
   de refrescar el relay.
3. `refresh_routes.py` usa `tenant_resource_runtimes` para decidir el runtime,
   falla con código distinto de cero ante errores y detecta AppHost ausente.
4. `refresh_application_routes(..., strict=True)` propaga errores en reparación
   explícita; el deploy mantiene el comportamiento tolerante.
5. Contrato `rootless_ingress`: el editor de rutas de Dominios
   (“Guardar y publicar”) consulta el runtime persistido, sincroniza
   `domains_app_hosts`, reconcilia la celda/relay y **no** escribe el documento
   de contenedor. Borrar la ruta `/` elimina el AppHost y despublica el relay.

## CONTRACT

- Un AppHost existente + deploy rootless siempre produce fila en
  `tenant_ingress_routes`, `apps-routes.conf` en la celda y Traefik apuntando a
  `http://<relay-bind>:40000+index`.
- Sin AppHost no se publica nada y la reparación explícita lo reporta.
- La migración no borra ni modifica `domains_routes`.

## VERIFICATION

- `test_app_hosts_migration.py`: backfill, normalización, exclusión de hosting,
  apps borradas y rutas no-root; idempotencia.
- `test_refresh_routes.py`: runtime persistido manda sobre la heurística.
- Suites de Domains, Apps (ingress/rootless) y ruff en verde.
