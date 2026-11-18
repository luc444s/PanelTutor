# A.SPEC 0106 — TLS for rootless-backed routes

> `risk: medium` — agrega HTTPS al publicador de rutas rootless sin tocar Traefik.

## WHY

A.SPEC 0104 publicó rutas rootless por el relay, pero solo se probó HTTP (`web`). TLS/ACME ya viven en el Traefik padre; falta demostrar HTTPS para un Host servido por una app rootless sin meter certificados en la celda ni en el relay.

## WHAT

El publicador puede emitir opcionalmente un router HTTP de redirect y un router `websecure` con `tls.certResolver`, reutilizando `render_site_yaml` sin cambiar el renderer.

## SCOPE

- `RootlessRoutePublisher.publish()` acepta `https: bool = True` (default de `PathRoute` en `HEAD`) y pasa `PathRoute(..., https=https, entrypoints=())`. `https=False` reproduce el YAML HTTP-plano del artifact 0104.
- Resolver, entrypoints y exclusión de `/.well-known/acme-challenge/` vienen de `proxy/settings.py` y `proxy/core.py`; nada hardcodeado.
- `AppsSettings` lee `SPANEL_ROOTLESS_ROUTES_HTTPS` (default `true`, conserva el código actual); `RootlessRoutes.refresh()` lo propaga. `false` es opt-out explícito.
- Tests de forma del YAML, certResolver, challenge, default HTTP y propagación.
- E2E en lab con el resolver `internal` (step-ca).

## OUT OF SCOPE

Cambiar Traefik o reiniciarlo; guardar certificados en celdas/relay; tocar `proxy/core.py`, `operations.py`, `files.py`, cert-agent, DNS-01, `cell-g`, `cell-h`, MariaDB/phpMyAdmin/WordPress del host o producción; habilitar HTTPS por defecto.

## CONTRACT

Con `https=True` (default): router HTTP con `redirectScheme` y exclusión del challenge, router HTTPS en `websecure` con `certResolver` de `proxy_settings().resolver`. Con `https=False`: un único router HTTP-plano, idéntico al artifact 0104. En ambos casos: un servicio con `servers.url = http://<bind>:<relay_port>`. Sin endpoint de celda no se publica nada. Traefik recarga por file-provider.

## INVARIANTS

```yaml
invariants:
  - "Traefik es el unico terminador TLS y el unico que habla ACME."
  - "Ningun secreto ACME entra en la celda, el relay ni AppArmor."
  - "El certResolver se toma de Dominios: nunca hardcodeado."
  - "La regla HTTP excluye /.well-known/acme-challenge/."
  - "SPANEL_ROOTLESS_ROUTES_HTTPS=true por defecto conserva el codigo actual; false reproduce el YAML HTTP del artifact 0104."
  - "Sin endpoint de celda no hay ruta HTTP ni HTTPS."
  - "No se tocan core.py, operations.py, files.py ni configuracion estatica de Traefik."
  - "No se tocan cell-g, cell-h, Traefik, phpMyAdmin, MariaDB, WordPress ni produccion."
```

## VERIFICATION

```bash
PYTHONPATH=vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/domains/backend/tests/test_rootless_routes.py vendor/systutor-core/plugins/apps/backend/tests/test_rootless_routes.py -q
PYTHONPATH=vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/domains/backend/tests/test_rootless_routes.py vendor/systutor-core/plugins/apps/backend/tests/test_rootless_routes.py vendor/systutor-core/plugins/apps/backend/tests/test_plans.py -q
ruff check vendor/systutor-core/plugins/domains/backend/publisher.py vendor/systutor-core/plugins/apps/backend/rootless_routes.py vendor/systutor-core/plugins/apps/backend/settings.py
PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -c "from plugins.domains.backend.publisher import RootlessRoutePublisher; import inspect; assert 'https' in inspect.signature(RootlessRoutePublisher.publish).parameters; print('ok')"
```

E2E: `artifacts/0106-rootless-route-tls-e2e.json` con YAML, certificado (subject/SAN/emisor), redirect HTTP→HTTPS y HTTPS 200 con cuerpo de la app.

## ROLLBACK

Volver `https=False` y republicar devuelve el documento HTTP anterior; sin cambios de esquema ni estado en celdas.

## Change Surface

```yaml
change_surface:
  allowed:
    - vendor/systutor-core/plugins/domains/backend/publisher.py
    - vendor/systutor-core/plugins/domains/backend/tests/test_rootless_routes.py
    - vendor/systutor-core/plugins/apps/backend/settings.py
    - vendor/systutor-core/plugins/apps/backend/rootless_routes.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_rootless_routes.py
    - vendor/systutor-core/plugins/apps/backend/tests/__init__.py
  prohibited:
    - vendor/systutor-core/src/**
    - vendor/systutor-core/app/**
    - vendor/systutor-core/migrations/**
    - vendor/systutor-core/plugins/domains/backend/proxy/core.py
    - vendor/systutor-core/plugins/domains/backend/proxy/operations.py
    - vendor/systutor-core/plugins/domains/backend/proxy/files.py
    - scripts/tenant_cell/**
    - apps/web/**
    - docker-compose.yml
    - /opt/stacks/**
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - YAML dinamico de rutas rootless
    - router HTTP de redirect y router HTTPS
  indirect:
    - emision de certificados por el resolver central
    - acceso HTTPS a apps rootless
  must_not_affect:
    - rutas rootful y sus certificados
    - rutas rootless HTTP existentes
    - cell-g y cell-h
    - Traefik, phpMyAdmin, MariaDB, WordPress
    - produccion
```

## Composition

```yaml
composition:
  requires_aspecs:
    - "0104-apps-rootless-edge-routes"
    - "0105-apps-cell-apparmor-inverted"
  must_compose_with:
    - "0104-apps-rootless-edge-routes"
  systemic_invariants:
    - "Un dueno por Host y marker managed-by: spanel."
    - "El 503 fail-closed de la API de planes no cambia."
  composition_checks:
    - "PYTHONPATH=vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/domains/backend/tests/test_rootless_routes.py vendor/systutor-core/plugins/apps/backend/tests/test_rootless_routes.py -q"
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: one coherent responsibility and one main reason to change
  entrypoints_must_stay_thin: true
  review_threshold_lines: 500
  extraction_threshold_lines: 800
```

## Traceability

- Requirement: HTTPS y certificados para apps rootless sin mover TLS del Traefik padre.
- Evidence: E2E 0104/0105 (HTTP only) y resolver `internal` del lab.
- owner: lucas
- approver: lucas
- Deployment: laboratorio `spanel.lab`; sin producción.

## Definition of Done

- [ ] Objective satisfied
- [ ] Scope respected
- [ ] Contract satisfied
- [ ] Invariants preserved
- [ ] Verification passed
- [ ] Rollback honest
- [ ] No unrelated changes
- [ ] E2E HTTPS con certificado real y contenido de app rootless
