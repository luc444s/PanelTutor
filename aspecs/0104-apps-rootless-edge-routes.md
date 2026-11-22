# A.SPEC 0104 — Rootless app edge routes through the single parent Traefik

> `risk: high` — introduce un relay TCP en el host y publica rutas hacia apps
> rootless sin tocar Traefik, su red ni su configuración estática. Requiere
> `approver:`.

## WHY

Hoy el único Traefik corre en la red bridge `proxy` (`172.18.0.0/16`, gateway
`172.18.0.1`, contenedor `172.18.0.4`), no en host network. Las celdas rootless
publican en `127.x.y.z:<20000+index>` dentro del netns del host. Un contenedor
en bridge **no puede alcanzar ese loopback**, así que la ruta prevista en
A.SPEC 0096 §4.2 ("el registrar escribe rutas directas al loopback de la
celda") no es ejecutable en esta topología.

Mover Traefik a host network fue descartado: rompería todas las rutas
file-provider existentes (`http://<container>:<port>`, que dependen del DNS de
`proxy`), cambiaría el allowlist `nft skuid`, ampliaría el blast radius a todo
el loopback del host y violaría A.SPEC 0025/0029.

La solución es un **relay TCP no privilegiado en el host**, alcanzable desde la
red `proxy`, que reenvía al loopback privado de cada celda. Traefik sigue siendo
el único proxy y el único que termina TLS; los certificados no cambian de dueño
ni entran en las celdas.

El criterio de éxito es demostrable, no solo unitario: se debe crear una celda
rootless con **todas** sus configuraciones (usuario, `native.cgroupdriver=systemd`,
AppArmor, nft `skuid`, slice/plan y socket rootless propio), levantar dentro un
contenedor nginx con una página HTML estática que diga exactamente:

```
hola, este es un htrml que se ve desde un contenedor rootless
```

y probar que ese mismo cuerpo llega, en orden, a: (1) el loopback de la celda,
(2) el listener del relay en la gateway de `proxy`, y (3) el Traefik de
laboratorio con el `Host:` correspondiente. La evidencia debe incluir un link
visible desde el lab. Una segunda ronda, en otro entorno aislado, instala
*software para editores* en un contenedor y verifica su link; ese es el prueba
definitiva de que el relay TCP no privilegiado hizo su trabajo.

## WHAT

Un `edge_relay` en el host expone, en la gateway de `proxy`, un puerto estable
por celda que Traefik puede alcanzar; el control plane publica la ruta
dinámica con ese puerto como `servers.url`, reutilizando el file-provider y el
modelo de propiedad existente.

## SCOPE

- `network.py`: nueva función pura `relay_port(index)` (`40000 + index`), sin
  tocar las reglas `nft` ni los puertos de celda existentes.
- `relay.py` (nuevo): relay TCP con hilos, `bind` configurable (default
  `172.18.0.1`), allowlist de IP de origen (default la IP detectada del
  contenedor Traefik), y plano de control por Unix Domain Socket con
  `SO_PEERCRED` y verbos allowlist `apply`/`remove`/`status`/`reload`.
- `cli.py`: comando `edge-relay`, con el mismo gate host-only que `plan-agent`.
- `deploy/spanel-edge-relay.service` (nuevo): unidad systemd con
  `User=<SPANEL_TRAEFIK_UID>` (1000 por defecto, UID ya autorizado por `nft`),
  sin mounts de sockets Docker.
- `host_agent.py`: verbo de solo lectura `endpoint(slug)` que devuelve
  `loopback_address`, `publish_port`, `relay_port`, `bind` y `allowed_sources`,
  derivados del registry y de `network.py`.
- `plans_client.py`: método tipado `endpoint(slug)` usando el mismo protocolo
  HMAC/UDS que el resto del cliente.
- `domains/backend/publisher.py`: `RootlessRoutePublisher` que reutiliza
  `ProxyOperations.write_route_document(..., validate_runtime=False,
  connect_network=False)` con `PathRoute(container=bind, port=relay_port)`.
  El marker, el nombre del archivo y el dueño del Host siguen siendo los
  actuales.
- `apps/backend/rootless_routes.py` (nuevo): resuelve el endpoint del tenant
  vía el cliente del agente y llama al publicador; se engancha a los hooks
  existentes de refresh/cleanup de rutas.
- Tests: relay real con servidor HTTP local, auth del socket, endpoint del
  agente, render con IP destino sin validación de contenedor, y E2E en lab.

## OUT OF SCOPE

- Mover Traefik a host network ni cambiar su compose, red o configuración
  estática.
- Reiniciar Traefik ni tocar `/opt/stacks/traefik/**` fuera del directorio
  dinámico ya gestionado por el file-provider.
- Montar sockets Docker (de host o de celda) en Traefik ni en el relay.
- Emitir o renovar certificados dentro de las celdas; cambiar `certResolver`.
- Modificar las reglas `nft skuid` ni los puertos `20000+index` existentes.
- Tocar `cell-g`, `cell-h`, MariaDB, phpMyAdmin, WordPress ni producción.
- Cambiar el API de planes, el 503 fail-closed ni A.SPEC 0101/0102/0103.

## CONTRACT

**Precondiciones**: el host tiene la gateway de `proxy` (o `SPANEL_EDGE_RELAY_BIND`), el registry de celdas existe, el agente host está disponible y el file-provider de Traefik apunta al directorio ya detectado por `domains`.

**Postcondiciones**:

- `relay_port(index) = 40000 + index` no colisiona con `publish_port(index)`.
- El relay solo acepta conexiones cuya IP de origen esté en `allowed_sources`;
  por defecto la IP del contenedor Traefik detectada en `proxy`.
- El relay reenvía bytes en ambos sentidos y cierra ambos lados al terminar;
  no interpreta HTTP ni necesita TLS.
- `endpoint(slug)` es de solo lectura y no amplía privilegios del agente.
- Las rutas rootless se escriben como `spanel-*.yml` con el marker, sin
  `validate_runtime` ni conexión a red Docker, y son removibles por dominio.
- Un Host con ruta rootless tiene un único dueño; si no hay endpoint de celda,
  no se publica ruta (fail-closed).
- Traefik sigue terminando TLS y resolviendo ACME; la app rootless sirve HTTP
  plano al relay.

## INVARIANTS

```yaml
invariants:
  - "Traefik no recibe ningun socket Docker de celda ni del host."
  - "No se mueve Traefik a host network ni se reinicia; su configuracion estatica queda intacta."
  - "El relay corre sin privilegios, como SPANEL_TRAEFIK_UID, ya autorizado por nft skuid."
  - "El relay no expone exec, paths ni unidades arbitrarias: solo apply/remove/status/reload de endpoints de celda."
  - "Las rutas rootless usan el mismo file-provider, marker y uno-dueno-por-Host que las rutas rootful."
  - "No se llama a validate_runtime ni connect_network para rutas rootless: no hay contenedor en el daemon root."
  - "TLS y ACME siguen centralizados en Traefik; ningun certificado entra en la celda."
  - "PostgreSQL es la fuente de verdad del dominio; registry.json solo provee el indice de la celda."
  - "Sin endpoint de celda no se publica ruta."
  - "La evidencia E2E incluye el cuerpo HTML exacto y su hash en los tres saltos: celda, relay y Traefik."
  - "El link entregado es navegable desde el lab y pasa por el relay no privilegiado."
  - "No se tocan cell-g, cell-h, Traefik, phpMyAdmin, MariaDB, WordPress ni produccion."
```

## VERIFICATION

```bash
PYTHONPATH=vendor/systutor-core:. python3 -m pytest scripts/tests/test_tenant_cell_relay.py scripts/tests/test_tenant_cell_provision.py vendor/systutor-core/plugins/domains/backend/tests/test_rootless_routes.py vendor/systutor-core/plugins/domains/backend/tests/test_proxy_files.py vendor/systutor-core/plugins/apps/backend/tests/test_plans.py -q
PYTHONPATH=vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/apps/backend/tests/test_plans.py vendor/systutor-core/plugins/apps/backend/tests/test_plans_client.py vendor/systutor-core/plugins/apps/backend/tests/test_plans_agent.py scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_provision.py scripts/tests/test_tenant_cell_relay.py -q
ruff check scripts/tenant_cell vendor/systutor-core/plugins/domains/backend/publisher.py vendor/systutor-core/plugins/apps/backend/rootless_routes.py
python3 scripts/spanel_tenant.py edge-relay --help
```

### Criterio de aceptación E2E (obligatorio, lab)

La evidencia se genera en `artifacts/0104-rootless-edge-route-e2e.json` y debe
cubrir **toda la cadena**, con el mismo cuerpo HTML y su hash en cada salto:

1. Celda rootless desechable, creada por CLI, con **todas** las configuraciones:
   usuario del sistema, linger, `native.cgroupdriver=systemd`, AppArmor en
   `enforce`, tabla nft `skuid`, slice/plan aplicado y socket
   `/var/lib/spanel/cells/<slug>/docker.sock` propio. No se reutilizan
   `cell-g` ni `cell-h`.
2. Contenedor nginx estático dentro de esa celda, servido en el puerto
   publicado `127.x.y.z:<20000+index>`, con el cuerpo exacto:
   `hola, este es un htrml que se ve desde un contenedor rootless`.
3. Salto 1 — directo a la celda: `curl http://127.x.y.z:<puerto>/` desde el
   host devuelve ese cuerpo.
4. Salto 2 — relay no privilegiado: `endpoint(slug)` devuelve
   `172.18.0.1:<40000+index>` (en lab, la gateway correspondiente); el relay
   está corriendo como `SPANEL_TRAEFIK_UID` y solo acepta la IP de Traefik.
   `curl http://<bind>:<relay_port>/` devuelve **el mismo** cuerpo.
5. Salto 3 — Traefik padre: el YAML `spanel-*.yml` publicado en el directorio
   dinámico del Traefik de laboratorio contiene el `Host:` de prueba y
   `servers.url = http://<bind>:<relay_port>`. Una petición con ese `Host:`
   contra `127.0.0.1:9080` devuelve **el mismo** cuerpo, confirmando que
   Traefik queda detrás del relay sin haber sido modificado.
6. **Link visible desde el lab**: se registra el hostname de prueba en el DNS
   del laboratorio (o entrada equivalente en `/etc/hosts` del cliente) y se
   entrega una URL navegable, p. ej. `http://rootless-e2e.lab:9080/`, además
   del `curl -H 'Host: rootless-e2e.lab' ...` usado como prueba falsable.
7. **Ronda 2, entorno aislado distinto**: una celda nueva, sin compartir
   datos con la anterior, instala *software para editores* en un contenedor;
   se publica su ruta por el mismo relay y se entrega su link verificado.
   Esta segunda ronda es la prueba definitiva de que el relay TCP no
   privilegiado funciona como infraestructura reutilizable.

## ROLLBACK

Quitar la ruta con `remove` y bajar el relay devuelve el sistema a su estado anterior; no hay migración de esquema. Las rutas rootful no se tocan: el publicador rootless solo escribe documentos `spanel-*` nuevos y los elimina. La unidad del relay se puede deshabilitar sin afectar el deploy ni los certificados.

## Change Surface

```yaml
change_surface:
  allowed:
    - scripts/tenant_cell/relay.py
    - scripts/tenant_cell/network.py
    - scripts/tenant_cell/host_agent.py
    - scripts/tenant_cell/cli.py
    - scripts/tenant_cell/deploy/spanel-edge-relay.service
    - scripts/tests/test_tenant_cell_relay.py
    - vendor/systutor-core/plugins/apps/backend/plans_client.py
    - vendor/systutor-core/plugins/apps/backend/rootless_routes.py
    - vendor/systutor-core/plugins/apps/backend/register.py
    - vendor/systutor-core/plugins/apps/backend/worker.py
    - vendor/systutor-core/plugins/domains/backend/publisher.py
    - vendor/systutor-core/plugins/domains/backend/tests/test_rootless_routes.py
  prohibited:
    - vendor/systutor-core/src/**
    - vendor/systutor-core/app/**
    - vendor/systutor-core/migrations/**
    - vendor/systutor-core/plugins/hosting/**
    - vendor/systutor-core/plugins/tenant/**
    - vendor/systutor-core/plugins/domains/backend/proxy/core.py
    - vendor/systutor-core/plugins/domains/backend/proxy/operations.py
    - vendor/systutor-core/plugins/domains/backend/proxy/files.py
    - apps/web/**
    - docker-compose.yml
    - /opt/stacks/**
    - /etc/**
    - /run/**
    - scripts/e2e_*.py
```

Nota: el unit file del relay se entrega como plantilla bajo `scripts/tenant_cell/deploy/`; el GENERATOR no escribe `/etc/**`.

## Blast Radius

```yaml
blast_radius:
  direct:
    - listener TCP en la gateway de proxy y su allowlist de origen
    - verbo endpoint del agente host y cliente apps
    - publicacion de documentos spanel-*.yml para dominios rootless
  indirect:
    - rutas de apps rootless en Traefik
    - reconciliate/refresh de rutas del worker de apps
  must_not_affect:
    - rutas rootful existentes y sus YAML
    - Traefik, su red, su configuracion estatica y sus certificados
    - cell-g y cell-h
    - MariaDB / phpMyAdmin / WordPress
    - produccion
```

## Composition

```yaml
composition:
  requires_aspecs:
    - "0096-apps-rootless-tenant-cell"
    - "0100-apps-tenant-resource-plan"
    - "0102-apps-host-plan-materializer-wiring"
  must_compose_with:
    - "0101-apps-tenant-plan-backend"
  systemic_invariants:
    - "Un dueno por Host y el marker managed-by: spanel se conservan."
    - "Sin plan, _override sigue usando 512m/1.0/256."
    - "El 503 fail-closed de la API de planes no cambia."
  composition_checks:
    - "PYTHONPATH=vendor/systutor-core:. python3 -m pytest scripts/tests/test_tenant_cell_relay.py scripts/tests/test_tenant_cell_plan.py -q"
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: one coherent responsibility and one main reason to change
  entrypoints_must_stay_thin: true
  review_threshold_lines: 1000
  extraction_threshold_lines: 1600
  preferred_new_logic_locations:
    - scripts/tenant_cell/relay.py
    - vendor/systutor-core/plugins/apps/backend/rootless_routes.py
```

El tamaño en líneas no es bloqueante; gobiernan la corrección y la VERIFICATION.

## Traceability

- Requirement: hacer alcanzables las apps rootless desde el único Traefik sin moverlo a host network.
- Evidence: topologia real `proxy` 172.18.0.0/16, gateway 172.18.0.1, Traefik 172.18.0.4; A.SPEC 0096 §4.2.
- E2E ejecutado: `artifacts/0104-rootless-edge-route-e2e.json` (dos rondas PASS, links vivos).
- GAP-1 (seguido): `plan set` con `Slice=tenant-<slug>.slice` hace que `runc` de contenedores rootless caiga al bus del sistema (`/run/systemd/private`, EPERM). El plan se verificó pero hubo que retirarlo para conservar los links; requiere spec de seguimiento.
- GAP-2 (seguido): el perfil AppArmor generado omite reglas para imágenes reales (`docker-proxy`, nginx, `/proc/sys/net/ipv4/**`, `cgroup.type`); parcheado solo en el lab, requiere spec de seguimiento.
- owner: lucas
- approver: lucas
- Commit:
- Deployment: laboratorio `spanel.lab`; sin producción hasta aprobación.

## Definition of Done

- [ ] Objective satisfied
- [ ] Scope respected
- [ ] Contract satisfied
- [ ] Independent falsable truth exists now
- [ ] Invariants preserved
- [ ] Verification passed
- [ ] Rollback / compensation is honest
- [ ] Composition checks passed when applicable
- [ ] No unrelated changes
- [ ] Structural constraints respected
- [ ] Traceability established
- [ ] Celda rootless E2E con todas las configuraciones y contenedor nginx con el HTML exacto
- [ ] Mismo cuerpo y hash verificados en celda, relay y Traefik de laboratorio
- [ ] Link navegable entregado desde el lab
- [ ] Ronda 2 en entorno aislado con software para editores y su link verificado
