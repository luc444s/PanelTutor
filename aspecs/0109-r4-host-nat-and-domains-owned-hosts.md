# A.SPEC 0109-R4 — Host-side cell NAT and domains-owned app hosts

> `risk: high` — toca red privilegiada del host, propiedad de dominios y un contrato público
> nuevo; exige `approver:`. Cierra los dos bloqueos del E2E black-box de 0109-R3.

## WHY

El E2E black-box de 0109-R3 dio **FAIL 0/4** con dos causas reales:

1. **NAT EPERM:** `ExecStartPost` intentó `nsenter -t $MAINPID -n` desde una unidad
   `systemd --user` (uid de la celda) y recibió `Operación no permitida`: hace falta
   `CAP_SYS_ADMIN` en el netns destino. La celda quedó `degraded`, sin `docker.sock`, y el
   deploy murió con `docker ... command failed (1)`. El MASQUERADE solo funcionó cuando el
   E2E lo aplicó como root con sudo.
2. **Dominio descartado por diseño:** `catalog.py:181-186` fija `domain=None` al crear apps
   («Ingress belongs to Dominios»), así que `ApplicationCreate` nunca persiste el Host y
   `rootless_routes.py` no tiene nada que publicar. El check de ruta sin puente es
   imposible hoy.

Decisión del usuario: **A + D**. El NAT lo aplica el **lado host privilegiado**; el dominio
se crea y se creará **mediante la API del plugin `domains`**, con su migración y
compatibilidad con el campo legacy `apps_applications.domain` **hasta que se decida
arbitrariamente su desaparición** (sin fecha autocumplida).

## WHAT

**El tráfico de salida de cada celda se materializa desde el host como root dentro del
netns de la celda (sin reglas iptables en el host), y el Host de una app rootless es
propiedad del plugin `domains`,PUBLICADO vía contrato, con backfill legacy y fallback
temporal mientras el campo histórico siga existiendo.**

## SCOPE

### A. NAT desde el host (no desde la unidad de usuario)

- `scripts/tenant_cell/executor.py`: **eliminar** `ExecStartPost`/`ExecStopPost` con
  `nsenter` de las unidades systemd (son los que dan EPERM). Conservar `--iptables=false`
  y `--ip6tables=false`.
- `scripts/tenant_cell/network.py`: conservar `egress_subnet()`, `masquerade_argv()` y el
  port-driver `builtin`; exponer un helper que, dado el PID de dockerd de la celda,
  construya el argv `nsenter -t <pid> -n iptables -t nat -C/-A/-D POSTROUTING -s <subnet>
  -j MASQUERADE`.
- `scripts/tenant_cell/cells.py`: en el aprovisionamiento (root), resolver el PID principal
  de dockerd de la celda y aplicar la regla **dentro de su netns** de forma idempotente; en
  el desaprovisionamiento, revertirla. Reintentar si el daemon aún no está listo; fallar
  explícitamente si no se puede.
- `scripts/tenant_cell/host_agent.py`: exponer la operación como capacidad UDS (con HMAC,
  `SO_PEERCRED` y el gate `SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS=1` en el proceso host) para
  observar/forzar el estado del NAT por slug.
- **Ninguna regla iptables en el netns del host**; `--iptables=false` sigue vigente.

### D. Dominio propiedad de `domains` + migración + legacy

- **Contrato nuevo** `vendor/systutor-core/src/systutor/contracts/app_hosts.py`:
  `AppHost(site_id, application_id, service, domain, https)`,
  `register_app_host_provider(app, name, provider)`,
  `list_app_hosts(app, db, tenant_id, application_id=None)`,
  `resolve_app_host(app, db, tenant_id, application_id, service)`. Estilo de los contratos
  existentes (`domain_ownership`, `site_domain_publisher`). Sin sockets ni endpoints.
- **Plugin `domains`**:
  - Modelo `DomainAppHost` (tabla `domains_app_hosts`: `tenant_id`, `application_id`,
    `service`, `domain`, `https`, timestamps), con unique `(tenant_id, application_id,
    service)` y `domain` único.
  - **Migración `005_rootless_app_hosts.py`** ( patrón `revision`/`upgrade(db)`/
    `downgrade(db)`, ejecutada por el runtime migrador de plugins; **nunca Alembic CLI**):
    crea la tabla y hace **backfill** desde `apps_applications.domain` donde no sea NULL,
    usando `ingress_service` para derivar el `service`. `downgrade` solo elimina la tabla.
  - `service.py`: `add_app_host` / `remove_app_host` / `list_app_hosts` validando tenencia
    con `resolve_site` (`site_id = f"{application_id}:{service}"`) y reclamando el dominio
    con `claim_domain` / `domain_owner` del contrato `domain_namespace`.
  - `router.py`: endpoints públicos `POST/GET/DELETE /api/v1/plugins/domains/app-hosts`
    con permisos `domains.domains.manage|read`, scope por tenant (plataforma ve todo).
  - `register.py`: registra el provider de `app_hosts` y emite el evento existente
    `domains.domain.added` con el `site_id` correspondiente.
- **Plugin `apps`**:
  - `rootless_routes.py`: `_domains()` pasa a leer el **contrato `app_hosts`** primero y, si
    no hay fila, cae al campo legacy `Application.domain` (**compatibilidad legacy**).
  - `register.py` (`resolve_apps_sites`): mismo orden — contrato primero, legacy después.
  - Un manejador del evento `domains.domain.added` llama a `RootlessRoutes.refresh` para el
    tenant/application del `site_id`, sin acoplarse al modelo de `domains`.
  - `catalog.py` **no cambia**: las apps nuevas siguen sin fijar `domain` desde Apps.

### Compatibilidad legacy ( explícita )

- Mientras `apps_applications.domain` siga existiendo, las lecturas funcionan con ambos
  orígenes; el nuevo es preferente. La migración ya copia los valores antiguos.
- Se documenta en el contrato y en el README de `domains` que el fallback legacy se
  eliminará **cuando se decida arbitrariamente**, no por un automatismo ni una fecha.

## OUT OF SCOPE

- Cambiar `catalog.py` ni hacer que Apps vuelva a persisting `domain` (se mantiene la
  decisión «Ingress belongs to Dominios»).
- Quitar los `audit deny` de AppArmor, volver a añadir hardeners (0109-R2 cerrado) ni
  tocar `scripts/tenant_cell/apparmor.py`.
- Gaps de entorno `0109R-5` (dramatiq) y `0109R-6` (GitHub tenant-scoped).
- Hosting (0110), correo (0111), retirada de hardeners de app (0112), producción.

## CONTRACT

1. Provisionar una celda deja el daemon `running` y `NET_OK` desde dentro, con la regla
   MASQUERADE visible **solo en el netns de la celda** y ninguna regla nueva en el host.
2. `POST /api/v1/plugins/domains/app-hosts` con `{application_id, service, domain}` devuelve
   201, reclama el dominio para el tenant y registra el `AppHost`.
3. `rootless_routes.refresh` publica el `Host` del `AppHost` por `RootlessRoutePublisher`
   (0104/0106), sin puente TCP; HTTP 200 del editor por ese dominio.
4. Una app con `apps_applications.domain` histórico y sin fila en `domains_app_hosts`
   sigue publicando su ruta (fallback legacy); tras la migración 005, la fila nueva gana.
5. Downgrade de la migración 005 elimina solo `domains_app_hosts`; legacy intacto.
6. Rollback por app vuelve a la ruta/runtime previos y conserva el contenedor rootful.

## INVARIANTS

```yaml
invariants:
  - "El NAT se aplica desde el host root dentro del netns de la celda: nunca iptables en el netns del host."
  - "--iptables=false y --ip6tables=false no cambian; las 8 audit deny de Core siguen intactas."
  - "El Host de una app rootless es propiedad de domains: apps solo lo consume por contrato."
  - "catalog.py no persiste domain: la creacion de apps sigue sin publicar rutas automaticas desde Apps."
  - "La migracion 005 es aditiva y reversible; usa el runtime migrador, nunca Alembic CLI manual."
  - "El fallback a apps_applications.domain es temporal y se eliminara solo por decision arbitraria."
  - "Un tenant no puede reclamar dominio de otro; core.platform.admin ve todos."
  - "SPANEL_TENANTS_ROOTLESS=false no reescribe runtime ya registrado (0107)."
  - "Sin puentes TCP temporales ni MASQUERADE manuales en el E2E."
  - "Sin produccion; Celda/dominio desechables se eliminan al final."
```

## VERIFICATION

```bash
python3 -m pytest scripts/tests/test_tenant_cell_provision.py scripts/tests/test_tenant_cell_plan.py -q
PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/domains/backend/tests/test_app_hosts.py -q
PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/apps/backend/tests/test_rootless_routes.py vendor/systutor-core/plugins/apps/backend/tests/test_rootless_worker.py -q
ruff check vendor/systutor-core/src/systutor/contracts/app_hosts.py scripts/tenant_cell/network.py scripts/tenant_cell/cells.py scripts/tenant_cell/host_agent.py scripts/tenant_cell/executor.py vendor/systutor-core/plugins/domains/backend/models.py vendor/systutor-core/plugins/domains/backend/schemas.py vendor/systutor-core/plugins/domains/backend/service.py vendor/systutor-core/plugins/domains/backend/router.py vendor/systutor-core/plugins/domains/backend/register.py vendor/systutor-core/plugins/domains/migrations/005_rootless_app_hosts.py vendor/systutor-core/plugins/domains/backend/tests/test_app_hosts.py vendor/systutor-core/plugins/apps/backend/rootless_routes.py vendor/systutor-core/plugins/apps/backend/register.py vendor/systutor-core/plugins/apps/backend/tests/test_rootless_routes.py
```

E2E black-box final: `artifacts/0109-r4-host-nat-and-domains-owned-hosts-e2e.json` con los
4 checks de 0109-R3 (NAT sin parche, 2 GB desde el inicio, ruta publicada sin puente,
rollback real), `delta_denied: 0`, Core intacto y `cleanup_verified: true`.

## ROLLBACK

- NAT: helper de host idempotente; revertir en deprovision; sin cambios en el host.
- Dominio: `DELETE /app-hosts` + `downgrade` de 005; el campo legacy queda intacto.
- Publicación: el publicador retira el documento `spanel-*.yml`; Traefik no se reinicia.
- Rollback por app: ya implementado en 0109; aquí solo se ejerce.

## Change Surface

```yaml
change_surface:
  allowed:
    - vendor/systutor-core/src/systutor/contracts/app_hosts.py
    - scripts/tenant_cell/network.py
    - scripts/tenant_cell/executor.py
    - scripts/tenant_cell/cells.py
    - scripts/tenant_cell/host_agent.py
    - scripts/tests/test_tenant_cell_provision.py
    - vendor/systutor-core/plugins/domains/backend/models.py
    - vendor/systutor-core/plugins/domains/backend/schemas.py
    - vendor/systutor-core/plugins/domains/backend/service.py
    - vendor/systutor-core/plugins/domains/backend/router.py
    - vendor/systutor-core/plugins/domains/backend/register.py
    - vendor/systutor-core/plugins/domains/migrations/005_rootless_app_hosts.py
    - vendor/systutor-core/plugins/domains/backend/tests/test_app_hosts.py
    - vendor/systutor-core/plugins/domains/README.md
    - vendor/systutor-core/src/systutor/contracts/README.md
    - vendor/systutor-core/plugins/apps/backend/rootless_routes.py
    - vendor/systutor-core/plugins/apps/backend/register.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_rootless_routes.py
    - artifacts/0109-r4-host-nat-and-domains-owned-hosts-e2e.json
  prohibited:
    - vendor/systutor-core/plugins/apps/backend/catalog.py
    - vendor/systutor-core/plugins/apps/backend/models.py
    - vendor/systutor-core/plugins/tenant/**
    - vendor/systutor-core/plugins/hosting/**
    - vendor/systutor-core/plugins/mail/**
    - scripts/tenant_cell/apparmor.py
    - scripts/tenant_cell/relay.py
    - vendor/systutor-core/src/systutor/kernel/**
    - docker-compose.yml
    - /opt/stacks/**
```

## Traceability

- Requirement: corregir los 2 gaps del E2E R3 (NAT EPERM y dominio descartado) bajo la
  decisión A + D del usuario, con migración y compatibilidad legacy.
- owner: lucas
- approver: lucas
- Commit: (pendiente; NO ejecutada)
- Evidence: `artifacts/0109-r3-cell-plumbing-and-cutover-e2e.json` (FAIL 0/4).
- Deployment: laboratorio `spanel.lab`; sin producción.

## Definition of Done

- [ ] Objective satisfied (4 checks del E2E en PASS sin parches manuales)
- [ ] Contract satisfied
- [ ] Invariants preserved (Core, contrato y legacy)
- [ ] Verification passed
- [ ] Rollback honest (downgrade 005 ejecutado en VERIFICATION)
- [ ] E2E black-box PASS + limpieza verificada
