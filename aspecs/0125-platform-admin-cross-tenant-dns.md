# A.SPEC 0125 — Plataforma administra DNS y Cloudflare de cualquier tenant

## Problema

Hoy `core.platform.admin` puede **leer** la lista global de dominios
(`GET /domains?scope=all`), pero no administrar los recursos DNS de esos
dominios:

- `DnsService._owned()` filtra siempre por `tenant_context.current_tenant_id`.
  Un administrador de plataforma recibe `404` al intentar leer o modificar una
  zona PowerDNS de otro tenant.
- `CloudflareService._zone_access()` y los métodos de records resuelven
  credenciales y propiedad usando el tenant activo. Una zona Cloudflare de otro
  tenant tampoco se puede administrar.
- La vista global del panel muestra los dominios ajenos, pero deshabilita
  DNS/Cloudflare para ellos (`owned=false`).

Se quiere que un administrador de plataforma pueda, **sin cambiar el tenant
activo**, crear, modificar y borrar zonas y registros DNS/Cloudflare de
cualquier tenant. La propiedad de una zona **no se mueve**: solo se administra
su contenido.

## Decisiones

1. El tenant objetivo se elige desde la fila de la vista global. El backend
   recibe un `tenant_id` explícito solo cuando hace falta crear algo nuevo; para
   operar sobre una zona existente basta con la zona, y la propiedad se resuelve
   por la tabla de ownership.
2. Solo `core.platform.admin` puede salir del tenant activo. Un tenant normal
   conserva exactamente el comportamiento actual.
3. No se permite reasignar propiedad entre tenants en esta spec. Mover una zona
   de tenant requerirá una operación aparte, auditada y con confirmación.
4. La auditoría de una operación cross-tenant registra:
   - `tenant_id` = tenant dueño del recurso;
   - `actor_user_id` = administrador de plataforma;
   - `details.via_platform = true` cuando el tenant no era el activo.
5. PowerDNS y Cloudflare se tratan igual: la plataforma puede administrar
   ambos.

## Contrato backend

### 1. Resolución del tenant efectivo

Nuevo helper en `plugins/domains/backend/`:

```python
def resolve_effective_tenant(
    context: TenantContext,
    target_tenant_id: str | None,
) -> str:
    if target_tenant_id and target_tenant_id != context.current_tenant_id:
        if not context.is_platform:
            raise AppError(
                "only the platform administrator can target another tenant",
                status_code=403,
                code="domains.platform_required",
            )
        return target_tenant_id
    return context.current_tenant_id
```

Y una variante para auditar con el tenant dueño:

```python
def context_for_tenant(context: TenantContext, tenant_id: str) -> TenantContext:
    return replace(context, current_tenant_id=tenant_id, current_branch_id=None)
```

`current_branch_id` se limpia al operar en otro tenant porque la rama activa
pertenece al tenant original.

### 2. PowerDNS (`dns_router.py` / `dns/service.py`)

- `DnsService._owned()`:
  - primero busca la propiedad con el tenant activo;
  - si no existe y `context.is_platform`, busca la zona en cualquier tenant
    (`get_ownership_any_tenant`);
  - si la encuentra, devuelve la fila y las operaciones usan
    `context_for_tenant(context, row.tenant_id)` para auditoría/eventos.
- `list_zones(context, scope="tenant")`:
  - `scope=tenant`: sin cambios.
  - `scope=all`: solo plataforma; devuelve todas las filas de
    `domains_dns_zones` e incluye `tenant_id` en cada `ZoneItem`.
- `create_zone(zone, context, target_tenant_id=None)`:
  - resuelve el tenant efectivo;
  - valida que el dominio esté registrado en ese tenant
    (`list_tenant_domains(app, db, effective_tenant_id)`), no en el activo;
  - crea la propiedad con `tenant_id=effective_tenant_id`;
  - audita con ese tenant y `via_platform` si aplica.
- `resolve(domain, context, target_tenant_id=None)`:
  - si hay `target_tenant_id`, busca dentro de las zonas de ese tenant;
  - si no, busca primero en el activo y, para plataforma, en todos; devuelve
    `tenant_id` en la respuesta.
- `get_zone`, `delete_zone`, `plan_rrsets`, `apply_rrsets`, `delete_rrset`,
  `import`, `export`: sin cambios de firma; `_owned()` ya resuelve la
  propiedad global para plataforma. La auditoría debe usar el tenant dueño.
- Router:
  - `GET /dns/zones?scope=tenant|all`
  - `POST /dns/zones` acepta `tenant_id` opcional en el body; solo plataforma.
  - `GET /dns/resolve?tenant_id=...` opcional.
  - El resto de rutas no cambia; el `zone_name` es único globalmente.
- `ZoneItem` añade `tenant_id: str | None`.

### 3. Cloudflare (`cloudflare_router.py` / `cloudflare/service.py`)

- Helper `_zone_tenant(context, zone_id)`:
  - tenant normal: `self._tenant_id(context)`;
  - plataforma: resuelve `CloudflareZoneOwnership.tenant_id` por `zone_id`; si
    no hay fila, `404 zone_not_found`.
- `records_for_tenant`, `create_record`, `update_record`, `delete_record` y
  `_zone_access` usan `_zone_tenant()` cuando el contexto es plataforma. En
  modo `single` las credenciales siguen saliendo de la conexión host; en modo
  `tenant` salen de la conexión del tenant dueño.
- `zones_for_tenant(context, scope="tenant")`:
  - `scope=tenant`: sin cambios;
  - `scope=all` solo plataforma y solo en modo `single`: devuelve
    `host_zones(include_unowned=False)` con `tenant_id` incluido.
  - En modo `tenant`, `scope=all` responde `409
    domains.dns.cloudflare.scope_all_requires_single` (evita fan-out de
    credenciales); la UI usa el tenant activo en ese caso.
- `GET /dns/cloudflare/zones?scope=tenant|all`.
- `records` existentes (`/zones/{zone_id}/records`) no necesitan `tenant_id`:
  la propiedad de `zone_id` ya determina el tenant.
- `provision/plan|apply` aceptan `tenant_id` opcional; solo plataforma. El
  provisioner usa el tenant efectivo para validar/adoptar propiedad y auditar.
- Los endpoints host (`/host/*`) no cambian.

### 4. Auditoría y eventos

- Las acciones cross-tenant usan el tenant dueño en `record_audit` y en el
  payload del evento.
- `details` añade `"via_platform": True` cuando
  `context.current_tenant_id != effective_tenant_id`.
- No se registran tokens, secretos ni contenido de registros.

## Contrato frontend

### 1. Estado DNS global

- `DomainsPage`:
  - si `platform`, consulta `GET /dns/zones?scope=all`; si no, `scope=tenant`.
  - en modo Cloudflare `single`, consulta
    `GET /dns/cloudflare/zones?scope=all`; en `tenant` mantiene la consulta
    actual.
  - `Zones`/`CloudflareZone` incluyen `tenant_id`.
- `DomainsTable`:
  - la celda DNS de una fila se calcula con las zonas de **su tenant**:
    `longestOwnedZoneForTenant(domain, zones, item.tenant_id)`;
  - si no hay coincidencia para ese tenant, mantiene `—`;
  - una fila ajena es operable cuando `platform && canReadDns`.
- `DnsStatusCell` no cambia.

### 2. Abrir/editar DNS de otro tenant

- `DomainsTable` permite doble clic/Enter en filas ajenas cuando `platform`.
- `DnsZoneDialog` recibe `tenantId` y `platform`:
  - `getZone`, `planRrsets`, `applyRrsets`, `deleteRrset`, `deleteZone`,
    `import` y `export` siguen enviando solo `zone_name`; el backend resuelve
    el dueño.
  - `createZone` envía `tenant_id` cuando `platform` y el dominio es de otro
    tenant.
- `ZoneTab`/`RecordsTab` no cambian de contrato; solo reciben las mutaciones
  existentes.
- El botón de activar zona se muestra para plataforma aunque la fila sea de
  otro tenant; la creación se hace con el `tenant_id` de la fila.

### 3. Cloudflare

- `CloudflareDnsPanel` sigue usando `zone.id`; no necesita `tenant_id`: el
  backend deriva el dueño de la zona.
- La vista global muestra **Cloudflare** para zonas ajenas cuando el listado
  global las incluye.
- El provisionado manual desde la vista global usa el `tenant_id` de la fila
  seleccionada; si no hay fila, el tenant activo.
- En modo `tenant` (no `single`), la vista global no lista Cloudflare de otros
  tenants; se mantiene el comportamiento actual y el usuario puede cambiar de
  tenant.

## Seguridad e invariantes

1. Ningún usuario sin `core.platform.admin` puede pasar un `tenant_id` distinto
   al activo; recibe `403 domains.platform_required`.
2. `scope=all` siempre exige `is_platform`.
3. La plataforma no puede leer ni escribir una zona inexistente en ownership;
   recibe `404` sin revelar si existe en otro tenant.
4. La plataforma no puede reasignar propiedad en esta spec.
5. Los tenants normales no cambian de comportamiento ni de payloads (salvo
   campos aditivos `tenant_id`).
6. Los endpoints host de Cloudflare siguen siendo `platform_only`.

## Pruebas

Backend:

- `test_dns_service.py`: plataforma lee/edita/borra una zona de otro tenant;
  tenant normal recibe 404; auditoría con tenant dueño; `create_zone` con
  `tenant_id` ajeno valida el namespace de ese tenant.
- `test_dns_router.py`: `scope=all` permitido solo a plataforma; `tenant_id`
  ajeno rechazado para tenant normal.
- `test_cloudflare_service.py` / `test_cloudflare_single_mode.py`: plataforma
  lista zonas globales en `single`, lee/crea/edita/borra records de una zona
  ajena usando host; en modo `tenant` usa la conexión del dueño.
- `test_cloudflare_router.py`: `scope=all`, `tenant_id` opcional y `403` para
  no plataforma; no filtra tokens.
- Verificar que la suite existente en modo tenant sigue pasando sin cambios de
  expectativas.

Frontend:

- `domains-dns.logic.test.ts`: `longestOwnedZoneForTenant` no cruza tenants.
- `domains-cloudflare.logic.test.ts`: visibilidad de acciones para plataforma y
  estado global.
- Test de `DomainsPage`/`DomainsTable` (o el más cercano existente): una fila
  ajena es operable para plataforma y muestra el estado DNS correcto.

Comandos:

```bash
python3 -m pytest vendor/systutor-core/plugins/domains/backend/tests -q
npm --prefix apps/web test
node apps/web/node_modules/typescript/bin/tsc --noEmit -p apps/web/tsconfig.json
ruff check .
python3 -m pyright vendor/systutor-core/plugins/domains/backend
```

## Fuera de alcance

- Reasignar la propiedad de una zona/dominio entre tenants.
- Cambiar el tenant activo desde el backend.
- Administrar conexiones OAuth de Cloudflare de otros tenants (eso sigue siendo
  del tenant dueño o del host en modo `single`).
- PowerDNS/Cloudflare fan-out global en modo `tenant` para Cloudflare.

## Notas

- No hacer commit hasta que el revisor lo indique si se implementa en modo
  generador.
- No desplegar directamente a producción sin pruebas en `spanel.lab`.
- Mantener la regla de migraciones de `AGENTS.md`; esta spec no requiere
  cambios de esquema.
