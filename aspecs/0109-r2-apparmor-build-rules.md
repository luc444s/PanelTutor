# A.SPEC 0109-R2 — Simplify the cell profile by removing obsolete hardeners

> `risk: high` — relaja un perfil de confinamiento; exige `approver:`. No añade reglas:
> **consolida y quita** las que ya no cumplen ningún propósito bajo el modelo de confianza
> por tenant.

## WHY

El black-box de 0109-R pasó 9/9 pero el build real solo funcionó con un perfil desechable
parcheado a mano (gaps `0109R-3`/`-4`). La reacción natural —añadir ~10 reglas estrechas
para `apt`, entrypoints y remounts— fue **rechazada**: bajo el modelo de este sistema el
**tenant es la unidad de confianza**, no cada contenedor. Meterse en el daemon rootless del
propio tenant está permitido por diseño; el sandbox existe para aislar tenants entre sí y
proteger Core, no para separar apps dentro del mismo tenant.

Por tanto el perfil tiene hardeners que **ya no compran aislamiento** y solo rompen builds:
el calificador `owner` en la grant amplia del rootfs y una larga lista de excepciones por
ruta de imagen que existían únicamente para compensar ese `owner`. Se quitan, no se
sustituyen por reglas nuevas.

### Decisión de confianza (registro oficial)

> **El límite de confianza es el tenant.** El acceso entre contenedores del mismo tenant
> está permitido por diseño, incluido su daemon Docker rootless interno. El sandbox
> protege: (a) frente a otros tenants — userns, mount namespace y tabla nft con `skuid` —
> y (b) frente a la infraestructura Core — los `audit deny` de host/kernel. Quitar esos
> `audit deny` sí estaría fuera de alcance.

## WHAT

**El perfil se simplifica eliminando el `owner` de la grant amplia y las listas por imagen
que lo compensaban; un build real del fixture arranca con delta de DENIED = 0 desde el
primer arranque, y los denials de Core y el aislamiento entre tenants siguen intactos.**

## SCOPE

### 1. Quitar el `owner` de la grant amplia (`scripts/tenant_cell/apparmor.py`)

Reemplazar:

```apparmor
  owner /** rix,
  owner /** rwklix,
  owner /** m,
```

por:

```apparmor
  # Trust boundary is the tenant, not the uid: other tenants are kept out by
  # their own userns/mountns and the per-cell nft skuid table, not by AppArmor
  # ownership. This single grant replaces the per-image path lists below.
  /** rix,
  /** rwklix,
  /** m,
```

### 2. Eliminar reglas que se vuelven redundantes

Borrar del template los bloques que solo existían para compensar `owner`:
- la grant de binarios/librerías root-only de las líneas 37-41 (`/{{bin,sbin,usr,...}}/** rix`, `... m`, `/run/user/[0-9]*/** rix`), ya cubierta por `/** rix` y `/** m`;
- la lista de datadirs por imagen (líneas 95-120: `/data/`, `/var/lib/mysql/`, `/var/cache/`, `/var/log/`, `/var/www/`, `/app/`, `/docker-entrypoint-initdb.d/`, `/run/mysqld/`, `/etc/mysql/`, `/var/lib/postgresql/`, `/home/`), ya cubierta por `/** rwklix`.

**No se toca** `owner /var/lib/spanel/cells/{slug}/docker.sock rw`: el socket interno
sigue permitido explícitamente, coherente con la decisión de confianza.

### 3. Consolidar remounts (modificar, no añadir)

Sustituir la serie de reglas estrechas de `mount`/`remount` de las líneas ~215-221 por
**una sola regla equivalente pero más amplia**, siempre dentro del namespace de la celda;
la forma exacta se deriva de las líneas `DENIED` capturadas en el lab antes del cambio.
Cada regla eliminada y su sustituta se documentan en el artefacto.

**Corrección obligatoria (E2E 0109-R2, FAIL):** AppArmor **no empareja** un `remount`
(`flags="ro, remount, rbind"`, sin `srcname`) con una regla de dos paths
(`mount ... src -> dst`). Por tanto la consolidación **debe conservar** la regla de un
solo path que ya existía:

```apparmor
  remount options in (ro, rw, nosuid, nodev, noexec, bind, rbind) /var/lib/spanel/cells/{slug}/**,
```

y las variantes `mount options=(ro, remount, rbind) ...` / `(ro, nosuid, nodev, noexec,
remount, rbind) ...` que también existían. **Restaurarlas no es añadir reglas nuevas**: son
reglas preexistentes que la consolidación eliminó por error. La consolidación solo es válida
si el build real sigue pasando; si no, se revierte a las reglas originales y se documenta
como «consolidación no equivalente, revertida».

### 4. Lo que NO se toca (frontera Core)

Las ocho `audit deny` finales quedan **idénticas**: `/var/run/docker.sock`,
`/run/secrets/**`, `/run/systemd/private`, `dbus bus=system`, `/proc/kcore`,
`/proc/[0-9]*/mem`, `/sys/kernel/**` y `/dev/{sd,vd,hd,nvme}*`. Tampoco se cambian
capabilities, reglas de red ni la tabla nft por celda.

### 5. Tests y evidencia

- `scripts/tests/test_tenant_cell_apparmor.py`: afirmar que la grant amplia **ya no lleva
  `owner`**, que los bloques redundantes desaparecieron, que las ocho denials siguen
  presentes y que el perfil no contiene rutas de otras celdas.
- E2E laboratorio: build real del fixture, `aa-status` + `dmesg` antes/después, artefacto
  `artifacts/0109-r2-apparmor-build-e2e.json` con `delta_denied: 0` desde el primer arranque,
  build `succeeded`, HTTP 200 y aislamiento Core/otro tenant comprobado.

## OUT OF SCOPE

- Añadir reglas para `apt`, `/docker-entrypoint.sh`, `/docker-entrypoint.d/` ni remounts
  puntuales: quedan cubiertas por la grant amplia y la consolidación.
- Bloquear el socket interno de la celda ni crear una celda de build separada (decisión de
  confianza por tenant).
- Quitar los `audit deny` de Core; cambiar capabilities o red.
- Gaps `0109R-2` (NAT), `-5` (dramatiq), `-6` (GitHub), `-7` (port-driver): specs aparte.
- Hosting (0110), correo (0111), retirada de hardeners anti-root de app (0112), producción.

## CONTRACT

1. `render_profile(slug)` contiene `/** rix`, `/** rwklix`, `/** m` y **no** contiene
   `owner /**`.
2. Los bloques por imagen de las líneas 37-41 y 95-120 ya no están.
3. Las ocho `audit deny` siguen presentes con la misma forma.
4. Build real del fixture en celda desechable → `succeeded`, contenedor `running`, HTTP 200,
   `delta_denied: 0` desde el primer arranque.
5. Otro tenant y los seis componentes Core siguen intactos (PID/hash).

## INVARIANTS

```yaml
invariants:
  - "El tenant es la unidad de confianza: intra-tenant (incluido su docker.sock) permitido por diseno."
  - "Las ocho audit deny de host/kernel no se debilitan ni se eliminan."
  - "El aislamiento entre tenants no depende de AppArmor owner: depende de userns, mountns y nft skuid."
  - "No se anaden reglas nuevas: cada cambio es una eliminacion o una consolidation de reglas existentes."
  - "No se cambian capabilities ni reglas de red."
  - "El build se verifica con imagenes reales, nunca sembradas a mano."
  - "Sin produccion; la celda desechable se elimina al final."
```

## VERIFICATION

```bash
python3 -m pytest scripts/tests/test_tenant_cell_apparmor.py -q
python3 -m pytest scripts/tests/test_tenant_cell_provision.py scripts/tests/test_tenant_cell_plan.py -q
ruff check scripts/tenant_cell/apparmor.py scripts/tests/test_tenant_cell_apparmor.py
```

E2E laboratorio: `artifacts/0109-r2-apparmor-build-e2e.json` con `result: PASS`,
`delta_denied: 0` desde el primer arranque, mapeo de reglas eliminadas/consolidadas y
limpieza verificada.

## ROLLBACK

- Restaurar el template anterior desde git; `profile_hash` vuelve a su valor de 0105.
- Los perfiles instalados se regeneran con `spanel-tenant apparmor install` y se validan
  con `apparmor_verify`. Sin migración de esquema.

## Change Surface

```yaml
change_surface:
  allowed:
    - scripts/tenant_cell/apparmor.py
    - scripts/tests/test_tenant_cell_apparmor.py
    - scripts/tests/test_tenant_cell_provision.py
    - artifacts/0109-r2-apparmor-build-e2e.json
  prohibited:
    - scripts/tenant_cell/executor.py
    - scripts/tenant_cell/network.py
    - scripts/tenant_cell/relay.py
    - vendor/systutor-core/**
    - docker-compose.yml
    - /opt/stacks/**
```

## Traceability

- Requirement: cerrar `GAP-0109R-3` y `GAP-0109R-4` **sin añadir reglas**, bajo el modelo
  de confianza por tenant decidido por el usuario.
- owner: lucas
- approver: lucas
- Commit: `2140598` (perfil simplificado, tests, spec y artefacto E2E).
- Evidence: `artifacts/0109-r2-apparmor-build-e2e.json` (**PASS 16/16**, `delta_denied: 0`
  desde el primer arranque, `cleanup_verified: true`). Baseline OLD: build rc=1 con 10 DENIED
  de `apt-get` sobre `/var/lib/apt/lists/**`; perfil reparado con grant amplia sin `owner`,
  4 reglas de remount preexistentes restauradas y 8 `audit deny` intactas: build backend y
  frontend rc=0, HTTP 200 del editor, otro tenant y Core intactos. Un gap `info`: la
  exposición pública usó configuración desechable del lab (GAP-0109R-7, spec aparte).
- Deployment: laboratorio `spanel.lab`; sin producción.

## Definition of Done

- [x] Objective satisfied (build real, 0 DENIED desde el inicio)
- [x] Contract satisfied
- [x] Invariants preserved (Core intacto, aislamiento entre tenants intacto)
- [x] Verification passed (16 + 40 tests, ruff, `apparmor_parser -Q`)
- [x] Rollback honest (perfil byte-idéntico al estado reparado; lab restaurado)
- [x] Evidence artifact PASS 16/16 + limpieza verificada
