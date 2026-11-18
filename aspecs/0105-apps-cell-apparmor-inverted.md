# A.SPEC 0105 — Inverted AppArmor profile and seccomp for rootless cells

> `risk: high` — cambia el perfil de confinamiento de todas las celdas y añade
> un filtro seccomp. Aunque no toca producción, un perfil mal formado puede
> impedir que arranquen Apps reales. Requiere `approver:`.

## WHY

El E2E de A.SPEC 0104 demostró que el perfil generado por
`scripts/tenant_cell/apparmor.py` es un allowlist de paths demasiado estrecho:
con imágenes reales aparecieron denegaciones para `docker-proxy`,
`/docker-entrypoint.sh`, `/usr/sbin/nginx`, cachés/logs propios,
`/proc/<pid>/comm`, sysctls de red y `cgroup.type`. En el laboratorio hubo que
parchear los perfiles **a mano** para que nginx y la SPA de editores funcionaran;
toda celda nueva vuelve a nacer con el mismo problema (GAP-2).

Además, en este daemon rootless AppArmor **no se aplica por contenedor**:
`docker info` reporta `seccomp`, `rootless`, `cgroupns` pero no `apparmor`. El
perfil se engancha al daemon con `aa-exec` y lo heredan todos sus hijos, así que
un allowlist estrecho tendría que cubrir simultáneamente el daemon (paths del
host) y cualquier imagen del tenant (paths de su propio rootfs). Eso no escala.

La solución es invertir el modelo: **permitir ampliamente el filesystem propio de
la celda/imagen y ser estricto solo en las interfaces del host y del kernel**
(`/proc`, `/sys`, cgroups, devices, capabilities, dbus, mount/ptrace). Para la
reducción real de syscalls se usa **seccomp**, que el daemon rootless ya soporta.

## WHAT

Generar un perfil AppArmor "invertido" y un perfil seccomp por celda, instalarlos
con el daemon rootless y demostrar con una matriz de imágenes reales que no
aparecen `DENIED` y que los paths/host/buses prohibidos siguen vedados.

## SCOPE

- `apparmor.py`: reemplazar el allowlist de ejecutables y paths por un perfil
  con filesystem propio amplio (`/** r/ix`, `rwkl` acotado a los árboles de la
  celda y de la imagen) y reglas estrictas de host/kernel.
- `apparmor.py`: mantener `profile_name()`, `render_profile()` y
  `profile_hash()`; el hash cambiará de forma determinista (esperado en
  `status`/`verify`).
- `cell-seccomp.json` (nuevo): perfil seccomp con `defaultAction:
  SCMP_ACT_ERRNO`, allowlist de syscalls compatibles con rootless Docker y
  denegación explícita de las peligrosas para userns.
- `executor.py`: copiar el perfil seccomp al data-root de la celda y referenciarlo
  desde `daemon.json` (`seccomp-profile`), junto al `exec-opts` existente.
- Tests: perfil invertido (paths permitidos/denegados, capabilities, dbus de
  usuario, sin bus del sistema, sin `unconfined`, sin `complain`), validez del
  JSON seccomp, hash determinista, y matriz de render para nginx/php/MariaDB/node/gitea.
- E2E posterior en lab: matriz de imágenes reales y verificación de `DENIED`.
  **Criterio obligatorio**: instalar **Gitea** dentro de una celda rootless
  desechable (sandbox con usuario, userns, AppArmor, seccomp, nft y socket
  propios), con su base de datos SQLite, y publicar su link a través del relay
  de A.SPEC 0104. La prueba es que el perfil invertido permita una app real con
  entrypoint, escritura de datadir y sesiones sin parcheos manuales.

## OUT OF SCOPE

- Tocar WordPress, MariaDB, phpMyAdmin, `cell-g`, `cell-h` ni producción.
- Poner perfiles en `complain` ni `unconfined`, ni relajar A.SPEC 0086/0087.
- Habilitar el bus del sistema (`/run/systemd/private`) ni `dbus bus=system`.
- Cambiar el relay de A.SPEC 0104, el plan de A.SPEC 0100/0101 ni el agente de
  0102.
- Mover Traefik, cambiar su red ni reiniciarlo.
- Cambiar `runc`, `containerd` ni los flags `--rootless` (GAP-1 es otro asunto).
- Escribir `/etc/**` o `/run/**` desde el GENERATOR.

## CONTRACT

**Precondiciones**: AppArmor disponible en el kernel, perfil cargado por
`aa-exec`, directorio de la celda propiedad del uid del tenant.

**Postcondiciones**:

- El perfil permite ejecutar bins y escribir cachés/logs/config **dentro del
  rootfs de la celda o de la imagen**, sin enumerar uno por uno.
- El perfil **deniega explícitamente**: `/var/run/docker.sock`, `/run/secrets/**`,
  `/run/systemd/private`, `dbus bus=system`, los árboles
  `/var/lib/spanel/cells/<otro-slug>/**`, `/proc/kcore`, `/proc/[0-9]*/mem`,
  `/sys/kernel/**` en escritura y dispositivos de bloque del host.
- El único bus permitido sigue siendo el de usuario (`bus=session` en sintaxis
  AppArmor, `/run/user/<uid>/bus`).
- `mount`/`pivot_root` siguen restringidos a los árboles de la celda; no se
  añade un comodín que permita montar sobre el host.
- El seccomp profile es JSON válido, con `defaultAction: SCMP_ACT_ERRNO` y una
  allowlist que incluye los syscalls usados por rootlesskit, runc, nginx,
  php-fpm, MariaDB, node y Gitea; `clone3`/`userfaultfd` se tratan explícitamente.
- `daemon.json` de cada celda referencia el seccomp profile copiado a su
  data-root, sin mounts nuevos ni sockets Docker adicionales.
- `profile_hash()` sigue siendo estable para un mismo slug.

## INVARIANTS

```yaml
invariants:
  - "El perfil no usa complain ni unconfined, y no transiciona a perfiles ajenos a la celda."
  - "El rootfs propio de la celda/imagen puede ejecutar y escribir sin listas de paths por imagen."
  - "Los paths del host (docker.sock, secrets, systemd private, otras celdas) siguen denegados explicitamente."
  - "Solo se permite el bus de usuario; el bus del sistema permanece denegado."
  - "Mount, ptrace y capabilities siguen limitados a la celda y a lo estrictamente necesario."
  - "seccomp usa defaultAction SCMP_ACT_ERRNO: fail-closed, nunca SCMP_ACT_ALLOW global."
  - "No se habilita dbus system ni se relaja el aislamiento para arreglar OwnerUID (GAP-1)."
  - "profile_name, render_profile y profile_hash conservan su contrato y el hash es determinista."
  - "No se tocan cell-g, cell-h, Traefik, phpMyAdmin, MariaDB, WordPress ni produccion."
  - "No se modifica el planeador, el plan materializer ni el relay de A.SPEC 0104."
```

## VERIFICATION

```bash
PYTHONPATH=vendor/systutor-core:. python3 -m pytest scripts/tests/test_tenant_cell_apparmor.py scripts/tests/test_tenant_cell_provision.py scripts/tests/test_tenant_cell_doctor.py -q
PYTHONPATH=vendor/systutor-core:. python3 -m pytest scripts/tests/test_tenant_cell_relay.py scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_provision.py scripts/tests/test_tenant_cell_apparmor.py -q
ruff check scripts/tenant_cell scripts/tests/test_tenant_cell_apparmor.py
python3 -c "import json; p=json.load(open('scripts/tenant_cell/deploy/cell-seccomp.json')); assert p['defaultAction']=='SCMP_ACT_ERRNO'; print(p['defaultAction'], len(p['syscalls']))"
```

La evidencia E2E se genera en el lab en `artifacts/0105-inverted-apparmor-e2e.json`: matriz de nginx, SPA de editores, php-fpm, MariaDB mínima y **Gitea en SQLite dentro de una celda sandbox** en celdas desechables, con `aa-status`, salida de `dmesg|grep DENIED` y links de cualquiera que sirva HTTP. El link de Gitea debe responder y mostrar la UI de instalación o el login; si aparece `DENIED` o Gitea no arranca sin parche manual, la ronda es FAIL.

## ROLLBACK

Revertir `apparmor.py` y `executor.py` restaura el perfil anterior; las celdas
ya aprovisionadas necesitan `repair` para recargar el perfil. El seccomp profile
se elimina del `daemon.json` y se borra del data-root. No hay cambios de esquema
ni datos; los links de 0104 no se tocan.

## Change Surface

```yaml
change_surface:
  allowed:
    - scripts/tenant_cell/apparmor.py
    - scripts/tenant_cell/executor.py
    - scripts/tenant_cell/deploy/cell-seccomp.json
    - scripts/tests/test_tenant_cell_apparmor.py
    - scripts/tests/test_tenant_cell_provision.py
    - scripts/tests/test_tenant_cell_doctor.py
  prohibited:
    - vendor/systutor-core/**
    - apps/web/**
    - scripts/tenant_cell/relay.py
    - scripts/tenant_cell/cli.py
    - scripts/tenant_cell/host_agent.py
    - scripts/tenant_cell/plans.py
    - scripts/tenant_cell/materializer.py
    - scripts/e2e_*.py
    - /etc/**
    - /run/**
    - docker-compose.yml
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - contenido del perfil AppArmor de cada celda y su hash
    - seccomp profile copiado al data-root y referenciado por daemon.json
  indirect:
    - arranque de imagenes reales dentro de celdas
    - salida de aa-status y audit DENIED
  must_not_affect:
    - relay y links vivos de A.SPEC 0104
    - plan de A.SPEC 0100/0101 y agente de 0102
    - cell-g y cell-h
    - Traefik / phpMyAdmin / MariaDB / WordPress
    - produccion
```

## Composition

```yaml
composition:
  requires_aspecs:
    - "0096-apps-rootless-tenant-cell"
    - "0104-apps-rootless-edge-routes"
  must_compose_with:
    - "0104-apps-rootless-edge-routes"
  systemic_invariants:
    - "El perfil se hereda del daemon via aa-exec; no hay transiciones a unconfined."
    - "El 503 fail-closed de la API de planes no cambia."
    - "Sin plan, _override sigue usando 512m/1.0/256."
  composition_checks:
    - "PYTHONPATH=vendor/systutor-core:. python3 -m pytest scripts/tests/test_tenant_cell_apparmor.py scripts/tests/test_tenant_cell_relay.py -q"
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: one coherent responsibility and one main reason to change
  entrypoints_must_stay_thin: true
  review_threshold_lines: 900
  extraction_threshold_lines: 1400
  preferred_new_logic_locations:
    - scripts/tenant_cell/apparmor.py
    - scripts/tenant_cell/deploy/cell-seccomp.json
```

El tamaño en líneas no es bloqueante; gobiernan la corrección y la VERIFICATION.

## Traceability

- Requirement: eliminar GAP-2 invirtiendo el modelo de AppArmor y añadiendo seccomp.
- Evidence: `artifacts/0104-rootless-edge-route-e2e.json` (parcheos manuales de perfil), `artifacts/0105-gap1-rootless-detection-experiment.json`.
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
- [ ] Gitea instalado y funcionando dentro de una celda sandbox sin parcheos manuales de AppArmor
- [ ] Link de Gitea verificado a través del relay y sin DENIED en audit
