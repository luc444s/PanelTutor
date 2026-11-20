# A.SPEC 0109-R3 — Rootless cell plumbing and cutover guarantees

> `risk: high` — toca red de celdas, límites de build y publicación de rutas; exige
> `approver:`. Unifica los 4 gaps abiertos de producto de la serie 0109 en **una** verdad.

## WHY

Tras 0109, 0109-R y 0109-R2, la celda rootless ya arranca, el build pasa con
`delta_denied: 0` y el editor responde HTTP 200. Pero el black-box final necesitó
**cuatro arreglos de laboratorio** para llegar ahí. La analogía del edificio:

1. **Rampa de salida (NAT/egress):** el `--dns` funciona pero el build no tiene salida;
   el E2E puso un MASQUERADE a mano en el netns (`GAP-0109R-2`).
2. **Portero que mide por mueble (cap 512 MB):** `MAX_APP_MEMORY` impide desplegar el
   fixture de 3 servicios con 2 GB desde el inicio; se desplegó con 1.4 GB y se elevó
   después (`GAP-0109R-1`).
3. **Interfono mudo (publicación de puerto):** rootlesskit no abrió `127.69.1.1:20068`;
   el link se expuso con un puente TCP temporal y el publicador 0104/0106 no se ejerció
   (`GAP-0109R-7` y el gap `info` de 0109-R2).
4. **Simulacro no ensayado (rollback):** el primer E2E dejó `flag_and_rollback: false`;
   el black-box final nunca restauró ruta+runtime sobre un deployment real.

## WHAT

**La celda rootless tiene salida a red, el plan agregado de 2 GB se puede aplicar desde el
primer deploy, el link se publica por el publicador del producto, y el rollback por app se
ejerce con un deployment real — todo sin parches manuales de laboratorio.**

## SCOPE

### 1. NAT de salida permanente (`scripts/tenant_cell/{network,executor}.py`)

- Materializar el MASQUERADE de `172.17.0.0/16` **dentro del netns de la celda** junto con
  el `--dns`, sin tocar iptables del host (ver decisión `--iptables=false`).
- Debe ser idempotente, auditable y revertirse al desaprovisionar la celda.
- Verificación: `wget https://registry.npmjs.org/vite` dentro de la celda → `NET_OK` **sin**
  regla añadida a mano.

### 2. Límite agregado, no por servicio (`runtime/probes.py`)

- Ajustar la validación para que `MAX_APP_MEMORY` no bloquee el reparto cuando el **plan
  agregado del tenant** lo permite: con 2 GB y 3 servicios, el deploy debe poder arrancar
  con el plan completo desde el inicio.
- Sin cambiar el reparto `tenant_plan.py` ni los defaults de los contenedores.

### 3. Publicación por el producto (`network.py`, `executor.py`, `rootless_routes.py`)

- Hacer que el port-driver de rootlesskit abra el rango `127.x.y.z:20000+` y que
  `RootlessRoutePublisher` (0104/0106) publique el `Host` cuando la app tenga `domain`
  asignado por superficie pública. Sin puentes TCP temporales.

### 4. Simulacro de rollback (tests + E2E)

- Ejercitar con un deployment real: fallo inducido → restaurar ruta previa y runtime
  registrado (0107), conservando el contenedor rootful original; verificar que con la
  bandera en `false` lo ya migrado sigue administrable.

### 5. Evidencia

- Un único artefacto `artifacts/0109-r3-cell-plumbing-and-cutover-e2e.json` con los 4
  checks y `cleanup_verified: true`.

## OUT OF SCOPE

- Quitar los `audit deny` de Core ni volver a añadir hardeners AppArmor (0109-R2 cerrado).
- Gaps de entorno `0109R-5` (dramatiq) y `0109R-6` (GitHub tenant-scoped): son de laboratorio.
- Hosting (0110), correo (0111), retirada de hardeners de app (0112), producción.

## CONTRACT

1. Build real del fixture con `NET_OK` y `rc=0` sin MASQUERADE manual.
2. Deploy de 3 servicios con `memory_bytes=2147483648` aplicado **desde el inicio**.
3. HTTP 200 del editor por dominio publicado por `RootlessRoutePublisher`, sin puente TCP.
4. Rollback real: ruta y runtime vuelven al estado previo; rootful conservado.
5. Core (Traefik, MariaDB, PMA, PowerDNS, DMS) y otros tenants intactos.

## INVARIANTS

```yaml
invariants:
  - "El NAT vive dentro del netns de la celda: nunca se instalan reglas iptables en el host (--iptables=false)."
  - "El plan agregado del tenant es la superficie de 2 GB; el reparto por servicio no cambia."
  - "La publicacion del link usa el publicador del producto, no puentes temporales del laboratorio."
  - "El rollback conserva contenedores y volumenes rootful hasta confirmar recuperacion."
  - "SPANEL_TENANTS_ROOTLESS=false no reescribe runtime ya registrado."
  - "Las 8 audit deny de Core y el aislamiento nft skuid siguen intactos."
  - "Sin produccion; toda celda/dominio desechable se elimina al final."
```

## VERIFICATION

```bash
python3 -m pytest scripts/tests/test_tenant_cell_provision.py scripts/tests/test_tenant_cell_plan.py -q
PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/apps/backend/tests/test_rootless_worker.py -q
ruff check scripts/tenant_cell/network.py scripts/tenant_cell/executor.py vendor/systutor-core/plugins/apps/backend/runtime/probes.py vendor/systutor-core/plugins/apps/backend/rootless_routes.py
```

E2E black-box laboratorio: `artifacts/0109-r3-cell-plumbing-and-cutover-e2e.json` con los
4 checks, `delta_denied: 0`, Core intacto y `cleanup_verified: true`.

## ROLLBACK

- NAT: quitar la regla del netns al desaprovisionar; no persiste en el host.
- Límite: revertir la validación en `probes.py` al valor anterior.
- Publicación: retirar el documento `spanel-*.yml` publicado; sin cambios en Traefik.
- Rollback por app: ya implementado en 0109; aquí solo se ejercita y se demuestra.

## Change Surface

```yaml
change_surface:
  allowed:
    - scripts/tenant_cell/network.py
    - scripts/tenant_cell/executor.py
    - vendor/systutor-core/plugins/apps/backend/runtime/probes.py
    - vendor/systutor-core/plugins/apps/backend/rootless_routes.py
    - scripts/tests/test_tenant_cell_provision.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_rootless_worker.py
    - artifacts/0109-r3-cell-plumbing-and-cutover-e2e.json
  prohibited:
    - scripts/tenant_cell/apparmor.py
    - scripts/tenant_cell/relay.py
    - vendor/systutor-core/src/systutor/kernel/**
    - vendor/systutor-core/plugins/hosting/**
    - vendor/systutor-core/plugins/tenant/**
    - docker-compose.yml
    - /opt/stacks/**
```

## Traceability

- Requirement: unificar `GAP-0109R-1`, `GAP-0109R-2`, `GAP-0109R-7` y el gap de rollback
  del primer E2E 0109.
- owner: lucas
- approver: lucas
- Commit: (pendiente; NO ejecutada)
- Evidence: artefactos `0109-apps-rootless-sandbox-e2e.json`,
  `0109-spanel-lab-blackbox-e2e.json` y `0109-r2-apparmor-build-e2e.json`.
- Deployment: laboratorio `spanel.lab`; sin producción.

## Definition of Done

- [ ] Objective satisfied (4 gaps cerrados sin parches manuales)
- [ ] Contract satisfied
- [ ] Invariants preserved
- [ ] Verification passed
- [ ] Rollback honest (simulacro ejecutado)
- [ ] Evidence artifact PASS + limpieza
