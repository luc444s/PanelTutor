# A.SPEC 0103 — Tenant plan host probes and user-manager identity fix

> `risk: high` — corrige la identidad con la que se ejecutan comandos `systemctl
> --user` y el camino del probe que comprueba límites en el host. Afecta a
> `provision` y a `plan verify`, ambos con privilegios. Requiere `approver:`.

## WHY

El E2E de A.SPEC 0102 (`artifacts/0102-cli-only-e2e.json`) demostró que la
materialización del plan funciona (cgroups reales con los valores exactos),
pero destapó tres defectos en la capa host, fuera del `change_surface` de 0101
y 0102:

1. `Executor._run_user()` ejecuta `systemctl --user` como **root**, con
   `XDG_RUNTIME_DIR`/bus ajenos → `EPERM`. El `provision` deja el daemon
   rootless caído y la celda en estado `degraded`; la unidad de usuario queda
   `disabled`.
2. `plan verify` usa el **socket rootless de la celda** para su probe
   "rootful"; `runc` intenta `/run/systemd/private` y recibe *permission
   denied* al crear un scope bajo un slice del sistema.
3. `slice_cgroup_path()` compone
   `/tenant.slice/tenant-<slug>.slice`, pero systemd inserta slices
   intermedios para nombres con guiones; el `startswith()` de `verify` falla
   aunque el slice exista.

El E2E los sorteó con un workaround de laboratorio (`runuser` manual y
comandos CLI directos). Esta A.SPEC los corrige en el código para que el
propio CLI sea honesto y el E2E se pueda repetir sin workarounds.

## WHAT

Los comandos de usuario se ejecutan con la **identidad real del usuario de la
celda**, el probe rootful se hace contra el daemon root del host y la ruta del
slice se obtiene del propio systemd (con fallback determinista).

## SCOPE

- `executor.py`: `_run_user()` pasa por `runuser -u <cell-user> -- ...`
  conservando `XDG_RUNTIME_DIR` y `DBUS_SESSION_BUS_ADDRESS`, y resolviendo el
  nombre de usuario desde el uid. Esto repara `provision`, el `enable` de la
  unidad de usuario y el `systemd-run --user` del probe rootless.
- `plans.py`: `slice_cgroup_path()` consulta `systemctl show <slice> -p
  ControlGroup --value`, con fallback al valor anterior si systemd no responde.
- `plans.py`: `run_plan_probe()` usa el daemon root del host (sin `DOCKER_HOST`
  de celda) para el contenedor con `--cgroup-parent`, manteniendo el scope
  rootless vía `_run_user`.
- Tests unitarios que fallan con el código actual y pasan con el arreglo:
  identidad del `runuser`, path real del slice y env del probe rootful.
- Repetir el E2E de 0102 en el laboratorio sin el workaround de `runuser`.

## OUT OF SCOPE

- Cambiar el modelo de privilegios del agente host ni el 503 fail-closed de
  `plans_service.py` (A.SPEC 0102).
- Modificar `vendor/systutor-core/**`, la API de planes ni la UI.
- Tocar `cell-g`, `cell-h`, Traefik, phpMyAdmin, MariaDB, WordPress ni
  producción.
- Escribir `/etc/**` o `/run/**` desde el GENERATOR (solo tests con fakes).
- Invocar Alembic directamente.
- La spec de Traefik padre (siguiente trabajo).

## CONTRACT

**Precondiciones**: el proceso CLI corre como root en el host; `runuser`
existe; la celda tiene usuario del sistema y linger; el slice está aplicado
cuando se llama a `verify`.

**Postcondiciones**:

- `_run_user(uid, argv)` ejecuta `argv` como `pwd.getpwuid(uid).pw_name`, con
  el entorno de bus de ese uid; ningún `systemctl --user` corre como root.
- Tras `provision`, el daemon rootless está activo y la unidad de usuario
  queda habilitada: un reinicio de `user@<uid>.service` lo recupera sin
  intervención manual.
- `slice_cgroup_path()` devuelve la ruta real informada por systemd
  (incluyendo slices intermedios) y solo usa la composición literal como
  fallback.
- `plan verify` usa el daemon root del host para el contenedor del probe;
  cualquier `DOCKER_HOST` heredado del entorno se elimina explícitamente para
  ese probe. El scope rootless sigue pasando por `_run_user`.
- `plan verify` puede devolver `ok: true` cuando los límites están aplicados;
  si el kernel no los aplica, debe seguir devolviendo `ok: false` con
  evidencia.

## INVARIANTS

```yaml
invariants:
  - "Ningun systemctl --user se ejecuta como root: siempre pasa por la identidad del usuario de la celda."
  - "El probe rootful usa el daemon root del host, nunca el socket rootless de la celda."
  - "El scope rootless del probe se crea con systemd --user como el usuario de la celda."
  - "La ruta del slice se deriva de systemd (ControlGroup) con fallback determinista; no se asume ausencia de slices intermedios."
  - "Sin plan, _override sigue usando 512m/1.0/256."
  - "PostgreSQL sigue siendo la unica fuente de verdad del plan; plans.json es solo cache."
  - "El gate SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS=1 sigue restringido al host."
  - "La API de planes conserva el 503 fail-closed cuando no hay cliente."
  - "No se monta el socket Docker del host en el contenedor de la app."
  - "No se tocan cell-g, cell-h, Traefik, phpMyAdmin, MariaDB ni produccion."
  - "No se modifica vendor/systutor-core, apps/web ni /etc o /run directamente."
```

## VERIFICATION

```bash
PYTHONPATH=vendor/systutor-core:. python3 -m pytest scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_provision.py -q
PYTHONPATH=vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/apps/backend/tests/test_plans.py vendor/systutor-core/plugins/apps/backend/tests/test_plans_client.py vendor/systutor-core/plugins/apps/backend/tests/test_plans_agent.py vendor/systutor-core/plugins/apps/backend/tests/test_no_invasive_hardening.py vendor/systutor-core/plugins/apps/backend/tests/test_scoped_planner.py scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_provision.py -q
ruff check scripts/tenant_cell scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_provision.py
python3 scripts/spanel_tenant.py plan --help
```

Después del GENERATOR se repite el E2E de 0102 en el lab usando la CLI
corregida, sin el workaround de `runuser`, y se actualiza el artifact de
evidencia.

## ROLLBACK

Revertir `executor.py` y `plans.py` devuelve el comportamiento anterior; no hay
cambios de esquema ni datos. El `provision` vuelve a dejar el daemon caído
(comportamiento defectuoso documentado), pero ningún plan ni slice existente
se altera por el rollback.

## Change Surface

```yaml
change_surface:
  allowed:
    - scripts/tenant_cell/executor.py
    - scripts/tenant_cell/plans.py
    - scripts/tests/test_tenant_cell_plan.py
    - scripts/tests/test_tenant_cell_provision.py
  prohibited:
    - vendor/systutor-core/**
    - apps/web/**
    - /etc/**
    - /run/**
    - scripts/e2e_*.py
    - scripts/tenant_cell/host_agent.py
    - scripts/tenant_cell/plans_client.py
    - aspecs/0101-apps-tenant-plan-backend.md
    - aspecs/0102-apps-host-plan-materializer-wiring.md
```

El GENERATOR no debe modificar la A.SPEC 0103 ni el artifact de evidencia; el
hilo principal se encarga del E2E y del commit final.

## Blast Radius

```yaml
blast_radius:
  direct:
    - identidad de ejecucion de comandos systemctl --user / systemd-run --user
    - obtencion de la ruta real del slice tenant-<slug>.slice
    - entorno del contenedor del probe rootful de plan verify
  indirect:
    - provision y arranque del daemon rootless por celda
    - resultado de plan verify y su auditoria
  must_not_affect:
    - API de planes y cliente del agente host
    - kernel systutor y permisos core.*
    - cell-g y cell-h
    - Traefik / phpMyAdmin / MariaDB / WordPress
    - produccion
```

## Composition

```yaml
composition:
  requires_aspecs:
    - "0101-apps-tenant-plan-backend"
    - "0102-apps-host-plan-materializer-wiring"
  must_compose_with:
    - "0100-apps-tenant-resource-plan"
  systemic_invariants:
    - "Sin plan, _override sigue usando 512m/1.0/256."
    - "AppArmor sigue en enforce tras cualquier materializacion."
    - "El socket rootless de cada celda sigue siendo exclusivo del tenant."
  composition_checks:
    - "PYTHONPATH=vendor/systutor-core:. python3 -m pytest scripts/tests/test_tenant_cell_plan.py scripts/tests/test_tenant_cell_provision.py -q"
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: one coherent responsibility and one main reason to change
  entrypoints_must_stay_thin: true
  review_threshold_lines: 600
  extraction_threshold_lines: 900
  preferred_new_logic_locations:
    - scripts/tenant_cell/executor.py
    - scripts/tenant_cell/plans.py
```

El tamaño en líneas no es bloqueante; gobiernan la corrección y la VERIFICATION.

## Traceability

- Requirement: corregir los tres defectos de host encontrados por el E2E CLI de A.SPEC 0102.
- Evidence: `artifacts/0102-cli-only-e2e.json` (known_defects).
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
