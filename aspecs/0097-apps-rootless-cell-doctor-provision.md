# A.SPEC 0097 — Provision rootless tenant cell in the lab (Fase 1)

> `risk: high` — crea usuarios, perfiles AppArmor, sockets y reglas de red por
> tenant. Requiere gate `doctor`, rollback explícito y tests unitarios con
> ejecutores falsos antes de tocar un host real.

## WHY

El A.SPEC 0096 define la celda rootless por tenant como reemplazo del hardener
retirado, pero aún no existe ninguna herramienta que la cree o la verifique.
Sin `doctor` ni `provision`, no se puede demostrar que un host reúne los
prerequisitos (cgroup v2 delegado, AppArmor, nftables con `skuid`) ni que una
celda queda aislada antes de desplegar la primera app.

## WHAT

Existe una CLI Python que, **solo después de un `doctor` verde**, crea una
celda rootless por `slug` con usuario de sistema, bloque subuid/subgid,
directorios `0700`, socket Docker del tenant, perfil AppArmor efectivo y
publish loopback protegido; y puede inspeccionarla y desmontarla de forma
idempotente y auditable.

## SCOPE

- `scripts/spanel_tenant.py` como entrypoint delgado (typer).
- Paquete `scripts/tenant_cell/` con: `cli.py`, `doctor.py`, `alloc.py`,
  `cells.py`, `apparmor.py`, `network.py`, `audit.py`.
- Comandos: `doctor`, `provision --slug`, `status --slug`, `list`,
  `repair --slug`, `deprovision --slug`, `apparmor install|verify|remove`.
- Tests unitarios con host y ejecutores falsos (sin tocar un sistema real).

## OUT OF SCOPE

- Backend `TenantRuntime`, worker, releases, probes o migraciones de DB.
- `migrate-legacy` (Fase 3b).
- Ejecutar `provision` contra el laptop del lab o producción desde este change.
- Modificar Compose, Dockerfile, env, secretos, stack Docker o kernel.

## CONTRACT

- `doctor --json` devuelve un objeto con `ready: bool` y el detalle de cada
  capability: `kernel_cgroup2`, `systemd_delegate`, `apparmor_enabled`,
  `apparmor_parser`, `nftables_skuid`, `subuid_range_free`, `rootless_docker`.
- `provision --slug <slug>` sale con error y **cero cambios** si `doctor` no
  está verde para ese host.
- `provision` es idempotente: repetirlo sobre una celda `ready` no duplica
  usuario, bloque uid, perfil ni reglas, y devuelve el mismo estado.
- `status --json` devuelve `state`, `slug`, `uid_map` efectivo leído del host,
  `socket_path`, `apparmor.profile`, `apparmor.effective`, `apparmor.hash` y
  `cgroup_path`. Nunca devuelve secretos.
- `deprovision --slug` desmonta daemon, unidad systemd, reglas y perfil; por
  defecto **conserva los datos** (`--keep-data` es el comportamiento default).
- Todo comando mutante escribe un registro JSONL con `tenant_slug`, `verb`,
  `exit_code`, sin secretos ni stack traces en la salida al backend.

## INVARIANTS

```yaml
invariants:
  - "Ningún archivo bajo change_surface.allowed supera 400 líneas (review threshold) ni 600 (extraction threshold)."
  - "slug se valida con ^[a-z0-9][a-z0-9-]{0,61}$; cualquier otro valor se rechaza antes de cualquier cambio en filesystem o sistema."
  - "provision se niega a actuar salvo que doctor declare ready=true; no se permite aprovisionamiento parcial tras un gate fallido."
  - "La CLI no acepta contraseñas/tokens como argumento ni escribe secretos en disco; ningún log contiene secretos."
  - "La CLI no importa ni modifica código de backend/runtime ni del kernel; los archivos del pipeline de apps existente permanecen byte-idénticos."
  - "Todo comando mutante es idempotente y emite tenant_slug, verb y exit_code en el audit log JSONL."
  - "Las rutas se derivan solo del slug validado y de la asignación persistida; un tenant no puede leer ni alcanzar la celda de otro."
  - "El socket rootless lo crea el usuario de la celda, nunca root; la CLI no enlaza puertos privilegiados ni usa el docker.sock global."
  - "El mapeo de UID se lee del host (no se asume que UID 0 sea el primer subuid) y se reporta en status."
```

## VERIFICATION

```bash
.venv/bin/python -m ruff check scripts/spanel_tenant.py scripts/tenant_cell scripts/tests/test_tenant_cell_doctor.py scripts/tests/test_tenant_cell_provision.py
PYTHONPATH=vendor/systutor-core:. .venv/bin/python -m pytest scripts/tests/test_tenant_cell_doctor.py scripts/tests/test_tenant_cell_provision.py -q
.venv/bin/python scripts/spanel_tenant.py --help
```

Los tests inyectan un `HostProbe` y un `Executor` falsos: ningún test crea
usuarios, perfiles, reglas de red ni contacta con un host real.

## ROLLBACK

`deprovision --slug <slug>` desmonta daemon, unidad systemd, perfil AppArmor y
reglas `nftables`, conservando datos por defecto. El código fuente se revierte
con `git checkout -- <allowed files>`. Ninguna acción de esta A.SPEC borra
datos de apps ni modifica el stack del panel.

## Change Surface

```yaml
change_surface:
  allowed:
    - scripts/spanel_tenant.py
    - scripts/tenant_cell/__init__.py
    - scripts/tenant_cell/cli.py
    - scripts/tenant_cell/doctor.py
    - scripts/tenant_cell/executor.py
    - scripts/tenant_cell/alloc.py
    - scripts/tenant_cell/cells.py
    - scripts/tenant_cell/apparmor.py
    - scripts/tenant_cell/network.py
    - scripts/tenant_cell/audit.py
    - scripts/tests/test_tenant_cell_doctor.py
    - scripts/tests/test_tenant_cell_provision.py
  prohibited:
    - vendor/systutor-core/**
    - src/systutor/**
    - docker-compose*.yml
    - Dockerfile
    - .env*
    - secrets/**
    - scripts/app_deploy.py
    - scripts/dangerous_build/**
    - scripts/e2e_*.py
    - aspecs/0096-apps-rootless-tenant-cell.md
    - ADD/**
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - scripts/spanel_tenant.py
    - scripts/tenant_cell/**
  indirect:
    - scripts/tests/**
  must_not_affect:
    - vendor/systutor-core/plugins/apps/backend/**
    - src/systutor/**
    - scripts/app_deploy.py
    - docker-compose*.yml
    - hosts remotos (lab y producción)
```

## Composition

```yaml
composition:
  requires_aspecs:
    - aspecs/0096-apps-rootless-tenant-cell.md
  must_compose_with: []
  systemic_invariants:
    - "La celda es la única unidad de aislamiento; no se reintroduce hardening."
  composition_checks: []
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: one coherent responsibility and one main reason to change
  entrypoints_must_stay_thin: true
  review_threshold_lines: 400
  extraction_threshold_lines: 600
  preferred_new_logic_locations:
    - scripts/tenant_cell/
```

## Traceability

- Requirement: A.SPEC 0096 Fase 1 — doctor + provision/status/deprovision.
- owner: lucas
- approver: lucas
- Commit: a644ce5
- Deployment: lab laptop `spanel.lab` (Fase 1, tras aprobación)

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
