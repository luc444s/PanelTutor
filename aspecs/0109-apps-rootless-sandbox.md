# A.SPEC 0109 — Deploy apps into the tenant rootless sandbox

> `risk: high` — cambia el runtime de deploy en producción, con rollback por aplicación.
> **Meta simple: desplegar apps en sandboxes.**

> Objetivo falsable en una frase: *el software para editores corre dentro de una celda
> rootless con 512 MB y 1 núcleo; si le hago estrés y el estrés no se sale del tenant,
> la prueba E2E pasa.*

## WHY

0107 dio la ficha de residencia de cada recurso y 0108 el medidor que no rompe la
cerradura. Pero el deploy de apps en producción todavía entra por el **portero central
del edificio**: `tasks.py` construye el `AppsWorker` sin `runtime_registry` y todo va al
daemon rootful global, aunque el contenedor corra como no-root.

Con la analogía: ya tenemos el apartamento y el medidor; falta que el **portero del
apartamento** sea quien mete y saca los muebles de la app. La ficha de residencia (0107)
debe decir a qué portero llamar, y si apagas la bandera global nadie pierde la
administración de lo que ya se mudó.

## WHAT

**Con `SPANEL_TENANTS_ROOTLESS=true`, el deploy de una app usa el `docker.sock` de la
celda de su tenant, persiste el runtime por despliegue solo tras verificación, y el
rollback restaura rutas y runtime sin borrar el contenedor rootful original hasta
confirmar la recuperación. La prueba E2E se considera PASS solo si el estrés dentro del
tenant de 512 MB/1 núcleo queda aislado.**

## SCOPE

### 1. Cableado del runtime rootless en producción

- `tasks.py`: construir el `AppsWorker` con un `TenantRuntimeRegistry` cuando la bandera
  `SPANEL_TENANTS_ROOTLESS` esté activa. Sin bandera, el worker es byte-idéntico al actual
  (un único `Runner` global).
- `worker.py`: `_runner(tenant_id)` ya sabe resolver `for_tenant(...).runner()` →
  `unix://<data_root>/cells/<slug>/docker.sock`. Conectar el recorder de runtime para que,
  tras un deploy verificado, se persista `rootless` en el registro de 0107 mediante un
  callback inyectado (sin acoplar el modelo de `apps` al de `tenant`).
- `register.py` / `settings.py`: leer la bandera y exponer el registry/recorder sin
  duplicar lógica. La bandera **solo habilita nuevas migraciones**: nunca reescribe el
  runtime de un despliegue ya registrado (corrección 2).
- Rutas por dominio: reutilizar el publicador de 0104/0106 tal cual; no cambiar Traefik.

### 2. Rollback por aplicación

- Si el deploy, la verificación o la publicación de ruta fallan: restaurar la ruta previa
  y el runtime registrado, marcar la operación como fallida y **conservar** el contenedor
  rootful original. No se elimina nada hasta confirmar migración y recuperación de datos.
- Con bandera en `false`, las apps ya migradas siguen administrándose por su runtime
  registrado (0107) y no se mueven.

### 3. Criterio E2E black-box (meta simple, una sola ronda)

Fixture real: `luc444s/software-de-gestion-para-editores` (rama usada en 0104/0105),
desplegado como app en una celda desechable con plan **512 MB RAM, 1 núcleo** (`pids`
coherente con 0108). Debe cumplirse, en este orden:

1. **Desplegar y revisar**: la app se despliega por la API de Apps en la celda rootless;
   el link publicado por el relay/Traefik responde **HTTP 200** y muestra la UI del editor.
   Verificar uid no-root dentro del contenedor, `0 DENIED` de AppArmor, sin `EPERM`.
2. **Estrés al tenant**: desde dentro de la celda, generar carga sostenida de CPU y
   memoria (p. ej. `stress-ng` o equivalente en el daemon de la celda) intentando superar
   el plan.
3. **Aislamiento (compuerta)**: el estrés **no se sale** del tenant:
   - `memory.max=536870912`, `cpu.max` de 1 núcleo y `pids.max` se respetan; la carga
     se limita/OOM dentro del tenant, nunca en otro sitio.
   - La app del editor sigue respondiendo HTTP 200 después del estrés (o se recupera
     sin intervención manual).
   - Traefik, MariaDB compartida, phpMyAdmin, PowerDNS y Docker Mailserver conservan
     mismo PID y sha256 de Config; otros tenants siguen en HTTP 200; sin OOM en el host.
   - Sin `EPERM`, sin `DENIED` nuevo y sin escrituras fuera de la celda.
4. Si el estrés afecta a otro tenant o al Core → **FAIL**, no se pasa la prueba.

Artefacto: `artifacts/0109-apps-rootless-sandbox-e2e.json`, con el link vivo, las
mediciones del plan y la comparación PID/hash del Core antes/después.

## OUT OF SCOPE

- Migrar WordPress o estáticos (0110), cambiar el mínimo de correo (0111), o la
  creación por defecto (0111).
- Tocar `scripts/tenant_cell/**` (0108 ya lo cerró), AppArmor/seccomp, relay, Traefik,
  certificados, DNS.
- Traefik, MariaDB compartida, phpMyAdmin, PowerDNS, Docker Mailserver ni su hardening;
  DNS, correo, backups, `vendor/systutor-core/src/**`, `vendor/systutor-core/app/**`,
  `docker-compose.yml`, `/opt/stacks/**`, producción.
- Hardening invasivo sobre Dockerfiles o código del repositorio fixture.

## CONTRACT

**Precondiciones:** bandera `SPANEL_TENANTS_ROOTLESS=true`; celda del tenant aprovisionada
con plan 512 MB/1 núcleo efectivo (0108); registry de 0107 disponible; repo fixture
accesible.

**Postcondiciones:**

1. El deploy de app usa `unix://<data_root>/cells/<slug>/docker.sock`, nunca
   `/var/run/docker.sock`.
2. El runtime `rootless` se persiste solo después de deploy + verificación + publicación
   de ruta correctos.
3. Con bandera `false`, el worker elige el `Runner` global; los despliegues ya marcados
   `rootless` siguen resolviéndose como rootless (0107).
4. Ante fallo, ruta y runtime vuelven al estado previo; el contenedor rootful original
   sigue existiendo.
5. E2E: HTTP 200 del editor antes y después del estrés; cuotas del tenant respetadas;
   Core y otros tenants intactos → `result: PASS`.

## INVARIANTS

```yaml
invariants:
  - "Sin bandera el worker es byte-identico al actual: un unico Runner global rootful."
  - "El socket usado por un deploy rootless es siempre el de la celda, nunca /var/run/docker.sock."
  - "El runtime se persiste solo tras verificar el deploy; un fallo no deja un resource marcado rootless."
  - "SPANEL_TENANTS_ROOTLESS=false no reescribe runtime ya registrado (0107)."
  - "El rollback restaura rutas y runtime sin eliminar contenedores ni volumenes rootful."
  - "El estres del tenant queda confinado por su plan de 512 MB / 1 nucleo / pids; no afecta a otros tenants ni al host."
  - "Traefik, MariaDB compartida, phpMyAdmin, PowerDNS y Docker Mailserver conservan PID y hash de Config."
  - "0 DENIED de AppArmor, sin EPERM, sin hardening invasivo en el fixture."
  - "Las rutas publicadas por dominio (0104/0106) no cambian de forma."
  - "Sin produccion; la creacion de WP y estaticos no se toca (0110)."
```

## VERIFICATION

```bash
# Tests del worker y del registro de runtime (a ejecutar al implementar)
PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/apps/backend/tests/test_tenant_runtime.py vendor/systutor-core/plugins/apps/backend/tests/test_rootless_worker.py -q
PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/tenant/backend/tests -q
ruff check vendor/systutor-core/plugins/apps/backend/tasks.py vendor/systutor-core/plugins/apps/backend/worker.py vendor/systutor-core/plugins/apps/backend/register.py vendor/systutor-core/plugins/apps/backend/settings.py
PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -c "from plugins.apps.backend.tasks import worker; from plugins.apps.backend.worker import AppsWorker; print('ok')"
```

E2E black-box en laboratorio: `artifacts/0109-apps-rootless-sandbox-e2e.json` con el
criterio de la sección SCOPE §3. Los comandos de estrés se ejecutan **desde dentro de la
celda**, nunca contra el daemon global ni contra Core.

## ROLLBACK

- Bandera a `false`: vuelve el `Runner` global sin tocar despliegues ya migrados.
- Por app: restaurar ruta previa y `set_runtime` al valor anterior; conservar el
  contenedor rootful hasta confirmar recuperación.
- Sin migración de esquema: el registro de 0107 y el plan de 0108 no se modifican.

## Change Surface

```yaml
change_surface:
  allowed:
    - vendor/systutor-core/plugins/apps/backend/tasks.py
    - vendor/systutor-core/plugins/apps/backend/worker.py
    - vendor/systutor-core/plugins/apps/backend/register.py
    - vendor/systutor-core/plugins/apps/backend/settings.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_rootless_worker.py
    - artifacts/0109-apps-rootless-sandbox-e2e.json
  prohibited:
    - scripts/tenant_cell/**
    - vendor/systutor-core/src/systutor/kernel/**
    - vendor/systutor-core/app/**
    - vendor/systutor-core/plugins/apps/backend/models.py
    - vendor/systutor-core/plugins/apps/backend/runtime/**
    - vendor/systutor-core/plugins/hosting/**
    - vendor/systutor-core/plugins/tenant/**
    - vendor/systutor-core/plugins/domains/**
    - vendor/systutor-core/plugins/mail/**
    - apps/web/**
    - scripts/phpmyadmin_up.sh
    - docker-compose.yml
    - /opt/stacks/**
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - seleccion de runner en el worker de Apps
    - persistencia del runtime por despliegue
  indirect:
    - rutas publicadas de apps
    - administracion posterior de despliegues migrados
  must_not_affect:
    - despliegues rootful existentes y sus rutas
    - inventario y runtime de 0107
    - plan RAM de 0108 y celdas rootless
    - Traefik, MariaDB compartida, phpMyAdmin, PowerDNS, Docker Mailserver
    - hosting WordPress/estaticos (0110), correo (0111), produccion
```

## Composition

```yaml
composition:
  requires_aspecs:
    - "0107-tenant-resource-runtime-and-inventory"
    - "0108-rootless-userspace-ram-dry-run"
  must_compose_with:
    - "0110-hosting-rootless-phpmyadmin"
    - "0111-creation-limited-userspace-mail-minimum"
  systemic_invariants:
    - "El runtime registrado manda sobre la bandera global."
    - "El estres de un tenant nunca compromete la infraestructura Core."
  composition_checks:
    - "PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/tenant/backend/tests -q"
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: one coherent responsibility and one main reason to change
  entrypoints_must_stay_thin: true
  review_threshold_lines: 500
  extraction_threshold_lines: 800
  preferred_new_logic_locations:
    - vendor/systutor-core/plugins/apps/backend/worker.py
    - vendor/systutor-core/plugins/apps/backend/register.py
```

## Traceability

- Requirement: req. 2 (apps rootful → rootless) y corrección 2 (rollback por aplicación,
  bandera solo para nuevas migraciones, no borrar rootful hasta confirmar).
- owner: lucas
- approver: lucas
- Commit: (pendiente; NO ejecutada)
- Evidence: pendiente — `artifacts/0109-apps-rootless-sandbox-e2e.json`.
- Deployment: laboratorio `spanel.lab`; sin producción.

## Definition of Done

- [ ] Objective satisfied (apps desplegadas en sandbox rootless)
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
- [ ] E2E: editor en 512 MB/1 núcleo HTTP 200 y estrés aislado sin afectar Core ni otros tenants
