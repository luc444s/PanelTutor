# A.SPEC 0088 — Deploy Apps Globally and Incrementally by Service

> `risk: high` — cambia el camino central de deploy/rollback y el estado activo
> de aplicaciones multi-servicio. Requiere aprobación humana y E2E real.

## STATUS

Implementada y verificada en el lab real (`100.67.5.50`). El E2E obligatorio
pasó con Docker, API y worker reales: deploy inicial, canary de frontend,
deploy global incremental de solo `frontend`, probes verdes, cero reinicios,
base de datos intacta y revert global. Evidencia:
`artifacts/0088-scoped-e2e.json`.

Quedan como casos adicionales no ejecutados en esta corrida: deploy manual por
servicio a una release anterior, limpieza explícita de override con un global
posterior y restauración automática tras un probe fallido.

## WHY

Una aplicación Compose es una unidad de compatibilidad, pero no todos sus
servicios cambian en cada commit. Recrear frontend, backend y base de datos por
un cambio exclusivo del frontend aumenta tiempo, indisponibilidad y riesgo.

Al mismo tiempo, el operador necesita dos niveles de control:

1. **Global**: desplegar o volver toda la aplicación a una release compatible.
2. **Por servicio**: desplegar o volver únicamente frontend, backend, worker o
   base de datos cuando exista una necesidad puntual.

La UI no debe obligar al usuario a calcular dependencias. El motor debe decidir
el alcance efectivo, demostrarlo y elegir el camino global ante cualquier duda.

## WHAT

PanelTutor mantiene releases globales, inmutables y firmadas, pero introduce un
**alcance efectivo por servicio**:

- un deploy/rollback global compara la release objetivo con el estado activo y
  recrea solo los servicios afectados;
- un deploy/rollback solicitado desde un servicio afecta solo ese servicio;
- una acción global posterior reemplaza cualquier excepción individual y deja
  todos los servicios asociados a la release global objetivo;
- si el análisis diferencial no puede probar un subconjunto seguro, el motor
  ejecuta un deploy global.

La verdad falsable es: **un cambio exclusivo de un servicio no reinicia los
demás, pero la aplicación conserva una release global verificable y puede
volver a un estado global coherente**.

## SCOPE

- Fingerprint firmado por servicio.
- Comparación entre release objetivo y estado efectivo activo.
- Selección automática de servicios afectados.
- Deploy y rollback con scope global o servicio explícito.
- Estado efectivo `service -> release_id` sin migración de base de datos.
- Probes de aislamiento por servicio y probes funcionales/globales.
- Evidencia del alcance solicitado, alcance efectivo y fallback.
- UI global en **Deployments** y UI por servicio dentro de cada Service dialog.
- Rollback transaccional del subconjunto modificado.

## OUT OF SCOPE

- Rollback de datos, volúmenes o esquemas de base de datos.
- Alembic o cambios de esquema SQL.
- Inferir compatibilidad semántica entre APIs frontend/backend.
- Canary, blue/green, porcentajes de tráfico o múltiples réplicas.
- Deploy parcial entre aplicaciones distintas.
- Debilitar aislamiento, firma, probes o red interna.
- Runner falso, Docker simulado o mocks de runtime como evidencia de la
  selección incremental. Las unitarias pueden probar funciones puras, pero la
  preservación de contenedores se demuestra únicamente con Docker real.

## CONTRACT

### Release global

1. Toda release continúa representando el árbol y Compose completos.
2. La firma cubre también un mapa canónico `service_fingerprints`.
3. Un fingerprint nunca contiene secretos ni valores de environment.
4. Una release parcial o una imagen suelta no es desplegable.

### Scope solicitado

La API acepta exactamente uno de estos scopes:

```json
{"scope": {"type": "global"}}
{"scope": {"type": "service", "service": "frontend"}}
```

`global` es el default compatible. El nombre de servicio debe existir en la
release objetivo y en la aplicación.

### Scope efectivo

- **Primer deploy**: todos los servicios.
- **Global**: servicios con fingerprint distinto, más los afectados por cambios
  compartidos. Si no hay cambios de runtime, se registra un no-op verificable.
- **Servicio**: solo el servicio solicitado; no se levantan dependencias con
  `--deps` ni se recrean servicios vecinos.
- **Ambigüedad**: todos los servicios y `fallback_reason` obligatorio.

### Precedencia

- Una acción por servicio crea una excepción efectiva para ese servicio.
- La siguiente acción global elimina todas las excepciones, aunque algunos
  contenedores no necesiten recrearse por tener fingerprint idéntico.
- El mapa activo final apunta todos los servicios a la release global objetivo.

### Base de datos

Un rollback del servicio DB restaura únicamente imagen, command, environment
referenciado y configuración Compose. Los volúmenes y sus datos no se revierten,
reemplazan ni purgan.

## DESIGN

### 1. Fingerprint por servicio

Cada release firma:

```json
{
  "service_fingerprints": {
    "frontend": "sha256:...",
    "backend": "sha256:...",
    "database": "sha256:..."
  },
  "shared_fingerprint": "sha256:..."
}
```

El fingerprint de servicio incluye, en forma canónica:

- configuración Compose endurecida del servicio;
- Dockerfile y argumentos de build no secretos;
- digest conservador del build context respetando `.dockerignore`;
- referencia/digest de imagen externa;
- nombres de variables referenciadas, nunca valores;
- mounts administrados, healthcheck, command, entrypoint y dependencias;
- redes y recursos compartidos que el servicio referencia.

El `shared_fingerprint` cubre configuración que no puede atribuirse con certeza
a un único servicio. Si cambia, el alcance efectivo es global.

### 2. Planificador

```text
plan(target, active, requested_scope):
  verify signature and isolation contract

  if requested_scope is service:
    require service in target
    return [service]

  if no active state:
    return all target services

  if shared fingerprint changed or active state is incomplete:
    return all target services with fallback_reason

  changed = services whose fingerprint differs
  return changed
```

El plan se persiste antes de ejecutar y contiene:

```json
{
  "requested_scope": "global",
  "effective_services": ["frontend"],
  "strategy": "incremental",
  "fallback_reason": null
}
```

### 3. Ejecución

Para cada servicio efectivo:

1. stage de la release global verificada;
2. pull/build del servicio objetivo;
3. comprobar usuario non-root e image ID;
4. `docker compose up -d --no-deps <service>`;
5. verificar aislamiento, health opcional y cero reinicios;
6. ejecutar probe funcional del servicio cuando exista;
7. al terminar el lote, ejecutar probes funcionales globales.

Cuando el plan es global (todos los servicios), el arranque se hace con un
único `docker compose up -d` sin lista de servicios: Compose debe poder parar
todos los contenedores antes de reconciliar la red del proyecto. Hacerlo
servicio a servicio con `--no-deps` deja los demás contenedores conectados y
`up` falla al intentar eliminar la red (`network ... has active endpoints`).

Los servicios fuera del plan deben conservar container ID, StartedAt y
RestartCount. Esta condición se captura antes y se verifica después.

### 4. Fallo y rollback automático

Si cualquier build, start o probe falla:

- solo los servicios ya modificados vuelven a su release efectiva anterior;
- la restauración usa `up -d --no-deps`, nunca `start` después de `down`;
- los servicios que comparten release se recrean en una sola llamada de
  Compose (`up -d --no-deps a b ...`), no una por servicio, para que la
  reconciliación de red no encuentre endpoints activos;
- se vuelven a ejecutar probes del subconjunto y probes globales;
- el plan fallido no se publica: `service_releases`, `overrides` y fingerprints
  siguen siendo los del deployment activo anterior;
- si la restauración recrea los servicios, sus nuevos container IDs,
  `service_runtime` y la evidencia de probes se publican como un nuevo
  deployment activo (mismo commit y releases), de modo que el estado activo
  nunca apunte a contenedores destruidos por el intento fallido;
- si la verificación posterior a la restauración falla, el nuevo deployment
  activo se publica igualmente con estado `degraded` y `probe_error`;
- si algún servicio no puede restaurarse, la app queda `degraded` con
  diagnóstico hasheado y solo se publican las identidades verificadas.

### 5. Estado activo sin migración

El manifest activo almacena:

```json
{
  "global_release_id": "release-global",
  "service_releases": {
    "frontend": "release-frontend",
    "backend": "release-global",
    "database": "release-global"
  },
  "service_fingerprints": {},
  "overrides": ["frontend"]
}
```

Se publica atómicamente solo después de probes verdes. No se agregan columnas ni
tablas. Los deployments históricos continúan inmutables.

### 6. UI

#### Aplicación

La pestaña **Deployments** administra el scope global:

- deploy global;
- evidencia global;
- rollback global;
- resumen del alcance efectivo ejecutado.

#### Servicio

Cada Service dialog agrega **Deployments**:

- release efectiva del servicio;
- releases globales compatibles disponibles;
- deploy/rollback solo del servicio;
- evidencia filtrada al servicio;
- advertencia en DB: “no revierte datos del volumen”.

La UI no muestra fingerprints, dependencias internas ni selector manual de
servicios durante un deploy global.

## INVARIANTS

```yaml
invariants:
  - I1: toda ejecución parte de una release global firmada y verificada
  - I2: ningún servicio fuera del plan se recrea o reinicia
  - I3: ante ambigüedad el alcance crece a global, nunca se reduce
  - I4: firma, aislamiento, non-root, probes y cero reinicios siguen obligatorios
  - I5: el mapa activo cambia atómicamente solo después de probes verdes
  - I6: un fallo restaura únicamente servicios modificados y preserva los demás
  - I7: un deploy o rollback global elimina todos los overrides por servicio
  - I8: rollback de DB nunca modifica ni elimina volúmenes o datos
  - I9: environment y evidencia no exponen secretos
  - I10: el lock por aplicación impide planes concurrentes globales o parciales
```

## VERIFICATION

### Unitarias

- canonicalización estable de fingerprints;
- mismo input produce mismo hash;
- cambio exclusivo de frontend selecciona solo frontend;
- cambio compartido selecciona todos;
- estado incompleto activa fallback global;
- scope de servicio rechaza nombres desconocidos;
- global limpia overrides;
- rollback genera `up -d --no-deps`, nunca `down` global + `start`;
- valores de environment no aparecen en fingerprint/evidencia.

### E2E obligatorio — Software para Editores con Docker real

La prueba de aceptación usa exclusivamente:

```text
repo:     luc444s/software-de-gestion-para-editores
branch:   feature/workflow-diseno
compose:  docker-compose.dokploy.yml
services: frontend, backend, database
```

No se acepta runner falso, mocks de Docker ni una fixture reducida como prueba
de esta A.SPEC. El flujo se ejecuta por la API HTTPS y el worker reales del lab:

1. Comprobar que la rama remota está limpia y que
   `frontend/public/test.md` no existe.
2. Desplegar la aplicación completa desde el commit inicial y exigir release
   firmada, probes verdes y cero reinicios.
3. Capturar para cada servicio: container ID, image ID, `StartedAt`,
   `RestartCount`, mounts y release efectiva.
4. Escribir `frontend/public/test.md` con un canary único no secreto.
5. Crear un commit real y ejecutar `git push` a la rama configurada.
6. Solicitar **Deploy global** desde PanelTutor; no indicar manualmente
   `frontend` ni enviar una lista de servicios.
7. El planner debe reportar:

   ```json
   {
     "requested_scope": "global",
     "effective_services": ["frontend"],
     "strategy": "incremental",
     "fallback_reason": null
   }
   ```

8. Verificar que solo `frontend` cambia container ID, image ID y `StartedAt`.
9. Verificar por HTTP que `/test.md` devuelve exactamente el canary pusheado.
10. Verificar que `backend` y `database` conservan exactamente container ID,
    image ID y `StartedAt`; ambos mantienen `RestartCount == 0`.
11. Verificar que database conserva el mismo volumen/mount y un dato centinela
    creado antes del redeploy.
12. Verificar que los probes globales y por servicio pasan y que la evidencia
    no contiene secretos.
13. Revertir el commit de `test.md`, ejecutar otro `git push` y hacer deploy
    global para devolver la rama y la app a su estado inicial. Este segundo
    deploy también debe afectar solo `frontend`.
14. Guardar evidencia JSON con commits inicial/canary/revert, releases,
    fingerprints, plan, IDs anteriores/posteriores, probes y cleanup.
15. Al finalizar, la rama no contiene `test.md` y la aplicación permanece
    desplegada y funcional sobre el commit de revert; no se elimina como parte
    del cleanup.

La prueba falla si `backend` o `database` se recrean, reinician o cambian de
mount, aunque la aplicación siga respondiendo.

### Casos reales adicionales

Después del canary obligatorio de frontend:

1. un cambio exclusivo de backend debe preservar frontend y database;
2. un deploy manual de frontend a una release anterior debe preservar backend
   y database;
3. un deploy global posterior debe eliminar el override individual;
4. un probe fallido debe restaurar solo el subconjunto tocado.

Comandos mínimos:

```bash
ruff check vendor/systutor-core/plugins/apps scripts
PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core python -m pytest \
  vendor/systutor-core/plugins/apps/backend/tests -q
npm --prefix apps/web run build
npm --prefix apps/web test -- --run
SPANEL_LIVE_TESTS=1 python -m pytest \
  scripts/tests/test_e2e_apps_scoped_deploy_live.py -q -s
git diff --check
```

## ROLLBACK

1. Desactivar el planner incremental mediante un feature flag server-owned.
2. Mantener lectura de manifests con `service_releases`, pero ejecutar todos los
   servicios para acciones globales.
3. Ocultar Deployments por servicio en UI.
4. No borrar releases, manifests ni volúmenes.
5. Verificar un deploy global completo y probes antes de cerrar rollback.

## Change Surface

```yaml
change_surface:
  allowed:
    - vendor/systutor-core/plugins/apps/backend/releases/**
    - vendor/systutor-core/plugins/apps/backend/runtime/**
    - vendor/systutor-core/plugins/apps/backend/schemas.py
    - vendor/systutor-core/plugins/apps/backend/router.py
    - vendor/systutor-core/plugins/apps/backend/worker.py
    - vendor/systutor-core/plugins/apps/backend/tests/**
    - vendor/systutor-core/plugins/apps/frontend/**
    - apps/web/src/i18n/es/apps.ts
    - scripts/e2e_apps_*.py
    - scripts/tests/test_e2e_apps_*.py
    - temporary commits to luc444s/software-de-gestion-para-editores
  prohibited:
    - database schema changes
    - alembic
    - weakening isolation or probes
    - volume deletion or data rollback
    - fake runners as acceptance evidence
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - Apps deploy and rollback planner
    - signed release descriptor
    - active deployment manifest
    - global and service Deployments UI
  indirect:
    - route refresh after ingress-service changes
    - worker operation reports and evidence
    - recovery after failed deployment
  must_not_affect:
    - tenant isolation and RBAC
    - encrypted environment storage
    - application volumes and database data
    - services outside the effective plan
```

## Composition

```yaml
composition:
  requires_aspecs:
    - 0083
    - 0084
    - 0087
  must_compose_with:
    - signed immutable releases
    - isolation-only admission
    - automatic server-owned runtime policy
  systemic_invariants:
    - global release remains the compatibility and signature boundary
    - incremental execution never bypasses global verification
  composition_checks:
    - full deploy from no active state
    - real push of frontend/public/test.md changes only frontend container
    - incremental deploy followed by global rollback
    - service override followed by global deploy
    - failed partial deploy followed by verified restoration
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: planner, executor and state publisher have separate responsibilities
  entrypoints_must_stay_thin: true
  review_threshold_lines: 400
  extraction_threshold_lines: 600
  preferred_new_logic_locations:
    - vendor/systutor-core/plugins/apps/backend/releases/fingerprints.py
    - vendor/systutor-core/plugins/apps/backend/releases/planner.py
    - vendor/systutor-core/plugins/apps/backend/releases/scoped_execution.py
```

## Traceability

- Requirement: gestión global y por servicio con deploy global incremental
- owner: PanelTutor Apps
- approver: Lucas (platform owner)
- Commit: 2ec1acb
- Deployment: verificado en lab el 2026-11-15. Aplicación
  `scoped-e2e-45fd702497` (`705cd067-aaa0-490c-aab0-5dd591a8fe1c`) desplegada
  sobre el commit de revert `8e802927c41b433f9700ce26da7422cf153377a6`.
  Evidencia: `artifacts/0088-scoped-e2e.json`.

## Verificación ejecutada

```text
ruff check vendor/systutor-core/plugins/apps \
  scripts/e2e_apps_scoped_deploy.py \
  scripts/tests/test_e2e_apps_scoped_deploy_live.py   -> clean
PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core \
  python -m pytest vendor/systutor-core/plugins/apps/backend/tests -q
                                                      -> 141 passed
npm --prefix apps/web run build                       -> OK
npm --prefix apps/web test -- --run                   -> 54 passed
git diff --check                                      -> clean
```

E2E real ejecutado en el lab (`http://127.0.0.1:3000`) con Docker real:

```text
E2E OK
status: passed
initial_commit: 2f1c615617b7b3e72169271990477040a1bdffc5
canary_commit:  1c5464e32b629f48fccb2b1da4841ad3a1043e1f
revert_commit:  8e802927c41b433f9700ce26da7422cf153377a6
initial: 3 servicios, restart_count=0
canary:  effective_services=["frontend"], fallback_reason=null,
         backend/database con mismo container_id, image_id y started_at
http:    /test.md devolvió el canary en 8080
final:   effective_services=["frontend"], branch sin test.md
```

Para que el fixture arrancara se envió su política de hardening explícita
(`database` uid/gid 70 y `/var/run/postgresql` escribible). La política
automática por defecto usa uid 1000 y no es compatible con `postgres:16-alpine`
sin `user` en el Compose del fixture.

## Definition of Done

- [x] Objective satisfied — planner, ejecutor y UI implementados; E2E de canary
      incremental verificado en lab.
- [x] Scope respected
- [x] Contract satisfied
- [x] Independent falsable truth exists now — evidencia Docker/API/Git real en
      `artifacts/0088-scoped-e2e.json`.
- [x] Invariants preserved
- [x] Verification passed — E2E obligatorio de la A.SPEC en lab.
- [x] Rollback / compensation is honest
- [ ] Composition checks passed when applicable — pasaron los obligatorios
      (deploy completo, canary solo frontend y revert global); faltan los casos
      adicionales de override por servicio y restauración fallida.
- [x] No unrelated changes
- [x] Structural constraints respected
- [x] Traceability established — app y evidencia desplegadas en lab.
