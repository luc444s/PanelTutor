# A.SPEC 0088 — Deploy Apps Globally and Incrementally by Service

> `risk: high` — cambia el camino central de deploy/rollback y el estado activo
> de aplicaciones multi-servicio. Requiere aprobación humana y E2E real.

## STATUS

Definida. Implementación pendiente.

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

Los servicios fuera del plan deben conservar container ID, StartedAt y
RestartCount. Esta condición se captura antes y se verifica después.

### 4. Fallo y rollback automático

Si cualquier build, start o probe falla:

- solo los servicios ya modificados vuelven a su release efectiva anterior;
- la restauración usa `up -d --no-deps`, nunca `start` después de `down`;
- se vuelven a ejecutar probes del subconjunto y probes globales;
- el mapa activo no cambia hasta completar el plan entero;
- si la restauración falla, la app queda `degraded` con diagnóstico hasheado.

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

### Integración con runner falso

- container IDs de servicios no afectados permanecen iguales;
- fallo en el segundo servicio restaura el primero;
- el manifest activo no se publica antes de probes;
- DB conserva exactamente los mismos mounts antes y después de rollback.

### E2E Docker real

Fixture con `frontend`, `backend` y `database`:

1. deploy inicial global: inicia los tres;
2. cambiar solo frontend: cambia solo container ID de frontend;
3. cambiar backend: cambia solo backend;
4. deploy manual de frontend a release anterior: DB/backend intactos;
5. deploy global: elimina override y sincroniza mapa completo;
6. provocar probe fallido: restaura subconjunto y conserva datos DB;
7. confirmar firma, evidencia, cero reinicios y HTTPS funcional.

Comandos mínimos:

```bash
ruff check vendor/systutor-core/plugins/apps scripts
PYTHONPATH=vendor/systutor-core/src:vendor/systutor-core python -m pytest \
  vendor/systutor-core/plugins/apps/backend/tests -q
npm --prefix apps/web run build
npm --prefix apps/web test -- --run
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
  prohibited:
    - database schema changes
    - alembic
    - weakening isolation or probes
    - volume deletion or data rollback
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
- Commit: pending
- Deployment: pending

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
