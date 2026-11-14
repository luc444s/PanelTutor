# A.SPEC 0082 — Apps Hardening Backend and API-first CLI

## WHY

Apps clona repositorios GitHub y hoy solo ejecuta el auditor básico antes del
deploy. El hardener transaccional existe como herramienta separada, por lo que
no hay todavía una operación backend durable, tenant-scoped y auditable que lo
ejecute ni una forma API-first de solicitarla. El primer incremento debe crear
ese límite confiable sin afirmar aún que el deploy consume el candidato.

## SCOPE

- Añadir contratos backend inmutables para una política runtime explícita y la
  evidencia de un candidato endurecido.
- Añadir un adaptador local fail-closed que invoque
  `dangerous-build-normalize harden` sin shell, con timeout, entorno saneado y
  JSON acotado/validado.
- Añadir `POST /applications/{id}/hardening`, como operación durable `harden`,
  tenant-scoped, idempotente y protegida por `apps.deployments.create`.
- Ejecutar el hardener exclusivamente en el checkout temporal ya clonado por el
  worker. El token GitHub no puede llegar al proceso hardener.
- Añadir `spanel_apps.py harden` como cliente HTTP puro, con políticas
  `--service-user SERVICE=UID:GID`, `--writable-path SERVICE=/PATH:MODE` y
  `--wait`.
- Añadir pruebas unitarias del adaptador, schema, router, worker y CLI.

## OUT OF SCOPE

- Hacer que `deploy` consuma el candidato endurecido.
- Inferir automáticamente UID/GID, writable paths o dependencias.
- Añadir adapters de frameworks, capability broker, canary o promoción.
- Cambios de modelos, base de datos o migraciones.
- UI/frontend.
- Modificar el motor existente bajo `scripts/dangerous_build/`.

## WHAT

### Backend contracts

Crear `plugins/apps/backend/hardening/` con:

- `RuntimeUserPolicy(service, uid, gid)`; UID y GID deben ser enteros no-root.
- `WritablePathPolicy(service, path, mode)`; ruta absoluta normalizada, sin
  traversal, y modo octal restringido.
- `HardeningPolicy`; servicios únicos, al menos uno, paths asociados solo a
  servicios declarados.
- `HardenedCandidate`; solo puede construirse desde una respuesta cuyo
  `status=applied`, `applied=true`, gate primario `passed` y gate post-apply
  `reused` o `passed`.
- `HardeningRejected`, error seguro que no incorpora stdout/stderr arbitrario.

### Command adapter

`CommandHardeningEngine.prepare(checkout, compose_file, policy)` debe:

1. Resolver un ejecutable único desde constructor o
   `SPANEL_APPS_HARDENER_COMMAND`, default `dangerous-build-normalize`.
2. Invocar mediante argv, nunca `shell=True`.
3. Incluir `harden`, `--apply`, `--format json`, cada `--service-user` y cada
   `--writable-path`; incluir `--compose-file` solo si fue configurado.
4. Eliminar `GH_TOKEN`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK` y variables de
   credenciales GitHub del entorno hijo.
5. Aplicar timeout configurable y límite de 8 MiB a stdout JSON.
6. Rechazar executable ausente, timeout, exit distinto de cero, JSON inválido,
   payload sobredimensionado o evidencia incompleta.
7. Devolver evidencia sanitizada; no devolver stdout/stderr bruto ni rutas de
   backup/source del checkout temporal.

### API and worker

- Añadir `HardeningRequest` a schemas con `service_users` y `writable_paths`
  validados y límites explícitos.
- El router debe guardar únicamente la política no secreta en `Operation.report`
  y despachar `kind=harden` mediante `_queue`.
- `AppsWorker` debe aceptar un `hardening_engine` inyectable; por defecto usar
  `CommandHardeningEngine`.
- `run()` debe tratar `harden` como operación de fuente.
- Tras clone y borrado lógico del token local, `harden` debe construir la
  política desde el report durable, ejecutar el engine en el checkout temporal
  y devolver el reporte sanitizado del candidato.
- `inspect` y `deploy` deben conservar su comportamiento actual.
- Una política ausente o inválida bloquea cerrado antes de invocar el engine.

### CLI

- `harden APPLICATION` requiere al menos un `--service-user`.
- Flags repetidos se convierten a un payload estructurado y rechazan servicios
  duplicados, root, paths relativos/traversal y modos inválidos antes de HTTP.
- `--wait` usa el polling existente.
- La CLI continúa sin imports de runtime, DB, Docker o SSH y nunca acepta token
  por argv.

## CONTRACT

```yaml
request:
  service_users:
    web: {uid: 10001, gid: 10001}
  writable_paths:
    - {service: web, path: /app/data, mode: "0750"}

accepted_result:
  status: validated
  source_tree_sha256: <sha256>
  hardened_tree_sha256: <sha256>
  compose: compose.yml
  services: [web]
  changes: [Dockerfile, compose.yml]
  policy: <sanitized policy>
  gate: <sanitized gate evidence>
```

El endpoint devuelve inicialmente un `OperationView` 202. El resultado final se
consulta por la ruta de operaciones existente.

## INVARIANTS

```yaml
invariants:
  - id: H1
    statement: el hardener jamás recibe credenciales GitHub.
    proof: test del entorno hijo y token ausente en report/result.
  - id: H2
    statement: ningún resultado parcial se representa como candidato validado.
    proof: matrix de exit/JSON/status/gates incompletos rechazada.
  - id: H3
    statement: el proceso no usa shell ni concatena input en un comando.
    proof: runner fake inspecciona argv y shell=false.
  - id: H4
    statement: la operación está aislada por tenant y permiso existente.
    proof: tests router cross-tenant/RBAC e idempotencia vía _queue.
  - id: H5
    statement: la política durable no contiene secretos y está limitada.
    proof: schemas + report exacto + límites de cantidad/tamaño.
  - id: H6
    statement: CLI solo usa HTTP autenticado y valida antes de transportar.
    proof: AST/import test y FakeTransport sin llamadas en inputs inválidos.
  - id: H7
    statement: inspect y deploy mantienen compatibilidad.
    proof: suites existentes de Apps worker/deploy/CLI.
```

## CHANGE SURFACE

```yaml
change_surface:
  allowed:
    - aspecs/0082-apps-hardening-backend-cli.md
    - vendor/systutor-core/plugins/apps/backend/hardening/**
    - vendor/systutor-core/plugins/apps/backend/schemas.py
    - vendor/systutor-core/plugins/apps/backend/router.py
    - vendor/systutor-core/plugins/apps/backend/worker.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_hardening_engine.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_worker_github.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_deploy_source.py
    - scripts/spanel_apps.py
    - scripts/tests/test_spanel_apps.py
  prohibited:
    - vendor/systutor-core/plugins/apps/backend/models.py
    - vendor/systutor-core/plugins/apps/backend/migrations/**
    - vendor/systutor-core/plugins/apps/backend/runtime/deployment.py
    - vendor/systutor-core/plugins/apps/frontend/**
    - scripts/dangerous_build/**
    - docker-compose.yml
    - .env.docker.example
```

## VERIFICATION

```bash
.venv/bin/python -m pytest \
  vendor/systutor-core/plugins/apps/backend/tests/test_hardening_engine.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_worker_github.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_deploy_source.py \
  scripts/tests/test_spanel_apps.py -q
.venv/bin/python -m ruff check \
  vendor/systutor-core/plugins/apps/backend/hardening \
  vendor/systutor-core/plugins/apps/backend/schemas.py \
  vendor/systutor-core/plugins/apps/backend/router.py \
  vendor/systutor-core/plugins/apps/backend/worker.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_hardening_engine.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_worker_github.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_deploy_source.py \
  scripts/spanel_apps.py scripts/tests/test_spanel_apps.py
git diff --check
```

## VALIDATION EVIDENCE

Verificación ejecutada desde el hilo principal tras la implementación:

```text
50 passed   scope: hardening engine + worker + deploy source + Apps CLI
100 passed  apps backend full suite
78 passed   existing hardener + app deploy suites
ruff        All checks passed
diff-check  clean
```

Cobertura relevante:

- El runner recibe argv exacto, `shell=False` y un entorno sin `GH_TOKEN`,
  `GITHUB_TOKEN` ni `SSH_AUTH_SOCK`.
- La respuesta sanitizada no contiene `source`, `backup` ni stderr.
- Exit 2, JSON inválido, timeout y evidencia incompleta se rechazan sin eco.
- Root UID/GID, traversal, modo world-writable, servicios duplicados y paths de
  servicios no declarados fallan antes de cualquier invocación.
- Endpoint `harden` es tenant-scoped, idempotente y persiste solo la política.
- `inspect` y `deploy` conservan sus suites originales.

## DEFINITION OF DONE

- [x] Contratos y adaptador fail-closed implementados.
- [x] Endpoint durable `harden` implementado sin migración.
- [x] Worker sanea credenciales y devuelve evidencia validada.
- [x] CLI API-first implementada con validación local.
- [x] Verificación declarada completa en verde.

## FOLLOW-UP (fuera de esta A.SPEC)

El deploy todavía no consume `HardenedCandidate`. El siguiente hito está
definido en `aspecs/0083-apps-trusted-deployment-pipeline.md`:
`TrustedRelease` firmada, guard de deploy, probes independientes y rollback.
Hasta que 0083 se implemente, ningún resultado de esta A.SPEC debe presentarse
como “deploy endurecido”.
