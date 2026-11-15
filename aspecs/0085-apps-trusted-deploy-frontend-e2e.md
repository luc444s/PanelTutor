# A.SPEC 0085 — Apps Trusted Deploy Frontend E2E

## STATUS

Implementado. Evidencia live registrada contra el lab. Depende de A.SPEC 0084
(frontend). La admisión es isolation-only (A.SPEC 0087): no hay overrides de
gate por CVEs.

## WHY

A.SPEC 0084 integra el pipeline de release firmada en el frontend. Las pruebas
unitarias de React no demuestran que el contrato completo funcione contra el
worker, Docker y los probes reales.

El E2E debe correr contra el fixture real
`luc444s/software-de-gestion-para-editores` (branch `feature/workflow-diseno`,
Compose `docker-compose.dokploy.yml`), un stack multi-servicio con build,
dependencias y healthchecks reales. Ese repositorio puede tener vulnerabilidades
o dependencias viejas dentro de sus contenedores: eso es responsabilidad del
dueño de la app y no bloquea la admisión. Lo que el E2E valida es firma,
aislamiento, probes y build real.

El test es black-box: **solo APIs del sistema**, con login real, y despliega en
el laboratorio.

## CONTRACT

1. Login real por HTTP(S) con email y password leído de archivo `0600`; el
   password y el token nunca se imprimen.
2. El test descubre instalación y repositorio GitHub reales mediante la API.
3. Crea una aplicación temporal con nombre único y la elimina al final.
4. Ejecuta `inspect` real y exige `services` no vacío.
5. La política cubre todos los servicios y usa el mismo formato que el
   frontend: `{service_users, writable_paths}`.
6. Un deploy sin `hardening` ni `hardened_operation_id` devuelve
   `422 apps.trusted_release_required`.
7. El deploy con política termina `succeeded`, devuelve `release_id`, hashes y
   `key_id`. La release no expone `advisories`, `insecure` ni `gate`.
8. El deployment activo queda `running`; los probes de aislamiento, funcional y
   estabilidad están verdes; los servicios son non-root y no publican puertos.
9. `POST /releases/{release}/verify` devuelve `status=valid`.
10. `GET /releases/{release}/evidence` responde sin valores de entorno.
11. Un redeploy con `hardened_operation_id` (camino “deploy release” del
    frontend) termina `succeeded`.
12. Un canario en `environment` no aparece en ninguna respuesta, evidencia ni
    error.
13. El cleanup elimina la aplicación y sus datos; la API responde 404 después.
14. Ningún fallo deja la aplicación temporal viva, salvo `--keep-failed`.

## SCOPE

- Runner black-box `scripts/e2e_apps_trusted_deploy.py`.
- Pruebas unitarias de helpers puros.
- Wrapper live opt-in.
- Reutiliza `ApiClient`, `E2EError`, `queue`, `poll_operation`,
  `read_password`, `validate_base_url`, `assert_no_secrets`,
  `expect_missing` y `environment` de `scripts/e2e_apps_api.py`, cargado por
  ruta con `importlib`. No se duplica login, polling ni entorno del fixture.
- No modifica `scripts/e2e_apps_api.py`.

## OUT OF SCOPE

- Navegador/Playwright; el contrato se valida por API, no por DOM.
- Cambios al motor, releases o probes (A.SPEC 0080–0083, 0087).
- Escaneo de CVEs o lint de Dockerfiles como condición de admisión.
- Producción. El E2E exige `--base-url` explícito y está pensado para el lab.
- Crear repositorios GitHub; usa uno existente del tenant.

## PRERREQUISITOS DEL LAB

En el contenedor `mailadmin-app` y `mailadmin-apps-worker` (o en su `.env`):

```text
SPANEL_APPS_PROBE_COMMAND=["wget","-qO-","http://frontend:8080/"]
```

- El healthcheck de la imagen se acepta por defecto; la estabilidad sigue
  exigiendo contenedores `healthy` y `RestartCount == 0`.
- El comando de probe debe apuntar a un servicio real del fixture. Para
  `software-de-gestion-para-editores` se usa `frontend:8080`.
- Reconstruir/reiniciar el worker tras cambiar el entorno.
- El fixture debe estar autorizado por la GitHub App del tenant.

## ENTORNO

```text
SPANEL_E2E_BASE_URL              URL de la API del lab (obligatoria)
SPANEL_E2E_EMAIL                 usuario real con permisos de Apps
SPANEL_E2E_PASSWORD_FILE         archivo 0600 con el password
SPANEL_E2E_REPOSITORY            default luc444s/software-de-gestion-para-editores
SPANEL_E2E_BRANCH                default feature/workflow-diseno
SPANEL_E2E_COMPOSE_FILE          default docker-compose.dokploy.yml
SPANEL_E2E_POLICY                JSON opcional; default abajo
SPANEL_E2E_ENV_JSON              JSON opcional; default environment() del fixture
SPANEL_E2E_OPERATION_TIMEOUT     default 900
SPANEL_E2E_DEPLOY_TIMEOUT        default 2400
SPANEL_E2E_KEEP                  si vale 1, conserva la app
SPANEL_E2E_KEEP_FAILED           si vale 1, conserva la app ante fallo
SPANEL_E2E_EVIDENCE              ruta opcional para evidencia 0600
```

Política por defecto:

```json
{
  "service_users": {
    "backend": {"uid": 10001, "gid": 10001},
    "frontend": {"uid": 101, "gid": 101},
    "database": {"uid": 70, "gid": 70}
  },
  "writable_paths": [
    {"service": "database", "path": "/var/run/postgresql", "mode": "0775"}
  ]
}
```

### Admisión isolation-only

No hay flags inseguros. El runner envía únicamente la política de aislamiento:

```json
{
  "hardening": {
    "service_users": {"...": {"uid": 1, "gid": 1}},
    "writable_paths": []
  }
}
```

- Trivy y Hadolint no participan de la admisión; una app con CVEs, PHP 5 o
  dependencias viejas se admite si su aislamiento y sus probes pasan.
- El runner falla si la release listada expone `insecure`, `gate` o
  `advisories`: esa metadata ya no debe existir.

## DESIGN

### Flujo

1. **Login**: `POST /api/v1/auth/login`; `GET /api/v1/auth/me`.
   Exige `apps.applications.read`, `apps.applications.create` y
   `apps.deployments.create`.
2. **Fuente**: recorre instalaciones y repositorios hasta encontrar
   `SPANEL_E2E_REPOSITORY`; falla si no está disponible.
3. **App temporal**: `POST /plugins/apps/applications` con nombre
   `Trusted E2E <hex>`, branch y `compose_file`. Guarda `id` y `slug`.
4. **Inspect**: `POST /applications/{id}/inspect` con Idempotency-Key; poll
   hasta `succeeded`. Exige `result.services` no vacío.
5. **Política**: `policy_for(services)` exige cobertura exacta;
   falla si falta o sobra un servicio.
6. **Negativo sin política**: `POST /deployments` con
   `{"environment": [...]}`; exige HTTP 422 y mensaje de release firmada.
7. **Deploy endurecido**: `POST /deployments` con
   `{"environment": environment + canary, "hardening": policy}`; poll hasta
   `succeeded`.
8. **Release**: valida `release_id` y hashes; la release listada no debe exponer
   `insecure`, `gate` ni `advisories`.
9. **Runtime**: `GET /applications/{id}`; `active_deployment.status=running`,
   `release` coincide, `probes` verdes, `service_details` con `user` non-root,
   sin `ports`, `restart_count=0`.
10. **Verify**: `POST /releases/{release}/verify`; exige `status=valid` y todos
    los checks verdaderos.
11. **Evidence**: `GET .../evidence`; `assert_no_secrets` con canario y
    password.
12. **Redeploy por release**: `POST /deployments` con
    `{"environment": [], "hardened_operation_id": release}`; poll
    `succeeded`.
13. **Cleanup**: `DELETE /applications/{id}` con
    `{confirm: slug, purge_data: true}`; poll; `GET /applications/{id}` → 404.
14. **Evidencia**: JSON 0600 con host, repo, commit, app slug, release,
    hashes, `admission`, `probe_command`, probes resumidos, cleanup y
    duración. Sin secretos ni valores de entorno.

### Verificación de probes

```text
probes.isolation[service].processes > 0
probes.functional.checks[*].returncode == 0
probes.functional.checks[*].bytes > 0
probes.stability.restart_counts[service] == 0
probes.stability.checks >= 1
```

### Cleanup y fallos

- `try/finally`: en fallo, cleanup best-effort salvo `KEEP_FAILED`.
- Si el cleanup falla, el E2E falla con app/slug para retiro manual, sin
  secretos.
- `--keep` omite el cleanup y imprime la orden de retiro.

## INVARIANTS

- `I1` Login y token nunca aparecen en stdout, stderr, evidencia ni argv.
- `I2` El único acceso externo es HTTP(S) a la API objetivo.
- `I3` El deploy exitoso exige release firmada y probes verdes; no hay bypass.
- `I4` El payload de deploy es idéntico al del frontend de A.SPEC 0084:
  `{environment, hardening}` con `service_users` y `writable_paths`.
- `I5` La app temporal no sobrevive a un éxito sin `--keep`.
- `I6` El canario de entorno no aparece en ninguna respuesta.
- `I7` Un 422 negativo no crea operación ni deployment.
- `I8` El E2E no usa flags inseguros ni envía `gate`.
- `I9` Los probes y el aislamiento son la única autoridad de admisión.

## RISKS

- **Lab sin el repo fixture**: falla antes de crear la app, con instrucción de
  instalar/actualizar la GitHub App.
- **Probe command incorrecto**: el deploy falla en probes; el E2E muestra un
  error seguro y el cleanup retira la app.
- **Dependencias viejas o CVEs**: no bloquean; se consideran riesgo del dueño
  de la app y quedan fuera de la evidencia de admisión.
- **Build lento** (npm + pip): `--deploy-timeout` por defecto 2400 s.
- **Cleanup con datos**: `purge_data=true` elimina solo la app creada por este
  E2E.

## CHANGE SURFACE

```yaml
change_surface:
  allowed:
    - aspecs/0085-apps-trusted-deploy-frontend-e2e.md
    - scripts/e2e_apps_trusted_deploy.py
    - scripts/tests/test_e2e_apps_trusted_deploy.py
    - scripts/tests/test_e2e_apps_trusted_deploy_live.py
  prohibited:
    - scripts/e2e_apps_api.py
    - vendor/systutor-core/plugins/apps/**
    - scripts/dangerous_build/**
    - docker-compose.yml
    - Dockerfile
    - .env*
```

## PHASES

| Fase | Entrega | Gate |
|---|---|---|
| P0 | Runner + helpers puros + unit tests | pytest + ruff |
| P1 | Wrapper live opt-in | pytest skip/collect |
| P2 | Corrida real contra lab con overrides y evidencia | live |

## VERIFICATION

```bash
.venv/bin/python -m pytest \
  scripts/tests/test_e2e_apps_trusted_deploy.py -q

.venv/bin/python -m ruff check \
  scripts/e2e_apps_trusted_deploy.py \
  scripts/tests/test_e2e_apps_trusted_deploy.py \
  scripts/tests/test_e2e_apps_trusted_deploy_live.py

git diff --check
```

Live en lab:

```bash
SPANEL_LIVE_TESTS=1 \
SPANEL_E2E_BASE_URL=http://127.0.0.1:3000 \
SPANEL_E2E_EMAIL=<admin> \
SPANEL_E2E_PASSWORD_FILE=/secure/e2e-password \
python3 scripts/e2e_apps_trusted_deploy.py \
  --evidence /secure/evidence/trusted-deploy-e2e.json
```

Desde fuera del lab, `SPANEL_E2E_BASE_URL=https://spanel.lab`.

Resultado esperado:

```text
login ok
source luc444s/software-de-gestion-para-editores
app created (slug)
inspect: succeeded
negative deploy without policy: 422 apps.trusted_release_required
deploy hardened: succeeded (release ...)
verify: valid
evidence: ok
redeploy release: succeeded
cleanup: application deleted
E2E OK
```

## VALIDATION EVIDENCE (LIVE)

- Lab `100.67.5.50`, API `http://127.0.0.1:3000`.
- Fixture `luc444s/software-de-gestion-para-editores`, branch
  `feature/workflow-diseno`, commit `2f1c615`.
- App temporal `trusted-e2e-c381080a75`; cleanup verificado con 404.
- Release `ad49a372-b5a9-43b9-8541-4f71a9944819`, firmada.
- Admisión isolation-only: sin `gate`, sin `insecure`, sin `advisories`.
- Probes: 2 chequeos funcionales, 3 servicios, 0 restarts.
- Usuarios efectivos: `backend=10001:10001`, `frontend=101:101`,
  `database=70:70`.
- `verify: valid`; evidence sin secretos; redeploy por release `succeeded`.
- `E2E OK` en 79.9 s.

Requisito de lab usado:
`SPANEL_APPS_PROBE_COMMAND=["wget","-qO-","http://frontend:8080/"]`.

## ROLLBACK

El runner no modifica código ni infraestructura permanente. Si se interrumpe,
el cleanup explícito es:

```bash
python3 scripts/spanel_apps.py delete <application_id> --purge-data --wait
```

## DEFINITION OF DONE

- [x] Login real y permisos validados.
- [x] Repo `software-de-gestion-para-editores` descubierto por API.
- [x] App temporal creada, inspeccionada y desplegada con política.
- [x] 422 negativo sin política verificado.
- [x] Overrides de gate eliminados; el deploy se admite por aislamiento,
      firma y probes.
- [x] Release firmada sin `insecure`/`advisories`; probes verdes y runtime
      non-root verificados.
- [x] Verify y evidence OK, sin secretos.
- [x] Redeploy por `hardened_operation_id` OK.
- [x] Cleanup verificado con 404.
- [x] Unit tests, ruff y live E2E en verde.
- [x] Evidencia registrada en esta A.SPEC.
