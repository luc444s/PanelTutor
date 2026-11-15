# A.SPEC 0086 — Apps Lab-Only Insecure Hardening Gate

## STATUS

Superseded por A.SPEC 0087 (isolation-only). Las excepciones de Trivy/Hadolint/
build ya no existen: la admisión es solo aislamiento. El código de 0086 fue
eliminado en 0087.

## WHY

El pipeline de A.SPEC 0083 es fail-closed: Trivy y Hadolint bloquean el deploy.
El repositorio real `luc444s/software-de-gestion-para-editores` tiene 25
vulnerabilidades HIGH, 1 CRITICAL y advertencias de Hadolint conocidas. Bloquear
el E2E hasta parchear el repositorio impide validar el resto del pipeline
(worker, release, probes, frontend) en el laboratorio.

Se necesitan **overrides de gate explícitos, auditados y exclusivos de
laboratorio** que permitan saltar Trivy y Hadolint sin abrir un bypass en
producción y sin relajar aislamiento, BuildKit ni probes.

## CONTRACT

1. Por defecto, cualquier override de gate se rechaza con
   `422 apps.insecure_hardening_forbidden`.
2. Solo se aceptan si el proceso que sirve la API/worker tiene
   `SPANEL_APPS_ALLOW_INSECURE_HARDENING=1`.
3. Los overrides permitidos son exactamente `skip_trivy`, `skip_hadolint` y
   `skip_build`. No hay forma de saltar aislamiento, probes ni usuario non-root.
   `skip_build` omite el build del gate; el deployment real sigue construyendo.
   `SPANEL_APPS_ALLOW_IMAGE_HEALTHCHECK=1` (lab-only) permite aceptar el
   `HEALTHCHECK` de la imagen cuando el Compose no declara uno; el probe de
   estabilidad sigue exigiendo el contenedor `healthy`.
4. El gate reporta el salto como `skipped: "insecure-override"`, nunca como
   `passed` silencioso.
5. La política firmada incluye `gate` y `policy_sha256` lo cubre; la release
   queda marcada `insecure: true`.
6. El frontend no ofrece estos overrides. Solo la API con el guard de entorno y
   el E2E de laboratorio los usan.
7. Los logs/auditoría de la operación registran el override, la operación y el
   actor. Nunca registran secretos.
8. Un release creado con overrides sigue exigiendo probes verdes y runtime
   non-root; el override no toca el nivel 1 ni el nivel 3.

## SCOPE

Motor:

- `scripts/dangerous_build/cli.py`: `harden` acepta `--skip-trivy`,
  `--skip-hadolint` y `--skip-build`. `_gate_payload` los usa para devolver
  resultados `available: true`, `blocking: 0`, `skipped: "insecure-override"`
  (o `attempted: false` en BuildKit).
- Tests del motor.

Backend:

- `HardeningPolicy` agrega `gate: GatePolicy | None`.
- `HardeningRequest` agrega `gate: HardeningGateRequest | None`.
- El router rechaza `gate` sin el guard de entorno.
- `worker.py` pasa la política al engine.
- `CommandHardeningEngine` agrega los flags al argv solo si `policy.gate` los
  declara.
- El reporte de operación y la evidencia muestran el override.

## OUT OF SCOPE

- Exponer overrides en el frontend.
- Permitir overrides por tenant, usuario o release sin el guard de entorno.
- Saltar probes, aislamiento, `cap_drop`, `no-new-privileges`, read-only o
  usuario non-root.
- Ignorar vulnerabilidades por ID/CVE; el único mecanismo es saltar el gate
  completo y queda auditado.
- Producción.

## DESIGN

### Política

```json
{
  "service_users": {
    "backend": {"uid": 10001, "gid": 10001},
    "frontend": {"uid": 101, "gid": 101},
    "database": {"uid": 70, "gid": 70}
  },
  "writable_paths": [
    {"service": "database", "path": "/var/run/postgresql", "mode": "0775"}
  ],
  "gate": {
    "skip_trivy": true,
    "skip_hadolint": true,
    "skip_build": true
  }
}
```

`gate` es opcional. Si falta, la política y el hash son idénticos a los de
A.SPEC 0083 (compatibilidad con releases existentes).

### Guard

```text
SPANEL_APPS_ALLOW_INSECURE_HARDENING=1   # solo laboratorio
```

- Sin el guard, `gate` en el payload → 422 `apps.insecure_hardening_forbidden`.
- Con el guard, el payload se acepta y se persiste en el reporte de la
  operación.
- El guard no se documenta en la UI ni se expone en `/auth/me`.

### Motor

```bash
dangerous-build-normalize harden <dir> --apply --format json \
  --service-user ... --writable-path ... \
  --skip-trivy --skip-hadolint --skip-build
```

Resultado del gate:

```json
"trivy": {"available": true, "blocking": 0, "skipped": "insecure-override", "findings": []},
"hadolint": {"available": true, "blocking": 0, "skipped": "insecure-override", "findings": []},
"buildkit": {"attempted": false, "passed": null, "services": [], "error": null}
```

`status` sigue siendo `passed` solo si el resto del gate pasa.

### Release

- `policy.as_dict()` incluye `gate` solo cuando existe.
- `release.policy` y `policy_sha256` cubren el override.
- El resumen de deployment expuesto por `catalog` incluye `insecure: true` y
  los overrides para que la UI muestre una advertencia.

## INVARIANTS

- `I1` Sin `SPANEL_APPS_ALLOW_INSECURE_HARDENING=1`, el override es imposible.
- `I2` Los únicos overrides son los tres booleanos declarados.
- `I3` Probes, aislamiento, read-only, cap_drop, no-new-privileges, non-root y
  BuildKit siguen siendo obligatorios.
- `I4` La release firmada y su evidencia registran el override.
- `I5` Ningún valor de entorno, secreto o stdout/stderr aparece en la respuesta.
- `I6` Una política sin `gate` conserva exactamente el hash anterior.

## CHANGE SURFACE

```yaml
change_surface:
  allowed:
    - aspecs/0086-apps-lab-insecure-hardening-gate.md
    - scripts/dangerous_build/cli.py
    - scripts/dangerous_build/compose.py
    - scripts/tests/test_dangerous_build_normalize.py
    - vendor/systutor-core/plugins/apps/backend/hardening/contracts.py
    - vendor/systutor-core/plugins/apps/backend/hardening/engine.py
    - vendor/systutor-core/plugins/apps/backend/schemas.py
    - vendor/systutor-core/plugins/apps/backend/router.py
    - vendor/systutor-core/plugins/apps/backend/worker.py
    - vendor/systutor-core/plugins/apps/backend/releases/pipeline.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_hardening_engine.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_deploy_source.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_worker_github.py
  prohibited:
    - vendor/systutor-core/plugins/apps/backend/models.py
    - vendor/systutor-core/plugins/apps/backend/migrations/**
    - vendor/systutor-core/plugins/apps/frontend/**
    - vendor/systutor-core/plugins/apps/backend/runtime/probes.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_probes.py
    - Dockerfile
    - docker-compose.yml
    - .env*
```

## VERIFICATION

```bash
.venv/bin/python -m pytest \
  scripts/tests/test_dangerous_build_normalize.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_hardening_engine.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_deploy_source.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_worker_github.py -q

.venv/bin/python -m ruff check \
  scripts/dangerous_build/cli.py \
  vendor/systutor-core/plugins/apps/backend/hardening \
  vendor/systutor-core/plugins/apps/backend/schemas.py \
  vendor/systutor-core/plugins/apps/backend/router.py \
  vendor/systutor-core/plugins/apps/backend/worker.py

git diff --check
```

Casos obligatorios:

- Sin guard + `gate` → 422.
- Con guard + `gate` → política aceptada y flags en argv.
- Sin `gate` → hash de política igual al de 0083.
- `skip_trivy` → gate no ejecuta Trivy y marca `skipped`.
- `skip_hadolint` → gate no ejecuta Hadolint y marca `skipped`.
- `skip_build` → gate no ejecuta BuildKit; el deployment sí construye y los
  probes siguen siendo obligatorios.
- Probes y aislamiento siguen fallando si el runtime no es seguro.

## VALIDATION EVIDENCE (LIVE)

- El hardener real aceptó el fixture `software-de-gestion-para-editores` con
  `--skip-trivy --skip-hadolint --skip-build` y política
  `backend=10001:10001`, `frontend=101:101`, `database=70:70`,
  writable `database=/var/run/postgresql:0775`.
- El gate reportó `trivy`/`hadolint` como `skipped: "insecure-override"` y
  BuildKit como `attempted: false`; la release quedó `insecure: true`.
- El deployment real construyó las imágenes con Compose (incluido el build arg
  `VITE_API_BASE_URL`) y los probes pasaron.
- Dos correcciones necesarias descubiertas en vivo:
  - Los writable paths efímeros bajo `/run` o `/var/run` se materializan como
    `tmpfs` con `uid`/`gid`, no como volúmenes, para no chocar con la auditoría
    de paths sensibles.
  - `SPANEL_APPS_ALLOW_IMAGE_HEALTHCHECK=1` acepta el `HEALTHCHECK` de la
    imagen cuando el Compose no lo declara; la estabilidad sigue exigiendo
    `healthy`.
- Sin el guard `SPANEL_APPS_ALLOW_INSECURE_HARDENING=1`, el router devuelve 422
  (cubierto por tests).

## ROLLBACK

Quitar los flags del motor, el campo `gate` del schema/política y el guard.
Las releases ya creadas con `gate` dejan de verificar si se elimina el campo del
descriptor; por eso el rollback debe conservar `from_dict` tolerante o marcar
esas releases como inválidas explícitamente. En laboratorio se recrean.

## DEFINITION OF DONE

- [x] Guard de entorno implementado y testeado.
- [x] Overrides solo `skip_trivy`/`skip_hadolint`/`skip_build`.
- [x] Motor marca `skipped` y no oculta el override.
- [x] Release firmada registra `gate` e `insecure`.
- [x] Sin `gate` el hash de política no cambia.
- [x] Probes y aislamiento intactos.
- [x] Suites y ruff en verde.
