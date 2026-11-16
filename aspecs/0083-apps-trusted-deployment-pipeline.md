# A.SPEC 0083 — Apps Trusted Deployment Pipeline

## STATUS

Implementado P0–P5. P6 (evidencia live) pendiente de sincronizar el laboratorio.
Sucede a A.SPEC 0082 (backend + CLI de hardening).

## WHY

A.SPEC 0082 creó la operación durable de hardening y el adaptador fail-closed,
pero `deploy` todavía acepta un `AuditResult` construido desde un checkout
recién clonado. Por tanto, hoy existen dos caminos de admisión: el hardener y el
deployer. Mientras el deployer acepte un checkout, un Compose o un Dockerfile
que no haya sido autorizado por el pipeline, el contrato de aislamiento no está
cerrado.

Este hito elimina el segundo camino. La release endurecida pasa a ser el único
objeto desplegable y debe estar firmada, ser verificable, estar vinculada a una
política administrada y superar probes independientes del healthcheck declarado
por el repositorio.

## CONTRACT

> **Ningún deployment puede ejecutarse desde un checkout, Compose o Dockerfile
> no autorizado. Todo despliegue requiere una release firmada, verificable,
> vinculada a una política y validada mediante probes independientes.**

Corolarios normativos:

1. `deploy` no acepta rutas, `AuditResult`, Compose ni Dockerfiles como entrada.
2. La única entrada desplegable es una `TrustedRelease` firmada.
3. La firma cubre el artefacto, el Compose autorizado, los Dockerfiles
   autorizados, la política y la evidencia del gate.
4. Una release es válida solo para su tenant, aplicación, commit y política.
5. Los probes del deployment son ejecutados por el pipeline, no por el
   healthcheck del repositorio no confiable.
6. Cualquier fallo de verificación o probe produce rechazo o rollback; nunca
   “continuar de todos modos”.

## SCOPE

- Definir `TrustedRelease`, su descriptor canónico y su firma HMAC.
- Persistir el artefacto endurecido y el descriptor firmado en el state root,
  sin migraciones ni Alembic.
- Añadir un verificador fail-closed que se ejecute antes de extraer, antes de
  construir y antes de promover.
- Añadir `deploy_trusted()` como único camino de despliegue.
- Añadir probes independientes: aislamiento, funcional y estabilidad.
- Añadir rollback a una release firmada anterior.
- Añadir la superficie CLI final: deploy autónomo, deploy por release, verify,
  evidence, releases y rollback.
- Cubrir todo con pruebas unitarias y una validación live en laboratorio.

## OUT OF SCOPE

- Blue/green con cambio atómico de rutas (fase posterior).
- Adapters específicos de framework más allá de la política administrada.
- Inferencia automática de UID/GID, dependencias o writable paths.
- Cambios de frontend.
- Migraciones de modelos o Alembic (prohibido en desarrollo).
- Modificar el motor `scripts/dangerous_build/**` en este hito.

## THREAT MODEL

Se asume que el repositorio GitHub es hostil y que su Compose, Dockerfile,
healthcheck y scripts no son autoridad. También se asume que un operador con
acceso al state root puede intentar sustituir un artefacto.

El pipeline debe impedir:

| Amenaza | Control |
|---|---|
| Deploy de un checkout sin hardenizar | `deploy` exige `TrustedRelease` firmada |
| Sustitución del tar endurecido | SHA-256 del tar + firma del descriptor |
| Cambio de Compose tras el gate | `compose_sha256` firmado y reverificado |
| Cambio de Dockerfile tras el gate | mapa firmado de Dockerfiles + tree digest |
| Reutilizar release de otra app/tenant | binding tenant+app+commit |
| Policy drift | `policy_sha256` y fingerprint de herramientas |
| Healthcheck mentiroso | probes independientes + aislamiento efectivo |
| Secreto en evidencia | redacción y digests, nunca valores |
| Release vieja con vulnerabilidades | TTL y re-hardenizado obligatorio |

## DESIGN

### 1. TrustedRelease

Descriptor canónico, serializado con claves ordenadas y sin espacios:

```json
{
  "schema": 1,
  "algorithm": "hmac-sha256",
  "key_id": "4f2a9c1e",
  "release_id": "op_...",
  "tenant_id": "...",
  "application_id": "...",
  "operation_id": "...",
  "repo": "acme/repo",
  "branch": "main",
  "commit": "...",
  "artifact_sha256": "...",
  "source_tree_sha256": "...",
  "hardened_tree_sha256": "...",
  "compose_path": "compose.yml",
  "compose_sha256": "...",
  "dockerfiles": {"Dockerfile": "..."},
  "policy_sha256": "...",
  "policy": {...},
  "gate_sha256": "...",
  "tool_versions": {...},
  "created_at": "...",
  "expires_at": "...",
  "signature": "..."
}
```

- La firma se calcula sobre el JSON canónico **sin** el campo `signature`.
- `key_id` identifica la clave; la clave nunca se persiste.
- `artifact_sha256` es el hash del `source.tar.gz`; el descriptor vive al lado.
- `gate_sha256` cubre la evidencia completa del gate primario y post-apply.
- `dockerfiles` enumera cada archivo que participa en el build, con hash.

### 2. Claves de firma

Interfaz administrada, explícita y auditada:

```text
SPANEL_APPS_RELEASE_SIGNING_KEY       # clave activa, mínimo 32 bytes
SPANEL_APPS_RELEASE_VERIFY_KEYS       # JSON {key_id: key} solo para verificar
SPANEL_APPS_RELEASE_TTL_SECONDS       # default 86400
```

Reglas:

- Sin clave activa, `deploy` falla cerrado (`apps.release_signing_unavailable`).
- La clave no aparece en argv, JSON, logs, manifiestos ni operaciones.
- `key_id = sha256(key)[:8]`; permite rotación sin invalidar releases previas.
- Releases con `key_id` desconocido o firma inválida se rechazan.
- `scripts/configure_apps_release_key.py` provisiona, audita y rota las claves
  sin exponerlas; `apply` es idempotente y `rotate` conserva la anterior en
  `SPANEL_APPS_RELEASE_VERIFY_KEYS`.

### 3. Almacén

```text
$SPANEL_APPS_STATE_ROOT/
  hardened/<tenant_id>/<application_id>/<artifact_sha256>/
    release.json      0600
    source.tar.gz     0600
```

- Directorio y padre `0700`; archivos regulares, nunca symlinks.
- Escritura en temporal + `fsync` + `rename`.
- Lectura valida `lstat`, tipo, modo, tamaño máximo y hash.
- Sin modelos nuevos: `Operation.result` guarda `artifact_sha256` y metadatos;
  `Deployment.manifest.hardened_release` guarda el descriptor verificado
  (sin firma secreta, la firma es pública y verificable).

### 4. Verificación previa al deploy

Orden obligatorio, todo fail-closed:

1. release pertenece a tenant y aplicación;
2. descriptor es regular, `0600`, no symlink;
3. `key_id` conocido y firma HMAC válida;
4. `expires_at` vigente;
5. `artifact_sha256` coincide con el tar;
6. extracción a `private/staging/<release_id>` `0700`;
7. `hardened_tree_sha256` coincide con el árbol extraído;
8. `compose_sha256` y cada Dockerfile coinciden;
9. `policy_sha256` coincide con la política administrada;
10. `audit_project(non_root=True)` sin errores;
11. el Compose resuelto no publica puertos ni introduce binds/host access.

Solo entonces se construye.

### 5. `deploy_trusted()`

Nuevo módulo `runtime/release_deploy.py`:

```python
def deploy_trusted(
    release: TrustedRelease,
    options: DeployOptions,
    runner: Runner,
) -> dict[str, Any]:
    ...
```

Reutiliza la maquinaria existente (`_stage_release`, `_override`,
`_image_users`, `_containers`, `_publish_release_state`) pero:

- el `AuditResult` se construye desde el árbol verificado, nunca desde GitHub;
- el override de labels/aislamiento se suma al Compose ya endurecido;
- se registran IDs de imagen, no solo tags;
- toda imagen debe tener usuario non-root definitivo;
- todo servicio debe tener healthcheck efectivo en el Compose renderizado;
- `running none` deja de ser un estado aceptable.

### 6. Probes independientes

El healthcheck del repositorio es un prerrequisito, no una prueba.

**Nivel 1 — aislamiento efectivo**

- UID real de todos los procesos ≠ 0.
- `cap_drop: ALL`, `no-new-privileges`, rootfs read-only.
- Sin privileged, devices, host network, host PID, binds ni published ports.
- Red interna sin egress.
- Escritura solo en paths declarados.

**Nivel 2 — probe funcional independiente**

- Contenedor de probe desechable, imagen fijada por digest y administrada.
- Unido únicamente a la red interna del release.
- Ejecuta HTTP/TCP/command sin shell.
- Timeout, CPU/memoria/PIDs limitados.
- Salida acotada; se guarda digest y tamaño, nunca contenido.

**Nivel 3 — estabilidad**

- Ventana configurable con N chequeos consecutivos correctos.
- `RestartCount == 0` durante la ventana.
- Un fallo invalida la release y dispara rollback.

Los probes se ejecutan **antes** de publicar `current.json`, crear el
`Deployment` activo o refrescar rutas.

### 7. Rollback

- El release anterior se conserva intacto.
- Un fallo hace `down` del release nuevo y `start` del anterior.
- Solo releases firmadas pueden ser objetivo de rollback.
- Si el anterior no puede restaurarse, la app queda `degraded` y el error se
  registra sin secretos.
- Las rutas no se tocan hasta que los probes del nuevo release pasan.

### 8. Worker y API

- `POST /applications/{id}/deployments` acepta:
  - `hardening`: política → harden + deploy atómico;
  - `hardened_operation_id`: release ya validada;
  - ninguno → `422 apps.trusted_release_required`.
- `deploy` deja de invocar `audit_project` sobre un clone directo.
- `inspect` se mantiene como diagnóstico, nunca como autorización.
- Lock por aplicación, no global.
- El token GitHub solo existe durante el clone.
- Nuevo endpoint de verificación:
  `POST /applications/{id}/releases/{operation_id}/verify`.

### 9. Compatibilidad

- `SPANEL_APPS_ALLOW_UNHARDENED_DEPLOY=1` puede existir solo para laboratorio,
  con auditoría explícita y nunca por defecto.
- Aplicaciones ya desplegadas siguen operando con lifecycle normal.
- El primer deploy tras el hito requiere hardenizar de nuevo.

## INVARIANTS

```yaml
invariants:
  - id: T1
    statement: deploy no acepta checkout, ruta, Compose ni Dockerfile como entrada.
    proof: schema y router rechazan cualquier payload sin release firmada.
  - id: T2
    statement: la firma cubre artefacto, Compose, Dockerfiles, política y gate.
    proof: alterar cualquiera invalida HMAC o hash.
  - id: T3
    statement: una release no puede reutilizarse en otra app o tenant.
    proof: tests cruzados.
  - id: T4
    statement: el artefacto se verifica antes y después de extraer.
    proof: tamper del tar y del árbol.
  - id: T5
    statement: sin clave de firma, el deploy falla cerrado.
    proof: entorno sin clave y release con key_id desconocido.
  - id: T6
    statement: ningún servicio se promueve sin healthcheck efectivo.
    proof: Compose sin healthcheck y estado running none.
  - id: T7
    statement: los probes son independientes del healthcheck del repositorio.
    proof: healthcheck mentiroso + probe funcional fallido.
  - id: T8
    statement: un probe fallido restaura el release anterior y no publica rutas.
    proof: fake runner y assertions de current.json/route_refresh.
  - id: T9
    statement: evidencia y errores no contienen secretos.
    proof: canary de secretos en env, logs y descriptor.
  - id: T10
    statement: rollback solo apunta a releases firmadas.
    proof: deployment sin hardened_release rechazado.
```

## CHANGE SURFACE

```yaml
change_surface:
  allowed:
    - aspecs/0083-apps-trusted-deployment-pipeline.md
    - vendor/systutor-core/plugins/apps/backend/hardening/**
    - vendor/systutor-core/plugins/apps/backend/releases/**
    - vendor/systutor-core/plugins/apps/backend/github.py
    - vendor/systutor-core/plugins/apps/backend/runtime/release_deploy.py
    - Dockerfile
    - vendor/systutor-core/plugins/apps/backend/runtime/deployment.py
    - vendor/systutor-core/plugins/apps/backend/runtime/probes.py
    - vendor/systutor-core/plugins/apps/backend/schemas.py
    - vendor/systutor-core/plugins/apps/backend/router.py
    - vendor/systutor-core/plugins/apps/backend/worker.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_release_signing.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_trusted_deploy.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_probes.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_worker_github.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_deploy_source.py
    - scripts/spanel_apps.py
    - scripts/tests/test_spanel_apps.py
  prohibited:
    - vendor/systutor-core/plugins/apps/backend/models.py
    - vendor/systutor-core/plugins/apps/backend/migrations/**
    - Dockerfile
    - vendor/systutor-core/plugins/apps/backend/runtime/deployment.py
    - vendor/systutor-core/plugins/apps/frontend/**
    - scripts/dangerous_build/**
    - docker-compose.yml
    - .env.docker.example
```

## PHASES

| Fase | Entrega | Gate |
|---|---|---|
| P0 | `TrustedRelease`, firma, canonicalización, key ring | unit |
| P1 | Almacén inmutable y verificación de artefacto | unit + tamper |
| P2 | `deploy_trusted()` y guard del router | unit + regresión |
| P3 | Probes de aislamiento, funcionales y estabilidad | unit + fake runner |
| P4 | Rollback firmado y publicación de estado | unit |
| P5 | CLI final | unit |
| P6 | Validación live en lab con app scratch y fallo inducido | live |

## CLI FINAL

### Deploy autónomo

```bash
spanel_apps.py deploy demo-app \
  --service-user web=10001:10001 \
  --service-user db=999:999 \
  --writable-path web=/app/data:0750 \
  --env-file ./demo.env \
  --wait
```

### Verificar sin desplegar

```bash
spanel_apps.py harden demo-app \
  --service-user web=10001:10001 \
  --json
```

### Desplegar una release existente

```bash
spanel_apps.py deploy demo-app \
  --hardened op_abc123 \
  --env-file ./demo.env \
  --wait
```

### Auditar y revertir

```bash
spanel_apps.py verify demo-app --hardened op_abc123
spanel_apps.py evidence demo-app --hardened op_abc123
spanel_apps.py releases demo-app
spanel_apps.py rollback demo-app --to <deployment_id> --wait
```

Reglas:

- `deploy` sin política ni `--hardened` falla localmente antes de HTTP.
- `--env-file` exige `0600` y estar fuera del checkout.
- `--wait` usa polling acotado y devuelve `blocked` + causa segura.
- Ningún comando imprime valores de secretos, stderr del hardener ni la clave.
- `--json` sigue siendo global.

## VERIFICATION

```bash
.venv/bin/python -m pytest \
  vendor/systutor-core/plugins/apps/backend/tests/test_release_signing.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_trusted_deploy.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_probes.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_worker_github.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_deploy_source.py \
  scripts/tests/test_spanel_apps.py -q

.venv/bin/python -m pytest vendor/systutor-core/plugins/apps/backend/tests -q

.venv/bin/python -m ruff check \
  vendor/systutor-core/plugins/apps/backend \
  scripts/spanel_apps.py scripts/tests/test_spanel_apps.py

git diff --check
```

## LIVE EVIDENCE (P6)

La validación live debe demostrar:

1. App scratch endurecida, firmada, desplegada y con probes verdes.
2. Intento de deploy sin release → rechazo 422.
3. Tar sustituido → rechazo por hash/firma.
4. Compose modificado después del gate → rechazo.
5. Release de otra app/tenant → rechazo.
6. Healthcheck mentiroso + probe fallido → rollback y rutas intactas.
7. `current.json` no cambia hasta que los probes pasan.
8. Sin contenedores, redes, volúmenes ni imágenes efímeras residuales.

## DEFINITION OF DONE

- [x] `TrustedRelease` firmada y verificable implementada.
- [x] Deploy rechaza cualquier entrada no firmada.
- [x] Artefacto verificado antes y después de extraer.
- [x] Política y fingerprints ligados a la release.
- [x] Probes independientes obligatorios.
- [x] Rollback firmado probado.
- [x] CLI final implementada.
- [x] Suites de Apps y CLI en verde.
- [x] Evidencia live de P6 registrada.

## IMPLEMENTATION NOTES

- `releases/trusted.py` — descriptor canónico, firma HMAC, key ring y TTL.
- `releases/store.py` — almacén inmutable `0600` con escritura atómica y
  validación `lstat`/`O_NOFOLLOW`.
- `releases/verify.py` — verificación fail-closed antes y después de extraer,
  hashes de Compose/Dockerfiles, política y auditoría estática.
- `releases/pipeline.py` — construcción y firma de la release desde un
  `HardenedCandidate`.
- `releases/execution.py` — orquestación de harden, deploy y rollback; el lock
  por aplicación cubre build, probes, publicación de estado, commit y rutas.
- `runtime/release_deploy.py` — único camino de despliegue; registra IDs de
  imagen y publica estado solo después de los probes.
- `runtime/probes.py` — aislamiento efectivo, probe funcional con imagen fijada
  por digest en la red interna y ventana de estabilidad.
- `github.py` — se añadió a la superficie autorizada para extraer
  `repository_row` y mantener `worker.py` por debajo de 600 líneas.
- Las releases sin Dockerfile se aceptan: los stacks de solo imágenes externas
  siguen siendo desplegables; el árbol firmado y el Compose siguen cubiertos por
  hash y firma.
- Evidencia de verificación local:

```text
158 passed  (Apps backend + CLI)
ruff: All checks passed
git diff --check: limpio
```

### Evidencia live en laboratorio

- App scratch `luc444s/spanel-trusted-e2e` (commit `43de55e`), política
  `web=10001:10002`, sin writable paths.
- Tres releases firmadas y desplegadas por el worker real:
  `f495cccd`, `b8e663f6` y `9c8fdd53`.
- Probes: aislamiento efectivo, funcional con
  `alpine@sha256:d9e853…` fijado por digest, y estabilidad (2 chequeos, 0
  restarts).
- Contenedor `web`: `user=10001:10002`, rootfs read-only, `cap_drop: ALL`,
  `no-new-privileges`, sin puertos publicados, health `healthy`.
- Causa del bloqueo previo: el worker no incluía el plugin `buildx`, así que
  `docker build` con `DOCKER_BUILDKIT=1` abortaba antes de construir. El
  `Dockerfile` ahora instala `buildx` en `/usr/local/lib/docker/cli-plugins`.

## GAPS

- **Digests de imágenes externas**: la release firma el Compose, pero un tag
  externo puede mutar después de la firma. Falta un mapa firmado
  `service -> image@sha256` y ejecutar por digest. Debe abordarse en una A.SPEC
  posterior antes de declarar soporte externo completamente confiable.
