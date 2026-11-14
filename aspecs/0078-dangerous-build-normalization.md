# A.SPEC 0078 — Dangerous Build Normalization and Anti-Root Hardening

> `risk: high` — detecta y (opcionalmente) reescribe Dockerfiles y Compose de
> repositorios no confiables. Un auto-fix erróneo puede romper builds, permisos
> de arranque o conectividad. Por defecto opera en modo dry-run y nunca sobrescribe
> sin `--apply` ni backup previo. Requiere `approver: luc444s` y falla cerrado.

## WHY

El repositorio ya cuenta con un auditor estricto para apps genéricas
(`scripts/app_deploy.py inspect` + `vendor/.../runtime/docker_audit.py`), pero
ese auditor **solo detecta**: no ofrece un camino para normalizar los artefactos
peligrosos a una forma segura. Los equipos terminan ignorando los hallazgos o
copiando Dockerfiles “que se quieren pasar de listos” (root implícito, `latest`,
`chmod 777`, `curl | sh`, mounts de docker.sock, puertos publicados, etc.).

Esta A.SPEC define un **motor de normalización de builds peligrosos** (detector +
auto-fixer) que:

1. Detecta Dockerfiles y `docker-compose*.yml` vulnerables o “demasiado listos”.
2. Clasifica cada hallazgo por riesgo de auto-fix (A/B/C).
3. Aplica automáticamente solo los de bajo riesgo y propone el resto como diff.
4. Trata el acceso a `docker.sock` como **prohibido por defecto**, con escape
   explícito y trazado.
5. Distingue secretos de Compose correctamente suministrados de archivos
   sensibles procedentes de un repo no confiable.
6. Reusa la lógica existente (`docker_audit.py`, `audit.py`) en lugar de
   duplicarla.

## WHAT

CLI independiente (script Python, sin dependencias de SPanel):

```bash
# Detección (ya existente, base)
python3 scripts/dangerous_build_normalize.py scan <path> \
  [--format text|json] [--fail-on high|medium|low] [--compose-file ...] \
  [--allow-docker-socket]

# Normalización (nuevo)
python3 scripts/dangerous_build_normalize.py fix <path> \
  [--apply] [--dry-run] [--uid 10001] [--gid 10001] [--out-dir .] \
  [--allow-docker-socket] [--allow-env-file] [--allow-published-ports] \
  [--deployment-copy] [--service-user SERVICE=USER]

# Gate integrado y fail-closed
python3 scripts/dangerous_build_normalize.py gate <path> \
  [--compose-file ...] [--non-root] [--require-build] \
  [--trivy-severity HIGH,CRITICAL] \
  [--hadolint-failure-threshold warning] [--skip-build] \
  [--format text|json]
```

- `scan` reporta hallazgos con severidad, archivo, línea, código y remediación.
- `fix` por defecto es **dry-run**: genera `Dockerfile.fixed`, `docker-compose.fixed.yml`
  y un diff unificado; nunca toca los originales.
- `fix --apply` crea `.bak` y sobrescribe; luego re-audita y reporta residual.
- `--deployment-copy` habilita la eliminación de accesos Nivel C únicamente en
  un checkout desechable destinado al despliegue. No debe ejecutarse sobre el
  repositorio canónico y queda fuera del modo `fix` normal.
- `--service-user SERVICE=USER` permite declarar de forma explícita el usuario
  no-root correcto de un servicio de imagen externa. No se adivinan usuarios.
- En `--deployment-copy`, antes del `USER` final se hace legible y atravesable
  el `WORKDIR` absoluto (`chmod -R a+rX`). Esto neutraliza modos `0700`
  heredados del checkout temporal sin hacer archivos escribibles.
- Al retirar un `env_file` del checkout, el servicio conserva
  `x-spanel-external-env: true`. El deployer transforma esa marca en el
  `app.env` privado staged fuera de la fuente; nunca vuelve a leer el archivo
  versionado.
- `gate` combina el auditor propio con Trivy (`vuln,misconfig,secret`) y
  Hadolint sobre todos los `Dockerfile*`, no solo los referenciados por Compose.
- Trivy y Hadolint son requisitos fail-closed. Si faltan, fallan o devuelven
  JSON inválido, el gate queda bloqueado sin construir.
- BuildKit se ejecuta con `DOCKER_BUILDKIT=1` únicamente cuando las tres capas
  estáticas están limpias. Cada imagen recibe un tag efímero que se elimina al
  terminar. `--skip-build` permite ejecutar solo la parte estática.
- El JSON consolidado no reproduce matches de secretos ni logs del build:
  expone código, ubicación, severidad y mensaje sanitizado.

## SCOPE

### 1. Detección (reuso de `runtime/docker_audit.py` y `runtime/audit.py`)

Reusar sin duplicar:

- `_dockerfile_instructions`, `_audit_dockerfile` (root final, HEALTHCHECK, ADD remoto,
  `curl|sh`, `chmod 777`, setuid/sudoers, ARG/ENV con nombres tipo secreto).
- `audit_project` (privileged, cap_add, devices, namespaces host, security_opt,
  mounts sensibles, docker.sock, binds absolutos/escape, env_file, secretos inline,
  build host network/entitlements, recursos externos, nombres fijos).

Reglas adicionales a incorporar (no cubiertas hoy):

- `dockerfile_base_latest`: `FROM ...:latest` o sin tag explícito → warning.
- `dockerfile_no_user_explicit`: ausencia total de `USER` (incluso intermedio) → info.
- `dockerfile_apt_no_cleanup`: `apt-get update` sin `rm -rf /var/lib/apt/lists/*`
  en la misma capa → info.
- `dockerfile_npm_no_cache`: `npm install` sin `--prefer-offline`/limpieza → info.
- `compose_published_port`: ya existe; por defecto **error** (bloqueante).
- `compose_env_file`: ya existe; por defecto **error solo si el archivo está dentro del checkout**.
  Si es una ruta absoluta o proporcionada por el administrador (fuera del checkout) con
  permisos restringidos, se permite con trazado (`--allow-env-file` o auto-detección).
- `compose_external_resource`: ya existe; por defecto **error** (B/C).
- `compose_secret_untrusted_source`: nuevo → `secrets:` con `file:` apuntando dentro
  del checkout → error/warning según origen.

### 2. Clasificación de auto-fix por riesgo

| Transformación | Nivel | Acción |
|---|---|---|
| Eliminar `container_name` | A | Directo (bajo riesgo, puede haber referencias externas). |
| Dockerfile `USER` final ausente | B | Insertar `USER <uid>:<gid>` al final del último stage (configurable). |
| Dockerfile sin `HEALTHCHECK` | B/C | Añadir placeholder con `TODO: ajustar endpoint`. |
| `chmod 777` → `755/644` | B | Reemplazo heurístico según path. |
| `ADD https://...` → `COPY` | B | Convertir + comentario de descarga/verificación previa. |
| `curl … \| sh` → pasos separados | B/C | Download + placeholder de hash + ejecución. |
| Eliminar `privileged: true` | B | Eliminar clave. |
| Eliminar `cap_add` | B | Eliminar clave. |
| Eliminar namespaces `host` | B | Eliminar clave. |
| Eliminar `ports:` | B | Eliminar/comentar (puede dejar app inaccesible). |
| Eliminar `env_file:` | B/C | Eliminar + comentario “usar env externo”. |
| Eliminar `security_opt` inseguro | B | Eliminar clave. |
| Eliminar `external: true` | B/C | Sugerir quitar `external` o renombrar. |
| Bind de docker.sock | C | Solo reportar; nunca auto-fix. |
| `secrets:` de Compose | C | Solo reportar; distinguir origen. |
| `ARG/ENV` con nombre tipo secreto | C | Solo reportar + sugerir inyección runtime. |
| Base `:latest` / sin pin | Info | Sugerir pin por digest (no auto). |
| Multi-stage ausente | Info | Sugerir (no auto). |

### 3. Política docker.sock (prohibido por defecto)

- `compose_docker_socket` → **error bloqueante**.
- CI: `scan` falla si hay docker.sock y no hay `--allow-docker-socket`.
- `--allow-docker-socket`: omite el error pero queda registrado en el reporte como
  “excepción documentada” (trazabilidad).
- El fixer normal nunca elimina el montaje automáticamente (Nivel C). El modo
  explícito `--deployment-copy` sí puede retirarlo de una copia desechable.
- Sugerir alternativas en el reporte: API Docker sobre TCP/TLS con certs restringidos,
  proxy/sidecar, rootless Docker, o servicio privilegiado mínimo para el deployer.

### 4. Secretos de Compose (distinción)

- **Secretos correctamente suministrados** (`secrets:` con `external: true` o
  referencias a secretos del orquestador) → **no tocar**, solo verificar origen.
- **Archivos sensibles de repo no confiable** (`secrets:` con `file:` apuntando al
  checkout, o montajes de claves) → reportar `compose_secret_untrusted_source`,
  sugerir migrar a secretos externos o env vars inyectadas por el runner.
- El fixer no elimina automáticamente el bloque `secrets`.

### 5. Estrategia de edición

- **Dockerfile**: manipulación por líneas/instrucciones (reusar `_dockerfile_instructions`),
  preservando formato/comentarios. Insertar `USER` antes del último `CMD`/`ENTRYPOINT`
  del último stage; añadir `HEALTHCHECK` placeholder; ajustar `chmod`.
- **Compose**: usar `ruamel.yaml` (preserva comentarios) si está disponible; fallback
  a PyYAML + warning. Aplicar solo eliminaciones Nivel B; dejar Nivel C como
  comentarios/sugerencias.
- **Dry-run por defecto**: escribe `*.fixed` + `*.patch` (diff unificado). No toca
  originales.
- **`--apply`**: crea `.bak`, sobrescribe, re-audita, reporta residual.
- **Re-audit** tras fix con `audit_project` y reportar qué quedó sin resolver.

### 6. Casos especiales a respetar

- Entrypoint que necesita root (puerto <1024, escritura en rutas del sistema): no
  forzar `USER`; reportar como C y sugerir `setcap` o cambiar puerto.
- Imágenes base no-root por defecto (distroless, chainguard): detectar y no duplicar
  `USER`.
- Builds multi-stage con `COPY --from`: no romper referencias al insertar `USER`.

## OUT OF SCOPE

- Construir o desplegar imágenes (eso es `app_deploy.py`).
- Soporte de Kubernetes/Swarm/rootless daemon.
- Reparar automáticamente Nivel C.
- Publicar dominio/TLS o abrir puertos públicos.
- Commit/push a repositorios externos.
- Reescribir Dockerfiles completos desde cero (solo parches dirigidos).

## CONTRACT

- **Precondición scan**: ruta válida, compose discoverable (o `--compose-file`).
- **Precondición fix**: scan previo recomendado; `--apply` requiere confirmación
  implícita (backup `.bak`).
- **Postcondición scan**: reporte estable (text/json), exit code ≠ 0 si hay errores
  (según `--fail-on`).
- **Postcondición fix (dry-run)**: archivos `*.fixed` + `*.patch` generados, originales
  intactos.
- **Postcondición fix (--apply)**: originales reemplazados con backup, re-audit
  ejecutado sobre los archivos aplicados y residual reportado.
- **Postcondición fix (dry-run)**: el re-audit se ejecuta sobre una copia temporal
  que contiene los artefactos corregidos, no sobre los originales.
- **Invariantes**: nunca modificar sin backup; nunca auto-fix Nivel C salvo en
  `--deployment-copy`; docker.sock prohibido por defecto.
- **Postcondición gate**: BuildKit solo se intenta si auditor propio, Trivy y
  Hadolint no bloquean; cualquier herramienta ausente o build fallido retorna 2.

## INVARIANTS

```yaml
invariants:
  - id: I1
    statement: Dry-run nunca modifica archivos originales.
    proof: tests con snapshot antes/después y verificación de .bak ausente.
  - id: I2
    statement: Nivel C nunca se auto-aplica en el modo normal.
    proof: tests sin --deployment-copy con --apply y assert sin cambios.
  - id: I3
    statement: docker.sock prohibido por defecto; escape requiere flag y trazado.
    proof: tests con/sin --allow-docker-socket y assert en reporte.
  - id: I4
    statement: Re-audit tras fix reporta residual real (sin falsos negativos).
    proof: tests con fixtures conocidos y assert de códigos residuales.
  - id: I5
    statement: No se duplica lógica de audit existente; se reusa runtime.
    proof: grep de imports y tests de paridad con app_deploy inspect.
  - id: I6
    statement: Secretos de Compose correctamente suministrados no se tocan.
    proof: tests con external: true y assert sin cambios.
  - id: I7
    statement: Un análisis estático bloqueado nunca ejecuta el Dockerfile.
    proof: test con hallazgo Hadolint y falso docker que no debe ser invocado.
  - id: I8
    statement: El gate no puede pasar si Trivy o Hadolint no están disponibles.
    proof: test con PATH vacío y estado consolidado blocked.
```

## VERIFICATION

```bash
cd /data/data/com.termux/files/home/Proyectos/mailadmin

.venv/bin/python -m pytest scripts/tests/test_dangerous_build_normalize.py -q

.venv/bin/python -m ruff check scripts/dangerous_build_normalize.py

python3 scripts/dangerous_build_normalize.py gate /path/to/checkout \
  --compose-file docker-compose.yml --non-root --require-build --format json

python3 scripts/dangerous_build_normalize.py scan /data/data/com.termux/files/usr/tmp/opencode/auditcopy \
  --compose-file docker-compose.yml --non-root --format json

python3 scripts/dangerous_build_normalize.py fix /data/data/com.termux/files/usr/tmp/opencode/auditcopy \
  --compose-file docker-compose.yml --dry-run
```

## ROLLBACK

- `fix --apply` crea `.bak`; restaurar con `mv Dockerfile.bak Dockerfile`.
- Revertir la A.SPEC elimina el script; los artefactos ya normalizados permanecen.
- Nunca ejecutar cleanup global de `*.fixed`/`*.bak` sin revisión.

## Change Surface

```yaml
change_surface:
  allowed:
    - aspecs/0078-dangerous-build-normalization.md
    - scripts/dangerous_build_normalize.py
    - scripts/tests/test_dangerous_build_normalize.py
  prohibited:
    - vendor/systutor-core/src/**
    - vendor/systutor-core/plugins/**
    - apps/**
    - docker-compose.yml
    - Dockerfile
    - .env*
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - repositorios analizados (lectura)
    - archivos Dockerfile/docker-compose (solo con --apply + backup)
  indirect:
    - pipelines CI que consuman el exit code
  must_not_affect:
    - contenedores/volúmenes/redes existentes
    - aplicación SPanel y su base de datos
    - secretos versionados
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: reusar runtime existente; no duplicar lógica de audit
  implementation_shape: un script monolítico scripts/dangerous_build_normalize.py
  line_limit: none
  package_split_prohibited: true
```

## Traceability

- Requirement: detector + auto-fixer de Dockerfiles/Compose peligrosos, anti-root,
  con política docker.sock prohibido y distinción de secretos.
- Base reusada: `scripts/app_deploy.py`, `vendor/.../runtime/docker_audit.py`,
  `vendor/.../runtime/audit.py`.
- owner: luc444s
- approver: luc444s

## Definition of Done

- [x] `scan` reporta hallazgos con archivo/línea/código/remediación.
- [x] `fix` dry-run genera `*.fixed` + `*.patch` sin tocar originales.
- [x] `fix --apply` crea backup y re-audita.
- [x] Nivel C nunca se auto-aplica en modo normal.
- [x] docker.sock prohibido por defecto; escape con flag y trazado.
- [x] Secretos correctamente suministrados no se tocan en modo normal.
- [x] Reuso de runtime existente verificado (sin duplicación).
- [x] Gate consolidado con Trivy, Hadolint y BuildKit fail-closed.
- [x] BuildKit queda detrás de las tres comprobaciones estáticas.
- [x] Suites offline verdes y `git diff --check` verde.

## Validation Evidence

- `pytest scripts/tests/test_dangerous_build_normalize.py -q`: 6 passed.
- Suite combinada con `scripts/tests/test_app_deploy.py`: 59 passed.
- `ruff check scripts/dangerous_build_normalize.py scripts/tests/test_dangerous_build_normalize.py`: green.
- Clon limpio de `luc444s/PanelTutor`: 12 errores antes; `fix --deployment-copy`
  termina con `findings=0 errors=0` sin modificar el checkout original.
