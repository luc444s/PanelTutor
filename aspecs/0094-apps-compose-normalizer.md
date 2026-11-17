# A.SPEC 0094 — Apps Compose Normalizer

> `risk: high` — se inserta antes del hardener y cambia qué Compose se firma y
> ejecuta. Requiere E2E real y aprobación humana.

## STATUS

Implementada y aceptada en `spanel.lab` (2026-11-16). Evidencia en
`artifacts/apps-compose-normalizer-pos-e2e.json`.

Caso que la motiva: desplegar `satisfecho/pos` sin modificar su repo ni sus
YAML. El hardener actual elimina `container_name`, binds, `ports` y `sysctls`,
pero no ofrece un reemplazo compatible: los servicios siguen buscando
`pos-back`, HAProxy pierde `haproxy.cfg` y no puede bindear `:80` como non-root.

## WHY

Los repos reales traen supuestos de Docker Compose que el aislamiento del panel
no puede aceptar tal cual:

- `container_name` usado como DNS interno,
- archivos de configuración montados desde el checkout,
- HAProxy/Nginx propios escuchando en puertos privilegiados,
- `ports` publicados, redes externas, binds de código y `.env` del repo.

Hoy el harden “gana” eliminando esas construcciones, pero deja una app que
arranca rota o no arranca. El dueño de la app no debería tener que reescribir
su Compose para probarla en el panel, y el panel no debería ejecutar un proxy
ajeno como ingress externo.

La normalización debe ocurrir **antes** del hardening, sobre una copia, para
que el harden audite exactamente lo que se va a ejecutar.

## WHAT

Una etapa determinista `normalize(compose) -> normalized_compose` que:

1. transforma una copia del Compose seleccionado;
2. preserva la compatibilidad interna de la app sin ceder aislamiento;
3. deja evidencia auditable y firmable de cada regla aplicada;
4. falla cerrado si una transformación no puede probarse segura;
5. nunca modifica el repositorio, sus archivos ni su Compose original.

Orden del pipeline:

```
clone
  -> detect source/compose
  -> normalize(compose)        <- esta spec
  -> harden(normalized)
  -> build
  -> verify (firma el compose normalizado + endurecido)
  -> deploy / probes
```

## SCOPE

- Módulo de normalización y su contrato de reglas.
- Integración en el worker entre la selección/adaptación de fuente y `harden`.
- Evidencia de normalización en el release y en el manifiesto.
- Reglas de compatibilidad de esta primera entrega:
  - `N1` alias DNS desde `container_name`;
  - `N2` inyección pre-start de archivos read-only desde el checkout;
  - `N3` sysctl de puertos no privilegiados;
  - `N4` propiedad del ingress externo por el panel;
  - `N5` servicios one-shot (ya implementados; se referencian).
- Tests unitarios por regla y E2E live con POS sin tocar su repo.
- Ajustes mínimos en el hardener y en la verificación/probes para aceptar
  exactamente las construcciones normalizadas.

## OUT OF SCOPE

- Buildpacks o source-only (Railpack/Nixpacks): spec separada.
- Merge de múltiples Compose (`-f base -f overlay`): sigue siendo un archivo.
- Generar archivos de configuración que la app espera y no están en el repo.
- Poda automática de servicios o “modo compatibilidad” heurístico.
- Permitir `cap_add`, `privileged`, host namespaces, binds de directorios,
  binds rw, `docker.sock`, puertos publicados o redes externas.
- Cambios al contrato de firma distintos de incluir el Compose normalizado.
- Migraciones de base de datos o cambios de esquema.

## CONTRACT

Precondiciones:

- el checkout staged contiene un Compose seleccionado y parseable;
- la política de usuarios runtime ya fue resuelta para todos sus servicios;
- el hardener trabaja sobre una copia transaccional y conserva el checkout si
  cualquier gate falla.

Postcondiciones:

- el Compose que recibe el hardener contiene las adaptaciones N1–N4 y ninguna
  adaptación fuera de esta spec;
- el Compose final y la evidencia de reglas quedan cubiertos por la firma del
  release;
- ningún bind llega al runtime y un sysctl no permitido sigue bloqueando el
  release;
- el repositorio remoto y el YAML fuente permanecen byte a byte intactos.

Verdad nueva falsable: una app Compose puede conservar aliases internos,
archivos de configuración inyectados de forma inmutable y listeners non-root
en puertos bajos sin obtener nombres globales, capacidades, binds al host ni
puertos publicados.

### Determinismo e idempotencia

- La misma entrada y las mismas reglas producen el mismo Compose normalizado
  (YAML canónico, orden estable).
- `normalize(normalize(x)) == normalize(x)`.
- El panel nunca escribe en el checkout original. Trabaja sobre la copia
  staged de la release.

### Evidencia

Cada ejecución produce:

```json
{
  "schema": 1,
  "source_sha256": "<sha256 del compose original>",
  "normalized_sha256": "<sha256 del compose normalizado>",
  "rules": [
    {"id": "N1", "applied": true, "services": ["back"], "details": {"alias": "pos-back"}}
  ],
  "warnings": [],
  "rejected": []
}
```

La evidencia y el Compose normalizado se guardan en el release firmado y se
exponen en el manifiesto. Un `rejected` no vacío aborta el deploy.

### Reglas

#### N1 — `container_name` como alias de red

- Entrada: `services.<svc>.container_name`.
- Transformación:
  - se elimina `container_name` del runtime;
  - se agrega el nombre como alias en la red interna del proyecto:
    ```yaml
    networks:
      default:
        aliases: [pos-back]
    ```
- Validación:
  - DNS label válido (`[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}`);
  - único dentro del proyecto;
  - no colisiona con el nombre de otro servicio;
  - no es un nombre reservado del panel.
- Si no valida: warning y se descarta el alias; el deploy puede fallar después
  por DNS, con mensaje claro.
- Seguridad: el alias vive solo en la red interna del proyecto; no cambia el
  nombre global del contenedor ni crea nombres compartidos entre tenants.

#### N2 — Inyección read-only de archivo dentro del checkout

- Entrada: entrada de `volumes` con forma `./ruta:/destino[:ro]`.
- Se registra para inyección **solo** si:
  - el source es relativo al directorio del Compose seleccionado y resuelve a
    un **archivo regular** dentro de la copia staged;
  - el target es absoluto;
  - el modo es `ro`;
  - el source no es symlink que escape del checkout;
  - no es `docker.sock` ni una ruta sensible (`/`, `/proc`, `/sys`, `/dev`,
    `/var/run` como target).
- El bind se elimina del Compose final y se reemplaza por metadata firmada
  `x-spanel-readonly-files` con `source` y `target` canónicos.
- El runtime ejecuta `compose create`, obtiene el contenedor detenido del
  servicio, copia el archivo desde la release verificada con modo `0444` y
  luego ejecuta `compose up -d --no-recreate`.
- La copia usa `docker cp` (stream cliente→daemon), no una ruta host interpretada
  por Docker. Esto funciona aunque el release viva en un named volume del
  worker.
- Se elimina todo bind de directorio, rw, absoluto o fuera del checkout.
- `check_isolation` y la verificación efectiva continúan rechazando **todos**
  los binds.
- Si el archivo no existe en la copia: se elimina el bind y se emite warning;
  la app falla más adelante si lo necesita.

#### N3 — Sysctl para puertos privilegiados

- Entrada: `expose`/`ports` con algún puerto de contenedor `< 1024`.
- Transformación: agregar al servicio:
  ```yaml
  sysctls:
    net.ipv4.ip_unprivileged_port_start: "0"
  ```
- Solo se permite ese sysctl namespaced. Cualquier otro `sysctls` de la app se
  elimina.
- No se agrega `cap_add` ni `privileged`; el contenedor sigue non-root y con
  `cap_drop: ALL`.
- La app puede bindear 80/443 **dentro de su netns**; el ingress externo sigue
  siendo del panel.

#### N4 — El ingress externo es del panel

- El Compose normalizado no publica puertos al host; `ports` se convierte en
  `expose` (comportamiento actual del hardener, explicitado).
- El proxy propio de la app (HAProxy/Traefik/Nginx) puede correr **interno**
  para compatibilidad, pero nunca es el ingress externo del panel.
- El ingress que el panel publica es el declarado en la app
  (`ingress_service`/`ingress_port`), que es metadata del panel, no un YAML.
- No se podan servicios automáticamente en esta versión. Si un servicio de
  ingress propio no puede correr, el deploy falla con un error explícito; el
  operador puede cambiar el ingress declarado o adaptar la app.
- La ruta externa se publica solo después de que el ingress declarado y sus
  dependencias estén sanos.

#### N5 — Servicios one-shot

- Se reconocen por `x-spanel-one-shot: true` o por
  `depends_on: {condition: service_completed_successfully}`.
- El normalizador no los transforma; la readiness, probes y manifiesto ya los
  tratan como init: se espera `exited 0`, se excluyen de isolation/estabilidad
  y se registran con `one_shot: true`.

#### H1 — Hardening del usuario runtime y su WORKDIR

- Si el Dockerfile declara un `USER` numérico, se respeta.
- Si no declara usuario, el hardener inyecta el fallback non-root `1000:1000`;
  nunca se permite root implícito.
- Al inyectar ese usuario, los `COPY`/`ADD` de la etapa final sin `--chown`
  reciben `--chown=uid:gid`, y el `WORKDIR` final absoluto seguro recibe
  `RUN chown uid:gid <workdir>` (no recursivo) antes de `USER`.
- Esto preserva la escritura de entrypoints que modifican archivos copiados
  (caso POS `front`) sin modificar el repositorio ni aceptar root.

#### H3 — Resultado de operación serializable

- `release_result` debe devolver estructuras JSON puras. `tool_versions` está
  congelado con `MappingProxyType` anidados; copiarlo superficialmente rompe la
  persistencia del resultado (TypeError al guardar en la BD) aunque el deploy
  ya haya terminado bien.
- Se usa el cuerpo firmado ya descongelado (`release.body`) para
  `normalization` y se añade test de serialización.

#### H2 — Volúmenes anónimos con nombre determinista

- Un volumen de servicio sin `source` (`/app/node_modules`) se convierte en un
  volumen gestionado `spanel-<service>-<hash>` declarado en `volumes`.
- El nombre es determinista, queda dentro del project scope y `delete
  --purge-data` puede eliminarlo; no se acumulan volúmenes anónimos huérfanos.
- No se usa `nocopy` para estos volúmenes: el contenido imagen debe seguir
  disponible en el primer arranque.

### Invariantes de seguridad

Después de normalizar y harden:

- no hay `privileged`, `cap_add`, `devices`, host namespaces ni `docker.sock`;
- no hay binds efectivos de ningún tipo;
- las inyecciones read-only solo leen archivos regulares dentro del release y
  producen archivos root-owned modo `0444` antes del arranque;
- solo el sysctl namespaced de N3;
- no hay `ports` publicados;
- una sola red interna;
- todos los servicios corren non-root;
- el ingress externo lo controla el panel.

### Fallo cerrado

- Si una transformación no puede validarse, se rechaza con código y mensaje
  públicos; no se aplica una variante insegura.
- Si el Compose normalizado no pasa el harden o la verificación, el deploy
  falla antes de crear contenedores.

## INVARIANTS

```yaml
invariants:
  - id: I1
    statement: Ningún servicio publica puertos al host ni usa una red externa.
    proof: tests de hardener y verificación estática del Compose final.
  - id: I2
    statement: Ningún contenedor efectivo contiene binds; solo se inyectan archivos regulares firmados con modo 0444 antes del arranque.
    proof: tests positivos y negativos de normalize, create/cp/up, verify_release y check_isolation.
  - id: I3
    statement: privileged, cap_add, devices, host namespaces y docker.sock continúan bloqueados.
    proof: fixture negativa y regresión del hardener.
  - id: I4
    statement: Todos los servicios continúan non-root, cap_drop ALL y no-new-privileges.
    proof: tests de hardener y probes de aislamiento.
  - id: I5
    statement: Compose sin container_name, binds de archivo ni puertos bajos conserva el resultado previo salvo evidencia canónica.
    proof: tests de regresión existentes e idempotencia.
  - id: I6
    statement: El repo remoto y el Compose fuente nunca son escritos; solo cambia el checkout staged transaccional.
    proof: test que compara bytes fuente antes/después de preview y rollback.
```

## DESIGN

### Flujo

1. El worker clona el repo y selecciona el Compose (raíz, elegido o adaptado).
2. `normalize` lee el YAML y produce `normalized_compose` + evidencia.
3. El hardener consume el Compose normalizado y produce el envelope de
   aislamiento (usuarios, caps, volúmenes gestionados, red interna).
4. `verify_release` firma el árbol endurecido y valida que el Compose final
   cumpla los invariantes.
5. El manifiesto registra `normalization` y `one_shot`.

### Cambios necesarios

- Nuevo módulo `plugins/apps/backend/compose_normalizer.py` con:
  - `normalize_compose(text, checkout_root) -> NormalizationResult`;
  - reglas puras e idempotentes;
  - códigos `normalize_*` para evidencia y errores.
- Integración en `worker._source_operation` antes de `audit_project`/harden.
- `scripts/dangerous_build/compose.py`: preservar los alias, metadata de
  inyección y el sysctl normalizado; no reintroducir binds descartados;
  nombrar volúmenes anónimos (H2).
- `scripts/dangerous_build/dockerfile.py`: respetar el `USER` numérico del
  Dockerfile y, al inyectar el fallback non-root, alinear `COPY --chown` y la
  propiedad del `WORKDIR` final (H1).
- `releases/verify.py` (`_assert_compose_hardened`): validar la metadata de
  inyección contra el release firmado y permitir solo el sysctl namespaced.
- `runtime/release_deploy.py` y `runtime/deployment.py`: crear contenedores,
  inyectar archivos con copia temporal `0444` y arrancar sin recrear.
- `releases/scoped_execution.py`: la ruta scoped/incremental debe aplicar la
  misma secuencia `rm -sf → create → cp → up --no-recreate` para los servicios
  efectivos; si no, un `up -d` directo pierde la inyección y el servicio
  (p. ej. HAProxy) arranca sin su archivo firmado. La versión de Compose del
  worker no acepta `--no-deps` en `create`; sí en `up`.
- `runtime/probes.py` (`check_isolation`): rechazar todos los binds efectivos y
  permitir solo el sysctl namespaced.
- `runtime/types.py`: helpers compartidos (`volume_is_host_bind`,
  `readonly_release_file`, `one_shot_services`, alias/port helpers).
- Frontend: exponer warnings/evidencia de normalización en la operación
  (opcional para esta entrega).

### Casos de POS que cubre

- `pos-back`, `pos-front`, `pos-ws-bridge` → alias N1; el `proxy_pass` de Nginx y
  los `server ... pos-*` de HAProxy resuelven.
- `haproxy.cfg` y `CHANGELOG.md` → inyección pre-start N2, sin host bind.
- `bind *:80` de HAProxy y Nginx → sysctl N3.
- Ingress externo → metadata del panel N4; HAProxy queda interno o se enruta a
  `front`.

## TESTS

### Unitarios

- N1: alias válido, duplicado, colisión con servicio, label inválido.
- N2: archivo ro dentro del checkout, incluido Compose anidado; metadata
  firmada, orden `create → docker cp → up --no-recreate`; rechazo de
  directorio, rw, ruta absoluta, symlink que escapa, `docker.sock`, target
  sensible y archivo inexistente.
- N3: puerto <1024 agrega sysctl; puerto >=1024 no; sysctl de la app se elimina;
  no se agregan caps.
- N4: `ports` desaparecen; no se publica nada.
- N5: one-shot por extensión y por dependencia.
- Idempotencia y determinismo del YAML.
- La evidencia incluye reglas, warnings y hashes.

### Integración / E2E live

Fixture positiva: `satisfecho/pos` sin tocar el repo ni sus YAML.

Debe demostrar:

1. inspect y harden exitosos;
2. deploy con `ws-bridge` resolviendo `pos-back`;
3. HAProxy/Nginx arrancando con `haproxy.cfg` modo 0444, sin binds, y puerto 80 interno;
4. ingress del panel respondiendo HTTPS;
5. `/api` y `/ws` funcionando a través del ingress;
6. probes de aislamiento, funcionales y estabilidad verdes;
7. rerun idempotente y cleanup total.

Fixture negativa: Compose con bind de directorio, bind rw, `docker.sock`,
`privileged`, puerto publicado y alias inválido. Debe rechazar con códigos
claros y sin contenedores huérfanos.

## VERIFICATION

```bash
.venv/bin/python -m pytest \
  scripts/tests/test_compose_normalizer.py \
  scripts/tests/test_dangerous_build_normalize.py \
  scripts/tests/test_transactional_build_hardener.py -q

cd vendor/systutor-core && ../../.venv/bin/python -m pytest \
  plugins/apps/backend/tests/test_compose_normalizer.py \
  plugins/apps/backend/tests/test_hardening_engine.py \
  plugins/apps/backend/tests/test_trusted_deploy.py \
  plugins/apps/backend/tests/test_probes.py \
  plugins/apps/backend/tests/test_volume_binds.py \
  plugins/apps/backend/tests/test_one_shot.py -q

.venv/bin/python -m ruff check \
  scripts/dangerous_build/compose.py \
  scripts/dangerous_build/compose_normalizer.py \
  scripts/dangerous_build/dockerfile.py \
  scripts/dangerous_build/hardener.py \
  scripts/tests/test_compose_normalizer.py \
  vendor/systutor-core/plugins/apps/backend/compose_normalizer.py \
  vendor/systutor-core/plugins/apps/backend/hardening/engine.py \
  vendor/systutor-core/plugins/apps/backend/releases/pipeline.py \
  vendor/systutor-core/plugins/apps/backend/releases/verify.py \
  vendor/systutor-core/plugins/apps/backend/runtime/probes.py

git diff --check
```

El worker del lab **debe** recrearse con el mismo stack que la API, o montará
otro volumen de estado y la API no verá los releases:

```bash
docker compose -p spanel \
  -f docker-compose.yml -f docker-compose.powerdns.yml \
  -f docker-compose.lab-local.yml \
  --env-file .env.docker --env-file .env.powerdns \
  up -d --no-deps apps-worker

# verificación: debe montar mailadmin_apps_state, no spanel_apps_state
docker inspect spanel-apps-worker-1 \
  --format '{{range .Mounts}}{{.Name}} -> {{.Destination}}; {{end}}'
```

Live black-box, después de publicar/reiniciar el worker y solo cuando no haya
otro E2E activo:

```bash
SPANEL_E2E_BASE_URL=https://spanel.lab \
SPANEL_E2E_REPOSITORY=satisfecho/pos \
SPANEL_E2E_BRANCH=master \
SPANEL_E2E_COMPOSE_FILE=docker-compose.yml \
SPANEL_E2E_EMAIL="$SPANEL_E2E_EMAIL" \
SPANEL_E2E_PASSWORD_FILE="$SPANEL_E2E_PASSWORD_FILE" \
.venv/bin/python scripts/e2e_apps_trusted_deploy.py \
  --evidence artifacts/apps-compose-normalizer-pos-e2e.json
```

## ROLLBACK

Revertir únicamente los archivos de esta A.SPEC y reconstruir/reiniciar el
worker. Los releases existentes conservan su descriptor y siguen verificando.
La publicación transaccional del hardener debe restaurar el Compose previo si
falla durante apply. El E2E elimina su app temporal; ante interrupción se usa
`python3 scripts/spanel_apps.py delete <application_id> --purge-data --wait`.

No hay migración ni cambio de esquema de base de datos.

## Change Surface

```yaml
change_surface:
  allowed:
    - scripts/dangerous_build/compose.py
    - scripts/dangerous_build/compose_normalizer.py
    - scripts/dangerous_build/dockerfile.py
    - scripts/dangerous_build/hardener.py
    - scripts/dangerous_build/transaction.py
    - scripts/tests/test_compose_normalizer.py
    - scripts/tests/test_dangerous_build_normalize.py
    - scripts/tests/test_transactional_build_hardener.py
    - vendor/systutor-core/plugins/apps/backend/compose_normalizer.py
    - vendor/systutor-core/plugins/apps/backend/hardening/contracts.py
    - vendor/systutor-core/plugins/apps/backend/hardening/engine.py
    - vendor/systutor-core/plugins/apps/backend/releases/execution.py
    - vendor/systutor-core/plugins/apps/backend/releases/pipeline.py
    - vendor/systutor-core/plugins/apps/backend/releases/scoped_execution.py
    - vendor/systutor-core/plugins/apps/backend/releases/verify.py
    - vendor/systutor-core/plugins/apps/backend/runtime/probes.py
    - vendor/systutor-core/plugins/apps/backend/runtime/deployment.py
    - vendor/systutor-core/plugins/apps/backend/runtime/release_deploy.py
    - vendor/systutor-core/plugins/apps/backend/runtime/types.py
    - vendor/systutor-core/plugins/apps/backend/worker.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_compose_normalizer.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_hardening_engine.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_trusted_deploy.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_probes.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_volume_binds.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_one_shot.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_scoped_planner.py
    - artifacts/apps-compose-normalizer-pos-e2e.json
  prohibited:
    - vendor/systutor-core/alembic/**
    - vendor/systutor-core/migrations/**
    - vendor/systutor-core/plugins/apps/frontend/**
    - apps/web/**
    - docker-compose.yml
    - docker-compose.powerdns.yml
    - repositorios de aplicaciones clonados o remotos
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - Compose hardening y release verification de Apps
    - probes de aislamiento de Apps
  indirect:
    - manifests y evidencia de deployments de Apps
    - compatibilidad de repos Compose existentes
  must_not_affect:
    - publicación de puertos y aislamiento de red
    - bloqueo de mounts y privilegios inseguros
    - runtime non-root y límites de recursos
    - repositorio y YAML fuente
```

## Composition

```yaml
composition:
  requires_aspecs: [0087, 0089]
  must_compose_with: [0093]
  systemic_invariants:
    - isolation-only admission remains fail-closed
    - one-shot services remain excluded only after successful completion
  composition_checks:
    - backend verification suite listed above
    - POS black-box deploy without repository modifications
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: normalización de compatibilidad separada del hardening de aislamiento
  entrypoints_must_stay_thin: true
  review_threshold_lines: 400
  extraction_threshold_lines: 600
  preferred_new_logic_locations:
    - scripts/dangerous_build/compose_normalizer.py
    - vendor/systutor-core/plugins/apps/backend/compose_normalizer.py
```

## Traceability

- Requirement: ejecutar repos Compose raros sin modificar el repo ni sus YAML.
- owner: Apps platform implementation agent
- approver: human requester (explicit implementation authorization, 2026-11-16)
- Commit: pending
- Deployment: aceptado en `spanel.lab` — POS `luc444s/pos@6d3c951`, release
  `65d2e37a-a750-46dc-80c9-f0a0ef855ba4`, 6 servicios, probes verdes,
  verificación de firma válida, redeploy y cleanup completo (258 s).
- Crónica y lecciones: `docs/0094-apps-compose-normalizer-milestone.md`.

## ACCEPTANCE CRITERIA

- [x] `normalize` es determinista e idempotente y no escribe en el checkout.
- [x] Las cinco reglas tienen tests unitarios y negativos.
- [x] El Compose normalizado y su evidencia se firman en el release.
- [x] El harden consume el normalizado y preserva solo lo permitido.
- [x] `verify_release` acepta la metadata N1–N3 y `check_isolation` demuestra
      cero binds efectivos.
- [x] El usuario final del Dockerfile endurecido es non-root y es dueño efectivo
      de su `WORKDIR` (caso POS `front`).
- [x] Los volúmenes anónimos se nombran de forma determinista y `--purge-data`
      los elimina sin dejar huérfanos.
- [x] POS despliega sin cambios en su repo y pasa el E2E black-box.
- [x] Un fixture inseguro falla cerrado con mensaje público y sin restos.

## OPEN QUESTIONS

- ¿Los alias deben incluir también `container_name` de servicios sin red
  explícita? Propuesta: sí, todos los servicios están en la red interna.
- ¿Se permite un alias que coincida con un nombre de servicio existente?
  Propuesta: no, warning y descarte.
- ¿N4 debe podar servicios de ingress propio en el futuro? Propuesta: no en
  esta spec; primero medir con POS.
- ¿Los archivos ro deben limitarse por tamaño o tipo? Propuesta: archivo
  regular, sin límite especial; el tamaño del release ya está acotado.
- ¿La evidencia de normalización debe mostrarse en la UI? Propuesta: sí, en la
  operación y el detalle del deployment, en una entrega posterior.
