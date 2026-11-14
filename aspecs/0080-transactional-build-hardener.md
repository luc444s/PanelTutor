# A.SPEC 0080 — Transactional Build Hardener

> `risk: high` — este motor transforma Dockerfile y Compose no confiables. Una
> transformación sintácticamente correcta puede romper el build, el arranque,
> la persistencia o los permisos. Por ello el motor falla cerrado, trabaja en
> staging y nunca publica cambios que no superen todos los gates.

## WHY

El gate de A.SPEC 0078 ya combina auditor propio, Trivy, Hadolint y BuildKit.
La prueba contra GoCortex Broken Bank demostró buena cobertura, pero también que
el fixer original puede producir falsos verdes: reemplaza un `USER root` usado
durante el build, convierte permisos sin conocer propietarios y solo reaudita
reglas internas. Hace falta separar detección de transformación y convertir el
fix en una transacción verificable.

## WHAT

1. Convertir `scripts/dangerous_build_normalize.py` en una fachada pequeña.
2. Mover el motor a `scripts/dangerous_build/` con componentes separados para
   CLI, Dockerfile, Compose, gate y transacciones.
3. Añadir `harden`, un fixer V2 conservador:

```bash
dangerous-build-normalize harden <checkout> \
  --compose-file docker-compose.yml \
  --non-root --require-build \
  [--deployment-copy] \
  [--service-user SERVICE=UID:GID] \
  [--writable-path SERVICE=/path:MODE] \
  [--env-file /secure/runtime.env] \
  [--apply] [--format text|json]
```

4. `harden` siempre crea una copia staging y aplica allí las transformaciones.
5. El staging debe superar auditor interno, Trivy filesystem, Hadolint,
   BuildKit, Trivy sobre cada imagen construida y un arranque Compose temporal
   dentro del perímetro de aislamiento antes de considerarse candidato. Sin
   herramientas externas no hay éxito.
6. `--apply` publica únicamente los archivos cambiados, con backup versionado,
   manifest de hashes y rollback automático ante fallo parcial.
7. Servicios `image:` son ciudadanos de primera clase: el motor hace pull,
   resuelve el tag a digest, escanea el digest con Trivy y usa ese digest en el
   smoke aislado. Hadolint se omite limpiamente cuando no existe Dockerfile.
   `--require-build` permite al administrador prohibir imágenes externas.

## PLATFORM CONTRACT — ISOLATION FIRST

PanelTutor prioriza aislamiento extremo. El motor intenta preservar la función
únicamente dentro de este perímetro obligatorio:

- usuario runtime no-root explícito por servicio;
- `cap_drop: [ALL]`, `no-new-privileges`, filesystem raíz read-only y `/tmp`
  efímero con `noexec,nosuid,nodev`;
- cero binds del host, dispositivos, namespaces host o socket Docker;
- cero puertos publicados directamente; se conservan como `expose` internos y
  la publicación pertenece a una interfaz administrada posterior;
- redes runtime `internal: true`, sin egress no autorizado;
- persistencia solo mediante volúmenes administrados declarados como rutas
  escribibles explícitas;
- secretos solo mediante la interfaz externa privada administrada.

El env externo es opcional, debe ser un archivo regular no-symlink `0600`, no se
copia al checkout y solo se entrega al smoke runtime mediante Compose.

Si una función exige romper este perímetro, el motor la deshabilita cuando la
retirada es determinista o rechaza el despliegue. Nunca reduce aislamiento para
preservar funcionalidad ni declara segura una transformación no demostrada.

La meta de “cualquier repositorio” se expresa como contrato total: para toda
entrada el motor produce un candidato que supera todas las pruebas o un rechazo
cerrado y explicable. No existe un tercer resultado de éxito parcial.

## SAFETY MODEL

### Transformaciones automáticas admitidas

- Eliminar nombres fijos, privilegios, capabilities, dispositivos y namespaces
  host de Compose.
- Sustituir secretos literales Compose por referencias `${NAME}` sin copiar el
  valor al reporte.
- Retirar puertos y `env_file` según la política existente.
- En `--deployment-copy`, retirar mounts/recursos host clasificados como nivel C.
- Añadir un `USER` final explícito **después de todas las instrucciones de build**
  y antes de `CMD`/`ENTRYPOINT`, sin reemplazar usuarios usados durante el build.
- Preparar rutas escribibles solo cuando el operador declara servicio, ruta,
  usuario y modo; nunca inferirlas.

### Transformaciones prohibidas

- Nunca convertir globalmente `chmod 777` a `755`.
- Nunca inventar healthchecks de `echo ok`.
- Nunca eliminar secretos Dockerfile ni comandos `curl | sh` automáticamente.
- Nunca adivinar usuarios de imágenes externas ni ownership por nombre.
- Nunca ejecutar BuildKit si cualquier gate estático bloquea.
- Nunca aplicar parcialmente si el staging no pasa completo.

## TRANSACTION

1. Validar checkout y política.
2. Crear staging fuera del checkout.
3. Calcular plan y hashes iniciales.
4. Transformar solo staging.
5. Ejecutar gate completo sobre staging.
6. Si falla: conservar fuente byte-for-byte y devolver evidencia sanitizada.
7. Si pasa y no hay `--apply`: emitir plan/diff; no modificar fuente.
8. Si pasa y hay `--apply`:
   - crear el backup fuera del checkout en
     `<parent>/.spanel-build-backups/<checkout>/<timestamp>/`;
   - copiar originales y escribir `manifest.json` modo `0600`;
   - publicar con temporales + `os.replace`;
   - reauditar fuente publicada;
   - ante error, restaurar desde backup y fallar.

## CONTRACT

- Éxito dry-run: staging pasa gate completo, fuente intacta, plan disponible.
- Éxito apply: fuente coincide con candidato validado y existe backup verificable.
- Fallo: fuente intacta o restaurada; nunca estado parcial.
- Exit `0`: todos los gates y publicación pasan.
- Exit `2`: política, herramienta, gate, build o publicación bloquean.
- Los reportes no incluyen valores secretos ni stdout/stderr crudos de builds.

## INVARIANTS

```yaml
invariants:
  - id: H1
    statement: USER de runtime nunca invalida instrucciones de build previas.
    proof: fixture con USER root temprano y apt/RUN posteriores.
  - id: H2
    statement: permisos ambiguos nunca se reescriben automáticamente.
    proof: chmod 777 permanece y bloquea hasta política explícita.
  - id: H3
    statement: un gate fallido deja la fuente byte-for-byte intacta incluso con --apply.
    proof: snapshots y herramientas falsas bloqueantes.
  - id: H4
    statement: BuildKit jamás se ejecuta tras bloqueo estático.
    proof: docker falso no invocado.
  - id: H5
    statement: apply publica todos los archivos o restaura todos.
    proof: fallo inyectado durante publicación y comparación de hashes.
  - id: H6
    statement: todo apply exitoso tiene manifest y backups 0600.
    proof: test de permisos, hashes y rutas.
  - id: H7
    statement: la fachada CLI conserva scan, fix y gate existentes.
    proof: suite A.SPEC 0078 sin regresiones.
  - id: H8
    statement: una imagen construida con vulnerabilidades HIGH/CRITICAL nunca se publica.
    proof: Trivy image bloqueante, fuente intacta y tag efímero eliminado.
  - id: H9
    statement: deployable exige arranque temporal exitoso bajo el aislamiento final.
    proof: Compose up --wait con override efímero, seguido siempre por down --volumes.
  - id: H10
    statement: una imagen externa nunca se ejecuta desde un tag mutable no resuelto.
    proof: pull + inspect RepoDigests + Trivy del digest + override runtime por digest.
  - id: H11
    statement: running sin healthcheck no demuestra que una aplicación sea desplegable.
    proof: imagen externa limpia pero sin healthcheck bloquea antes del smoke y de apply.
```

## STRUCTURE

```text
scripts/dangerous_build_normalize.py       # fachada
scripts/dangerous_build/
  __init__.py
  cli.py                                   # parser y compatibilidad
  dockerfile.py                            # plan semántico Dockerfile
  hardener.py                              # staging y orquestación
  transaction.py                           # backup/publicación/rollback
```

El gate existente puede permanecer inicialmente en `cli.py`; no se duplican sus
reglas. La separación posterior no cambia el contrato público.

## VERIFICATION

```bash
.venv/bin/python -m pytest \
  scripts/tests/test_dangerous_build_normalize.py \
  scripts/tests/test_transactional_build_hardener.py \
  scripts/tests/test_app_deploy.py -q

.venv/bin/python -m ruff check \
  scripts/dangerous_build_normalize.py \
  scripts/dangerous_build \
  scripts/tests/test_transactional_build_hardener.py

git diff --check
```

## ROLLBACK

- Restaurar cada archivo según `manifest.json` del último backup.
- La publicación automática ya restaura ante error parcial.
- El rollback nunca elimina archivos ajenos ni usa `git reset/checkout`.

## CHANGE SURFACE

```yaml
allowed:
  - aspecs/0080-transactional-build-hardener.md
  - scripts/dangerous_build_normalize.py
  - scripts/dangerous_build/**
  - scripts/tests/test_dangerous_build_normalize.py
  - scripts/tests/test_transactional_build_hardener.py
prohibited:
  - docker-compose.yml
  - Dockerfile
  - vendor/**
  - apps/**
```

## DEFINITION OF DONE

- [x] Fachada CLI pequeña y paquete por componentes.
- [x] `harden` transaccional con staging obligatorio.
- [x] USER final se inserta sin romper el build previo.
- [x] No hay reescritura ciega de permisos.
- [x] Gate completo obligatorio antes de apply.
- [x] Trivy image obligatorio y tags efímeros eliminados.
- [x] Smoke runtime aislado obligatorio con cleanup probado.
- [x] Backup, manifest, publicación atómica y rollback probados.
- [x] Suites y lint verdes.

## VALIDATION EVIDENCE

- Suite local combinada: 75 passed.
- Lab: 17 tests específicos passed.
- Fixture `scratch` con binario estático: staging y post-apply gates passed;
  Trivy filesystem/image limpios; smoke Compose healthy; aislamiento verificado;
  cleanup sin contenedores, imágenes ni redes `spanel-gate-*`.
- GoCortex Broken Bank `463f71e`: candidate blocked antes de BuildKit con 11
  hallazgos internos bloqueantes, 232 Trivy y 66 Hadolint; `--apply` no modificó
  ningún byte del checkout y no dejó recursos efímeros.
- `odoo:18.0`: tag resuelto a
  `odoo@sha256:d0b20aa4ec8a4d97ca096ada36275d77963d571c1cb1cceca69faf6098326c83`;
  cero HIGH/CRITICAL en Trivy image y usuario upstream `100:101`, pero sin
  healthcheck de imagen/Compose. El motor bloqueó antes del smoke y de apply,
  conservó la fuente y no dejó recursos efímeros.
