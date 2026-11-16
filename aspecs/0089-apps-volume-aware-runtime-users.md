# A.SPEC 0089 — Usuarios de runtime alineados con el volumen

> `risk: high` — cambia la resolución de usuarios no-root del deploy y puede
> ejecutar operaciones sobre volúmenes nombrados. Requiere aprobación humana y
> E2E real con Docker.

## STATUS

Propuesta. No implementada.

## WHY

El hardening exige un usuario no-root por servicio, pero el UID elegido puede no
coincidir con el dueño del volumen de datos. Es el caso típico de Postgres:

- la imagen oficial corre como `postgres` (UID 70);
- un volumen nuevo se inicializa copiando ese dueño (70:70);
- si el deploy fuerza `1000:1000`, el motor no puede escribir `PGDATA`;
- `database` queda `unhealthy`, `backend`/`frontend` no arrancan por
  `depends_on` y el deploy falla.

Hoy la única salida es que el operador ejecute un `chown` manual o cambie el
código de la app. Ambas rompen el objetivo de “clic en Deploy y ya”.

La regla física es simple: **el usuario efectivo del servicio debe poder escribir
su volumen**. El UID concreto no es una frontera de seguridad; la frontera es que
sea no-root y que el aislamiento se mantenga.

## WHAT

PanelTutor resuelve el usuario efectivo de cada servicio antes de endurecer y
firmar la release:

1. Calcula el usuario **deseado** (política explícita → `user:` numérico del
   compose → `USER` final del Dockerfile).
2. Descubre los volúmenes nombrados que monta cada servicio.
3. Para un volumen **nuevo** (no existe): lo crea vacío, con el label de owner
   del proyecto, y lo inicializa con el usuario deseado antes del primer
   arranque.
4. Para un volumen **existente**: lee su dueño raíz.
   - dueño no-root igual al deseado → sin cambios;
   - dueño no-root distinto → el servicio corre con el dueño del volumen;
   - dueño root (0) o ilegible → falla cerrado.
5. Firma los usuarios **efectivos**, no los solicitados, y registra la
   diferencia con su origen.

El operador no toca código ni ejecuta `chown`. El repo puede seguir declarando
`1000:1000`; PanelTutor elige un usuario no-root compatible con el volumen.

## SCOPE

- Servicios con volúmenes nombrados gestionados por Compose.
- Volúmenes nuevos y preexistentes.
- Resolución de usuario deseado: política, compose y Dockerfile.
- Inicialización de volúmenes nuevos (crear + `chown` del directorio raíz).
- Lectura del dueño de volúmenes existentes.
- Política firmada con usuarios efectivos y evidencia de la resolución.
- Mensajes de error con servicio y estado efectivo.
- Visualización del usuario efectivo y su origen en el detalle del deployment.

## OUT OF SCOPE

- `chown` recursivo automático de volúmenes existentes.
- Cambiar el contenido de los datos o migrar esquemas.
- Volúmenes `external: true` (nunca se crean ni se modifican).
- Bind mounts del host (el aislamiento ya los prohíbe en los probes).
- Resolver usuarios por nombre a UID/GID dentro de la imagen.
- Volúmenes compartidos por servicios con usuarios deseados distintos.
- Cambios de esquema SQL o Alembic.
- Debilitar aislamiento, probes, firma o red interna.

## CONTRACT

### Resolución del usuario deseado

Orden, sin excepciones:

1. `service_users` explícito en la política del deploy.
2. `user:` numérico del compose del servicio.
3. `USER` final numérico del Dockerfile.
4. Si ninguno es un entero no-root: fail-closed con el servicio afectado.

Cualquier UID/GID `> 0` es válido. `70:70` es tan aceptable como `1000:1000`.

### Descubrimiento de volúmenes

Para cada servicio se consideran solo volúmenes con nombre:

- `volumes: [data:/var/lib/...]` → nombre Compose `<project>_data`;
- volumen con `name:` explícito → ese nombre;
- volumen `external: true` → se inspecciona pero **nunca** se crea ni se
  modifica;
- bind mount (`/host/path:/container/path`) → fuera de alcance: el deploy
  mantiene el usuario deseado y el probe de aislamiento decide.

### Volumen nuevo

Antes de `docker compose up`:

1. `docker volume create --label io.spanel.app.owner=<project> <name>`.
2. Inicializar el directorio raíz con el usuario deseado usando un contenedor
   desechable sin red, `--read-only`, `--cap-drop ALL --cap-add CHOWN`.
3. Verificar el dueño resultante; si no coincide, abortar antes de arrancar.

Solo se inicializan volúmenes que PanelTutor acaba de crear y que están vacíos.

### Volumen existente

1. Leer dueño raíz con un contenedor desechable (`stat -c %u:%g`).
2. Si el dueño es `0:*` → fail-closed: no se ejecuta ningún servicio con root.
3. Si el dueño es no-root → el usuario efectivo de ese servicio pasa a ser ese
   UID/GID, aunque la política pidiera otro.
4. Si el volumen es de solo lectura y el usuario efectivo no puede leerlo →
   fail-closed.

No se ejecuta `chown` sobre volúmenes existentes.

### Evidencia y firma

El manifest del deployment incluye:

```json
{
  "runtime_users": {
    "database": {
      "requested": "1000:1000",
      "effective": "70:70",
      "source": "volume-owner",
      "volume": "app-demo_database-data"
    },
    "frontend": {
      "requested": "1000:1000",
      "effective": "1000:1000",
      "source": "policy"
    }
  }
}
```

La política firmada y el compose endurecido usan `effective`. La release nunca
declara un usuario distinto del que realmente arranca el contenedor.

### Errores

Si el arranque falla, el error incluye el estado efectivo sin volcar secretos:

```text
Compose services failed to start (exit 1): database is unhealthy
```

Si el volumen es root o ilegible:

```text
volume app-demo_database-data is owned by root; refusing to run database as root
```

## DESIGN

### Orden del pipeline

1. Clonar y auditar el checkout.
2. Resolver usuarios deseados.
3. Descubrir volúmenes por servicio y resolver nombres Compose.
4. Inspeccionar volúmenes existentes y calcular usuarios efectivos.
5. Completar y congelar la política con los usuarios efectivos.
6. Endurecer, verificar y firmar la release.
7. Crear e inicializar los volúmenes nuevos.
8. Ejecutar `up -d` (global) o por servicio.
9. Probes y publicación del estado.

Los pasos 2–5 ocurren antes del hardening; los pasos 7 antes del `up`.

### Helper de volúmenes

Se reutiliza la imagen de probe fijada por digest (sin descargar otra):

```text
docker run --rm --network none --read-only \
  --cap-drop ALL --cap-add CHOWN \
  -v <volume>:/volume \
  --entrypoint sh <probe-image> -c 'stat -c %u:%g /volume'
```

Para inicializar:

```text
... --entrypoint chown <probe-image> <uid>:<gid> /volume
```

Los helper containers no publican puertos, no usan red y solo montan el volumen
objetivo. Los helpers de inspección corren como `65534:65534`. Docker elimina
las capacidades efectivas al combinar un UID no-root con `--cap-add CHOWN`, por
lo que el helper de inicialización corre como UID 0 exclusivamente con
`CAP_CHOWN`; no conserva ninguna otra capacidad y su rootfs sigue read-only.

### Volúmenes compartidos

Si dos servicios montan el mismo volumen:

- con usuarios deseados iguales → se usa ese usuario;
- con usuarios deseados distintos → fail-closed y se exige política explícita;
- si el volumen existe y su dueño es no-root → ambos usan el dueño.

### Compatibilidad

- Sin volúmenes nombrados, el comportamiento actual no cambia.
- Un usuario explícito sigue ganando como **deseado**, pero puede ser ajustado
  por el dueño de un volumen existente; la evidencia lo muestra.
- Las releases antiguas no se reescriben.

## INVARIANTS

- Ningún servicio corre como root. Solo el helper efímero que inicializa un
  volumen recién creado puede usar UID 0, limitado a `CAP_CHOWN`, sin red,
  rootfs read-only y con un único volumen montado.
- Ningún volumen existente se modifica automáticamente.
- Ningún volumen `external` se crea, renombra o inicializa.
- El usuario efectivo siempre aparece en la evidencia firmada.
- El aislamiento, `cap_drop`, read-only rootfs y probes no se relajan.
- La resolución es determinista y no depende del orden de los diccionarios.
- No se introduce Alembic ni cambios de esquema.

## VERIFICATION

### Unitarias

- Precedencia usuario deseado: política → compose → Dockerfile → error.
- Nombre Compose de volúmenes con y sin `name:`.
- Volumen nuevo: se crea con label y se inicializa con el usuario deseado.
- Volumen existente no-root distinto: usuario efectivo = dueño.
- Volumen existente root: fail-closed.
- Volumen `external`: nunca se inicializa.
- Dos servicios con el mismo volumen y usuarios distintos: fail-closed.
- Manifest con `requested`, `effective`, `source` y `volume`.

### E2E real en lab

1. **App nueva con repo que declara 1000 y Postgres**: el volumen se crea e
   inicializa con 1000; primer deploy verde.
2. **App existente con volumen 70 y política 1000**: el deploy corre database
   como 70, arranca, probes verdes y la evidencia muestra `volume-owner`.
3. **App recreada desde cero sobre el volumen 70 anterior**: mismo resultado que
   el caso 2.
4. **Datos intactos**: el contenido de la base sobrevive a los tres casos.
5. **Aislamiento**: el helper no tiene red, no publica puertos y no monta el
   socket.

La evidencia se guarda como `artifacts/0089-volume-aware-users-e2e.json`.

## ROLLBACK

- Revertir el código restaura el comportamiento anterior sin tocar datos.
- Los volúmenes creados por PanelTutor permanecen; son volúmenes Compose
  normales con su label de owner.
- Las releases ya firmadas conservan los usuarios efectivos; no se reescriben.
- No hay migraciones ni cambios de esquema.

## CHANGE SURFACE

- `worker`: resolución de usuarios deseados y volúmenes antes del hardening.
- `hardening/contracts.py`: completar la política con usuarios efectivos.
- `runtime/deployment.py`: manifiesto `runtime_users`.
- `runtime/source.py`: ya expone el `USER` final del Dockerfile (A.SPEC 0088).
- `releases/scoped_execution.py`: no cambia su contrato de arranque.
- Frontend: mostrar usuario efectivo y origen en el detalle del deployment.
- Tests unitarios y E2E de Apps.

## BLAST RADIUS

- Deploys de servicios con volúmenes nombrados.
- La política firmada cambia para reflejar el usuario efectivo.
- Sin impacto en apps sin volúmenes, Hosting, correo o dominios.

## DEFINITION OF DONE

- [ ] Resolución usuario deseado implementada y probada.
- [ ] Descubrimiento y nombres Compose de volúmenes probados.
- [ ] Volúmenes nuevos inicializados con el usuario efectivo.
- [ ] Volúmenes existentes no-root usados sin `chown`.
- [ ] Volúmenes root o ilegibles fallan cerrado.
- [ ] Volúmenes `external` y bind mounts intactos.
- [ ] Evidencia `runtime_users` firmada en el manifest.
- [ ] Error de arranque incluye el servicio y su estado.
- [ ] E2E real en lab con los tres escenarios y datos intactos.
- [ ] Sin cambios de esquema ni Alembic.
