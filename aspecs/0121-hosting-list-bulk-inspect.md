# A.SPEC 0121 — Listado de Hosting sin N+1 de `docker inspect`

## Problema

`HostingService.list_sites()` (`vendor/systutor-core/plugins/hosting/backend/service.py:790-832`)
hace, por cada sitio, una resolución de runtime y un `docker inspect`:

```python
for site in self._db.scalars(stmt):
    info = self._inspect_for(site, site.container_name)
```

Cada `_inspect_for()` implica:

1. `_runtime_for(site)` → `HostingRuntimeResolver.resolve()` (`runtime.py:144-161`):
   `read_resource_runtime()` (BD), `resolve_container_runtime()` →
   `RootlessCellProvider.__call__()` (lee y parsea `registry.json` del disco) y
   **`handle.health()`**, que ejecuta `docker -H <socket> info --format '{{.ID}}'`;
2. un `docker inspect <name>` para obtener `State.Status`, `Config.Image` y
   `Config.Labels`.

En producción (vmi3461574) hay 13 sitios. Medido: `docker info` en la celda
tarda 0,222 s y un `inspect` 0,050 s → **~3,5 s solo en llamadas Docker**, más
13 lecturas de `registry.json`. Con `SPANEL_DOCKER_TRANSPORT=ssh`, cada llamada
además abre un handshake SSH nuevo (`build_docker_argv()` no usa ControlMaster).

La BD **no** guarda el estado: `HostingSite` (`models.py:46-77`) no tiene columna
de status. El listado necesita el estado real del contenedor, así que no se
puede eliminar Docker; pero sí se puede pasar de N inspecciones a **una por
daemon**.

## Contrato

1. **Bulk inspect en los handles concretos de Hosting** (`hosting/backend/runtime.py`):
   añadir `inspect_many(self, names: Sequence[str]) -> dict[str, dict | None]` a
   `RootfulDockerHandle` y `RootlessCellHandle`. Debe ejecutar **un solo**
   `docker inspect --format '{{json .}}' n1 n2 … nN` por daemon (agrupando en
   chunks de hasta 50 nombres), tolerar fallos parciales (`docker inspect`
   devuelve exit 1 si falta algún nombre pero imprime los demás) y devolver un
   dict keyed por nombre de contenedor **sin el `/` inicial**. Los nombres
   ausentes mapean a `None`. El payload debe ser el JSON completo de `inspect`,
   para que `candidato_de()` (`inspection.py:42-58`) y
   `estado_del_contenedor()` (`service.py:127-131`) sigan comportándose
   exactamente igual.

2. **Helper compartido** (`hosting/backend/inspection.py`): añadir la función
   que ejecuta y parsea el batch (acepta `env` para rootful y una función
   `command` inyectada para rootless), sin duplicar lógica en `runtime.py`.

3. **`list_sites()` sin N+1** (`service.py`):
   - resolver el runtime **una sola vez por tenant** (agrupar sitios por
     `tenant_id`) en vez de una vez por sitio;
   - añadir `check_health: bool = True` a `HostingRuntimeResolver.resolve()`
     (`runtime.py`) y a `_runtime_for()`; el listado llama con `False`, el resto
     del código conserva el default `True`. Un daemon caído ya se detecta
     porque `inspect` devuelve `None` → `status="missing"`;
   - por cada daemon, llamar a `inspect_many()` con todos sus nombres y hacer
     el join con las filas de la BD. Si un handle de un tercero no expone
     `inspect_many()`, hacer fallback al `_inspect_for()` actual (compatibilidad,
     sin romper la interfaz pública `systutor.contracts.ContainerRuntimeHandle`).

4. **Cache de `registry.json`** (`plugins/tenant/backend/container_runtime.py`,
   `RootlessCellProvider.__call__`): cachear el `json.loads` con TTL corto
   (5 s) y validación por `st_mtime` del archivo, keyed por `data_root`.
   Fail-closed igual que hoy: si no se puede leer, lanza
   `ContainerRuntimeError("tenant cell registry unavailable")`.

5. **ControlMaster para Hosting** (`hosting/backend/transport.py`,
   `build_docker_argv()`): si el env trae `SPANEL_DOCKER_SSH_CONTROL_PATH`,
   añadir `ControlMaster=auto`, `ControlPath=<path>` y `ControlPersist=<n>`,
   con el mismo patrón y garantías que
   `plugins/mail/backend/provider.py:95-131` (A.SPEC 0006). La contraseña NO
   debe aparecer en argv: se mantiene `sshpass -e` con `SSHPASS` en el entorno
   del hijo. Sin la variable, el argv queda idéntico al actual.

6. No se modifica la interfaz pública en `systutor.contracts`, no hay cambios
   de esquema, no se invoca Alembic ni el runtime migrador.

## Criterios de aceptación

- Con N sitios de un mismo tenant rootless, `list_sites()` ejecuta **una** llamada
  `docker inspect` con N nombres y **ningún** `docker info` de health.
- El status, `managed` y `kind` del listado son idénticos a los del código actual
  (mismo `candidato_de()` sobre el payload completo de inspect).
- Un sitio cuyo contenedor no existe sigue apareciendo con `status="missing"` y
  `managed=False`.
- Un handle sin `inspect_many()` sigue funcionando por el fallback por sitio.
- Los sitios rootful con `SPANEL_DOCKER_TRANSPORT=ssh` reutilizan la conexión
  cuando se configura `SPANEL_DOCKER_SSH_CONTROL_PATH`.
- `registry.json` se lee una sola vez dentro de la ventana de TTL, y se recarga
  si cambia el `mtime`.

## Pruebas

Añadir `vendor/systutor-core/plugins/hosting/backend/tests/test_list_sites_bulk.py`:

- bulk inspect con una respuesta simulada de varios contenedores: mapeo por
  nombre, `/` inicial removido, nombre ausente → `None`, tolerando exit parcial;
- `list_sites()` con 3 sitios del mismo tenant: assertions de **1** llamada a
  `inspect_many` y **0** llamadas a `health`, y summaries idénticos a los
  esperados;
- fallback: handle sin `inspect_many` → usa `_inspect_for` por sitio;
- `resolve(check_health=False)` no llama a `health`; el default sigue llamándolo;
- cache de registry: dos llamadas con el mismo mtime → una lectura; con mtime
  distinto → dos;
- `build_docker_argv` con `SPANEL_DOCKER_SSH_CONTROL_PATH` incluye las tres
  opciones y **no** incluye la password; sin la variable, argv sin cambios.

Verificación:

```bash
cd /data/data/com.termux/files/home/Proyectos/mailadmin
python3 -m pytest vendor/systutor-core/plugins/hosting/backend/tests -q
python3 -m pytest vendor/systutor-core/plugins/tenant/backend/tests -q
ruff check vendor/systutor-core/plugins/hosting/backend vendor/systutor-core/plugins/tenant/backend/container_runtime.py
```

## Notas

- No hacer commit: el revisor integra y commitea.
- No desplegar en producción; validar en `spanel.lab` primero.
- La A.SPEC 0120 (rootless sin attach a `spanel-db`) debe seguir pasando.
