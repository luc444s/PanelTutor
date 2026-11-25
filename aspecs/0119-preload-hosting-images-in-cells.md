# A.SPEC 0119 — Preload de imágenes de Hosting en las celdas

## Problema

En vmi3461574, la celda `testpr6` tiene `mariadb:11` y `nginx:alpine` pero no
`wordpress:latest`. `Provisioner.create()` crea la red/volúmenes y el contenedor
MariaDB correctamente, pero al crear el contenedor WordPress el daemon rootless
intenta bajar la imagen, no puede (egress de la celda) y falla con
`hosting_provision_failed` → el panel muestra "The site could not be
provisioned" y el `cleanup()` borra todo, sin dejar rastro.

Ya existe el mecanismo en `scripts/migrate_milton_legacy.py:339`
(`stream(rootful.argv("save", image), cell.argv("load"))`), pero solo se usa en
migraciones puntuales. Hay que generalizarlo.

## Contrato

1. `scripts/tenant_cell/images.py` (nuevo, < 400 líneas) expone:
   - `desired_images() -> list[str]`: lee `SPANEL_HOSTING_WP_IMAGE`
     (default `wordpress:latest`), `SPANEL_HOSTING_DB_IMAGE`
     (default `mariadb:11`) y `SPANEL_HOSTING_STATIC_IMAGE`
     (default `nginx:alpine`, para sitios estáticos), sin duplicados.
   - `image_exists(socket_path, image) -> bool`: `docker -H unix://<socket> image inspect`.
   - `ensure_image(socket_path, image, *, rootful_socket="/var/run/docker.sock")`:
     idempotente. Si ya está en la celda, no hace nada. Si no está pero sí en el
     daemon rootful, transfiere con `docker save <image> | docker load`
     (piping con `subprocess.Popen`, timeout acotado, sin `shell=True`). Si
     tampoco está en rootful, hace `docker pull` **en rootful** (el host sí tiene
     egress) y luego transfiere.
   - `ensure_cell_images(data_root) -> list[dict]`: recorre los `allocations` del
     registry, omite celdas sin `docker.sock`, y devuelve un resultado por slug.
2. `Executor` (base en `scripts/tenant_cell/executor.py`) gana
   `ensure_cell_images(self, socket_path: str, images: list[str]) -> None` con
   implementación **no-op** por defecto, para que los tests con `FakeExecutor`
   sigan sin invocar Docker. `LocalExecutor` la sobrescribe con la llamada real.
3. `CellService.provision()` (`scripts/tenant_cell/cells.py`) invoca el hook
   justo después de `start_daemon` cuando ya existe el socket, y marca
   `applied["images"] = True`. Debe ser idempotente y no retransferir en
   reprovisionamientos.
4. `scripts/tenant_cell/reconcile_cells.py` (creado en A.SPEC 0118) también
   llama a `ensure_cell_images(data_root)` para que `deploy.sh` repare las
   celdas ya existentes sin ningún comando manual.
5. La transferencia nunca toca contenedores ni datos de la celda; solo imágenes.
   La authorize sigue siendo el gate local `SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS`.

## Criterios de aceptación

- Tras `bash scripts/deploy.sh`, `wordpress:latest`, `mariadb:11` y
  `nginx:alpine` existen en cada celda con daemon activo (verificado con
  `docker -H ... image inspect`).
- Una celda creada después del deploy ya nace con esas imágenes, sin pull desde
  la celda.
- Un segundo deploy no transfiere nada (`unchanged`).
- No se invoca Alembic ni se cambia el esquema.

## Pruebas

- `scripts/tests/test_tenant_cell_images.py`: transferencia simulada con
  `Popen` monokeypatcheda, idempotencia, y fallback a pull rootful.
- Los tests existentes de provision/reconcile deben seguir pasando (el hook
  base es no-op para el fake executor).

## Notas

- No hacer commit: el revisor (agente principal) integra y commitea.
- No modificar permisos RBAC ni el frontend salvo lo estrictamente necesario.
