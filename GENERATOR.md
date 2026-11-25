# GENERATOR.md — delegación de implementación

Eres el agente implementador. Tu tarea está especificada en
`aspecs/0119-preload-hosting-images-in-cells.md`. **Lee esa spec primero** y
cumple el contrato tal cual.

## Contexto mínimo

- Repo: `/data/data/com.termux/files/home/Proyectos/mailadmin` (rama `main`).
- El error que motiva el cambio: en la celda rootless `testpr6` falta
  `wordpress:latest`; el daemon rootless no puede bajarlo por egress y la
  creación de sitios WordPress termina en `hosting_provision_failed` (409)
  con cleanup posterior. El mecanismo `docker save | docker load` ya existe en
  `scripts/migrate_milton_legacy.py:339` y debe generalizarse.
- `scripts/tenant_cell/reconcile_cells.py` ya existe (A.SPEC 0118) y es llamado
  desde `scripts/deploy.sh` en cada deploy.

## Reglas

1. **No hacer commit ni push.** El agente principal revisa e integra.
2. **No usar Alembic CLI** ni cambiar esquema (ver `AGENTS.md` de la raíz y de
   `vendor/systutor-core`).
3. No tocar permisos RBAC ni frontend salvo lo estrictamente necesario.
4. Ningún archivo nuevo > 400 líneas; mantener el estilo del código vecino.
5. El hook `Executor.ensure_cell_images` debe ser **no-op en la clase base**
   para no romper los `FakeExecutor` de los tests existentes.
6. La transferencia de imágenes debe ser idempotente, usar `subprocess.Popen`
   con `stdout`/`stdin` pipe (nunca `shell=True`) y timeout acotado.

## Entregable

1. Implementar los 4 puntos del contrato de la spec.
2. Añadir `scripts/tests/test_tenant_cell_images.py` con tests aislados
   (monkeypatch de `Popen`/`subprocess.run`; sin Docker real).
3. Ejecutar y dejar passing:
   - `python3 -m pytest scripts/tests/test_tenant_cell_images.py -q`
   - `python3 -m pytest scripts/tests/test_tenant_cell_provision.py scripts/tests/test_reconcile_cells.py -q`
   - `ruff check` sobre los archivos que modifiques.
   (`ruff` binario disponible; `python3 -m ruff` no).
4. Reportar: archivos cambiados, comandos ejecutados y resultados. Si algo no
   se pudo verificar, decirlo explícitamente. No reportes "listo" sin evidence.
