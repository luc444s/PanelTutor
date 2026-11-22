## Migraciones de esquema

- **Prohibido usar Alembic directamente en desarrollo** (ni `alembic upgrade`,
  ni `alembic revision --autogenerate`, ni invocar el CLI de Alembic a mano
  contra la app host).
- Los cambios de esquema de **systutor-core y sus plugins** se hacen con el
  **runtime migrador de systutor-core**:
  - kernel: `vendor/systutor-core/migrations/` + `alembic.ini`, ejecutados por
    el runtime del kernel;
  - plugins: `vendor/systutor-core/plugins/<plugin>/migrations/00X_*.py` con
    `revision`, `upgrade(db)` y `downgrade(db)`, ejecutados por
    `upgrade_plugin_migrations()` en
    `src/systutor/kernel/plugins/migrations.py`.
- Esta regla **no prohíbe el mecanismo de migraciones del core**; prohíbe
  invocar Alembic por separado durante el desarrollo de la app host.
