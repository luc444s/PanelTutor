"""Add the declared storage limit to tenant plans (A.SPEC 0111).

Executed by the systutor-core plugin migration runtime
(``upgrade_plugin_migrations``), never by the Alembic CLI in development.

``storage_bytes`` is a declared limit, not an applied quota: existing rows keep
``NULL`` until an operator saves storage for their tenant, and nothing in the
host materializer reads this column.
"""

from __future__ import annotations

from sqlalchemy import Engine, inspect, text

revision = "008_add_tenant_plan_storage"


def _connection(db):
    """Use the caller's own connection so DDL is visible to the next step."""
    if isinstance(db, Engine):
        return db.connect()
    if hasattr(db, "connection"):
        return db.connection()
    return db


def _upgrade_conn(conn) -> None:
    if "apps_tenant_plans" not in inspect(conn).get_table_names():
        return
    present = {column["name"] for column in inspect(conn).get_columns("apps_tenant_plans")}
    if "storage_bytes" not in present:
        conn.execute(text(
            "ALTER TABLE apps_tenant_plans ADD COLUMN storage_bytes BIGINT"
        ))


def upgrade(db) -> None:
    connection = _connection(db)
    try:
        if isinstance(db, Engine):
            with connection.begin():
                _upgrade_conn(connection)
        else:
            _upgrade_conn(connection)
    finally:
        if isinstance(db, Engine):
            connection.close()


def _downgrade_conn(conn) -> None:
    if "apps_tenant_plans" not in inspect(conn).get_table_names():
        return
    present = {column["name"] for column in inspect(conn).get_columns("apps_tenant_plans")}
    if "storage_bytes" in present:
        conn.execute(text("ALTER TABLE apps_tenant_plans DROP COLUMN storage_bytes"))


def downgrade(db) -> None:
    connection = _connection(db)
    try:
        if isinstance(db, Engine):
            with connection.begin():
                _downgrade_conn(connection)
        else:
            _downgrade_conn(connection)
    finally:
        if isinstance(db, Engine):
            connection.close()
