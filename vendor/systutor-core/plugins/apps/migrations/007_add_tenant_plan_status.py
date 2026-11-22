"""Add explicit lifecycle state to tenant plans (A.SPEC 0102).

Executed by the systutor-core plugin migration runtime
(``upgrade_plugin_migrations``), never by the Alembic CLI in development.
Existing 0101 rows were already materialized, so they are backfilled to
``applied`` exactly once, when the status column is first added.
"""

from __future__ import annotations

from sqlalchemy import Engine, inspect, text

revision = "007_add_tenant_plan_status"


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
    timestamp = (
        "TIMESTAMP WITH TIME ZONE" if conn.dialect.name == "postgresql" else "DATETIME"
    )
    added_status = False
    if "status" not in present:
        conn.execute(text(
            "ALTER TABLE apps_tenant_plans ADD COLUMN status "
            "VARCHAR(16) NOT NULL DEFAULT 'pending'"
        ))
        added_status = True
    if "applied_at" not in present:
        conn.execute(text(
            f"ALTER TABLE apps_tenant_plans ADD COLUMN applied_at {timestamp}"
        ))
    if "last_error" not in present:
        conn.execute(text("ALTER TABLE apps_tenant_plans ADD COLUMN last_error TEXT"))
    if "desired_hash" not in present:
        conn.execute(text(
            "ALTER TABLE apps_tenant_plans ADD COLUMN desired_hash VARCHAR(64)"
        ))
    if added_status:
        conn.execute(text("UPDATE apps_tenant_plans SET status = 'applied'"))


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
    for name in ("desired_hash", "last_error", "applied_at", "status"):
        if name in present:
            conn.execute(text(f"ALTER TABLE apps_tenant_plans DROP COLUMN {name}"))


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
