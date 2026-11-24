"""Drop the legacy Apps ingress columns (A.SPEC 0114).

Domains owns every App Host; Apps keeps no route state of its own.  The kernel
``tenant_ingress_routes`` table (owner_kind='apps') is the only route source.

Executed by ``upgrade_plugin_migrations`` at boot, never by the Alembic CLI.
"""

from __future__ import annotations

from sqlalchemy import Engine, inspect, text

revision = "009_drop_apps_legacy_ingress"

COLUMNS = {
    "apps_applications": ("domain", "ingress_service", "ingress_port"),
    "apps_deployments": ("ingress_service", "ingress_port"),
}


def _connection(db):
    """Use the caller's own connection so DDL is visible to the next step."""
    if isinstance(db, Engine):
        return db.connect()
    if hasattr(db, "connection"):
        return db.connection()
    return db


def _drop_columns(conn) -> None:
    tables = set(inspect(conn).get_table_names())
    for table, columns in COLUMNS.items():
        if table not in tables:
            continue
        present = {column["name"] for column in inspect(conn).get_columns(table)}
        for column in columns:
            if column in present:
                conn.execute(
                    text(f"ALTER TABLE {table} DROP COLUMN {column}")
                )


def upgrade(db) -> None:
    connection = _connection(db)
    try:
        if isinstance(db, Engine):
            with connection.begin():
                _drop_columns(connection)
        else:
            _drop_columns(connection)
    finally:
        if isinstance(db, Engine):
            connection.close()


def _add_columns(conn) -> None:
    tables = set(inspect(conn).get_table_names())
    definitions = {
        "apps_applications": (
            ("domain", "VARCHAR(255)"),
            ("ingress_service", "VARCHAR(255)"),
            ("ingress_port", "INTEGER"),
        ),
        "apps_deployments": (
            ("ingress_service", "VARCHAR(255)"),
            ("ingress_port", "INTEGER"),
        ),
    }
    for table, columns in definitions.items():
        if table not in tables:
            continue
        present = {column["name"] for column in inspect(conn).get_columns(table)}
        for column, sql_type in columns:
            if column not in present:
                conn.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")
                )


def downgrade(db) -> None:
    connection = _connection(db)
    try:
        if isinstance(db, Engine):
            with connection.begin():
                _add_columns(connection)
        else:
            _add_columns(connection)
    finally:
        if isinstance(db, Engine):
            connection.close()
