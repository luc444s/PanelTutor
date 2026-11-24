"""Drop the legacy Apps ingress columns (A.SPEC 0114).

Domains owns every App Host; Apps keeps no route state of its own.  The kernel
``tenant_ingress_routes`` table (owner_kind='apps') is the only route source.

Executed by ``upgrade_plugin_migrations`` at boot, never by the Alembic CLI.
"""

from __future__ import annotations

from uuid import uuid4

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


def _backfill_domains_app_hosts(conn) -> None:
    """Preserve the legacy Host before the column disappears.

    Domains owns the Host table. Plugin migrations may run in any order after
    a registry rebuild, so the drop must not depend on ``005`` having run
    first; this is the last chance to read ``apps_applications.domain``.
    """
    tables = set(inspect(conn).get_table_names())
    if not {"apps_applications", "domains_app_hosts"}.issubset(tables):
        return
    columns = {
        column["name"]
        for column in inspect(conn).get_columns("apps_applications")
    }
    if not {"domain", "ingress_service"}.issubset(columns):
        return
    rows = conn.execute(
        text(
            "SELECT id, tenant_id, ingress_service, domain "
            "FROM apps_applications WHERE domain IS NOT NULL AND domain <> ''"
        )
    ).mappings().all()
    for row in rows:
        exists = conn.execute(
            text(
                "SELECT 1 FROM domains_app_hosts "
                "WHERE tenant_id=:tenant_id AND application_id=:application_id "
                "AND service=:service"
            ),
            {
                "tenant_id": row["tenant_id"],
                "application_id": row["id"],
                "service": row["ingress_service"],
            },
        ).first()
        if exists is not None:
            continue
        conn.execute(
            text(
                "INSERT INTO domains_app_hosts "
                "(id, tenant_id, application_id, service, domain, https) "
                "VALUES (:id, :tenant_id, :application_id, :service, :domain, "
                ":https)"
            ),
            {
                "id": str(uuid4()),
                "tenant_id": row["tenant_id"],
                "application_id": row["id"],
                "service": row["ingress_service"],
                "domain": str(row["domain"]).strip().lower().removesuffix("."),
                "https": True,
            },
        )


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
                _backfill_domains_app_hosts(connection)
                _drop_columns(connection)
        else:
            _backfill_domains_app_hosts(connection)
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
