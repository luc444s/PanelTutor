"""Persist per-tenant resource plans in the Apps plugin database.

Executed by the systutor-core plugin migration runtime
(``upgrade_plugin_migrations``), never by the Alembic CLI in development.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Engine,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    inspect,
)

revision = "006_add_tenant_resource_plans"

metadata = MetaData()
Table("tenants", metadata, Column("id", String(36), primary_key=True))
tenant_plans = Table(
    "apps_tenant_plans",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("tenant_id", String(36), ForeignKey("tenants.id"), nullable=False),
    Column("memory_bytes", BigInteger, nullable=False),
    Column("cpus", Float, nullable=False),
    Column("pids", Integer, nullable=False),
    Column("cpuset", String(255)),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("tenant_id", name="uq_apps_tenant_plans_tenant_id"),
)


def _bind(db):
    return db if isinstance(db, Engine) else db.get_bind()


def upgrade(db) -> None:
    bind = _bind(db)
    if "apps_tenant_plans" not in inspect(bind).get_table_names():
        tenant_plans.create(bind=bind)


def downgrade(db) -> None:
    bind = _bind(db)
    if "apps_tenant_plans" in inspect(bind).get_table_names():
        tenant_plans.drop(bind=bind)
