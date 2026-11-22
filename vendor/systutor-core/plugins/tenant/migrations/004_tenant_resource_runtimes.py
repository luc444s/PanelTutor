"""Persist the daemon selection for each tenant resource."""

from __future__ import annotations

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    Engine,
    ForeignKey,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    inspect,
)

revision = "004_tenant_resource_runtimes"

metadata = MetaData()
Table("tenants", metadata, Column("id", String(36), primary_key=True))
resource_runtimes = Table(
    "tenant_resource_runtimes",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("tenant_id", String(36), ForeignKey("tenants.id"), nullable=False),
    Column("kind", String(32), nullable=False),
    Column("resource_id", String(255), nullable=False),
    Column("runtime", String(16), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint(
        "tenant_id", "kind", "resource_id", name="uq_tenant_resource_runtime"
    ),
    CheckConstraint(
        "runtime in ('rootful','rootless')", name="ck_tenant_resource_runtime"
    ),
)


def _bind(db):
    return db if isinstance(db, Engine) else db.get_bind()


def upgrade(db) -> None:
    bind = _bind(db)
    if "tenant_resource_runtimes" not in inspect(bind).get_table_names():
        resource_runtimes.create(bind=bind)


def downgrade(db) -> None:
    bind = _bind(db)
    if "tenant_resource_runtimes" in inspect(bind).get_table_names():
        resource_runtimes.drop(bind=bind)
