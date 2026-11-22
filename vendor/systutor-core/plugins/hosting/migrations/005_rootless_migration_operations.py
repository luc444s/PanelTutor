"""Persistent rootless migration operations and cell ingress routes."""

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    inspect,
)

revision = "005_rootless_migration_operations"
metadata = MetaData()
Table("tenants", metadata, Column("id", String(36), primary_key=True))
Table("hosting_sites", metadata, Column("id", String(36), primary_key=True))

operations = Table(
    "hosting_rootless_migrations",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("site_id", String(36), ForeignKey("hosting_sites.id"), nullable=False, index=True),
    Column("tenant_id", String(36), ForeignKey("tenants.id"), nullable=False, index=True),
    Column("kind", String(16), nullable=False),
    Column("from_runtime", String(16), nullable=False),
    Column("to_runtime", String(16), nullable=False),
    Column("state", String(32), nullable=False),
    Column("steps_json", Text, nullable=False),
    Column("error", Text),
    Column("backup_path", Text),
    Column("backup_sha256", String(64)),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

routes = Table(
    "hosting_rootless_routes",
    metadata,
    Column("site_id", String(36), ForeignKey("hosting_sites.id"), primary_key=True),
    Column("tenant_id", String(36), ForeignKey("tenants.id"), nullable=False, index=True),
    Column("domain", String(255), nullable=False),
    Column("target", String(255), nullable=False),
    Column("port", Integer, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("tenant_id", "domain", name="uq_hosting_rootless_route_domain"),
)


def upgrade(db) -> None:
    names = set(inspect(db.get_bind()).get_table_names())
    if operations.name not in names:
        operations.create(bind=db.get_bind())
    if routes.name not in names:
        routes.create(bind=db.get_bind())


def downgrade(db) -> None:
    names = set(inspect(db.get_bind()).get_table_names())
    if routes.name in names:
        routes.drop(bind=db.get_bind())
    if operations.name in names:
        operations.drop(bind=db.get_bind())
