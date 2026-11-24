"""Move Hosting ingress routes to the kernel cell-ingress table (A.SPEC 0114).

The kernel revision ``20261123_0012`` already created
``tenant_ingress_routes`` and copied every ``hosting_rootless_routes`` row with
``owner_kind='hosting'``.  This plugin migration only drops the now-unused
private table; it never writes ingress route state itself.

Executed by ``upgrade_plugin_migrations`` at boot, never by the Alembic CLI.
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa

revision = "006_use_kernel_cell_ingress"

metadata = sa.MetaData()
routes = sa.Table(
    "hosting_rootless_routes",
    metadata,
    sa.Column("site_id", sa.String(36), primary_key=True),
    sa.Column("tenant_id", sa.String(36), nullable=False),
    sa.Column("domain", sa.String(255), nullable=False),
    sa.Column("target", sa.String(255), nullable=False),
    sa.Column("port", sa.Integer(), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("tenant_id", "domain", name="uq_hosting_rootless_route_domain"),
)

kernel_routes = sa.Table(
    "tenant_ingress_routes",
    sa.MetaData(),
    sa.Column("route_id", sa.String(255), primary_key=True),
    sa.Column("tenant_id", sa.String(36)),
    sa.Column("owner_kind", sa.String(16)),
    sa.Column("owner_id", sa.String(255)),
    sa.Column("service", sa.String(255)),
    sa.Column("domain", sa.String(255)),
    sa.Column("target", sa.String(255)),
    sa.Column("port", sa.Integer()),
    sa.Column("updated_at", sa.DateTime(timezone=True)),
)


def _bind(db):
    return db.get_bind() if hasattr(db, "get_bind") else db


def upgrade(db) -> None:
    bind = _bind(db)
    if routes.name in set(sa.inspect(bind).get_table_names()):
        routes.drop(bind)


def downgrade(db) -> None:
    bind = _bind(db)
    names = set(sa.inspect(bind).get_table_names())
    if routes.name not in names:
        routes.create(bind)
    if kernel_routes.name not in names:
        return
    rows = bind.execute(
        sa.select(kernel_routes).where(kernel_routes.c.owner_kind == "hosting")
    ).mappings().all()
    for row in rows:
        bind.execute(
            routes.insert().values(
                site_id=row["owner_id"],
                tenant_id=row["tenant_id"],
                domain=row["domain"],
                target=row["target"],
                port=row["port"],
                updated_at=row["updated_at"] or datetime.now(UTC),
            )
        )
