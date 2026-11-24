"""Move Hosting ingress routes to the kernel cell-ingress table (A.SPEC 0114).

Kernel revision ``20261123_0012`` creates ``tenant_ingress_routes`` and copies
every ``hosting_rootless_routes`` row with ``owner_kind='hosting'``.  The panel
image does not ship the Alembic directory, so this plugin migration repeats the
copy idempotently before dropping the private table; otherwise an existing
deployment would lose every published Hosting route.

Executed by ``upgrade_plugin_migrations`` at boot, never by the Alembic CLI.
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from sqlalchemy import Engine

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
    """Prefer the engine so DDL commits before the next migration step."""
    if isinstance(db, Engine):
        return db
    if hasattr(db, "get_bind"):
        return db.get_bind()
    return db


def _run(db, operation) -> None:
    bind = _bind(db)
    if isinstance(bind, Engine):
        with bind.begin() as connection:
            operation(connection)
    else:
        operation(bind)


def _upgrade(connection) -> None:
    bind = connection
    names = set(sa.inspect(bind).get_table_names())
    if kernel_routes.name not in names:
        # ``Base.metadata.create_all`` normally creates the kernel table at
        # boot; create it here as a safety net for hosts that only run plugin
        # migrations.
        from systutor.kernel.cell_ingress import TenantIngressRoute

        TenantIngressRoute.__table__.create(bind)
        names.add(kernel_routes.name)
    if routes.name in names:
        # Copy before dropping: the panel image does not ship the Alembic
        # directory, so kernel revision 0012 may never run on an existing
        # deployment. Without this copy Hosting would lose every published
        # route when the private table disappears.
        existing = {
            row[0]
            for row in bind.execute(
                sa.select(kernel_routes.c.route_id)
            ).all()
        }
        for row in bind.execute(sa.select(routes)).mappings().all():
            route_id = f"hosting:{row['site_id']}"
            if route_id in existing:
                continue
            bind.execute(
                kernel_routes.insert().values(
                    route_id=route_id,
                    tenant_id=row["tenant_id"],
                    owner_kind="hosting",
                    owner_id=row["site_id"],
                    service=None,
                    domain=row["domain"],
                    target=row["target"],
                    port=row["port"],
                    updated_at=row["updated_at"] or datetime.now(UTC),
                )
            )
        routes.drop(bind)


def _downgrade(connection) -> None:
    bind = connection
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


def upgrade(db) -> None:
    _run(db, _upgrade)


def downgrade(db) -> None:
    _run(db, _downgrade)
