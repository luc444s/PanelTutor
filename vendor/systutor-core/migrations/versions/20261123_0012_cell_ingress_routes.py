"""Create the kernel cell-ingress route table (A.SPEC 0114).

Revision ID: 20261123_0012
Revises: 20261119_0011

Executed by the systutor-core migration runtime at boot, never by the Alembic
CLI during development (see AGENTS.md).  Existing Hosting route rows are copied
with ``owner_kind='hosting'`` before the Hosting plugin migration drops its own
table.
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "20261123_0012"
down_revision = "20261119_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "tenant_ingress_routes" not in tables:
        op.create_table(
            "tenant_ingress_routes",
            sa.Column("route_id", sa.String(length=255), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("owner_kind", sa.String(length=16), nullable=False),
            sa.Column("owner_id", sa.String(length=255), nullable=False),
            sa.Column("service", sa.String(length=255), nullable=True),
            sa.Column("domain", sa.String(length=255), nullable=False),
            sa.Column("target", sa.String(length=255), nullable=False),
            sa.Column("port", sa.Integer(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint(
                "tenant_id", "domain", name="uq_tenant_ingress_route_domain"
            ),
        )
        op.create_index(
            "ix_tenant_ingress_routes_tenant_id",
            "tenant_ingress_routes",
            ["tenant_id"],
        )
        op.create_index(
            "ix_tenant_ingress_routes_owner",
            "tenant_ingress_routes",
            ["owner_kind", "owner_id"],
        )
    # SQLite (tests) has no information_schema and no hosting table: copy only
    # when the source exists, exactly like the plugin migrations do.
    inspector = sa.inspect(bind)
    if "hosting_rootless_routes" not in set(inspector.get_table_names()):
        return
    source = sa.Table(
        "hosting_rootless_routes",
        sa.MetaData(),
        sa.Column("site_id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String()),
        sa.Column("domain", sa.String()),
        sa.Column("target", sa.String()),
        sa.Column("port", sa.Integer()),
        sa.Column("updated_at", sa.DateTime()),
    )
    destination = sa.Table(
        "tenant_ingress_routes",
        sa.MetaData(),
        sa.Column("route_id", sa.String()),
        sa.Column("tenant_id", sa.String()),
        sa.Column("owner_kind", sa.String()),
        sa.Column("owner_id", sa.String()),
        sa.Column("service", sa.String()),
        sa.Column("domain", sa.String()),
        sa.Column("target", sa.String()),
        sa.Column("port", sa.Integer()),
        sa.Column("updated_at", sa.DateTime()),
    )
    existing = {
        row[0]
        for row in bind.execute(sa.select(destination.c.route_id)).all()
    }
    rows = bind.execute(sa.select(source)).mappings().all()
    for row in rows:
        route_id = f"hosting:{row['site_id']}"
        if route_id in existing:
            continue
        bind.execute(
            destination.insert().values(
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


def downgrade() -> None:
    bind = op.get_bind()
    if "tenant_ingress_routes" in set(sa.inspect(bind).get_table_names()):
        op.drop_table("tenant_ingress_routes")
