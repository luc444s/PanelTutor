"""Create Domains-owned rootless app Hosts and backfill the Apps legacy field."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    false,
    inspect,
    text,
)

revision = "005_rootless_app_hosts"
metadata = MetaData()
Table("tenants", metadata, Column("id", String(36), primary_key=True))

app_hosts = Table(
    "domains_app_hosts",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("tenant_id", String(36), ForeignKey("tenants.id"), nullable=False),
    Column("application_id", String(36), nullable=False),
    Column("service", String(255), nullable=False),
    Column("domain", String(253), nullable=False),
    Column("https", Boolean, nullable=False, server_default=false()),
    Column(
        "created_at", DateTime(timezone=True), nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    ),
    Column(
        "updated_at", DateTime(timezone=True), nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    ),
    UniqueConstraint("tenant_id", "application_id", "service"),
    UniqueConstraint("domain"),
    Index("ix_domains_app_hosts_tenant_id", "tenant_id"),
    Index("ix_domains_app_hosts_application_id", "application_id"),
    Index("ix_domains_app_hosts_domain", "domain"),
)


def upgrade(db) -> None:
    bind = db.get_bind() if hasattr(db, "get_bind") else db
    names = set(inspect(bind).get_table_names())
    if app_hosts.name not in names:
        app_hosts.create(bind)
    if "apps_applications" not in names:
        return
    # A.SPEC 0114: the Apps plugin drops ``domain``/``ingress_service``. This
    # migration may run again after every boot (the registry is recreated), so
    # the legacy backfill must disappear with the columns instead of failing.
    columns = {
        column["name"]
        for column in inspect(bind).get_columns("apps_applications")
    }
    if not {"domain", "ingress_service"}.issubset(columns):
        return
    rows = db.execute(
        text(
            "SELECT id, tenant_id, ingress_service, domain "
            "FROM apps_applications WHERE domain IS NOT NULL AND domain <> ''"
        )
    ).mappings()
    for row in rows:
        exists = db.execute(
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
        if exists is None:
            db.execute(
                app_hosts.insert().values(
                    id=str(uuid4()),
                    tenant_id=row["tenant_id"],
                    application_id=row["id"],
                    service=row["ingress_service"],
                    domain=str(row["domain"]).strip().lower().removesuffix("."),
                    https=True,
                )
            )


def downgrade(db) -> None:
    bind = db.get_bind() if hasattr(db, "get_bind") else db
    if app_hosts.name in set(inspect(bind).get_table_names()):
        app_hosts.drop(bind)
