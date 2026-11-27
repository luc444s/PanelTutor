"""Create host-wide Cloudflare tables and zone ownership (A.SPEC 0124).

Additive only: the existing tenant connection and flow tables (004) are never
altered. The migration runs on every boot through the plugin runtime and is
safe to re-execute; it also works with SQLite in tests.
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    inspect,
    text,
)

revision = "007_cloudflare_single_mode"
metadata = MetaData()
Table("tenants", metadata, Column("id", String(36), primary_key=True))

host_connection = Table(
    "domains_cloudflare_host_connection",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("cloudflare_account_id", String(32), nullable=False),
    Column("account_name", String(255), nullable=False),
    Column("access_ciphertext", LargeBinary, nullable=False),
    Column("access_nonce", LargeBinary, nullable=False),
    Column("refresh_ciphertext", LargeBinary, nullable=True),
    Column("refresh_nonce", LargeBinary, nullable=True),
    Column("key_version", Integer, nullable=False, server_default="1"),
    Column("scopes_json", JSON, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=True),
    Column("status", String(32), nullable=False, server_default="active"),
    Column(
        "created_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    ),
    Column(
        "updated_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    ),
    CheckConstraint("id = 1", name="ck_cloudflare_host_connection_singleton"),
)

host_flows = Table(
    "domains_cloudflare_host_oauth_flows",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("state_hash", String(64), nullable=False),
    Column("verifier_ciphertext", LargeBinary, nullable=False),
    Column("verifier_nonce", LargeBinary, nullable=False),
    Column("key_version", Integer, nullable=False, server_default="1"),
    Column("redirect_uri", String(1000), nullable=False),
    Column("status", String(32), nullable=False, server_default="pending"),
    Column("error_code", String(64), nullable=True),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("consumed_at", DateTime(timezone=True), nullable=True),
    Column(
        "created_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    ),
    Column(
        "updated_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    ),
    UniqueConstraint("state_hash"),
    Index(
        "ix_domains_cloudflare_host_oauth_flows_state_hash",
        "state_hash",
    ),
)

zone_ownership = Table(
    "domains_cloudflare_zone_ownership",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("tenant_id", String(36), ForeignKey("tenants.id"), nullable=False),
    Column("zone_id", String(32), nullable=False),
    Column("zone_name", String(253), nullable=False),
    Column("account_id", String(32), nullable=False),
    Column(
        "created_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    ),
    Column(
        "updated_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    ),
    UniqueConstraint("zone_id"),
    UniqueConstraint("zone_name"),
    Index(
        "ix_domains_cloudflare_zone_ownership_tenant_id",
        "tenant_id",
    ),
)


def upgrade(db) -> None:
    bind = db.get_bind() if hasattr(db, "get_bind") else db
    names = set(inspect(bind).get_table_names())
    for table in (host_connection, host_flows, zone_ownership):
        if table.name not in names:
            table.create(bind)


def downgrade(db) -> None:
    bind = db.get_bind() if hasattr(db, "get_bind") else db
    names = set(inspect(bind).get_table_names())
    for table in (host_flows, host_connection, zone_ownership):
        if table.name in names:
            table.drop(bind)
