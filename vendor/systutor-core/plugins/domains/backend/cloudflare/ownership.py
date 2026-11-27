"""Tenant ownership of zones inside a single shared Cloudflare account.

The ownership table is the isolation authority in `single` mode. Every read or
write of a zone or record must first resolve a row for the current tenant; the
absence of a row is reported as `zone_not_found` so a tenant never learns that
another tenant owns the zone.
"""

from __future__ import annotations

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from plugins.domains.backend.cloudflare.client import (
    CloudflareZoneInUse,
    CloudflareZoneNotFound,
)
from plugins.domains.backend.models import CloudflareZoneOwnership


def normalize_zone_name(value: str) -> str:
    return (value or "").strip().rstrip(".").lower()


def get_ownership_by_zone_id(db: Session, zone_id: str) -> CloudflareZoneOwnership | None:
    return db.scalar(
        select(CloudflareZoneOwnership).where(
            CloudflareZoneOwnership.zone_id == zone_id
        )
    )


def get_ownership_by_zone_name(
    db: Session, zone_name: str
) -> CloudflareZoneOwnership | None:
    return db.scalar(
        select(CloudflareZoneOwnership).where(
            CloudflareZoneOwnership.zone_name == normalize_zone_name(zone_name)
        )
    )


def get_tenant_ownership(
    db: Session, tenant_id: str, zone_id: str
) -> CloudflareZoneOwnership | None:
    return db.scalar(
        select(CloudflareZoneOwnership)
        .where(CloudflareZoneOwnership.tenant_id == tenant_id)
        .where(CloudflareZoneOwnership.zone_id == zone_id)
    )


def require_tenant_ownership(
    db: Session, tenant_id: str, zone_id: str
) -> CloudflareZoneOwnership:
    row = get_tenant_ownership(db, tenant_id, zone_id)
    if row is None:
        raise CloudflareZoneNotFound("Cloudflare zone not found")
    return row


def owned_zone_ids(db: Session, tenant_id: str, zone_ids: set[str]) -> set[str]:
    if not zone_ids:
        return set()
    statement = select(CloudflareZoneOwnership.zone_id).where(
        CloudflareZoneOwnership.tenant_id == tenant_id,
        CloudflareZoneOwnership.zone_id.in_(zone_ids),
    )
    return {str(value) for value in db.scalars(statement).all()}


def list_ownerships(db: Session, tenant_id: str | None = None) -> list[CloudflareZoneOwnership]:
    statement = select(CloudflareZoneOwnership).order_by(
        CloudflareZoneOwnership.zone_name.asc()
    )
    if tenant_id is not None:
        statement = statement.where(CloudflareZoneOwnership.tenant_id == tenant_id)
    return list(db.scalars(statement).all())


def lock_zone_name(db: Session, zone_name: str) -> None:
    """Serialize concurrent applies for one zone name on PostgreSQL.

    SQLite has a single writer, so no advisory lock is needed there. The helper
    intentionally only emits PostgreSQL syntax when the active dialect is
    PostgreSQL; tests stay portable.
    """
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:zone_name))"),
            {"zone_name": normalize_zone_name(zone_name)},
        )


def claim_zone(
    db: Session,
    *,
    tenant_id: str,
    zone_id: str,
    zone_name: str,
    account_id: str,
) -> tuple[CloudflareZoneOwnership, bool]:
    """Insert or reuse a tenant's ownership row without auto-claiming zones.

    Raises `CloudflareZoneInUse` when another tenant already owns the zone id or
    zone name. The caller controls the transaction/savepoint.
    """
    name = normalize_zone_name(zone_name)
    existing = get_ownership_by_zone_id(db, zone_id)
    if existing is None:
        existing = get_ownership_by_zone_name(db, name)
    if existing is not None:
        if existing.tenant_id != tenant_id:
            raise CloudflareZoneInUse("the Cloudflare zone belongs to another tenant")
        name_row = get_ownership_by_zone_name(db, name)
        if name_row is not None and name_row.id != existing.id:
            raise CloudflareZoneInUse("the Cloudflare zone belongs to another tenant")
        try:
            with db.begin_nested():
                existing.zone_id = zone_id
                existing.zone_name = name
                existing.account_id = account_id
                db.flush()
        except IntegrityError as exc:
            raise CloudflareZoneInUse(
                "the Cloudflare zone belongs to another tenant"
            ) from exc
        return existing, False
    row = CloudflareZoneOwnership(
        tenant_id=tenant_id,
        zone_id=zone_id,
        zone_name=name,
        account_id=account_id,
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError as exc:
        raise CloudflareZoneInUse("the Cloudflare zone belongs to another tenant") from exc
    return row, True
