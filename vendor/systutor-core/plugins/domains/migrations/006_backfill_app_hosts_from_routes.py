"""Backfill Domains AppHosts from routes created before A.SPEC 0114.

Apps rootless ingress is fed by ``domains_app_hosts``. Deployments that were
migrated before the AppHost contract only kept ``domains_routes`` rows, so the
cell ingress had no Host to publish and the legacy Traefik document kept
pointing at a stopped rootful container (502). This migration recreates the
missing AppHost from the existing root route.

It is idempotent: the runtime migrator records the revision, and the inserts
also skip any service/domain that already has a Host.
"""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import inspect, text

revision = "006_backfill_app_hosts_from_routes"

_REQUIRED_TABLES = {"apps_applications", "domains_app_hosts", "domains_routes"}


def _bind(db):
    return db.get_bind() if hasattr(db, "get_bind") else db


def upgrade(db) -> None:
    bind = _bind(db)
    if not _REQUIRED_TABLES <= set(inspect(bind).get_table_names()):
        return
    routes = db.execute(
        text(
            "SELECT tenant_id, site_id, domain, https "
            "FROM domains_routes WHERE path = '/' "
            "ORDER BY updated_at DESC"
        )
    ).mappings()
    seen: set[tuple[str, str, str]] = set()
    for row in routes:
        application_id, separator, service = str(row["site_id"] or "").partition(":")
        if not separator or not application_id or not service:
            # Hosting sites use a plain uuid; they are not App Hosts.
            continue
        key = (str(row["tenant_id"]), application_id, service)
        if key in seen:
            continue
        seen.add(key)
        exists = db.execute(
            text(
                "SELECT 1 FROM domains_app_hosts "
                "WHERE tenant_id=:tenant_id AND application_id=:application_id "
                "AND service=:service"
            ),
            {
                "tenant_id": key[0],
                "application_id": application_id,
                "service": service,
            },
        ).first()
        if exists is not None:
            continue
        if db.execute(
            text("SELECT 1 FROM domains_app_hosts WHERE domain=:domain"),
            {"domain": row["domain"]},
        ).first() is not None:
            continue
        app_exists = db.execute(
            text(
                "SELECT 1 FROM apps_applications "
                "WHERE id=:application_id AND deleted_at IS NULL"
            ),
            {"application_id": application_id},
        ).first()
        if app_exists is None:
            continue
        db.execute(
            text(
                "INSERT INTO domains_app_hosts "
                "(id, tenant_id, application_id, service, domain, https, "
                "created_at, updated_at) VALUES "
                "(:id, :tenant_id, :application_id, :service, :domain, :https, "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {
                "id": str(uuid4()),
                "tenant_id": key[0],
                "application_id": application_id,
                "service": service,
                "domain": str(row["domain"]).strip().lower().removesuffix("."),
                "https": bool(row["https"]),
            },
        )


def downgrade(db) -> None:
    """A backfill is data, not schema; there is nothing safe to undo."""
    del db
