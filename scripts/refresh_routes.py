#!/usr/bin/env python3
"""Re-render Domains routes for Apps applications without the UI or a deploy.

This is the autonomous equivalent of opening each service's Dominios tab and
saving the route again. It reuses the Domains renderer, ownership checks and
container reconnection, then optionally restarts the proxy so failed ACME
orders are retried immediately.

Run inside the Spanel app container.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence

from fastapi import FastAPI
from plugins.apps.backend.cell_ingress import AppsIngress
from plugins.apps.backend.models import Application
from plugins.apps.backend.register import resolve_apps_sites
from plugins.apps.backend.rootless_routes import build_rootless_routes
from plugins.domains.backend.service import (
    provide_app_hosts,
    refresh_application_routes,
)
from plugins.domains.backend.settings import register_domains_settings
from sqlalchemy import select
from systutor.contracts.app_hosts import list_app_hosts, register_app_host_provider
from systutor.contracts.domain_ownership import register_site_provider
from systutor.core.config import get_settings
from systutor.core.database import build_session_factory
from systutor.kernel.cell_ingress import TenantIngressRoute


def select_applications(db, application_id: str | None, slug: str | None) -> list[Application]:
    stmt = select(Application).where(Application.deleted_at.is_(None))
    if application_id:
        stmt = stmt.where(Application.id == application_id)
    elif slug:
        stmt = stmt.where(Application.slug == slug)
    return list(db.scalars(stmt.order_by(Application.created_at)).all())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    identity = parser.add_mutually_exclusive_group()
    identity.add_argument("--application-id", "--app-id", dest="application_id")
    identity.add_argument("--slug")
    parser.add_argument("--restart-proxy", action="store_true")
    parser.add_argument("--proxy-container", default="traefik")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    try:
        register_domains_settings()
        fastapi_app = FastAPI()
        register_site_provider(fastapi_app, "apps", resolve_apps_sites)
        register_app_host_provider(fastapi_app, "domains", provide_app_hosts)
        rootless = build_rootless_routes(fastapi_app)
        settings = get_settings()
        factory = build_session_factory(settings)
        with factory() as db:
            applications = select_applications(db, args.application_id, args.slug)
            if not applications:
                print("No applications match")
                return 2
            for application in applications:
                hosts = list_app_hosts(
                    fastapi_app, db, application.tenant_id, application.id
                )
                cut_over = db.scalar(
                    select(TenantIngressRoute.route_id).where(
                        TenantIngressRoute.tenant_id == application.tenant_id,
                        TenantIngressRoute.owner_kind == "apps",
                        TenantIngressRoute.owner_id == application.id,
                    )
                ) is not None
                rootless_app = bool(hosts) and (rootless is not None or cut_over)
                if args.dry_run:
                    mode = "rootless ingress + relay" if rootless_app else "routes"
                    print(f"{application.slug}: its {mode} would be refreshed")
                    continue
                if rootless_app:
                    if rootless is None:
                        print(
                            f"{application.slug}: rootless relay is not configured; "
                            "refusing to overwrite the relay document",
                            file=sys.stderr,
                        )
                        continue
                    # A rootless App's document points at the relay; rendering
                    # it again with the container target would overwrite it.
                    AppsIngress(fastapi_app, db).reconcile(
                        application.tenant_id, application.id
                    )
                    rootless.refresh(
                        db, application.tenant_id, application.id
                    )
                    print(f"{application.slug}: rootless ingress and relay refreshed")
                    continue
                refresh_application_routes(
                    db, fastapi_app, application.tenant_id, application.id
                )
                print(f"{application.slug}: routes refreshed")
        if args.restart_proxy and not args.dry_run:
            subprocess.run(
                ["docker", "restart", args.proxy_container],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            print(f"{args.proxy_container}: restarted to retry ACME")
        return 0
    except Exception as exc:  # noqa: BLE001 - mensaje operativo sin secretos
        print(f"refresh_routes: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
