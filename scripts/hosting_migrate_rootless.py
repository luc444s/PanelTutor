#!/usr/bin/env python3
"""Operator CLI for the Hosting rootless migration backend (A.SPEC 0110-A)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "vendor" / "systutor-core"
for path in (str(CORE / "src"), str(CORE), str(ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from plugins.hosting.backend.models import HostingSite
from plugins.hosting.backend.rootless_migration import RootlessMigrationService
from sqlalchemy import select
from systutor.core.lifecycle import ensure_session_factory
from systutor.kernel.tenants.models import Tenant


def _ensure_plugins_dir() -> None:
    """Use checkout plugins when a container-only path leaked to the host CLI."""
    configured = Path(os.environ.get("SYSTUTOR_PLUGINS_DIR", ""))
    if configured.is_dir():
        return
    checkout_plugins = CORE / "plugins"
    if checkout_plugins.is_dir():
        os.environ["SYSTUTOR_PLUGINS_DIR"] = str(checkout_plugins)


@contextmanager
def service_context() -> Iterator[tuple[RootlessMigrationService, Any]]:
    _ensure_plugins_dir()
    from app.main import create_app

    app = create_app()
    factory = ensure_session_factory(app)
    with factory() as db:
        yield RootlessMigrationService(app, db), db


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hosting_migrate_rootless.py")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "migrate"):
        item = sub.add_parser(name)
        item.add_argument("--site")
        item.add_argument("--tenant")
        item.add_argument("--all", action="store_true")
        item.add_argument("--kind", choices=("static", "wordpress"))
        item.add_argument("--exclude", action="append", default=[])
        item.add_argument(
            "--shared-db",
            default=None,
            help="Legacy shared database container (explicit opt-in).",
        )
        item.add_argument("--json", action="store_true")
        if name == "migrate":
            item.add_argument("--dry-run", action="store_true")
            failure = item.add_mutually_exclusive_group()
            failure.add_argument("--stop-on-failure", action="store_true", default=True)
            failure.add_argument("--continue-on-failure", action="store_true")
    for name in ("rollback", "finalize"):
        item = sub.add_parser(name)
        item.add_argument("--site", required=True)
        item.add_argument("--operation", required=True)
        item.add_argument("--json", action="store_true")
        if name == "finalize":
            item.add_argument("--confirm-domain", required=True)
    for name in ("status", "reconcile"):
        item = sub.add_parser(name)
        item.add_argument("--site", required=True)
        item.add_argument("--json", action="store_true")
    item = sub.add_parser("verify-pma")
    item.add_argument("--site")
    item.add_argument("--tenant")
    item.add_argument("--all", action="store_true")
    item.add_argument("--json", action="store_true")
    return parser


def _sites(db: Any, args: argparse.Namespace) -> list[HostingSite]:
    if args.site:
        row = db.get(HostingSite, args.site)
        if row is None:
            raise ValueError("site not found")
        return [row]
    if not args.all or not args.tenant:
        raise ValueError("use --site, or --tenant <slug> --all")
    tenant = db.scalar(select(Tenant).where(Tenant.slug == args.tenant))
    if tenant is None:
        raise ValueError("tenant not found")
    stmt = select(HostingSite).where(HostingSite.tenant_id == tenant.id)
    kind = getattr(args, "kind", None)
    if kind:
        stmt = stmt.where(HostingSite.kind == kind)
    excluded = set(getattr(args, "exclude", []) or [])
    rows = [row for row in db.scalars(stmt) if row.id not in excluded]
    order = {"static": 0, "wordpress": 1}
    return sorted(rows, key=lambda row: (order.get(row.kind, 9), row.id))


def _verify_pma_site(service: RootlessMigrationService, site: HostingSite) -> dict[str, Any]:
    """Exercise the same broker + login path as the phpMyAdmin button."""
    import secrets

    from plugins.hosting.backend.phpmyadmin_broker import close_relay_quietly
    from plugins.hosting.backend.phpmyadmin_proxy import PmaClient, validate_url
    from plugins.hosting.backend.service import HostingService
    from systutor.kernel.tenants.context import TenantContext

    settings = service.settings
    hosting = HostingService(service.db, settings=settings, app=service.app)
    # The audit row stays tenant-scoped; there is no interactive user in a
    # migration job, so the actor is deliberately null.
    context = TenantContext(site.tenant_id, None, None, (), None)  # type: ignore[arg-type]
    relay: dict[str, str] | None = None
    try:
        relay = hosting.phpmyadmin_relay_server(
            site, context, secrets.token_urlsafe(32)
        )
        client = PmaClient(
            validate_url(settings.phpmyadmin_internal_url),
            settings.phpmyadmin_timeout,
        )
        cookies = hosting.phpmyadmin_login_credentials(
            site,
            context,
            client,
            server=relay["server"] if relay else None,
        )
        if not cookies:
            raise RuntimeError("phpMyAdmin returned no session cookie")
        return {
            "ok": True,
            "site_id": site.id,
            "domain": str(site.domain),
            "kind": site.kind,
            "relay": bool(relay),
        }
    except Exception as exc:  # noqa: BLE001 - operator CLI reports the boundary
        return {
            "ok": False,
            "site_id": site.id,
            "domain": str(site.domain),
            "kind": site.kind,
            "error": str(exc)[:300],
            "code": getattr(exc, "code", None),
        }
    finally:
        if relay is not None:
            close_relay_quietly(
                settings,
                relay.get("tenant_slug"),
                relay.get("relay_id"),
            )


def execute(args: argparse.Namespace) -> dict[str, Any]:
    with service_context() as (service, db):
        if args.command in {"plan", "migrate"}:
            sites = _sites(db, args)
            results: list[dict[str, Any]] = []
            for site in sites:
                try:
                    result = (
                        service.plan(site.id)
                        if args.command == "plan" or args.dry_run
                        else service.migrate(
                            site.id, shared_db=getattr(args, "shared_db", None)
                        )
                    )
                except Exception as exc:  # noqa: BLE001 - CLI redacts the boundary
                    result = {
                        "ok": False,
                        "operation_id": None,
                        "site_id": site.id,
                        "kind": site.kind,
                        "from_runtime": "rootful",
                        "to_runtime": "rootless",
                        "state": "failed",
                        "steps": [],
                        "rollback_available": False,
                        "error": str(exc)[:300],
                    }
                results.append(result)
                if not result.get("ok") and not getattr(
                    args, "continue_on_failure", False
                ):
                    break
            if len(results) == 1 and args.site:
                return results[0]
            return {"ok": all(row.get("ok") for row in results), "results": results}
        if args.command == "verify-pma":
            sites = [site for site in _sites(db, args) if site.kind == "wordpress"]
            if not sites:
                return {
                    "ok": False,
                    "error": "no WordPress site selected for phpMyAdmin verification",
                    "results": [],
                }
            results = [_verify_pma_site(service, site) for site in sites]
            if len(results) == 1 and args.site:
                return results[0]
            return {"ok": all(row.get("ok") for row in results), "results": results}
        if args.command == "rollback":
            return service.rollback(args.site, args.operation)
        if args.command == "finalize":
            return service.finalize(args.site, args.operation, args.confirm_domain)
        if args.command == "status":
            return service.status(args.site)
        return service.reconcile(args.site)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if getattr(args, "json", False):
            with redirect_stdout(sys.stderr):
                payload = execute(args)
        else:
            payload = execute(args)
    except Exception as exc:  # noqa: BLE001 - printable operator error
        payload = {"ok": False, "error": str(exc)[:300]}
    if getattr(args, "json", False):
        print(json.dumps(payload, sort_keys=True, default=str))
    else:
        for key, value in payload.items():
            print(f"{key}: {value}")
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
