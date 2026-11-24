#!/usr/bin/env python3
"""Migrate existing Apps to the rootless cell ingress (A.SPEC 0114).

Runs inside the Spanel app container (``spanel-app-1``): it needs the database,
Domains and the tenant cell handle.  It never talks to the rootful Docker
daemon except to retain or stop containers with ``--stop-rootful``.

    export SPANEL_DOMAIN=spanel.systutor.com
    python3 /app/scripts/migrate_apps_rootless.py --tenant milton --dry-run
    python3 /app/scripts/migrate_apps_rootless.py --tenant milton --apply

Phases per App: inventory -> preflight -> ingress -> cutover -> verify ->
retain/stop rootful -> result.  Exit codes: 0 ok, 1 failure, 2 usage/error.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_LEDGER = "/var/lib/spanel/apps-rootless-operations.json"


class MigrationError(RuntimeError):
    """A failure already explained to the operator."""


@dataclass
class Step:
    phase: str
    status: str
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class AppResult:
    application_id: str
    slug: str
    ok: bool = False
    dry_run: bool = True
    domains: list[str] = field(default_factory=list)
    containers: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    error: str = ""

    def add(self, phase: str, status: str, detail: str = "") -> None:
        self.steps.append(Step(phase, status, detail))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--app", action="append", default=[], dest="apps")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", default=True)
    mode.add_argument("--apply", action="store_false", dest="dry_run")
    parser.add_argument("--stop-rootful", action="store_true")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--rollback", default=None)
    parser.add_argument("--ledger", default=DEFAULT_LEDGER)
    return parser


# -- ledger ------------------------------------------------------------------


class OperationLedger:
    """Minimal idempotent record of retained rootful containers."""

    def __init__(self, path: str | Path = DEFAULT_LEDGER) -> None:
        self.path = Path(path)

    def _load(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")

    def record(self, operation_id: str, value: dict[str, Any]) -> None:
        data = self._load()
        data[operation_id] = value
        self._save(data)

    def get(self, operation_id: str) -> dict[str, Any] | None:
        return self._load().get(operation_id)


# -- rootful helpers ---------------------------------------------------------


def docker(argv: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *argv], capture_output=True, text=True, check=False,
        timeout=timeout,
    )


def rootful_containers(project: str, timeout: int = 60) -> list[str]:
    result = docker(
        ["ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
        timeout=timeout,
    )
    if result.returncode:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def stop_rootful(project: str, timeout: int = 60) -> list[str]:
    containers = rootful_containers(project, timeout=timeout)
    if containers:
        docker(["stop", *containers], timeout=timeout)
    return containers


def start_rootful(containers: list[str], timeout: int = 60) -> None:
    if containers:
        docker(["start", *containers], timeout=timeout)


# -- migration ---------------------------------------------------------------


class AppsRootlessMigrator:
    def __init__(
        self,
        db: Any,
        fastapi_app: Any,
        *,
        tenant_id: str,
        dry_run: bool = True,
        stop_rootful_enabled: bool = False,
        timeout: int = 60,
        ledger: OperationLedger | None = None,
    ) -> None:
        self.db = db
        self.app = fastapi_app
        self.tenant_id = tenant_id
        self.dry_run = dry_run
        self.stop_rootful_enabled = stop_rootful_enabled
        self.timeout = timeout
        self.ledger = ledger or OperationLedger()

    def _hosts(self, application_id: str) -> list[Any]:
        from systutor.contracts.app_hosts import list_app_hosts

        return list(
            list_app_hosts(self.app, self.db, self.tenant_id, application_id)
        )

    def _preflight(self) -> tuple[Any, Any]:
        from plugins.apps.backend.rootless_routes import build_rootless_routes
        from plugins.apps.backend.runtime.tenant_runtime import tenant_slug
        from systutor.contracts.container_runtime import (
            resolve_container_runtime,
        )

        handle = resolve_container_runtime(
            self.app, self.db, self.tenant_id, "rootless"
        )
        health = handle.health()
        if health.state != "ready":
            raise MigrationError(f"cell handle is {health.state}")
        routes = build_rootless_routes(self.app)
        if routes is None:
            raise MigrationError("rootless route client is not configured")
        endpoint = routes.endpoint(tenant_slug(self.db, self.tenant_id))
        if not endpoint.bind or not endpoint.relay_port:
            raise MigrationError("relay endpoint is incomplete")
        return handle, routes

    def _verify(self, domains: list[str]) -> None:
        try:
            from plugins.hosting.backend.rootless_ingress import (
                verify_external_route,
            )
        except ImportError as exc:  # pragma: no cover - Hosting is installed
            raise MigrationError("external verifier is unavailable") from exc
        for domain in domains:
            verify_external_route(
                domain, deadline_seconds=max(5, self.timeout)
            )

    def migrate_app(self, application: Any) -> AppResult:
        from plugins.apps.backend.cell_ingress import AppsIngress

        result = AppResult(
            application_id=application.id,
            slug=application.slug,
            dry_run=self.dry_run,
        )
        try:
            hosts = self._hosts(application.id)
            if not hosts:
                result.add("inventory", "skipped", "no Domains Host")
                result.ok = True
                return result
            result.domains = [host.domain for host in hosts]
            result.add("inventory", "ok", f"{len(hosts)} Domains Host(s)")
            deployment = (
                self.db.get(
                    __import__(
                        "plugins.apps.backend.models",
                        fromlist=["Deployment"],
                    ).Deployment,
                    application.active_deployment_id,
                )
                if application.active_deployment_id
                else None
            )
            if deployment is None:
                raise MigrationError("no active deployment")
            manifest = (
                deployment.manifest
                if isinstance(deployment.manifest, dict) else {}
            )
            containers = manifest.get("containers") or {}
            names = manifest.get("container_names") or {}
            container_names = {
                str(service): str(names.get(service) or container)
                for service, container in containers.items()
            }
            result.containers = sorted(
                value for value in container_names.values() if value
            )
            result.add("inventory", "ok", f"{len(containers)} container(s)")
            if self.dry_run:
                result.add("preflight", "pending", "--apply required")
                result.ok = True
                return result
            _, routes = self._preflight()
            result.add("preflight", "ok", "handle ready, relay resolved")
            AppsIngress(self.app, self.db).reconcile(
                self.tenant_id, application.id
            )
            result.add("ingress", "ok")
            published = routes.refresh(
                self.db, self.tenant_id, application.id
            )
            result.add("cutover", "ok", ",".join(published.get("published", [])))
            self.db.commit()
            self._verify(result.domains)
            result.add("verify", "ok", "external HTTP 200")
            if self.stop_rootful_enabled:
                stopped = stop_rootful(application.runtime_project, self.timeout)
                self.ledger.record(
                    f"apps-rootless:{application.id}",
                    {
                        "application_id": application.id,
                        "tenant_id": self.tenant_id,
                        "runtime_project": application.runtime_project,
                        "routes": {
                            host.domain: {
                                "container": container_names.get(host.service, ""),
                                "port": host.port,
                            }
                            for host in hosts
                        },
                        "stopped": stopped,
                        "domains": result.domains,
                    },
                )
                result.add("retain", "stopped", f"{len(stopped)} container(s)")
            else:
                result.add("retain", "retained")
            result.ok = True
        except Exception as exc:  # noqa: BLE001 - report, never leak secrets
            result.error = str(exc)[:500]
            result.add("result", "failed", result.error)
            self.db.rollback()
        return result

    def migrate(self, slug: str | None = None) -> dict[str, Any]:
        from plugins.apps.backend.models import Application
        from sqlalchemy import select

        stmt = select(Application).where(
            Application.tenant_id == self.tenant_id,
            Application.deleted_at.is_(None),
        )
        if slug:
            stmt = stmt.where(Application.slug == slug)
        apps = list(self.db.scalars(stmt.order_by(Application.slug)))
        results = [self.migrate_app(application) for application in apps]
        return {
            "ok": all(result.ok for result in results),
            "tenant": self.tenant_id,
            "dry_run": self.dry_run,
            "apps": [asdict(result) for result in results],
        }

    def rollback(self, operation_id: str) -> dict[str, Any]:
        from plugins.apps.backend.cell_ingress import AppsIngress
        from systutor.contracts.site_domain_publisher import (
            get_site_domain_publisher,
        )

        record = self.ledger.get(operation_id)
        if record is None:
            raise MigrationError(f"unknown operation: {operation_id}")
        application_id = str(record.get("application_id") or "")
        result = AppResult(
            application_id=application_id, slug=application_id, dry_run=False
        )
        try:
            AppsIngress(self.app, self.db).remove(
                self.tenant_id, application_id
            )
            result.add("ingress", "removed")
            from plugins.apps.backend.rootless_routes import (
                build_rootless_routes as build_routes,
            )

            routes = build_routes(self.app)
            if routes is not None:
                houses = self._hosts(application_id)
                for host in houses:
                    routes.publisher.unpublish(host.domain)
                result.add("relay", "removed")
            publisher = get_site_domain_publisher(self.app)
            stopped = record.get("stopped") or []
            if publisher is not None:
                for domain, value in (record.get("routes") or {}).items():
                    # Ledgers written before A.SPEC 0114 stored only the
                    # container; new ones keep the port of the Domains route.
                    if isinstance(value, dict):
                        container = str(value.get("container") or "")
                        port = int(value.get("port") or 80)
                    else:
                        container, port = str(value or ""), 80
                    if container:
                        publisher.publish(container, str(domain), port)
                result.add("legacy", "republished")
            if self.stop_rootful_enabled:
                start_rootful([str(item) for item in stopped], self.timeout)
                result.add("rootful", "started")
            self.db.commit()
            result.ok = True
        except Exception as exc:  # noqa: BLE001
            result.error = str(exc)[:500]
            result.add("result", "failed", result.error)
            self.db.rollback()
        return {"ok": result.ok, "rollback": operation_id, "app": asdict(result)}


def _select_app(db: Any, tenant_id: str, app_id: str) -> Any:
    from plugins.apps.backend.models import Application

    return db.get(Application, app_id)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        from app.main import app

        factory = getattr(app.state, "session_factory", None)
        if factory is None:
            raise MigrationError("session factory is unavailable")
        ledger = OperationLedger(args.ledger)
        with factory() as db:
            migrator = AppsRootlessMigrator(
                db,
                app,
                tenant_id=args.tenant,
                dry_run=args.dry_run,
                stop_rootful_enabled=args.stop_rootful,
                timeout=args.timeout,
                ledger=ledger,
            )
            if args.rollback:
                payload = migrator.rollback(args.rollback)
            elif args.apps:
                results = []
                for application_id in args.apps:
                    application = _select_app(db, args.tenant, application_id)
                    if application is None:
                        raise MigrationError(
                            f"application {application_id} not found"
                        )
                    results.append(asdict(migrator.migrate_app(application)))
                payload = {
                    "ok": all(item["ok"] for item in results),
                    "tenant": args.tenant,
                    "dry_run": args.dry_run,
                    "apps": results,
                }
            else:
                payload = migrator.migrate()
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                f"tenant={payload.get('tenant')} ok={payload.get('ok')} "
                f"dry_run={payload.get('dry_run')}"
            )
            for item in payload.get("apps", []):
                print(
                    f"  {item.get('slug')}: ok={item.get('ok')} "
                    f"domains={','.join(item.get('domains', []))} "
                    f"{item.get('error', '')}"
                )
        return 0 if payload.get("ok") else 1
    except Exception as exc:  # noqa: BLE001 - operational message without secrets
        print(f"migrate_apps_rootless: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
