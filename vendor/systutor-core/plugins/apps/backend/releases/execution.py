"""Trusted release orchestration shared by the Apps worker.

The worker owns operation lifecycle and source preparation; this module owns the
parts that consume a signed release: hardening, scoped deploy and rollback.
Every entry point re-verifies the descriptor before touching the runtime.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ..managed_environment import MANAGED_DATABASE_NAMES
from ..models import Application, Deployment, Operation
from ..runtime import AppDeployError, Runner
from .pipeline import create_release, release_result
from .planner import DeployScope, plan_deployment
from .scoped_execution import (
    ScopedDeployFailed,
    ScopedRestoreError,
    deploy_scoped,
)
from .store import find_release, release_store_root
from .trusted import TrustedRelease
from .verify import verify_release

logger = logging.getLogger(__name__)

_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def application_lock(application_id: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(application_id, threading.Lock())


def pending_env_path(operation_id: str) -> Path:
    return release_store_root(os.environ) / "pending" / f"{operation_id}.env"


def _probe_target(service: object, port: object) -> tuple[str, int] | None:
    """Derive the default probe target from the app ingress."""
    if (
        isinstance(service, str) and service
        and isinstance(port, int) and 1 <= port <= 65535
    ):
        return service, port
    return None


def _declared_services(
    release: TrustedRelease,
    manifest: dict[str, Any] | None = None,
) -> list[str]:
    if release.service_fingerprints:
        return sorted(release.service_fingerprints)
    if isinstance(manifest, dict):
        services = manifest.get("services")
        if isinstance(services, list):
            return sorted({str(item) for item in services if str(item)})
    return []


class ReleaseExecution:
    """Signed-release operations bound to a worker's session and runtime."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        runner_factory: Callable[..., Runner],
        *,
        hardening_engine: Any,
        route_refresh: Callable[[Session, str, str], None] | None,
        transport: Callable[[], str],
    ) -> None:
        self.session_factory = session_factory
        self.runner_factory = runner_factory
        self.hardening_engine = hardening_engine
        self.route_refresh = route_refresh
        self.transport = transport

    def _publish_restored_state(
        self,
        *,
        application_id: str,
        operation_id: str,
        previous_id: str | None,
        manifest: Mapping[str, Any],
        repository: str,
        branch: str,
    ) -> str | None:
        """Persist the verified restoration as the new active deployment.

        A failed partial deploy can recreate the touched containers while
        restoring them.  Without publishing those new identities the historical
        manifest would point at dead container IDs and the next deployment
        could not prove the untouched services.
        """

        if previous_id is None:
            return None
        restoration = manifest.get("restoration")
        restoration = restoration if isinstance(restoration, Mapping) else {}
        containers = restoration.get("container_ids")
        if not isinstance(containers, Mapping) or not containers:
            return None
        verified = restoration.get("verified") is True or bool(
            restoration.get("probes")
        )
        status = "running" if verified else "degraded"
        with self.session_factory() as db:
            previous = db.get(Deployment, previous_id)
            app = db.get(Application, application_id)
            if (
                previous is None
                or app is None
                or app.active_deployment_id != previous.id
            ):
                return None
            base = dict(previous.manifest or {})
            runtime = restoration.get("service_runtime")
            merged = {
                **base,
                "containers": dict(sorted(containers.items())),
                "service_runtime": (
                    runtime if isinstance(runtime, Mapping)
                    else base.get("service_runtime") or {}
                ),
                "probes": restoration.get("probes") or base.get("probes"),
                "status": status,
                "restoration": dict(restoration),
            }
            deployment = Deployment(
                application_id=application_id,
                operation_id=operation_id,
                repository=repository,
                branch=branch,
                commit=previous.commit,
                tree_hash=previous.tree_hash,
                compose_file=previous.compose_file,
                ingress_service=previous.ingress_service,
                ingress_port=previous.ingress_port,
                status=status,
                release=previous.release,
                manifest=merged,
                finished_at=datetime.now(UTC),
            )
            db.add(deployment)
            db.flush()
            app.active_deployment_id = deployment.id
            app.status = status
            db.commit()
            deployment_id = deployment.id
        self.refresh_routes(application_id)
        return deployment_id

    def harden_checkout(self, checkout, source, policy, operation_id, application_id,
                        tenant_id, *, normalization=None):
        candidate = self.hardening_engine.prepare(checkout, source[2], policy)
        if normalization is not None:
            candidate = replace(candidate, normalization=normalization)
        release = create_release(
            checkout,
            candidate,
            tenant_id=tenant_id,
            application_id=application_id,
            operation_id=operation_id,
            repo=source[0],
            branch=source[1],
            policy=policy,
            environ=os.environ,
            normalization=candidate.normalization,
        )
        return release, candidate

    def deploy_known_release(self, operation_id: str, application_id: str,
                             release_id: str, operation_report: dict) -> dict:
        with self.session_factory() as db:
            app = db.get(Application, application_id)
            if app is None:
                raise RuntimeError("Application not found")
            source = (
                app.repository, app.branch, app.compose_file, app.runtime_project,
                app.ingress_service, app.ingress_port, app.domain,
            )
            tenant_id = app.tenant_id
            tenant_names = tuple(sorted({
                str(name)
                for name in (operation_report.get("tenant_environment_names") or [])
                if str(name) not in MANAGED_DATABASE_NAMES
            }))
        release = find_release(
            release_store_root(os.environ), tenant_id, application_id, release_id
        )
        return self.trusted_deploy(
            operation_id, application_id, release, source, tenant_names,
            repository=source[0], branch=source[1],
            scope=operation_report.get("scope"),
        )

    def trusted_deploy(self, operation_id, application_id, release, source,
                       tenant_names, *, repository, branch,
                       scope: object = None) -> dict:
        with self.session_factory() as db:
            current_app = db.get(Application, application_id)
            previous = (
                db.get(Deployment, current_app.active_deployment_id)
                if current_app is not None and current_app.active_deployment_id else None
            )
            previous_release = (
                Path(previous.release) if previous and previous.release else None
            )
            previous_manifest = (
                dict(previous.manifest)
                if previous is not None and isinstance(previous.manifest, dict)
                else None
            )
            previous_id = previous.id if previous is not None else None
        requested = DeployScope.from_value(scope)
        services = _declared_services(release, previous_manifest)
        plan = plan_deployment(
            release, previous_manifest, requested, services=services or None
        )
        env_file = pending_env_path(operation_id)
        runner = self.runner_factory(self.transport())
        lock = application_lock(application_id)
        if not lock.acquire(blocking=False):
            raise RuntimeError("Another build or deployment is active")
        try:
            try:
                manifest = deploy_scoped(
                    runner,
                    release,
                    plan=plan,
                    scope=requested,
                    project=source[3],
                    previous_manifest=previous_manifest,
                    previous_release=previous_release,
                    env_file=env_file if env_file.exists() else None,
                    staging_id=operation_id,
                    tenant_environment_names=tenant_names,
                    publish_state=True,
                    require_expiry=True,
                    probe_target=_probe_target(source[4], source[5]),
                )
            except ScopedDeployFailed as exc:
                self._publish_restored_state(
                    application_id=application_id,
                    operation_id=operation_id,
                    previous_id=previous_id,
                    manifest=exc.manifest,
                    repository=repository,
                    branch=branch,
                )
                raise
            except ScopedRestoreError as exc:
                published = self._publish_restored_state(
                    application_id=application_id,
                    operation_id=operation_id,
                    previous_id=previous_id,
                    manifest=exc.manifest,
                    repository=repository,
                    branch=branch,
                )
                if published is None:
                    with self.session_factory() as db:
                        failed_app = db.get(Application, application_id)
                        if failed_app is not None:
                            failed_app.status = "degraded"
                            db.commit()
                raise
            if manifest is None:
                raise RuntimeError("Deployment produced no manifest")
            with self.session_factory() as db:
                deployment = Deployment(
                    application_id=application_id,
                    operation_id=operation_id,
                    repository=repository,
                    branch=branch,
                    commit=manifest.get("commit"),
                    tree_hash=manifest.get("tree_hash"),
                    compose_file=manifest.get("compose"),
                    ingress_service=source[4],
                    ingress_port=source[5],
                    status="running",
                    release=manifest.get("release"),
                    manifest=manifest,
                    finished_at=datetime.now(UTC),
                )
                db.add(deployment)
                db.flush()
                app = db.get(Application, application_id)
                if app is not None:
                    app.active_deployment_id = deployment.id
                    app.status = "running"
                db.commit()
                deployment_id = deployment.id
            self.refresh_routes(application_id)
        finally:
            lock.release()
        result = {
            "deployment_id": deployment_id,
            "status": "running",
            "scope": plan.to_dict(),
        }
        result.update(release_result(release))
        return result

    def rollback_operation(self, operation_id: str, application_id: str) -> dict:
        with self.session_factory() as db:
            app = db.get(Application, application_id)
            operation = db.get(Operation, operation_id)
            if app is None or operation is None:
                raise RuntimeError("Application not found")
            report = dict(operation.report or {})
            target_id = report.get("to_deployment_id")
            target = db.get(Deployment, target_id) if isinstance(target_id, str) else None
            if (
                target is None or target.application_id != app.id
                or not isinstance(target.manifest, dict)
                or not isinstance(target.manifest.get("hardened_release"), dict)
            ):
                raise AppDeployError("Rollback target is not a signed release")
            current = (
                db.get(Deployment, app.active_deployment_id)
                if app.active_deployment_id else None
            )
            project = app.runtime_project
            current_release = (
                Path(current.release) if current is not None and current.release else None
            )
            current_manifest = (
                dict(current.manifest)
                if current is not None and isinstance(current.manifest, dict)
                else None
            )
            current_id = current.id if current is not None else None
            target_release_path = Path(target.release) if target.release else None
            target_manifest = dict(target.manifest or {})
            release = TrustedRelease.from_dict(target.manifest["hardened_release"])
            ingress_service, ingress_port = app.ingress_service, app.ingress_port
        verify_release(
            release_store_root(os.environ), release, environ=os.environ,
            require_expiry=False,
        )
        requested = DeployScope.from_value(report.get("scope"))
        services = _declared_services(release, target_manifest)
        plan = plan_deployment(
            release, current_manifest, requested, services=services or None
        )
        runner = self.runner_factory(self.transport())
        lock = application_lock(application_id)
        if not lock.acquire(blocking=False):
            raise RuntimeError("Another build or deployment is active")
        staging_release = target_release_path
        if (
            staging_release is not None
            and runner.transport == "local"
            and not staging_release.exists()
        ):
            staging_release = None
        try:
            try:
                manifest = deploy_scoped(
                    runner,
                    release,
                    plan=plan,
                    scope=requested,
                    project=project,
                    previous_manifest=current_manifest,
                    previous_release=current_release,
                    env_file=None,
                    staging_id=operation_id,
                    publish_state=True,
                    require_expiry=False,
                    staging_release=staging_release,
                    probe_target=_probe_target(ingress_service, ingress_port),
                )
            except ScopedDeployFailed as exc:
                self._publish_restored_state(
                    application_id=application_id,
                    operation_id=operation_id,
                    previous_id=current_id,
                    manifest=exc.manifest,
                    repository=release.repo,
                    branch=release.branch,
                )
                raise
            except ScopedRestoreError as exc:
                published = self._publish_restored_state(
                    application_id=application_id,
                    operation_id=operation_id,
                    previous_id=current_id,
                    manifest=exc.manifest,
                    repository=release.repo,
                    branch=release.branch,
                )
                if published is None:
                    with self.session_factory() as db:
                        failed_app = db.get(Application, application_id)
                        if failed_app is not None:
                            failed_app.status = "degraded"
                            db.commit()
                raise
            with self.session_factory() as db:
                deployment = Deployment(
                    application_id=application_id,
                    operation_id=operation_id,
                    repository=release.repo,
                    branch=release.branch,
                    commit=manifest.get("commit"),
                    tree_hash=manifest.get("tree_hash"),
                    compose_file=manifest.get("compose"),
                    ingress_service=ingress_service,
                    ingress_port=ingress_port,
                    status="running",
                    release=manifest.get("release"),
                    manifest=manifest,
                    finished_at=datetime.now(UTC),
                )
                db.add(deployment)
                db.flush()
                current_app = db.get(Application, application_id)
                if current_app is not None:
                    current_app.active_deployment_id = deployment.id
                    current_app.status = "running"
                db.commit()
                deployment_id = deployment.id
            self.refresh_routes(application_id)
        finally:
            lock.release()
        result = {
            "deployment_id": deployment_id,
            "status": "running",
            "rollback": True,
            "scope": plan.to_dict(),
        }
        result.update(release_result(release))
        return result

    def refresh_routes(self, application_id: str) -> None:
        if self.route_refresh is None:
            return
        with self.session_factory() as db:
            current_app = db.get(Application, application_id)
            if current_app is None:
                return
            try:
                self.route_refresh(db, current_app.tenant_id, application_id)
            except Exception:  # noqa: BLE001 - rutas no bloquean deploy
                logger.warning(
                    "apps_route_refresh_failed",
                    extra={"application_id": application_id},
                )
