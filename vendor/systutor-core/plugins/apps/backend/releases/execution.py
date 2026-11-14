"""Trusted release orchestration shared by the Apps worker.

The worker owns operation lifecycle and source preparation; this module owns the
parts that consume a signed release: hardening, deploy and rollback.  Every
entry point re-verifies the descriptor before touching the runtime.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ..managed_environment import MANAGED_DATABASE_NAMES
from ..models import Application, Deployment, Operation
from ..runtime import (
    AppDeployError,
    DeployOptions,
    LifecycleOptions,
    Runner,
    lifecycle,
)
from ..runtime.deployment import _publish_release_state
from ..runtime.release_deploy import deploy_trusted
from .pipeline import create_release, release_result
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

    def harden_checkout(self, checkout, source, policy, operation_id, application_id,
                        tenant_id):
        candidate = self.hardening_engine.prepare(checkout, source[2], policy)
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
        )

    def trusted_deploy(self, operation_id, application_id, release, source,
                       tenant_names, *, repository, branch) -> dict:
        with self.session_factory() as db:
            current_app = db.get(Application, application_id)
            previous = (
                db.get(Deployment, current_app.active_deployment_id)
                if current_app is not None and current_app.active_deployment_id else None
            )
            previous_release = (
                Path(previous.release) if previous and previous.release else None
            )
        env_file = pending_env_path(operation_id)
        runner = self.runner_factory(self.transport())
        lock = application_lock(application_id)
        if not lock.acquire(blocking=False):
            raise RuntimeError("Another build or deployment is active")
        try:
            try:
                manifest = deploy_trusted(
                    release,
                    DeployOptions(
                        repo=repository, branch=branch, project=source[3],
                        non_root=True,
                        env_file=env_file if env_file.exists() else None,
                        release_id=operation_id,
                        publish_state=False,
                        tenant_environment_names=tenant_names,
                    ),
                    runner,
                )
            except Exception:
                if previous_release is not None:
                    try:
                        lifecycle(
                            LifecycleOptions(
                                command="start", project=source[3],
                                release=previous_release,
                            ),
                            runner,
                        )
                    except Exception:
                        with self.session_factory() as db:
                            failed_app = db.get(Application, application_id)
                            if failed_app is not None:
                                failed_app.status = "degraded"
                                db.commit()
                raise
            if manifest is None:
                raise RuntimeError("Deployment produced no manifest")
            _publish_release_state(runner, Path(str(manifest["release"])), manifest)
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
        }
        result.update(release_result(release))
        return result

    def rollback_operation(self, operation_id: str, application_id: str) -> dict:
        with self.session_factory() as db:
            app = db.get(Application, application_id)
            operation = db.get(Operation, operation_id)
            if app is None or operation is None:
                raise RuntimeError("Application not found")
            target_id = (operation.report or {}).get("to_deployment_id")
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
            target_release = Path(target.release) if target.release else None
            target_manifest = dict(target.manifest or {})
            target_row_id = target.id
            release = TrustedRelease.from_dict(target.manifest["hardened_release"])
        if target_release is None:
            raise AppDeployError("Rollback target is not a signed release")
        verify_release(
            release_store_root(os.environ), release, environ=os.environ,
            require_expiry=False,
        )
        runner = self.runner_factory(self.transport())
        lock = application_lock(application_id)
        if not lock.acquire(blocking=False):
            raise RuntimeError("Another build or deployment is active")
        try:
            try:
                if current_release is not None:
                    lifecycle(
                        LifecycleOptions(
                            command="down", project=project, release=current_release,
                        ),
                        runner,
                    )
                lifecycle(
                    LifecycleOptions(
                        command="start", project=project,
                        release=target_release,
                    ),
                    runner,
                )
            except Exception:
                with self.session_factory() as db:
                    failed_app = db.get(Application, application_id)
                    if failed_app is not None:
                        failed_app.status = "degraded"
                        db.commit()
                raise AppDeployError(
                    "Rollback could not restore the signed release"
                ) from None
            target_manifest["status"] = "running"
            _publish_release_state(runner, target_release, target_manifest)
            with self.session_factory() as db:
                target = db.get(Deployment, target_row_id)
                app = db.get(Application, application_id)
                if target is not None:
                    target.status = "running"
                    target.manifest = target_manifest
                if app is not None:
                    app.active_deployment_id = target_row_id
                    app.status = "running"
                db.commit()
            self.refresh_routes(application_id)
        finally:
            lock.release()
        result = {
            "deployment_id": target_row_id,
            "status": "running",
            "rollback": True,
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
