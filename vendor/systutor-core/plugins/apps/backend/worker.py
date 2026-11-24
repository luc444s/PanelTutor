"""Serialized Apps worker; HTTP code never calls these external-I/O handlers."""

from __future__ import annotations

import importlib
import logging
import os
import shutil
import tempfile
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .catalog import audit as record_catalog_audit
from .catalog import mark_installation_suspended, require_source
from .crypto import EncryptedValue, TokenCipher
from .github import GithubClient, UrllibGithubClient, app_jwt_for, repository_row
from .hardening import (
    HardeningPolicy,
    HardeningRejected,
    automatic_hardening_policy,
    resolve_hardening_policy,
)
from .managed_environment import MANAGED_DATABASE_NAMES, clear_managed_environment
from .models import (
    Application,
    Deployment,
    GithubInstallation,
    GithubProvider,
    GithubRepository,
    Operation,
)
from .operations import claim_operation
from .releases import ReleaseRejected, release_result
from .releases.execution import ReleaseExecution, pending_env_path
from .releases.store import release_store_root
from .runtime import (
    AppDeployError,
    LifecycleOptions,
    Runner,
    audit_project,
    clone_repo,
    compose_candidates,
    dockerfile_runtime_user,
    lifecycle,
    materialize_source_adapter,
    purge_orphaned_project,
    runtime_snapshot,
)
from .runtime.tenant_runtime import TenantRuntimeRegistry, tenant_slug
from .service import audit as record_apps_audit

logger = logging.getLogger(__name__)


class AppsWorker:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        cipher: TokenCipher,
        *,
        runner_factory: Callable[..., Runner] = Runner,
        publisher: Any = None,
        github: GithubClient | None = None,
        route_cleanup: Callable[[Session, str, str], None] | None = None,
        route_refresh: Callable[[Session, str, str], None] | None = None,
        runtime_registry: TenantRuntimeRegistry | None = None,
        runtime_recorder: Callable[[Session, str, list[str], str], dict[str, str]]
        | None = None,
        rootless_routes: Any | None = None,
        apps_ingress: Callable[[Session, str, str], list[str]] | None = None,
        app: Any | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.cipher = cipher
        self.runner_factory = runner_factory
        self.runtime_registry = runtime_registry
        self.runtime_recorder = runtime_recorder
        self.publisher = publisher
        self.rootless_routes = rootless_routes
        self.apps_ingress = apps_ingress
        self.app = app
        if self.rootless_routes is None:
            from .rootless_routes import build_rootless_routes

            previous_transport = os.environ.get("SPANEL_DOCKER_TRANSPORT")
            try:
                self.rootless_routes = build_rootless_routes()
            finally:
                if self.runtime_registry is None:
                    if previous_transport is None:
                        os.environ.pop("SPANEL_DOCKER_TRANSPORT", None)
                    else:
                        os.environ["SPANEL_DOCKER_TRANSPORT"] = previous_transport
        self.github = github or UrllibGithubClient()
        self.route_cleanup = route_cleanup
        self.route_refresh = route_refresh
        self.execution = ReleaseExecution(
            session_factory,
            runner_factory,
            route_refresh=route_refresh,
            transport=self._transport,
            runner_for_tenant=self._runner,
        )

    def run(self, operation_id: str) -> None:
        with self.session_factory() as db:
            operation = claim_operation(db, operation_id)
            if operation is None:
                return
            application_id = operation.application_id
            kind = operation.kind
            subject_type = operation.subject_type
            subject_id = operation.subject_id
        stopped = threading.Event()
        heartbeat = threading.Thread(
            target=self._heartbeat, args=(operation_id, stopped), daemon=True
        )
        heartbeat.start()
        try:
            if kind == "github_sync":
                result = self._sync_operation(operation_id, subject_type, subject_id)
            elif kind in {"inspect", "deploy", "harden"}:
                if application_id is None:
                    raise RuntimeError("Application not found")
                if kind == "deploy" and self.runtime_registry is not None:
                    result = self._rootless_deploy(operation_id, application_id)
                else:
                    result = self._source_operation(operation_id, application_id, kind)
            elif kind == "rollback":
                if application_id is None:
                    raise RuntimeError("Application not found")
                # A.SPEC 0114: the relay targets the cell ingress, never a
                # container port.  The App must not publish its own host port.
                result = self.execution.rollback_operation(
                    operation_id,
                    application_id,
                    ingress_publish=None,
                )
            else:
                if application_id is None:
                    raise RuntimeError("Application not found")
                result = self._lifecycle_operation(operation_id, application_id, kind)
            self._finish(operation_id, result)
        except Exception as exc:
            safe_error = (
                str(exc)
                if isinstance(exc, (AppDeployError, HardeningRejected, ReleaseRejected))
                else "internal error"
            )
            logger.exception(
                "apps_operation_failed operation_id=%s application_id=%s "
                "operation_kind=%s error_type=%s error=%s",
                operation_id,
                application_id,
                kind,
                type(exc).__name__,
                safe_error,
                extra={
                    "operation_id": operation_id,
                    "application_id": application_id,
                    "operation_kind": kind,
                    "error_type": type(exc).__name__,
                },
            )
            self._fail(operation_id, exc)
        finally:
            stopped.set()
            heartbeat.join(timeout=1)
            pending_env_path(operation_id).unlink(missing_ok=True)

    def _heartbeat(self, operation_id: str, stopped: threading.Event) -> None:
        while not stopped.wait(30):
            with self.session_factory() as db:
                operation = db.get(Operation, operation_id)
                if operation is None or operation.status != "running":
                    return
                operation.heartbeat_at = datetime.now(UTC)
                db.commit()

    @staticmethod
    def _transport() -> str:
        value = os.environ.get("SPANEL_DOCKER_TRANSPORT", "local").strip()
        return value if value in {"local", "ssh"} else "local"

    def _ingress_publish(self, tenant_id: str) -> tuple[str, int] | None:
        """Resolve the cell loopback where the ingress service must be published.

        The plan-agent owns the cell endpoint; the deploy only mirrors its
        ``loopback_address``/``publish_port`` into a loopback-only Compose
        ``ports`` entry.  Without an agent the helper stays inert and the
        deployment remains exactly as before.
        """
        if self.rootless_routes is None:
            return None
        resolver = getattr(self.rootless_routes, "endpoint", None)
        if not callable(resolver):
            return None
        with self.session_factory() as db:
            slug = tenant_slug(db, tenant_id)
        try:
            endpoint = resolver(slug)
        except Exception:  # noqa: BLE001 - the cutover fails closed on route
            logger.warning(
                "apps_rootless_ingress_endpoint_failed", extra={"slug": slug},
                exc_info=True,
            )
            return None
        host = str(getattr(endpoint, "loopback_address", "")).strip()
        port = int(getattr(endpoint, "publish_port", 0) or 0)
        if not host or not 1 <= port <= 65535:
            return None
        return host, port

    def _runner(self, tenant_id: str) -> Runner:
        """Select the authenticated tenant's rootless socket when configured.

        Without an injected registry the worker is byte-identical to before:
        one global Runner inherited from the worker environment.
        """
        if self.runtime_registry is None:
            return self.runner_factory(self._transport())
        with self.session_factory() as db:
            slug = tenant_slug(db, tenant_id)
        return self.runtime_registry.for_tenant(tenant_id, slug).runner()

    def _rootless_deploy(self, operation_id: str, application_id: str) -> dict:
        """Complete the rootless cutover only after deploy, probe and route."""
        with self.session_factory() as db:
            app = db.get(Application, application_id)
            if app is None:
                raise RuntimeError("Application not found")
            tenant_id = app.tenant_id
            previous_deployment_id = app.active_deployment_id
            previous_status = app.status
        # A.SPEC 0114: the cell ingress owns the publish port; Kubernetes-like
        # per-App host publishing would collide with ``spanel-cell-ingress``.
        result = self._source_operation(
            operation_id, application_id, "deploy", ingress_publish=None
        )
        try:
            resource_ids = self._publish_and_verify_rootless_route(
                tenant_id, application_id, result
            )
            if self.runtime_recorder is not None:
                with self.session_factory() as db:
                    self.runtime_recorder(db, tenant_id, resource_ids, "rootless")
                    db.commit()
        except Exception as exc:
            self._restore_deploy_cutover(
                tenant_id,
                application_id,
                previous_deployment_id,
                previous_status,
            )
            if isinstance(exc, AppDeployError):
                raise
            raise AppDeployError("Rootless deployment cutover failed") from exc
        return result

    def _hosts_ref(self) -> Any:
        return getattr(self.rootless_routes, "app", None) or self.app

    def _publish_and_verify_rootless_route(
        self, tenant_id: str, application_id: str, result: dict
    ) -> list[str]:
        deployment_id = result.get("deployment_id")
        if result.get("status") != "running" or not isinstance(deployment_id, str):
            raise AppDeployError("Rootless deployment was not verified")
        from systutor.contracts.app_hosts import list_app_hosts

        from .cell_ingress import AppsIngress

        with self.session_factory() as db:
            app = db.get(Application, application_id)
            deployment = db.get(Deployment, deployment_id)
            if app is None or deployment is None or app.active_deployment_id != deployment.id:
                raise AppDeployError("Rootless deployment was not published")
            manifest = deployment.manifest if isinstance(deployment.manifest, dict) else {}
            containers = manifest.get("containers")
            if not isinstance(containers, dict) or not containers:
                raise AppDeployError("Rootless deployment has no verified containers")
            app_ref = self._hosts_ref()
            hosts = list_app_hosts(app_ref, db, tenant_id, application_id)
            if not hosts:
                return [
                    f"{application_id}:{service}" for service in sorted(containers)
                ]
            if self.rootless_routes is None:
                raise AppDeployError("Rootless route publisher is unavailable")
            if self.apps_ingress is not None:
                self.apps_ingress(db, tenant_id, application_id)
            else:
                AppsIngress(app_ref, db).reconcile(tenant_id, application_id)
            published = self.rootless_routes.refresh(db, tenant_id, application_id)
            domains = (
                published.get("published", [])
                if isinstance(published, dict) else []
            )
            expected = [host.domain for host in hosts]
            if published.get("complete") is False or sorted(domains) != sorted(expected):
                raise AppDeployError("Rootless route publication failed")
            return [f"{application_id}:{service}" for service in sorted(containers)]

    def _restore_deploy_cutover(
        self,
        tenant_id: str,
        application_id: str,
        previous_deployment_id: str | None,
        previous_status: str,
    ) -> None:
        """Restore metadata and routes; intentionally retain every container/volume."""
        with self.session_factory() as db:
            app = db.get(Application, application_id)
            if app is not None:
                app.active_deployment_id = previous_deployment_id
                app.status = previous_status
                db.commit()
        with self.session_factory() as db:
            if self.rootless_routes is not None:
                self.rootless_routes.cleanup(db, tenant_id, application_id)
            if self.route_refresh is not None and previous_deployment_id is not None:
                self.route_refresh(db, tenant_id, application_id)

    def _source_operation(
        self,
        operation_id: str,
        application_id: str,
        kind: str,
        *,
        ingress_publish: tuple[str, int] | None = None,
    ) -> dict:
        from systutor.core.errors import AppError

        with self.session_factory() as db:
            operation = db.get(Operation, operation_id)
            operation_report = dict(operation.report or {}) if operation else {}
        if kind == "deploy":
            release_id = operation_report.get("hardened_operation_id")
            if isinstance(release_id, str) and release_id:
                return self.execution.deploy_known_release(
                    operation_id, application_id, release_id, operation_report,
                    ingress_publish=ingress_publish,
                )
        with self.session_factory() as db:
            app = db.get(Application, application_id)
            if app is None:
                raise RuntimeError("Application not found")
            tenant_id = app.tenant_id
            try:
                installation, repository, provider = require_source(db, app)
            except AppError:
                self._mark_reconnect(application_id)
                raise RuntimeError("GitHub reconnect required") from None
            try:
                pem = self.cipher.decrypt_scoped(
                    "github-app-private-key", provider.tenant_id, provider.id,
                    EncryptedValue(
                        provider.private_key_ciphertext, provider.private_key_nonce,
                        provider.key_version,
                    ),
                )
                jwt = app_jwt_for(pem, provider.github_app_id)
                token_value = self.github.installation_token(
                    jwt, installation.github_installation_id,
                    repository_id=repository.github_repository_id,
                    permissions={"contents": "read"},
                )
            except Exception:
                self._mark_reconnect(application_id)
                raise RuntimeError("GitHub reconnect required") from None
            provider.last_used_at = datetime.now(UTC)
            db.commit()
            token = token_value.token
            operation = db.get(Operation, operation_id)
            hardening_report = (
                operation.report if operation is not None and kind == "harden" else None
            )
            reported_names = (
                (operation.report or {}).get("tenant_environment_names")
                if operation is not None else []
            )
            if not isinstance(reported_names, list):
                reported_names = []
            tenant_names = tuple(
                sorted({
                    str(name) for name in reported_names
                    if str(name) not in MANAGED_DATABASE_NAMES
                })
            )
            source = (
                repository.full_name, app.branch, app.compose_file, app.runtime_project,
            )
        with tempfile.TemporaryDirectory(prefix="spanel-app-worker-") as temporary:
            checkout = Path(temporary) / "checkout"
            clone_env = dict(os.environ, GH_TOKEN=token, GH_PROMPT_DISABLED="1")
            clone_repo(source[0], source[1], checkout, self.runner_factory("local", clone_env))
            token = ""
            clone_env["GH_TOKEN"] = ""
            del clone_env
            adaptation = materialize_source_adapter(checkout, source[2])
            effective_compose = adaptation.compose_file or source[2]
            source = (
                source[0], source[1], effective_compose, source[3],
            )
            # The checkout is audited exactly as cloned.  No normalizer runs
            # here: container names, binds, ports and users are validated, not
            # rewritten, so the developer's Compose remains byte-identical.
            audit = audit_project(checkout, effective_compose, non_root=True)
            service_details = []
            dockerfile_users: dict[str, str | None] = {}
            for service in sorted(audit.data["services"]):
                config = audit.data["services"].get(service)
                config = config if isinstance(config, dict) else {}
                dockerfile = audit.dockerfiles.get(service)
                image = config.get("image")
                compose_user = config.get("user")
                user_declared = (
                    dockerfile_runtime_user(dockerfile)
                    if dockerfile is not None else None
                )
                dockerfile_users[service] = user_declared
                service_details.append({
                    "name": service,
                    "build": dockerfile is not None,
                    "dockerfile": (
                        dockerfile.relative_to(audit.root).as_posix()
                        if dockerfile is not None else None
                    ),
                    "image": image if isinstance(image, str) else None,
                    "compose_user": (
                        str(compose_user) if compose_user is not None else None
                    ),
                    "dockerfile_user": user_declared,
                })
            report = {
                "compose": audit.compose.relative_to(audit.root).as_posix(),
                "compose_candidates": [
                    path.relative_to(audit.root).as_posix()
                    for path in compose_candidates(audit.root)
                ],
                "services": sorted(audit.data["services"]),
                "service_details": service_details,
                "findings": [finding.__dict__ for finding in audit.findings],
                "warnings": list(audit.warnings),
                "blocking": bool(audit.errors),
                "source_adapter": adaptation.as_dict(),
            }
            if audit.warnings:
                report["output"] = "\n".join(
                    f"WARNING: {warning}" for warning in audit.warnings
                )
                for warning in audit.warnings:
                    logger.warning(
                        "apps_checkout_warning: %s", warning,
                        extra={"application_id": application_id},
                    )
            if kind == "inspect":
                return report
            if kind == "harden":
                try:
                    raw_policy = (
                        hardening_report.get("policy")
                        if isinstance(hardening_report, dict)
                        else None
                    )
                    policy = resolve_hardening_policy(
                        HardeningPolicy.from_dict(raw_policy),
                        audit.data["services"],
                        dockerfile_users,
                    )
                except (TypeError, ValueError):
                    raise HardeningRejected(
                        "Admission policy is missing or invalid"
                    ) from None
                # Kept operation name for API compatibility: this now only
                # validates and signs the original tree; it does not harden it.
                release = self.execution.prepare_release(
                    checkout, source, policy, operation_id, application_id, tenant_id,
                )
                result = release_result(release)
                result.update({
                    "status": "validated",
                    "services": sorted(audit.data["services"]),
                })
                return result
            if kind != "deploy":
                raise AppDeployError("Unsupported source operation")
            raw_policy = operation_report.get("hardening")
            try:
                if raw_policy is not None:
                    policy = resolve_hardening_policy(
                        HardeningPolicy.from_dict(raw_policy),
                        audit.data["services"],
                        dockerfile_users,
                    )
                else:
                    policy = automatic_hardening_policy(
                        audit.data["services"], dockerfile_users
                    )
            except (TypeError, ValueError) as exc:
                raise AppDeployError(f"Admission policy could not be generated: {exc}") from None
            release = self.execution.prepare_release(
                checkout, source, policy, operation_id, application_id, tenant_id,
            )
            return self.execution.trusted_deploy(
                operation_id, application_id, release, source, tenant_names,
                repository=source[0], branch=source[1],
                scope=operation_report.get("scope"),
                ingress_publish=ingress_publish,
            )

    def reconcile_routes(self) -> int:
        """Re-publish routes for every active app; safe to run on every boot."""
        if self.route_refresh is None and self.rootless_routes is None:
            return 0
        with self.session_factory() as db:
            rows = list(db.execute(
                select(Application.id, Application.tenant_id).where(
                    Application.deleted_at.is_(None),
                    Application.active_deployment_id.is_not(None),
                )
            ).all())
        refreshed = 0
        for application_id, tenant_id in rows:
            with self.session_factory() as db:
                try:
                    if self.route_refresh is not None:
                        self.route_refresh(db, tenant_id, application_id)
                    if self.rootless_routes is not None:
                        from .cell_ingress import AppsIngress

                        AppsIngress(
                            self._hosts_ref(), db
                        ).reconcile(tenant_id, application_id)
                        self.rootless_routes.refresh(db, tenant_id, application_id)
                except Exception:  # noqa: BLE001 - una app no bloquea al resto
                    logger.warning(
                        "apps_route_reconcile_failed",
                        extra={"application_id": application_id},
                    )
                else:
                    refreshed += 1
        return refreshed

    def _unpublish_legacy_documents(
        self, tenant_id: str, application_id: str
    ) -> None:
        """Remove the rootful document Domains no longer owns for this App."""
        if self.publisher is None:
            return
        from systutor.contracts.app_hosts import list_app_hosts

        app_ref = self._hosts_ref()
        with self.session_factory() as db:
            hosts = list_app_hosts(app_ref, db, tenant_id, application_id)
        for host in hosts:
            self.publisher.unpublish(host.domain)

    def _mark_reconnect(self, application_id: str) -> None:
        with self.session_factory() as db:
            app = db.get(Application, application_id)
            if app is not None:
                app.source_status = "source_reconnect_required"
                db.commit()

    def _sync_operation(
        self, operation_id: str, subject_type: str | None, subject_id: str | None
    ) -> dict:
        if subject_type != "installation" or not subject_id:
            raise RuntimeError("GitHub sync subject is invalid")
        with self.session_factory() as db:
            operation = db.get(Operation, operation_id)
            installation = db.get(GithubInstallation, subject_id)
            if operation is None or installation is None:
                raise RuntimeError("GitHub sync installation not found")
            if installation.tenant_id != operation.tenant_id:
                raise RuntimeError("GitHub sync installation not found")
            provider = db.get(GithubProvider, installation.provider_id)
            if provider is None or provider.tenant_id != installation.tenant_id:
                raise RuntimeError("GitHub provider not found")
            if installation.status != "active" or provider.status != "active":
                mark_installation_suspended(db, installation, installation.status)
                db.commit()
                raise RuntimeError("GitHub installation is not active")
            try:
                pem = self.cipher.decrypt_scoped(
                    "github-app-private-key", provider.tenant_id, provider.id,
                    EncryptedValue(
                        provider.private_key_ciphertext, provider.private_key_nonce,
                        provider.key_version,
                    ),
                )
                jwt = app_jwt_for(pem, provider.github_app_id)
                token_value = self.github.installation_token(
                    jwt, installation.github_installation_id,
                    permissions={"metadata": "read"},
                )
            except Exception:
                raise RuntimeError("GitHub sync authentication failed") from None
            token = token_value.token
            provider.last_used_at = datetime.now(UTC)
            github_id = installation.github_installation_id
            tenant_id = installation.tenant_id
            installation_id = installation.id
        observed: dict[int, dict] = {}
        page = 1
        try:
            while page <= 100:
                data = self.github.installation_repositories(token, page)
                rows = data.get("repositories")
                if not isinstance(rows, list):
                    raise RuntimeError("GitHub repositories response is invalid")
                if not rows:
                    break
                for row in rows:
                    repository = repository_row(row)
                    observed[repository["github_repository_id"]] = repository
                page += 1
        finally:
            token = ""
        if page > 100:
            raise RuntimeError("GitHub repositories pagination exceeded the limit")
        now = datetime.now(UTC)
        with self.session_factory() as db:
            installation = db.get(GithubInstallation, installation_id)
            if installation is None:
                raise RuntimeError("GitHub installation disappeared")
            provider = db.get(GithubProvider, installation.provider_id)
            existing = {
                row.github_repository_id: row
                for row in db.scalars(select(GithubRepository).where(
                    GithubRepository.installation_id == installation_id
                )).all()
            }
            seen: set[int] = set()
            for github_repository_id, values in observed.items():
                seen.add(github_repository_id)
                row = existing.get(github_repository_id)
                if row is None:
                    row = GithubRepository(
                        installation_id=installation_id, tenant_id=tenant_id,
                        github_repository_id=github_repository_id,
                        full_name=values["full_name"],
                    )
                    db.add(row)
                row.full_name = values["full_name"]
                row.private = values["private"]
                row.default_branch = values["default_branch"]
                row.archived = values["archived"]
                row.disabled = values["disabled"]
                row.observed_at = now
                row.removed_at = None
            for github_repository_id, row in existing.items():
                if github_repository_id not in seen and row.removed_at is None:
                    row.removed_at = now
                    apps = db.scalars(select(Application).where(
                        Application.tenant_id == tenant_id,
                        Application.source_repository_id == row.id,
                        Application.deleted_at.is_(None),
                    )).all()
                    for app in apps:
                        app.source_status = "source_reconnect_required"
            installation.last_synced_at = now
            installation.status = "active"
            if provider is not None:
                provider.last_used_at = now
            record_catalog_audit(
                db, "github.sync.completed", tenant_id=tenant_id,
                actor=None, entity_id=installation_id,
                details={"github_installation_id": github_id, "repositories": len(seen)},
            )
            db.commit()
        return {
            "installation_id": installation_id,
            "github_installation_id": github_id,
            "repositories": len(seen),
        }

    def _lifecycle_operation(self, operation_id: str, application_id: str, kind: str) -> dict:
        with self.session_factory() as db:
            app = db.get(Application, application_id)
            if app is None:
                raise RuntimeError("Application not found")
            project = app.runtime_project
            tenant_id = app.tenant_id
            operation = db.get(Operation, operation_id)
            purge_data = bool((operation.report or {}).get("purge_data")) if operation else False
            service = (operation.report or {}).get("service") if operation else None
            deployment = (
                db.get(Deployment, app.active_deployment_id)
                if app.active_deployment_id else None
            )
            if deployment is None or not deployment.manifest:
                if kind != "delete":
                    raise RuntimeError("Active deployment not found")
                deployment = None
            if service is not None:
                containers = deployment.manifest.get("containers", {}) if deployment else {}
                if not isinstance(service, str) or service not in containers:
                    raise RuntimeError("Service does not belong to the active deployment")
                if kind in {"down", "delete"}:
                    raise RuntimeError("down and delete always affect the whole application")
        if deployment is None:
            # Un borrador (o una inspección/deploy fallido) no tiene runtime
            # publicado: se retiran los recursos etiquetados que sí existan y
            # los metadatos. Los volúmenes solo se eliminan al purgar datos.
            runner = self._runner(tenant_id)
            purge_orphaned_project(runner, project, volumes=purge_data)
            project_root = release_store_root(runner.environ) / project
            if project_root.name == project:
                if runner.transport == "ssh":
                    runner.run(["rm", "-rf", "--", str(project_root)])
                elif project_root.exists():
                    shutil.rmtree(project_root)
            if self.route_cleanup is not None or self.rootless_routes is not None:
                with self.session_factory() as db:
                    if self.route_cleanup is not None:
                        self.route_cleanup(db, tenant_id, application_id)
                    if self.rootless_routes is not None:
                        self.rootless_routes.cleanup(db, tenant_id, application_id)
            self._unpublish_legacy_documents(tenant_id, application_id)
            with self.session_factory() as db:
                current = db.get(Application, application_id)
                if current is not None:
                    current.deleted_at = datetime.now(UTC)
                    current.status = "deleted"
                    if purge_data:
                        clear_managed_environment(current)
                    db.commit()
            return {
                "application_id": application_id,
                "operation_id": operation_id,
                "action": kind,
                "output": "No active deployment; application metadata removed.",
            }
        command = "status" if kind == "refresh" else kind
        runner = self._runner(tenant_id)
        result = lifecycle(
            LifecycleOptions(
                command=command, project=project,
                release=Path(deployment.release) if deployment.release else None,
                purge_data=purge_data if kind == "delete" else False,
                confirm_purge=project if kind == "delete" and purge_data else None,
                service=service,
            ),
            runner,
        )
        if kind == "refresh":
            containers = deployment.manifest.get("containers", {})
            snapshot = runtime_snapshot(runner, containers)
            if snapshot:
                with self.session_factory() as db:
                    current = db.get(Deployment, deployment.id)
                    if current is not None:
                        current.manifest = {
                            **(current.manifest or {}),
                            "service_runtime": snapshot,
                        }
                        db.commit()
        if kind == "delete" and (
            self.route_cleanup is not None or self.rootless_routes is not None
        ):
            with self.session_factory() as db:
                if self.route_cleanup is not None:
                    self.route_cleanup(db, tenant_id, application_id)
                if self.rootless_routes is not None:
                    self.rootless_routes.cleanup(db, tenant_id, application_id)
        if kind == "delete":
            self._unpublish_legacy_documents(tenant_id, application_id)
        if kind == "delete":
            release = Path(str(deployment.manifest.get("release", "")))
            project_root = (
                release.parent.parent if release.parent.name == "releases" else release
            )
            if project_root.name == project:
                runner = self._runner(tenant_id)
                if runner.transport == "ssh":
                    runner.run(["rm", "-rf", "--", str(project_root)])
                elif project_root.exists():
                    shutil.rmtree(project_root)
            with self.session_factory() as db:
                app = db.get(Application, application_id)
                if app is not None:
                    app.deleted_at = datetime.now(UTC)
                    app.status = "deleted"
                    if purge_data:
                        clear_managed_environment(app)
                    db.commit()
        return {
            "application_id": application_id, "operation_id": operation_id,
            "action": kind, "output": result.output[-65536:],
        }

    def _finish(self, operation_id: str, result: dict) -> None:
        with self.session_factory() as db:
            operation = db.get(Operation, operation_id)
            if operation is None:
                return
            operation.status = "succeeded"
            operation.phase = "complete"
            operation.result = result
            operation.finished_at = datetime.now(UTC)
            if operation.application_id is not None:
                app = db.get(Application, operation.application_id)
                if app is not None:
                    if operation.kind == "inspect":
                        app.status = "blocked" if result.get("blocking") else "inspected"
                        if not app.compose_file and result.get("compose"):
                            app.compose_file = str(result["compose"])
                    if app.active_operation_id == operation.id:
                        app.active_operation_id = None
            record_apps_audit(
                db, f"operation.{operation.kind}.complete", tenant_id=operation.tenant_id,
                actor=operation.actor_user_id, entity_id=operation.application_id,
                details={"operation_id": operation.id},
            )
            db.commit()

    def _fail(self, operation_id: str, exc: Exception) -> None:
        with self.session_factory() as db:
            operation = db.get(Operation, operation_id)
            if operation is None:
                return
            operation.status = "failed"
            operation.phase = "failed"
            operation.error_code = (
                getattr(exc, "code", None)
                if isinstance(
                    exc, (AppDeployError, HardeningRejected, ReleaseRejected)
                )
                else None
            ) or "apps_operation_failed"
            operation.public_error = (
                str(exc)
                if isinstance(exc, (AppDeployError, HardeningRejected, ReleaseRejected))
                else "Application operation failed"
            )
            operation.finished_at = datetime.now(UTC)
            if operation.application_id is not None:
                app = db.get(Application, operation.application_id)
                if app is not None and app.active_operation_id == operation.id:
                    app.active_operation_id = None
            record_apps_audit(
                db, f"operation.{operation.kind}.failed", tenant_id=operation.tenant_id,
                actor=operation.actor_user_id, entity_id=operation.application_id,
                result="failure",
                details={"operation_id": operation.id, "code": operation.error_code},
            )
            db.commit()


def build_actor(handler: Callable[[str], None]):
    dramatiq = importlib.import_module("dramatiq")
    return dramatiq.actor(
        actor_name="apps_operation", queue_name="apps", max_retries=0
    )(handler)
