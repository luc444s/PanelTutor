"""Incremental and per-service execution for verified signed releases.

The planner decides the effective services; this module only executes that
decision and proves the services outside the plan were not touched.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..hardening import HardeningPolicy
from ..runtime.deployment import (
    _compose_command,
    _container_names,
    _containers,
    _ensure_owned,
    _env_path,
    _image_users,
    _manifest_data,
    _override,
    _publish_release_state,
    _stage_release,
    _state_root,
    _validate_compose_environment,
    _verify_containers,
    _write_manifest,
    runtime_snapshot,
    validate_env_file,
)
from ..runtime.lifecycle import _read_manifest
from ..runtime.probes import run_probes
from ..runtime.transport import Runner
from ..runtime.types import AppDeployError, DeployOptions
from .planner import DeployPlan, DeployScope, active_state
from .store import release_store_root
from .trusted import TrustedRelease
from .verify import verify_release


class ScopedRestoreError(AppDeployError):
    """The touched subset could not be restored to its previous release."""

    restore_failed = True


class ScopedDeployFailed(AppDeployError):
    """A partial deployment failed, but the touched subset was restored.

    The manifest carries the verified restoration evidence so the caller can
    publish the restored container identities as the new active state.
    """

    restore_failed = False

    def __init__(self, message: str, manifest: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.manifest = dict(manifest)


def _release_dir(state_root: Path, project: str, release_id: str) -> Path:
    return state_root / project / "releases" / release_id


def previous_service_paths(
    previous_manifest: Mapping[str, Any] | None,
    previous_release: Path | None,
    state_root: Path,
    project: str,
    services: Sequence[str],
) -> dict[str, Path | None]:
    previous = previous_manifest if isinstance(previous_manifest, Mapping) else {}
    recorded = previous.get("service_release_paths")
    recorded = recorded if isinstance(recorded, Mapping) else {}
    releases = previous.get("service_releases")
    releases = releases if isinstance(releases, Mapping) else {}
    default = previous_release
    result: dict[str, Path | None] = {}
    for service in services:
        value = recorded.get(service)
        if isinstance(value, str) and value:
            result[service] = Path(value)
            continue
        release_id = releases.get(service)
        if isinstance(release_id, str) and release_id:
            result[service] = _release_dir(state_root, project, release_id)
            continue
        result[service] = default
    return result


def _identity(runner: Runner, container: str) -> dict[str, Any]:
    result = runner.run(
        [
            "docker",
            "container",
            "inspect",
            "-f",
            "{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.RestartCount}}",
            container,
        ],
        check=False,
    )
    if result.returncode:
        raise AppDeployError("cannot inspect a container outside the plan")
    parts = result.stdout.strip().split("|")
    if len(parts) != 4 or not parts[0]:
        raise AppDeployError("container identity evidence is invalid")
    try:
        restarts = int(parts[3])
    except ValueError:
        raise AppDeployError("container identity evidence is invalid") from None
    return {
        "container_id": parts[0],
        "image_id": parts[1],
        "started_at": parts[2],
        "restart_count": restarts,
    }


def _diagnostic(runner: Runner, staged: Path, compose_rel: str, project: str) -> dict:
    logs = runner.run(
        _compose_command(
            staged, compose_rel, project, True,
            "logs", "--no-color", "--tail", "200",
        ),
        check=False,
    )
    payload = (logs.stdout + logs.stderr).encode()
    return {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}


def _restore(
    runner: Runner,
    *,
    project: str,
    services: Sequence[str],
    paths: Mapping[str, Path | None],
) -> tuple[list[str], list[str]]:
    restored: list[str] = []
    failed: list[str] = []
    root = _state_root(runner.transport, runner.environ)
    for service in services:
        path = paths.get(service)
        if path is None:
            failed.append(service)
            continue
        try:
            manifest = _read_manifest(runner, root, project, Path(path))
            started = runner.run(
                _compose_command(
                    Path(path), manifest["compose"], project, True,
                    "up", "-d", "--no-deps", service,
                ),
                check=False,
            )
            if started.returncode:
                raise AppDeployError("previous service release did not start")
        except Exception:
            failed.append(service)
        else:
            restored.append(service)
    return restored, failed


def _merged_paths(
    previous: Mapping[str, Path | None],
    services: Sequence[str],
    staged: Path,
    effective: Sequence[str],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for service in services:
        if service in effective:
            result[service] = str(staged)
            continue
        value = previous.get(service)
        if value is not None:
            result[service] = str(value)
    return dict(sorted(result.items()))


def deploy_scoped(
    runner: Runner,
    release: TrustedRelease,
    *,
    plan: DeployPlan,
    scope: DeployScope,
    project: str,
    previous_manifest: Mapping[str, Any] | None,
    previous_release: Path | None,
    env_file: Path | None,
    staging_id: str,
    tenant_environment_names: Sequence[str] = (),
    timeout: int = 1800,
    wait: int = 180,
    publish_state: bool = True,
    require_expiry: bool = True,
    staging_release: Path | None = None,
) -> dict[str, Any]:
    """Execute exactly the planned subset and publish state only when green."""

    try:
        policy = HardeningPolicy.from_dict(release.body["policy"])
    except (TypeError, ValueError, KeyError):
        raise AppDeployError("release policy is invalid") from None
    verified = verify_release(
        release_store_root(runner.environ),
        release,
        environ=runner.environ,
        policy=policy,
        require_expiry=require_expiry,
    )
    result = verified.audit
    if result.errors:
        raise AppDeployError("release audit found blocking errors")
    if env_file is not None:
        env_file = validate_env_file(env_file, result.root)
    state_root = _state_root(runner.transport, runner.environ)
    staged = (
        Path(staging_release) if staging_release is not None
        else _release_dir(state_root, project, staging_id)
    )
    reusing = staging_release is not None
    if not reusing:
        if runner.transport == "local" and staged.exists():
            raise AppDeployError(
                "project release already exists; use lifecycle commands or a new project"
            )
        if runner.transport == "ssh":
            available = runner.run(["test", "!", "-e", str(staged)], check=False)
            if available.returncode == 1:
                raise AppDeployError(
                    "remote project release already exists; use lifecycle commands"
                )
            if available.returncode:
                raise AppDeployError(
                    "cannot verify remote project release availability"
                )
        _ensure_owned(runner, project)
        override = _override(result.data, project, True, _env_path(staged))
        _stage_release(runner, result.root, staged, release.compose_path, override, env_file)
    compose_rel = release.compose_path
    all_services = sorted(result.data["services"])
    effective = [item for item in plan.effective_services if item in all_services]
    if len(effective) != len(plan.effective_services):
        raise AppDeployError("plan references services outside the verified release")
    initial = not isinstance(previous_manifest, Mapping) or not previous_manifest
    previous = previous_manifest if isinstance(previous_manifest, Mapping) else {}
    previous_containers = previous.get("containers")
    previous_containers = (
        previous_containers if isinstance(previous_containers, Mapping) else {}
    )
    previous_images = previous.get("images")
    previous_images = previous_images if isinstance(previous_images, Mapping) else {}
    previous_image_ids = previous.get("image_ids")
    previous_image_ids = (
        previous_image_ids if isinstance(previous_image_ids, Mapping) else {}
    )
    previous_paths = previous_service_paths(
        previous, previous_release, state_root, project, all_services
    )
    state = active_state(previous, release, plan, all_services)
    options = DeployOptions(
        repo=release.repo,
        branch=release.branch,
        project=project,
        non_root=True,
        env_file=env_file,
        timeout=timeout,
        wait=wait,
        release_id=staging_id,
        publish_state=publish_state,
        tenant_environment_names=tuple(tenant_environment_names),
    )
    images = dict(previous_images)
    image_ids = dict(previous_image_ids)
    manifest: dict[str, Any] | None = None
    modified: list[str] = []
    up_started = False
    try:
        if effective:
            _validate_compose_environment(runner, staged, compose_rel, project)
            pulled = runner.run(
                _compose_command(
                    staged, compose_rel, project, True,
                    "pull", "--ignore-buildable", *effective,
                ),
                timeout=timeout,
                check=False,
            )
            if pulled.returncode:
                raise AppDeployError(
                    f"Compose image pull failed (exit {pulled.returncode})"
                )
            built = runner.run(
                _compose_command(staged, compose_rel, project, True, "build", *effective),
                timeout=timeout,
                check=False,
            )
            if built.returncode:
                raise AppDeployError(
                    f"Compose image build failed (exit {built.returncode})"
                )
            resolved = _image_users(
                runner, staged, compose_rel, project, True, effective
            )
            for service, image in resolved.items():
                inspected = runner.run(
                    ["docker", "image", "inspect", "-f", "{{.Id}}", image],
                    check=False,
                )
                image_id = inspected.stdout.strip()
                if inspected.returncode or not image_id:
                    raise AppDeployError(
                        f"cannot resolve the image id for service {service}"
                    )
                images[service] = image
                image_ids[service] = image_id
        host = "local" if runner.transport == "local" else runner.host
        manifest = _manifest_data(
            options, result, project, images, "building", host, staged
        )
        manifest.update({
            **state,
            "commit": release.commit,
            "tree_hash": release.hardened_tree_sha256,
            "source_tree_sha256": release.source_tree_sha256,
            "compose": compose_rel,
            "services": all_services,
            "images": dict(sorted(images.items())),
            "image_ids": dict(sorted(image_ids.items())),
            "hardened_release": release.to_dict(),
            "non_root": True,
            "scope": plan.to_dict(),
            "requested_scope": plan.requested_scope,
            "requested_service": plan.requested_service,
            "effective_services": list(plan.effective_services),
            "strategy": plan.strategy,
            "fallback_reason": plan.fallback_reason,
            "service_release_paths": _merged_paths(
                previous_paths, all_services, staged, effective
            ),
        })
        _write_manifest(runner, staged, manifest)
        untouched = [item for item in all_services if item not in effective]
        before: dict[str, dict[str, Any]] = {}
        for service in untouched:
            container = previous_containers.get(service)
            if not isinstance(container, str) or not container:
                raise AppDeployError(
                    "active state is incomplete; a global deployment is required"
                )
            before[service] = _identity(runner, container)
        if effective:
            if initial:
                started = runner.run(
                    _compose_command(staged, compose_rel, project, True, "up", "-d"),
                    timeout=timeout,
                    check=False,
                )
                up_started = True
                if started.returncode:
                    raise AppDeployError(
                        f"Compose services failed to start (exit {started.returncode})"
                    )
            else:
                for service in effective:
                    modified.append(service)
                    started = runner.run(
                        _compose_command(
                            staged, compose_rel, project, True,
                            "up", "-d", "--no-deps", service,
                        ),
                        timeout=timeout,
                        check=False,
                    )
                    up_started = True
                    if started.returncode:
                        raise AppDeployError(
                            f"service {service} failed to start "
                            f"(exit {started.returncode})"
                        )
        containers = _containers(
            runner, staged, compose_rel, project, True, all_services
        )
        if effective:
            _verify_containers(
                runner,
                {service: containers[service] for service in effective},
                project,
                True,
                wait,
            )
        after: dict[str, dict[str, Any]] = {}
        for service in untouched:
            current = containers.get(service)
            if not isinstance(current, str) or not current:
                raise AppDeployError(
                    f"service {service} outside the plan has no container"
                )
            after[service] = _identity(runner, current)
            if after[service] != before[service]:
                raise AppDeployError(
                    f"service {service} outside the plan changed during deployment"
                )
        merged_containers = {
            service: (
                containers[service] if service in effective
                else str(previous_containers[service])
            )
            for service in all_services
        }
        scoped_probes: dict[str, Any] | None = None
        if effective and set(effective) != set(all_services):
            scoped_probes = run_probes(
                runner,
                release=staged,
                compose_rel=compose_rel,
                project=project,
                services=effective,
                containers={item: merged_containers[item] for item in effective},
                environ=runner.environ,
            )
        probes = run_probes(
            runner,
            release=staged,
            compose_rel=compose_rel,
            project=project,
            services=all_services,
            containers=merged_containers,
            environ=runner.environ,
        )
        manifest.update({
            "status": "running",
            "containers": dict(sorted(merged_containers.items())),
            "container_names": _container_names(runner, merged_containers),
            "service_runtime": runtime_snapshot(runner, merged_containers),
            "probes": probes,
            "service_probes": scoped_probes,
            "preserved": {
                "services": untouched,
                "before": before,
                "after": after,
            },
        })
        _write_manifest(runner, staged, manifest)
        if publish_state:
            _publish_release_state(runner, staged, manifest)
        return manifest
    except Exception as exc:
        if manifest is None:
            raise
        manifest["status"] = "failed"
        if up_started:
            manifest["diagnostics"] = _diagnostic(
                runner, staged, compose_rel, project
            )
        if modified and not initial:
            restored, failed = _restore(
                runner,
                project=project,
                services=modified,
                paths=previous_paths,
            )
            manifest["restoration"] = {
                "restored": restored,
                "failed": failed,
            }
            if not failed:
                base = previous_release or next(
                    (value for value in previous_paths.values()
                     if value is not None),
                    None,
                )
                if base is None:
                    failed.append("probes")
                else:
                    try:
                        previous_compose = previous.get("compose")
                        if not isinstance(previous_compose, str) or not previous_compose:
                            previous_compose = release.compose_path
                        restored_containers = _containers(
                            runner, Path(base), previous_compose, project, True,
                            all_services,
                        )
                        restored_probes = run_probes(
                            runner,
                            release=Path(base),
                            compose_rel=previous_compose,
                            project=project,
                            services=all_services,
                            containers=restored_containers,
                            environ=runner.environ,
                        )
                    except Exception:
                        failed.append("probes")
                    else:
                        manifest["restoration"]["probes"] = restored_probes
                        manifest["restoration"]["container_ids"] = restored_containers
                        manifest["restoration"]["service_runtime"] = runtime_snapshot(
                            runner, restored_containers
                        )
            _write_manifest(runner, staged, manifest)
            if failed:
                raise ScopedRestoreError(
                    "restoration failed; the application is degraded"
                ) from exc
            raise ScopedDeployFailed(
                str(exc) or "scoped deployment failed", manifest
            ) from exc
        elif initial and up_started:
            runner.run(
                _compose_command(
                    staged, compose_rel, project, True,
                    "down", "--remove-orphans",
                ),
                check=False,
            )
        _write_manifest(runner, staged, manifest)
        if isinstance(exc, AppDeployError):
            raise
        raise AppDeployError("scoped deployment failed") from None
