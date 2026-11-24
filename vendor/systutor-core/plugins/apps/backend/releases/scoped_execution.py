"""Incremental and per-service execution for verified signed releases.

The planner decides the effective services; this module only executes that
decision and proves the services outside the plan were not touched.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from ..hardening import HardeningPolicy
from ..runtime.deployment import (
    _compose_command,
    _container_names,
    _containers,
    _ensure_owned,
    _env_path,
    _image_users,
    _inject_readonly_files,
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
from ..runtime.types import AppDeployError, DeployOptions, one_shot_services
from ..runtime.volumes import prepare_runtime_volumes
from .planner import DeployPlan, DeployScope, active_state
from .store import release_store_root
from .trusted import TrustedRelease
from .verify import verify_release


class ScopedRestoreError(AppDeployError):
    """The touched subset could not be restored to its previous release."""

    restore_failed = True

    def __init__(
        self, message: str, manifest: Mapping[str, Any] | None = None
    ) -> None:
        super().__init__(message)
        self.manifest = dict(manifest or {})


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
) -> tuple[list[str], list[str], dict[str, str], dict[str, str]]:
    """Recreate the touched services from their previous releases.

    Returns the restored and failed services, the container identity of every
    recreated service and the compose file each service was restored with.
    The identities are captured here so the caller never has to guess which
    release path produced a container.
    """

    restored: list[str] = []
    failed: list[str] = []
    containers: dict[str, str] = {}
    composes: dict[str, str] = {}
    root = _state_root(runner.transport, runner.environ)
    groups: dict[str, list[str]] = {}
    for service in services:
        path = paths.get(service)
        if path is None:
            failed.append(service)
            continue
        groups.setdefault(str(Path(path)), []).append(service)
    for path_text, group in groups.items():
        path = Path(path_text)
        try:
            manifest = _read_manifest(runner, root, project, path)
            compose = manifest["compose"]
            # Recreate the whole group in one Compose call.  With a global
            # rollback this stops every affected service before Compose
            # reconciles the project network; per-service calls would remove
            # a network that still has the other services attached.
            started = runner.run(
                _compose_command(
                    path, compose, project, True,
                    "up", "-d", "--no-deps", *group,
                ),
                check=False,
            )
            if started.returncode:
                raise AppDeployError("previous service release did not start")
            recreated = _containers(
                runner, path, compose, project, True, group
            )
            missing = [service for service in group if not recreated.get(service)]
            if missing:
                raise AppDeployError(
                    "previous service release did not recreate the container"
                )
        except Exception:
            failed.extend(group)
        else:
            restored.extend(group)
            containers.update({service: recreated[service] for service in group})
            for service in group:
                composes[service] = compose
    return restored, failed, containers, composes


_PROBE_PREFERRED_SERVICES = (
    "frontend", "web", "app", "vote", "result", "nginx", "ingress",
    "haproxy", "traefik", "proxy",
)
_PROBE_DENIED_SERVICES = frozenset({
    "database", "db", "postgres", "postgresql", "mysql", "mariadb",
    "mongo", "mongodb", "redis", "cache", "queue", "rabbitmq",
})


def compose_failure_reason(payload: object) -> str | None:
    """Summarise unhealthy/exited services from ``docker compose ps`` JSON."""
    if isinstance(payload, Mapping):
        if "Service" in payload or "Name" in payload:
            entries = [payload]
        else:
            entries = payload.get("services") or []
            if isinstance(entries, Mapping):
                entries = list(entries.values())
    elif isinstance(payload, list):
        entries = payload
    else:
        return None
    if not isinstance(entries, list):
        return None
    reasons: list[str] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        service = entry.get("Service") or entry.get("Name")
        state = str(entry.get("State") or "").lower()
        health = str(entry.get("Health") or "").lower()
        exit_code = entry.get("ExitCode")
        if health == "unhealthy":
            reasons.append(f"{service} is unhealthy")
        elif state in {"exited", "dead"}:
            reasons.append(f"{service} exited with code {exit_code}")
    if not reasons:
        return None
    return "; ".join(sorted(set(reasons))[:4])


def parse_compose_ps_json(value: str) -> object:
    """Accept both Compose JSON arrays and its newline-delimited JSON output."""
    text = value.strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        entries: list[object] = []
        for line in text.splitlines():
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                return []
        return entries


def _missing_runtime(
    runner: Runner,
    previous_containers: Mapping[str, Any],
    services: Sequence[str],
) -> list[str]:
    """Return services whose recorded container no longer exists."""
    missing: list[str] = []
    for service in services:
        container = previous_containers.get(service)
        if not isinstance(container, str) or not container:
            missing.append(service)
            continue
        inspected = runner.run(
            [
                "docker", "container", "inspect", "-f",
                "{{.State.Status}}", container,
            ],
            check=False,
        )
        if inspected.returncode:
            missing.append(service)
    return missing


def _exposed_port(config: Mapping[str, Any]) -> int | None:
    for entry in config.get("expose") or []:
        text = str(entry).split("/", 1)[0].strip()
        if text.isdigit() and 1 <= int(text) <= 65535:
            return int(text)
    for entry in config.get("ports") or []:
        target: object = None
        if isinstance(entry, Mapping):
            target = entry.get("target")
        elif isinstance(entry, str):
            target = entry.rsplit(":", 1)[-1].split("/", 1)[0]
        if isinstance(target, str) and target.isdigit():
            port = int(target)
        elif isinstance(target, int):
            port = target
        else:
            continue
        if 1 <= port <= 65535:
            return port
    return None


def fallback_probe_target(services: object) -> tuple[str, int] | None:
    """Pick a declared HTTP service when the app has no explicit ingress.

    Isolation is unchanged: the target is always a service of the same release
    network. Databases and services without a declared port never qualify, and
    an ambiguous set without a conventional ingress name fails closed.
    """
    if not isinstance(services, Mapping):
        return None
    candidates: dict[str, int] = {}
    for name, config in services.items():
        if not isinstance(name, str) or not isinstance(config, Mapping):
            continue
        if name.lower() in _PROBE_DENIED_SERVICES:
            continue
        port = _exposed_port(config)
        if port is not None:
            candidates[name] = port
    if len(candidates) == 1:
        service, port = next(iter(candidates.items()))
        return service, port
    for preferred in _PROBE_PREFERRED_SERVICES:
        if preferred in candidates:
            return preferred, candidates[preferred]
    return None


def _start_failure(
    runner: Runner,
    staged: Path,
    compose_rel: str,
    project: str,
    *,
    prefix: str,
) -> str:
    """Add the effective service state to a Compose start failure."""
    result = runner.run(
        _compose_command(
            staged, compose_rel, project, True,
            "ps", "--all", "--format", "json",
        ),
        check=False,
    )
    if result.returncode == 0:
        payload = parse_compose_ps_json(result.stdout)
        reason = compose_failure_reason(payload)
        if reason:
            return f"{prefix}: {reason}"
    return prefix


def _merged_paths(    previous: Mapping[str, Path | None],
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


def _ingress_labels_missing(
    runner: Runner,
    containers: Mapping[str, Any],
    services: Sequence[str],
    tenant_id: str,
) -> list[str]:
    """Containers deployed before A.SPEC 0114 have no tenancy labels.

    Docker cannot add labels to a running container, so a "noop" redeploy would
    leave the cell ingress unable to publish the App.  Return the services that
    must be recreated from the signed release.
    """
    missing: list[str] = []
    for service in services:
        container = containers.get(service)
        if not isinstance(container, str) or not container:
            missing.append(service)
            continue
        inspected = runner.run(
            [
                "docker",
                "inspect",
                "-f",
                '{{index .Config.Labels "spanel.managed"}}|'
                '{{index .Config.Labels "spanel.tenant"}}',
                container,
            ],
            check=False,
        )
        if inspected.returncode:
            missing.append(service)
            continue
        managed, _, tenant = inspected.stdout.strip().partition("|")
        if managed != "true" or tenant != tenant_id:
            missing.append(service)
    return missing


def _rewrite_override(runner: Runner, staged: Path, override: str) -> None:
    """Replace ``override.yaml`` in a release reused by a rollback."""
    path = staged / "override.yaml"
    if runner.transport == "ssh":
        result = runner.run(
            [
                "sh",
                "-c",
                f"umask 077; cat > {shlex.quote(str(path))}",
            ],
            stdin=override.encode(),
            check=False,
        )
        if result.returncode:
            raise AppDeployError("cannot rewrite the remote compose override")
        return
    path.write_text(override, encoding="utf-8")
    path.chmod(0o600)


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
    probe_target: tuple[str, int] | None = None,
    ingress_publish: tuple[str, int] | None = None,
    tenant_id: str | None = None,
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
    one_shot = one_shot_services(result.data["services"])
    resolved_probe_target = probe_target or fallback_probe_target(
        result.data.get("services")
    )
    publish: tuple[str, str, int, int] | None = None
    if ingress_publish is not None:
        if resolved_probe_target is None:
            raise AppDeployError("rootless ingress service could not be resolved")
        publish = (
            resolved_probe_target[0],
            ingress_publish[0],
            ingress_publish[1],
            resolved_probe_target[1],
        )
    if env_file is not None:
        env_file = validate_env_file(env_file, result.root)
    state_root = _state_root(runner.transport, runner.environ)
    staged = (
        Path(staging_release) if staging_release is not None
        else _release_dir(state_root, project, staging_id)
    )
    reusing = staging_release is not None
    override = _override(
        result.data, project, True, _env_path(staged), staging_id,
        ingress_publish=publish,
        tenant_id=tenant_id,
    )
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
        _stage_release(runner, result.root, staged, release.compose_path, override, env_file)
    else:
        # A reused release directory may carry an override from a previous
        # version without the spanel.* labels (A.SPEC 0114).  Rewrite it with
        # the current contract instead of inheriting stale state.
        _rewrite_override(runner, staged, override)
    compose_rel = release.compose_path
    # Compose services behind an inactive profile are never started by
    # `docker compose up` (they stay in `created`).  Exclude them from the
    # deploy plan and from runtime verification, just like `docker compose
    # config --format json` does.
    active = set(result.data["services"])
    try:
        compose_data = yaml.safe_load(
            (result.root / compose_rel).read_text(encoding="utf-8")
        )
        if isinstance(compose_data, Mapping):
            declared = compose_data.get("services", {})
            if isinstance(declared, Mapping):
                filtered = {
                    name
                    for name, config in declared.items()
                    if isinstance(name, str)
                    and not (isinstance(config, Mapping) and config.get("profiles"))
                }
                if filtered:
                    active = filtered
    except (OSError, ValueError, yaml.YAMLError):
        pass
    all_services = sorted(name for name in result.data["services"] if name in active)
    effective = [item for item in plan.effective_services if item in all_services]
    force_recreate = False
    if any(item not in result.data["services"] for item in plan.effective_services):
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
    if not initial and _missing_runtime(runner, previous_containers, all_services):
        # The signed state is valid but its containers were removed (for
        # example by an explicit ``down``).  Preserving services outside the
        # plan is impossible, so reconcile the whole release.
        plan = DeployPlan(
            requested_scope=plan.requested_scope,
            requested_service=plan.requested_service,
            effective_services=tuple(all_services),
            strategy="fallback",
            fallback_reason="runtime_containers_missing",
        )
        effective = list(all_services)
    if tenant_id and not initial:
        missing = _ingress_labels_missing(
            runner, previous_containers, all_services, tenant_id
        )
        # A.SPEC 0114 removes the per-App host publish that collided with
        # ``spanel-cell-ingress``.  Deployments written before this contract
        # must be recreated once even when their labels are already correct.
        stale_contract = previous.get("ingress_contract") != 2
        if missing or stale_contract:
            if stale_contract:
                forced = list(all_services)
                reason = "ingress_contract_migration"
            else:
                forced = sorted(set(effective) | set(missing))
                reason = "ingress_labels_missing"
            plan = DeployPlan(
                requested_scope="global",
                effective_services=tuple(forced),
                strategy="fallback",
                fallback_reason=reason,
            )
            effective = forced
            force_recreate = True
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
        tenant_id=tenant_id,
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
            prepare_runtime_volumes(runner, project, policy, effective)
        host = "local" if runner.transport == "local" else runner.host
        manifest = _manifest_data(
            options, result, project, images, "building", host, staged, policy
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
            # A.SPEC 0114: the relay targets the cell ingress; Apps never
            # publish their own host port.
            "ingress_contract": 2,
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
        # Pre-refactor releases carried ``x-spanel-readonly-files`` markers
        # produced by the retired Compose normalizer.  Only those legacy
        # artifacts need the stop/create/inject cycle so they stay rollback-
        # compatible.  New releases keep the developer's Compose untouched and
        # go straight from build to ``up``.
        readonly_services = {
            name for name in effective
            if isinstance(result.data["services"].get(name), Mapping)
            and result.data["services"][name].get("x-spanel-readonly-files")
        }
        if effective:
            if readonly_services:
                # Recreate the effective services so signed legacy read-only
                # files can be copied before the processes start.
                removed = runner.run(
                    _compose_command(
                        staged, compose_rel, project, True,
                        "rm", "-s", "-f", *sorted(effective),
                    ),
                    timeout=timeout,
                    check=False,
                )
                if removed.returncode:
                    raise AppDeployError(
                        f"Compose services failed to remove (exit {removed.returncode})"
                    )
                created = runner.run(
                    _compose_command(
                        staged, compose_rel, project, True,
                        "create", *sorted(effective),
                    ),
                    timeout=timeout,
                    check=False,
                )
                if created.returncode:
                    raise AppDeployError(
                        f"Compose services failed to create (exit {created.returncode})"
                    )
                staged_containers = _containers(
                    runner, staged, compose_rel, project, True, sorted(effective)
                )
                _inject_readonly_files(
                    runner,
                    staged,
                    compose_rel,
                    staged_containers,
                    {name: result.data["services"][name] for name in effective},
                )
            if initial or len(effective) == len(all_services):
                # A global plan must reconcile every service in one Compose
                # call.  Doing it service by service stops only one container
                # and then Compose tries to remove the project network while
                # the remaining containers are still attached.
                if not initial:
                    modified = list(effective)
                started = runner.run(
                    _compose_command(
                        staged, compose_rel, project, True,
                        "up", "-d",
                        "--force-recreate" if force_recreate else "--no-recreate",
                    ),
                    timeout=timeout,
                    check=False,
                )
                up_started = True
                if started.returncode:
                    raise AppDeployError(_start_failure(
                        runner, staged, compose_rel, project,
                        prefix=(
                            "Compose services failed to start "
                            f"(exit {started.returncode})"
                        ),
                    ))
            else:
                for service in effective:
                    modified.append(service)
                    started = runner.run(
                        _compose_command(
                            staged, compose_rel, project, True,
                            "up", "-d", "--no-deps",
                            "--force-recreate" if force_recreate else "--no-recreate",
                            service,
                        ),
                        timeout=timeout,
                        check=False,
                    )
                    up_started = True
                    if started.returncode:
                        raise AppDeployError(_start_failure(
                            runner, staged, compose_rel, project,
                            prefix=(
                                f"service {service} failed to start "
                                f"(exit {started.returncode})"
                            ),
                        ))
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
                one_shot=one_shot,
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
                target=resolved_probe_target,
                one_shot=one_shot,
            )
        probes = run_probes(
            runner,
            release=staged,
            compose_rel=compose_rel,
            project=project,
            services=all_services,
            containers=merged_containers,
            environ=runner.environ,
            target=resolved_probe_target,
            one_shot=one_shot,
        )
        manifest.update({
            "status": "running",
            "containers": dict(sorted(merged_containers.items())),
            "container_names": _container_names(runner, merged_containers),
            "service_runtime": runtime_snapshot(runner, merged_containers),
            "probes": probes,
            "service_probes": scoped_probes,
            "probe_target": (
                {"service": resolved_probe_target[0], "port": resolved_probe_target[1]}
                if resolved_probe_target is not None else None
            ),
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
            restored, failed, restored_containers, restored_composes = _restore(
                runner,
                project=project,
                services=modified,
                paths=previous_paths,
            )
            manifest["restoration"] = {
                "restored": restored,
                "failed": failed,
            }
            restoration = manifest["restoration"]
            previous_compose = previous.get("compose")
            if not isinstance(previous_compose, str) or not previous_compose:
                previous_compose = release.compose_path
            # Every service needs an identity before the restored runtime can be
            # verified: touched services come from the recreation above, the rest
            # keep the active state they already had.
            identities: dict[str, str] = dict(restored_containers)
            for service in all_services:
                if service in identities or service in failed:
                    continue
                container = previous_containers.get(service)
                if isinstance(container, str) and container:
                    identities[service] = container
            complete = len(identities) == len(all_services)
            if identities:
                restoration["container_ids"] = dict(sorted(identities.items()))
                restoration["service_runtime"] = runtime_snapshot(
                    runner, identities
                )
            if identities and complete and not failed:
                probe_release = (
                    previous_paths.get(restored[0])
                    if restored else previous_release
                )
                probe_compose = (
                    restored_composes.get(restored[0])
                    if restored else None
                ) or previous_compose
                if probe_release is None:
                    restoration["failed"] = [*failed, "verification"]
                    restoration["verification_error"] = (
                        "no release path is available to verify the restoration"
                    )
                else:
                    try:
                        # The restored containers were just recreated: wait for
                        # running/healthy before the probe window, exactly like a
                        # regular scoped deployment does.
                        _verify_containers(
                            runner,
                            restored_containers,
                            project,
                            True,
                            wait,
                            one_shot=set(previous.get("one_shot") or []),
                        )
                    except Exception as verify_exc:
                        restoration["failed"] = [*failed, "verification"]
                        restoration["verification_error"] = (
                            str(verify_exc) or type(verify_exc).__name__
                        )
                    else:
                        try:
                            restored_probes = run_probes(
                                runner,
                                release=probe_release,
                                compose_rel=probe_compose,
                                project=project,
                                services=all_services,
                                containers=identities,
                                environ=runner.environ,
                                target=resolved_probe_target,
                                one_shot=set(previous.get("one_shot") or []),
                            )
                        except Exception as probe_exc:
                            restoration["failed"] = [*failed, "probes"]
                            restoration["probe_error"] = (
                                str(probe_exc) or type(probe_exc).__name__
                            )
                        else:
                            restoration["probes"] = restored_probes
                            restoration["verified"] = True
            elif not failed:
                restoration["failed"] = [*failed, "verification"]
                restoration["verification_error"] = (
                    "restored state does not cover every service"
                )
            _write_manifest(runner, staged, manifest)
            failed = list(restoration.get("failed") or [])
            if any(service in modified for service in failed):
                raise ScopedRestoreError(
                    "restoration failed; the application is degraded",
                    manifest,
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
