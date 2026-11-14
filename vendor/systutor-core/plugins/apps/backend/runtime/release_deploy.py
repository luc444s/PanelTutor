"""The only deployment path: a verified, signed ``TrustedRelease``."""

from __future__ import annotations

import hashlib
from typing import Any

from ..hardening import HardeningPolicy
from ..releases.store import release_store_root
from ..releases.verify import verify_release
from .deployment import (
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
from .probes import run_probes
from .transport import Runner
from .types import AppDeployError, DeployOptions


def deploy_trusted(
    release: Any,
    options: DeployOptions,
    runner: Runner,
) -> dict[str, Any]:
    """Verify, stage, build, probe and publish one signed release."""

    try:
        policy = HardeningPolicy.from_dict(release.body["policy"])
    except (TypeError, ValueError, KeyError):
        raise AppDeployError("release policy is invalid") from None
    verified = verify_release(
        release_store_root(runner.environ), release,
        environ=runner.environ, policy=policy,
    )
    result = verified.audit
    if result.errors:
        raise AppDeployError("release audit found blocking errors")
    env_file = (
        validate_env_file(options.env_file, result.root)
        if options.env_file else None
    )
    if options.dry_run:
        return None  # type: ignore[return-value]
    project = options.project
    if not project:
        raise AppDeployError("trusted deployments require a project identifier")
    release_id = options.release_id or release.release_id
    state_root = _state_root(options.transport, runner.environ)
    staged = state_root / project / "releases" / release_id
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
            raise AppDeployError("cannot verify remote project release availability")
    _ensure_owned(runner, project)
    compose_rel = release.compose_path
    override = _override(result.data, project, True, _env_path(staged))
    _stage_release(runner, result.root, staged, compose_rel, override, env_file)
    services = sorted(result.data["services"])
    _validate_compose_environment(runner, staged, compose_rel, project)
    pulled = runner.run(
        _compose_command(
            staged, compose_rel, project, True, "pull", "--ignore-buildable",
        ),
        timeout=options.timeout,
        check=False,
    )
    if pulled.returncode:
        raise AppDeployError(f"Compose image pull failed (exit {pulled.returncode})")
    built = runner.run(
        _compose_command(staged, compose_rel, project, True, "build"),
        timeout=options.timeout,
        check=False,
    )
    if built.returncode:
        raise AppDeployError(f"Compose image build failed (exit {built.returncode})")
    images = _image_users(runner, staged, compose_rel, project, True, services)
    image_ids: dict[str, str] = {}
    for service, image in images.items():
        inspected = runner.run(
            ["docker", "image", "inspect", "-f", "{{.Id}}", image], check=False
        )
        image_id = inspected.stdout.strip()
        if inspected.returncode or not image_id:
            raise AppDeployError(f"cannot resolve the image id for service {service}")
        image_ids[service] = image_id
    host = "local" if runner.transport == "local" else runner.host
    manifest = _manifest_data(options, result, project, images, "building", host, staged)
    manifest.update({
        "commit": release.commit,
        "tree_hash": release.hardened_tree_sha256,
        "source_tree_sha256": release.source_tree_sha256,
        "compose": compose_rel,
        "images": images,
        "image_ids": image_ids,
        "hardened_release": release.to_dict(),
        "non_root": True,
    })
    _write_manifest(runner, staged, manifest)
    up_started = False
    try:
        started = runner.run(
            _compose_command(staged, compose_rel, project, True, "up", "-d"),
            timeout=options.timeout,
            check=False,
        )
        up_started = True
        if started.returncode:
            raise AppDeployError(
                f"Compose services failed to start (exit {started.returncode})"
            )
        containers = _containers(runner, staged, compose_rel, project, True, services)
        _verify_containers(runner, containers, project, True, options.wait)
        probes = run_probes(
            runner,
            release=staged,
            compose_rel=compose_rel,
            project=project,
            services=services,
            containers=containers,
            environ=runner.environ,
        )
        manifest["status"] = "running"
        manifest["containers"] = containers
        manifest["container_names"] = _container_names(runner, containers)
        manifest["service_runtime"] = runtime_snapshot(runner, containers)
        manifest["probes"] = probes
        _write_manifest(runner, staged, manifest)
        if options.publish_state:
            _publish_release_state(runner, staged, manifest)
        return manifest
    except Exception as exc:
        manifest["status"] = "failed"
        if up_started:
            logs = runner.run(
                _compose_command(
                    staged, compose_rel, project, True,
                    "logs", "--no-color", "--tail", "200",
                ),
                check=False,
            )
            diagnostic = (logs.stdout + logs.stderr).encode()
            manifest["diagnostics"] = {
                "sha256": hashlib.sha256(diagnostic).hexdigest(),
                "bytes": len(diagnostic),
            }
            runner.run(
                _compose_command(
                    staged, compose_rel, project, True, "down", "--remove-orphans"
                ),
                check=False,
            )
        _write_manifest(runner, staged, manifest)
        if isinstance(exc, AppDeployError):
            raise
        raise AppDeployError("trusted deployment failed") from None
