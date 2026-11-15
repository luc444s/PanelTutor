#!/usr/bin/env python3
"""E2E: reject unsafe PanelTutor, normalize a copy, and deploy it safely."""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "vendor" / "systutor-core" / "plugins"
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from apps.backend.runtime import (  # type: ignore
    OWNER_LABEL,
    AppDeployError,
    DeployOptions,
    LifecycleOptions,
    Runner,
    audit_project,
    clone_repo,
    deploy,
    lifecycle,
)

DEFAULT_REPO = "luc444s/PanelTutor"
DEFAULT_BRANCH = "main"
DEFAULT_COMPOSE = "docker-compose.yml"
EXPECTED_UNSAFE = {
    "compose_docker_socket",
    "compose_external_resource",
    "compose_repo_env_file",
    "dockerfile_final_user_root",
}
ROOT_USERS = {"", "0", "root", "0:0", "root:root"}


class E2EError(RuntimeError):
    """Expected failure whose message contains no secret values."""


def default_project() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    return f"paneltutor-normalized-e2e-{stamp}-{os.getpid()}"[:63]


def validate_env_file(path: Path) -> Path:
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise E2EError("env file does not exist") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise E2EError("env file must be a regular non-symlink file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise E2EError("env file must have mode 0600")
    return resolved


def unsafe_codes(result: Any) -> set[str]:
    return {item.code for item in result.errors}


def require_unsafe_source(result: Any) -> set[str]:
    codes = unsafe_codes(result)
    if not result.errors:
        raise E2EError("source was not blocked before normalization")
    missing = EXPECTED_UNSAFE.difference(codes)
    if missing:
        raise E2EError(
            "source did not expose the expected unsafe controls: "
            + ", ".join(sorted(missing))
        )
    return codes


def normalize_checkout(checkout: Path, compose_file: str) -> None:
    command = [
        sys.executable,
        str(ROOT / "scripts" / "dangerous_build_normalize.py"),
        "fix",
        str(checkout),
        "--compose-file",
        compose_file,
        "--non-root",
        "--deployment-copy",
        "--service-user",
        "postgres=postgres",
        "--service-user",
        "redis=redis",
        "--apply",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise E2EError("normalizer could not execute") from exc
    if completed.returncode:
        raise E2EError("normalizer did not produce a deployable checkout")


def _non_root(value: Any) -> bool:
    text = str(value).strip().lower()
    first = text.split(":", 1)[0]
    return text not in ROOT_USERS and first != "root" and not (
        first.isdigit() and int(first) == 0
    )


def _container_inspect(runner: Runner, container: str) -> dict[str, Any]:
    completed = runner.run(
        ["docker", "container", "inspect", "--format", "{{json .}}", container]
    )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise E2EError("Docker returned invalid container inspection data") from exc
    if not isinstance(value, dict):
        raise E2EError("Docker returned invalid container inspection data")
    return value


def _verify_mounts(container: dict[str, Any], service: str) -> None:
    for mount in container.get("Mounts") or []:
        if not isinstance(mount, dict):
            raise E2EError(f"service {service} has an unreadable mount")
        source = str(mount.get("Source") or "").rstrip("/").lower()
        destination = "/" + str(mount.get("Destination") or "").lstrip("/")
        if source.endswith("/docker.sock") or source == "docker.sock":
            raise E2EError(f"service {service} retained docker.sock")
        if mount.get("Type") == "bind":
            private_secret = (
                destination.startswith("/run/secrets/") and mount.get("RW") is False
            )
            if not private_secret:
                raise E2EError(f"service {service} retained an uncontrolled host bind")


def verify_deployment(
    manifest: dict[str, Any], runner: Runner, project: str
) -> dict[str, dict[str, Any]]:
    if manifest.get("status") != "running" or manifest.get("project") != project:
        raise E2EError("deployment manifest is not running for the requested project")
    if manifest.get("owner_label") != OWNER_LABEL or manifest.get("non_root") is not True:
        raise E2EError("deployment manifest lacks controlled ownership or non-root mode")
    containers = manifest.get("containers")
    services = manifest.get("services")
    if not isinstance(containers, dict) or not containers:
        raise E2EError("deployment manifest has no containers")
    if set(containers) != set(services or []):
        raise E2EError("deployment manifest does not map every service")

    evidence: dict[str, dict[str, Any]] = {}
    for service, container_id in sorted(containers.items()):
        inspected = _container_inspect(runner, str(container_id))
        config = inspected.get("Config") or {}
        host = inspected.get("HostConfig") or {}
        state = inspected.get("State") or {}
        labels = config.get("Labels") or {}
        if labels.get(OWNER_LABEL) != project:
            raise E2EError(f"service {service} lacks the ownership label")
        if not state.get("Running"):
            raise E2EError(f"service {service} is not running")
        health = (state.get("Health") or {}).get("Status")
        if health and health != "healthy":
            raise E2EError(f"service {service} is not healthy")
        if not _non_root(config.get("User")):
            raise E2EError(f"service {service} has a root image user")
        if host.get("Privileged") or host.get("CapAdd"):
            raise E2EError(f"service {service} retained elevated privileges")
        for key in ("NetworkMode", "PidMode", "IpcMode", "UTSMode", "UsernsMode"):
            if str(host.get(key) or "").lower() == "host":
                raise E2EError(f"service {service} retained host namespace access")
        if host.get("PortBindings"):
            raise E2EError(f"service {service} published host ports")
        _verify_mounts(inspected, str(service))
        users = runner.run(
            ["docker", "top", str(container_id), "-eo", "pid,uid"], check=False
        )
        rows = [line.split() for line in users.stdout.splitlines() if line.strip()]
        try:
            uid_index = [item.lower() for item in rows[0]].index("uid")
            process_users = [row[uid_index].lower() for row in rows[1:]]
        except (IndexError, ValueError):
            process_users = []
        if (
            users.returncode
            or not process_users
            or any(not _non_root(user) for user in process_users)
        ):
            raise E2EError(f"service {service} has root or unreadable effective processes")
        evidence[str(service)] = {
            "container_id": str(container_id),
            "health": health or "none",
            "running": True,
            "user": str(config.get("User")),
        }
    app_container = containers.get("app")
    if not app_container:
        raise E2EError("PanelTutor deployment has no app service")
    health_probe = runner.run(
        [
            "docker",
            "exec",
            str(app_container),
            "python",
            "-c",
            (
                "import os,urllib.request;"
                "port=os.environ.get('PORT','3000');"
                "urllib.request.urlopen('http://127.0.0.1:' + port + "
                "'/api/v1/system/health',timeout=10).read()"
            ),
        ],
        check=False,
        timeout=30,
    )
    if health_probe.returncode:
        raise E2EError("PanelTutor application health endpoint is unavailable")
    evidence["app"]["application_health"] = "ok"
    return evidence


def write_evidence(path: Path, payload: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, sort_keys=True, indent=2)
        stream.write("\n")
    path.chmod(0o600)


def cleanup_failed(project: str, transport: str, runner: Runner) -> None:
    lifecycle(
        LifecycleOptions(
            command="down",
            project=project,
            transport=transport,
            purge_data=True,
            confirm_purge=project,
        ),
        runner,
    )


def run(args: argparse.Namespace) -> int:
    env_file = validate_env_file(args.env_file)
    runner = Runner(args.transport)
    deployed = False
    started = datetime.now(UTC)
    try:
        with tempfile.TemporaryDirectory(prefix="paneltutor-normalized-e2e-") as temporary:
            checkout = Path(temporary) / "checkout"
            print("[1/6] Clone unnormalized PanelTutor source")
            clone_repo(args.repo, args.branch, checkout, Runner("local"))

            print("[2/6] Prove the original source is blocked")
            initial = audit_project(checkout, args.compose_file, non_root=True)
            initial_codes = require_unsafe_source(initial)
            print(f"  blocked with {len(initial.errors)} errors")

            print("[3/6] Normalize the disposable deployment checkout")
            normalize_checkout(checkout, args.compose_file)

            print("[4/6] Require a clean post-normalization audit")
            normalized = audit_project(checkout, args.compose_file, non_root=True)
            if normalized.errors:
                codes = ", ".join(sorted(unsafe_codes(normalized)))
                raise E2EError(f"normalized checkout still has blocking findings: {codes}")

            print("[5/6] Deploy through the controlled Apps runtime")
            manifest = deploy(
                DeployOptions(
                    repo=args.repo,
                    branch=args.branch,
                    env_file=env_file,
                    project=args.project,
                    transport=args.transport,
                    non_root=True,
                    timeout=args.timeout,
                    wait=args.wait,
                ),
                normalized,
                runner,
            )
            if manifest is None:
                raise E2EError("controlled deploy returned no manifest")
            deployed = True

            print("[6/6] Verify confinement and leave the deployment running")
            services = verify_deployment(manifest, runner, args.project)
            evidence = {
                "schema": 1,
                "repository": args.repo,
                "branch": args.branch,
                "commit": manifest.get("commit"),
                "project": args.project,
                "status": "running",
                "transport": args.transport,
                "initial_error_codes": sorted(initial_codes),
                "residual_error_codes": [],
                "services": services,
                "completed_at": datetime.now(UTC).isoformat(),
                "duration_seconds": (datetime.now(UTC) - started).total_seconds(),
            }
            if args.evidence:
                write_evidence(args.evidence, evidence)
            print(json.dumps(evidence, sort_keys=True))
            print("Deployment preserved. Remove it explicitly with:")
            print(
                f"python3 scripts/app_deploy.py down --transport {args.transport} "
                f"--project {args.project} --purge-data --confirm-purge {args.project}"
            )
            return 0
    except Exception:
        if deployed and not args.keep_failed:
            try:
                cleanup_failed(args.project, args.transport, runner)
            except Exception as cleanup_error:
                raise E2EError("deployment verification and controlled cleanup failed") from cleanup_error
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument("--compose-file", default=DEFAULT_COMPOSE)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--transport", choices=("local", "ssh"), default="local")
    parser.add_argument("--project", default=default_project())
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--wait", type=int, default=300)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument(
        "--keep-failed",
        action="store_true",
        help="preserve an owned deployment even when runtime verification fails",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(build_parser().parse_args(argv))
    except (AppDeployError, E2EError) as exc:
        print(f"E2E FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
