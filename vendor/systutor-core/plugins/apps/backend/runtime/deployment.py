"""Staging, ownership checks, deployment and manifests."""
from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
import re
import shlex
import stat
import subprocess
import tarfile
import time
from collections.abc import Iterable, Mapping
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from ..hardening.contracts import HardeningPolicy
from ..symlinks import symlink_target
from .source import _inside
from .tenant_plan import TenantPlan, current_tenant_plan, service_limits
from .transport import Runner
from .types import (
    MANIFEST,
    OWNER_LABEL,
    PROJECT_RE,
    SAFE_REMOTE_RE,
    AppDeployError,
    AuditResult,
    DeployOptions,
    one_shot_services,
    readonly_release_file,
)


def validate_env_file(path: Path, checkout: Path) -> Path:
    path = path.expanduser()
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise AppDeployError("env file does not exist") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise AppDeployError("env file must be a regular non-symlink file")
    if info.st_mode & (stat.S_IRGRP | stat.S_IROTH):
        raise AppDeployError("env file must not be readable by group or others")
    if _inside(resolved, checkout.resolve(strict=True)):
        raise AppDeployError("env file must be outside the checkout")
    return resolved


def render_report(result: AuditResult, output_format: str = "human") -> str:
    if output_format == "json":
        return json.dumps(
            {
                "compose": result.compose.relative_to(result.root).as_posix(),
                "findings": [asdict(item) for item in result.findings],
                "warnings": list(result.warnings),
                "errors": len(result.errors),
                "warning": (
                    "Static heuristics do not prove safety; Docker builds execute "
                    "untrusted code."
                ),
            },
            sort_keys=True,
            indent=2,
        )
    rows = [
        f"Compose: {result.compose.relative_to(result.root).as_posix()}",
        "WARNING: static heuristics do not prove safety; Docker builds execute untrusted code.",
    ]
    rows.extend(f"WARNING: {warning}" for warning in result.warnings)
    for item in result.findings:
        owner = f" service={item.service}" if item.service else ""
        rows.append(
            f"{item.severity.upper()} {item.code} {item.path}:{item.line}{owner}: "
            f"{item.message} Remediation: {item.remediation}"
        )
    rows.append(f"Summary: errors={len(result.errors)} findings={len(result.findings)}")
    return "\n".join(rows)


def _project_id(repo: str | None, source: Path) -> str:
    seed = repo or source.name
    slug = re.sub(r"[^a-z0-9]+", "-", seed.lower()).strip("-")[-40:] or "app"
    digest = hashlib.sha256(seed.encode()).hexdigest()[:10]
    return f"{slug}-{digest}"[:63]


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if rel == ".git" or rel.startswith(".git/"):
            continue
        digest.update(rel.encode() + b"\0")
        if path.is_symlink():
            digest.update(b"L" + symlink_target(path).encode())
        elif path.is_file():
            digest.update(b"F")
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
    return digest.hexdigest()


def _git_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    value = result.stdout.strip()
    return (
        value
        if result.returncode == 0 and re.fullmatch(r"[0-9a-fA-F]{40,64}", value)
        else "unknown"
    )


def _is_loopback_host(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _override(
    data: dict[str, Any],
    project: str,
    non_root: bool,
    external_env: Path | None = None,
    image_tag: str = "latest",
    plan: TenantPlan | None = None,
    *,
    ingress_publish: tuple[str, str, int, int] | None = None,
    tenant_id: str | None = None,
) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", image_tag):
        raise AppDeployError("release image tag is invalid")
    service_labels: dict[str, str] = {OWNER_LABEL: project}
    if tenant_id:
        # The cell ingress only publishes a target that proves both ownership
        # and tenant identity, exactly like Hosting containers.
        service_labels["spanel.managed"] = "true"
        service_labels["spanel.tenant"] = str(tenant_id)
    services: dict[str, Any] = {}
    for service, source_config in data["services"].items():
        config: dict[str, Any] = {"labels": dict(service_labels)}
        if (
            isinstance(source_config, dict)
            and source_config.get("x-spanel-external-env") is True
            and external_env is not None
        ):
            config["env_file"] = [str(external_env)]
        if isinstance(source_config, dict) and source_config.get("build") is not None:
            image_key = hashlib.sha256(
                f"{project}\0{service}".encode()
            ).hexdigest()[:20]
            config["image"] = f"spanel-app-{image_key}:{image_tag}"
        # Security is enforced by the kernel boundary of the rootless cell
        # (user/mount/net namespaces, AppArmor profile, cgroups and nftables).
        # The platform must not inject container-level hardening the developer
        # did not ask for: doing so overrode their Compose (e.g. ``init: true``
        # or ``read_only: true``) and created conflicts the app never had.
        services[service] = config
    if ingress_publish is not None:
        service, host, host_port, target_port = ingress_publish
        if service not in services:
            raise AppDeployError("rootless ingress service is not in the release")
        if not _is_loopback_host(host) or not 1 <= host_port <= 65535:
            raise AppDeployError("rootless ingress publish address is invalid")
        if not 1 <= target_port <= 65535:
            raise AppDeployError("rootless ingress target port is invalid")
        source_config = data["services"].get(service)
        if isinstance(source_config, Mapping) and source_config.get("network_mode"):
            raise AppDeployError(
                "rootless ingress service uses network_mode; cannot publish"
            )
        ingress_network = "spanel-ingress"
        current = services[service].get("networks")
        if isinstance(current, Mapping):
            names = [str(name) for name in current]
        elif isinstance(current, list):
            names = [str(name) for name in current]
        else:
            names = ["default"]
        if ingress_network not in names:
            names.append(ingress_network)
        services[service]["networks"] = names
        # The cell's rootlesskit builtin port driver binds the requested parent
        # IP, so the service is reachable only on the cell's dedicated loopback.
        # It cannot publish from an internal Docker network; the public ingress
        # service gets a dedicated non-internal network while every other
        # service stays on the internal release network.
        services[service]["ports"] = [f"{host}:{host_port}:{target_port}"]
    effective_plan = plan if plan is not None else current_tenant_plan()
    if effective_plan is not None:
        # A plan replaces the fixed defaults: containers are placed under the
        # tenant slice and their limits are derived from the tenant aggregate.
        # Without a plan this block is a no-op and the override is byte-identical
        # to the previous behaviour (see test_no_invasive_hardening).
        derived = service_limits(effective_plan, data["services"])
        for service, config in services.items():
            config["cgroup_parent"] = effective_plan.slice
            config.update(derived.get(service, {}))
    output: dict[str, Any] = {"services": services}
    if data.get("volumes"):
        managed_volumes = {}
        for name, raw in data["volumes"].items():
            config = raw if isinstance(raw, dict) else {}
            if config.get("external") is True or isinstance(config.get("external"), dict):
                continue
            managed_volumes[name] = {"labels": {OWNER_LABEL: project}}
        if managed_volumes:
            output["volumes"] = managed_volumes
    declared_networks = data.get("networks") or {}
    network_entries: dict[str, Any] = {}
    for name, raw in declared_networks.items():
        config = raw if isinstance(raw, dict) else {}
        entry: dict[str, Any] = {"labels": {OWNER_LABEL: project}}
        external = config.get("external")
        if external is True or isinstance(external, dict):
            entry["external"] = True
            if config.get("name"):
                entry["name"] = config["name"]
        else:
            entry["internal"] = config.get("internal") is not False
        network_entries[str(name)] = entry
    if not network_entries:
        network_entries["default"] = {
            "internal": True,
            "labels": {OWNER_LABEL: project},
        }
    if ingress_publish is not None:
        network_entries["spanel-ingress"] = {
            "internal": False,
            "labels": {OWNER_LABEL: project},
        }
    output["networks"] = network_entries
    return yaml.safe_dump(output, sort_keys=True)


def _tar_release(
    root: Path, compose_rel: str, override: str, env_file: Path | None
) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", dereference=False) as archive:
        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root)
            if rel.parts and rel.parts[0] == ".git":
                continue
            archive.add(
                path, arcname=(Path("source") / rel).as_posix(), recursive=False
            )
        override_bytes = override.encode()
        info = tarfile.TarInfo("override.yaml")
        info.size, info.mode = len(override_bytes), 0o600
        archive.addfile(info, io.BytesIO(override_bytes))
        # An explicit (possibly empty) env file prevents Compose from loading
        # a checkout .env implicitly.
        env_bytes = env_file.read_bytes() if env_file else b""
        info = tarfile.TarInfo("app.env")
        info.size, info.mode = len(env_bytes), 0o600
        archive.addfile(info, io.BytesIO(env_bytes))
        marker = compose_rel.encode()
        info = tarfile.TarInfo("compose.path")
        info.size, info.mode = len(marker), 0o600
        archive.addfile(info, io.BytesIO(marker))
    return stream.getvalue()


def _state_root(transport: str, environ: dict[str, str]) -> Path:
    if transport == "ssh":
        value = environ.get("SPANEL_APP_REMOTE_ROOT", "").strip()
        if (
            not value
            or not SAFE_REMOTE_RE.fullmatch(value)
            or ".." in Path(value).parts
        ):
            raise AppDeployError("SSH requires a safe absolute SPANEL_APP_REMOTE_ROOT")
        return Path(value)
    value = (
        environ.get("SPANEL_APPS_STATE_ROOT", "").strip()
        or environ.get("SPANEL_APP_STATE_ROOT", "").strip()
    )
    return (
        Path(value).expanduser() if value else Path.home() / ".local/state/spanel/apps"
    )


def _stage_release(
    runner: Runner,
    root: Path,
    release: Path,
    compose_rel: str,
    override: str,
    env_file: Path | None,
) -> None:
    payload = _tar_release(root, compose_rel, override, env_file)
    if runner.transport == "ssh":
        if release.parent.name == "releases":
            private = release.parent.parent / "private" / release.name
            command = (
                f"umask 077; mkdir -p {shlex.quote(str(release))} "
                f"{shlex.quote(str(private))}; "
                f"tar -xzf - -C {shlex.quote(str(release))}; "
                f"mv {shlex.quote(str(release / 'app.env'))} "
                f"{shlex.quote(str(private / 'app.env'))}; "
                f"chmod 600 {shlex.quote(str(release / 'override.yaml'))} "
                f"{shlex.quote(str(private / 'app.env'))}"
            )
        else:
            command = (
                f"umask 077; mkdir -p {shlex.quote(str(release))}; "
                f"tar -xzf - -C {shlex.quote(str(release))}; "
                f"chmod 600 {shlex.quote(str(release / 'override.yaml'))} "
                f"{shlex.quote(str(release / 'app.env'))}"
            )
        argv, env = runner._ssh_argv(command)
        try:
            result = subprocess.run(
                argv,
                input=payload,
                capture_output=True,
                env=env,
                timeout=600,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AppDeployError("failed to transfer release over SSH") from exc
        if result.returncode:
            raise AppDeployError("failed to transfer release over SSH")
    else:
        release.mkdir(parents=True, exist_ok=False)
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            archive.extractall(release, filter="data")
        if release.parent.name == "releases":
            private = release.parent.parent / "private" / release.name
            private.mkdir(parents=True, mode=0o700)
            private.chmod(0o700)
            os.replace(release / "app.env", private / "app.env")
            (private / "app.env").chmod(0o600)


def _env_path(release: Path) -> Path:
    if release.parent.name == "releases":
        private = release.parent.parent / "private" / release.name / "app.env"
        # Releases staged by older versions kept app.env inside the release
        # directory.  Falling back keeps them restorable/rollback-able after
        # the private/<release>/app.env layout was introduced.
        if not private.exists() and (release / "app.env").is_file():
            return release / "app.env"
        return private
    return release / "app.env"


def _compose_command(
    release: Path, compose_rel: str, project: str, env: bool, *tail: str
) -> list[str]:
    args = [
        "docker",
        "compose",
        "--project-name",
        project,
        "--project-directory",
        str(release / "source"),
        "-f",
        str(release / "source" / compose_rel),
    ]
    if env:
        args.extend(["--env-file", str(_env_path(release))])
    args.extend(["-f", str(release / "override.yaml"), *tail])
    return args


def _ensure_owned(runner: Runner, project: str) -> None:
    for kind, label_source, listing in (
        (
            "container",
            ".Config.Labels",
            [
                "docker",
                "ps",
                "-aq",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ],
        ),
        (
            "network",
            ".Labels",
            [
                "docker",
                "network",
                "ls",
                "-q",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ],
        ),
        (
            "volume",
            ".Labels",
            [
                "docker",
                "volume",
                "ls",
                "-q",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ],
        ),
    ):
        found = runner.run(listing).stdout.split()
        for resource in found:
            label = runner.run(
                [
                    "docker",
                    kind,
                    "inspect",
                    "-f",
                    f'{{{{index {label_source} "{OWNER_LABEL}"}}}}',
                    resource,
                ],
                check=False,
            )
            if label.returncode or label.stdout.strip() != project:
                raise AppDeployError(f"project name is occupied by an unowned {kind}")


def _image_users(
    runner: Runner,
    release: Path,
    compose_rel: str,
    project: str,
    env: bool,
    services: Iterable[str],
) -> dict[str, str]:
    rendered = runner.run(
        _compose_command(
            release, compose_rel, project, env, "config", "--format", "json"
        )
    ).stdout
    try:
        configured = json.loads(rendered)
        configured_services = configured["services"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise AppDeployError("cannot resolve images from normalized Compose config") from exc
    images: dict[str, str] = {}
    for service in services:
        service_config = configured_services.get(service)
        if not isinstance(service_config, dict):
            # Compose omits services behind inactive profiles from `config`.
            # Such a service is not part of this deployment, so it has no image
            # to resolve and no container to verify.
            continue
        image = service_config.get("image", "")
        if not isinstance(image, str) or not image.strip() or "\n" in image:
            raise AppDeployError(
                f"cannot resolve exactly one image for service {service}"
            )
        image = image.strip()
        # UID 0 inside the cell is the tenant's own subuid, never host root, so
        # the image user is a developer decision, not an admission gate.
        images[service] = image
    return images


def _service_internal_ports(data: dict[str, Any]) -> dict[str, list[int]]:
    """Container-side ports only; host bindings never reach the API."""
    result: dict[str, list[int]] = {}
    for service, config in data["services"].items():
        if not isinstance(config, dict):
            result[str(service)] = []
            continue
        found: set[int] = set()
        for key in ("ports", "expose"):
            for item in config.get(key) or []:
                value: Any = item
                if isinstance(item, dict):
                    value = item.get("target")
                elif isinstance(item, str):
                    value = item.split("/", 1)[0].rsplit(":", 1)[-1]
                if isinstance(value, int) and 1 <= value <= 65535:
                    found.add(value)
                elif isinstance(value, str) and value.isdigit():
                    port = int(value)
                    if 1 <= port <= 65535:
                        found.add(port)
        result[str(service)] = sorted(found)
    return result


def _container_names(
    runner: Runner, containers: dict[str, str]
) -> dict[str, str]:
    """Stable Docker DNS names for the active containers (never IDs)."""
    result: dict[str, str] = {}
    for service, container in containers.items():
        inspected = runner.run(
            ["docker", "container", "inspect", "-f", "{{.Name}}", container],
            check=False,
        )
        name = inspected.stdout.strip().lstrip("/")
        if inspected.returncode == 0 and name:
            result[service] = name
    return result


def runtime_snapshot(
    runner: Runner, containers: dict[str, str]
) -> dict[str, dict[str, Any]]:
    """Best-effort, non-secret runtime state for the service modal."""
    result: dict[str, dict[str, Any]] = {}
    for service, container in containers.items():
        values: dict[str, Any] = {}
        for key, template in (
            ("status", "{{.State.Status}}"),
            (
                "health",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
            ),
            ("restart_count", "{{.RestartCount}}"),
            ("created_at", "{{.Created}}"),
            ("started_at", "{{.State.StartedAt}}"),
            ("container_id", "{{.Id}}"),
            ("image_id", "{{.Image}}"),
            ("user", "{{.Config.User}}"),
        ):
            inspected = runner.run(
                ["docker", "container", "inspect", "-f", template, container],
                check=False,
            )
            if inspected.returncode:
                continue
            text = inspected.stdout.strip()
            if key == "restart_count" and text.isdigit():
                values[key] = int(text)
            elif text:
                values[key] = text
        if values:
            result[service] = values
    return result


_ENV_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::[^}]*)?\}")


def _service_environment_names(data: dict[str, Any]) -> dict[str, list[str]]:
    """Nombres declarados o interpolados por el Compose de cada servicio.

    Las credenciales administradas (``APP_DB_*``) no se listan como claves de
    ``environment``: se interpolan dentro de otra variable, por ejemplo
    ``DATABASE_URL``. También son parte del entorno efectivo del servicio y
    deben aparecer en la metadata para poder revelarlas con auditoría.
    """
    result: dict[str, list[str]] = {}
    for service, config in data["services"].items():
        environment = config.get("environment", {}) if isinstance(config, dict) else {}
        names: list[str] = []
        values: list[str] = []
        if isinstance(environment, dict):
            names = [str(name) for name in environment]
            values = [str(value) for value in environment.values()]
        elif isinstance(environment, list):
            for item in environment:
                key, _, value = str(item).partition("=")
                names.append(key)
                values.append(value)
        referenced = {
            name for value in values for name in _ENV_REFERENCE.findall(value)
        }
        result[str(service)] = sorted({name for name in names if name} | referenced)
    return result


def _validate_compose_environment(
    runner: Runner,
    release: Path,
    compose_rel: str,
    project: str,
) -> None:
    configured = runner.run(
        _compose_command(
            release, compose_rel, project, True, "config", "--format", "json"
        ),
        check=False,
    )
    compose_stderr = configured.stderr.replace(r'\"', '"')
    missing = sorted(set(re.findall(
        r'The "([A-Za-z_][A-Za-z0-9_]*)" variable is not set',
        compose_stderr,
    )))
    if missing:
        raise AppDeployError(
            f"missing required Compose environment variables: {', '.join(missing)}"
        )
    if configured.returncode:
        raise AppDeployError("Compose configuration is invalid")


def _containers(
    runner: Runner,
    release: Path,
    compose_rel: str,
    project: str,
    env: bool,
    services: Iterable[str],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for service in services:
        value = runner.run(
            _compose_command(
                release, compose_rel, project, env, "ps", "--all", "-q", service
            )
        ).stdout.strip()
        if not value or "\n" in value:
            raise AppDeployError(
                f"service {service} does not have exactly one container"
            )
        result[service] = value
    return result


def _inject_readonly_files(
    runner: Runner,
    release: Path,
    compose_rel: str,
    containers: dict[str, str],
    services: dict[str, Any],
) -> None:
    """Copy signed files into stopped containers without daemon host binds."""
    private = release.parent.parent / "private" / release.name / "readonly-files"
    prepared = runner.run(["mkdir", "-p", str(private)], check=False)
    if prepared.returncode:
        raise AppDeployError("failed to prepare read-only file injection")
    compose_directory = (release / "source" / compose_rel).parent
    for service in sorted(services):
        config = services[service]
        files = config.get("x-spanel-readonly-files") if isinstance(config, dict) else None
        if files is None:
            continue
        if not isinstance(files, list) or not all(
            readonly_release_file(item, release / "source", compose_rel) for item in files
        ):
            raise AppDeployError("read-only file injection metadata is invalid")
        # `docker cp` never creates missing parent directories. Stage the whole
        # target tree and copy it once, so targets like /healthchecks/x.sh work
        # even when the image has no /healthchecks directory.
        staging = private / "rootfs" / service
        runner.run(["rm", "-rf", "--", str(staging)], check=False)
        try:
            for item in files:
                file_mode = item.get("mode", "0444")
                if file_mode not in {"0444", "0555"}:
                    raise AppDeployError("read-only file injection metadata is invalid")
                destination = staging / Path(item["target"].lstrip("/"))
                parent = runner.run(
                    ["mkdir", "-p", str(destination.parent)], check=False
                )
                if parent.returncode:
                    raise AppDeployError("failed to prepare read-only file injection")
                copied = runner.run(
                    ["cp", "--", str(compose_directory / item["source"]),
                     str(destination)],
                    check=False,
                )
                if copied.returncode:
                    raise AppDeployError("failed to prepare read-only file injection")
                chmod_result = runner.run(
                    ["chmod", file_mode, str(destination)], check=False
                )
                if chmod_result.returncode:
                    raise AppDeployError("failed to prepare read-only file injection")
            injected = runner.run(
                ["docker", "cp", f"{staging}/.", f"{containers[service]}:/"],
                check=False,
            )
            if injected.returncode:
                raise AppDeployError("failed to inject a read-only release file")
        finally:
            runner.run(["rm", "-rf", "--", str(staging)], check=False)


def _verify_containers(
    runner: Runner,
    containers: dict[str, str],
    project: str,
    non_root: bool,
    wait: int,
    one_shot: set[str] | frozenset[str] = frozenset(),
) -> None:
    deadline = time.monotonic() + wait
    last = ""
    completed = set(one_shot)
    while time.monotonic() < deadline:
        ready = True
        for service, container in containers.items():
            if service in completed:
                status = runner.run(
                    [
                        "docker",
                        "container",
                        "inspect",
                        "-f",
                        "{{.State.Status}} {{.State.ExitCode}}",
                        container,
                    ],
                    check=False,
                ).stdout.strip()
                last = f"{service}: {status}"
                state, _, exit_code = status.partition(" ")
                if state == "exited" and exit_code == "0":
                    continue
                if state == "exited":
                    raise AppDeployError(
                        f"one-shot service {service} exited with code "
                        f"{exit_code or 'unknown'}"
                    )
                ready = False
                continue
            status = runner.run(
                [
                    "docker",
                    "container",
                    "inspect",
                    "-f",
                    "{{.State.Status}} {{if .State.Health}}"
                    "{{.State.Health.Status}}{{else}}none{{end}}",
                    container,
                ],
                check=False,
            ).stdout.strip()
            last = f"{service}: {status}"
            if status not in {"running none", "running healthy"}:
                ready = False
        if ready:
            break
        time.sleep(2)
    else:
        raise AppDeployError(
            f"services did not become running/healthy before timeout ({last})"
        )
    for service, container in containers.items():
        owner = runner.run(
            [
                "docker",
                "container",
                "inspect",
                "-f",
                f'{{{{index .Config.Labels "{OWNER_LABEL}"}}}}',
                container,
            ]
        ).stdout.strip()
        if owner != project:
            raise AppDeployError(
                f"container {service} does not have the expected ownership label"
            )
    # Process users inside the cell are namespaced: uid 0 maps to the tenant's
    # own subuid, so the kernel boundary -- not an image-level user check --
    # decides isolation.


def _manifest_data(
    options: DeployOptions,
    result: AuditResult,
    project: str,
    images: dict[str, str],
    status: str,
    host: str,
    release: Path,
    policy: HardeningPolicy | None = None,
) -> dict[str, Any]:
    manifest = {
        "schema": 1,
        "owner_label": OWNER_LABEL,
        "project": project,
        "repo": options.repo,
        "branch": options.branch,
        "commit": _git_commit(result.root),
        "tree_hash": _tree_hash(result.root),
        "compose": result.compose.relative_to(result.root).as_posix(),
        "services": sorted(result.data["services"]),
        "one_shot": sorted(one_shot_services(result.data["services"])),
        "service_environment": _service_environment_names(result.data),
        "tenant_environment_names": sorted(set(options.tenant_environment_names)),
        "service_ports": _service_internal_ports(result.data),
        "images": images,
        "host": host,
        "created_at": datetime.now(UTC).isoformat(),
        "status": status,
        "release": str(release),
        "non_root": options.non_root,
        "has_env": True,
        "external_env_supplied": bool(options.env_file),
    }
    if policy is not None and policy.runtime_users:
        manifest["runtime_users"] = {
            item.service: {
                "requested": item.requested,
                "effective": item.effective,
                "source": item.source,
                **({"volume": item.volume} if item.volume is not None else {}),
            }
            for item in policy.runtime_users
        }
    return manifest


def _write_manifest(runner: Runner, release: Path, manifest: dict[str, Any]) -> None:
    content = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    if runner.transport == "ssh":
        runner.run(
            [
                "sh",
                "-c",
                'umask 077; cat > "$1"',
                "app-deploy",
                str(release / MANIFEST),
            ],
            stdin=content,
        )
    else:
        path = release / MANIFEST
        path.write_bytes(content)
        path.chmod(0o600)


def _publish_release_state(runner: Runner, release: Path, manifest: dict[str, Any]) -> None:
    if release.parent.name != "releases":
        return
    project_root = release.parent.parent
    content = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    targets = [project_root / "manifests" / f"{release.name}.json", project_root / "current.json"]
    if runner.transport == "ssh":
        for target in targets:
            runner.run(
                ["sh", "-c", 'umask 077; mkdir -p "$(dirname "$1")"; cat > "$1"',
                 "app-deploy", str(target)],
                stdin=content,
            )
    else:
        for target in targets:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(content)
            target.chmod(0o600)


def deploy(
    options: DeployOptions, result: AuditResult, runner: Runner
) -> dict[str, Any] | None:
    if result.errors:
        raise AppDeployError("static audit has errors; deployment blocked")
    env_file = (
        validate_env_file(options.env_file, result.root) if options.env_file else None
    )
    if options.dry_run:
        return None
    project = options.project or _project_id(options.repo, result.root)
    if not PROJECT_RE.fullmatch(project):
        raise AppDeployError(
            "project must match lowercase [a-z0-9_-] and be at most 63 characters"
        )
    state_root = _state_root(options.transport, runner.environ)
    release = (
        state_root / project / "releases" / options.release_id
        if options.release_id
        else state_root / project
    )
    if runner.transport == "local" and release.exists():
        raise AppDeployError(
            "project release already exists; use lifecycle commands or a new project"
        )
    if runner.transport == "ssh":
        available = runner.run(["test", "!", "-e", str(release)], check=False)
        if available.returncode == 1:
            raise AppDeployError(
                "remote project release already exists; use lifecycle commands or a new project"
            )
        if available.returncode:
            raise AppDeployError("cannot verify remote project release availability")
    _ensure_owned(runner, project)
    compose_rel = result.compose.relative_to(result.root).as_posix()
    override = _override(
        result.data,
        project,
        options.non_root,
        _env_path(release),
        options.release_id or "latest",
        tenant_id=options.tenant_id,
    )
    _stage_release(runner, result.root, release, compose_rel, override, env_file)
    services = sorted(result.data["services"])
    _validate_compose_environment(runner, release, compose_rel, project)
    pulled = runner.run(
        _compose_command(
            release,
            compose_rel,
            project,
            True,
            "pull",
            "--ignore-buildable",
        ),
        timeout=options.timeout,
        check=False,
    )
    if pulled.returncode:
        raise AppDeployError(f"Compose image pull failed (exit {pulled.returncode})")
    command = _compose_command(release, compose_rel, project, True, "build")
    built = runner.run(command, timeout=options.timeout, check=False)
    if built.returncode:
        raise AppDeployError(f"Compose image build failed (exit {built.returncode})")
    images: dict[str, str] = {}
    if options.non_root:
        images = _image_users(runner, release, compose_rel, project, True, services)
    else:
        for service in services:
            image = runner.run(
                _compose_command(
                    release,
                    compose_rel,
                    project,
                    True,
                    "images",
                    "-q",
                    service,
                )
            ).stdout.strip()
            if image:
                images[service] = image
    host = "local" if runner.transport == "local" else runner.host
    manifest = _manifest_data(options, result, project, images, "building", host, release)
    _write_manifest(runner, release, manifest)
    create_attempted = False
    up_started = False
    try:
        create_attempted = True
        created = runner.run(
            _compose_command(release, compose_rel, project, True, "create"),
            timeout=options.timeout,
            check=False,
        )
        if created.returncode:
            raise AppDeployError(
                f"Compose services failed to create (exit {created.returncode})"
            )
        containers = _containers(runner, release, compose_rel, project, True, services)
        _inject_readonly_files(runner, release, compose_rel, containers, result.data["services"])
        started = runner.run(
            _compose_command(
                release, compose_rel, project, True, "up", "-d", "--no-recreate"
            ),
            timeout=options.timeout,
            check=False,
        )
        up_started = True
        if started.returncode:
            raise AppDeployError(
                f"Compose services failed to start (exit {started.returncode})"
            )
        _verify_containers(
            runner, containers, project, options.non_root, options.wait,
            one_shot=one_shot_services(result.data["services"]),
        )
        manifest["status"] = "running"
        manifest["containers"] = containers
        manifest["container_names"] = _container_names(runner, containers)
        manifest["service_runtime"] = runtime_snapshot(runner, containers)
        _write_manifest(runner, release, manifest)
        if options.publish_state:
            _publish_release_state(runner, release, manifest)
        return manifest
    except AppDeployError:
        manifest["status"] = "failed"
        if up_started:
            logs = runner.run(
                _compose_command(
                    release,
                    compose_rel,
                    project,
                    True,
                    "logs",
                    "--no-color",
                    "--tail",
                    "200",
                ),
                check=False,
            )
            # Logs can contain secrets. Record only an integrity digest and size.
            diagnostic = (logs.stdout + logs.stderr).encode()
            manifest["diagnostics"] = {
                "sha256": hashlib.sha256(diagnostic).hexdigest(),
                "bytes": len(diagnostic),
            }
        if create_attempted:
            runner.run(
                _compose_command(
                    release, compose_rel, project, True, "down", "--remove-orphans"
                ),
                check=False,
            )
        _write_manifest(runner, release, manifest)
        raise
