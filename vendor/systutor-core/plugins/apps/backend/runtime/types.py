"""Shared runtime types and constants."""
from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

OWNER_LABEL = "io.spanel.app.owner"
MANIFEST = "manifest.json"
COMPOSE_NAMES = {
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
}
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
SAFE_REMOTE_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
SECRET_NAME_RE = re.compile(
    r"(?:secret|password|passwd|token|api[_-]?key|private[_-]?key|credential)",
    re.IGNORECASE,
)
ROOT_USERS = {"", "0", "root", "0:0", "root:root"}
MOUNT_BLOCKED = ("/", "/proc", "/sys", "/dev", "/var/run")


class AppDeployError(RuntimeError):
    """Expected, safely printable failure."""


@dataclass(frozen=True, order=True)
class Finding:
    severity: str
    code: str
    service: str | None
    path: str
    line: int
    message: str
    remediation: str


@dataclass
class AuditResult:
    root: Path
    compose: Path
    data: dict[str, Any]
    dockerfiles: dict[str, Path]
    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)

    @property
    def errors(self) -> list[Finding]:
        return [item for item in self.findings if item.severity == "error"]


@dataclass
class Completed:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def volume_is_host_bind(volume: object) -> bool:
    """Whether a Compose volume entry mounts a host path.

    A string without a colon is an anonymous *container* volume (for example
    ``/app/node_modules``) and must not be mistaken for a host bind.
    """
    if isinstance(volume, dict):
        if volume.get("type") == "bind":
            return True
        source = volume.get("source")
        return isinstance(source, str) and source.startswith((".", "/", "~"))
    if isinstance(volume, str):
        parts = volume.split(":")
        if len(parts) < 2:
            return False
        source = parts[0]
        return (
            source.startswith((".", "/", "~"))
            or "/" in source
            or "\\" in source
        )
    return False


def readonly_release_file_bind(
    volume: object,
    release_root: Path,
    compose_file: str | Path | None = None,
) -> bool:
    """Whether a Compose bind is the narrowly allowed release-local file mount."""
    if isinstance(volume, dict) and volume.get("type") == "bind":
        source, target = volume.get("source"), volume.get("target")
        read_only = volume.get("read_only") is True
    elif isinstance(volume, str):
        parts = volume.split(":")
        if len(parts) != 3:
            return False
        source, target, mode = parts
        read_only = mode.lower() == "ro"
    else:
        return False
    if (
        not read_only
        or not isinstance(source, str)
        or not source.startswith("./")
        or not isinstance(target, str)
        or not target.startswith("/")
        or any(
            target == item or target.startswith(item + "/")
            for item in MOUNT_BLOCKED
        )
    ):
        return False
    try:
        root = release_root.resolve(strict=True)
        relative = Path(compose_file) if compose_file is not None else None
        if relative is not None and (
            relative.is_absolute()
            or ".." in relative.parts
            or "\\" in str(compose_file)
        ):
            return False
        compose_directory = (
            (root / relative).parent.resolve(strict=True)
            if relative is not None
            else root
        )
        compose_directory.relative_to(root)
        path = compose_directory / source[2:]
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return False
    return (
        resolved.is_file()
        and path.name != "docker.sock"
        and resolved.name != "docker.sock"
    )


def readonly_release_file(
    item: object,
    release_root: Path,
    compose_file: str | Path,
) -> bool:
    """Validate one canonical signed pre-start file injection."""
    if not isinstance(item, Mapping) or set(item) not in (
        {"source", "target"}, {"source", "target", "mode"}
    ):
        return False
    if "mode" in item and item["mode"] not in {"0444", "0555"}:
        return False
    source, target = item.get("source"), item.get("target")
    if (
        not isinstance(source, str)
        or not source
        or "\\" in source
        or Path(source).is_absolute()
        or not isinstance(target, str)
        or not target.startswith("/")
        or str(PurePosixPath(target)) != target
        or ".." in PurePosixPath(target).parts
        or any(target == path or target.startswith(path + "/") for path in MOUNT_BLOCKED)
    ):
        return False
    try:
        root = release_root.resolve(strict=True)
        compose = Path(compose_file)
        if compose.is_absolute() or ".." in compose.parts or "\\" in str(compose_file):
            return False
        compose_directory = (root / compose).parent.resolve(strict=True)
        compose_directory.relative_to(root)
        candidate = compose_directory / source
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        canonical = Path(os.path.relpath(resolved, compose_directory)).as_posix()
    except (OSError, ValueError):
        return False
    return (
        source == canonical
        and resolved.is_file()
        and candidate.name != "docker.sock"
        and resolved.name != "docker.sock"
    )


def one_shot_services(services: object) -> set[str]:
    """Services that complete an initialization task and then exit.

    A service is one-shot when it explicitly opts in with
    ``x-spanel-one-shot: true`` or when another service waits for it with
    ``depends_on: {condition: service_completed_successfully}``.
    """
    if not isinstance(services, Mapping):
        return set()
    result: set[str] = set()
    for name, config in services.items():
        if not isinstance(name, str) or not isinstance(config, Mapping):
            continue
        if config.get("x-spanel-one-shot") is True:
            result.add(name)
        depends = config.get("depends_on")
        if isinstance(depends, Mapping):
            for dependency, spec in depends.items():
                if (
                    isinstance(spec, Mapping)
                    and spec.get("condition") == "service_completed_successfully"
                ):
                    result.add(str(dependency))
    return result


@dataclass(frozen=True)
class DeployOptions:
    repo: str | None = None
    branch: str = "main"
    env_file: Path | None = None
    dry_run: bool = False
    project: str | None = None
    transport: str = "local"
    non_root: bool = False
    timeout: int = 1800
    wait: int = 180
    release_id: str | None = None
    publish_state: bool = True
    # Nombres suministrados por el tenant, nunca sus valores. Se persisten en
    # el manifiesto para clasificar la metadata del modal sin adivinar.
    tenant_environment_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class LifecycleOptions:
    command: str
    project: str
    transport: str = "local"
    tail: int = 200
    purge_data: bool = False
    confirm_purge: str | None = None
    release: Path | None = None
    service: str | None = None


@dataclass(frozen=True)
class LifecycleResult:
    returncode: int
    output: str = ""
