"""Deterministic, non-secret service fingerprints for signed releases.

The global release remains the compatibility boundary.  Fingerprints only let
the planner prove which services must be reconciled, so they deliberately cover
build inputs, Compose configuration and referenced environment *names* — never
environment values or secrets.
"""

from __future__ import annotations

import fnmatch
import hashlib
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ..runtime.types import SECRET_NAME_RE, AppDeployError, AuditResult
from ..symlinks import symlink_target
from .trusted import canonical_json

MAX_FINGERPRINT_SERVICES = 256
MAX_IGNORE_PATTERNS = 1024
IGNORED_PARTS = {".git", ".spanel-build-backups"}


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _clean_relative(value: str) -> str:
    text = value.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.rstrip("/")


def _dockerignore_patterns(context: Path) -> list[tuple[str, bool]]:
    path = context / ".dockerignore"
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return []
    patterns: list[tuple[str, bool]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        if negated:
            line = line[1:].strip()
        line = _clean_relative(line)
        if not line:
            continue
        patterns.append((line, negated))
        if len(patterns) > MAX_IGNORE_PATTERNS:
            break
    return patterns


def _matches(relative: str, pattern: str) -> bool:
    if fnmatch.fnmatchcase(relative, pattern):
        return True
    if "/" not in pattern:
        return any(fnmatch.fnmatchcase(part, pattern) for part in relative.split("/"))
    if relative.startswith(pattern.rstrip("/") + "/"):
        return True
    return False


def _ignored(relative: str, patterns: Iterable[tuple[str, bool]]) -> bool:
    ignored = False
    for pattern, negated in patterns:
        if _matches(relative, pattern):
            ignored = not negated
    return ignored


def build_context_digest(context: Path, dockerfile: Path) -> str:
    """Hash every input Docker would send for this build context.

    ``.dockerignore`` is honoured so generated/dependency directories do not
    pollute the digest.  The Dockerfile and the ignore file are always covered
    explicitly, as Docker sends both regardless of ignore rules.
    """

    context = Path(context)
    digest = hashlib.sha256()
    patterns = _dockerignore_patterns(context)
    try:
        relative_dockerfile = dockerfile.resolve().relative_to(context.resolve())
    except (OSError, ValueError):
        relative_dockerfile = None
    for path in sorted(context.rglob("*"), key=lambda item: item.relative_to(context).as_posix()):
        relative = path.relative_to(context)
        if any(part in IGNORED_PARTS for part in relative.parts):
            continue
        name = relative.as_posix()
        is_dockerfile = (
            relative_dockerfile is not None and Path(name) == relative_dockerfile
        )
        if not is_dockerfile and name != ".dockerignore" and _ignored(name, patterns):
            continue
        digest.update(name.encode())
        digest.update(b"\0")
        try:
            if path.is_symlink():
                digest.update(b"L" + symlink_target(path).encode())
            elif path.is_file():
                digest.update(b"F")
                with path.open("rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
            elif path.is_dir():
                digest.update(b"D")
        except OSError as exc:
            raise AppDeployError("build context is unreadable") from exc
    return digest.hexdigest()


def _environment_names(value: object) -> list[str]:
    names: list[str] = []
    if isinstance(value, dict):
        names = [str(name) for name in value]
    elif isinstance(value, list):
        for item in value:
            names.append(str(item).partition("=")[0])
    return sorted({name for name in names if name})


def _sanitized_build(value: object) -> Any:
    if isinstance(value, str):
        return {"context": value, "dockerfile": "Dockerfile"}
    if not isinstance(value, dict):
        return value
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key == "args" and isinstance(item, dict):
            args: dict[str, Any] = {}
            for name, argument in item.items():
                text = "" if argument is None else str(argument)
                if SECRET_NAME_RE.search(str(name)) and not text.startswith("${"):
                    args[str(name)] = "[SECRET_REFERENCE]"
                else:
                    args[str(name)] = text
            result[str(key)] = dict(sorted(args.items()))
        else:
            result[str(key)] = item
    return result


def sanitize_service_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Remove runtime values while preserving every deployment input."""

    result: dict[str, Any] = {}
    for key, value in config.items():
        if key == "environment":
            result["environment_names"] = _environment_names(value)
        elif key == "build":
            result["build"] = _sanitized_build(value)
        elif key == "labels" and isinstance(value, dict):
            result["labels"] = {
                str(name): str(item) for name, item in sorted(value.items())
            }
        else:
            result[str(key)] = value
    return result


def _build_service_fingerprint(
    checkout: Path, audit: AuditResult, service: str, config: Mapping[str, Any]
) -> tuple[str, str | None]:
    build = config.get("build")
    context_digest: str | None = None
    dockerfile_digest: str | None = None
    image_reference: str | None = None
    if build is not None:
        if isinstance(build, str):
            context_text, dockerfile_text = build, "Dockerfile"
        elif isinstance(build, dict):
            context_text = str(build.get("context", "."))
            dockerfile_text = str(build.get("dockerfile", "Dockerfile"))
        else:
            context_text, dockerfile_text = ".", "Dockerfile"
        context = (audit.compose.parent / context_text).resolve()
        dockerfile = (context / dockerfile_text).resolve()
        if checkout.resolve() not in dockerfile.parents and dockerfile != checkout.resolve():
            raise AppDeployError("build context escapes the release")
        context_digest = build_context_digest(context, dockerfile)
        dockerfile_digest = _hash_file(dockerfile)
    image = config.get("image")
    if isinstance(image, str) and image.strip():
        image_reference = image.strip()
    payload = {
        "service": service,
        "compose": sanitize_service_config(config),
        "context_sha256": context_digest,
        "dockerfile_sha256": dockerfile_digest,
        "image": image_reference,
    }
    return _sha256(canonical_json(payload)), context_digest


def compute_fingerprints(
    checkout: Path, audit: AuditResult
) -> dict[str, Any]:
    """Return the signed ``service_fingerprints`` map and shared digest."""

    checkout = Path(checkout)
    services: dict[str, str] = {}
    for service, config in sorted(audit.data["services"].items()):
        if not isinstance(config, dict):
            raise AppDeployError("Compose service configuration is invalid")
        services[str(service)] = _build_service_fingerprint(
            checkout, audit, str(service), config
        )[0]
    if len(services) > MAX_FINGERPRINT_SERVICES:
        raise AppDeployError("release contains too many services")
    shared_payload = {
        key: value
        for key, value in audit.data.items()
        if key not in {"services", "version", "name"}
    }
    shared = _sha256(canonical_json({"compose": shared_payload}))
    return {
        "service_fingerprints": dict(sorted(services.items())),
        "shared_fingerprint": shared,
    }
