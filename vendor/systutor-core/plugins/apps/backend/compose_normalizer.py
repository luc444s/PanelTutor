"""Deterministic compatibility normalization for staged Compose files."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

_DNS_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\Z")
_SAFE_SYSCTL = "net.ipv4.ip_unprivileged_port_start"
_SENSITIVE_TARGETS = ("/", "/proc", "/sys", "/dev", "/var/run")
_ALIAS_MARKER = "x-spanel-normalized-aliases"
_READONLY_FILES_MARKER = "x-spanel-readonly-files"


class ComposeNormalizationError(ValueError):
    """Compose cannot be normalized safely."""


@dataclass(frozen=True, slots=True)
class NormalizationResult:
    text: str
    evidence: dict[str, Any]


def _warning(code: str, service: str, message: str) -> dict[str, str]:
    return {"code": code, "service": service, "message": message}


def _port(value: object) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if 1 <= value <= 65535 else None
    if isinstance(value, dict):
        target = value.get("target")
        protocol = str(value.get("protocol", "tcp")).lower()
        if isinstance(target, int) and 1 <= target <= 65535:
            return f"{target}/{protocol}" if protocol != "tcp" else str(target)
        return None
    text = str(value).strip()
    protocol = ""
    if "/" in text:
        text, protocol = text.rsplit("/", 1)
        protocol = "/" + protocol.lower()
    target = text.rsplit(":", 1)[-1]
    return f"{target}{protocol}" if target.isdigit() and 1 <= int(target) <= 65535 else None


def _low_port(value: object) -> bool:
    port = _port(value)
    return port is not None and int(port.split("/", 1)[0]) < 1024


def _target_is_safe(target: str) -> bool:
    if not target.startswith("/") or ".." in PurePosixPath(target).parts:
        return False
    return not any(target == item or target.startswith(item + "/") for item in _SENSITIVE_TARGETS)


def _volume_parts(value: object) -> tuple[str, str, bool] | None:
    if isinstance(value, str):
        parts = value.split(":")
        if len(parts) not in {2, 3}:
            return None
        if not (
            parts[0].startswith((".", "/", "~"))
            or "/" in parts[0]
            or "\\" in parts[0]
        ):
            return None
        return parts[0], parts[1], len(parts) == 3 and parts[2].lower() == "ro"
    if isinstance(value, dict) and value.get("type") == "bind":
        source = value.get("source")
        target = value.get("target")
        read_only = value.get("read_only") is True
        if isinstance(source, str) and isinstance(target, str):
            return source, target, read_only
    return None


def _compose_directory(checkout_root: Path, compose_file: str | Path | None) -> Path:
    root = checkout_root.resolve(strict=True)
    if compose_file is None:
        return root
    relative = Path(compose_file)
    if relative.is_absolute() or ".." in relative.parts or "\\" in str(compose_file):
        raise ComposeNormalizationError(
            "normalize_invalid_compose_path: Compose path must stay inside checkout"
        )
    try:
        directory = (root / relative).parent.resolve(strict=True)
        directory.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ComposeNormalizationError(
            "normalize_invalid_compose_path: Compose path must stay inside checkout"
        ) from exc
    return directory


def _safe_file(source: str, checkout_root: Path, compose_directory: Path) -> str | None:
    if not source or Path(source).is_absolute() or "\\" in source:
        return None
    candidate = compose_directory / source
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(checkout_root.resolve(strict=True))
    except (OSError, ValueError):
        return None
    if not resolved.is_file() or candidate.name == "docker.sock" or resolved.name == "docker.sock":
        return None
    return Path(os.path.relpath(resolved, compose_directory)).as_posix()


def _readonly_file(source: str, target: str) -> dict[str, str]:
    return {"source": source, "target": str(PurePosixPath(target))}


def normalize_compose(
    text: str,
    checkout_root: Path,
    compose_file: str | Path | None = None,
) -> NormalizationResult:
    """Normalize a Compose document without writing to its checkout."""
    source_hash = hashlib.sha256(text.encode()).hexdigest()
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ComposeNormalizationError("normalize_invalid_yaml: Compose is invalid YAML") from exc
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict):
        raise ComposeNormalizationError("normalize_invalid_compose: services must be a mapping")
    root = Path(checkout_root)
    compose_directory = _compose_directory(root, compose_file)
    services = data["services"]
    names = {str(name) for name in services}
    aliases: dict[str, str] = {}
    counts: dict[str, int] = {}
    for name, raw in services.items():
        if isinstance(raw, dict):
            alias = raw.get("container_name")
            if isinstance(alias, str):
                counts[alias] = counts.get(alias, 0) + 1
            marked = raw.get(_ALIAS_MARKER)
            if isinstance(marked, list) and len(marked) == 1 and isinstance(marked[0], str):
                aliases[str(name)] = marked[0]

    warnings: list[dict[str, str]] = []
    applied: dict[str, set[str]] = {key: set() for key in ("N1", "N2", "N3", "N4")}
    details: dict[str, dict[str, Any]] = {key: {} for key in applied}
    for raw_name in sorted(services, key=str):
        name = str(raw_name)
        config = services[raw_name]
        if not isinstance(config, dict):
            raise ComposeNormalizationError(f"normalize_invalid_service: {name} is not a mapping")

        alias = config.pop("container_name", None)
        if isinstance(alias, str):
            reserved = alias.lower() == "spanel" or alias.lower().startswith("spanel-")
            valid = (
                _DNS_LABEL.fullmatch(alias) is not None
                and counts.get(alias) == 1
                and alias not in names
                and not reserved
            )
            if valid:
                aliases[name] = alias
            else:
                aliases.pop(name, None)
                warnings.append(_warning(
                    "normalize_alias_discarded",
                    name,
                    "container alias is invalid, duplicate, reserved, or collides with a service",
                ))
        if name in aliases:
            value = aliases[name]
            config[_ALIAS_MARKER] = [value]
            config["networks"] = {"default": {"aliases": [value]}}
            applied["N1"].add(name)
            details["N1"][name] = {"alias": value}

        injections: list[dict[str, str]] = []
        marked_files = config.pop(_READONLY_FILES_MARKER, None)
        for item in marked_files if isinstance(marked_files, list) else []:
            if not isinstance(item, dict):
                continue
            source, target = item.get("source"), item.get("target")
            path = (
                _safe_file(source, root, compose_directory)
                if isinstance(source, str)
                and isinstance(target, str)
                and _target_is_safe(target)
                else None
            )
            if path is not None:
                injections.append(_readonly_file(path, target))

        kept: list[object] = []
        for volume in config.get("volumes") or []:
            parts = _volume_parts(volume)
            if parts is None:
                kept.append(volume)
                continue
            source, target, read_only = parts
            canonical_source = (
                _safe_file(source, root, compose_directory)
                if source.startswith("./") and read_only and _target_is_safe(target)
                else None
            )
            if canonical_source is None:
                warnings.append(_warning(
                    "normalize_bind_discarded",
                    name,
                    "host bind is not a read-only regular checkout file",
                ))
                continue
            injections.append(_readonly_file(canonical_source, target))
            applied["N2"].add(name)
        if kept:
            config["volumes"] = kept
        else:
            config.pop("volumes", None)
        if injections:
            unique = {(item["source"], item["target"]): item for item in injections}
            config[_READONLY_FILES_MARKER] = [unique[key] for key in sorted(unique)]
            applied["N2"].add(name)
            details["N2"][name] = {"files": config[_READONLY_FILES_MARKER]}

        published = config.pop("ports", []) or []
        exposed = {_port(value) for value in (config.get("expose") or [])}
        exposed.update(_port(value) for value in published)
        exposed.discard(None)
        if exposed:
            config["expose"] = sorted(
                exposed,
                key=lambda value: (int(value.split("/", 1)[0]), value),
            )
        else:
            config.pop("expose", None)
        if published:
            applied["N4"].add(name)
            details["N4"][name] = {"expose": list(config.get("expose") or [])}

        had_sysctls = bool(config.pop("sysctls", None))
        if any(_low_port(value) for value in config.get("expose") or []):
            config["sysctls"] = {_SAFE_SYSCTL: "0"}
            applied["N3"].add(name)
            details["N3"][name] = {"sysctl": _SAFE_SYSCTL}
        elif had_sysctls:
            warnings.append(_warning(
                "normalize_sysctl_discarded",
                name,
                "application sysctls are not permitted",
            ))

    normalized = yaml.safe_dump(data, sort_keys=True, default_flow_style=False)
    rules = [
        {
            "id": rule,
            "applied": bool(applied[rule]),
            "services": sorted(applied[rule]),
            "details": details[rule],
        }
        for rule in ("N1", "N2", "N3", "N4")
    ]
    evidence = {
        "schema": 1,
        "source_sha256": source_hash,
        "normalized_sha256": hashlib.sha256(normalized.encode()).hexdigest(),
        "rules": rules,
        "warnings": warnings,
        "rejected": [],
    }
    return NormalizationResult(normalized, evidence)
