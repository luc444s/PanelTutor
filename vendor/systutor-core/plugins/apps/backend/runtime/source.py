"""Checkout validation and Compose source discovery."""
from __future__ import annotations

import re
import stat
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, SequenceNode

from .transport import Runner
from .types import COMPOSE_NAMES, AppDeployError

_USER_INSTRUCTION = re.compile(r"^\s*USER\s+(\S+)\s*$", re.IGNORECASE)
_FROM_INSTRUCTION = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.IGNORECASE
)


def dockerfile_runtime_user(path: Path) -> str | None:
    """Return the final ``USER`` instruction declared by a Dockerfile."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    value: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _USER_INSTRUCTION.match(line)
        if match:
            value = match.group(1).strip("\"'")
    return value


def dockerfile_base_images(path: Path) -> tuple[str, ...]:
    """Return external image references declared by Dockerfile FROM lines."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ()
    images: list[str] = []
    stages: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _FROM_INSTRUCTION.match(line)
        if match is None:
            continue
        image = match.group(1).strip("\"'")
        if image.lower() not in stages:
            images.append(image)
        parts = line.split()
        for index, value in enumerate(parts[:-1]):
            if value.lower() == "as":
                stages.add(parts[index + 1].lower())
                break
    return tuple(images)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _resolve_inside(path: Path, root: Path, what: str, *, strict: bool = True) -> Path:
    try:
        resolved = path.resolve(strict=strict)
    except (OSError, RuntimeError) as exc:
        raise AppDeployError(f"{what} does not exist or cannot be resolved") from exc
    if not _inside(resolved, root):
        raise AppDeployError(f"{what} escapes the checkout")
    return resolved


def _broken_symlink_warning(relative: Path) -> str:
    return (
        f"Broken symlink in {relative.as_posix()}. "
        "Not used by deployment. Continuing."
    )


def validate_checkout(root: Path, warnings: list[str] | None = None) -> Path:
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise AppDeployError("source directory is not a directory")
    for path in root.rglob("*"):
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise AppDeployError("checkout contains an unreadable path") from exc
        if stat.S_ISLNK(mode):
            relative = path.relative_to(root)
            try:
                _resolve_inside(path, root, f"symlink {relative}")
            except AppDeployError:
                # A broken symlink is harmless while its target stays inside the
                # checkout: Docker copies the link itself and only fails if a
                # build step dereferences it. Symlinks whose target escapes the
                # checkout (or loop) are rejected again by the non-strict check.
                resolved = _resolve_inside(
                    path, root, f"symlink {relative}", strict=False
                )
                if resolved == path:
                    raise AppDeployError(
                        f"symlink {relative} does not exist or cannot be resolved"
                    ) from None
                if warnings is not None:
                    warnings.append(_broken_symlink_warning(relative))
        elif not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise AppDeployError(
                f"checkout contains special file: {path.relative_to(root)}"
            )
    return root


def clone_repo(
    repo: str, branch: str, destination: Path, runner: Runner | None = None
) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise AppDeployError("repository must be a GitHub owner/name identifier")
    if not branch or branch.startswith("-") or any(ch in branch for ch in "\x00\r\n"):
        raise AppDeployError("invalid branch")
    local = runner or Runner("local")
    local.run(
        [
            "gh",
            "repo",
            "clone",
            repo,
            str(destination),
            "--",
            "--branch",
            branch,
            "--single-branch",
        ],
        timeout=600,
    )


def compose_candidates(root: Path) -> list[Path]:
    root = root.resolve(strict=True)
    return sorted(
        path
        for path in root.iterdir()
        if path.is_file()
        and (
            path.name in COMPOSE_NAMES
            or re.fullmatch(r"docker-compose\..+\.ya?ml", path.name)
        )
    )


def discover_compose(root: Path, selected: str | None = None) -> Path:
    root = root.resolve(strict=True)
    if selected:
        candidate = _resolve_inside(root / selected, root, "Compose file")
        if not candidate.is_file():
            raise AppDeployError("Compose selection is not a regular file")
        return candidate
    candidates = compose_candidates(root)
    if not candidates:
        raise AppDeployError("no Compose file found")
    if len(candidates) > 1:
        names = ", ".join(path.name for path in candidates)
        raise AppDeployError(
            f"multiple Compose files found; use --compose-file: {names}"
        )
    return candidates[0]


def _node_lines(node: Node, prefix: tuple[str, ...] = ()) -> dict[tuple[str, ...], int]:
    result: dict[tuple[str, ...], int] = {}
    if isinstance(node, MappingNode):
        for key_node, value_node in node.value:
            key = str(getattr(key_node, "value", ""))
            current = (*prefix, key)
            result[current] = key_node.start_mark.line + 1
            result.update(_node_lines(value_node, current))
    elif isinstance(node, SequenceNode):
        for index, value_node in enumerate(node.value):
            current = (*prefix, str(index))
            result[current] = value_node.start_mark.line + 1
            result.update(_node_lines(value_node, current))
    return result


def _load_compose(path: Path) -> tuple[dict[str, Any], dict[tuple[str, ...], int]]:
    try:
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        node = yaml.compose(text, Loader=yaml.SafeLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise AppDeployError("Compose file is unreadable or invalid YAML") from exc
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("services"), dict)
        or not data["services"]
    ):
        raise AppDeployError("Compose must contain a non-empty services mapping")
    return data, _node_lines(node) if node else {}


def _line(lines: dict[tuple[str, ...], int], *parts: str) -> int:
    probe = tuple(parts)
    while probe:
        if probe in lines:
            return lines[probe]
        probe = probe[:-1]
    return 1
