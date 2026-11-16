"""Deterministic deployment overlays for supported source-only projects."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .source import compose_candidates, validate_checkout
from .types import AppDeployError

GENERATED_DIR = ".spanel-generated"
GENERATED_COMPOSE = ".spanel-compose.yaml"
_MAX_PACKAGE_JSON = 1024 * 1024
_NODE_RED_PORT = 1880


@dataclass(frozen=True, slots=True)
class SourceAdaptation:
    """Files materialized by the platform before audit and signing."""

    compose_file: str | None
    kind: str | None = None
    generated: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any] | None:
        if self.kind is None:
            return None
        return {
            "kind": self.kind,
            "compose": self.compose_file,
            "generated": list(self.generated),
        }


def _package(root: Path) -> dict[str, Any]:
    package_path = root / "package.json"
    lock_path = root / "package-lock.json"
    try:
        if not package_path.is_file() or package_path.stat().st_size > _MAX_PACKAGE_JSON:
            raise AppDeployError("source-only project has no supported deployment adapter")
        if not lock_path.is_file():
            raise AppDeployError("Node source adapter requires package-lock.json")
        value = json.loads(package_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AppDeployError("Node source adapter package metadata is invalid") from exc
    if not isinstance(value, dict):
        raise AppDeployError("Node source adapter package metadata is invalid")
    return value


def _node_red_metadata(package: dict[str, Any]) -> None:
    if package.get("name") != "node-red":
        raise AppDeployError("source-only project has no supported deployment adapter")
    scripts = package.get("scripts")
    engines = package.get("engines")
    if (
        not isinstance(scripts, dict)
        or not isinstance(scripts.get("build"), str)
        or not scripts["build"].strip()
        or not isinstance(scripts.get("start"), str)
        or not scripts["start"].strip()
        or not isinstance(engines, dict)
    ):
        raise AppDeployError("Node-RED source adapter requires build and start scripts")
    requirement = engines.get("node")
    match = re.fullmatch(r">=\s*(\d+)(?:\.\d+){0,2}", str(requirement or "").strip())
    if match is None or int(match.group(1)) > 24:
        raise AppDeployError("Node-RED source adapter requires an unsupported Node version")


def _write_overlay(root: Path) -> SourceAdaptation:
    generated = root / GENERATED_DIR
    compose = root / GENERATED_COMPOSE
    dockerignore = root / ".dockerignore"
    if generated.exists() or compose.exists():
        raise AppDeployError("reserved source adapter path already exists")
    if dockerignore.exists():
        raise AppDeployError("Node-RED source adapter will not replace .dockerignore")
    generated.mkdir(mode=0o755)
    dockerfile = generated / "Dockerfile"
    dockerfile.write_text(
        "FROM node:24-bookworm\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "RUN npm ci && npm run build && npm cache clean --force\n"
        "RUN install -d -o 1000 -g 1000 -m 0775 /data\n"
        "ENV HOME=/data NODE_ENV=production\n"
        "USER 1000:1000\n"
        f"EXPOSE {_NODE_RED_PORT}\n"
        'CMD ["npm", "start"]\n',
        encoding="utf-8",
    )
    compose.write_text(
        "services:\n"
        "  node-red:\n"
        "    build:\n"
        "      context: .\n"
        f"      dockerfile: {GENERATED_DIR}/Dockerfile\n"
        f'    expose: ["{_NODE_RED_PORT}"]\n'
        "    volumes:\n"
        "      - node-red-data:/data\n"
        "volumes:\n"
        "  node-red-data: {}\n",
        encoding="utf-8",
    )
    dockerignore.write_text(
        ".git\nnode_modules\n.spanel-build-backups\n",
        encoding="utf-8",
    )
    files = (
        ".dockerignore",
        f"{GENERATED_DIR}/Dockerfile",
        GENERATED_COMPOSE,
    )
    return SourceAdaptation(GENERATED_COMPOSE, "node-red-source", files)


def materialize_source_adapter(
    root: Path, selected_compose: str | None
) -> SourceAdaptation:
    """Create a signed overlay only when no repository Compose was selected."""

    root = validate_checkout(root)
    if selected_compose and selected_compose != GENERATED_COMPOSE:
        return SourceAdaptation(selected_compose)
    if selected_compose is None and compose_candidates(root):
        return SourceAdaptation(None)
    package = _package(root)
    _node_red_metadata(package)
    return _write_overlay(root)
