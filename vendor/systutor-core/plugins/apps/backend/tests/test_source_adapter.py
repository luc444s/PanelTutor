"""Source-only deployment overlays are conservative and deterministic."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from plugins.apps.backend.runtime import AppDeployError
from plugins.apps.backend.runtime.source_adapter import (
    GENERATED_COMPOSE,
    materialize_source_adapter,
)


def node_red(root: Path, *, engine: str = ">=22.9") -> None:
    root.joinpath("package.json").write_text(json.dumps({
        "name": "node-red",
        "scripts": {"build": "node scripts/build", "start": "node red.js"},
        "engines": {"node": engine},
    }))
    root.joinpath("package-lock.json").write_text("{}")


def test_materializes_node_red_overlay_without_touching_source_metadata(
    tmp_path: Path,
) -> None:
    node_red(tmp_path)

    result = materialize_source_adapter(tmp_path, None)

    assert result.compose_file == GENERATED_COMPOSE
    assert result.kind == "node-red-source"
    assert result.generated == (
        ".dockerignore",
        ".spanel-generated/Dockerfile",
        ".spanel-compose.yaml",
    )
    dockerfile = tmp_path.joinpath(".spanel-generated/Dockerfile").read_text()
    compose = tmp_path.joinpath(GENERATED_COMPOSE).read_text()
    assert "FROM node:24-bookworm" in dockerfile
    assert "USER 1000:1000" in dockerfile
    assert 'CMD ["npm", "start"]' in dockerfile
    assert "context: ." in compose
    assert "node-red-data:/data" in compose


def test_existing_compose_wins_over_source_adapter(tmp_path: Path) -> None:
    node_red(tmp_path)
    tmp_path.joinpath("compose.yaml").write_text("services: {web: {}}")

    result = materialize_source_adapter(tmp_path, None)

    assert result.kind is None
    assert not tmp_path.joinpath(".spanel-generated").exists()


def test_explicit_missing_compose_is_not_silently_replaced(tmp_path: Path) -> None:
    node_red(tmp_path)

    result = materialize_source_adapter(tmp_path, "missing.yml")

    assert result.compose_file == "missing.yml"
    assert result.kind is None


@pytest.mark.parametrize("mutation", ["wrong-name", "new-node", "collision"])
def test_unsupported_or_ambiguous_source_fails_closed(
    tmp_path: Path, mutation: str
) -> None:
    node_red(tmp_path, engine=">=25" if mutation == "new-node" else ">=22.9")
    if mutation == "wrong-name":
        package = json.loads(tmp_path.joinpath("package.json").read_text())
        package["name"] = "another-app"
        tmp_path.joinpath("package.json").write_text(json.dumps(package))
    if mutation == "collision":
        tmp_path.joinpath(".spanel-generated").mkdir()

    with pytest.raises(AppDeployError):
        materialize_source_adapter(tmp_path, None)
