from __future__ import annotations

import pytest
from pydantic import ValidationError

from plugins.apps.backend.compose_selection import (
    candidates_from_tree,
    is_compose_path,
)
from plugins.apps.backend.schemas import ComposeUpdate


def test_candidates_from_tree_keeps_nested_compose_files_sorted() -> None:
    entries = [
        {"type": "blob", "path": "compose.yml"},
        {"type": "blob", "path": "compose.yaml"},
        {"type": "blob", "path": "docker_example/docker-compose.yml"},
        {"type": "blob", "path": "deploy/docker-compose.yml"},
        {"type": "blob", "path": "docker/dev.docker-compose.yml"},
        {"type": "blob", "path": "node_modules/pkg/docker-compose.yml"},
        {"type": "blob", "path": "README.md"},
        {"type": "tree", "path": "compose.tree.yaml"},
    ]

    assert candidates_from_tree(entries) == [
        "compose.yaml",
        "compose.yml",
        "deploy/docker-compose.yml",
        "docker/dev.docker-compose.yml",
        "docker_example/docker-compose.yml",
    ]


@pytest.mark.parametrize(
    "path",
    [
        "../compose.yml",
        "/etc/compose.yml",
        "a/../compose.yml",
        "a//compose.yml",
        ".git/compose.yml",
        "node_modules/pkg/compose.yaml",
        "compose.txt",
        "README.md",
        "",
    ],
)
def test_is_compose_path_rejects_unsafe_or_unrelated_files(path: str) -> None:
    assert is_compose_path(path) is False


@pytest.mark.parametrize(
    "path",
    ["compose.yml", "compose.yaml", "docker/docker-compose.yml",
     "deploy/docker-compose.override.yaml"],
)
def test_is_compose_path_accepts_compose_files(path: str) -> None:
    assert is_compose_path(path) is True


def test_compose_update_normalizes_and_rejects_escapes() -> None:
    assert ComposeUpdate(compose_file=" docker_example/docker-compose.yml ").compose_file == (
        "docker_example/docker-compose.yml"
    )
    assert ComposeUpdate(compose_file="").compose_file is None
    assert ComposeUpdate(compose_file=None).compose_file is None
    for value in ("/etc/compose.yml", "../compose.yml", "a/../compose.yml",
                  "compose.txt", "a//compose.yml", "a\\compose.yml"):
        with pytest.raises(ValidationError):
            ComposeUpdate(compose_file=value)
