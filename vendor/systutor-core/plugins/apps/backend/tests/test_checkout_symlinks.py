from __future__ import annotations

from pathlib import Path

import pytest

from plugins.apps.backend.runtime.audit import audit_project
from plugins.apps.backend.runtime.source import validate_checkout
from plugins.apps.backend.runtime.types import AppDeployError


def _write(root: Path, relative: str, content: str = "x") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_broken_symlink_inside_checkout_is_a_warning(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    _write(root, ".claude/skills/.keep")
    (root / ".claude/skills/fastapi").symlink_to(
        "../../.venv/lib/python3.14/site-packages/fastapi"
    )

    warnings: list[str] = []
    assert validate_checkout(root, warnings) == root.resolve()
    assert warnings == [
        "Broken symlink in .claude/skills/fastapi. "
        "Not used by deployment. Continuing."
    ]


def test_symlink_escaping_checkout_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "escape").symlink_to(outside)

    with pytest.raises(AppDeployError, match="escapes the checkout"):
        validate_checkout(root, [])


def test_broken_symlink_escaping_checkout_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "escape").symlink_to("../../outside/missing")

    with pytest.raises(AppDeployError, match="escapes the checkout"):
        validate_checkout(root, [])


def test_existing_symlink_inside_checkout_is_silent(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    _write(root, "target.txt")
    (root / "link.txt").symlink_to("target.txt")

    warnings: list[str] = []
    validate_checkout(root, warnings)
    assert warnings == []


def test_symlink_loop_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "a").symlink_to("b")
    (root / "b").symlink_to("a")

    with pytest.raises(AppDeployError):
        validate_checkout(root, [])


def test_audit_project_exposes_checkout_warnings(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    _write(root, "compose.yaml", "services:\n  app:\n    image: alpine:3.20\n")
    (root / "link").symlink_to("missing")

    result = audit_project(root, "compose.yaml", non_root=True)

    assert result.warnings == [
        "Broken symlink in link. Not used by deployment. Continuing."
    ]
