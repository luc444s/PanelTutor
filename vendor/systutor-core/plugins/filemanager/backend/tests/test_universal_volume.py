"""Universal filemanager helper: rootless volume -> one rootful image."""

# The mandated root-level test command requires this local package bootstrap.
# ruff: noqa: E402
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

CORE = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(CORE / "src"))
sys.path.insert(0, str(CORE))

from plugins.filemanager.backend.router import _universal_volume_target
from systutor.contracts.file_targets import FileTarget


class FakeRuntime:
    def __init__(self, mounts: list[dict], uid: int | None = 60000) -> None:
        self.mounts = mounts
        self.uid = uid

    def inspect(self, kind: str, name: str) -> dict:
        return {"Mounts": self.mounts}

    def health(self) -> SimpleNamespace:
        return SimpleNamespace(cell_uid=self.uid)


def _mount(source: Path, destination: str = "/usr/share/nginx/html") -> dict:
    return {"Type": "volume", "Source": str(source), "Destination": destination}


def test_rootless_volume_maps_to_the_host_path(tmp_path: Path) -> None:
    source = tmp_path / "_data"
    source.mkdir()
    target = FileTarget(
        "spanel-demo-web",
        "/usr/share/nginx/html",
        "site-2",
        runtime="volume",
        execution_runtime="rootless",
    )
    mapped = _universal_volume_target(target, FakeRuntime([_mount(source)]))
    assert mapped is not None
    assert mapped.root == "/data"
    assert mapped.volume_source == str(source)
    assert mapped.owner_uid == 60000
    assert mapped.owner_gid == 60000


def test_subdirectory_root_is_kept_relative(tmp_path: Path) -> None:
    source = tmp_path / "_data"
    source.mkdir()
    target = FileTarget(
        "spanel-demo-web",
        "/usr/share/nginx/html/public",
        "site-2",
        runtime="volume",
        execution_runtime="rootless",
    )
    mapped = _universal_volume_target(target, FakeRuntime([_mount(source)]))
    assert mapped is not None
    assert mapped.root == "/data/public"


def test_missing_host_path_falls_back_to_the_cell(tmp_path: Path) -> None:
    target = FileTarget(
        "spanel-demo-web",
        "/usr/share/nginx/html",
        "site-2",
        runtime="volume",
        execution_runtime="rootless",
    )
    runtime = FakeRuntime([_mount(tmp_path / "does-not-exist")])
    assert _universal_volume_target(target, runtime) is None


def test_unrelated_mount_is_ignored(tmp_path: Path) -> None:
    source = tmp_path / "_data"
    source.mkdir()
    target = FileTarget(
        "spanel-demo-web",
        "/var/www/html",
        "site-2",
        runtime="volume",
        execution_runtime="rootless",
    )
    assert _universal_volume_target(target, FakeRuntime([_mount(source)])) is None


def test_missing_cell_uid_falls_back(tmp_path: Path) -> None:
    source = tmp_path / "_data"
    source.mkdir()
    target = FileTarget(
        "spanel-demo-web",
        "/usr/share/nginx/html",
        "site-2",
        runtime="volume",
        execution_runtime="rootless",
    )
    assert _universal_volume_target(target, FakeRuntime([_mount(source)], uid=None)) is None
