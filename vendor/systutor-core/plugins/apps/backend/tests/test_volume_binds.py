from __future__ import annotations

from pathlib import Path

from plugins.apps.backend.runtime.types import (
    readonly_release_file,
    volume_is_host_bind,
)


def test_anonymous_container_volume_is_not_a_host_bind() -> None:
    assert volume_is_host_bind("/app/node_modules") is False


def test_named_volume_is_not_a_host_bind() -> None:
    assert volume_is_host_bind("pos_pgdata:/var/lib/postgresql") is False
    assert volume_is_host_bind(
        {"type": "volume", "source": "pos_pgdata", "target": "/var/lib/postgresql"}
    ) is False


def test_host_binds_are_detected() -> None:
    assert volume_is_host_bind("./back:/app") is True
    assert volume_is_host_bind("/var/run/docker.sock:/var/run/docker.sock:ro") is True
    assert volume_is_host_bind("~/data:/data") is True
    assert volume_is_host_bind(
        {"type": "bind", "source": "./back", "target": "/app"}
    ) is True


def test_only_canonical_safe_release_file_metadata_is_allowed(tmp_path: Path) -> None:
    (tmp_path / "config").write_text("ok", encoding="utf-8")
    (tmp_path / "directory").mkdir()
    (tmp_path / "compose.yml").write_text("services: {}\n", encoding="utf-8")
    assert readonly_release_file(
        {"source": "config", "target": "/etc/app.conf"},
        tmp_path, "compose.yml",
    )
    assert not readonly_release_file(
        {"source": "directory", "target": "/etc/app"}, tmp_path, "compose.yml"
    )
    assert not readonly_release_file(
        {"source": "config", "target": "/var/run/app.conf"},
        tmp_path, "compose.yml",
    )
    assert readonly_release_file(
        {"source": "config", "target": "/etc/app.conf", "mode": "0555"},
        tmp_path, "compose.yml",
    )
    assert not readonly_release_file(
        {"source": "config", "target": "/etc/app.conf", "mode": "0777"},
        tmp_path, "compose.yml",
    )


def test_release_file_uses_nested_compose_directory_and_cannot_escape(
    tmp_path: Path,
) -> None:
    compose_dir = tmp_path / "deploy"
    compose_dir.mkdir()
    (compose_dir / "compose.yml").write_text("services: {}\n", encoding="utf-8")
    (compose_dir / "config").write_text("ok", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.write_text("secret", encoding="utf-8")
    assert readonly_release_file(
        {"source": "config", "target": "/etc/app.conf"},
        tmp_path, "deploy/compose.yml",
    )
    assert not readonly_release_file(
        {"source": f"../../{outside.name}", "target": "/etc/app.conf"},
        tmp_path, "deploy/compose.yml",
    )
