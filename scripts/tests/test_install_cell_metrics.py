"""Tests for scripts/install_cell_metrics.py."""

from __future__ import annotations

import importlib.util
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "install_cell_metrics.py"
TEMPLATE = ROOT / "apps" / "cell-metrics" / "spanel-cell-metrics.service"

spec = importlib.util.spec_from_file_location("install_cell_metrics", SCRIPT)
assert spec is not None and spec.loader is not None
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)


def test_render_unit_uses_configured_paths() -> None:
    rendered = install.render_unit(
        TEMPLATE.read_text(encoding="utf-8"),
        binary=Path("/usr/local/bin/spanel-cell-metrics"),
        socket_path=Path("/run/spanel/cell-metrics.sock"),
        token_path=Path("/etc/spanel/cell_metrics_token"),
        allowed_uids="0,1000",
    )
    assert "--socket /run/spanel/cell-metrics.sock" in rendered
    assert "--token-file /etc/spanel/cell_metrics_token" in rendered
    assert "--allowed-uids 0,1000" in rendered
    assert "ReadOnlyPaths=/etc/spanel/cell_metrics_token" in rendered
    assert "ExecStart=/usr/local/bin/spanel-cell-metrics --serve" in rendered
    # The shared runtime dir is owned by edge-relay; this root unit must not
    # declare RuntimeDirectory, but it does need write access to its socket.
    assert "RuntimeDirectory=" not in rendered
    assert "ReadWritePaths=/run/spanel" in rendered
    assert rendered.count("--socket") == 1
    assert rendered.count("--token-file") == 1
    assert rendered.count("--allowed-uids 0,1000") == 1
    assert "/run/secrets/cell_metrics_token" not in rendered


def test_render_unit_rejects_relative_paths() -> None:
    with pytest.raises(install.InstallError):
        install.render_unit(
            TEMPLATE.read_text(encoding="utf-8"),
            socket_path=Path("run/spanel/cell-metrics.sock"),
        )


def test_render_unit_rejects_bad_uids() -> None:
    with pytest.raises(install.InstallError):
        install.render_unit(
            TEMPLATE.read_text(encoding="utf-8"),
            allowed_uids="0; rm -rf /",
        )


def test_ensure_token_creates_private_file_and_never_rotates(tmp_path: Path) -> None:
    token = tmp_path / "nested" / "cell_metrics_token"
    assert install.ensure_token(token, dry_run=False) == "created"
    assert stat.S_IMODE(token.stat().st_mode) == 0o600
    first = token.read_text(encoding="utf-8")
    assert first.strip()
    assert install.ensure_token(token, dry_run=False) == "existing"
    assert token.read_text(encoding="utf-8") == first


def test_ensure_token_tightens_permissions(tmp_path: Path) -> None:
    token = tmp_path / "cell_metrics_token"
    token.write_text("secret\n", encoding="utf-8")
    token.chmod(0o644)
    assert install.ensure_token(token, dry_run=False) == "tightened"
    assert stat.S_IMODE(token.stat().st_mode) == 0o600


def test_ensure_token_refuses_directories(tmp_path: Path) -> None:
    token = tmp_path / "cell_metrics_token"
    token.mkdir()
    with pytest.raises(install.InstallError):
        install.ensure_token(token, dry_run=False)


def test_missing_mounts_reports_both(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        install, "app_mounts", lambda container: ["/var/run/docker.sock"]
    )
    assert install.missing_mounts("abc") == [
        "/run/spanel",
        "/run/secrets/cell_metrics_token",
    ]


def test_missing_mounts_accepts_socket_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        install,
        "app_mounts",
        lambda container: ["/run/spanel", "/run/secrets/cell_metrics_token"],
    )
    assert install.missing_mounts("abc") == []
