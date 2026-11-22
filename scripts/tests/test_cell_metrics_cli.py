"""Tests for scripts/cell_metrics_cli.py (A.SPEC 0112)."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "cell_metrics_cli.py"

spec = importlib.util.spec_from_file_location("cell_metrics_cli", SCRIPT)
assert spec is not None and spec.loader is not None
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)

SAMPLE = {
    "ts_ms": 1795314600000,
    "slug": "demo",
    "uid": 60070,
    "interval_ms": 1000,
    "warmup": False,
    "memory": {
        "current_bytes": 1524629504,
        "peak_bytes": 1729629504,
        "max_bytes": 2147483648,
        "oom_kill": 0,
    },
    "cpu": {
        "usage_usec": 123456789,
        "cores": 0.62,
        "quota_usec": 100000,
        "period_usec": 100000,
        "nr_throttled": 0,
    },
    "pids": {"current": 118, "max": 256},
    "pressure": {
        "cpu": {"some_avg10": 3.1, "full_avg10": 0.0},
        "memory": {"some_avg10": 0.4, "full_avg10": 0.0},
        "io": {"some_avg10": 0.0, "full_avg10": 0.0},
    },
    "io": {
        "read_bytes": 12345678,
        "write_bytes": 87654321,
        "read_bytes_per_s": 1200.5,
        "write_bytes_per_s": 3400.0,
    },
}


def _write_registry(data_root: Path, slug: str = "demo", uid: int = 60070) -> None:
    data_root.mkdir(parents=True, exist_ok=True)
    (data_root / "registry.json").write_text(
        json.dumps({"version": 1, "allocations": {slug: {"slug": slug, "uid": uid}}}),
        encoding="utf-8",
    )


def _write_fake_binary(path: Path, lines: list[str]) -> Path:
    body = "\n".join(lines)
    path.write_text(f"#!/bin/sh\ncat <<'EOF'\n{body}\nEOF\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = {key: value for key, value in os.environ.items() if key != "SPANEL_CELL_METRICS_BIN"}
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def test_resolve_uid_reads_registry(tmp_path: Path) -> None:
    _write_registry(tmp_path, "demo", 60070)
    assert cli.resolve_uid(tmp_path, "demo") == 60070


def test_resolve_uid_rejects_missing_slug(tmp_path: Path) -> None:
    _write_registry(tmp_path, "demo", 60070)
    with pytest.raises(cli.CliError, match="no existe"):
        cli.resolve_uid(tmp_path, "otra")


def test_render_snapshot_matches_documented_table() -> None:
    table = cli.render_snapshot(SAMPLE)
    assert "Cell demo · uid 60070 · 2026-11-22 02:30:00Z · intervalo 1.0s" in table
    assert "1,42 GiB / 2,00 GiB    71 %   pico 1,61 GiB" in table
    assert "0,62 cores / 1,00    62 %   throttled 0" in table
    assert "118 / 256" in table
    assert "CPU 3,1 % · RAM 0,4 % · IO 0,0 %" in table
    assert "lectura 1,2 kB/s · escritura 3,4 kB/s" in table
    assert "Ctrl-C para salir." in table


def test_render_snapshot_handles_null_limits_and_warmup() -> None:
    sample = json.loads(json.dumps(SAMPLE))
    sample["warmup"] = True
    sample["memory"]["max_bytes"] = None
    sample["memory"]["peak_bytes"] = None
    sample["cpu"]["cores"] = 0.0
    sample["cpu"]["quota_usec"] = None
    sample["cpu"]["period_usec"] = None
    sample["pids"]["max"] = None
    sample["io"]["read_bytes_per_s"] = None
    sample["io"]["write_bytes_per_s"] = None
    table = cli.render_snapshot(sample)
    assert "sin límite" in table
    assert "0,00 cores" in table
    assert "I/O        lectura — · escritura —" in table


def test_once_json_passes_through_fake_binary(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    _write_registry(data_root)
    line = json.dumps(SAMPLE, separators=(",", ":"))
    binary = _write_fake_binary(tmp_path / "fake-cell-metrics", [line])

    result = _run(
        "--slug",
        "demo",
        "--once",
        "--json",
        "--bin",
        str(binary),
        "--data-root",
        str(data_root),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == line


def test_once_table_uses_fake_binary(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    _write_registry(data_root)
    line = json.dumps(SAMPLE)
    binary = _write_fake_binary(tmp_path / "fake-cell-metrics", [line])

    result = _run(
        "--slug",
        "demo",
        "--once",
        "--bin",
        str(binary),
        "--data-root",
        str(data_root),
    )
    assert result.returncode == 0, result.stderr
    assert "Cell demo · uid 60070" in result.stdout
    assert "1,42 GiB / 2,00 GiB" in result.stdout


def test_missing_binary_suggests_build(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    _write_registry(data_root)
    missing = tmp_path / "not-built"

    result = _run(
        "--slug",
        "demo",
        "--once",
        "--bin",
        str(missing),
        "--data-root",
        str(data_root),
    )
    assert result.returncode != 0
    assert "binario no encontrado" in result.stderr
    assert "cargo build --release" in result.stderr


def test_unknown_slug_fails_clearly(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    _write_registry(data_root, "demo", 60070)
    binary = _write_fake_binary(tmp_path / "fake-cell-metrics", ["{}"])

    result = _run(
        "--slug",
        "otra",
        "--once",
        "--bin",
        str(binary),
        "--data-root",
        str(data_root),
    )
    assert result.returncode != 0
    assert "no existe" in result.stderr
