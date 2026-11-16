"""Opt-in real Apps E2E for Nextcloud, MariaDB, Redis, and cron."""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LIVE = os.environ.get("SPANEL_LIVE_TESTS") == "1"
pytestmark = pytest.mark.skipif(
    not LIVE,
    reason="requires SPANEL_LIVE_TESTS=1 and a configured lab API",
)


def _environment() -> list[list[str]]:
    suffix = secrets.token_hex(6)
    return [
        ["MARIADB_ROOT_PASSWORD", secrets.token_hex(32)],
        ["MARIADB_DATABASE", "nextcloud"],
        ["MARIADB_USER", "nextcloud"],
        ["MARIADB_PASSWORD", secrets.token_hex(32)],
        ["NEXTCLOUD_ADMIN_USER", f"admin_{suffix}"],
        ["NEXTCLOUD_ADMIN_PASSWORD", secrets.token_hex(32)],
        ["NEXTCLOUD_TRUSTED_DOMAINS", "localhost 127.0.0.1 app"],
        ["OVERWRITEHOST", "nextcloud-e2e.invalid"],
        ["OVERWRITEPROTOCOL", "https"],
    ]


def test_nextcloud_mariadb_redis_against_the_lab() -> None:
    base_url = os.environ.get("SPANEL_E2E_BASE_URL", "https://spanel.lab").strip()
    password_file = os.environ.get(
        "SPANEL_E2E_PASSWORD_FILE", "/tmp/e2e-password"
    ).strip()
    environment = os.environ.get("SPANEL_E2E_ENV_JSON", "").strip()
    command = [
        sys.executable,
        str(ROOT / "scripts" / "e2e_apps_trusted_deploy.py"),
        "--base-url",
        base_url,
        "--repository",
        "luc444s/nextcloud-paneltutor-fixture",
        "--branch",
        "main",
        "--compose-file",
        "compose.yaml",
        "--env-json",
        environment or json.dumps(_environment()),
        "--evidence",
        str(ROOT / "artifacts" / "nextcloud-mariadb-redis-e2e.json"),
        "--operation-timeout",
        os.environ.get("SPANEL_E2E_OPERATION_TIMEOUT", "1200"),
        "--deploy-timeout",
        os.environ.get("SPANEL_E2E_DEPLOY_TIMEOUT", "3600"),
    ]
    if os.environ.get("SPANEL_E2E_KEEP") == "1":
        command.append("--keep")
    if os.environ.get("SPANEL_E2E_KEEP_FAILED") == "1":
        command.append("--keep-failed")
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=int(os.environ.get("SPANEL_E2E_TIMEOUT", "5400")),
        check=False,
        env={**os.environ, "SPANEL_E2E_PASSWORD_FILE": password_file},
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    assert "E2E OK" in completed.stdout
