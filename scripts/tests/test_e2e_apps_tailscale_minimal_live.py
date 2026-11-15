"""Opt-in live black-box E2E for the Tailscale minimal Apps fixture."""
from __future__ import annotations

import json
import os
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

POLICY = {
    "service_users": {
        "tailscale": {"uid": 1000, "gid": 1000},
    },
    "writable_paths": [],
}


def test_tailscale_minimal_against_the_lab() -> None:
    base_url = os.environ.get("SPANEL_E2E_BASE_URL", "https://spanel.lab").strip()
    password_file = os.environ.get(
        "SPANEL_E2E_PASSWORD_FILE", "/tmp/e2e-password"
    ).strip()
    assert base_url
    assert password_file
    command = [
        sys.executable,
        str(ROOT / "scripts" / "e2e_apps_trusted_deploy.py"),
        "--base-url",
        base_url,
        "--repository",
        os.environ.get("SPANEL_E2E_REPOSITORY", "luc444s/tailscale-minimal").strip()
        or "luc444s/tailscale-minimal",
        "--branch",
        os.environ.get("SPANEL_E2E_BRANCH", "main").strip() or "main",
        "--compose-file",
        os.environ.get("SPANEL_E2E_COMPOSE_FILE", "docker-compose.yml").strip()
        or "docker-compose.yml",
        "--policy-json",
        os.environ.get("SPANEL_E2E_POLICY", json.dumps(POLICY)),
        "--env-json",
        os.environ.get("SPANEL_E2E_ENV_JSON", "[]"),
        "--evidence",
        os.environ.get(
            "SPANEL_E2E_EVIDENCE", "/tmp/tailscale-minimal-e2e-evidence.json"
        ).strip(),
    ]
    for option, variable in (
        ("--deploy-timeout", "SPANEL_E2E_DEPLOY_TIMEOUT"),
        ("--operation-timeout", "SPANEL_E2E_OPERATION_TIMEOUT"),
    ):
        value = os.environ.get(variable, "").strip()
        if value:
            command.extend([option, value])
    if os.environ.get("SPANEL_E2E_KEEP") == "1":
        command.append("--keep")
    if os.environ.get("SPANEL_E2E_KEEP_FAILED") == "1":
        command.append("--keep-failed")
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=int(os.environ.get("SPANEL_E2E_TIMEOUT", "3600")),
        check=False,
        env={**os.environ, "SPANEL_E2E_PASSWORD_FILE": password_file},
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert "E2E OK" in completed.stdout
