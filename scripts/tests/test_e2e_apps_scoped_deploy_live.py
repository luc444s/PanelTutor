"""Opt-in live E2E for global incremental Apps deployments (A.SPEC 0088)."""
from __future__ import annotations

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


def test_global_deploy_only_recreates_the_changed_service() -> None:
    base_url = os.environ.get("SPANEL_E2E_BASE_URL", "").strip()
    password_file = os.environ.get("SPANEL_E2E_PASSWORD_FILE", "").strip()
    assert base_url, "SPANEL_E2E_BASE_URL is required"
    assert password_file, "SPANEL_E2E_PASSWORD_FILE is required"
    command = [
        sys.executable,
        str(ROOT / "scripts" / "e2e_apps_scoped_deploy.py"),
        "--base-url",
        base_url,
    ]
    for option, variable in (
        ("--repository", "SPANEL_E2E_REPOSITORY"),
        ("--branch", "SPANEL_E2E_BRANCH"),
        ("--compose-file", "SPANEL_E2E_COMPOSE_FILE"),
        ("--git-token", "SPANEL_E2E_GIT_TOKEN"),
        ("--git-remote", "SPANEL_E2E_GIT_REMOTE"),
        ("--evidence", "SPANEL_E2E_EVIDENCE"),
        ("--deploy-timeout", "SPANEL_E2E_DEPLOY_TIMEOUT"),
    ):
        value = os.environ.get(variable, "").strip()
        if value:
            command.extend([option, value])
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=int(os.environ.get("SPANEL_E2E_TIMEOUT", "5400")),
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    assert "E2E OK" in completed.stdout
