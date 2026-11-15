"""Opt-in destructive E2E that intentionally leaves a safe deployment running."""
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
    reason="requires SPANEL_LIVE_TESTS=1 and an explicitly configured Docker lab",
)


def test_real_paneltutor_is_blocked_normalized_and_left_running() -> None:
    env_file = os.environ.get("SPANEL_PANELTUTOR_E2E_ENV_FILE", "").strip()
    assert env_file, "SPANEL_PANELTUTOR_E2E_ENV_FILE is required"
    command = [
        sys.executable,
        str(ROOT / "scripts" / "e2e_paneltutor_normalized_deploy.py"),
        "--env-file",
        env_file,
        "--transport",
        os.environ.get("SPANEL_PANELTUTOR_E2E_TRANSPORT", "local"),
    ]
    for option, variable in (
        ("--project", "SPANEL_PANELTUTOR_E2E_PROJECT"),
        ("--evidence", "SPANEL_PANELTUTOR_E2E_EVIDENCE"),
        ("--branch", "SPANEL_PANELTUTOR_E2E_BRANCH"),
    ):
        value = os.environ.get(variable, "").strip()
        if value:
            command.extend([option, value])
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=int(os.environ.get("SPANEL_PANELTUTOR_E2E_TIMEOUT", "3600")),
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert "Deployment preserved" in completed.stdout
