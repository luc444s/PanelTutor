"""Opt-in live black-box E2E for the example-voting-app fixture."""
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

REPOSITORY = "luc444s/example-voting-app"
BRANCH = "main"
COMPOSE_FILE = "docker-compose.yml"


def test_example_voting_app_against_the_lab() -> None:
    base_url = os.environ.get("SPANEL_E2E_BASE_URL", "https://spanel.lab").strip()
    password_file = os.environ.get(
        "SPANEL_E2E_PASSWORD_FILE", "/tmp/e2e-password"
    ).strip()
    email = os.environ.get("SPANEL_E2E_EMAIL", "sihuen8@gmail.com").strip()
    assert base_url and password_file and email

    command = [
        sys.executable,
        str(ROOT / "scripts" / "e2e_apps_trusted_deploy.py"),
        "--base-url",
        base_url,
        "--repository",
        os.environ.get("SPANEL_E2E_REPOSITORY", REPOSITORY).strip() or REPOSITORY,
        "--branch",
        os.environ.get("SPANEL_E2E_BRANCH", BRANCH).strip() or BRANCH,
        "--compose-file",
        os.environ.get("SPANEL_E2E_COMPOSE_FILE", COMPOSE_FILE).strip() or COMPOSE_FILE,
        "--env-json",
        os.environ.get("SPANEL_E2E_ENV_JSON", "[]"),
        "--evidence",
        os.environ.get(
            "SPANEL_E2E_EVIDENCE", "/tmp/voting-e2e-evidence.json"
        ).strip(),
    ]
    # No explicit policy: exercise the engine-owned automatic policy.
    if os.environ.get("SPANEL_E2E_POLICY", "").strip():
        command.extend(["--policy-json", os.environ["SPANEL_E2E_POLICY"]])
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
        env={
            **os.environ,
            "SPANEL_E2E_EMAIL": email,
            "SPANEL_E2E_PASSWORD_FILE": password_file,
        },
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert "E2E OK" in completed.stdout
