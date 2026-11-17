"""Opt-in live black-box E2E for the Langflow Apps fixture.

Runs scripts/e2e_apps_trusted_deploy.py against the real lab API, worker and
Docker host.  Credentials come from SPANEL_E2E_EMAIL and a mode-0600 password
file (SPANEL_E2E_PASSWORD_FILE); no secret is written to this file.

Enable with SPANEL_LIVE_TESTS=1.  Deployed resources are removed by the E2E
script at the end of the run.
"""
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

REPOSITORY = "langflow-ai/langflow"
BRANCH = "main"
COMPOSE_FILE = "docker_example/docker-compose.yml"

# docker_example/docker-compose.yml exposes services: langflow, postgres.
# policy_for() in the E2E script requires exact coverage of the inspected services.
POLICY = {
    "service_users": {
        "langflow": {"uid": 1000, "gid": 1000},
        "postgres": {"uid": 70, "gid": 70},
    },
    "writable_paths": [
        {"service": "langflow", "path": "/app/langflow", "mode": "0775"},
        {"service": "postgres", "path": "/var/run/postgresql", "mode": "0775"},
    ],
}


def test_langflow_against_the_lab() -> None:
    base_url = os.environ.get("SPANEL_E2E_BASE_URL", "https://spanel.lab").strip()
    password_file = os.environ.get(
        "SPANEL_E2E_PASSWORD_FILE", "/tmp/e2e-password"
    ).strip()
    email = os.environ.get("SPANEL_E2E_EMAIL", "sihuen8@gmail.com").strip()
    assert base_url
    assert password_file
    assert email

    environment = {
        "POSTGRES_PASSWORD": secrets.token_hex(24),
        "LANGFLOW_SUPERUSER_PASSWORD": secrets.token_hex(24),
    }

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
        "--policy-json",
        os.environ.get("SPANEL_E2E_POLICY", json.dumps(POLICY)),
        "--env-json",
        os.environ.get("SPANEL_E2E_ENV_JSON", json.dumps(environment)),
        "--evidence",
        os.environ.get(
            "SPANEL_E2E_EVIDENCE", "/tmp/langflow-e2e-evidence.json"
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
        env={
            **os.environ,
            "SPANEL_E2E_EMAIL": email,
            "SPANEL_E2E_PASSWORD_FILE": password_file,
        },
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert "E2E OK" in completed.stdout
