from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "dangerous_build_normalize.py"
sys.path.insert(0, str(ROOT / "scripts"))

from dangerous_build import transaction
from dangerous_build.compose import ServicePolicy, harden_compose
from dangerous_build.dockerfile import WritablePath, harden_dockerfile


def fixture(root: Path, *, unsafe_permissions: bool = False) -> Path:
    root.mkdir()
    permission = "RUN chmod 777 /app/data\n" if unsafe_permissions else ""
    (root / "Dockerfile").write_text(
        "FROM alpine:3.20\n"
        "USER root\n"
        "RUN mkdir -p /app/data\n"
        f"{permission}"
        "WORKDIR /app\n"
        'HEALTHCHECK CMD ["true"]\n'
        'CMD ["sh"]\n',
        encoding="utf-8",
    )
    (root / "compose.yml").write_text(
        """services:
  web:
    build: .
    container_name: unsafe-web
    privileged: true
    ports:
      - "8080:8080"
    environment:
      API_TOKEN: literal-secret
    volumes:
      - ./data:/app/data
""",
        encoding="utf-8",
    )
    return root


def fake_tool(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)


def tools(tmp_path: Path, *, trivy_body: str | None = None) -> tuple[dict[str, str], Path]:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    calls = tmp_path / "calls"
    fake_tool(
        binaries,
        "trivy",
        trivy_body or f"echo trivy >> {calls}; echo '{{\"Results\":[]}}'",
    )
    fake_tool(binaries, "hadolint", f"echo hadolint >> {calls}; echo '[]'")
    fake_tool(
        binaries,
        "docker",
        f"echo docker:$DOCKER_BUILDKIT:$@ >> {calls}; exit 0",
    )
    return {**os.environ, "PATH": f"{binaries}:{os.environ.get('PATH', '')}"}, calls


def run_harden(root: Path, env: dict[str, str], *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "harden",
            str(root),
            "--compose-file",
            "compose.yml",
            "--service-user",
            "web=10001:10001",
            "--format",
            "json",
            *extra,
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_runtime_user_is_inserted_after_build_without_rewriting_permissions() -> None:
    original = (
        "FROM alpine:3.20\nUSER root\nRUN apk add curl\n"
        "RUN chmod 777 /data\nCMD [\"sh\"]\n"
    )
    fixed = harden_dockerfile(original, uid=10001, gid=10001)
    assert "USER root" in fixed
    assert "RUN chmod 777 /data" in fixed
    assert fixed.index("RUN apk add curl") < fixed.index("USER 10001:10001")
    assert fixed.index("USER 10001:10001") < fixed.index('CMD ["sh"]')


def test_compose_hardening_creates_isolation_envelope() -> None:
    original = """services:
  web:
    build: .
    privileged: true
    ports: ["8080:8080"]
    environment: {API_TOKEN: literal}
    volumes: ["./data:/app/data"]
"""
    fixed = yaml.safe_load(
        harden_compose(
            original,
            {"web": ServicePolicy(10001, 10001, (WritablePath("/app/data"),))},
        )
    )
    service = fixed["services"]["web"]
    assert "privileged" not in service
    assert "ports" not in service
    assert service["expose"] == ["8080"]
    assert service["user"] == "10001:10001"
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["read_only"] is True
    assert service["environment"]["API_TOKEN"] == "${API_TOKEN}"
    assert fixed["networks"]["default"]["internal"] is True
    assert service["volumes"][0].endswith(":/app/data")
    assert "./data:/app/data" not in service["volumes"]


def test_blocked_hardening_never_changes_source_or_runs_buildkit(tmp_path: Path) -> None:
    root = fixture(tmp_path / "checkout", unsafe_permissions=True)
    before = {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()}
    env, calls = tools(tmp_path)
    result = run_harden(root, env, "--apply")
    assert result.returncode == 2, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()} == before
    recorded = calls.read_text(encoding="utf-8")
    assert "trivy" in recorded and "hadolint" in recorded
    assert "docker:" not in recorded


def test_apply_is_gated_backed_up_and_reaudited(tmp_path: Path) -> None:
    root = fixture(tmp_path / "checkout")
    env, calls = tools(tmp_path)
    result = run_harden(root, env, "--writable-path", "web=/app/data:0750", "--apply")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "applied"
    assert payload["gate"]["buildkit"]["runtime"]["passed"] is True
    assert payload["gate_after_apply"]["buildkit"]["runtime"]["passed"] is True
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.index("RUN mkdir -p /app/data") < dockerfile.index("USER 10001:10001")
    assert "RUN install -d -o 10001 -g 10001 -m 750 /app/data" in dockerfile
    compose = yaml.safe_load((root / "compose.yml").read_text(encoding="utf-8"))
    assert compose["services"]["web"]["read_only"] is True
    manifest = Path(payload["backup"]) / "manifest.json"
    assert manifest.stat().st_mode & 0o777 == 0o600
    manifest_payload = json.loads(manifest.read_text())
    assert {item["path"] for item in manifest_payload["files"]} == {
        "Dockerfile",
        "compose.yml",
    }
    assert manifest_payload["metadata"]["policy"]["isolation"]["runtime_egress"] is False
    recorded = calls.read_text(encoding="utf-8")
    assert recorded.count("docker:1:build") == 2
    assert recorded.count("compose --project-name") == 4  # up/down before and after apply


def test_failed_post_apply_gate_rolls_everything_back(tmp_path: Path) -> None:
    root = fixture(tmp_path / "checkout")
    before = {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()}
    count = tmp_path / "trivy-count"
    body = (
        f"n=$(cat {count} 2>/dev/null || echo 0); n=$((n+1)); echo $n > {count}; "
        "if [ $n -le 2 ]; then echo '{\"Results\":[]}'; else "
        "echo '{\"Results\":[{\"Target\":\"compose.yml\",\"Secrets\":[{"
        "\"Severity\":\"HIGH\",\"RuleID\":\"test-secret\",\"Category\":\"test\"}]}]}'; fi"
    )
    env, _calls = tools(tmp_path, trivy_body=body)
    result = run_harden(root, env, "--apply")
    assert result.returncode == 2, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "rolled_back"
    assert {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()} == before


def test_vulnerable_built_image_blocks_publication_and_is_removed(tmp_path: Path) -> None:
    root = fixture(tmp_path / "checkout")
    before = {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()}
    body = (
        "if [ \"$1\" = image ]; then "
        "echo '{\"Results\":[{\"Target\":\"image\",\"Vulnerabilities\":[{"
        "\"Severity\":\"CRITICAL\",\"VulnerabilityID\":\"CVE-TEST\","
        "\"PkgName\":\"fixture\",\"Title\":\"fixture vulnerability\"}]}]}'; "
        "else echo '{\"Results\":[]}'; fi"
    )
    env, calls = tools(tmp_path, trivy_body=body)
    result = run_harden(root, env, "--apply")
    assert result.returncode == 2, result.stderr
    payload = json.loads(result.stdout)
    service = payload["gate"]["buildkit"]["services"][0]
    assert service["image_scan"]["blocking"] == 1
    assert payload["applied"] is False
    assert {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()} == before
    recorded = calls.read_text(encoding="utf-8")
    assert "docker:1:build" in recorded
    assert "docker:1:image rm --force" in recorded


def test_publication_failure_restores_previously_replaced_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    candidate = tmp_path / "candidate"
    root.mkdir()
    candidate.mkdir()
    for name in ("one", "two"):
        (root / name).write_text(f"old-{name}", encoding="utf-8")
        (candidate / name).write_text(f"new-{name}", encoding="utf-8")
    real = transaction._replace_from
    calls = 0

    def fail_second(source: Path, target: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected publication failure")
        real(source, target)

    monkeypatch.setattr(transaction, "_replace_from", fail_second)
    with pytest.raises(transaction.PublicationError, match="originals were restored"):
        transaction.publish(root, candidate, (Path("one"), Path("two")))
    assert (root / "one").read_text() == "old-one"
    assert (root / "two").read_text() == "old-two"
