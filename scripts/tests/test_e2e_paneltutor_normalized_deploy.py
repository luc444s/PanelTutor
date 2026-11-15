from __future__ import annotations

import importlib.util
import json
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "e2e_paneltutor_normalized_deploy",
    ROOT / "scripts/e2e_paneltutor_normalized_deploy.py",
)
assert SPEC and SPEC.loader
e2e = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = e2e
SPEC.loader.exec_module(e2e)


def finding(code: str) -> SimpleNamespace:
    return SimpleNamespace(code=code)


def unsafe_result() -> SimpleNamespace:
    return SimpleNamespace(errors=[finding(code) for code in sorted(e2e.EXPECTED_UNSAFE)])


def test_requires_a_genuinely_unsafe_initial_source() -> None:
    assert e2e.require_unsafe_source(unsafe_result()) == e2e.EXPECTED_UNSAFE
    with pytest.raises(e2e.E2EError, match="not blocked"):
        e2e.require_unsafe_source(SimpleNamespace(errors=[]))
    with pytest.raises(e2e.E2EError, match="expected unsafe"):
        e2e.require_unsafe_source(SimpleNamespace(errors=[finding("other")]))


def test_env_file_requires_exact_private_mode(tmp_path: Path) -> None:
    path = tmp_path / "app.env"
    path.write_text("SECRET=not-printed\n", encoding="utf-8")
    path.chmod(0o640)
    with pytest.raises(e2e.E2EError, match="0600"):
        e2e.validate_env_file(path)
    path.chmod(0o600)
    assert e2e.validate_env_file(path) == path.resolve()


class DockerRunner:
    transport = "local"

    def run(self, argv, **kwargs):
        if argv[:3] == ["docker", "container", "inspect"]:
            payload = {
                "Config": {
                    "User": "10001:10001",
                    "Labels": {e2e.OWNER_LABEL: "safe-project"},
                },
                "HostConfig": {
                    "Privileged": False,
                    "CapAdd": None,
                    "NetworkMode": "safe-project_default",
                    "PidMode": "",
                    "IpcMode": "private",
                    "UTSMode": "",
                    "UsernsMode": "",
                    "PortBindings": {},
                },
                "State": {"Running": True, "Health": {"Status": "healthy"}},
                "Mounts": [{"Type": "volume", "Source": "/var/lib/docker/volumes/x", "Destination": "/data"}],
            }
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        if argv[:2] == ["docker", "top"]:
            return SimpleNamespace(returncode=0, stdout="PID UID\n1 10001\n", stderr="")
        if argv[:2] == ["docker", "exec"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(argv)


def manifest() -> dict:
    return {
        "status": "running",
        "project": "safe-project",
        "owner_label": e2e.OWNER_LABEL,
        "non_root": True,
        "services": ["app"],
        "containers": {"app": "container-1"},
    }


def test_runtime_verification_proves_controlled_container() -> None:
    result = e2e.verify_deployment(manifest(), DockerRunner(), "safe-project")
    assert result["app"]["running"] is True
    assert result["app"]["health"] == "healthy"
    assert result["app"]["application_health"] == "ok"


def test_runtime_verification_rejects_docker_socket() -> None:
    class SocketRunner(DockerRunner):
        def run(self, argv, **kwargs):
            result = super().run(argv, **kwargs)
            if argv[:3] == ["docker", "container", "inspect"]:
                payload = json.loads(result.stdout)
                payload["Mounts"] = [{
                    "Type": "bind",
                    "Source": "/var/run/docker.sock",
                    "Destination": "/var/run/docker.sock",
                }]
                result.stdout = json.dumps(payload)
            return result

    with pytest.raises(e2e.E2EError, match="docker.sock"):
        e2e.verify_deployment(manifest(), SocketRunner(), "safe-project")


def test_runtime_verification_allows_only_read_only_secret_bind() -> None:
    class SecretRunner(DockerRunner):
        def __init__(self, read_write: bool):
            self.read_write = read_write

        def run(self, argv, **kwargs):
            result = super().run(argv, **kwargs)
            if argv[:3] == ["docker", "container", "inspect"]:
                payload = json.loads(result.stdout)
                payload["Mounts"] = [{
                    "Type": "bind",
                    "Source": "/secure/apps-key",
                    "Destination": "/run/secrets/apps_key",
                    "RW": self.read_write,
                }]
                result.stdout = json.dumps(payload)
            return result

    e2e.verify_deployment(manifest(), SecretRunner(False), "safe-project")
    with pytest.raises(e2e.E2EError, match="uncontrolled host bind"):
        e2e.verify_deployment(manifest(), SecretRunner(True), "safe-project")


def test_runtime_verification_requires_real_panel_health() -> None:
    class UnhealthyRunner(DockerRunner):
        def run(self, argv, **kwargs):
            result = super().run(argv, **kwargs)
            if argv[:2] == ["docker", "exec"]:
                result.returncode = 1
            return result

    with pytest.raises(e2e.E2EError, match="health endpoint"):
        e2e.verify_deployment(manifest(), UnhealthyRunner(), "safe-project")


def test_evidence_is_private_and_contains_no_environment(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    e2e.write_evidence(path, {"project": "safe-project", "status": "running"})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "running"


def test_full_flow_preserves_successful_deployment(monkeypatch, tmp_path: Path) -> None:
    env_file = tmp_path / "app.env"
    env_file.write_text("SECRET=canary\n", encoding="utf-8")
    env_file.chmod(0o600)
    audits = iter([unsafe_result(), SimpleNamespace(errors=[])])
    deployed = manifest()
    deployed["commit"] = "a" * 40
    calls: list[str] = []

    class Runner:
        def __init__(self, transport):
            self.transport = transport

    def clone(repo, branch, checkout, runner):
        checkout.mkdir(parents=True)
        calls.append("clone")

    monkeypatch.setattr(e2e, "Runner", Runner)
    monkeypatch.setattr(e2e, "clone_repo", clone)
    monkeypatch.setattr(e2e, "audit_project", lambda *a, **k: next(audits))
    monkeypatch.setattr(e2e, "normalize_checkout", lambda *a: calls.append("normalize"))
    monkeypatch.setattr(e2e, "deploy", lambda *a: deployed)
    monkeypatch.setattr(
        e2e,
        "verify_deployment",
        lambda *a: {"web": {"container_id": "c1", "running": True}},
    )
    monkeypatch.setattr(e2e, "cleanup_failed", lambda *a: calls.append("cleanup"))
    args = SimpleNamespace(
        env_file=env_file,
        transport="local",
        repo=e2e.DEFAULT_REPO,
        branch="main",
        compose_file="docker-compose.yml",
        project="safe-project",
        timeout=10,
        wait=5,
        evidence=None,
        keep_failed=False,
    )
    assert e2e.run(args) == 0
    assert calls == ["clone", "normalize"]
