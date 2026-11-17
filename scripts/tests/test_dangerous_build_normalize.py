from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "dangerous_build_normalize.py"


def project(tmp_path: Path, *, nested: bool = False) -> Path:
    root = tmp_path / "checkout"
    root.mkdir()
    dockerfile = root / ("image/Dockerfile" if nested else "Dockerfile")
    dockerfile.parent.mkdir(parents=True, exist_ok=True)
    dockerfile.write_text(
        "FROM python:3.12-slim\nWORKDIR /app\nRUN chmod 777 /app\n"
        "CMD [\"python\", \"-V\"]\n",
        encoding="utf-8",
    )
    context = "./image" if nested else "."
    (root / "compose.yml").write_text(
        f"""services:
  web:
    build: {context}
    container_name: unsafe-web
    env_file: .env
    privileged: true
    ports:
      - "8080:8080"
    environment:
      API_TOKEN: literal-secret
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
networks:
  shared:
    external: true
    name: global-network
""",
        encoding="utf-8",
    )
    (root / ".env").write_text("VALUE=unsafe\n", encoding="utf-8")
    return root


def run(
    *args: object, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *(str(value) for value in args)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def fake_tool(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_scan_json_reports_real_findings_without_argument_crash(tmp_path: Path) -> None:
    root = project(tmp_path)
    result = run(
        "scan", root, "--compose-file", "compose.yml", "--non-root", "--format", "json"
    )
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    codes = {item["code"] for item in payload["findings"]}
    assert "compose_docker_socket" in codes
    assert "compose_repo_env_file" in codes
    assert "dockerfile_final_user_root" in codes
    assert "AttributeError" not in result.stderr


def test_default_fix_preserves_level_c_and_reaudits_preview(tmp_path: Path) -> None:
    root = project(tmp_path)
    original = (root / "compose.yml").read_text(encoding="utf-8")
    result = run("fix", root, "--compose-file", "compose.yml", "--non-root")
    assert result.returncode == 2
    assert "compose_docker_socket" in result.stderr
    assert (root / "compose.yml").read_text(encoding="utf-8") == original
    fixed = yaml.safe_load((root / "docker-compose.fixed.yml").read_text(encoding="utf-8"))
    assert fixed["services"]["web"]["volumes"] == [
        "/var/run/docker.sock:/var/run/docker.sock"
    ]
    assert not (root / "compose.yml.bak").exists()
    assert (root / "docker-compose.patch").is_file()
    assert (root / "Dockerfile.patch").is_file()
    assert "source=normalized-preview" in result.stdout


def test_deployment_copy_dry_run_is_clean_and_keeps_originals(tmp_path: Path) -> None:
    root = project(tmp_path, nested=True)
    compose_before = (root / "compose.yml").read_text(encoding="utf-8")
    dockerfile_before = (root / "image/Dockerfile").read_text(encoding="utf-8")
    result = run(
        "fix",
        root,
        "--compose-file",
        "compose.yml",
        "--non-root",
        "--deployment-copy",
    )
    assert result.returncode == 0, result.stderr
    assert "errors=0" in result.stdout
    assert (root / "compose.yml").read_text(encoding="utf-8") == compose_before
    assert (root / "image/Dockerfile").read_text(encoding="utf-8") == dockerfile_before
    fixed_compose = yaml.safe_load(
        (root / "docker-compose.fixed.yml").read_text(encoding="utf-8")
    )
    service = fixed_compose["services"]["web"]
    assert "volumes" not in service
    assert "ports" not in service
    assert "env_file" not in service
    assert service["x-spanel-external-env"] is True
    assert "container_name" not in service
    assert fixed_compose["networks"]["shared"] == {}
    fixed_dockerfile = (root / "image/Dockerfile.fixed").read_text(encoding="utf-8")
    assert "USER 10001:10001" in fixed_dockerfile
    assert "HEALTHCHECK" in fixed_dockerfile
    assert "chmod 755" in fixed_dockerfile
    assert "RUN chmod -R a+rX /app" in fixed_dockerfile


def test_apply_creates_backups_and_normalizes_referenced_dockerfile(tmp_path: Path) -> None:
    root = project(tmp_path, nested=True)
    result = run(
        "fix",
        root,
        "--compose-file",
        "compose.yml",
        "--non-root",
        "--deployment-copy",
        "--apply",
    )
    assert result.returncode == 0, result.stderr
    assert (root / "compose.yml.bak").is_file()
    assert (root / "image/Dockerfile.bak").is_file()
    assert "USER 10001:10001" in (root / "image/Dockerfile").read_text(encoding="utf-8")
    second = run(
        "fix",
        root,
        "--compose-file",
        "compose.yml",
        "--non-root",
        "--deployment-copy",
        "--apply",
    )
    assert second.returncode == 2
    assert "backup already exists" in second.stderr


def test_fail_on_aliases_and_scan_exceptions(tmp_path: Path) -> None:
    root = project(tmp_path)
    result = run(
        "scan",
        root,
        "--compose-file",
        "compose.yml",
        "--allow-docker-socket",
        "--allow-env-file",
        "--fail-on",
        "warning",
        "--format",
        "json",
    )
    payload = json.loads(result.stdout)
    codes = {item["code"] for item in payload["findings"]}
    assert "compose_docker_socket" not in codes
    assert "compose_bind_absolute" not in codes
    assert "compose_mount_sensitive" not in codes
    assert "compose_repo_env_file" not in codes
    assert result.returncode == 2  # other unsafe findings still block


def test_deployment_copy_can_preserve_explicit_socket_exception(tmp_path: Path) -> None:
    root = project(tmp_path)
    result = run(
        "fix",
        root,
        "--compose-file",
        "compose.yml",
        "--non-root",
        "--deployment-copy",
        "--allow-docker-socket",
    )
    assert result.returncode == 0, result.stderr
    fixed = yaml.safe_load((root / "docker-compose.fixed.yml").read_text(encoding="utf-8"))
    assert fixed["services"]["web"]["volumes"] == [
        "/var/run/docker.sock:/var/run/docker.sock"
    ]


def test_explicit_service_user_is_applied_and_must_be_non_root(tmp_path: Path) -> None:
    root = project(tmp_path)
    result = run(
        "fix",
        root,
        "--compose-file",
        "compose.yml",
        "--deployment-copy",
        "--service-user",
        "web=application",
    )
    assert result.returncode == 0, result.stderr
    fixed = yaml.safe_load((root / "docker-compose.fixed.yml").read_text(encoding="utf-8"))
    assert fixed["services"]["web"]["user"] == "application"
    rejected = run(
        "fix",
        root,
        "--compose-file",
        "compose.yml",
        "--service-user",
        "web=root",
    )
    assert rejected.returncode == 2
    assert "explicit non-root user" in rejected.stderr


def test_gate_fails_closed_when_external_tools_are_missing(tmp_path: Path) -> None:
    root = project(tmp_path)
    env = {**os.environ, "PATH": str(tmp_path / "empty-bin")}
    result = run(
        "gate",
        root,
        "--compose-file",
        "compose.yml",
        "--format",
        "json",
        env=env,
    )
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["trivy"]["error"] == "required executable is unavailable"
    assert payload["hadolint"]["error"] == "required executable is unavailable"
    assert payload["buildkit"]["attempted"] is False


def test_gate_combines_tools_and_buildkit_on_clean_project(tmp_path: Path) -> None:
    root = project(tmp_path)
    (root / "Dockerfile").write_text(
        "FROM python:3.12-slim\nUSER 10001:10001\n"
        "HEALTHCHECK CMD python -V || exit 1\nCMD [\"python\", \"-V\"]\n",
        encoding="utf-8",
    )
    (root / "Dockerfile.extra").write_text("FROM scratch\n", encoding="utf-8")
    (root / "compose.yml").write_text(
        "services:\n  web:\n    build: .\n",
        encoding="utf-8",
    )
    tools = tmp_path / "bin"
    tools.mkdir()
    calls = tmp_path / "calls"
    fake_tool(tools, "trivy", f"echo trivy:$@ >> {calls}; echo '{{\"Results\":[]}}'")
    fake_tool(tools, "hadolint", f"echo hadolint:$@ >> {calls}; echo '[]'")
    fake_tool(
        tools,
        "docker",
        f"echo docker:$DOCKER_BUILDKIT:$@ >> {calls}; "
        "if [ \"$1 $2\" = \"image inspect\" ]; then "
        "echo '{\"RepoDigests\":[],\"Config\":{"
        "\"Healthcheck\":{\"Test\":[\"CMD\",\"true\"]}}}'; fi; exit 0",
    )
    env = {**os.environ, "PATH": f"{tools}:{os.environ.get('PATH', '')}"}

    result = run(
        "gate",
        root,
        "--compose-file",
        "compose.yml",
        "--non-root",
        "--format",
        "json",
        env=env,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "passed"
    assert payload["trivy"]["blocking"] == 0
    assert payload["hadolint"]["blocking"] == 0
    assert payload["buildkit"]["attempted"] is True
    assert payload["buildkit"]["passed"] is True
    recorded = calls.read_text(encoding="utf-8")
    assert "Dockerfile.extra" in recorded
    assert "docker:1:build" in recorded
    assert "docker:1:image rm --force" in recorded


def test_gate_skips_build_when_hadolint_blocks(tmp_path: Path) -> None:
    root = project(tmp_path)
    tools = tmp_path / "bin"
    tools.mkdir()
    calls = tmp_path / "calls"
    fake_tool(tools, "trivy", "echo '{\"Results\":[]}'")
    fake_tool(
        tools,
        "hadolint",
        "echo '[{\"code\":\"DL3002\",\"message\":\"Last user should not be root\","
        "\"level\":\"warning\",\"line\":1,\"column\":1,\"file\":\"Dockerfile\"}]'; exit 1",
    )
    fake_tool(tools, "docker", f"echo called >> {calls}; exit 0")
    env = {**os.environ, "PATH": f"{tools}:{os.environ.get('PATH', '')}"}

    result = run(
        "gate",
        root,
        "--compose-file",
        "compose.yml",
        "--format",
        "json",
        env=env,
    )
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["hadolint"]["blocking"] == 1
    assert payload["buildkit"]["attempted"] is False
    assert not calls.exists()


def test_harden_is_isolation_only_and_never_runs_trivy_hadolint_or_buildkit(
    tmp_path: Path,
) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "Dockerfile").write_text(
        "FROM python:3.12-slim\nUSER 10001:10001\n"
        "HEALTHCHECK CMD python -V || exit 1\nCMD [\"python\", \"-V\"]\n",
        encoding="utf-8",
    )
    (root / "compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    build: .\n"
        '    user: "10001:10001"\n',
        encoding="utf-8",
    )
    tools = tmp_path / "bin"
    tools.mkdir()
    markers = tmp_path / "invoked"
    for name in ("trivy", "hadolint", "docker"):
        fake_tool(tools, name, f"echo {name} >> {markers}; exit 1")
    env = {**os.environ, "PATH": f"{tools}:{os.environ.get('PATH', '')}"}
    result = run(
        "harden",
        root,
        "--apply",
        "--compose-file",
        "compose.yml",
        "--format",
        "json",
        "--service-user",
        "web=10001:10001",
        env=env,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "applied"
    assert payload["gate"]["isolation"]["blocking"] == 0
    assert "trivy" not in payload["gate"]
    assert "hadolint" not in payload["gate"]
    assert "buildkit" not in payload["gate"]
    assert not markers.exists(), "harden must not invoke external scanners or Docker"


def test_ephemeral_writable_paths_use_tmpfs_instead_of_volumes() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    from dangerous_build.compose import ServicePolicy, harden_compose
    from dangerous_build.dockerfile import WritablePath

    data = yaml.safe_load(
        "services:\n"
        "  database:\n"
        "    image: postgres:16-alpine\n"
        "    volumes:\n"
        "      - database-data:/var/lib/postgresql/data\n"
        "volumes:\n"
        "  database-data:\n"
    )
    hardened = yaml.safe_load(
        harden_compose(
            yaml.safe_dump(data),
            {
                "database": ServicePolicy(
                    70,
                    70,
                    (WritablePath("/var/run/postgresql", "0775"),),
                )
            },
        )
    )
    service = hardened["services"]["database"]
    assert service["volumes"] == [{
        "type": "volume",
        "source": "database-data",
        "target": "/var/lib/postgresql/data",
        "volume": {"nocopy": True},
    }]
    assert "/var/run/postgresql:rw,noexec,nosuid,nodev,mode=0775,uid=70,gid=70" in service["tmpfs"]
    assert not any("postgresql" in name for name in hardened.get("volumes", {}))


def test_hardener_preserves_only_normalized_compatibility(tmp_path: Path) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    from dangerous_build.compose import ServicePolicy, harden_compose
    from dangerous_build.compose_normalizer import normalize_compose

    (tmp_path / "proxy.cfg").write_text("ok", encoding="utf-8")
    normalized = normalize_compose(
        """services:
  proxy:
    container_name: pos-proxy
    ports: ["80:80"]
    volumes: ["./proxy.cfg:/etc/proxy.cfg:ro", "./code:/app"]
""",
        tmp_path,
    )
    data = yaml.safe_load(
        harden_compose(normalized.text, {"proxy": ServicePolicy(1000, 1000)}, tmp_path)
    )
    service = data["services"]["proxy"]
    assert service["networks"]["default"]["aliases"] == ["pos-proxy"]
    assert "volumes" not in service
    assert service["x-spanel-readonly-files"] == [{
        "source": "proxy.cfg", "target": "/etc/proxy.cfg",
    }]
    assert service["sysctls"] == {
        "net.ipv4.ip_unprivileged_port_start": "0"
    }
    assert "ports" not in service


def test_hardener_preserves_executable_directory_injections(tmp_path: Path) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    from dangerous_build.compose import ServicePolicy, harden_compose
    from dangerous_build.compose_normalizer import normalize_compose

    checks = tmp_path / "healthchecks"
    checks.mkdir()
    script = checks / "postgres.sh"
    script.write_text("#!/bin/sh\npg_isready\n", encoding="utf-8")
    script.chmod(0o755)
    normalized = normalize_compose(
        'services:\n  db:\n    volumes: ["./healthchecks:/healthchecks"]\n',
        tmp_path,
    )
    data = yaml.safe_load(
        harden_compose(normalized.text, {"db": ServicePolicy(1000, 1000)}, tmp_path)
    )
    service = data["services"]["db"]
    assert "volumes" not in service
    assert service["x-spanel-readonly-files"] == [{
        "source": "healthchecks/postgres.sh",
        "target": "/healthchecks/postgres.sh",
        "mode": "0555",
    }]


def test_hardener_resolves_bind_from_nested_compose_directory(tmp_path: Path) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    from dangerous_build.compose import ServicePolicy, harden_compose

    compose_dir = tmp_path / "deploy"
    compose_dir.mkdir()
    (compose_dir / "proxy.cfg").write_text("ok", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.cfg"
    outside.write_text("secret", encoding="utf-8")
    source = """services:
  proxy:
    volumes:
      - {type: bind, source: ./proxy.cfg, target: /etc/proxy.cfg, read_only: true}
      - {type: bind, source: ./../../TMP_OUTSIDE, target: /etc/outside.cfg, read_only: true}
""".replace("TMP_OUTSIDE", outside.name)
    data = yaml.safe_load(harden_compose(
        source,
        {"proxy": ServicePolicy(1000, 1000)},
        tmp_path,
        "deploy/compose.yml",
    ))
    assert "volumes" not in data["services"]["proxy"]
