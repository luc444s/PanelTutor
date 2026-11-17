"""Regression tests: Apps deploys original applications, not rewritten ones.

The retired hardener used to rewrite Dockerfiles and Compose so that any app
would run as a non-root user.  These tests pin the new contract:

* the signed tree is byte-for-byte the cloned tree;
* no USER/ENTRYPOINT/CMD/volume/network translation is performed;
* the existing host-resource security validations still reject unsafe input;
* signed releases still verify, so rollbacks of old releases stay possible.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from plugins.apps.backend.hardening import (
    HardeningPolicy,
    RuntimeUserPolicy,
    automatic_hardening_policy,
)
from plugins.apps.backend.releases import ReleaseKeyRing, find_release, verify_release
from plugins.apps.backend.releases import pipeline as pipeline_module
from plugins.apps.backend.releases.pipeline import create_release, release_result
from plugins.apps.backend.releases.verify import tree_digest
from plugins.apps.backend.runtime import audit_project

KEY = "k" * 32
POLICY = HardeningPolicy((RuntimeUserPolicy("web", 10001, 10002),), ())

COMPOSE = """services:
  web:
    build: {context: ., dockerfile: Dockerfile}
    user: "10001:10002"
    entrypoint: ["/app/start"]
    command: ["serve", "--port", "8080"]
    networks: [backbone]
    volumes:
      - data:/var/lib/app
    healthcheck:
      test: ["CMD", "true"]
networks:
  backbone:
volumes:
  data:
"""
DOCKERFILE = (
    "FROM alpine:3.20\n"
    "USER 10001:10002\n"
    "ENTRYPOINT [\"/app/start\"]\n"
    "CMD [\"serve\"]\n"
    "HEALTHCHECK CMD true\n"
)


def make_app(tmp_path: Path) -> Path:
    root = tmp_path / "checkout"
    root.mkdir()
    root.joinpath("compose.yml").write_text(COMPOSE, encoding="utf-8")
    root.joinpath("Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
    return root


def sign_env(tmp_path: Path) -> dict[str, str]:
    return {
        "SPANEL_APPS_RELEASE_SIGNING_KEY": KEY,
        "SPANEL_APPS_STATE_ROOT": str(tmp_path / "state"),
    }


@pytest.fixture(autouse=True)
def _fixed_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pipeline_module, "_git_commit", lambda _root: "a" * 40)


def test_image_specific_writable_paths_are_no_longer_generated() -> None:
    """Postgres/MySQL chmod paths were hardener-only; they must not reappear."""

    policy = automatic_hardening_policy(
        {"db": {"image": "postgres:16"}, "mysql": {"image": "mariadb:11"}}, {}
    )
    data = policy.as_dict()
    assert data["service_users"] == {}
    assert data["writable_paths"] == []
    assert "runtime_volumes" not in data


def test_release_signs_the_checkout_without_rewriting_any_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = sign_env(tmp_path)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    root = make_app(tmp_path)
    before = tree_digest(root)
    compose_before = root.joinpath("compose.yml").read_bytes()
    dockerfile_before = root.joinpath("Dockerfile").read_bytes()

    release = create_release(
        root,
        compose_file="compose.yml",
        tenant_id="t1",
        application_id="a1",
        operation_id="op-1",
        repo="acme/demo",
        branch="main",
        policy=POLICY,
        environ=env,
    )

    assert tree_digest(root) == before
    assert root.joinpath("compose.yml").read_bytes() == compose_before
    assert root.joinpath("Dockerfile").read_bytes() == dockerfile_before
    assert release.source_tree_sha256 == before
    assert release.hardened_tree_sha256 == before
    assert release.compose_sha256 == pipeline_module._sha256(root / "compose.yml")
    assert release.dockerfiles == {"Dockerfile": pipeline_module._sha256(root / "Dockerfile")}
    assert find_release(tmp_path / "state", "t1", "a1", "op-1").release_id == "op-1"


def test_no_hardener_subprocess_is_invoked_during_release_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = sign_env(tmp_path)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SPANEL_APPS_HARDENER_COMMAND", "dangerous-build-normalize")
    calls: list[list[str]] = []

    def record(argv: list[str], **_kwargs: Any) -> None:
        calls.append([str(item) for item in argv])
        raise AssertionError("release creation must not spawn a hardener")

    monkeypatch.setattr(subprocess, "run", record)
    create_release(
        make_app(tmp_path),
        compose_file="compose.yml",
        tenant_id="t1",
        application_id="a1",
        operation_id="op-2",
        repo="acme/demo",
        branch="main",
        policy=POLICY,
        environ=env,
    )
    assert calls == []


def test_original_entrypoint_command_user_volumes_and_networks_are_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = sign_env(tmp_path)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    root = make_app(tmp_path)
    create_release(
        root,
        compose_file="compose.yml",
        tenant_id="t1",
        application_id="a1",
        operation_id="op-3",
        repo="acme/demo",
        branch="main",
        policy=POLICY,
        environ=env,
    )
    verified = verify_release(
        tmp_path / "state",
        find_release(tmp_path / "state", "t1", "a1", "op-3"),
        environ=env,
    )
    service = verified.audit.data["services"]["web"]
    assert service["user"] == "10001:10002"
    assert service["entrypoint"] == ["/app/start"]
    assert service["command"] == ["serve", "--port", "8080"]
    assert service["volumes"] == ["data:/var/lib/app"]
    assert service["networks"] == ["backbone"]
    assert set(verified.audit.data["networks"]) == {"backbone"}
    assert set(verified.audit.data["volumes"]) == {"data"}
    for injected in (
        "read_only", "tmpfs", "privileged", "cap_add", "cap_drop", "security_opt",
        "x-spanel-readonly-files", "x-spanel-normalized-aliases",
        "x-spanel-external-env",
    ):
        assert injected not in service


def test_new_releases_carry_no_normalization_or_transformation_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = sign_env(tmp_path)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    release = create_release(
        make_app(tmp_path),
        compose_file="compose.yml",
        tenant_id="t1",
        application_id="a1",
        operation_id="op-4",
        repo="acme/demo",
        branch="main",
        policy=POLICY,
        environ=env,
    )
    result = release_result(release)
    assert "normalization" not in result
    assert release.body.get("tool_versions") == {"schema": 1}


# --- security validations remain active -----------------------------------


def audit_codes(root: Path, compose: str) -> set[str]:
    root.joinpath("compose.yml").write_text(compose, encoding="utf-8")
    return {item.code for item in audit_project(root, "compose.yml").errors}


def test_docker_socket_bind_is_still_blocked(tmp_path: Path) -> None:
    codes = audit_codes(
        tmp_path,
        "services:\n  web:\n    image: alpine:3.20\n"
        "    volumes: ['/var/run/docker.sock:/var/run/docker.sock']\n",
    )
    assert "compose_docker_socket" in codes


def test_sensitive_and_absolute_host_binds_are_still_blocked(tmp_path: Path) -> None:
    codes = audit_codes(
        tmp_path,
        "services:\n  web:\n    image: alpine:3.20\n"
        "    volumes: ['/etc/shadow:/var/run']\n",
    )
    assert {"compose_mount_sensitive", "compose_bind_absolute"} <= codes


def test_host_namespaces_and_privilege_escalation_are_still_blocked(
    tmp_path: Path,
) -> None:
    codes = audit_codes(
        tmp_path,
        "services:\n  web:\n    image: alpine:3.20\n"
        "    privileged: true\n    cap_add: [NET_ADMIN]\n"
        "    network_mode: host\n    pid: host\n",
    )
    assert {
        "compose_privileged",
        "compose_cap_add",
        "compose_host_network_mode",
        "compose_host_pid",
    } <= codes


def test_root_user_and_published_ports_are_still_rejected(tmp_path: Path) -> None:
    codes = audit_codes(
        tmp_path,
        "services:\n  web:\n    image: alpine:3.20\n"
        "    user: '0:0'\n    ports: ['8080:80']\n",
    )
    assert {"compose_root_user", "compose_published_port"} <= codes


def test_blocking_security_findings_abort_release_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = sign_env(tmp_path)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    root = make_app(tmp_path)
    root.joinpath("compose.yml").write_text(
        COMPOSE.replace(
            '    user: "10001:10002"',
            "    user: '0:0'\n    privileged: true",
        ),
        encoding="utf-8",
    )
    with pytest.raises(Exception, match="blocking security findings"):
        create_release(
            root,
            compose_file="compose.yml",
            tenant_id="t1",
            application_id="a1",
            operation_id="op-5",
            repo="acme/demo",
            branch="main",
            policy=POLICY,
            environ=env,
        )


def test_declared_named_nonroot_user_is_respected_without_invented_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An official-style image with ``USER node`` needs no hardener at all."""

    env = sign_env(tmp_path)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    root = tmp_path / "checkout"
    root.mkdir()
    root.joinpath("compose.yml").write_text(
        "services:\n  web:\n    build: {context: ., dockerfile: Dockerfile}\n"
        "    healthcheck:\n      test: ['CMD', 'true']\n",
        encoding="utf-8",
    )
    root.joinpath("Dockerfile").write_text(
        "FROM node:20-alpine\nUSER node\nHEALTHCHECK CMD true\n", encoding="utf-8"
    )
    policy = automatic_hardening_policy({"web": {}}, {"web": "node"})
    assert policy.as_dict()["service_users"] == {}
    release = create_release(
        root,
        compose_file="compose.yml",
        tenant_id="t1",
        application_id="a1",
        operation_id="op-7",
        repo="acme/demo",
        branch="main",
        policy=policy,
        environ=env,
    )
    verified = verify_release(
        tmp_path / "state",
        release,
        environ=env,
        policy=HardeningPolicy.from_dict(release.body["policy"]),
    )
    assert verified.audit.errors == []
    assert release.policy["service_users"] == {}
    assert root.joinpath("Dockerfile").read_text().startswith("FROM node:20-alpine")


def test_signed_release_still_verifies_after_hardener_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = sign_env(tmp_path)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    release = create_release(
        make_app(tmp_path),
        compose_file="compose.yml",
        tenant_id="t1",
        application_id="a1",
        operation_id="op-6",
        repo="acme/demo",
        branch="main",
        policy=POLICY,
        environ=env,
    )
    verified = verify_release(
        tmp_path / "state", release, environ=env, policy=POLICY
    )
    assert verified.release.release_id == "op-6"
    assert verified.audit.errors == []
    assert ReleaseKeyRing.from_environ(env).active_key_id == release.key_id
