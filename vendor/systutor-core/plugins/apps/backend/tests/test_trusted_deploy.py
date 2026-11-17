from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from plugins.apps.backend.hardening import HardeningPolicy, RuntimeUserPolicy
from plugins.apps.backend.releases import (
    ReleaseKeyRing,
    ReleaseRejected,
    ReleaseSigningUnavailable,
    TrustedRelease,
    artifact_path,
    build_artifact,
    canonical_json,
    find_release,
    key_id_for,
    load_release,
    release_store_root,
    verify_release,
    write_release,
)
from plugins.apps.backend.releases import store as store_module
from plugins.apps.backend.releases.verify import tree_digest
from plugins.apps.backend.runtime import release_deploy
from plugins.apps.backend.runtime.deployment import _image_users
from plugins.apps.backend.runtime.probes import ProbeFailed
from plugins.apps.backend.runtime.types import AppDeployError, Completed, DeployOptions

KEY = "k" * 32
POLICY = HardeningPolicy((RuntimeUserPolicy("web", 10001, 10002),), ())
COMPOSE = """services:
  web:
    build: {context: ., dockerfile: Dockerfile}
    user: "10001:10002"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    healthcheck:
      test: ["CMD", "true"]
"""
DOCKERFILE = "FROM alpine:3.20\nUSER 10001:10002\nHEALTHCHECK CMD true\n"


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    root.mkdir()
    root.joinpath("compose.yml").write_text(COMPOSE, encoding="utf-8")
    root.joinpath("Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
    return root


def make_release(
    tmp_path: Path,
    *,
    tenant: str = "t1",
    application: str = "a1",
    release_id: str = "op-1",
    key: str = KEY,
    age: int = 0,
    tree: Path | None = None,
) -> TrustedRelease:
    tree = tree or workspace(tmp_path)
    artifact = build_artifact(tree)
    created = datetime.now(UTC) - timedelta(seconds=age)
    ring = ReleaseKeyRing.from_environ({"SPANEL_APPS_RELEASE_SIGNING_KEY": key})
    policy = POLICY.as_dict()
    value = TrustedRelease(
        schema=1,
        algorithm="hmac-sha256",
        key_id=key_id_for(key.encode()),
        release_id=release_id,
        tenant_id=tenant,
        application_id=application,
        operation_id=release_id,
        repo="acme/repo",
        branch="main",
        commit="a" * 40,
        artifact_sha256=sha(artifact),
        source_tree_sha256="b" * 64,
        hardened_tree_sha256=tree_digest(tree),
        compose_path="compose.yml",
        compose_sha256=sha(tree.joinpath("compose.yml").read_bytes()),
        dockerfiles={"Dockerfile": sha(tree.joinpath("Dockerfile").read_bytes())},
        policy_sha256=sha(canonical_json(policy)),
        policy=policy,
        gate_sha256="c" * 64,
        tool_versions={"hardener": "1"},
        created_at=created.isoformat(),
        expires_at=(created + timedelta(seconds=3600)).isoformat(),
    ).sign(ring)
    write_release(tmp_path / "state", value, artifact)
    return value


def test_release_result_is_json_serializable_with_nested_normalization(
    tmp_path: Path,
) -> None:
    from plugins.apps.backend.releases.pipeline import release_result

    release = replace(
        make_release(tmp_path),
        tool_versions={
            "hardener": "1",
            "normalization": {
                "schema": 1,
                "rules": [{"id": "N1", "services": ["web"]}],
                "warnings": [{"code": "normalize_alias", "message": "x"}],
            },
        },
    )
    payload = release_result(release)
    assert payload["normalization"]["rules"][0]["id"] == "N1"
    json.dumps(payload)


def test_verified_release_roundtrip_and_store_binding(tmp_path: Path) -> None:
    release = make_release(tmp_path)
    verified = verify_release(
        tmp_path / "state", release,
        environ={"SPANEL_APPS_RELEASE_SIGNING_KEY": KEY},
        policy=POLICY,
    )
    assert verified.root == tmp_path / "state" / "private" / "staging" / "op-1"
    assert verified.audit.errors == []
    assert find_release(tmp_path / "state", "t1", "a1", "op-1") == release
    with pytest.raises(ReleaseRejected):
        load_release(tmp_path / "state", "t1", "a2", release.artifact_sha256)
    with pytest.raises(ReleaseRejected):
        find_release(tmp_path / "state", "t1", "a2", "op-1")
    with pytest.raises(ReleaseRejected):
        find_release(tmp_path / "state", "t2", "a1", "op-1")


def test_tampered_artifact_and_unknown_key_are_rejected(tmp_path: Path) -> None:
    release = make_release(tmp_path)
    path = artifact_path(
        tmp_path / "state", release.tenant_id, release.application_id,
        release.artifact_sha256,
    )
    path.write_bytes(b"replaced")
    path.chmod(0o600)
    with pytest.raises(ReleaseRejected):
        verify_release(
            tmp_path / "state", release,
            environ={"SPANEL_APPS_RELEASE_SIGNING_KEY": KEY},
        )
    with pytest.raises(ReleaseSigningUnavailable):
        verify_release(
            tmp_path / "state", release,
            environ={"SPANEL_APPS_RELEASE_SIGNING_KEY": "z" * 32},
        )


def test_compose_and_policy_changes_break_the_release(tmp_path: Path) -> None:
    tree = workspace(tmp_path)
    release = make_release(tmp_path, tree=tree)
    tree.joinpath("compose.yml").write_text(
        COMPOSE.replace('"10001:10002"', '"0:0"'), encoding="utf-8"
    )
    artifact = build_artifact(tree)
    ring = ReleaseKeyRing.from_environ({"SPANEL_APPS_RELEASE_SIGNING_KEY": KEY})
    changed = replace(
        release,
        artifact_sha256=sha(artifact),
        hardened_tree_sha256=tree_digest(tree),
    ).sign(ring)
    write_release(tmp_path / "state", changed, artifact)
    with pytest.raises(ReleaseRejected):
        verify_release(
            tmp_path / "state", changed,
            environ={"SPANEL_APPS_RELEASE_SIGNING_KEY": KEY},
        )
    with pytest.raises(ReleaseRejected):
        verify_release(
            tmp_path / "state", release,
            environ={"SPANEL_APPS_RELEASE_SIGNING_KEY": KEY},
            policy=HardeningPolicy((RuntimeUserPolicy("web", 20000, 20001),), ()),
        )


def test_verified_release_accepts_canonical_file_injection_metadata(tmp_path: Path) -> None:
    tree = workspace(tmp_path)
    tree.joinpath("proxy.cfg").write_text("frontend web\n", encoding="utf-8")
    tree.joinpath("compose.yml").write_text(
        COMPOSE.replace(
            "    healthcheck:\n",
            "    x-spanel-readonly-files:\n"
            "      - {source: proxy.cfg, target: /etc/proxy.cfg}\n"
            "    healthcheck:\n",
        ),
        encoding="utf-8",
    )
    release = make_release(tmp_path, tree=tree)
    assert verify_release(
        tmp_path / "state", release,
        environ={"SPANEL_APPS_RELEASE_SIGNING_KEY": KEY},
    ).audit.data["services"]["web"]["x-spanel-readonly-files"]


@pytest.mark.parametrize(
    "compose_extra",
    [
        "    volumes: ['./proxy.cfg:/etc/proxy.cfg:ro']\n",
        "    x-spanel-readonly-files:\n"
        "      - {source: proxy.cfg, target: /var/run/proxy.cfg}\n",
    ],
)
def test_verified_release_rejects_binds_and_unsafe_file_metadata(
    tmp_path: Path, compose_extra: str,
) -> None:
    tree = workspace(tmp_path)
    tree.joinpath("proxy.cfg").write_text("frontend web\n", encoding="utf-8")
    tree.joinpath("compose.yml").write_text(
        COMPOSE.replace("    healthcheck:\n", compose_extra + "    healthcheck:\n"),
        encoding="utf-8",
    )
    release = make_release(tmp_path, tree=tree)
    with pytest.raises(ReleaseRejected):
        verify_release(
            tmp_path / "state", release,
            environ={"SPANEL_APPS_RELEASE_SIGNING_KEY": KEY},
        )


def test_expired_release_is_rejected_but_can_be_audited_for_rollback(
    tmp_path: Path,
) -> None:
    release = make_release(tmp_path, age=7200)
    with pytest.raises(ReleaseRejected):
        verify_release(
            tmp_path / "state", release,
            environ={"SPANEL_APPS_RELEASE_SIGNING_KEY": KEY},
        )
    verified = verify_release(
        tmp_path / "state", release,
        environ={"SPANEL_APPS_RELEASE_SIGNING_KEY": KEY},
        require_expiry=False,
    )
    assert verified.release == release


def test_deploy_trusted_requires_a_signing_key_before_external_io(
    tmp_path: Path,
) -> None:
    release = make_release(tmp_path)
    runner = FakeRunner({})
    with pytest.raises(ReleaseSigningUnavailable):
        release_deploy.deploy_trusted(
            release,
            DeployOptions(project="app-demo", release_id="op-1"),
            runner,
        )
    assert runner.calls == []


class FakeRunner:
    transport = "local"
    host = "local"

    def __init__(self, environ: dict[str, str]) -> None:
        self.environ = dict(environ)
        self.calls: list[list[str]] = []

    def run(self, argv, *, timeout=600, check=True, **_kwargs):
        self.calls.append(list(argv))
        if argv[:4] == ["docker", "compose", "--project-name", "app-demo"]:
            if "pull" in argv or "build" in argv or "up" in argv or "down" in argv:
                return Completed(0)
        if argv[:3] == ["docker", "image", "inspect"]:
            return Completed(0, "sha256:" + "a" * 64)
        return Completed(0)


def prepare_deploy(monkeypatch, tmp_path: Path):
    release = make_release(tmp_path)
    monkeypatch.setattr(release_deploy, "_ensure_owned", lambda *_args: None)
    monkeypatch.setattr(release_deploy, "_stage_release", lambda *_args: None)
    monkeypatch.setattr(
        release_deploy, "_validate_compose_environment", lambda *_args: None
    )
    monkeypatch.setattr(
        release_deploy, "_image_users", lambda *_args: {"web": "img:latest"}
    )
    monkeypatch.setattr(release_deploy, "_containers", lambda *_args: {"web": "cid1"})
    monkeypatch.setattr(release_deploy, "_verify_containers", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(release_deploy, "_write_manifest", lambda *_args: None)
    monkeypatch.setattr(release_deploy, "_container_names", lambda *_args: {"web": "x"})
    monkeypatch.setattr(release_deploy, "runtime_snapshot", lambda *_args: {})
    published: list[dict] = []
    monkeypatch.setattr(
        release_deploy, "_publish_release_state",
        lambda _runner, _path, manifest: published.append(dict(manifest)),
    )
    environ = {
        "SPANEL_APPS_STATE_ROOT": str(tmp_path / "state"),
        "SPANEL_APPS_RELEASE_SIGNING_KEY": KEY,
        "SPANEL_APPS_PROBE_IMAGE": "probe@sha256:" + "d" * 64,
        "SPANEL_APPS_PROBE_COMMAND": '["true"]',
        "SPANEL_APPS_PROBE_CHECKS": "1",
        "SPANEL_APPS_PROBE_WINDOW_SECONDS": "0",
    }
    runner = FakeRunner(environ)
    return release, runner, published


def test_deploy_trusted_publishes_only_after_probes(monkeypatch, tmp_path: Path) -> None:
    release, runner, published = prepare_deploy(monkeypatch, tmp_path)
    monkeypatch.setattr(
        release_deploy, "run_probes",
        lambda *_args, **_kwargs: {"isolation": {}, "functional": {}, "stability": {}},
    )
    manifest = release_deploy.deploy_trusted(
        release,
        DeployOptions(project="app-demo", release_id="op-1"),
        runner,
    )
    assert manifest["status"] == "running"
    assert manifest["hardened_release"]["artifact_sha256"] == release.artifact_sha256
    assert manifest["image_ids"] == {"web": "sha256:" + "a" * 64}
    assert manifest["probes"]["stability"] == {}
    assert published and published[-1]["status"] == "running"


def test_deploy_orders_create_copy_and_up_without_recreate(monkeypatch, tmp_path: Path) -> None:
    release, runner, _published = prepare_deploy(monkeypatch, tmp_path)
    monkeypatch.setattr(release_deploy, "run_probes", lambda *_args, **_kwargs: {})

    def inject(*_args, **_kwargs):
        runner.calls.append(["test-copy"])

    monkeypatch.setattr(release_deploy, "_inject_readonly_files", inject)
    release_deploy.deploy_trusted(
        release, DeployOptions(project="app-demo", release_id="op-1"), runner,
    )
    create_index = next(i for i, call in enumerate(runner.calls) if "create" in call)
    copy_index = runner.calls.index(["test-copy"])
    up_index = next(i for i, call in enumerate(runner.calls) if "up" in call)
    assert create_index < copy_index < up_index
    assert "--no-recreate" in runner.calls[up_index]


def test_file_injection_uses_mode_0444_and_separate_argv(tmp_path: Path) -> None:
    release = tmp_path / "app" / "releases" / "op-1"
    source = release / "source"
    source.mkdir(parents=True)
    source.joinpath("compose.yml").write_text("services: {}\n", encoding="utf-8")
    source.joinpath("proxy.cfg").write_text("frontend web\n", encoding="utf-8")
    runner = FakeRunner({})
    release_deploy._inject_readonly_files(
        runner,
        release,
        "compose.yml",
        {"web": "cid1"},
        {"web": {"x-spanel-readonly-files": [
            {"source": "proxy.cfg", "target": "/etc/proxy.cfg"}
        ]}},
    )
    assert any(call[:2] == ["chmod", "0444"] for call in runner.calls)
    assert any(call[:2] == ["docker", "cp"] and call[-1] == "cid1:/"
               for call in runner.calls)


def test_file_injection_preserves_executable_mode(tmp_path: Path) -> None:
    release = tmp_path / "app" / "releases" / "op-1"
    source = release / "source"
    source.mkdir(parents=True)
    source.joinpath("compose.yml").write_text("services: {}\n", encoding="utf-8")
    source.joinpath("check.sh").write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
    runner = FakeRunner({})
    release_deploy._inject_readonly_files(
        runner,
        release,
        "compose.yml",
        {"db": "cid1"},
        {"db": {"x-spanel-readonly-files": [
            {
                "source": "check.sh",
                "target": "/healthchecks/check.sh",
                "mode": "0555",
            }
        ]}},
    )
    assert any(call[:2] == ["chmod", "0555"] for call in runner.calls)
    assert any(call[:2] == ["docker", "cp"] and call[-1] == "cid1:/"
               for call in runner.calls)


def test_copy_failure_runs_down_cleanup(monkeypatch, tmp_path: Path) -> None:
    release, runner, published = prepare_deploy(monkeypatch, tmp_path)

    def fail_copy(*_args, **_kwargs):
        raise AppDeployError("failed to inject a read-only release file")

    monkeypatch.setattr(release_deploy, "_inject_readonly_files", fail_copy)
    with pytest.raises(AppDeployError, match="failed to inject"):
        release_deploy.deploy_trusted(
            release, DeployOptions(project="app-demo", release_id="op-1"), runner,
        )
    assert published == []
    assert any("down" in call for call in runner.calls)
    assert not any("up" in call for call in runner.calls)


def test_probe_failure_tears_down_and_never_publishes(monkeypatch, tmp_path: Path) -> None:
    release, runner, published = prepare_deploy(monkeypatch, tmp_path)

    def fail(*_args, **_kwargs):
        raise ProbeFailed("the independent functional probe failed")

    monkeypatch.setattr(release_deploy, "run_probes", fail)
    with pytest.raises(ProbeFailed):
        release_deploy.deploy_trusted(
            release,
            DeployOptions(project="app-demo", release_id="op-1"),
            runner,
        )
    assert published == []
    assert any("down" in call for call in runner.calls)


def test_image_users_ignores_services_absent_from_rendered_config() -> None:
    """Compose omits inactive-profile services from `config --format json`."""

    class ConfigRunner:
        transport = "local"
        environ: dict[str, str] = {}

        def run(self, argv, **_kwargs):
            if "config" in argv:
                rendered = {"services": {"web": {"image": "web:1"}}}
                return Completed(0, json.dumps(rendered))
            if "inspect" in argv and "image" in argv:
                return Completed(0, "10001:10002")
            return Completed(0)

    users = _image_users(
        ConfigRunner(), Path("."), "compose.yml", "app-demo", True,
        ["web", "seed"],
    )
    assert users == {"web": "web:1"}


def test_release_store_root_matches_the_apps_state_root(tmp_path: Path) -> None:
    assert release_store_root({
        "SPANEL_APPS_STATE_ROOT": str(tmp_path),
    }) == tmp_path
    assert store_module.MAX_DESCRIPTOR_BYTES > 1024
    assert json.loads(canonical_json({"b": 1, "a": 2})) == {"a": 2, "b": 1}
