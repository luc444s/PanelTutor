from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from plugins.apps.backend.releases.fingerprints import (
    build_context_digest,
    compute_fingerprints,
    sanitize_service_config,
)
from plugins.apps.backend.releases.planner import (
    DeployPlan,
    DeployScope,
    active_state,
    plan_deployment,
)
from plugins.apps.backend.releases.trusted import (
    ReleaseRejected,
    TrustedRelease,
)
from plugins.apps.backend.runtime.audit import audit_project
from plugins.apps.backend.runtime.deployment import _override

COMPOSE = """services:
  frontend:
    build: {context: ./frontend, dockerfile: Dockerfile}
    user: "10001:10002"
    environment:
      VITE_API_URL: "https://example.test"
      JWT_SECRET_KEY: "super-secret-value"
  database:
    build: {context: ./database, dockerfile: Dockerfile}
    user: "10001:10002"
volumes:
  data:
"""


def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    (root / "frontend" / "public").mkdir(parents=True)
    (root / "database").mkdir()
    root.joinpath("compose.yml").write_text(COMPOSE, encoding="utf-8")
    root.joinpath("frontend", "Dockerfile").write_text(
        "FROM alpine:3.20\nUSER 10001:10002\n", encoding="utf-8"
    )
    root.joinpath("frontend", "index.html").write_text("hello", encoding="utf-8")
    root.joinpath("database", "Dockerfile").write_text(
        "FROM alpine:3.20\nUSER 10001:10002\n", encoding="utf-8"
    )
    root.joinpath("database", "init.sql").write_text("select 1;", encoding="utf-8")
    return root


def release(
    service_fingerprints: dict[str, str],
    shared: str,
    release_id: str = "release-global",
) -> TrustedRelease:
    return TrustedRelease(
        schema=1,
        algorithm="hmac-sha256",
        key_id="a" * 8,
        release_id=release_id,
        tenant_id="t1",
        application_id="a1",
        operation_id=release_id,
        repo="acme/repo",
        branch="main",
        commit="a" * 40,
        artifact_sha256="b" * 64,
        source_tree_sha256="c" * 64,
        hardened_tree_sha256="d" * 64,
        compose_path="compose.yml",
        compose_sha256="e" * 64,
        dockerfiles={"frontend/Dockerfile": "f" * 64},
        policy_sha256=hashlib.sha256(b"{}").hexdigest(),
        policy={"service_users": {}, "writable_paths": []},
        gate_sha256="1" * 64,
        tool_versions={"hardener": "1"},
        created_at="2026-01-01T00:00:00+00:00",
        expires_at="2026-01-02T00:00:00+00:00",
        service_fingerprints=service_fingerprints,
        shared_fingerprint=shared,
    )


def active_manifest(fps: dict[str, str], shared: str) -> dict:
    return {
        "service_fingerprints": fps,
        "shared_fingerprint": shared,
        "service_releases": {name: "release-global" for name in fps},
        "containers": {name: f"cid-{name}" for name in fps},
    }


def test_fingerprints_are_stable_and_do_not_contain_environment_values(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    audit = audit_project(root, "compose.yml", non_root=True)
    first = compute_fingerprints(root, audit)
    second = compute_fingerprints(root, audit)
    assert first == second
    assert set(first["service_fingerprints"]) == {"frontend", "database"}
    assert "super-secret-value" not in repr(first)
    sanitized = sanitize_service_config(audit.data["services"]["frontend"])
    assert sanitized["environment_names"] == ["JWT_SECRET_KEY", "VITE_API_URL"]
    assert "super-secret-value" not in repr(sanitized)


def test_exclusive_frontend_change_selects_only_frontend(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    before = compute_fingerprints(
        root, audit_project(root, "compose.yml", non_root=True)
    )
    root.joinpath("frontend", "public", "test.md").write_text("canary", encoding="utf-8")
    after = compute_fingerprints(
        root, audit_project(root, "compose.yml", non_root=True)
    )
    assert before["shared_fingerprint"] == after["shared_fingerprint"]
    assert before["service_fingerprints"]["database"] == after["service_fingerprints"]["database"]
    assert before["service_fingerprints"]["frontend"] != after["service_fingerprints"]["frontend"]
    plan = plan_deployment(
        release(after["service_fingerprints"], after["shared_fingerprint"]),
        active_manifest(before["service_fingerprints"], before["shared_fingerprint"]),
    )
    assert plan.effective_services == ("frontend",)
    assert plan.strategy == "incremental"
    assert plan.fallback_reason is None


def test_global_change_forces_fallback_and_complete_release(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    before = compute_fingerprints(
        root, audit_project(root, "compose.yml", non_root=True)
    )
    root.joinpath("compose.yml").write_text(
        COMPOSE + "networks:\n  extra:\n", encoding="utf-8"
    )
    after = compute_fingerprints(
        root, audit_project(root, "compose.yml", non_root=True)
    )
    assert before["shared_fingerprint"] != after["shared_fingerprint"]
    plan = plan_deployment(
        release(after["service_fingerprints"], after["shared_fingerprint"]),
        active_manifest(before["service_fingerprints"], before["shared_fingerprint"]),
    )
    assert set(plan.effective_services) == {"frontend", "database"}
    assert plan.strategy == "fallback"
    assert plan.fallback_reason == "shared_configuration_changed"


def test_incomplete_active_state_and_unknown_service_fall_back_safely() -> None:
    fps = {"frontend": "a" * 64, "database": "b" * 64}
    target = release(fps, "c" * 64)
    plan = plan_deployment(target, {"service_fingerprints": {"frontend": "a" * 64}})
    assert plan.strategy == "fallback"
    assert plan.fallback_reason == "active_state_incomplete"
    with pytest.raises(ReleaseRejected):
        plan_deployment(target, None, DeployScope("service", "worker"))
    assert plan_deployment(target, None).strategy == "initial"


def test_global_action_clears_overrides_and_service_action_keeps_them() -> None:
    previous = active_manifest(
        {"frontend": "f" * 64, "database": "d" * 64}, "c" * 64
    )
    previous["overrides"] = ["frontend"]
    target = release({"frontend": "f2" * 32, "database": "d" * 64}, "c" * 64, "release-new")
    service_plan = plan_deployment(
        target, previous, DeployScope("service", "database")
    )
    state = active_state(previous, target, service_plan, ["database", "frontend"])
    assert state["overrides"] == ["database", "frontend"]
    assert state["service_releases"]["database"] == "release-new"
    global_plan = plan_deployment(target, previous, DeployScope("global"))
    state = active_state(previous, target, global_plan, ["database", "frontend"])
    assert state["overrides"] == []
    assert state["service_releases"] == {
        "database": "release-new", "frontend": "release-new",
    }
    assert state["global_release_id"] == "release-new"


def test_noop_global_plan_is_verifiable_and_does_not_recreate() -> None:
    fps = {"frontend": "a" * 64, "database": "b" * 64}
    target = release(fps, "c" * 64)
    plan = plan_deployment(target, active_manifest(fps, "c" * 64))
    assert plan.strategy == "noop"
    assert plan.effective_services == ()
    assert isinstance(plan, DeployPlan)


def test_dockerignore_excludes_context_noise(tmp_path: Path) -> None:
    context = tmp_path / "ctx"
    context.mkdir()
    context.joinpath("Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
    context.joinpath(".dockerignore").write_text("node_modules\n*.log\n", encoding="utf-8")
    context.joinpath("app.js").write_text("x", encoding="utf-8")
    first = build_context_digest(context, context / "Dockerfile")
    context.joinpath("debug.log").write_text("noise", encoding="utf-8")
    (context / "node_modules").mkdir()
    context.joinpath("node_modules", "pkg.js").write_text("dep", encoding="utf-8")
    assert build_context_digest(context, context / "Dockerfile") == first
    context.joinpath("app.js").write_text("y", encoding="utf-8")
    assert build_context_digest(context, context / "Dockerfile") != first


def test_release_override_uses_immutable_build_image_tags() -> None:
    rendered = _override(
        {
            "services": {
                "frontend": {"build": {"context": "."}},
                "database": {"image": "postgres:16-alpine"},
            }
        },
        "app-demo",
        True,
        image_tag="release-123",
    )
    assert "spanel-app-" in rendered
    assert ":release-123" in rendered
    assert "postgres:16-alpine" not in rendered


def test_compose_failure_reason_reports_unhealthy_and_exited() -> None:
    from plugins.apps.backend.releases.scoped_execution import compose_failure_reason

    assert compose_failure_reason([
        {"Service": "database", "State": "running", "Health": "unhealthy"},
        {"Service": "backend", "State": "exited", "ExitCode": 1},
        {"Service": "frontend", "State": "running", "Health": "healthy"},
    ]) == "backend exited with code 1; database is unhealthy"
    assert compose_failure_reason([]) is None
    assert compose_failure_reason({"services": {"db": {"State": "dead"}}}) is not None


def test_fallback_probe_target_prefers_ingress_and_skips_datastores() -> None:
    from plugins.apps.backend.releases.scoped_execution import fallback_probe_target

    assert fallback_probe_target({
        "database": {"expose": ["5432"]},
        "backend": {"expose": ["8000"]},
        "frontend": {"expose": ["8080"]},
    }) == ("frontend", 8080)
    assert fallback_probe_target({
        "database": {"expose": ["5432"]},
        "api": {"ports": [{"target": 9000}]},
    }) == ("api", 9000)
    assert fallback_probe_target({
        "database": {"expose": ["5432"]},
        "alpha": {"expose": ["8080"]},
        "beta": {"expose": ["8081"]},
    }) is None
    assert fallback_probe_target({"database": {"expose": ["5432"]}}) is None


def test_env_path_falls_back_to_legacy_release_layout(tmp_path: Path) -> None:
    from plugins.apps.backend.runtime.deployment import _env_path

    project = tmp_path / "project"
    release = project / "releases" / "legacy"
    release.mkdir(parents=True)
    legacy = release / "app.env"
    legacy.write_text("A=1\n", encoding="utf-8")
    assert _env_path(release) == legacy

    private = project / "private" / "legacy" / "app.env"
    private.parent.mkdir(parents=True)
    private.write_text("A=2\n", encoding="utf-8")
    assert _env_path(release) == private


def test_restoration_uses_up_no_deps_and_never_global_down(tmp_path: Path, monkeypatch) -> None:
    from plugins.apps.backend.releases import scoped_execution
    from plugins.apps.backend.runtime.types import Completed

    class Runner:
        transport = "local"
        environ = {}

        def __init__(self) -> None:
            self.commands: list[list[str]] = []

        def run(self, argv, **_kwargs):
            self.commands.append(list(argv))
            if list(argv)[-3:] == ["ps", "-q", "frontend"]:
                return Completed(0, "container123\n", "")
            return Completed(0, "", "")

    monkeypatch.setattr(
        scoped_execution, "_read_manifest",
        lambda *_args, **_kwargs: {"compose": "compose.yml"},
    )
    runner = Runner()
    restored, failed, containers, composes = scoped_execution._restore(
        runner,
        project="app-demo",
        services=["frontend"],
        paths={"frontend": tmp_path / "release"},
    )
    assert restored == ["frontend"]
    assert failed == []
    assert containers == {"frontend": "container123"}
    assert composes == {"frontend": "compose.yml"}
    flat = " ".join(runner.commands[0])
    assert "up -d --no-deps frontend" in flat
    assert " down" not in flat


def test_restoration_recreates_group_in_one_compose_call(
    tmp_path: Path, monkeypatch
) -> None:
    from plugins.apps.backend.releases import scoped_execution
    from plugins.apps.backend.runtime.types import Completed

    class Runner:
        transport = "local"
        environ = {}

        def __init__(self) -> None:
            self.commands: list[list[str]] = []

        def run(self, argv, **_kwargs):
            self.commands.append(list(argv))
            if "ps" in argv and "-q" in argv:
                return Completed(0, f"cid-{argv[-1]}\n", "")
            return Completed(0, "", "")

    monkeypatch.setattr(
        scoped_execution, "_read_manifest",
        lambda *_args, **_kwargs: {"compose": "compose.yml"},
    )
    runner = Runner()
    release_path = tmp_path / "release"
    restored, failed, containers, composes = scoped_execution._restore(
        runner,
        project="app-demo",
        services=["backend", "frontend"],
        paths={"backend": release_path, "frontend": release_path},
    )
    assert restored == ["backend", "frontend"]
    assert failed == []
    assert containers == {"backend": "cid-backend", "frontend": "cid-frontend"}
    assert composes == {"backend": "compose.yml", "frontend": "compose.yml"}
    ups = [command for command in runner.commands if "up" in command]
    assert len(ups) == 1
    flat = " ".join(ups[0])
    assert "up -d --no-deps backend frontend" in flat


def _scoped_failure_env(tmp_path: Path, monkeypatch, *, probes):
    """Drive deploy_scoped through a failed scoped deploy + restoration."""

    from types import SimpleNamespace

    from plugins.apps.backend.releases import scoped_execution
    from plugins.apps.backend.releases.planner import DeployPlan
    from plugins.apps.backend.runtime.types import AppDeployError, Completed

    previous_release = tmp_path / "releases" / "release-previous"
    previous_release.mkdir(parents=True)
    staged = tmp_path / "releases" / "op-failed"
    written: dict = {}

    class Runner:
        transport = "local"
        environ = {}
        host = "local"

        def __init__(self) -> None:
            self.commands: list[list[str]] = []

        def run(self, argv, **_kwargs):
            argv = list(argv)
            self.commands.append(argv)
            if argv[:4] == ["docker", "container", "inspect", "-f"]:
                return Completed(
                    0, f"{argv[-1]}|sha256:img|2026-01-01T00:00:00Z|0\n", ""
                )
            if argv[:3] == ["docker", "image", "inspect"]:
                return Completed(0, "sha256:img\n", "")
            return Completed(0, "", "")

    monkeypatch.setattr(scoped_execution, "HardeningPolicy", SimpleNamespace(
        from_dict=lambda _value: object()
    ))
    monkeypatch.setattr(
        scoped_execution, "verify_release",
        lambda *_a, **_k: SimpleNamespace(
            audit=SimpleNamespace(
                errors=[],
                root=tmp_path,
                data={"services": {"frontend": {}, "backend": {}}},
            ),
        ),
    )
    monkeypatch.setattr(scoped_execution, "_state_root", lambda *_a, **_k: tmp_path)
    monkeypatch.setattr(scoped_execution, "_ensure_owned", lambda *_a, **_k: None)
    monkeypatch.setattr(scoped_execution, "_override", lambda *_a, **_k: "override")
    monkeypatch.setattr(scoped_execution, "_stage_release", lambda *_a, **_k: None)
    monkeypatch.setattr(
        scoped_execution, "_env_path", lambda *_a, **_k: tmp_path / "app.env"
    )
    monkeypatch.setattr(
        scoped_execution, "_validate_compose_environment", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        scoped_execution, "_image_users",
        lambda *_a, **_k: {"frontend": "spanel-app-x:op-failed"},
    )
    monkeypatch.setattr(
        scoped_execution, "_manifest_data",
        lambda options, *_a, **_k: {"release": options.release_id},
    )
    monkeypatch.setattr(
        scoped_execution, "_write_manifest",
        lambda _runner, _release, payload: written.update(payload),
    )
    monkeypatch.setattr(scoped_execution, "_publish_release_state", lambda *_a: None)
    monkeypatch.setattr(
        scoped_execution, "_container_names", lambda *_a, **_k: {},
    )
    monkeypatch.setattr(
        scoped_execution, "runtime_snapshot",
        lambda _runner, containers: {
            name: {"container_id": value, "status": "running"}
            for name, value in containers.items()
        },
    )
    verify_calls = {"count": 0}

    def fail_first_verification(*_a, **_k):
        verify_calls["count"] += 1
        if verify_calls["count"] == 1:
            raise AppDeployError("frontend broke")

    monkeypatch.setattr(
        scoped_execution, "_verify_containers", fail_first_verification,
    )
    monkeypatch.setattr(
        scoped_execution, "_read_manifest",
        lambda *_a, **_k: {"compose": "compose.yml"},
    )

    def fake_containers(_runner, release, _compose, _project, _env, services):
        if Path(release) == previous_release:
            return {name: f"restored-{name}" for name in services}
        return {name: f"new-{name}" for name in services}

    monkeypatch.setattr(scoped_execution, "_containers", fake_containers)
    monkeypatch.setattr(scoped_execution, "run_probes", probes)

    previous_manifest = {
        "compose": "compose.yml",
        "services": ["backend", "frontend"],
        "service_releases": {"backend": "release-previous",
                             "frontend": "release-previous"},
        "service_release_paths": {"backend": str(previous_release),
                                  "frontend": str(previous_release)},
        "containers": {"backend": "cid-backend", "frontend": "cid-old"},
        "images": {}, "image_ids": {},
    }
    plan = DeployPlan(
        requested_scope="service",
        requested_service="frontend",
        effective_services=("frontend",),
        strategy="service",
    )
    return (
        scoped_execution, Runner(), previous_release, previous_manifest, plan,
        staged, written,
    )


def test_global_plan_with_previous_state_uses_single_up(
    tmp_path: Path, monkeypatch
) -> None:
    from plugins.apps.backend.releases.planner import DeployPlan

    probes = {"isolation": {"frontend": {}}, "functional": {"checks": [{}]},
              "stability": {"restart_counts": {"frontend": 0, "backend": 0}}}
    (scoped_execution, runner, previous_release, previous_manifest, _plan,
     staged, _written) = _scoped_failure_env(
        tmp_path, monkeypatch, probes=lambda *_a, **_k: probes,
    )
    monkeypatch.setattr(scoped_execution, "_verify_containers", lambda *_a, **_k: None)
    plan = DeployPlan(
        requested_scope="global",
        requested_service=None,
        effective_services=("backend", "frontend"),
        strategy="global",
        fallback_reason="active_state_incomplete",
    )
    manifest = scoped_execution.deploy_scoped(
        runner,
        release({"frontend": "f" * 64, "backend": "b" * 64}, "c" * 64),
        plan=plan,
        scope=plan.requested_scope,
        project="app-demo",
        previous_manifest=previous_manifest,
        previous_release=previous_release,
        env_file=None,
        staging_id=staged.name,
    )
    ups = [command for command in runner.commands if "up" in command]
    assert len(ups) == 1
    assert "--no-deps" not in ups[0]
    assert manifest["status"] == "running"


def test_failed_scoped_deploy_restores_and_verifies_without_name_errors(
    tmp_path: Path, monkeypatch
) -> None:
    from plugins.apps.backend.releases.scoped_execution import ScopedDeployFailed

    probes = {"isolation": {"frontend": {}}, "functional": {"checks": [{}]},
              "stability": {"restart_counts": {"frontend": 0, "backend": 0}}}
    (scoped_execution, runner, previous_release, previous_manifest, plan,
     staged, _written) = _scoped_failure_env(
        tmp_path, monkeypatch, probes=lambda *_a, **_k: probes,
    )
    with pytest.raises(ScopedDeployFailed) as raised:
        scoped_execution.deploy_scoped(
            runner,
            release({"frontend": "f" * 64, "backend": "b" * 64}, "c" * 64),
            plan=plan,
            scope=plan.requested_scope,
            project="app-demo",
            previous_manifest=previous_manifest,
            previous_release=previous_release,
            env_file=None,
            staging_id=staged.name,
        )
    restoration = raised.value.manifest["restoration"]
    assert restoration["restored"] == ["frontend"]
    assert restoration["failed"] == []
    assert restoration["verified"] is True
    assert restoration["probes"] == probes
    assert restoration["container_ids"] == {
        "backend": "cid-backend", "frontend": "restored-frontend",
    }
    assert restoration["service_runtime"]["frontend"]["container_id"] == (
        "restored-frontend"
    )


def test_failed_scoped_deploy_keeps_identities_when_restored_probes_fail(
    tmp_path: Path, monkeypatch
) -> None:
    from plugins.apps.backend.releases.scoped_execution import ScopedDeployFailed
    from plugins.apps.backend.runtime.probes import ProbeFailed

    def probes(*_a, **_k):
        raise ProbeFailed("the independent functional probe failed")

    (scoped_execution, runner, previous_release, previous_manifest, plan,
     staged, _written) = _scoped_failure_env(
        tmp_path, monkeypatch, probes=probes,
    )
    with pytest.raises(ScopedDeployFailed) as raised:
        scoped_execution.deploy_scoped(
            runner,
            release({"frontend": "f" * 64, "backend": "b" * 64}, "c" * 64),
            plan=plan,
            scope=plan.requested_scope,
            project="app-demo",
            previous_manifest=previous_manifest,
            previous_release=previous_release,
            env_file=None,
            staging_id=staged.name,
        )
    restoration = raised.value.manifest["restoration"]
    assert restoration["failed"] == ["probes"]
    assert restoration["probe_error"] == "the independent functional probe failed"
    assert "verified" not in restoration
    # The restored identities must still be published so the active state never
    # points at the container the failed deployment destroyed.
    assert restoration["container_ids"]["frontend"] == "restored-frontend"


def test_unrecoverable_restoration_reports_partial_identities(
    tmp_path: Path, monkeypatch
) -> None:
    from plugins.apps.backend.releases.scoped_execution import ScopedRestoreError
    from plugins.apps.backend.runtime.types import AppDeployError

    proxies = {"probes": lambda *_a, **_k: {}}
    (scoped_execution, runner, previous_release, previous_manifest, plan,
     staged, _written) = _scoped_failure_env(
        tmp_path, monkeypatch, probes=proxies["probes"],
    )

    def failing_containers(_runner, release, *_args):
        if Path(release) == previous_release:
            raise AppDeployError("the previous release did not recreate the service")
        return {"backend": "new-backend", "frontend": "new-frontend"}

    monkeypatch.setattr(scoped_execution, "_containers", failing_containers)
    with pytest.raises(ScopedRestoreError) as raised:
        scoped_execution.deploy_scoped(
            runner,
            release({"frontend": "f" * 64, "backend": "b" * 64}, "c" * 64),
            plan=plan,
            scope=plan.requested_scope,
            project="app-demo",
            previous_manifest=previous_manifest,
            previous_release=previous_release,
            env_file=None,
            staging_id=staged.name,
        )
    restoration = raised.value.manifest["restoration"]
    assert restoration["failed"] == ["frontend"]
    assert restoration["container_ids"] == {"backend": "cid-backend"}
