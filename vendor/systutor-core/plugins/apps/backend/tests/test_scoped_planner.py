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


def test_restoration_uses_up_no_deps_and_never_global_down(tmp_path: Path, monkeypatch) -> None:
    from plugins.apps.backend.releases import scoped_execution
    from plugins.apps.backend.runtime.types import Completed

    commands: list[list[str]] = []

    class Runner:
        transport = "local"
        environ = {}

        def run(self, argv, **_kwargs):
            commands.append(list(argv))
            return Completed(0, "", "")

    monkeypatch.setattr(
        scoped_execution, "_read_manifest",
        lambda *_args, **_kwargs: {"compose": "compose.yml"},
    )
    restored, failed = scoped_execution._restore(
        Runner(),
        project="app-demo",
        services=["frontend"],
        paths={"frontend": tmp_path / "release"},
    )
    assert restored == ["frontend"]
    assert failed == []
    flat = " ".join(commands[0])
    assert "up -d --no-deps frontend" in flat
    assert " down" not in flat
