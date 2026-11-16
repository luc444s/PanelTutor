from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from plugins.apps.backend.hardening.contracts import (
    HardeningPolicy,
    RuntimeUserEvidence,
    RuntimeUserPolicy,
    automatic_hardening_policy,
    resolve_hardening_policy,
)
from plugins.apps.backend.runtime.deployment import _manifest_data
from plugins.apps.backend.runtime.types import AppDeployError, Completed, DeployOptions
from plugins.apps.backend.runtime.volumes import (
    prepare_runtime_volumes,
    resolve_runtime_volumes,
)


class VolumeRunner:
    transport = "local"
    host = "local"

    def __init__(self, owners: dict[str, str] | None = None) -> None:
        self.environ = {
            "SPANEL_APPS_PROBE_IMAGE": "probe@sha256:" + "a" * 64,
        }
        self.owners = dict(owners or {})
        self.calls: list[list[str]] = []

    def run(self, argv, *, check=True, **_kwargs):
        call = list(argv)
        self.calls.append(call)
        if call[:3] == ["docker", "volume", "inspect"]:
            return Completed(0 if call[3] in self.owners else 1)
        if call[:3] == ["docker", "volume", "create"]:
            self.owners[call[-1]] = "0:0"
            return Completed(0, call[-1])
        if call[:2] == ["docker", "run"]:
            mount = call[call.index("-v") + 1]
            name = mount.split(":", 1)[0]
            entrypoint = call[call.index("--entrypoint") + 1]
            image_index = call.index(self.environ["SPANEL_APPS_PROBE_IMAGE"])
            command = call[image_index + 1:]
            if entrypoint == "stat":
                return Completed(0, self.owners[name] + "\n")
            if entrypoint == "chown":
                self.owners[name] = command[0]
            return Completed(0)
        return Completed(0)


def policy(*users: tuple[str, int, int, str]) -> HardeningPolicy:
    return HardeningPolicy(
        tuple(RuntimeUserPolicy(name, uid, gid) for name, uid, gid, _source in users),
        runtime_users=tuple(
            RuntimeUserEvidence(name, f"{uid}:{gid}", f"{uid}:{gid}", source)
            for name, uid, gid, source in users
        ),
    )


def test_desired_user_precedence_policy_compose_dockerfile_then_default() -> None:
    explicit = policy(("web", 2000, 2001, "policy"))
    resolved = resolve_hardening_policy(
        explicit, {"web": {"user": "3000:3001"}}, {"web": "4000:4001"}
    )
    assert resolved.as_dict()["runtime_users"]["web"]["source"] == "policy"
    compose = automatic_hardening_policy(
        {"web": {"user": "3000:3001"}}, {"web": "4000:4001"}
    )
    assert compose.as_dict()["runtime_users"]["web"]["source"] == "compose"
    dockerfile = automatic_hardening_policy({"web": {}}, {"web": "4000:4001"})
    assert dockerfile.as_dict()["runtime_users"]["web"]["source"] == "dockerfile"
    fallback = automatic_hardening_policy({"web": {}}, {})
    assert fallback.as_dict()["runtime_users"]["web"] == {
        "requested": "1000:1000",
        "effective": "1000:1000",
        "source": "policy",
    }


def test_named_dockerfile_users_fall_back_before_volume_owner_resolution() -> None:
    generated = automatic_hardening_policy(
        {"backend": {}, "database": {}, "frontend": {}},
        {"backend": "app", "database": "postgres", "frontend": "101"},
    )
    assert generated.as_dict()["service_users"] == {
        "backend": {"uid": 1000, "gid": 1000},
        "database": {"uid": 1000, "gid": 1000},
        "frontend": {"uid": 101, "gid": 101},
    }


def test_compose_volume_names_with_and_without_explicit_name() -> None:
    runner = VolumeRunner({"app-demo_data": "1000:1000", "postgres-data": "1000:1000"})
    data = {
        "services": {"web": {"volumes": ["data:/data", "db:/db"]}},
        "volumes": {"data": {}, "db": {"name": "postgres-data"}},
    }
    resolved = resolve_runtime_volumes(
        runner, data, "app-demo", policy(("web", 1000, 1000, "policy"))
    )
    assert [item.name for item in resolved.runtime_volumes] == [
        "app-demo_data", "postgres-data"
    ]


def test_new_volume_is_labeled_initialized_and_helper_is_isolated() -> None:
    runner = VolumeRunner()
    data = {"services": {"web": {"volumes": ["data:/data"]}}, "volumes": {"data": {}}}
    resolved = resolve_runtime_volumes(
        runner, data, "app-demo", policy(("web", 1000, 1001, "policy"))
    )
    prepare_runtime_volumes(runner, "app-demo", resolved, ["web"])
    assert runner.owners == {"app-demo_data": "1000:1001"}
    assert [
        "docker", "volume", "create", "--label", "io.spanel.app.owner=app-demo",
        "app-demo_data",
    ] in runner.calls
    helper_calls = [call for call in runner.calls if call[:2] == ["docker", "run"]]
    assert all(
        "--network" in call and call[call.index("--network") + 1] == "none"
        for call in helper_calls
    )
    assert all(
        "-p" not in call and "/var/run/docker.sock" not in " ".join(call)
        for call in helper_calls
    )
    assert any("--cap-add" in call and "CHOWN" in call for call in helper_calls)


def test_existing_non_root_owner_becomes_effective_without_chown() -> None:
    runner = VolumeRunner({"app-demo_data": "70:70"})
    data = {"services": {"db": {"volumes": ["data:/data"]}}, "volumes": {"data": {}}}
    resolved = resolve_runtime_volumes(
        runner, data, "app-demo", policy(("db", 1000, 1000, "policy"))
    )
    assert resolved.as_dict()["service_users"]["db"] == {"uid": 70, "gid": 70}
    assert resolved.as_dict()["runtime_users"]["db"] == {
        "requested": "1000:1000", "effective": "70:70",
        "source": "volume-owner", "volume": "app-demo_data",
    }
    prepare_runtime_volumes(runner, "app-demo", resolved, ["db"])
    assert not any("chown" in call for call in runner.calls)


def test_existing_root_volume_fails_closed() -> None:
    runner = VolumeRunner({"app-demo_data": "0:0"})
    data = {"services": {"db": {"volumes": ["data:/data"]}}, "volumes": {"data": {}}}
    with pytest.raises(AppDeployError, match="owned by root"):
        resolve_runtime_volumes(
            runner, data, "app-demo", policy(("db", 1000, 1000, "policy"))
        )


def test_external_volume_is_inspected_but_never_initialized() -> None:
    runner = VolumeRunner({"shared-data": "70:70"})
    data = {
        "services": {"db": {"volumes": ["data:/data"]}},
        "volumes": {"data": {"name": "shared-data", "external": True}},
    }
    resolved = resolve_runtime_volumes(
        runner, data, "app-demo", policy(("db", 1000, 1000, "policy"))
    )
    prepare_runtime_volumes(runner, "app-demo", resolved, ["db"])
    assert not any(call[:3] == ["docker", "volume", "create"] for call in runner.calls)
    assert not any("chown" in call for call in runner.calls)


def test_new_shared_volume_with_different_users_fails_closed() -> None:
    runner = VolumeRunner()
    data = {
        "services": {
            "api": {"volumes": ["data:/data"]},
            "worker": {"volumes": ["data:/data"]},
        },
        "volumes": {"data": {}},
    }
    with pytest.raises(AppDeployError, match="shared by services with different users"):
        resolve_runtime_volumes(
            runner, data, "app-demo",
            policy(("api", 1000, 1000, "policy"), ("worker", 2000, 2000, "policy")),
        )


def test_manifest_contains_signed_runtime_user_evidence(tmp_path: Path) -> None:
    compose = tmp_path / "compose.yml"
    compose.write_text("services: {web: {user: '1000:1000'}}\n", encoding="utf-8")
    result = SimpleNamespace(
        root=tmp_path, compose=compose,
        data={"services": {"web": {"user": "1000:1000"}}},
    )
    manifest = _manifest_data(
        DeployOptions(project="app-demo"), result, "app-demo", {}, "building",
        "local", tmp_path / "release", policy(("web", 1000, 1000, "compose")),
    )
    assert manifest["runtime_users"]["web"] == {
        "requested": "1000:1000", "effective": "1000:1000", "source": "compose",
    }
