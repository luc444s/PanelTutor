from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from plugins.apps.backend.hardening import (
    CommandHardeningEngine,
    HardenedCandidate,
    HardeningPolicy,
    HardeningRejected,
    RuntimeUserPolicy,
    WritablePathPolicy,
    automatic_hardening_policy,
    resolve_hardening_policy,
)
from plugins.apps.backend.runtime.source import dockerfile_runtime_user
from plugins.apps.backend.schemas import HardeningRequest


def policy() -> HardeningPolicy:
    return HardeningPolicy(
        (RuntimeUserPolicy("web", 10001, 10002),),
        (WritablePathPolicy("web", "/app/data", "0750"),),
    )


def test_automatic_policy_requires_and_uses_inspected_users() -> None:
    generated = automatic_hardening_policy({
        "database": {"image": "postgres:16", "user": "70:70"},
        "web": {"build": ".", "user": "1200:1300"},
        "worker": {"user": "1400"},
    })
    assert generated.as_dict() == {
        "service_users": {
            "database": {"uid": 70, "gid": 70},
            "web": {"uid": 1200, "gid": 1300},
            "worker": {"uid": 1400, "gid": 1400},
        },
        "writable_paths": [],
        "runtime_users": {
            "database": {"requested": "70:70", "effective": "70:70", "source": "compose"},
            "web": {"requested": "1200:1300", "effective": "1200:1300", "source": "compose"},
            "worker": {"requested": "1400:1400", "effective": "1400:1400", "source": "compose"},
        },
    }
    with pytest.raises(ValueError, match="explicit runtime user required for: database"):
        automatic_hardening_policy({"database": {"image": "postgres:16"}})


def test_automatic_policy_uses_dockerfile_user_when_compose_has_none() -> None:
    generated = automatic_hardening_policy(
        {
            "database": {"build": "."},
            "web": {"build": ".", "user": "1200:1300"},
        },
        {"database": "70:70", "web": "1000:1000"},
    )
    assert generated.as_dict()["service_users"] == {
        "database": {"uid": 70, "gid": 70},
        "web": {"uid": 1200, "gid": 1300},
    }


def test_resolve_policy_fills_omitted_services_from_dockerfile() -> None:
    base = HardeningPolicy((RuntimeUserPolicy("web", 1000, 1000),))
    resolved = resolve_hardening_policy(
        base,
        {"database": {"build": "."}, "web": {"build": "."}},
        {"database": "70:70"},
    )
    assert resolved.as_dict()["service_users"] == {
        "database": {"uid": 70, "gid": 70},
        "web": {"uid": 1000, "gid": 1000},
    }
    with pytest.raises(ValueError, match="explicit runtime user required"):
        resolve_hardening_policy(base, {"web": {}, "cache": {}}, {})
    with pytest.raises(ValueError, match="unknown service"):
        resolve_hardening_policy(base, {"database": {}}, {})


def test_dockerfile_runtime_user_uses_the_final_instruction(tmp_path: Path) -> None:
    path = tmp_path / "Dockerfile"
    path.write_text(
        "FROM postgres:16-alpine\nUSER postgres\nUSER 1000:1000\n",
        encoding="utf-8",
    )
    assert dockerfile_runtime_user(path) == "1000:1000"
    path.write_text("FROM scratch\n# USER 0\n", encoding="utf-8")
    assert dockerfile_runtime_user(path) is None


def applied() -> dict:
    return {
        "status": "applied",
        "applied": True,
        "changes": ["Dockerfile", "compose.yml"],
        "gate": {"status": "passed", "internal": {"blocking": 0}},
        "gate_after_apply": {"status": "reused", "evidence_reused": True},
        "source": "/secret/checkout",
        "backup": "/secret/backup",
    }


def test_contracts_reject_root_traversal_duplicates_and_incomplete_evidence() -> None:
    with pytest.raises(ValueError, match="non-root"):
        RuntimeUserPolicy("web", 0, 1)
    with pytest.raises(ValueError, match="traversal"):
        WritablePathPolicy("web", "/app/../root")
    with pytest.raises(ValueError, match="duplicate"):
        HardeningPolicy((RuntimeUserPolicy("web", 1, 1), RuntimeUserPolicy("web", 2, 2)))
    value = applied()
    value["gate_after_apply"] = {"status": "blocked"}
    with pytest.raises(ValueError, match="fully validated"):
        HardenedCandidate.from_response(
            value, source_tree_sha256="a" * 64, hardened_tree_sha256="b" * 64,
            compose="compose.yml", policy=policy(),
        )


def test_request_schema_is_bounded_and_builds_the_immutable_policy() -> None:
    request = HardeningRequest.model_validate({
        "service_users": {"web": {"uid": 10001, "gid": 10002}},
        "writable_paths": [{"service": "web", "path": "/app/data", "mode": "0750"}],
    })
    assert request.to_policy() == policy()
    with pytest.raises(ValueError):
        HardeningRequest.model_validate({
            "service_users": {"web": {"uid": 10001, "gid": 10002}},
            "writable_paths": [{"service": "other", "path": "/app/data", "mode": "0750"}],
        })


def test_policy_is_isolation_only_and_rejects_gate_fields() -> None:
    legacy = policy().as_dict()
    assert set(legacy) == {"service_users", "writable_paths"}
    assert HardeningPolicy.from_dict(legacy).as_dict() == legacy
    with pytest.raises(ValueError, match="policy is invalid"):
        HardeningPolicy.from_dict({**legacy, "gate": {"skip_trivy": True}})
    with pytest.raises(ValueError):
        HardeningRequest.model_validate({
            "service_users": {"web": {"uid": 10001, "gid": 10002}},
            "writable_paths": [],
            "gate": {"skip_trivy": True},
        })


def test_command_engine_never_adds_gate_flags(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "compose.yml").write_text("services: {web: {}}", encoding="utf-8")
    captured: dict[str, list[str]] = {}

    def runner(argv, **kwargs):
        captured["argv"] = argv
        return SimpleNamespace(
            returncode=0, stdout=json.dumps(applied()).encode(), stderr=b""
        )

    CommandHardeningEngine("/opt/hardener", runner=runner).prepare(
        checkout, "compose.yml", policy()
    )
    assert not [item for item in captured["argv"] if item.startswith("--skip")]


def test_command_engine_uses_argv_scrubs_credentials_and_sanitizes_result(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "compose.yml").write_text("services: {web: {}}", encoding="utf-8")
    captured = {}

    def runner(argv, **kwargs):
        captured.update({"argv": argv, **kwargs})
        return SimpleNamespace(
            returncode=0, stdout=json.dumps(applied()).encode(), stderr=b"secret"
        )

    candidate = CommandHardeningEngine(
        "/opt/hardener", runner=runner,
        environ={
            "PATH": "/bin", "GH_TOKEN": "secret", "GITHUB_TOKEN": "secret",
            "SSH_AUTH_SOCK": "x",
        },
    ).prepare(checkout, "compose.yml", policy())
    assert captured["argv"] == [
        "/opt/hardener", "harden", str(checkout.resolve()), "--apply", "--format", "json",
        "--compose-file", "compose.yml", "--service-user", "web=10001:10002",
        "--writable-path", "web=/app/data:0750",
    ]
    assert captured["shell"] is False
    assert captured["env"] == {"PATH": "/bin"}
    report = candidate.as_report()
    assert report["status"] == "validated"
    assert "source" not in report and "backup" not in report
    assert "/secret" not in json.dumps(report)


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (SimpleNamespace(returncode=2, stdout=b"{}", stderr=b"raw secret"), "rejected"),
        (SimpleNamespace(returncode=0, stdout=b"not-json", stderr=b""), "invalid evidence"),
    ],
)
def test_command_engine_fails_closed_without_echoing_output(
    tmp_path: Path, result, message
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "compose.yml").write_text("services: {web: {}}", encoding="utf-8")
    engine = CommandHardeningEngine(runner=lambda *_args, **_kwargs: result)
    with pytest.raises(HardeningRejected, match=message) as error:
        engine.prepare(checkout, "compose.yml", policy())
    assert "raw secret" not in str(error.value)


def test_command_engine_maps_timeout_to_safe_rejection(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("secret command", 1, output=b"secret")

    with pytest.raises(HardeningRejected, match="timed out"):
        CommandHardeningEngine(runner=timeout).prepare(checkout, "compose.yml", policy())
