from __future__ import annotations

import importlib.util
import json
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "e2e_apps_trusted_deploy",
    ROOT / "scripts/e2e_apps_trusted_deploy.py",
)
assert SPEC and SPEC.loader
e2e = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = e2e
SPEC.loader.exec_module(e2e)


def probes(restart: int = 0) -> dict:
    return {
        "isolation": {
            "backend": {"user": "10001:10001", "processes": 2},
            "frontend": {"user": "101:101", "processes": 1},
        },
        "functional": {"checks": [{"returncode": 0, "bytes": 128}]},
        "stability": {"checks": 3, "restart_counts": {"backend": restart}},
    }


def detail(user: str = "10001:10001", restart_count: int = 0) -> dict:
    return {
        "active_deployment": {
            "status": "running",
            "release_summary": {"release_id": "release-1"},
            "probes": probes(),
            "service_details": [
                {
                    "name": "backend",
                    "user": user,
                    "restart_count": restart_count,
                    "ports": [],
                }
            ],
        }
    }


def test_policy_covers_exactly_every_inspected_service() -> None:
    policy = e2e.policy_for(["database", "frontend", "backend"])
    assert list(policy["service_users"]) == ["backend", "database", "frontend"]
    assert "gate" not in policy
    with pytest.raises(e2e.E2EError, match="does not cover"):
        e2e.policy_for(["backend", "frontend", "database", "worker"])
    with pytest.raises(e2e.E2EError, match="unknown services"):
        e2e.policy_for(["backend", "frontend"])
    with pytest.raises(e2e.E2EError, match="any services"):
        e2e.policy_for([])


def test_policy_json_is_bounded_and_validated() -> None:
    with pytest.raises(e2e.E2EError, match="not valid JSON"):
        e2e.parse_policy("{")
    with pytest.raises(e2e.E2EError, match="service_users"):
        e2e.parse_policy(json.dumps({"service_users": {}}))
    custom = {
        "service_users": {"web": {"uid": 10001, "gid": 10001}},
        "writable_paths": [],
    }
    assert e2e.parse_policy(json.dumps(custom)) == custom


def test_environment_json_accepts_pairs_and_objects() -> None:
    assert e2e.environment_pairs('{"A": "one", "B": "two"}') == [
        ["A", "one"], ["B", "two"],
    ]
    assert e2e.environment_pairs('[["A", "one"]]') == [["A", "one"]]
    with pytest.raises(e2e.E2EError, match="invalid pair"):
        e2e.environment_pairs('[["A"]]')


def test_probes_require_isolation_functional_and_stability_evidence() -> None:
    summary = e2e.assert_probes(probes())
    assert summary["functional_checks"] == 1
    with pytest.raises(e2e.E2EError, match="restarted"):
        e2e.assert_probes(probes(restart=1))
    missing = probes()
    missing["functional"]["checks"] = [{"returncode": 1, "bytes": 10}]
    with pytest.raises(e2e.E2EError, match="functional probe"):
        e2e.assert_probes(missing)
    rooted = probes()
    rooted["isolation"]["backend"]["user"] = "0:0"
    with pytest.raises(e2e.E2EError, match="non-root"):
        e2e.assert_probes(rooted)


def test_runtime_requires_the_signed_release_and_non_root_services() -> None:
    runtime = e2e.assert_runtime(detail(), "release-1")
    assert runtime["users"] == {"backend": "10001:10001"}
    with pytest.raises(e2e.E2EError, match="non-root"):
        e2e.assert_runtime(detail(user="0"), "release-1")
    with pytest.raises(e2e.E2EError, match="restarted"):
        e2e.assert_runtime(detail(restart_count=2), "release-1")
    with pytest.raises(e2e.E2EError, match="does not match"):
        e2e.assert_runtime(detail(), "other-release")


class ErrorClient:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[tuple] = []

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, body))
        if self.error is not None:
            raise self.error
        return {"ok": True}


def test_negative_deploy_requires_422_and_the_trusted_release_marker() -> None:
    client = ErrorClient(e2e.E2EError("POST /deployments returned HTTP 422: trusted release"))
    e2e.expect_http_error(
        client, "POST", "/deployments", {}, 422, "trusted release", "negative"
    )
    assert client.calls
    with pytest.raises(e2e.E2EError, match="unexpectedly succeeded"):
        e2e.expect_http_error(ErrorClient(), "POST", "/deployments", {}, 422, "trusted", "x")
    with pytest.raises(e2e.E2EError, match="unexpected error"):
        e2e.expect_http_error(
            ErrorClient(e2e.E2EError("HTTP 500: boom")), "POST", "/", {}, 422, "x", "x"
        )


def test_evidence_is_written_private_and_contains_no_secrets(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    payload = {"release_id": "r1", "admission": "isolation"}
    e2e.write_evidence(path, payload)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text(encoding="utf-8")) == payload
    with pytest.raises(e2e.E2EError, match="symlink"):
        link = tmp_path / "link.json"
        link.symlink_to(path)
        e2e.write_evidence(link, payload)


def test_main_requires_an_explicit_base_url(monkeypatch, capsys) -> None:
    monkeypatch.delenv("SPANEL_E2E_BASE_URL", raising=False)
    assert e2e.main([]) == 1
    assert "base-url" in capsys.readouterr().err
