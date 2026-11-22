"""Unit tests for the 0110-C harness primitives (no lab required)."""

from __future__ import annotations

import importlib.util
import json
import signal
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "e2e_0110_c_hosting_rootless_closure",
    ROOT / "scripts/e2e_0110_c_hosting_rootless_closure.py",
)
assert SPEC and SPEC.loader
e2e = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = e2e
SPEC.loader.exec_module(e2e)


def test_redaction_removes_registered_secrets_and_sensitive_pairs() -> None:
    redactor = e2e.Redactor()
    token = redactor.add("jwt-0123456789")
    password = redactor.add("hunter2-password")
    assert token == "jwt-0123456789"
    rendered = redactor.text(
        f"Authorization=Bearer {token} password={password} host=example.lab"
    )
    assert token not in rendered
    assert password not in rendered
    assert "example.lab" in rendered
    value = redactor.value(
        {
            "access_token": token,
            "site": {"domain": "wp.example.lab", "password": password},
            "checks": [{"cookie": "session=abc", "id": "auth_rbac_scope"}],
        }
    )
    assert value["access_token"] == "***"
    assert value["site"]["password"] == "***"
    assert value["site"]["domain"] == "wp.example.lab"
    assert value["checks"][0]["cookie"] == "***"
    assert value["checks"][0]["id"] == "auth_rbac_scope"


def test_redaction_without_registry_still_hides_key_value_pairs() -> None:
    rendered = e2e.redact_text('{"password":"s3cret","token": "abc123", "id": "ok"}')
    assert "s3cret" not in rendered
    assert "abc123" not in rendered
    assert '"id": "ok"' in rendered


def test_wp_request_turns_timeout_into_retryable_status() -> None:
    class TimeoutOpener:
        def open(self, request, timeout):
            raise TimeoutError("slow wp-admin")

    assert e2e.wp_request(
        None, TimeoutOpener(), "wp.example.lab", "/wp-admin/", timeout=1
    ) == (0, b"", {})


def test_external_probe_wraps_socket_timeout(monkeypatch, tmp_path: Path) -> None:
    cfg = e2e.Config(
        stage=tmp_path,
        slug="timeout",
        evidence_path=tmp_path / "evidence.json",
    )
    monkeypatch.setattr(
        e2e.urllib.request,
        "urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("slow route")),
    )

    with pytest.raises(e2e.HarnessError, match="external probe"):
        e2e.external_probe(cfg, "static-timeout.lab", deadline=0)


def test_journal_is_atomic_and_resume_validates_identity(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    journal = e2e.Journal(path)
    journal.data = {"identity": {"slug": "e2e0110c"}, "phases": {}}
    journal.save()
    assert path.exists()
    assert not path.with_suffix(".tmp").exists()
    assert int(oct(path.stat().st_mode)[-3:], 8) == 0o600

    resumed = e2e.Journal(path)
    assert resumed.load()["identity"] == {"slug": "e2e0110c"}
    assert resumed.done("setup") is False
    resumed.mark("setup", {"state": "ready"})
    assert resumed.done("setup") is True
    resumed.validate_identity({"slug": "e2e0110c"})
    with pytest.raises(e2e.JournalError):
        resumed.validate_identity({"slug": "someone-else"})


def test_retries_are_bounded_to_two_attempts() -> None:
    attempts: list[int] = []
    sleeps: list[float] = []

    def flaky() -> str:
        attempts.append(1)
        if len(attempts) == 1:
            raise RuntimeError("transient")
        return "ok"

    result = e2e.call_with_retries(
        flaky, attempts=5, backoff=1.0, sleep=sleeps.append
    )
    assert result == "ok"
    assert len(attempts) == 2
    assert sleeps == [1.0]

    failed: list[int] = []

    def broken() -> None:
        failed.append(1)
        raise RuntimeError("broken")

    with pytest.raises(RuntimeError, match="broken"):
        e2e.call_with_retries(broken, attempts=7, sleep=lambda _: None)
    assert len(failed) == 2


def test_ownership_selection_is_exact() -> None:
    records = [
        {"name": "ours", "owner": "e2e0110c"},
        {"name": "theirs", "owner": "e2e0110c-extra"},
        {"name": "unowned"},
        {"owner": "e2e0110c", "name": "ours-too"},
    ]
    owned = e2e.select_owned(records, owner_key="owner", owner="e2e0110c")
    assert [item["name"] for item in owned] == ["ours", "ours-too"]


def test_pass_requires_all_checks_no_gaps_zero_denials_and_cleanup() -> None:
    green = [{"id": "check", "pass": True}]
    assert (
        e2e.evaluate_result(
            checks=green, gaps=[], delta_denied=0, cleanup_verified=True
        )
        == "PASS"
    )
    assert (
        e2e.evaluate_result(checks=green, cleanup_verified=False) == "FAIL"
    )
    assert (
        e2e.evaluate_result(
            checks=green, gaps=[{"id": "X"}], cleanup_verified=True
        )
        == "FAIL"
    )
    assert (
        e2e.evaluate_result(
            checks=green, delta_denied=1, cleanup_verified=True
        )
        == "FAIL"
    )
    assert (
        e2e.evaluate_result(
            checks=[{"id": "skipped", "pass": None}], cleanup_verified=True
        )
        == "FAIL"
    )
    assert (
        e2e.evaluate_result(checks=[{"id": "bad", "pass": False}], cleanup_verified=True)
        == "FAIL"
    )
    assert e2e.evaluate_result(checks=[], cleanup_verified=True) == "FAIL"
    assert (
        e2e.evaluate_result(
            checks=green, cleanup_verified=True, keep_on_failure=True
        )
        == "FAIL"
    )
    assert (
        e2e.evaluate_result(checks=green, blocked=True, cleanup_verified=True)
        == "BLOCKED"
    )
    assert (
        e2e.evaluate_result(
            checks=green,
            cleanup_verified=True,
            required_ids=("rollback_and_controlled_failure", "wordpress_surface"),
        )
        == "FAIL"
    )
    assert (
        e2e.evaluate_result(
            checks=green,
            blocked=True,
            cleanup_verified=True,
            required_ids=("rollback_and_controlled_failure",),
        )
        == "BLOCKED"
    )
    assert {"rollback_and_controlled_failure", "finalize", "wordpress_surface"}.issubset(
        set(e2e.REQUIRED_CHECKS)
    )


def test_signal_installed_by_harness_raises_interrupt(monkeypatch) -> None:
    original = signal.getsignal(signal.SIGTERM)
    e2e._install_signal_handlers()
    try:
        with pytest.raises(KeyboardInterrupt, match="signal 15"):
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
    finally:
        signal.signal(signal.SIGTERM, original)


def test_interrupt_still_runs_cleanup_and_never_passes(
    tmp_path: Path, monkeypatch
) -> None:
    calls: list[str] = []

    def interrupted(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt("signal 15")

    monkeypatch.setattr(e2e, "phase_preflight", interrupted)
    monkeypatch.setattr(
        e2e, "cleanup", lambda *_a, **_k: calls.append("cleanup")
    )
    monkeypatch.setattr(e2e, "write_report", lambda *_a, **_k: None)
    evidence = tmp_path / "evidence.json"
    code = e2e.main(
        [
            "--stage",
            str(tmp_path / "stage"),
            "--slug",
            "e2e0110c",
            "--evidence",
            str(evidence),
        ]
    )
    assert calls == ["cleanup"]
    assert code == 1
    payload = json.loads(evidence.read_text())
    assert payload["result"] == "FAIL"
    assert payload["ok"] is False
    assert any(gap["id"] == "SIGNAL" for gap in payload["gaps"])


def test_uid_map_helper_rejects_identity_mapping() -> None:
    assert e2e.is_non_identity_uid_map("         0          0 4294967295\n") is False
    assert e2e.is_non_identity_uid_map("         0     100000      65536\n") is True
    assert e2e.is_non_identity_uid_map("") is False


def test_script_never_invokes_alembic_cli() -> None:
    source = (ROOT / "scripts/e2e_0110_c_hosting_rootless_closure.py").read_text()
    lowered = source.lower()
    assert "alembic upgrade" not in lowered
    assert "alembic revision" not in lowered
    assert "--autogenerate" not in lowered


def test_pma_source_is_resolved_on_its_actual_network(tmp_path: Path, monkeypatch) -> None:
    live_env = tmp_path / "live.env"
    live_env.write_text(
        "SPANEL_PHPMYADMIN_INTERNAL_URL=http://spanel-lab-phpmyadmin:8080\n"
    )
    cfg = e2e.Config(
        tmp_path / "stage", "e2e0110c", tmp_path / "evidence.json", live_env=live_env
    )
    payload = json.dumps(
        [{"NetworkSettings": {"Networks": {"mariadb_internal": {"IPAddress": "172.24.0.3"}}}}]
    )
    monkeypatch.setattr(
        e2e,
        "docker",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, payload, ""),
    )

    assert e2e.resolve_pma_source_ip(cfg) == "172.24.0.3"


def test_pg_host_is_resolved_on_its_actual_network(tmp_path: Path, monkeypatch) -> None:
    cfg = e2e.Config(tmp_path / "stage", "e2e0110c", tmp_path / "evidence.json")
    payload = json.dumps(
        [{"NetworkSettings": {"Networks": {"spanel_default": {"IPAddress": "192.168.32.4"}}}}]
    )
    monkeypatch.setattr(
        e2e,
        "docker",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, payload, ""),
    )

    assert e2e.resolve_pg_host(cfg) == "192.168.32.4"
