from __future__ import annotations

import json
from pathlib import Path

from scripts import migrate_tenant_apps as mod


def detail(
    app_id: str = "app-1",
    *,
    operation: str | None = "op-signed",
    status: str = "running",
    containers: tuple[str, ...] = ("c1",),
    active: bool = True,
) -> dict:
    deployment = (
        {
            "id": "dep-1",
            "status": status,
            "release_summary": ({"operation_id": operation} if operation else None),
            "service_details": [
                {"name": f"svc-{index}", "container_id": cid}
                for index, cid in enumerate(containers)
            ],
        }
        if active
        else None
    )
    return {
        "id": app_id,
        "name": f"name-{app_id}",
        "domain": f"{app_id}.test",
        "active_deployment": deployment,
    }


class FakeClient:
    def __init__(self, details: list[dict], *, new_details: dict | None = None):
        self.details = {item["id"]: item for item in details}
        self.new_details = new_details or details[0] if details else {}
        self.calls: list[tuple] = []
        self.detail_reads = 0

    def request(self, method, path, payload=None, *, idempotency_key=None):
        self.calls.append((method, path, payload, idempotency_key))
        if method == "GET" and path == "/applications":
            return list(self.details.values())
        if method == "GET" and path.startswith("/applications/"):
            self.detail_reads += 1
            if self.detail_reads > 1 and self.new_details:
                return self.new_details
            return self.details[path.rsplit("/", 1)[-1]]
        if method == "POST" and path.endswith("/deployments"):
            return {"operation_id": "op-new"}
        raise AssertionError(f"unexpected call: {method} {path}")

    def poll(self, operation_id, timeout=900):
        self.calls.append(("POLL", operation_id, None, None))
        return {"status": "succeeded"}


class FakeRunner:
    def __init__(self, known: set[str]):
        self.known = known
        self.calls: list[list[str]] = []

    def __call__(self, argv, timeout=60):
        self.calls.append(argv)
        container = argv[-1]
        return mod.CommandOutput(0 if container in self.known else 1, "", "")


def make_socket(tmp_path) -> Path:
    socket = tmp_path / "cells" / "demo" / "docker.sock"
    socket.parent.mkdir(parents=True)
    socket.write_text("", encoding="utf-8")
    return socket


def make_migrator(tmp_path, details, *, known=None, dry_run=False):
    client = FakeClient(details)
    make_socket(tmp_path)
    # Path.is_socket() is False for a regular file; patch the migrator's check.
    runner = FakeRunner(known or set())
    migrator = mod.AppsMigrator(
        client,
        tenant="demo",
        data_root=str(tmp_path),
        dry_run=dry_run,
        runner=runner,
    )
    migrator._containers_in_cell = lambda ids: _cell_check(runner, ids)  # type: ignore[method-assign]
    return migrator, client, runner


def _cell_check(runner, ids):
    if not ids:
        return False, "no containers"
    for cid in ids:
        if runner(["docker", "inspect", cid]).returncode != 0:
            return False, "not in cell"
    return True, "already rootless"


def test_plan_marks_app_with_signed_release(tmp_path) -> None:
    migrator, _client, _runner = make_migrator(tmp_path, [detail()], known=set())
    plans = migrator.plans()
    assert plans[0].operation_id == "op-signed"
    assert plans[0].already_rootless is False


def test_plan_skips_containers_already_in_cell(tmp_path) -> None:
    migrator, _client, _runner = make_migrator(tmp_path, [detail()], known={"c1"})
    plans = migrator.plans()
    assert plans[0].already_rootless is True


def test_app_without_signed_release_requires_hardening(tmp_path) -> None:
    migrator, _client, _runner = make_migrator(
        tmp_path, [detail(operation=None)], known=set()
    )
    results = migrator.migrate(migrator.plans())
    assert results[0]["state"] == "requires_hardening"
    assert results[0]["ok"] is False


def test_dry_run_never_posts(tmp_path) -> None:
    migrator, client, _runner = make_migrator(
        tmp_path, [detail()], known=set(), dry_run=True
    )
    results = migrator.migrate(migrator.plans())
    assert results[0]["state"] == "planned"
    assert not any(call[0] == "POST" for call in client.calls)


def test_apply_redeploys_signed_release_and_verifies_cell(tmp_path) -> None:
    first = detail(containers=("old",))
    new = detail(containers=("new",))
    client = FakeClient([first], new_details=new)
    runner = FakeRunner({"new"})
    migrator = mod.AppsMigrator(
        client,
        tenant="demo",
        data_root=str(tmp_path),
        dry_run=False,
        runner=runner,
    )
    migrator._containers_in_cell = lambda ids: _cell_check(runner, ids)  # type: ignore[method-assign]
    make_socket(tmp_path)
    results = migrator.migrate(migrator.plans())
    assert results[0]["ok"] is True
    assert results[0]["state"] == "rootless"
    posts = [call for call in client.calls if call[0] == "POST"]
    assert posts[0][2]["hardened_operation_id"] == "op-signed"
    assert ("POLL", "op-new", None, None) in client.calls


def test_failed_poll_is_reported(tmp_path) -> None:
    class Failing(FakeClient):
        def poll(self, operation_id, timeout=900):
            from scripts.spanel_apps import CliError

            raise CliError("operation failed")

    client = Failing([detail(containers=("old",))])
    migrator = mod.AppsMigrator(
        client,
        tenant="demo",
        data_root=str(tmp_path),
        dry_run=False,
        verify_cell=False,
    )
    results = migrator.migrate(migrator.plans())
    assert results[0]["ok"] is False
    assert results[0]["state"] == "failed"


def test_api_url_uses_spanel_domain_from_env_file(tmp_path, monkeypatch) -> None:
    env = tmp_path / ".env.docker"
    env.write_text("SPANEL_DOMAIN=panel.real.test\n", encoding="utf-8")
    monkeypatch.delenv("SPANEL_DOMAIN", raising=False)
    assert mod.api_url(None, env_file=env) == "https://panel.real.test"
    assert mod.api_url("https://explicit.test", env_file=env) == "https://explicit.test"


def test_api_url_accepts_a_full_scheme(tmp_path) -> None:
    env = tmp_path / ".env.docker"
    env.write_text("SPANEL_DOMAIN=https://panel.real.test\n", encoding="utf-8")
    assert mod.api_url(None, env_file=env) == "https://panel.real.test"


def test_main_requires_token(monkeypatch, capsys) -> None:
    monkeypatch.delenv("SPANEL_APPS_TOKEN", raising=False)
    monkeypatch.delenv("SPANEL_ACCESS_TOKEN", raising=False)
    code = mod.main(["--tenant", "demo", "--json"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert "SPANEL_APPS_TOKEN" in payload["error"]


def test_main_dry_run_uses_token_file(monkeypatch, tmp_path, capsys) -> None:
    token = tmp_path / "token"
    token.write_text("secret\n", encoding="utf-8")
    fake = FakeClient([detail()])
    monkeypatch.setattr(mod, "Client", lambda *_args, **_kwargs: fake)
    code = mod.main(
        [
            "--tenant",
            "demo",
            "--api-url",
            "https://panel.test",
            "--token-file",
            str(token),
            "--dry-run",
            "--json",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["dry_run"] is True
