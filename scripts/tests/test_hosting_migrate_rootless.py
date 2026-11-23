from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace

from scripts import hosting_migrate_rootless as cli


class FakeDb:
    def __init__(self, sites):
        self.sites = {site.id: site for site in sites}

    def get(self, model, site_id):
        del model
        return self.sites.get(site_id)


class FakeService:
    def __init__(self):
        self.calls = []

    def plan(self, site_id):
        self.calls.append(("plan", site_id))
        return {
            "ok": True,
            "operation_id": None,
            "site_id": site_id,
            "kind": "static",
            "from_runtime": "rootful",
            "to_runtime": "rootless",
            "state": "planned",
            "steps": [],
            "rollback_available": False,
            "mutation": False,
        }

    def migrate(self, site_id):
        self.calls.append(("migrate", site_id))
        return {**self.plan(site_id), "operation_id": "op-1", "state": "retained"}

    def rollback(self, site_id, operation):
        self.calls.append(("rollback", site_id, operation))
        return {"ok": True, "site_id": site_id, "state": "rolled_back"}

    def finalize(self, site_id, operation, domain):
        self.calls.append(("finalize", site_id, operation, domain))
        return {"ok": True, "site_id": site_id, "state": "finalized"}

    def status(self, site_id):
        return {"ok": True, "site_id": site_id, "state": "retained"}

    def reconcile(self, site_id):
        return {"ok": True, "site_id": site_id, "reconciled": True}


def install(monkeypatch):
    service = FakeService()
    db = FakeDb([SimpleNamespace(id="s1", kind="static")])

    @contextmanager
    def context():
        yield service, db

    monkeypatch.setattr(cli, "service_context", context)
    return service


def test_plan_and_dry_run_are_pure(monkeypatch, capsys) -> None:
    service = install(monkeypatch)
    assert cli.main(["plan", "--site", "s1", "--json"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["mutation"] is False
    assert service.calls == [("plan", "s1")]

    assert cli.main(["migrate", "--site", "s1", "--dry-run", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "planned"
    assert service.calls[-1] == ("plan", "s1")


def test_recovery_commands_reuse_backend(monkeypatch, capsys) -> None:
    service = install(monkeypatch)
    assert cli.main(["rollback", "--site", "s1", "--operation", "op-1", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "rolled_back"
    assert (
        cli.main(
            [
                "finalize",
                "--site",
                "s1",
                "--operation",
                "op-1",
                "--confirm-domain",
                "site.test",
                "--json",
            ]
        )
        == 0
    )
    assert service.calls[-1] == ("finalize", "s1", "op-1", "site.test")


def test_verify_pma_dispatches_for_a_wordpress_site(monkeypatch, capsys) -> None:
    service = FakeService()
    db = FakeDb([SimpleNamespace(id="s1", kind="wordpress", domain="site.test")])

    @contextmanager
    def context():
        yield service, db

    monkeypatch.setattr(cli, "service_context", context)
    monkeypatch.setattr(
        cli,
        "_verify_pma_site",
        lambda _service, site: {
            "ok": True,
            "site_id": site.id,
            "domain": site.domain,
        },
    )
    assert cli.main(["verify-pma", "--site", "s1", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["site_id"] == "s1"


def test_verify_pma_rejects_a_static_site(monkeypatch, capsys) -> None:
    service = FakeService()
    db = FakeDb([SimpleNamespace(id="s1", kind="static", domain="site.test")])

    @contextmanager
    def context():
        yield service, db

    monkeypatch.setattr(cli, "service_context", context)
    assert cli.main(["verify-pma", "--site", "s1", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert "no WordPress" in payload["error"]


def test_host_cli_replaces_a_container_only_plugins_path(monkeypatch) -> None:
    monkeypatch.setenv("SYSTUTOR_PLUGINS_DIR", "/app/plugins")
    cli._ensure_plugins_dir()
    assert cli.Path(cli.os.environ["SYSTUTOR_PLUGINS_DIR"]) == cli.CORE / "plugins"


def test_service_context_fixes_plugins_path_before_import() -> None:
    source = cli.Path(cli.__file__).read_text(encoding="utf-8")
    context = source.split("def service_context()", 1)[1].split("app = create_app()", 1)[0]
    assert context.index("_ensure_plugins_dir()") < context.index("from app.main import create_app")


def test_json_mode_keeps_incidental_output_off_stdout(monkeypatch, capsys) -> None:
    def execute(_args):
        print("plugin bootstrap noise")
        return {"ok": True, "state": "planned"}

    monkeypatch.setattr(cli, "execute", execute)
    assert cli.main(["plan", "--site", "s1", "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["state"] == "planned"
    assert "plugin bootstrap noise" in captured.err
