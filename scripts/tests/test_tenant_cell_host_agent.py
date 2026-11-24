"""A.SPEC 0110-B: the host agent only opens bounded DB relays.

The broker and the Docker connector are faked here; these tests cover the
privilege boundary: peer uid, HMAC binding, tenant allocation, bounded request
fields and handler dispatch.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts.tenant_cell import alloc, db_broker, host_agent, materializer
from scripts.tenant_cell.host_agent import Peer, PlanAgent

SECRET = "db-relay-secret"
UID = 4242


class FakeExecutor:
    """The materializer is never used by DB relay operations."""


def _cell(tmp_path: Path, slug: str = "demo") -> None:
    alloc.allocate(str(tmp_path), slug)
    alloc.update_allocation(tmp_path, slug, state="ready", cgroup_driver="systemd")


def _agent(tmp_path: Path, handler: Any) -> PlanAgent:
    return PlanAgent(
        materializer.PlanMaterializer(FakeExecutor(), tmp_path),
        secret=SECRET,
        allowed_uids={UID},
        data_root=tmp_path,
        peer_resolver=lambda _sock: Peer(UID, 100),
        db_relay_handler=handler,
    )


def test_legacy_shared_layout_resolves_the_shared_database(
    monkeypatch, tmp_path: Path
) -> None:
    _cell(tmp_path, "demo")
    site = {
        "Name": "/ardiffx",
        "Config": {
            "Labels": {"spanel.tenant": "tenant-id", "spanel.managed": "true"}
        },
        "NetworkSettings": {
            "Networks": {"spanel-demo-shared-db": {}, "spanel-hosting": {}}
        },
    }
    database = {
        "Name": "/mariadb",
        "Config": {"Labels": {}},
        "NetworkSettings": {"Networks": {"spanel-demo-shared-db": {}}},
    }

    def fake_json(data_root, slug, *args):
        if args[:2] == ("inspect", "ardiffx"):
            return [site]
        if args[:2] == ("inspect", "dbid"):
            return [database]
        raise AssertionError(args)

    def fake_text(data_root, slug, *args):
        if args and args[0] == "ps":
            return "dbid\n"
        raise AssertionError(args)

    monkeypatch.setattr(host_agent, "_cell_docker_json", fake_json)
    monkeypatch.setattr(host_agent, "_cell_docker_text", fake_text)
    result = host_agent._legacy_shared_descriptor(
        tmp_path, "demo", "ardiffx", "tenant-id"
    )
    assert result["db_container"] == "mariadb"
    assert result["private_network"] == "spanel-demo-shared-db"
    assert result["target_host"].startswith("127.")


def test_legacy_private_layout_resolves_the_site_database(
    monkeypatch, tmp_path: Path
) -> None:
    _cell(tmp_path, "legalattorney-pe")
    labels = {
        "spanel.tenant": "tenant-id",
        "spanel.managed": "true",
        "spanel.site": "legalattorney-clean",
    }
    site = {
        "Name": "/legalattorney-clean",
        "Config": {"Labels": labels},
        "NetworkSettings": {
            "Networks": {
                "spanel-hosting": {},
                "spanel-legalattorney-clean-private": {},
            }
        },
    }
    database = {
        "Name": "/legalattorney-clean-db",
        "Config": {"Labels": labels},
        "NetworkSettings": {
            "Networks": {"spanel-legalattorney-clean-private": {}}
        },
    }

    monkeypatch.setattr(
        host_agent,
        "_cell_docker_json",
        lambda *_args: [site, database],
    )
    monkeypatch.setattr(host_agent, "_cell_docker_text", lambda *_args: "wpid\ndbid\n")

    result = host_agent._legacy_private_descriptor(
        tmp_path, "legalattorney-pe", "legalattorney-clean", "tenant-id"
    )

    assert result is not None
    assert result["db_container"] == "legalattorney-clean-db"
    assert result["private_network"] == "spanel-legalattorney-clean-private"


def test_cell_docker_query_runs_as_the_cell_owner(monkeypatch, tmp_path: Path) -> None:
    _cell(tmp_path, "demo")
    allocation = alloc.load_registry(tmp_path)["allocations"]["demo"]
    captured: dict[str, Any] = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, "[]\n", "")

    monkeypatch.setattr(host_agent.subprocess, "run", fake_run)

    assert host_agent._cell_docker_json(tmp_path, "demo", "ps", "-a") == []
    assert captured["user"] == allocation["uid"]
    assert captured["group"] == allocation["gid"]
    assert captured["env"]["HOME"] == str(tmp_path / "cells" / "demo")
    assert captured["env"]["DOCKER_CONFIG"] == str(
        tmp_path / "cells" / "demo" / ".docker"
    )


def _request(op: str, *, tenant: str = "demo", slug: str = "demo", **extra: Any):
    request: dict[str, Any] = {
        "op": op,
        "tenant": tenant,
        "slug": slug,
        "token": db_broker.issue_capability(SECRET, op=op, tenant=tenant, slug=slug),
    }
    request.update(extra)
    return request


def _open_fields() -> dict[str, Any]:
    return {
        "site_id": "site-1",
        "pma_session_id": "session-1",
        "relay_id": "pma-relay-1",
        "source_ip": "172.24.0.3",
        "ttl": 1500,
    }


def _error(response: dict[str, Any]) -> str:
    return response["error"]["code"]


def test_open_is_dispatched_only_after_authorization(tmp_path: Path) -> None:
    _cell(tmp_path)
    seen: list[tuple[str, dict[str, Any]]] = []

    def handler(op: str, request: dict[str, Any]) -> dict[str, Any]:
        seen.append((op, request))
        return {
            "relay_id": request["relay_id"],
            "broker_host": "172.24.0.1",
            "broker_port": 41000,
            "expires_at": 1,
        }

    agent = _agent(tmp_path, handler)
    response = agent.dispatch(_request("db_relay_open", **_open_fields()), Peer(UID, 100))
    assert response["ok"] is True
    assert response["result"]["broker_port"] == 41000
    assert seen[0][0] == "db_relay_open"
    assert seen[0][1]["site_id"] == "site-1"


def test_capability_is_bound_to_the_operation(tmp_path: Path) -> None:
    _cell(tmp_path)
    calls: list[str] = []
    agent = _agent(tmp_path, lambda op, request: calls.append(op) or {})
    request = _request("db_relay_status", relay_id="pma-relay-1")
    request["op"] = "db_relay_close"
    response = agent.dispatch(request, Peer(UID, 100))
    assert _error(response) == host_agent.ERR_CAP
    assert calls == []


def test_tenant_must_match_slug_and_allocation(tmp_path: Path) -> None:
    _cell(tmp_path)
    agent = _agent(tmp_path, lambda op, request: {})
    mismatch = _request(
        "db_relay_open", tenant="other", slug="demo", **_open_fields()
    )
    assert _error(agent.dispatch(mismatch, Peer(UID, 100))) == host_agent.ERR_FORBIDDEN
    unknown = _request(
        "db_relay_open", tenant="missing", slug="missing", **_open_fields()
    )
    assert _error(agent.dispatch(unknown, Peer(UID, 100))) == host_agent.ERR_TENANT


@pytest.mark.parametrize("ttl", [0, -1, 3601, "60", None])
def test_ttl_is_bounded(tmp_path: Path, ttl: Any) -> None:
    _cell(tmp_path)
    agent = _agent(tmp_path, lambda op, request: {})
    fields = _open_fields()
    fields["ttl"] = ttl
    response = agent.dispatch(_request("db_relay_open", **fields), Peer(UID, 100))
    assert _error(response) == host_agent.ERR_REQUEST


@pytest.mark.parametrize("missing", ["site_id", "pma_session_id", "relay_id", "source_ip"])
def test_open_requires_session_scoped_fields(tmp_path: Path, missing: str) -> None:
    _cell(tmp_path)
    agent = _agent(tmp_path, lambda op, request: {})
    fields = _open_fields()
    fields[missing] = ""
    response = agent.dispatch(_request("db_relay_open", **fields), Peer(UID, 100))
    assert _error(response) == host_agent.ERR_REQUEST


def test_close_and_status_require_or_list_a_relay(tmp_path: Path) -> None:
    _cell(tmp_path)
    seen: list[tuple[str, str | None]] = []

    def handler(op: str, request: dict[str, Any]) -> dict[str, Any]:
        seen.append((op, request.get("relay_id")))
        return {"relay_id": request.get("relay_id")}

    agent = _agent(tmp_path, handler)
    assert agent.dispatch(
        _request("db_relay_close", relay_id="pma-relay-1"), Peer(UID, 100)
    )["ok"]
    assert agent.dispatch(_request("db_relay_status"), Peer(UID, 100))["ok"]
    assert seen == [("db_relay_close", "pma-relay-1"), ("db_relay_status", None)]


def test_reconcile_requires_a_global_subject(tmp_path: Path) -> None:
    _cell(tmp_path)
    seen: list[str] = []
    agent = _agent(tmp_path, lambda op, request: seen.append(op) or {})
    bad = _request("db_relay_reconcile", tenant="demo", slug="demo")
    assert _error(agent.dispatch(bad, Peer(UID, 100))) == host_agent.ERR_FORBIDDEN
    good = _request(
        "db_relay_reconcile",
        tenant=host_agent.RECONCILE_SUBJECT,
        slug=host_agent.RECONCILE_SUBJECT,
    )
    assert agent.dispatch(good, Peer(UID, 100))["ok"]
    assert seen == ["db_relay_reconcile"]


def test_untrusted_peer_never_reaches_the_handler(tmp_path: Path) -> None:
    _cell(tmp_path)
    calls: list[str] = []
    agent = _agent(tmp_path, lambda op, request: calls.append(op) or {})
    response = agent.dispatch(
        _request("db_relay_open", **_open_fields()), Peer(9999, 100)
    )
    assert _error(response) == host_agent.ERR_PEER
    assert calls == []


def test_site_descriptor_resolves_the_db_tenant_slug(tmp_path: Path, monkeypatch) -> None:
    """The agent sees only the cell slug; the SQL must use the mapped DB slug."""
    import sqlalchemy as sa

    _cell(tmp_path, "legalattorney-pe")
    alloc.update_allocation(
        tmp_path, "legalattorney-pe", tenant_slug="Legalattorney.pe"
    )
    monkeypatch.setenv("SYSTUTOR_DATABASE_URL", "sqlite://")
    captured: dict[str, Any] = {}

    class FakeResult:
        def first(self):
            return ("spanel-legalattorney-wp", "wordpress", "rootless", "t1")

    class FakeConn:
        def execute(self, _statement, params):
            captured.update(params)
            return FakeResult()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class FakeEngine:
        def connect(self):
            return FakeConn()

        def dispose(self):
            return None

    monkeypatch.setattr(sa, "create_engine", lambda *_a, **_k: FakeEngine())
    descriptor = host_agent._site_descriptor(tmp_path, "legalattorney-pe", "s1")

    assert captured["tenant_slug"] == "Legalattorney.pe"
    assert descriptor["db_container"] == "spanel-legalattorney-db"
