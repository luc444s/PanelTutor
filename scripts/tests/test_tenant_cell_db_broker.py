from __future__ import annotations

import socket
import subprocess
import threading
import time

import pytest

from scripts.tenant_cell import db_broker


def free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class FakeConnector:
    data_root = "/tmp/cells"

    def __init__(self) -> None:
        self.opened = []
        self.closed = []
        self.orphan_list = []

    def open(self, entry, *, db_container, private_network):
        self.opened.append((entry.relay_id, db_container, private_network))
        return f"connector-{entry.relay_id}"

    def close(self, slug, name):
        self.closed.append((slug, name))

    def orphans(self, slug, active):
        return [name for name in self.orphan_list if name not in active]


def make_broker(monkeypatch, sources=("172.25.0.20",)):
    base = free_port()
    connector = FakeConnector()
    broker = db_broker.DBBroker(
        bind="127.0.0.1",
        sources=sources,
        ports=(base, base + 9),
        connector=connector,
    )
    return broker, connector


def entry_args(broker, **overrides):
    return {
        "relay_id": "pma-1",
        "tenant_id": "tenant-1",
        "slug": "demo",
        "site_id": "site-1",
        "pma_session_id": "session-1",
        "source_ip": "172.25.0.20",
        "target_host": "127.70.0.1",
        "target_port": 33061,
        "ttl": 60,
        "db_container": "spanel-demo-db",
        "private_network": "spanel-demo-private",
        **overrides,
    }


def test_empty_allowlist_denies_everything(monkeypatch) -> None:
    broker, connector = make_broker(monkeypatch, sources=())
    with pytest.raises(db_broker.BrokerError):
        broker.open(**entry_args(broker))
    assert connector.opened == []


def test_source_outside_allowlist_is_rejected(monkeypatch) -> None:
    broker, connector = make_broker(monkeypatch)
    with pytest.raises(db_broker.BrokerError):
        broker.open(**entry_args(broker, source_ip="172.25.0.99"))
    assert connector.opened == []


def test_open_returns_only_bounded_public_fields(monkeypatch) -> None:
    broker, connector = make_broker(monkeypatch)
    result = broker.open(**entry_args(broker))
    assert result["relay_id"] == "pma-1"
    assert connector.opened == [("pma-1", "spanel-demo-db", "spanel-demo-private")]
    for forbidden in ("target_host", "source_ip", "db_container"):
        assert forbidden not in result
    assert broker.status("pma-1")["state"] == "open"


def test_connector_port_is_distinct_from_the_broker_port(monkeypatch) -> None:
    broker, connector = make_broker(monkeypatch)
    result = broker.open(**entry_args(broker))
    entry = broker._entries["pma-1"]
    assert entry.connector_port != entry.listen_port
    assert result["broker_port"] == entry.listen_port
    assert connector.opened == [("pma-1", "spanel-demo-db", "spanel-demo-private")]


def test_open_is_idempotent_and_close_is_idempotent(monkeypatch) -> None:
    broker, connector = make_broker(monkeypatch)
    first = broker.open(**entry_args(broker))
    second = broker.open(**entry_args(broker))
    assert first["listen_port"] == second["listen_port"]
    assert len(connector.opened) == 1
    assert broker.close("pma-1")["closed"] is True
    assert broker.close("pma-1")["closed"] is False
    assert connector.closed == [("demo", "connector-pma-1")]
    assert broker.status("pma-1")["state"] == "absent"


def test_expired_relay_is_closed_and_connector_removed(monkeypatch) -> None:
    broker, connector = make_broker(monkeypatch)
    broker.open(**entry_args(broker))
    broker.clock = lambda: time.time() + 3600
    assert broker.expire() == ["pma-1"]
    assert connector.closed == [("demo", "connector-pma-1")]
    assert broker.list() == []


def test_reconcile_removes_orphan_connectors(monkeypatch) -> None:
    broker, connector = make_broker(monkeypatch)
    broker.open(**entry_args(broker))
    connector.orphan_list = ["spanel-pma-orphan"]
    result = broker.reconcile()
    assert result["orphans"] == ["spanel-pma-orphan"]
    assert connector.closed == [("demo", "spanel-pma-orphan")]


def test_listener_forwards_bytes_to_the_cell_target(monkeypatch) -> None:
    target = socket.socket()
    target.bind(("127.0.0.1", 0))
    target.listen(1)
    target_port = target.getsockname()[1]

    def echo() -> None:
        conn, _ = target.accept()
        with conn:
            while data := conn.recv(1024):
                conn.sendall(b"echo:" + data)

    threading.Thread(target=echo, daemon=True).start()
    broker, _ = make_broker(monkeypatch, sources=("127.0.0.1",))
    broker.connector = None
    result = broker.open(**entry_args(broker, source_ip="127.0.0.1", target_host="127.0.0.1", target_port=target_port))
    client = socket.create_connection(("127.0.0.1", result["listen_port"]), timeout=5)
    with client:
        client.sendall(b"hello")
        assert client.recv(1024) == b"echo:hello"
    broker.close("pma-1")
    target.close()


def test_connector_requires_a_pinned_image(tmp_path) -> None:
    connector = db_broker.CellConnector(tmp_path, image="alpine/socat:latest", runner=lambda *_: None)
    entry = db_broker.RelayEntry(
        relay_id="pma-1", tenant_id="t", slug="demo", site_id="s",
        pma_session_id="p", source_ip="1.1.1.1", listen_port=1,
        target_host="127.0.0.1", target_port=2, created_at=0, expires_at=0,
    )
    with pytest.raises(db_broker.BrokerError):
        connector.open(entry, db_container="db", private_network="net")


def test_connector_argv_is_hardened_and_read_only_by_default(tmp_path) -> None:
    connector = db_broker.CellConnector(
        tmp_path, image="alpine/socat@sha256:" + "a" * 64, read_only=True, network="spanel-hosting"
    )
    entry = db_broker.RelayEntry(
        relay_id="pma-1", tenant_id="t", slug="demo", site_id="s",
        pma_session_id="p", source_ip="1.1.1.1", listen_port=41000,
        target_host="127.0.0.1", target_port=42000, connector_port=42000,
        created_at=0, expires_at=0,
    )
    argv = connector._argv(entry, "spanel-demo-db", "spanel-pma-pma-1", "spanel-demo-private")
    assert "--read-only" in argv
    assert "--cap-drop" in argv and "ALL" in argv
    assert "--security-opt" in argv and "no-new-privileges" in argv
    assert "--network" in argv and "spanel-hosting" in argv
    assert not any("docker.sock" in part for part in argv)
    assert argv[0] == "create"
    assert "42000:3306" in argv
    lax = db_broker.CellConnector(
        tmp_path, image="alpine/socat@sha256:" + "a" * 64, read_only=False, network="spanel-hosting"
    )
    assert "--read-only" not in lax._argv(
        entry, "spanel-demo-db", "spanel-pma-pma-1", "spanel-demo-private"
    )


def test_connector_docker_runs_as_the_cell_owner(tmp_path) -> None:
    from scripts.tenant_cell import alloc

    alloc.allocate(str(tmp_path), "demo")
    allocation = alloc.load_registry(tmp_path)["allocations"]["demo"]
    captured = {}

    def runner(argv, env, uid, gid):
        captured.update(argv=argv, env=env, uid=uid, gid=gid)
        return subprocess.CompletedProcess(argv, 0, "[]\n", "")

    connector = db_broker.CellConnector(
        tmp_path,
        image="alpine/socat@sha256:" + "a" * 64,
        runner=runner,
    )

    assert connector._docker("demo", ["image", "inspect", connector.image]).returncode == 0
    assert captured["uid"] == allocation["uid"]
    assert captured["gid"] == allocation["gid"]
    assert captured["env"]["HOME"] == str(tmp_path / "cells" / "demo")
    assert captured["env"]["DOCKER_CONFIG"] == str(
        tmp_path / "cells" / "demo" / ".docker"
    )


def test_issued_capability_is_bound_to_op_tenant_and_slug() -> None:
    token = db_broker.issue_capability(
        "secret", op="db_relay_open", tenant="demo", slug="demo"
    )
    assert token.count(".") == 1
    with pytest.raises(db_broker.BrokerError):
        db_broker.issue_capability("secret", op="sql_query", tenant="demo", slug="demo")
