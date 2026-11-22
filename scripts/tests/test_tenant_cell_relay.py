"""A.SPEC 0104: relay, endpoint verb, source allowlist and control plane.

Every test uses loopback sockets and a local HTTP server: no Docker, no
systemd, no Traefik. The HTML body matches the E2E acceptance criterion.
"""

from __future__ import annotations

import http.server
import os
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tenant_cell import alloc, cli, host_agent, network, plans, relay
from scripts.tenant_cell.host_agent import Peer, PlanAgent

BODY = b"hola, este es un htrml que se ve desde un contenedor rootless"
SECRET = "shared-secret-for-the-lab"


_RESERVED_PORTS: set[int] = set()


def _free_port() -> int:
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port not in _RESERVED_PORTS:
            _RESERVED_PORTS.add(port)
            return port


def _roundtrip(agent: relay.RelayControlAgent, request: dict[str, Any]) -> dict[str, Any]:
    from scripts.tenant_cell import host_agent as ha

    server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        ha.write_frame(client, request)
        agent.handle_connection(server)
        return ha.read_frame(client)
    finally:
        server.close()
        client.close()


def _http_server() -> http.server.ThreadingHTTPServer:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)

        def log_message(self, *_args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _endpoint(slug: str, relay_port: int, target_port: int) -> dict[str, Any]:
    return {
        "slug": slug,
        "loopback_address": "127.0.0.1",
        "publish_port": target_port,
        "relay_port": relay_port,
        "bind": "127.0.0.1",
        "allowed_sources": ["127.0.0.1"],
    }


# --- pure network derivation -------------------------------------------------


def test_relay_port_is_stable_and_disjoint_from_publish_port() -> None:
    for index in (0, 1, 7, 254, 19999):
        assert network.relay_port(index) == 40000 + index
        assert network.relay_port(index) != network.publish_port(index)
        assert network.publish_port(index) < 40000 <= network.relay_port(index)


def test_endpoint_is_derived_from_registry_without_mutation(tmp_path: Path) -> None:
    alloc.allocate(str(tmp_path), "acme")
    registry = alloc.load_registry(str(tmp_path))
    registry["allocations"]["acme"]["index"] = 3
    alloc.save_registry(str(tmp_path), registry)
    before = (tmp_path / "registry.json").read_bytes()

    endpoint = relay.endpoint_for_allocation(
        registry["allocations"]["acme"],
        bind="172.18.0.1",
        sources=("172.18.0.4",),
    )

    assert endpoint == {
        "slug": "acme",
        "loopback_address": network.loopback_address(3),
        "publish_port": network.publish_port(3),
        "relay_port": 40003,
        "bind": "172.18.0.1",
        "allowed_sources": ["172.18.0.4"],
    }
    assert (tmp_path / "registry.json").read_bytes() == before


# --- read-only endpoint verb on the host agent -------------------------------


def test_endpoint_verb_returns_host_facts_and_never_mutates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from plugins.apps.backend.plans_client import issue_capability

    alloc.allocate(str(tmp_path), "acme")
    registry = alloc.load_registry(str(tmp_path))
    registry["allocations"]["acme"]["index"] = 5
    alloc.save_registry(str(tmp_path), registry)
    before = (tmp_path / "registry.json").read_bytes()
    monkeypatch.setattr(
        relay, "allowed_sources", lambda *a, **k: ("172.18.0.4",)
    )

    agent = PlanAgent(
        object(), secret=SECRET, allowed_uids={4242}, data_root=tmp_path,
        peer_resolver=lambda _sock: Peer(4242, 100),
    )
    request = {
        "op": "endpoint",
        "tenant": "acme",
        "slug": "acme",
        "token": issue_capability(SECRET, op="endpoint", tenant="acme", slug="acme"),
    }
    response = agent.dispatch(request, Peer(4242, 100))

    assert response["ok"] is True
    assert response["result"]["relay_port"] == 40005
    assert response["result"]["bind"] == relay.DEFAULT_BIND
    assert response["result"]["allowed_sources"] == ["172.18.0.4"]
    assert (tmp_path / "registry.json").read_bytes() == before
    # Extra/unknown fields are still refused: the read-only verb widens nothing.
    request["path"] = "/etc"
    assert agent.dispatch(request, Peer(4242, 100))["error"]["code"] == (
        host_agent.ERR_REQUEST
    )


# --- real TCP relay ----------------------------------------------------------


def test_relay_forwards_the_exact_body_both_ways_and_filters_sources() -> None:
    upstream = _http_server()
    target_port = int(upstream.server_address[1])
    relay_port = _free_port()
    allowed = relay.TCPRelay("127.0.0.1", ("127.0.0.1",))
    denied_port = _free_port()
    denied = relay.TCPRelay("127.0.0.1", ("127.0.0.99",))
    try:
        assert allowed.apply(_endpoint("acme", relay_port, target_port))["relay_port"] == (
            relay_port
        )
        with urllib.request.urlopen(
            f"http://127.0.0.1:{relay_port}/", timeout=3
        ) as reply:
            assert reply.read() == BODY
        assert allowed.status()[0]["slug"] == "acme"

        denied.apply(_endpoint("beta", denied_port, target_port))
        with socket.create_connection(("127.0.0.1", denied_port), timeout=2) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            try:
                data = sock.recv(128)
            except OSError:  # the relay resets a disallowed source
                data = b""
            assert data == b""
        assert denied.remove("beta") is True
        assert denied.status() == []
    finally:
        allowed.close()
        denied.close()
        upstream.shutdown()
        upstream.server_close()


def test_connect_timeout_does_not_truncate_a_slow_response() -> None:
    class SlowHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            time.sleep(0.15)
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)

        def log_message(self, *_args: object) -> None:
            pass

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    relay_port = _free_port()
    service = relay.TCPRelay(
        "127.0.0.1", ("127.0.0.1",), connect_timeout=0.05
    )
    try:
        service.apply(
            _endpoint("slow", relay_port, int(upstream.server_address[1]))
        )
        with urllib.request.urlopen(
            f"http://127.0.0.1:{relay_port}/", timeout=2
        ) as reply:
            assert reply.read() == BODY
    finally:
        service.close()
        upstream.shutdown()
        upstream.server_close()


def test_relay_reload_replaces_endpoints_and_closes_old_listeners() -> None:
    upstream = _http_server()
    target_port = int(upstream.server_address[1])
    first_port, second_port = _free_port(), _free_port()
    service = relay.TCPRelay("127.0.0.1", ("127.0.0.1",))
    try:
        service.reload([_endpoint("acme", first_port, target_port)])
        with urllib.request.urlopen(f"http://127.0.0.1:{first_port}/", timeout=3) as r:
            assert r.read() == BODY
        service.reload([_endpoint("beta", second_port, target_port)])
        assert [item["slug"] for item in service.status()] == ["beta"]
        with urllib.request.urlopen(f"http://127.0.0.1:{second_port}/", timeout=3) as r:
            assert r.read() == BODY
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", first_port), timeout=1)
    finally:
        service.close()
        upstream.shutdown()
        upstream.server_close()


# --- control plane -----------------------------------------------------------


def test_control_plane_enforces_peer_uid_and_verb_allowlist() -> None:
    service = relay.TCPRelay("127.0.0.1", ("127.0.0.1",))
    agent = relay.RelayControlAgent(service, allowed_uids={os.getuid()})
    try:
        reply = _roundtrip(agent, {"op": "status"})
        assert reply["ok"] is True and reply["result"] == []
        assert _roundtrip(agent, {"op": "exec"})["error"]["code"] == "forbidden"
    finally:
        service.close()

    untrusted = relay.RelayControlAgent(
        service,
        allowed_uids={4242},
        peer_resolver=lambda _sock: SimpleNamespace(uid=9999),
    )
    response = untrusted.dispatch({"op": "status"}, SimpleNamespace(uid=9999))
    assert response["error"]["code"] == "peer_denied"
    assert relay.CONTROL_OPS == ("apply", "remove", "status", "reload")


def test_control_plane_apply_and_remove_use_framed_requests() -> None:
    upstream = _http_server()
    target_port = int(upstream.server_address[1])
    port = _free_port()
    service = relay.TCPRelay("127.0.0.1", ("127.0.0.1",))
    agent = relay.RelayControlAgent(
        service,
        allowed_uids={4242},
        peer_resolver=lambda _sock: Peer(4242, 100),
    )
    try:
        applied = _roundtrip(agent, {
            "op": "apply", "endpoint": _endpoint("acme", port, target_port),
        })
        assert applied["ok"] is True
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3) as reply:
            assert reply.read() == BODY

        removed = _roundtrip(agent, {"op": "remove", "slug": "acme"})
        assert removed["result"] == {"removed": True}
    finally:
        service.close()
        upstream.shutdown()
        upstream.server_close()


# --- CLI exposure ------------------------------------------------------------


def test_cli_exposes_edge_relay_with_the_host_only_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from typer.testing import CliRunner

    runner = CliRunner()
    help_result = runner.invoke(cli.app, ["edge-relay", "--help"])
    assert help_result.exit_code == 0, help_result.output
    assert "--data-root" in help_result.output

    monkeypatch.delenv(plans.MUTATION_GATE, raising=False)
    gated = runner.invoke(cli.app, ["edge-relay"])
    assert gated.exit_code == 2
    assert plans.MUTATION_GATE in gated.output


def test_relay_unit_runs_as_traefik_uid_without_docker_mounts() -> None:
    unit = (
        ROOT / "scripts" / "tenant_cell" / "deploy" / "spanel-edge-relay.service"
    ).read_text(encoding="utf-8")
    assert "User=<SPANEL_TRAEFIK_UID>" in unit
    assert "docker.sock" not in unit
    assert "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS=1" in unit
    assert plans.MUTATION_GATE in unit
