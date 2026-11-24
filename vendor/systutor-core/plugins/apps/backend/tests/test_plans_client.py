"""A.SPEC 0102: tests for the bounded Unix-socket protocol client.

No real host is touched: a fake socket records the framed request and returns
a canned reply. The capability tokens are checked against the *agent's*
verifier so the two halves of the protocol are proven to agree.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

import pytest
from scripts.tenant_cell import host_agent

from plugins.apps.backend import plans_client
from plugins.apps.backend.plans_client import (
    HostPlanMaterializerClient,
    PlanAgentAuthError,
    PlanAgentDenied,
    PlanAgentProtocolError,
    PlanAgentRejected,
    PlanAgentTimeout,
    PlanAgentUnavailable,
    issue_capability,
)

SECRET = "shared-secret-for-the-lab"
NOW = 1_800_000_000.0
PLAN = {"memory": 512 * 1024**2, "cpus": 0.5, "pids": 128, "cpuset": None}


class FakeSocket:
    def __init__(self, reply: dict[str, Any] | bytes | None = None) -> None:
        if reply is None:
            reply = {"ok": True, "result": {"slice": "tenant-acme.slice"}}
        raw = reply if isinstance(reply, bytes) else plans_client.encode_frame(reply)
        self._buffer = raw
        self.sent = b""
        self.timeouts: list[float] = []
        self.path: str | None = None
        self.closed = False
        self.raise_timeout = False

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def connect(self, path: str) -> None:
        self.path = path

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, size: int) -> bytes:
        if self.raise_timeout or not self._buffer:
            raise TimeoutError("timed out")
        chunk, self._buffer = self._buffer[:size], self._buffer[size:]
        return chunk

    def close(self) -> None:
        self.closed = True


def _request(sock: FakeSocket) -> dict[str, Any]:
    (size,) = struct.unpack("!I", sock.sent[:4])
    return json.loads(sock.sent[4 : 4 + size])


def _with_token(tmp_path: Path) -> Path:
    token = tmp_path / "plan_agent_token"
    token.write_text(SECRET + "\n", encoding="utf-8")
    return token


# --- capability tokens ------------------------------------------------------


def test_capability_is_accepted_by_the_agent_verifier() -> None:
    token = issue_capability(SECRET, op="apply", tenant="acme", slug="acme", now=NOW)
    payload = host_agent.verify_capability(
        SECRET, token, op="apply", tenant="acme", slug="acme", now=NOW
    )
    assert payload["exp"] > NOW
    assert payload["op"] == "apply"


@pytest.mark.parametrize(
    "op,tenant,slug,code",
    [
        ("apply", "acme", "acme", "capability_expired"),
        ("remove", "acme", "acme", "invalid_capability"),
        ("apply", "beta", "acme", "invalid_capability"),
        ("apply", "acme", "beta", "invalid_capability"),
    ],
)
def test_capability_rejects_wrong_binding_or_expiry(
    op: str, tenant: str, slug: str, code: str
) -> None:
    token = issue_capability(SECRET, op="apply", tenant="acme", slug="acme", now=NOW)
    with pytest.raises(host_agent.AuthorizationError) as raised:
        host_agent.verify_capability(
            SECRET, token, op=op, tenant=tenant, slug=slug,
            now=NOW + (61 if code == "capability_expired" else 0),
        )
    assert raised.value.code == code


def test_capability_rejects_tampering() -> None:
    token = issue_capability(SECRET, op="apply", tenant="acme", slug="acme", now=NOW)
    body, signature = token.split(".")
    tampered = body[:-1] + ("A" if body[-1] != "A" else "B") + "." + signature
    with pytest.raises(host_agent.AuthorizationError) as raised:
        host_agent.verify_capability(
            SECRET, tampered, op="apply", tenant="acme", slug="acme", now=NOW
        )
    assert raised.value.code == "invalid_capability"


# --- protocol client --------------------------------------------------------


def test_apply_sends_a_bounded_request_and_reads_the_result(tmp_path: Path) -> None:
    client, sock = _with_client(tmp_path)
    result = client.apply("acme", PLAN)
    assert result == {"slice": "tenant-acme.slice"}
    request = _request(sock)
    assert request["op"] == "apply"
    assert request["tenant"] == "acme" and request["slug"] == "acme"
    assert request["plan"] == PLAN
    host_agent.verify_capability(
        SECRET, request["token"], op="apply", tenant="acme", slug="acme"
    )
    assert sock.closed is True


def test_provision_sends_only_the_canonical_tenant_subject(tmp_path: Path) -> None:
    client, sock = _with_client(
        tmp_path, {"ok": True, "result": {"slug": "acme", "state": "ready"}}
    )

    assert client.provision("acme")["state"] == "ready"
    request = _request(sock)
    assert set(request) == {"op", "tenant", "slug", "token"}
    assert request["op"] == "provision"
    assert request["tenant"] == request["slug"] == "acme"
    host_agent.verify_capability(
        SECRET, request["token"], op="provision", tenant="acme", slug="acme"
    )


def test_connect_sets_the_configured_timeout_and_socket_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sock = FakeSocket()
    monkeypatch.setattr(plans_client.socket, "socket", lambda *args, **kwargs: sock)
    client = HostPlanMaterializerClient(
        "/run/spanel/plan-agent.sock", _with_token(tmp_path), timeout=7.5
    )
    assert client.apply("acme", PLAN)["slice"] == "tenant-acme.slice"
    assert sock.timeouts == [7.5]
    assert sock.path == "/run/spanel/plan-agent.sock"


def _with_client(tmp_path: Path, reply=None, **kwargs):
    sock = FakeSocket(reply)
    token = _with_token(tmp_path)
    client = HostPlanMaterializerClient(
        "/run/spanel/plan-agent.sock", token, connector=lambda: sock, **kwargs
    )
    return client, sock


def test_remove_verify_and_reconcile_use_the_right_operations(tmp_path: Path) -> None:
    client, sock_rm = _with_client(
        tmp_path, {"ok": True, "result": {"removed": True}}
    )
    assert client.remove("acme") == {"removed": True}
    assert _request(sock_rm)["op"] == "remove"

    client, sock_v = _with_client(tmp_path, {"ok": True, "result": {"ok": True}})
    client.verify("acme", PLAN)
    assert _request(sock_v)["op"] == "verify"
    assert _request(sock_v)["plan"] == PLAN

    desired = [{"slug": "acme", "tenant": "t1", "plan": PLAN}]
    client, sock_rc = _with_client(tmp_path, {"ok": True, "result": {"results": []}})
    client.reconcile(desired)
    request = _request(sock_rc)
    assert request["op"] == "reconcile"
    assert request["desired"] == desired
    assert request["tenant"] == plans_client.RECONCILE_SUBJECT


def test_capacity_is_a_global_read_only_operation(tmp_path: Path) -> None:
    host = {
        "memory_bytes": 8 * 1024**3,
        "cpus": 4.0,
        "storage_bytes": 160 * 1024**3,
    }
    client, sock = _with_client(tmp_path, {"ok": True, "result": host})
    assert client.capacity() == host
    request = _request(sock)
    assert request["op"] == "capacity"
    assert request["tenant"] == plans_client.RECONCILE_SUBJECT
    assert request["slug"] == plans_client.RECONCILE_SUBJECT
    assert "plan" not in request and "desired" not in request
    host_agent.verify_capability(
        SECRET, request["token"], op="capacity",
        tenant=plans_client.RECONCILE_SUBJECT,
        slug=plans_client.RECONCILE_SUBJECT,
    )


@pytest.mark.parametrize(
    "code,error_type",
    [
        ("unauthorized", PlanAgentAuthError),
        ("invalid_capability", PlanAgentAuthError),
        ("capability_expired", PlanAgentAuthError),
        ("peer_denied", PlanAgentAuthError),
        ("forbidden", PlanAgentDenied),
        ("tenant_not_allowed", PlanAgentDenied),
        ("invalid_plan", PlanAgentDenied),
        ("not_found", PlanAgentRejected),
        ("something_new", PlanAgentRejected),
    ],
)
def test_error_codes_map_to_typed_exceptions(
    tmp_path: Path, code: str, error_type: type[Exception]
) -> None:
    client, _ = _with_client(
        tmp_path, {"ok": False, "error": {"code": code, "message": "nope"}}
    )
    with pytest.raises(error_type) as raised:
        client.apply("acme", PLAN)
    assert raised.value.code == code


def test_connection_refusal_is_unavailable(tmp_path: Path) -> None:
    def refuse() -> None:
        raise OSError("connection refused")

    client = HostPlanMaterializerClient(
        "/run/spanel/plan-agent.sock", _with_token(tmp_path), connector=refuse
    )
    with pytest.raises(PlanAgentUnavailable):
        client.apply("acme", PLAN)


def test_socket_timeout_is_typed(tmp_path: Path) -> None:
    sock = FakeSocket()
    sock.raise_timeout = True
    client = HostPlanMaterializerClient(
        "/run/spanel/plan-agent.sock", _with_token(tmp_path), connector=lambda: sock
    )
    with pytest.raises(PlanAgentTimeout):
        client.apply("acme", PLAN)


@pytest.mark.parametrize(
    "reply",
    [
        b"\x00\x00\x00\x05{}bad",
        plans_client.encode_frame({"result": {}}),  # missing ok
        struct.pack("!I", 5) + b"[1,2]",  # not a JSON object
    ],
)
def test_malformed_replies_are_protocol_errors(tmp_path: Path, reply: bytes) -> None:
    client, _ = _with_client(tmp_path, reply)
    with pytest.raises(PlanAgentProtocolError):
        client.apply("acme", PLAN)


def test_client_has_no_host_logic() -> None:
    source = Path(plans_client.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "import subprocess", "os.system(", "systemctl", "slice_name(", "docker.",
    ):
        assert forbidden not in source


def test_register_wires_the_client_only_when_configured() -> None:
    # The host environment may resolve `systutor` from another checkout, so
    # this checks the wiring statically instead of importing register.py.
    register_source = (
        Path(plans_client.__file__).resolve().parents[0] / "register.py"
    ).read_text(encoding="utf-8")
    assert "HostPlanMaterializerClient" in register_source
    assert "plan_materializer=_build_plan_materializer(settings)" in register_source
    assert "if not str(settings.plan_agent_socket):" in register_source
    assert "return None" in register_source
