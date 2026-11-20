"""A.SPEC 0102: privilege-boundary tests for the host plan agent.

The agent is exercised with a fake executor (no real slice, drop-in, cgroup or
systemd call). One test uses a real ``AF_UNIX`` socketpair and the kernel's
``SO_PEERCRED`` to prove the credential check is genuinely enforced.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Any

import pytest
from scripts.tenant_cell import alloc, host_agent, materializer, plans
from scripts.tenant_cell.host_agent import Peer, PlanAgent

from plugins.apps.backend import plans_client
from plugins.apps.backend.plans_client import issue_capability

SECRET = "shared-secret-for-the-lab"
ROOT = Path(__file__).resolve().parents[6]
PLAN = {"memory": "512M", "cpus": 0.5, "pids": 128}
OK_PROBE = {"ok": True, "memory_max": "536870912"}


class FakeExecutor:
    def __init__(self, evidence: dict[str, Any] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.evidence = dict(evidence or OK_PROBE)

    def _rec(self, name: str, **kwargs: object) -> None:
        self.calls.append((name, dict(kwargs)))

    def install_tenant_slice(self, slug, plan):
        self._rec("install_tenant_slice", slug=slug, plan=plan)

    def remove_tenant_slice(self, slug):
        self._rec("remove_tenant_slice", slug=slug)

    def install_user_manager_dropin(self, slug, uid):
        self._rec("install_user_manager_dropin", slug=slug, uid=uid)

    def remove_user_manager_dropin(self, slug, uid):
        self._rec("remove_user_manager_dropin", slug=slug, uid=uid)

    def restart_user_manager(self, uid):
        self._rec("restart_user_manager", uid=uid)

    def read_plan_state(self, uid):
        self._rec("read_plan_state", uid=uid)
        return {
            "slice": plans.user_slice(uid),
            "effective": {},
            "properties": {},
            "owner_uid": str(uid),
            "cgroup_path": "",
        }

    def apply_plan_in_place(self, uid, plan):
        self._rec("apply_plan_in_place", uid=uid, plan=plan)

    def reset_plan_properties(self, uid):
        self._rec("reset_plan_properties", uid=uid)

    def run_plan_probe(self, slug, uid, plan, **kwargs):
        self._rec("run_plan_probe", slug=slug, uid=uid, plan=plan, **kwargs)
        return dict(self.evidence)

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


@pytest.fixture(autouse=True)
def _gate(monkeypatch: pytest.MonkeyPatch) -> None:
    # The gate belongs to this (agent) process only.
    monkeypatch.setenv(plans.MUTATION_GATE, "1")


def _cell(tmp_path: Path, slug: str = "acme") -> None:
    alloc.allocate(str(tmp_path), slug)
    alloc.update_allocation(str(tmp_path), slug, state="ready", cgroup_driver="systemd")


def _agent(
    tmp_path: Path,
    executor: FakeExecutor | None = None,
    *,
    uid: int = 4242,
    evidence: dict[str, Any] | None = None,
) -> tuple[PlanAgent, FakeExecutor]:
    executor = executor or FakeExecutor(evidence)
    svc = materializer.PlanMaterializer(executor, tmp_path)
    agent = PlanAgent(
        svc, secret=SECRET, allowed_uids={uid}, data_root=tmp_path,
        peer_resolver=lambda _sock: Peer(uid, 100),
    )
    return agent, executor


def _request(op: str, *, tenant: str | None = None, slug: str | None = None, **extra: Any):
    if op == "reconcile":
        tenant = tenant or host_agent.RECONCILE_SUBJECT
        slug = slug or host_agent.RECONCILE_SUBJECT
    else:
        tenant = tenant or "acme"
        slug = slug or "acme"
    request: dict[str, Any] = {
        "op": op,
        "tenant": tenant,
        "slug": slug,
        "token": issue_capability(SECRET, op=op, tenant=tenant, slug=slug),
    }
    request.update(extra)
    return request


def _error(response: dict[str, Any]) -> str:
    return response["error"]["code"]


# --- peer credentials -------------------------------------------------------


def test_agent_rejects_an_untrusted_peer_uid_without_any_host_call(
    tmp_path: Path,
) -> None:
    _cell(tmp_path)
    agent, executor = _agent(tmp_path)
    response = agent.dispatch(_request("apply", plan=PLAN), Peer(9999, 100))
    assert _error(response) == host_agent.ERR_PEER
    assert executor.calls == []
    assert not plans.plans_path(tmp_path).exists()


def test_agent_checks_gid_when_configured(tmp_path: Path) -> None:
    _cell(tmp_path)
    executor = FakeExecutor()
    svc = materializer.PlanMaterializer(executor, tmp_path)
    agent = PlanAgent(
        svc, secret=SECRET, allowed_uids={4242}, allowed_gids={100},
        data_root=tmp_path, peer_resolver=lambda _sock: Peer(4242, 999),
    )
    response = agent.dispatch(_request("apply", plan=PLAN), Peer(4242, 999))
    assert _error(response) == host_agent.ERR_PEER


def test_real_unix_socket_enforces_peer_credentials(tmp_path: Path) -> None:
    _cell(tmp_path)
    executor = FakeExecutor()
    svc = materializer.PlanMaterializer(executor, tmp_path)
    agent = PlanAgent(
        svc, secret=SECRET, allowed_uids={os.getuid()}, data_root=tmp_path,
    )  # real peer_resolver -> SO_PEERCRED
    server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    request = _request("apply", plan=PLAN)
    client.sendall(plans_client.encode_frame(request))
    agent.handle_connection(server)
    reply = plans_client.decode_frame(client)
    acme_uid = int(alloc.load_registry(tmp_path)["allocations"]["acme"]["uid"])
    assert reply["ok"] is True
    assert reply["result"]["slice"] == plans.user_slice(acme_uid)
    assert executor.names() == [
        "read_plan_state", "apply_plan_in_place", "read_plan_state",
    ]
    client.close()


# --- capability + authorization ---------------------------------------------


def test_agent_rejects_tampered_or_expired_capability(tmp_path: Path) -> None:
    _cell(tmp_path)
    agent, executor = _agent(tmp_path)
    body, signature = (
        issue_capability(SECRET, op="apply", tenant="acme", slug="acme").split(".")
    )
    bad = body[:-1] + ("A" if body[-1] != "A" else "B") + "." + signature
    request = {"op": "apply", "tenant": "acme", "slug": "acme", "token": bad, "plan": PLAN}
    assert _error(agent.dispatch(request, Peer(4242, 100))) == host_agent.ERR_CAP

    expired = issue_capability(
        SECRET, op="apply", tenant="acme", slug="acme", now=1_000_000.0
    )
    request["token"] = expired
    assert _error(agent.dispatch(request, Peer(4242, 100))) == host_agent.ERR_EXPIRED
    assert executor.calls == []


def test_agent_rejects_generic_exec_and_arbitrary_paths(tmp_path: Path) -> None:
    _cell(tmp_path)
    agent, executor = _agent(tmp_path)
    assert host_agent.ALLOWED_OPS == (
        "apply",
        "apply_in_place",
        "remove",
        "verify",
        "probe",
        "reconcile",
        "migrate_all",
        "nat_apply",
        "nat_remove",
    )
    assert "exec" not in host_agent.ALLOWED_OPS
    exec_request = _request("apply", plan=PLAN)
    exec_request["op"] = "exec"  # a token bound to apply cannot authorize exec
    assert _error(agent.dispatch(exec_request, Peer(4242, 100))) == host_agent.ERR_FORBIDDEN

    path_request = _request("apply", path="/etc/systemd/system/evil.slice", plan=PLAN)
    assert _error(agent.dispatch(path_request, Peer(4242, 100))) == host_agent.ERR_REQUEST
    assert executor.calls == []


def test_agent_derives_slice_from_the_validated_slug_only(tmp_path: Path) -> None:
    _cell(tmp_path)
    agent, executor = _agent(tmp_path)
    response = agent.dispatch(_request("apply", plan=PLAN), Peer(4242, 100))
    acme_uid = int(alloc.load_registry(tmp_path)["allocations"]["acme"]["uid"])
    assert response["ok"] is True
    assert response["result"]["slice"] == plans.user_slice(acme_uid)
    applied = next(kw for name, kw in executor.calls if name == "apply_plan_in_place")
    assert applied["uid"] == acme_uid
    assert "path" not in applied and "unit" not in applied


def test_agent_refuses_an_unallocated_tenant(tmp_path: Path) -> None:
    agent, executor = _agent(tmp_path)
    response = agent.dispatch(
        _request("apply", tenant="ghost", slug="ghost", plan=PLAN), Peer(4242, 100)
    )
    assert _error(response) == host_agent.ERR_TENANT
    assert executor.calls == []


@pytest.mark.parametrize(
    "plan",
    [
        {"memory": 0, "cpus": 0.5, "pids": 128},
        {"memory": "512M", "cpus": -1, "pids": 128},
        {"memory": "512M", "cpus": 0.5, "pids": 0},
        {"memory": "512M", "cpus": 0.5, "pids": 128, "path": "/etc"},
    ],
)
def test_agent_rejects_invalid_parameters_before_any_write(
    tmp_path: Path, plan: dict[str, Any]
) -> None:
    _cell(tmp_path)
    agent, executor = _agent(tmp_path)
    response = agent.dispatch(_request("apply", plan=plan), Peer(4242, 100))
    assert _error(response) == host_agent.ERR_PLAN
    assert executor.calls == []


# --- lifecycle + reconciliation ---------------------------------------------


def test_agent_supports_only_the_allowed_plan_operations(tmp_path: Path) -> None:
    _cell(tmp_path)
    agent, executor = _agent(tmp_path)
    assert agent.dispatch(_request("apply", plan=PLAN), Peer(4242, 100))["ok"]
    assert agent.dispatch(_request("verify", plan=PLAN), Peer(4242, 100))["ok"]
    assert agent.dispatch(_request("remove"), Peer(4242, 100))["ok"]
    desired = [{"slug": "acme", "tenant": "t1", "plan": PLAN}]
    assert agent.dispatch(_request("reconcile", desired=desired), Peer(4242, 100))["ok"]
    assert "run_plan_probe" in executor.names()


def test_reconcile_repairs_drift_and_missing_cache(tmp_path: Path) -> None:
    _cell(tmp_path)
    executor = FakeExecutor({"ok": False})
    agent, _ = _agent(tmp_path, executor, evidence={"ok": False})
    agent.dispatch(_request("apply", plan=PLAN), Peer(4242, 100))
    desired = [{"slug": "acme", "tenant": "t1", "plan": PLAN}]

    # Kernel evidence now differs -> the agent re-applies the desired plan.
    response = agent.dispatch(_request("reconcile", desired=desired), Peer(4242, 100))
    assert response["result"]["results"][0]["action"] == "re-applied"

    # Simulate a restart that lost plans.json: the DB desire is still enough.
    plans.plans_path(tmp_path).unlink()
    response = agent.dispatch(_request("reconcile", desired=desired), Peer(4242, 100))
    assert response["result"]["results"][0]["action"] == "re-applied"


def test_reconcile_removes_only_stale_cached_slugs(tmp_path: Path) -> None:
    _cell(tmp_path, "acme")
    _cell(tmp_path, "beta")
    agent, executor = _agent(tmp_path)
    agent.dispatch(_request("apply", plan=PLAN), Peer(4242, 100))
    agent.dispatch(_request("apply", tenant="beta", slug="beta", plan=PLAN), Peer(4242, 100))
    before = len(executor.calls)

    response = agent.dispatch(
        _request("reconcile", desired=[{"slug": "acme", "tenant": "t1", "plan": PLAN}]),
        Peer(4242, 100),
    )
    assert response["result"]["removed"] == ["beta"]
    registry = alloc.load_registry(tmp_path)["allocations"]
    acme_uid = int(registry["acme"]["uid"])
    beta_uid = int(registry["beta"]["uid"])
    suffix = executor.calls[before:]
    assert not any(
        name == "reset_plan_properties" and kw.get("uid") == acme_uid
        for name, kw in suffix
    )
    assert any(
        name == "reset_plan_properties" and kw.get("uid") == beta_uid
        for name, kw in suffix
    )


# --- deployment boundaries --------------------------------------------------


def test_mutation_gate_is_only_in_the_agent_service(tmp_path: Path) -> None:
    unit = (ROOT / "scripts/tenant_cell/deploy/spanel-plan-agent.service").read_text()
    assert "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS=1" in unit
    client_source = Path(plans_client.__file__).read_text(encoding="utf-8")
    assert plans.MUTATION_GATE not in client_source
    assert "systemctl" not in client_source


def test_host_wiring_lab_is_explicitly_non_production(tmp_path: Path) -> None:
    from scripts.tenant_cell import host_wiring_lab

    source = Path(host_wiring_lab.__file__).read_text(encoding="utf-8")
    assert "LAB" in source and "NOT PRODUCTION" in source
    _cell(tmp_path)
    svc = host_wiring_lab.lab_plan_materializer(tmp_path, FakeExecutor())
    acme_uid = int(alloc.load_registry(tmp_path)["allocations"]["acme"]["uid"])
    assert isinstance(svc, materializer.PlanMaterializer)
    assert svc.apply("acme", PLAN)["slice"] == plans.user_slice(acme_uid)
