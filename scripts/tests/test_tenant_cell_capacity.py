"""A.SPEC 0111: the host agent reports real capacity, never tenant usage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from scripts.tenant_cell import host_agent


def test_read_capacity_reports_real_host_facts(tmp_path: Path) -> None:
    result = host_agent.read_capacity(tmp_path)
    assert result["memory_bytes"] > 0
    assert result["cpus"] > 0
    assert result["storage_bytes"] > 0
    assert 0 <= result["storage_available_bytes"] <= result["storage_bytes"]
    assert result["source"] == "host"
    assert result["data_root"] == str(tmp_path)
    assert result["read_at"]
    assert "usage" not in result


def test_read_capacity_fails_closed_without_a_data_root() -> None:
    with pytest.raises(RuntimeError, match="data root"):
        host_agent.read_capacity("/nonexistent/spanel-capacity-root")


def _request(op: str) -> dict[str, Any]:
    from plugins.apps.backend.plans_client import issue_capability

    return {
        "op": op,
        "tenant": host_agent.RECONCILE_SUBJECT,
        "slug": host_agent.RECONCILE_SUBJECT,
        "token": issue_capability(
            "secret", op=op,
            tenant=host_agent.RECONCILE_SUBJECT,
            slug=host_agent.RECONCILE_SUBJECT,
        ),
    }


def test_agent_capacity_is_read_only_and_does_not_touch_the_materializer(
    tmp_path: Path,
) -> None:
    class NoCalls:
        def apply(self, *_args, **_kwargs):
            raise AssertionError("capacity must never mutate the host")

    facts = {
        "memory_bytes": 8 * 1024**3,
        "cpus": 4.0,
        "storage_bytes": 160 * 1024**3,
        "storage_available_bytes": 100 * 1024**3,
        "read_at": "2026-11-21T06:45:00+00:00",
        "source": "host",
        "data_root": str(tmp_path),
    }
    agent = host_agent.PlanAgent(
        NoCalls(), secret="secret", allowed_uids={4242}, data_root=tmp_path,
        peer_resolver=lambda _sock: host_agent.Peer(4242, 100),
        capacity_reader=lambda _root: dict(facts),
    )
    response = agent.dispatch(_request("capacity"), host_agent.Peer(4242, 100))
    assert response == {"ok": True, "result": facts}
