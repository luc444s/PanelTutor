from __future__ import annotations

from plugins.apps.backend.settings import AppsSettings


def test_default_timeout_allows_a_full_cell_provision(monkeypatch) -> None:
    monkeypatch.delenv("SPANEL_PLAN_AGENT_TIMEOUT", raising=False)
    # A.SPEC 0118: provisioning creates users, cells, nftables rules,
    # AppArmor profiles and waits for logind; 5s was not enough.
    assert AppsSettings.from_env().plan_agent_timeout >= 30.0


def test_timeout_can_be_overridden_by_environment(monkeypatch) -> None:
    monkeypatch.setenv("SPANEL_PLAN_AGENT_TIMEOUT", "12.5")
    assert AppsSettings.from_env().plan_agent_timeout == 12.5
