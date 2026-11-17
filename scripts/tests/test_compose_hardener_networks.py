"""N2: the hardener must preserve every authorized network attachment."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from dangerous_build.compose import ComposeHardeningError, ServicePolicy, harden_compose
from dangerous_build.dockerfile import WritablePath

POLICY = {"web": ServicePolicy(1000, 1000, (WritablePath("/data"),))}


def _harden(source: str, **kwargs: object) -> dict[str, object]:
    return yaml.safe_load(harden_compose(source, POLICY, **kwargs))  # type: ignore[return-value]


def test_multi_network_membership_and_aliases_are_preserved() -> None:
    source = """services:
  web:
    networks:
      frontend_net:
        aliases: [legacy-web]
        priority: 10
      database_net:
        aliases: [legacy-db]
    x-spanel-normalized-aliases: [pos-web]
networks:
  frontend_net:
  database_net:
"""
    data = _harden(source)
    assert data["services"]["web"]["networks"] == {
        "frontend_net": {"aliases": ["legacy-web", "pos-web"], "priority": 10},
        "database_net": {"aliases": ["legacy-db", "pos-web"]},
    }
    assert data["networks"] == {
        "frontend_net": {"internal": True},
        "database_net": {"internal": True},
    }


def test_absent_networks_use_default_with_alias() -> None:
    source = """services:
  web:
    x-spanel-normalized-aliases: [pos-web]
"""
    data = _harden(source)
    assert data["services"]["web"]["networks"] == {"default": {"aliases": ["pos-web"]}}
    assert data["networks"] == {"default": {"internal": True}}


def test_no_networks_and_no_alias_adds_nothing() -> None:
    data = _harden("services:\n  web: {}\n")
    assert "networks" not in data["services"]["web"]
    assert data["networks"] == {"default": {"internal": True}}


def test_explicit_empty_networks_stays_empty() -> None:
    data = _harden("services:\n  web: {networks: []}\n")
    assert data["services"]["web"]["networks"] == []


def test_internal_missing_becomes_true_and_false_needs_policy() -> None:
    source = """services:
  web: {networks: [upstream]}
networks:
  upstream: {internal: false}
"""
    with pytest.raises(ComposeHardeningError, match="not authorized"):
        _harden(source)
    data = _harden(source, egress_networks=frozenset({"upstream"}))
    assert data["networks"] == {"upstream": {"internal": False}}


def test_external_requires_authorization_and_name_is_restricted() -> None:
    source = """services:
  web: {networks: [shared]}
networks:
  shared: {external: true, name: tenant_shared}
"""
    with pytest.raises(ComposeHardeningError, match="not authorized"):
        _harden(source)
    data = _harden(source, authorized_external_networks=frozenset({"shared"}))
    assert data["networks"] == {"shared": {"external": True, "name": "tenant_shared"}}
    fixed_name = source.replace("external: true, name: tenant_shared", "name: tenant_shared")
    with pytest.raises(ComposeHardeningError, match="fixed name"):
        _harden(fixed_name)


@pytest.mark.parametrize("mode", ["host", "service:api", "container:abc"])
def test_network_mode_is_rejected_explicitly(mode: str) -> None:
    with pytest.raises(ComposeHardeningError, match="network_mode"):
        _harden(f"services:\n  web: {{network_mode: {mode}}}\n")


def test_undeclared_service_network_fails() -> None:
    with pytest.raises(ComposeHardeningError, match="undeclared network"):
        _harden("services:\n  web: {networks: [missing]}\n")


def test_policy_for_undeclared_network_fails() -> None:
    with pytest.raises(ComposeHardeningError, match="undeclared networks"):
        _harden("services:\n  web: {}\n", egress_networks=frozenset({"missing"}))


def test_host_driver_is_rejected() -> None:
    source = """services:
  web: {networks: [odd]}
networks:
  odd: {driver: host}
"""
    with pytest.raises(ComposeHardeningError, match="host driver"):
        _harden(source)
