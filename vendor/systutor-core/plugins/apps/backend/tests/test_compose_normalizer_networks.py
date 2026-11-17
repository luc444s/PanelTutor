"""Regression coverage: N1 must never destroy a service's network topology."""

from __future__ import annotations

from pathlib import Path

import yaml

from plugins.apps.backend.compose_normalizer import normalize_compose

MULTINET = """services:
  backend:
    image: my-backend
    container_name: api
    networks:
      - frontend_net
      - database_net
  db:
    image: postgres:16
    networks:
      - database_net
networks:
  frontend_net:
  database_net:
"""

EXTERNAL = """services:
  backend:
    container_name: api
    networks:
      - shared_net
networks:
  shared_net:
    external: true
"""


def _codes(result: object) -> set[str]:
    return {item["code"] for item in result.evidence["warnings"]}  # type: ignore[attr-defined]


def test_n1_preserves_networks_from_list(tmp_path: Path) -> None:
    """The exact reported failure: two networks replaced by a single default."""
    result = normalize_compose(MULTINET, tmp_path)
    data = yaml.safe_load(result.text)
    assert data["services"]["backend"]["networks"] == {
        "frontend_net": {"aliases": ["api"]},
        "database_net": {"aliases": ["api"]},
    }
    assert data["services"]["db"]["networks"] == ["database_net"]
    assert data["networks"] == {"frontend_net": None, "database_net": None}
    rule = result.evidence["rules"][0]
    assert rule["id"] == "N1" and rule["applied"] is True
    assert rule["services"] == ["backend"]
    assert normalize_compose(result.text, tmp_path).text == result.text


def test_n1_preserves_network_options_and_existing_aliases(tmp_path: Path) -> None:
    source = """services:
  backend:
    container_name: api
    networks:
      frontend_net:
        aliases: [legacy-api]
        ipv4_address: 172.20.0.10
        priority: 100
      database_net:
        aliases: [db-link]
networks:
  frontend_net:
  database_net:
"""
    result = normalize_compose(source, tmp_path)
    networks = yaml.safe_load(result.text)["services"]["backend"]["networks"]
    assert networks["frontend_net"] == {
        "aliases": ["legacy-api", "api"],
        "ipv4_address": "172.20.0.10",
        "priority": 100,
    }
    assert networks["database_net"] == {"aliases": ["db-link", "api"]}


def test_n1_absent_networks_still_uses_default(tmp_path: Path) -> None:
    result = normalize_compose(
        "services:\n  api: {container_name: legacy-api}\n", tmp_path
    )
    service = yaml.safe_load(result.text)["services"]["api"]
    assert service["networks"] == {"default": {"aliases": ["legacy-api"]}}


def test_n1_network_mode_is_incompatible_and_warns(tmp_path: Path) -> None:
    source = """services:
  sidecar:
    container_name: legacy-sidecar
    network_mode: service:api
"""
    result = normalize_compose(source, tmp_path)
    service = yaml.safe_load(result.text)["services"]["sidecar"]
    assert "networks" not in service
    assert service["network_mode"] == "service:api"
    assert "container_name" not in service
    assert "normalize_alias_network_mode" in _codes(result)
    assert result.evidence["rules"][0]["applied"] is False
    assert normalize_compose(result.text, tmp_path).text == result.text


def test_n1_external_networks_are_not_aliased_without_authorization(
    tmp_path: Path,
) -> None:
    result = normalize_compose(EXTERNAL, tmp_path)
    data = yaml.safe_load(result.text)
    assert data["services"]["backend"]["networks"] == ["shared_net"]
    assert data["networks"]["shared_net"] == {"external": True}
    assert "normalize_alias_external_network" in _codes(result)
    assert result.evidence["rules"][0]["applied"] is False
    assert normalize_compose(result.text, tmp_path).text == result.text


def test_n1_external_network_alias_requires_explicit_policy(tmp_path: Path) -> None:
    denied = normalize_compose(EXTERNAL, tmp_path)
    allowed = normalize_compose(
        EXTERNAL,
        tmp_path,
        authorized_external_networks=frozenset({"shared_net"}),
    )
    assert yaml.safe_load(denied.text)["services"]["backend"]["networks"] == ["shared_net"]
    assert yaml.safe_load(allowed.text)["services"]["backend"]["networks"] == {
        "shared_net": {"aliases": ["api"]}
    }
    assert yaml.safe_load(allowed.text)["networks"]["shared_net"] == {"external": True}
    assert allowed.evidence["rules"][0]["applied"] is True


def test_n1_external_default_is_not_autowired(tmp_path: Path) -> None:
    source = """services:
  api: {container_name: legacy-api}
networks:
  default: {external: true}
"""
    result = normalize_compose(source, tmp_path)
    assert "networks" not in yaml.safe_load(result.text)["services"]["api"]
    assert "normalize_alias_external_network" in _codes(result)


def test_n1_empty_networks_is_explicit_and_warns(tmp_path: Path) -> None:
    source = """services:
  isolated:
    container_name: legacy-isolated
    networks: []
"""
    result = normalize_compose(source, tmp_path)
    service = yaml.safe_load(result.text)["services"]["isolated"]
    assert service["networks"] == []
    assert "normalize_alias_empty_networks" in _codes(result)
    assert result.evidence["rules"][0]["applied"] is False
    assert normalize_compose(result.text, tmp_path).text == result.text
