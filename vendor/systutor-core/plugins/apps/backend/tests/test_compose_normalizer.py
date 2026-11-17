from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from plugins.apps.backend.compose_normalizer import (
    ComposeNormalizationError,
    normalize_compose,
)


def test_alias_validation_and_port_normalization(tmp_path: Path) -> None:
    result = normalize_compose(
        """services:
  api: {container_name: pos-api, ports: ["127.0.0.1:8080:80"]}
  web: {container_name: api, expose: [8080], sysctls: {kernel.shmmax: 1}}
""",
        tmp_path,
    )
    data = yaml.safe_load(result.text)
    assert data["services"]["api"]["networks"]["default"]["aliases"] == ["pos-api"]
    assert data["services"]["api"]["expose"] == ["80"]
    assert data["services"]["api"]["sysctls"]
    assert "networks" not in data["services"]["web"]
    assert "sysctls" not in data["services"]["web"]
    assert {item["code"] for item in result.evidence["warnings"]} == {
        "normalize_alias_discarded",
        "normalize_sysctl_discarded",
    }


def test_duplicate_invalid_and_reserved_aliases_are_discarded(tmp_path: Path) -> None:
    result = normalize_compose(
        """services:
  a: {container_name: duplicate}
  b: {container_name: duplicate}
  c: {container_name: "-invalid"}
  d: {container_name: spanel-control}
""",
        tmp_path,
    )
    assert all(
        "networks" not in config
        for config in yaml.safe_load(result.text)["services"].values()
    )
    assert len(result.evidence["warnings"]) == 4


def test_file_bind_matrix_and_source_bytes_are_unchanged(tmp_path: Path) -> None:
    good = tmp_path / "proxy.cfg"
    good.write_bytes(b"config")
    (tmp_path / "dir").mkdir()
    source = """services:
  web:
    volumes:
      - ./proxy.cfg:/etc/proxy.cfg:ro
      - ./proxy.cfg:/etc/write.cfg
      - ./dir:/etc/dir:ro
      - ./missing:/etc/missing:ro
      - /etc/passwd:/etc/passwd:ro
"""
    before = good.read_bytes()
    result = normalize_compose(source, tmp_path)
    assert good.read_bytes() == before
    service = yaml.safe_load(result.text)["services"]["web"]
    assert "volumes" not in service
    assert service["x-spanel-readonly-files"] == [{
        "source": "proxy.cfg", "target": "/etc/proxy.cfg",
    }]
    assert len(result.evidence["warnings"]) == 4


def test_nested_compose_resolves_binds_from_its_directory(tmp_path: Path) -> None:
    compose_dir = tmp_path / "deploy"
    compose_dir.mkdir()
    (compose_dir / "compose.yml").write_text("services: {}\n", encoding="utf-8")
    (compose_dir / "proxy.cfg").write_text("ok", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.cfg"
    outside.write_text("secret", encoding="utf-8")
    result = normalize_compose(
        """services:
  proxy:
    volumes:
      - ./proxy.cfg:/etc/proxy.cfg:ro
      - ./../../TMP_OUTSIDE:/etc/outside.cfg:ro
""".replace("TMP_OUTSIDE", outside.name),
        tmp_path,
        "deploy/compose.yml",
    )
    service = yaml.safe_load(result.text)["services"]["proxy"]
    assert "volumes" not in service
    assert service["x-spanel-readonly-files"] == [{
        "source": "proxy.cfg", "target": "/etc/proxy.cfg",
    }]


def test_is_idempotent_and_rejects_invalid_compose(tmp_path: Path) -> None:
    first = normalize_compose("services: {web: {expose: [443]}}\n", tmp_path)
    assert normalize_compose(first.text, tmp_path).text == first.text
    with pytest.raises(ComposeNormalizationError, match="invalid_yaml"):
        normalize_compose("services: [", tmp_path)
