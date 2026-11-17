from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from dangerous_build.compose_normalizer import normalize_compose


def test_normalizes_compatibility_rules_deterministically(tmp_path: Path) -> None:
    (tmp_path / "haproxy.cfg").write_text("frontend web\n", encoding="utf-8")
    source = """services:
  proxy:
    container_name: pos-proxy
    ports: ["8080:80"]
    sysctls: {kernel.shmmax: "1"}
    volumes: ["./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro"]
"""
    first = normalize_compose(source, tmp_path)
    second = normalize_compose(first.text, tmp_path)
    assert second.text == first.text
    service = yaml.safe_load(first.text)["services"]["proxy"]
    assert "container_name" not in service and "ports" not in service
    assert service["networks"]["default"]["aliases"] == ["pos-proxy"]
    assert service["expose"] == ["80"]
    assert service["sysctls"] == {
        "net.ipv4.ip_unprivileged_port_start": "0"
    }
    assert "volumes" not in service
    assert service["x-spanel-readonly-files"] == [{
        "source": "haproxy.cfg",
        "target": "/usr/local/etc/haproxy/haproxy.cfg",
    }]
    assert first.evidence["source_sha256"] != first.evidence["normalized_sha256"]
    assert first.evidence["rejected"] == []


def test_discards_unsafe_aliases_and_binds(tmp_path: Path) -> None:
    (tmp_path / "directory").mkdir()
    outside = tmp_path.parent / "outside"
    outside.write_text("secret", encoding="utf-8")
    (tmp_path / "escape").symlink_to(outside)
    source = """services:
  web:
    container_name: web
    volumes:
      - ./directory:/data:ro
      - ./missing:/missing:ro
      - ./escape:/escape:ro
      - /etc/passwd:/passwd:ro
      - ./file:/data
"""
    result = normalize_compose(source, tmp_path)
    service = yaml.safe_load(result.text)["services"]["web"]
    assert "container_name" not in service
    assert "volumes" not in service
    codes = {item["code"] for item in result.evidence["warnings"]}
    assert codes == {"normalize_alias_discarded", "normalize_bind_discarded"}


def test_directory_bind_becomes_signed_file_injections(tmp_path: Path) -> None:
    healthchecks = tmp_path / "healthchecks"
    healthchecks.mkdir()
    script = healthchecks / "postgres.sh"
    script.write_text("#!/bin/sh\npg_isready\n", encoding="utf-8")
    script.chmod(0o755)
    (healthchecks / "README").write_text("docs", encoding="utf-8")
    source = """services:
  db:
    volumes: ["./healthchecks:/healthchecks"]
"""
    result = normalize_compose(source, tmp_path)
    service = yaml.safe_load(result.text)["services"]["db"]
    assert "volumes" not in service
    assert service["x-spanel-readonly-files"] == [
        {
            "source": "healthchecks/README",
            "target": "/healthchecks/README",
        },
        {
            "source": "healthchecks/postgres.sh",
            "target": "/healthchecks/postgres.sh",
            "mode": "0555",
        },
    ]
    codes = {item["code"] for item in result.evidence["warnings"]}
    assert "normalize_bind_directory_injected" in codes
    assert "normalize_bind_discarded" not in codes


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
