"""Unit tests for the autonomous rootless phpMyAdmin setup script."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import configure_phpmyadmin_rootless as mod


def test_pick_pma_network_prefers_proxy_and_skips_invalid_gateways() -> None:
    info = {
        "NetworkSettings": {
            "Networks": {
                "spanel-db": {"IPAddress": "172.30.0.3", "Gateway": "invalid IP"},
                "mariadb_internal": {
                    "IPAddress": "172.19.0.9",
                    "Gateway": "172.19.0.1",
                },
                "proxy": {"IPAddress": "172.18.0.17", "Gateway": "172.18.0.1"},
            }
        }
    }
    assert mod.pick_pma_network(info) == ("proxy", "172.18.0.17", "172.18.0.1")


def test_host_database_url_rewrites_the_docker_dns_host() -> None:
    app = "postgresql+psycopg://postgres:postgres@postgres:5432/sysadmin"
    assert (
        mod.host_database_url(app, "172.27.0.2")
        == "postgresql+psycopg://postgres:postgres@172.27.0.2:5432/sysadmin"
    )


def test_update_dotenv_is_idempotent_and_preserves_other_keys(tmp_path: Path) -> None:
    env = tmp_path / ".env.docker"
    env.write_text(
        "OTHER=1\nSPANEL_PHPMYADMIN_SOURCE_IP=10.0.0.1\n"
        "SPANEL_PHPMYADMIN_SOURCE_IP=10.0.0.2\n",
        encoding="utf-8",
    )
    assert mod.update_dotenv(env, "172.18.0.17", dry_run=False) is True
    text = env.read_text(encoding="utf-8")
    assert "OTHER=1" in text
    assert text.count("SPANEL_PHPMYADMIN_SOURCE_IP=") == 1
    assert "SPANEL_PHPMYADMIN_SOURCE_IP=172.18.0.17" in text
    assert mod.update_dotenv(env, "172.18.0.17", dry_run=False) is False


def test_ufw_rule_uses_the_discovered_source_and_range(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "Rule added", "")

    monkeypatch.setattr(mod, "ufw_active", lambda: True)
    monkeypatch.setattr(mod, "run", fake_run)
    mod.ensure_ufw("172.18.0.17", dry_run=False)
    assert calls == [
        [
            "ufw",
            "allow",
            "from",
            "172.18.0.17",
            "to",
            "any",
            "port",
            "41000:41999",
            "proto",
            "tcp",
            "comment",
            "spanel-pma-broker",
        ]
    ]


def test_render_plan_env_contains_discovered_values() -> None:
    ctx = mod.Context(
        pma="pma",
        app="app",
        postgres_service="postgres",
        postgres_container="pg",
        plan_env=Path("/tmp/env"),
        dropin=Path("/tmp/dropin"),
        env_file=Path("/tmp/.env"),
        python="/python",
        pma_network="proxy",
        pma_ip="172.18.0.17",
        broker_bind="172.18.0.1",
        database_url="postgresql+psycopg://u:p@172.27.0.2:5432/db",
    )
    text = mod.render_plan_env(ctx)
    assert "SPANEL_DB_BROKER_BIND=172.18.0.1" in text
    assert "SPANEL_DB_BROKER_SOURCES=172.18.0.17" in text
    assert "SPANEL_TENANT_CELL_NET=slirp4netns" in text
    assert "SYSTUTOR_DATABASE_URL=postgresql+psycopg://u:p@172.27.0.2:5432/db" in text
    assert mod.CONNECTOR_IMAGE in text
