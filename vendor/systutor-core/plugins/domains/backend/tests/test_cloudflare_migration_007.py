"""Migration 007: additive host tables, idempotent and reversible."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from systutor.kernel.tenants.models import Tenant

MIGRATIONS = Path(__file__).resolve().parents[2] / "migrations"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        f"domains_migration_{name}", MIGRATIONS / f"{name}.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _seed_tenant(engine) -> None:
    with Session(engine) as session:
        session.add(Tenant(id="t1", name="One", slug="one"))
        session.commit()


def test_upgrade_is_idempotent_and_keeps_004_tables() -> None:
    migration_004 = _load("004_create_cloudflare_oauth")
    migration = _load("007_cloudflare_single_mode")
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        Tenant.__table__.create(bind=engine)
        _seed_tenant(engine)
        with Session(engine) as session:
            migration_004.upgrade(session)
            migration.upgrade(session)
            migration.upgrade(session)
            session.commit()

        names = set(inspect(engine).get_table_names())
        assert {
            "domains_cloudflare_connections",
            "domains_cloudflare_oauth_flows",
            "domains_cloudflare_host_connection",
            "domains_cloudflare_host_oauth_flows",
            "domains_cloudflare_zone_ownership",
        } <= names

        host_columns = {
            column["name"]
            for column in inspect(engine).get_columns(
                "domains_cloudflare_host_connection"
            )
        }
        assert host_columns == {
            "id",
            "cloudflare_account_id",
            "account_name",
            "access_ciphertext",
            "access_nonce",
            "refresh_ciphertext",
            "refresh_nonce",
            "key_version",
            "scopes_json",
            "expires_at",
            "status",
            "created_at",
            "updated_at",
        }
        flow_columns = {
            c["name"] for c in inspect(engine).get_columns("domains_cloudflare_host_oauth_flows")
        }
        assert "tenant_id" not in flow_columns
        assert "state_hash" in flow_columns and "verifier_ciphertext" in flow_columns
        ownership_columns = {
            c["name"] for c in inspect(engine).get_columns("domains_cloudflare_zone_ownership")
        }
        assert ownership_columns == {
            "id",
            "tenant_id",
            "zone_id",
            "zone_name",
            "account_id",
            "created_at",
            "updated_at",
        }
        ownership_uniques = inspect(engine).get_unique_constraints(
            "domains_cloudflare_zone_ownership"
        )
        constrained = {tuple(sorted(item["column_names"])) for item in ownership_uniques}
        assert ("zone_id",) in constrained and ("zone_name",) in constrained
        assert inspect(engine).get_foreign_keys("domains_cloudflare_zone_ownership")

        # Singleton check and uniqueness are enforced.
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO domains_cloudflare_host_connection "
                        "(id, cloudflare_account_id, account_name, access_ciphertext, "
                        "access_nonce, key_version, scopes_json, status) VALUES "
                        "(2, 'acct1', 'Lab', :access, :nonce, 1, '[]', 'active')"
                    ),
                    {"access": b"x", "nonce": b"y"},
                )
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO domains_cloudflare_zone_ownership "
                    "(id, tenant_id, zone_id, zone_name, account_id) VALUES "
                    "('o1', 't1', 'z1', 'example.com', 'acct1')"
                )
            )
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO domains_cloudflare_zone_ownership "
                        "(id, tenant_id, zone_id, zone_name, account_id) VALUES "
                        "('o2', 't1', 'z2', 'example.com', 'acct1')"
                    )
                )

        with Session(engine) as session:
            migration.downgrade(session)
            session.commit()
        names = set(inspect(engine).get_table_names())
        assert "domains_cloudflare_host_connection" not in names
        assert "domains_cloudflare_host_oauth_flows" not in names
        assert "domains_cloudflare_zone_ownership" not in names
        assert "domains_cloudflare_connections" in names
        assert "domains_cloudflare_oauth_flows" in names

        with Session(engine) as session:
            migration.upgrade(session)
            migration.upgrade(session)
            session.commit()
        with engine.connect() as connection:
            assert connection.execute(
                text("SELECT COUNT(*) FROM domains_cloudflare_host_connection")
            ).scalar() == 0
    finally:
        engine.dispose()
