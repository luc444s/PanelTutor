"""A.SPEC 0124: single host-wide Cloudflare account and tenant isolation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

import systutor.kernel.models  # noqa: F401
from plugins.domains.backend.cloudflare.client import (
    CloudflareHostManaged,
    CloudflareNotFound,
    CloudflareRecord,
    CloudflareZone,
    CloudflareZoneInUse,
    CloudflareZoneUnowned,
    OAuthTokens,
)
from plugins.domains.backend.cloudflare.config import CloudflareConfig
from plugins.domains.backend.cloudflare.crypto import CloudflareCipher
from plugins.domains.backend.cloudflare.ownership import (
    ZoneOwnerResolution,
    resolve_zone_owner,
)
from plugins.domains.backend.cloudflare.provisioning import CloudflareProvisioningService
from plugins.domains.backend.cloudflare.service import (
    HOST_IDENTITY,
    PURPOSE_ACCESS,
    PURPOSE_CLIENT_SECRET,
    PURPOSE_REFRESH,
    CloudflareService,
)
from plugins.domains.backend.cloudflare.store import get_host_connection
from plugins.domains.backend.cloudflare_router import router
from plugins.domains.backend.models import (
    CloudflareConnection,
    CloudflareHostConnection,
    CloudflareOAuthClient,
    CloudflareZoneOwnership,
)
from systutor.api.deps import get_db_session
from systutor.core.database import Base
from systutor.core.errors import register_exception_handlers
from systutor.kernel.audit.models import AuditLog
from systutor.kernel.auth.dependencies import get_current_tenant_context, get_current_user
from systutor.kernel.tenants.context import TenantContext
from systutor.kernel.tenants.models import Branch, Tenant

ACCESS = "host-access-canary"
REFRESH = "host-refresh-canary"
CLIENT_SECRET = "secret-canary"


class FakeCloudflare:
    def __init__(self) -> None:
        self.refresh_calls = 0
        self.exchange_calls = 0
        self.created_zones: list[str] = []
        self.mutations: list[tuple[str, str, str | None, dict[str, object] | None]] = []
        self.zones = [
            CloudflareZone("z1", "example.com", "active", "acct1", "Lab", ("ns1",), None, None),
            CloudflareZone("z2", "other.test", "active", "acct1", "Lab", ("ns1",), None, None),
            CloudflareZone("z3", "unowned.test", "active", "acct1", "Lab", ("ns1",), None, None),
        ]
        self.records: dict[str, list[CloudflareRecord]] = {
            "z1": [
                CloudflareRecord(
                    "r1", "example.com", "A", "192.0.2.1", 300, False, None, None, None
                )
            ],
            "z2": [
                CloudflareRecord(
                    "r2", "other.test", "A", "192.0.2.2", 300, False, None, None, None
                )
            ],
            "z3": [
                CloudflareRecord(
                    "r3", "unowned.test", "A", "192.0.2.3", 300, False, None, None, None
                )
            ],
        }

    def list_scopes(self, token):
        return [
            {"id": "1", "name": "Zone Read"},
            {"id": "2", "name": "Zone Write"},
            {"id": "3", "name": "DNS Read"},
            {"id": "4", "name": "DNS Write"},
        ]

    def register_client(self, **kwargs):
        return "client-1", CLIENT_SECRET

    def update_client(self, **kwargs):
        return None

    def authorization_url(self, *, state, code_challenge, **_kwargs):
        return f"https://dash.cloudflare.com/oauth2/auth?state={state}&code_challenge={code_challenge}"

    def exchange_code(self, **kwargs):
        self.exchange_calls += 1
        return OAuthTokens(ACCESS, REFRESH, 3600, "Zone Read Zone Write DNS Read DNS Write")

    def refresh(self, **kwargs):
        self.refresh_calls += 1
        return OAuthTokens("rotated-host-access", "rotated-host-refresh", 3600, "")

    def list_zones(self, credentials, refresh=None):
        return list(self.zones)

    def count_records(self, credentials, zone_id, refresh=None):
        return len(self.records.get(zone_id, []))

    def get_zone(self, credentials, zone_id, refresh=None):
        for zone in self.zones:
            if zone.id == zone_id:
                return zone
        raise CloudflareNotFound("zone not found")

    def list_records(self, credentials, zone_id, refresh=None):
        return list(self.records.get(zone_id, []))

    def create_record(self, credentials, zone_id, payload, refresh=None):
        self.mutations.append(("create", zone_id, None, payload))
        record = CloudflareRecord(
            "r-new",
            str(payload["name"]),
            str(payload["type"]),
            str(payload["content"]),
            int(payload["ttl"]),
            bool(payload.get("proxied", False)),
            None,
            None,
            None,
        )
        self.records.setdefault(zone_id, []).append(record)
        return record

    def update_record(self, credentials, zone_id, record_id, payload, refresh=None):
        self.mutations.append(("update", zone_id, record_id, payload))
        return CloudflareRecord(
            record_id,
            str(payload["name"]),
            str(payload["type"]),
            str(payload["content"]),
            int(payload["ttl"]),
            bool(payload.get("proxied", False)),
            None,
            None,
            None,
        )

    def delete_record(self, credentials, zone_id, record_id, refresh=None):
        self.mutations.append(("delete", zone_id, record_id, None))

    def create_zone(self, credentials, *, account_id, name, refresh=None):
        self.created_zones.append(name)
        zone = CloudflareZone(f"z-{name}", name, "pending", account_id, "Lab", ("ns1",), None, None)
        self.zones.append(zone)
        self.records.setdefault(zone.id, [])
        return zone

    def delete_zone(self, credentials, zone_id, refresh=None):
        self.created_zones.append(f"deleted:{zone_id}")

    def revoke(self, **kwargs):
        return None


def _config(tmp_path: Path) -> tuple[CloudflareConfig, CloudflareCipher]:
    key = tmp_path / "key"
    key.write_bytes(b"q" * 32)
    key.chmod(0o600)
    config = CloudflareConfig(key, "https://spanel.lab", mode="single")
    return config, CloudflareCipher(config.load_key())


def _seed(tmp_path: Path, *, with_host: bool = True):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'single.db'}")
    Base.metadata.create_all(engine)
    db = Session(engine, expire_on_commit=False)
    db.add_all(
        [
            Tenant(id="t1", name="One", slug="one"),
            Tenant(id="t2", name="Two", slug="two"),
            Branch(id="b1", tenant_id="t1", name="Main", code="MAIN"),
        ]
    )
    config, cipher = _config(tmp_path)
    secret = cipher.encrypt(PURPOSE_CLIENT_SECRET, "acct1:client-1", CLIENT_SECRET)
    db.add(
        CloudflareOAuthClient(
            id=1,
            account_id="acct1",
            client_id="client-1",
            secret_ciphertext=secret.ciphertext,
            secret_nonce=secret.nonce,
            key_version=secret.key_version,
            redirect_uri=config.redirect_uri,
            scopes_json=[
                {"id": "1", "name": "Zone Read"},
                {"id": "2", "name": "Zone Write"},
                {"id": "3", "name": "DNS Read"},
                {"id": "4", "name": "DNS Write"},
                {"id": "offline_access", "name": "Offline Access"},
            ],
        )
    )
    if with_host:
        access = cipher.encrypt(PURPOSE_ACCESS, HOST_IDENTITY, ACCESS)
        refresh = cipher.encrypt(PURPOSE_REFRESH, HOST_IDENTITY, REFRESH)
        db.add(
            CloudflareHostConnection(
                id=1,
                cloudflare_account_id="acct1",
                account_name="Lab",
                access_ciphertext=access.ciphertext,
                access_nonce=access.nonce,
                refresh_ciphertext=refresh.ciphertext,
                refresh_nonce=refresh.nonce,
                key_version=access.key_version,
                scopes_json=["Zone Read", "Zone Write", "DNS Read", "DNS Write"],
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                status="active",
            )
        )
    db.add_all(
        [
            CloudflareZoneOwnership(
                tenant_id="t1", zone_id="z1", zone_name="example.com", account_id="acct1"
            ),
            CloudflareZoneOwnership(
                tenant_id="t2", zone_id="z2", zone_name="other.test", account_id="acct1"
            ),
        ]
    )
    db.commit()
    fake = FakeCloudflare()
    return engine, db, config, cipher, fake


def _service(db: Session, config: CloudflareConfig, fake: FakeCloudflare, cipher: CloudflareCipher):
    return CloudflareService(
        db,
        None,
        fake,  # type: ignore[arg-type]
        config,
        cipher=cipher,
        publisher=lambda *args: None,
    )


def _context(tenant_id: str, *extra: str, platform: bool = False) -> TenantContext:
    permissions = [*extra]
    if platform:
        permissions.append("core.platform.admin")
    return TenantContext(tenant_id, "b1", "user-1", tuple(permissions), None)


def _app(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    with_host: bool = True,
):
    key = tmp_path / "router-key"
    key.write_bytes(b"w" * 32)
    key.chmod(0o600)
    monkeypatch.setenv("SPANEL_CLOUDFLARE_ENCRYPTION_KEY_FILE", str(key))
    monkeypatch.setenv("SPANEL_CLOUDFLARE_PUBLIC_URL", "https://spanel.lab")
    monkeypatch.setenv("SPANEL_CLOUDFLARE_MODE", "single")
    engine, db, _config_value, cipher, fake = _seed(tmp_path, with_host=with_host)
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(router, prefix="/api/v1/plugins/domains")
    app.state.cloudflare_client = fake
    app.state.cloudflare_cipher = cipher
    holder = {"context": _context("t1", "domains.dns.cloudflare", platform=True)}
    app.dependency_overrides[get_db_session] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id="user-1")
    app.dependency_overrides[get_current_tenant_context] = lambda: holder["context"]
    return app, fake, db, holder, cipher, engine


def test_status_without_host_connection_is_200_disconnected(tmp_path, monkeypatch) -> None:
    app, _fake, db, holder, _cipher, engine = _app(
        tmp_path, monkeypatch, with_host=False
    )
    try:
        with TestClient(app) as client:
            holder["context"] = _context("t1", "domains.dns.cloudflare")
            response = client.get("/api/v1/plugins/domains/dns/cloudflare/status")
            assert response.status_code == 200
            body = response.json()
            assert body["connected"] is False
            assert body["status"] == "disconnected"
            assert body["tenant_id"] is None
            assert body["mode"] == "single"
            assert body["managed_by_host"] is True
            assert "access-canary" not in response.text
    finally:
        db.close()
        engine.dispose()


def test_tenant_oauth_and_disconnect_rejected_in_single(tmp_path, monkeypatch) -> None:
    app, _fake, db, holder, _cipher, engine = _app(tmp_path, monkeypatch)
    try:
        with TestClient(app) as client:
            holder["context"] = _context("t1", "domains.dns.cloudflare")
            started = client.post("/api/v1/plugins/domains/dns/cloudflare/oauth/start")
            assert started.status_code == 409
            assert started.json()["error"]["code"] == "domains.dns.cloudflare.host_managed"
            disconnected = client.post("/api/v1/plugins/domains/dns/cloudflare/disconnect")
            assert disconnected.status_code == 409
            assert disconnected.json()["error"]["code"] == "domains.dns.cloudflare.host_managed"
            assert db.query(CloudflareHostConnection).count() == 1
    finally:
        db.close()
        engine.dispose()


def test_zones_and_records_are_isolated(tmp_path, monkeypatch) -> None:
    app, fake, db, holder, _cipher, engine = _app(tmp_path, monkeypatch)
    try:
        with TestClient(app) as client:
            holder["context"] = _context("t1", "domains.dns.cloudflare")
            zones = client.get("/api/v1/plugins/domains/dns/cloudflare/zones")
            assert zones.status_code == 200
            assert [item["id"] for item in zones.json()["items"]] == ["z1"]

            foreign = client.get(
                "/api/v1/plugins/domains/dns/cloudflare/zones/z2/records"
            )
            assert foreign.status_code == 404
            assert foreign.json()["error"]["code"] == "domains.dns.cloudflare.zone_not_found"
            assert "192.0.2.2" not in foreign.text

            own = client.get(
                "/api/v1/plugins/domains/dns/cloudflare/zones/z1/records"
            )
            assert own.status_code == 200
            assert own.json()["items"][0]["content"] == "192.0.2.1"

            create_foreign = client.post(
                "/api/v1/plugins/domains/dns/cloudflare/zones/z2/records",
                json={"name": "other.test", "type": "A", "content": "192.0.2.9", "ttl": 300},
            )
            assert create_foreign.status_code == 404
            assert fake.mutations == []
    finally:
        db.close()
        engine.dispose()


def test_platform_manages_foreign_zone_with_host_credentials(
    tmp_path, monkeypatch
) -> None:
    app, fake, db, holder, _cipher, engine = _app(tmp_path, monkeypatch)
    base = "/api/v1/plugins/domains/dns/cloudflare/zones"
    try:
        with TestClient(app) as client:
            holder["context"] = _context("t1", "domains.dns.cloudflare")
            assert [
                item["id"] for item in client.get(base).json()["items"]
            ] == ["z1"]

            holder["context"] = _context(
                "t1", "domains.dns.cloudflare", platform=True
            )
            global_zones = client.get(f"{base}?scope=all")
            assert global_zones.status_code == 200
            assert {
                (item["id"], item["tenant_id"])
                for item in global_zones.json()["items"]
            } == {("z1", "t1"), ("z2", "t2")}

            foreign = client.get(f"{base}/z2/records")
            assert foreign.status_code == 200
            assert foreign.json()["items"][0]["content"] == "192.0.2.2"

            created = client.post(
                f"{base}/z2/records",
                json={
                    "name": "api.other.test",
                    "type": "A",
                    "content": "192.0.2.20",
                    "ttl": 300,
                },
            )
            assert created.status_code == 200, created.text
            updated = client.put(
                f"{base}/z2/records/r2",
                json={
                    "name": "other.test",
                    "type": "A",
                    "content": "192.0.2.21",
                    "ttl": 300,
                },
            )
            assert updated.status_code == 200
            deleted = client.delete(f"{base}/z2/records/r2")
            assert deleted.status_code == 200

            holder["context"] = _context("t1", "domains.dns.cloudflare")
            assert client.get(f"{base}/z2/records").status_code == 404
            assert fake.mutations

        audits = db.query(AuditLog).filter(
            AuditLog.action.like("domains.dns.cloudflare_record_%")
        ).all()
        assert audits
        assert all(audit.tenant_id == "t2" for audit in audits)
        assert all(audit.details["via_platform"] is True for audit in audits)
    finally:
        db.close()
        engine.dispose()


def test_provision_plan_and_apply_ownership(tmp_path) -> None:
    engine, db, config, cipher, fake = _seed(tmp_path)
    service = _service(db, config, fake, cipher)
    provisioner = CloudflareProvisioningService(service)
    try:
        reused = provisioner.plan_for_tenant(
            "t1", domain="example.com", ipv4="192.0.2.10", www=False, replace=False
        )
        assert reused["zone_action"] == "reuse"

        with pytest.raises(CloudflareZoneInUse):
            provisioner.plan_for_tenant(
                "t1", domain="other.test", ipv4="192.0.2.10", www=False, replace=False
            )
        with pytest.raises(CloudflareZoneUnowned):
            provisioner.plan_for_tenant(
                "t1", domain="unowned.test", ipv4="192.0.2.10", www=False, replace=False
            )

        first = provisioner.apply_for_tenant(
            "t1", domain="new.test", ipv4="192.0.2.11", www=True, replace=False
        )
        assert first["applied"] is True
        assert first["zone"]["name"] == "new.test"
        assert fake.created_zones.count("new.test") == 1
        ownership = db.scalar(
            select(CloudflareZoneOwnership).where(
                CloudflareZoneOwnership.zone_name == "new.test"
            )
        )
        assert ownership is not None and ownership.tenant_id == "t1"

        second = provisioner.plan_for_tenant(
            "t1", domain="new.test", ipv4="192.0.2.11", www=True, replace=False
        )
        assert second["zone_action"] == "reuse"
        again = provisioner.apply_for_tenant(
            "t1", domain="new.test", ipv4="192.0.2.11", www=True, replace=False
        )
        assert again["applied"] is True
        assert fake.created_zones.count("new.test") == 1
        assert db.query(CloudflareZoneOwnership).filter_by(zone_name="new.test").count() == 1
    finally:
        db.close()
        engine.dispose()


def test_host_oauth_callback_uses_host_identity_and_preserves_ownership(
    tmp_path,
) -> None:
    engine, db, config, cipher, fake = _seed(tmp_path, with_host=False)
    service = _service(db, config, fake, cipher)
    try:
        start = service.start_host_flow()
        assert start["mode"] == "single"
        state = parse_qs(urlsplit(str(start["authorization_url"])).query)["state"][0]
        result = service.complete_callback(state=state, code="authorization-code")
        assert result.success is True
        row = get_host_connection(db)
        assert row is not None
        assert ACCESS.encode() not in row.access_ciphertext
        assert REFRESH.encode() not in row.refresh_ciphertext

        assert service.status_for_tenant("t1")["connected"] is True
        assert service.zones_for_tenant("t1")[0]["id"] == "z1"

        plan = service.disconnect_host(apply=True)
        assert plan["disconnected"] is True
        assert db.query(CloudflareZoneOwnership).count() == 2
        assert get_host_connection(db) is None
    finally:
        db.close()
        engine.dispose()


def test_host_refresh_is_locked_and_rotates_the_singleton(tmp_path) -> None:
    engine, db, config, cipher, fake = _seed(tmp_path)
    service = _service(db, config, fake, cipher)
    try:
        row = get_host_connection(db)
        assert row is not None
        row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        old_ciphertext = bytes(row.access_ciphertext)
        db.commit()
        zones = service.zones_for_tenant("t1")
        assert [zone["id"] for zone in zones] == ["z1"]
        assert fake.refresh_calls == 1
        refreshed = get_host_connection(db)
        assert refreshed is not None
        assert refreshed.access_ciphertext != old_ciphertext
        assert b"rotated-host-access" not in refreshed.access_ciphertext
    finally:
        db.close()
        engine.dispose()


def test_host_routes_require_platform_and_list_inventory(tmp_path, monkeypatch) -> None:
    app, fake, db, holder, _cipher, engine = _app(tmp_path, monkeypatch)
    try:
        with TestClient(app) as client:
            holder["context"] = _context("t1", "domains.dns.cloudflare")
            denied = client.get(
                "/api/v1/plugins/domains/dns/cloudflare/host/status"
            )
            assert denied.status_code == 403
            assert (
                client.post("/api/v1/plugins/domains/dns/cloudflare/host/oauth/start")
                .status_code
                == 403
            )

            holder["context"] = _context(
                "t1", "domains.dns.cloudflare", platform=True
            )
            status = client.get("/api/v1/plugins/domains/dns/cloudflare/host/status")
            assert status.status_code == 200
            assert status.json()["managed_by_host"] is True

            owned = client.get("/api/v1/plugins/domains/dns/cloudflare/host/zones")
            assert owned.status_code == 200
            assert {item["id"] for item in owned.json()["items"]} == {"z1", "z2"}

            inventory = client.get(
                "/api/v1/plugins/domains/dns/cloudflare/host/zones?include_unowned=true"
            )
            assert inventory.status_code == 200
            assert {item["id"] for item in inventory.json()["items"]} == {"z1", "z2", "z3"}
            assert "access-canary" not in inventory.text
    finally:
        db.close()
        engine.dispose()


def test_adopt_zone_and_adopt_all_are_platform_operations(tmp_path) -> None:
    engine, db, config, cipher, fake = _seed(tmp_path)
    service = _service(db, config, fake, cipher)
    try:
        dry = service.adopt_zone(domain="unowned.test", tenant_id="t1", apply=False)
        assert dry["applied"] is False
        assert db.query(CloudflareZoneOwnership).filter_by(zone_name="unowned.test").count() == 0
        applied = service.adopt_zone(domain="unowned.test", tenant_id="t1", apply=True)
        assert applied["applied"] is True
        assert db.query(CloudflareZoneOwnership).filter_by(zone_name="unowned.test").count() == 1
        again = service.adopt_zone(domain="unowned.test", tenant_id="t1", apply=True)
        assert again["already_adopted"] is True
        with pytest.raises(CloudflareZoneInUse):
            service.adopt_zone(domain="example.com", tenant_id="t2", apply=False)

        # adopt-all from a legacy tenant connection: same tenant, no conflict.
        access = cipher.encrypt(PURPOSE_ACCESS, "t1", "legacy-access")
        db.add(
            CloudflareConnection(
                tenant_id="t1",
                cloudflare_account_id="acct1",
                account_name="Lab",
                access_ciphertext=access.ciphertext,
                access_nonce=access.nonce,
                refresh_ciphertext=None,
                refresh_nonce=None,
                key_version=access.key_version,
                scopes_json=["Zone Read", "Zone Write", "DNS Read", "DNS Write"],
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                status="active",
            )
        )
        db.query(CloudflareZoneOwnership).filter_by(zone_name="other.test").delete()
        db.commit()
        plan = service.adopt_all_from_tenant_connections(apply=False)
        assert plan["applied"] is False
        assert plan["conflicts"] == []
        assert {claim["zone_name"] for claim in plan["claims"]} >= {"example.com", "other.test"}
        result = service.adopt_all_from_tenant_connections(apply=True)
        assert result["applied"] is True
    finally:
        db.close()
        engine.dispose()


def test_adopt_all_uses_domain_ownership_and_reassigns(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, db, config, cipher, fake = _seed(tmp_path)
    service = _service(db, config, fake, cipher)
    resolution = {"milt.test": ("t2", ("tenant_domains",), ("t2",))}

    def fake_resolver(_db, zone_name):
        tenant_id, sources, candidates = resolution.get(
            zone_name, (None, (), ())
        )
        return ZoneOwnerResolution(tenant_id, sources, candidates)

    monkeypatch.setattr(
        "plugins.domains.backend.cloudflare.service.resolve_zone_owner",
        fake_resolver,
    )
    try:
        fake.zones.append(
            CloudflareZone("z4", "milt.test", "active", "acct1", "Lab", ("ns1",), None, None)
        )
        db.add(
            CloudflareZoneOwnership(
                tenant_id="t1", zone_id="z4", zone_name="milt.test", account_id="acct1"
            )
        )
        access = cipher.encrypt(PURPOSE_ACCESS, "t1", "legacy-access")
        db.add(
            CloudflareConnection(
                tenant_id="t1",
                cloudflare_account_id="acct1",
                account_name="Lab",
                access_ciphertext=access.ciphertext,
                access_nonce=access.nonce,
                refresh_ciphertext=None,
                refresh_nonce=None,
                key_version=access.key_version,
                scopes_json=["Zone Read", "Zone Write", "DNS Read", "DNS Write"],
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                status="active",
            )
        )
        db.query(CloudflareZoneOwnership).filter_by(zone_name="other.test").delete()
        db.commit()

        plan = service.adopt_all_from_tenant_connections(apply=False)
        claim = next(item for item in plan["claims"] if item["zone_name"] == "milt.test")
        assert claim["tenant_id"] == "t2"
        assert claim["previous_tenant_id"] == "t1"
        assert claim["action"] == "reassign"
        assert claim["owner_source"] == "tenant_domains"
        assert plan["conflicts"] == []

        result = service.adopt_all_from_tenant_connections(apply=True)
        assert result["applied"] is True
        assert result["reassigned"] == 1
        row = db.query(CloudflareZoneOwnership).filter_by(zone_name="milt.test").one()
        assert row.tenant_id == "t2"

        # Two explicit sources disagreeing must be reported, never guessed.
        resolution["milt.test"] = (None, ("hosting_sites", "tenant_domains"), ("t1", "t2"))
        ambiguous = service.adopt_all_from_tenant_connections(apply=False)
        conflict = next(
            item for item in ambiguous["conflicts"] if item["zone_name"] == "milt.test"
        )
        assert conflict["reason"] == "ambiguous_domain_owner"
        assert conflict["candidates"] == ["t1", "t2"]
        with pytest.raises(CloudflareZoneInUse):
            service.adopt_all_from_tenant_connections(apply=True)
    finally:
        db.close()
        engine.dispose()


def test_resolve_zone_owner_reads_explicit_tables() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE tenant_domains ("
                    "domain VARCHAR(255) PRIMARY KEY, tenant_id VARCHAR(36) NOT NULL)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO tenant_domains (domain, tenant_id) "
                    "VALUES ('milt.test', 't2')"
                )
            )
        with Session(engine) as session:
            resolved = resolve_zone_owner(session, "MILT.test.")
            assert resolved.tenant_id == "t2"
            assert resolved.sources == ("tenant_domains",)
            assert resolved.candidates == ("t2",)

            with engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE TABLE hosting_sites ("
                        "domain VARCHAR(255), tenant_id VARCHAR(36) NOT NULL)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO hosting_sites (domain, tenant_id) "
                        "VALUES ('milt.test', 't1')"
                    )
                )
            ambiguous = resolve_zone_owner(session, "milt.test")
            assert ambiguous.tenant_id is None
            assert ambiguous.candidates == ("t1", "t2")

            missing = resolve_zone_owner(session, "unknown.test")
            assert missing.tenant_id is None
            assert missing.candidates == ()
    finally:
        engine.dispose()


def test_service_rejects_tenant_flow_helpers_in_single(tmp_path) -> None:
    engine, db, config, cipher, fake = _seed(tmp_path)
    service = _service(db, config, fake, cipher)
    try:
        with pytest.raises(CloudflareHostManaged):
            service.start_flow_for_tenant("t1")
        with pytest.raises(CloudflareHostManaged):
            service.disconnect_for_tenant("t1", apply=True)
    finally:
        db.close()
        engine.dispose()
