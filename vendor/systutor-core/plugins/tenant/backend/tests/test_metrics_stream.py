"""Endpoint SSE de métricas vivas (A.SPEC 0113)."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

# Test this checkout, not whatever editable `systutor` happens to be installed.
_CORE_ROOT = Path(__file__).resolve().parents[4]
for _path in (str(_CORE_ROOT / "src"), str(_CORE_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import systutor.kernel.models  # noqa: F401
from plugins.tenant.backend.metrics_client import (
    MetricsDenied,
    MetricsUnavailable,
)
from plugins.tenant.backend.metrics_router import (
    get_metrics_client,
    router as metrics_router,
)
from systutor.api.deps import get_db_session
from systutor.core.database import Base
from systutor.core.errors import register_exception_handlers
from systutor.kernel.auth.dependencies import get_current_tenant_context, get_current_user
from systutor.kernel.tenants.context import TenantContext
from systutor.kernel.tenants.models import Tenant

SAMPLE = {
    "ts_ms": 1795314600000,
    "slug": "demo",
    "uid": 60070,
    "interval_ms": 1000,
    "warmup": False,
    "memory": {
        "current_bytes": 1024,
        "peak_bytes": 2048,
        "max_bytes": 4096,
        "oom_kill": 0,
    },
    "cpu": {
        "usage_usec": 1000,
        "cores": 0.5,
        "quota_usec": 50000,
        "period_usec": 100000,
        "nr_throttled": 0,
    },
    "pids": {"current": 4, "max": 64},
    "pressure": {
        "cpu": {"some_avg10": 1.0, "full_avg10": 0.0},
        "memory": {"some_avg10": 0.0, "full_avg10": 0.0},
        "io": {"some_avg10": 0.0, "full_avg10": 0.0},
    },
    "io": {
        "read_bytes": 10,
        "write_bytes": 20,
        "read_bytes_per_s": 1.0,
        "write_bytes_per_s": 2.0,
    },
}


class FakeMetricsClient:
    def __init__(
        self,
        samples: list[dict[str, object]] | None = None,
        *,
        failure: Exception | None = None,
        ping_failure: Exception | None = None,
    ) -> None:
        self.samples = list(samples or [])
        self.failure = failure
        self.ping_failure = ping_failure
        self.pinged = False
        self.subscribed: tuple[str, int] | None = None
        self.closed = False

    def ping(self) -> bool:
        self.pinged = True
        if self.ping_failure is not None:
            raise self.ping_failure
        return True

    def subscribe(self, slug: str, interval_ms: int) -> Iterator[dict[str, object]]:
        self.subscribed = (slug, interval_ms)
        try:
            yield from self.samples
            if self.failure is not None:
                raise self.failure
        finally:
            self.closed = True


def _context(*, platform: bool = True, manage: bool = True) -> TenantContext:
    permissions: list[str] = []
    if platform:
        permissions.append("core.platform.admin")
    if manage:
        permissions.append("tenant.tenants.manage")
    return TenantContext(
        current_tenant_id="t1",
        current_branch_id=None,
        current_user_id="user-1",
        current_permissions=tuple(permissions),
        current_warehouse_ids=None,
    )


@contextmanager
def _metrics_app(fake: FakeMetricsClient, context: TenantContext | None = None):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        session.add(Tenant(id="t1", name="Demo", slug="demo", domain="demo.com"))
        session.add(Tenant(id="t2", name="Other", slug="other", domain="other.com"))
        session.add(
            Tenant(
                id="t3",
                name="Legal Attorney",
                slug="Legalattorney.pe",
                domain="legalattorney.pe",
            )
        )
        session.commit()

    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(metrics_router, prefix="/api/v1/plugins/tenant")

    def fake_session() -> Iterator[Session]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    resolved = context or _context()
    user = SimpleNamespace(id="user-1", tenant_id="t1", branch_id=None)
    app.dependency_overrides[get_db_session] = fake_session
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_current_tenant_context] = lambda: resolved
    app.dependency_overrides[get_metrics_client] = lambda: fake

    try:
        with TestClient(app) as client:
            yield client
    finally:
        engine.dispose()


STREAM = "/api/v1/plugins/tenant/tenants/t1/metrics/stream"


def test_stream_sends_retry_and_one_data_event_per_sample() -> None:
    second = {**SAMPLE, "ts_ms": SAMPLE["ts_ms"] + 1000}
    fake = FakeMetricsClient([SAMPLE, second])

    with _metrics_app(fake) as client:
        response = client.get(f"{STREAM}?interval_ms=500")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-cache"
    assert response.headers["x-accel-buffering"] == "no"
    assert response.headers["connection"] == "keep-alive"
    body = response.text
    assert "retry: 3000" in body
    assert body.count("data: ") == 2
    first_data = body.split("data: ", 1)[1].split("\n", 1)[0]
    assert json.loads(first_data)["memory"]["max_bytes"] == 4096
    assert fake.subscribed == ("demo", 500)
    assert fake.closed is True, "el generador debe cerrar el socket al terminar"


def test_stream_uses_the_slug_of_the_requested_tenant() -> None:
    fake = FakeMetricsClient([SAMPLE])

    with _metrics_app(fake) as client:
        response = client.get(
            "/api/v1/plugins/tenant/tenants/t2/metrics/stream?interval_ms=1000"
        )

    assert response.status_code == 200
    assert fake.subscribed == ("other", 1000)


def test_stream_uses_the_canonical_cell_slug() -> None:
    fake = FakeMetricsClient([SAMPLE])

    with _metrics_app(fake) as client:
        response = client.get(
            "/api/v1/plugins/tenant/tenants/t3/metrics/stream?interval_ms=1000"
        )

    assert response.status_code == 200
    assert fake.subscribed == ("legalattorney-pe", 1000)


def test_stream_emits_an_error_event_and_closes_on_daemon_failure() -> None:
    fake = FakeMetricsClient(
        [SAMPLE],
        failure=MetricsUnavailable("el daemon se cayó"),
    )

    with _metrics_app(fake) as client:
        response = client.get(STREAM)

    assert response.status_code == 200
    body = response.text
    assert "event: error" in body
    assert "tenant.metrics_unavailable" in body
    assert "el daemon se cayó" in body
    assert fake.closed is True


def test_stream_maps_denied_errors_to_their_own_code() -> None:
    fake = FakeMetricsClient(failure=MetricsDenied("token inválido"))

    with _metrics_app(fake) as client:
        response = client.get(STREAM)

    assert "event: error" in response.text
    assert "tenant.metrics_denied" in response.text


def test_stream_returns_503_before_streaming_when_the_daemon_is_missing() -> None:
    fake = FakeMetricsClient(ping_failure=MetricsUnavailable("socket ausente"))

    with _metrics_app(fake) as client:
        response = client.get(STREAM)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "tenant.metrics_unavailable"
    assert fake.pinged is True
    assert fake.subscribed is None, "no se debe abrir el stream si el ping falla"


def test_stream_allows_a_tenant_user_to_read_its_own_tenant() -> None:
    fake = FakeMetricsClient([SAMPLE])

    with _metrics_app(fake, _context(platform=False, manage=False)) as client:
        response = client.get(STREAM)

    assert response.status_code == 200
    assert fake.subscribed == ("demo", 1000)


def test_stream_denies_a_tenant_user_reading_another_tenant() -> None:
    fake = FakeMetricsClient([SAMPLE])

    with _metrics_app(fake, _context(platform=False)) as client:
        response = client.get(
            "/api/v1/plugins/tenant/tenants/t2/metrics/stream"
        )

    assert response.status_code == 403
    assert fake.subscribed is None


def test_stream_does_not_require_the_manage_permission() -> None:
    fake = FakeMetricsClient([SAMPLE])

    with _metrics_app(fake, _context(platform=True, manage=False)) as client:
        response = client.get(STREAM)

    assert response.status_code == 200
    assert fake.subscribed == ("demo", 1000)


def test_stream_returns_404_for_an_unknown_tenant() -> None:
    fake = FakeMetricsClient([SAMPLE])

    with _metrics_app(fake) as client:
        response = client.get(
            "/api/v1/plugins/tenant/tenants/missing/metrics/stream"
        )

    assert response.status_code == 404
    assert fake.subscribed is None


@pytest.mark.parametrize("interval", [249, 60001])
def test_stream_rejects_out_of_range_intervals(interval: int) -> None:
    fake = FakeMetricsClient([SAMPLE])

    with _metrics_app(fake) as client:
        response = client.get(f"{STREAM}?interval_ms={interval}")

    assert response.status_code == 422
    assert fake.pinged is False
