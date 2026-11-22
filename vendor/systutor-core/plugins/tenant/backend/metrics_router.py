"""SSE de métricas vivas por tenant (A.SPEC 0113).

Expone un único endpoint de solo lectura que reenvía los samples del daemon
Unix como Server-Sent Events. No calcula métricas, no escribe cgroups y exige
ámbito de plataforma: en v1 un tenant admin no puede abrir el stream de otro
tenant ni el suyo propio a través de esta ruta.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from plugins.tenant.backend.metrics_client import (
    MetricsClient,
    MetricsDenied,
    MetricsError,
    MetricsProtocolError,
    MetricsUnavailable,
)
from plugins.tenant.backend.service import get_tenant_by_id
from systutor.api.deps import get_db_session
from systutor.core.errors import AppError
from systutor.kernel.auth.dependencies import (
    get_current_tenant_context,
    require_permission,
)
from systutor.kernel.auth.models import User
from systutor.kernel.tenants.context import TenantContext

router = APIRouter(prefix="/tenants", tags=["tenant-metrics"])

SSE_RETRY_MS = 3000
SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",
    "Connection": "keep-alive",
}


def get_metrics_client() -> MetricsClient:
    """Dependencia inyectable: los tests la sustituyen por un cliente falso."""
    return MetricsClient.from_env()


def _error_code(exc: MetricsError) -> str:
    if isinstance(exc, MetricsDenied):
        return "tenant.metrics_denied"
    if isinstance(exc, MetricsUnavailable):
        return "tenant.metrics_unavailable"
    if isinstance(exc, MetricsProtocolError):
        return "tenant.metrics_protocol_error"
    return "tenant.metrics_error"


def _sse_event(event: str | None, payload: dict[str, Any]) -> str:
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    prefix = f"event: {event}\n" if event else ""
    return f"{prefix}data: {data}\n\n"


def _stream_samples(
    client: MetricsClient,
    slug: str,
    interval_ms: int,
) -> Iterator[str]:
    """Generador SSE; al cerrarse, el ``finally`` del cliente cierra el socket."""
    yield f"retry: {SSE_RETRY_MS}\n\n"
    try:
        for sample in client.subscribe(slug, interval_ms):
            yield _sse_event(None, sample)
    except MetricsError as exc:
        # El daemon falló a mitad: un evento de error y cierre del stream.
        yield _sse_event(
            "error",
            {"code": _error_code(exc), "message": str(exc)},
        )


@router.get("/{tenant_id}/metrics/stream")
def stream_tenant_metrics(
    tenant_id: str,
    interval_ms: int = Query(default=1000, ge=250, le=60_000),
    db: Session = Depends(get_db_session),
    context: TenantContext = Depends(get_current_tenant_context),
    _current_user: User = Depends(
        require_permission("tenant.tenants.manage", platform_only=True)
    ),
    client: MetricsClient = Depends(get_metrics_client),
) -> StreamingResponse:
    if not context.is_platform:
        # Defensa explícita además de `platform_only`.
        raise HTTPException(status_code=403, detail="Permission denied")

    tenant = get_tenant_by_id(db, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    slug = tenant.slug

    # Preflight: si el daemon no responde antes de abrir el stream, es un 503
    # claro en vez de un 200 que se corta a los pocos milisegundos.
    try:
        client.ping()
    except MetricsError as exc:
        raise AppError(
            "Cell metrics daemon is not available",
            status_code=503,
            code="tenant.metrics_unavailable",
        ) from exc

    return StreamingResponse(
        _stream_samples(client, slug, interval_ms),
        media_type="text/event-stream",
        headers=dict(SSE_HEADERS),
    )
