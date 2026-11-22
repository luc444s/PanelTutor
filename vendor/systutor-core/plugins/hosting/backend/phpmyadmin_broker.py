"""Client for the ephemeral database-relay protocol of the host agent.

Hosting never learns a cell socket, a container name or a port from the browser.
It asks the privileged host agent to open a bounded relay for one panel session
and receives only a loopback host/port that the shared phpMyAdmin can reach.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import socket
import struct
import time
from pathlib import Path
from typing import Any

from systutor.core.errors import AppError

MAX_FRAME = 1 << 20
MAX_TTL = 3600
OPS = ("db_relay_open", "db_relay_status", "db_relay_close", "db_relay_reconcile")


class BrokerUnavailable(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(
            message, status_code=409, code="hosting_phpmyadmin_unavailable"
        )


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def issue_capability(
    secret: str, *, op: str, tenant: str, slug: str, ttl: int = 60
) -> str:
    if op not in OPS:
        raise BrokerUnavailable(f"unknown relay operation: {op!r}")
    issued = int(time.time())
    payload = {
        "op": op,
        "tenant": tenant,
        "slug": slug,
        "iat": issued,
        "exp": issued + int(ttl),
        "nonce": secrets.token_hex(8),
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    return f"{_b64e(body)}.{_b64e(signature)}"


def read_secret(path: str | Path) -> str:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise BrokerUnavailable("the host-agent token file is unavailable") from exc
    if not value:
        raise BrokerUnavailable("the host-agent token file is empty")
    return value


def _encode(payload: dict[str, Any]) -> bytes:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if not 0 < len(raw) <= MAX_FRAME:
        raise BrokerUnavailable("relay request is empty or too large")
    return struct.pack("!I", len(raw)) + raw


def _read_exact(sock: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise BrokerUnavailable("host agent closed the connection mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _decode(sock: Any) -> dict[str, Any]:
    (size,) = struct.unpack("!I", _read_exact(sock, 4))
    if not 0 < size <= MAX_FRAME:
        raise BrokerUnavailable("relay reply is empty or too large")
    try:
        data = json.loads(_read_exact(sock, size))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerUnavailable("host agent sent invalid JSON") from exc
    if not isinstance(data, dict) or "ok" not in data:
        raise BrokerUnavailable("host agent sent a malformed reply")
    return data


class PmaBrokerClient:
    def __init__(
        self,
        socket_path: str | Path,
        token_file: str | Path,
        *,
        timeout: float = 10.0,
        connector: Any = None,
    ) -> None:
        self.socket_path = str(socket_path)
        self.token_file = Path(token_file)
        self.timeout = float(timeout)
        self._connector = connector or self._connect

    def _connect(self) -> Any:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
        except OSError as exc:
            sock.close()
            raise BrokerUnavailable("the host agent is not reachable") from exc
        return sock

    def _call(self, op: str, *, tenant: str, slug: str, **fields: Any) -> dict[str, Any]:
        request = {
            "op": op,
            "tenant": tenant,
            "slug": slug,
            "token": issue_capability(
                read_secret(self.token_file), op=op, tenant=tenant, slug=slug
            ),
            **fields,
        }
        try:
            sock = self._connector()
        except OSError as exc:
            raise BrokerUnavailable("cannot open the host-agent socket") from exc
        try:
            sock.sendall(_encode(request))
            response = _decode(sock)
        except TimeoutError as exc:
            raise BrokerUnavailable("the host agent timed out") from exc
        except OSError as exc:
            raise BrokerUnavailable("host-agent I/O failed") from exc
        finally:
            sock.close()
        if not response.get("ok"):
            error = response.get("error") or {}
            raise BrokerUnavailable(str(error.get("message", "relay rejected")))
        result = response.get("result")
        return result if isinstance(result, dict) else {}

    def open(
        self,
        *,
        tenant: str,
        tenant_id: str,
        site_id: str,
        pma_session_id: str,
        source_ip: str,
        ttl: int,
    ) -> dict[str, Any]:
        relay_id = "pma-" + secrets.token_hex(16)
        result = self._call(
            "db_relay_open",
            tenant=tenant,
            slug=tenant,
            relay_id=relay_id,
            tenant_id=tenant_id,
            site_id=site_id,
            pma_session_id=pma_session_id,
            source_ip=source_ip,
            ttl=min(MAX_TTL, max(1, int(ttl))),
        )
        return {**result, "relay_id": result.get("relay_id", relay_id)}

    def close(self, tenant_slug: str, relay_id: str) -> None:
        self._call(
            "db_relay_close",
            tenant=tenant_slug,
            slug=tenant_slug,
            relay_id=relay_id,
        )

    def status(self, tenant_slug: str, relay_id: str) -> dict[str, Any]:
        return self._call(
            "db_relay_status",
            tenant=tenant_slug,
            slug=tenant_slug,
            relay_id=relay_id,
        )


def broker_enabled(settings: Any) -> bool:
    return bool(getattr(settings, "phpmyadmin_rootless_broker", True))


def source_ip_from_env(settings: Any) -> str:
    configured = str(getattr(settings, "phpmyadmin_source_ip", "") or "").strip()
    if configured:
        return configured
    raise BrokerUnavailable(
        "SPANEL_PHPMYADMIN_SOURCE_IP is required for rootless phpMyAdmin"
    )


def server_address(result: dict[str, Any]) -> str:
    host = str(result.get("broker_host") or "").strip()
    port = int(result.get("broker_port") or 0)
    if not host or not 1 <= port <= 65535:
        raise BrokerUnavailable("the host agent returned an invalid relay endpoint")
    return f"{host}:{port}"


def close_relay_quietly(
    settings: Any, tenant_slug: str | None, relay_id: str | None
) -> None:
    """Idempotent cleanup used by logout, expiry and failed logins."""
    if not relay_id or not tenant_slug:
        return
    try:
        client = PmaBrokerClient(
            settings.phpmyadmin_broker_socket,
            settings.phpmyadmin_broker_token_file,
            timeout=settings.phpmyadmin_broker_timeout,
        )
        client.close(tenant_slug, relay_id)
    except Exception:  # noqa: BLE001 - the relay expires on its own TTL
        return


__all__ = [
    "BrokerUnavailable",
    "PmaBrokerClient",
    "broker_enabled",
    "close_relay_quietly",
    "issue_capability",
    "server_address",
    "source_ip_from_env",
]
