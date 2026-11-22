"""Bounded protocol client for the privileged host plan agent (A.SPEC 0102).

This is the only thing the unprivileged backend knows about the host. It
frames a small JSON request, writes it to a Unix Domain Socket, reads one
framed reply and maps errors to typed exceptions. It has **zero host logic**:
no subprocess, no systemd/cgroup knowledge, no filesystem writes other than
reading the shared token file. The backend decides which plan belongs to which
tenant; the agent materializes only the operation the backend asks for.

The socket is a privilege boundary, not an authorization by itself: each
request carries a short-lived HMAC capability bound to (tenant, slug, op) and
the agent additionally checks the peer's SO_PEERCRED credentials.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_SOCKET = "/run/spanel/plan-agent.sock"
DEFAULT_TOKEN_FILE = "/run/secrets/plan_agent_token"
DEFAULT_TIMEOUT = 5.0
TOKEN_TTL_SECONDS = 60
MAX_FRAME = 1 << 20  # plans are small; the protocol never carries files.

OPS = ("apply", "remove", "verify", "reconcile", "endpoint", "capacity")
RECONCILE_SUBJECT = "*"


@dataclass(frozen=True)
class CellEndpoint:
    """Read-only relay endpoint of a rootless cell (A.SPEC 0104)."""

    slug: str
    loopback_address: str
    publish_port: int
    relay_port: int
    bind: str
    allowed_sources: tuple[str, ...] = ()

    @classmethod
    def from_result(cls, result: dict[str, Any]) -> CellEndpoint:
        return cls(
            slug=str(result["slug"]),
            loopback_address=str(result["loopback_address"]),
            publish_port=int(result["publish_port"]),
            relay_port=int(result["relay_port"]),
            bind=str(result["bind"]),
            allowed_sources=tuple(result.get("allowed_sources", ())),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "loopback_address": self.loopback_address,
            "publish_port": self.publish_port,
            "relay_port": self.relay_port,
            "bind": self.bind,
            "allowed_sources": list(self.allowed_sources),
        }


class PlanAgentError(Exception):
    """Base class for every typed host-agent failure."""

    code = "agent_error"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class PlanAgentUnavailable(PlanAgentError):
    code = "unavailable"


class PlanAgentTimeout(PlanAgentError):
    code = "timeout"


class PlanAgentProtocolError(PlanAgentError):
    code = "protocol_error"


class PlanAgentAuthError(PlanAgentError):
    code = "unauthorized"


class PlanAgentDenied(PlanAgentError):
    code = "forbidden"


class PlanAgentRejected(PlanAgentError):
    code = "rejected"


ERROR_TYPES: dict[str, type[PlanAgentError]] = {
    "unavailable": PlanAgentUnavailable,
    "timeout": PlanAgentTimeout,
    "protocol_error": PlanAgentProtocolError,
    "unauthorized": PlanAgentAuthError,
    "invalid_capability": PlanAgentAuthError,
    "capability_expired": PlanAgentAuthError,
    "peer_denied": PlanAgentAuthError,
    "forbidden": PlanAgentDenied,
    "invalid_request": PlanAgentDenied,
    "invalid_plan": PlanAgentDenied,
    "tenant_not_allowed": PlanAgentDenied,
    "not_found": PlanAgentRejected,
    "rejected": PlanAgentRejected,
    "agent_error": PlanAgentError,
}


# --- capability tokens ------------------------------------------------------


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def issue_capability(
    secret: str,
    *,
    op: str,
    tenant: str,
    slug: str,
    ttl: int = TOKEN_TTL_SECONDS,
    now: float | None = None,
    nonce: str | None = None,
) -> str:
    """Return a signed capability bound to one operation, tenant and slug."""
    if op not in OPS:
        raise PlanAgentProtocolError(f"unknown operation: {op!r}")
    issued = int(time.time() if now is None else now)
    payload = {
        "op": op,
        "tenant": tenant,
        "slug": slug,
        "iat": issued,
        "exp": issued + int(ttl),
        "nonce": nonce or secrets.token_hex(8),
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    return f"{_b64e(body)}.{_b64e(signature)}"


def read_secret(path: str | Path) -> str:
    """Read the shared secret lazily so token rotation needs no restart."""
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise PlanAgentAuthError("plan agent token file is unavailable") from exc
    if not value:
        raise PlanAgentAuthError("plan agent token file is empty")
    return value


# --- framing ----------------------------------------------------------------


def encode_frame(payload: dict[str, Any]) -> bytes:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if not 0 < len(raw) <= MAX_FRAME:
        raise PlanAgentProtocolError("request frame is empty or too large")
    return struct.pack("!I", len(raw)) + raw


def _read_exact(sock: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise PlanAgentProtocolError("host agent closed the connection mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def decode_frame(sock: Any) -> dict[str, Any]:
    header = _read_exact(sock, 4)
    (size,) = struct.unpack("!I", header)
    if not 0 < size <= MAX_FRAME:
        raise PlanAgentProtocolError("reply frame is empty or too large")
    try:
        data = json.loads(_read_exact(sock, size))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlanAgentProtocolError("host agent sent invalid JSON") from exc
    if not isinstance(data, dict) or "ok" not in data:
        raise PlanAgentProtocolError("host agent sent a malformed reply")
    return data


# --- client -----------------------------------------------------------------


class HostPlanMaterializerClient:
    """Speaks the restricted plan protocol; never touches the host itself."""

    def __init__(
        self,
        socket_path: str | Path,
        token_file: str | Path,
        *,
        timeout: float = DEFAULT_TIMEOUT,
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
            raise PlanAgentUnavailable(
                f"cannot connect to the plan agent at {self.socket_path}"
            ) from exc
        return sock

    def _call(
        self,
        op: str,
        *,
        tenant: str,
        slug: str,
        plan: dict[str, Any] | None = None,
        desired: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        token = issue_capability(
            read_secret(self.token_file), op=op, tenant=tenant, slug=slug
        )
        request: dict[str, Any] = {
            "op": op,
            "tenant": tenant,
            "slug": slug,
            "token": token,
        }
        if plan is not None:
            request["plan"] = plan
        if desired is not None:
            request["desired"] = desired

        try:
            sock = self._connector()
        except OSError as exc:
            raise PlanAgentUnavailable("cannot open a connection to the host agent") from exc
        try:
            sock.sendall(encode_frame(request))
            response = decode_frame(sock)
        except PlanAgentError:
            raise
        except TimeoutError as exc:
            raise PlanAgentTimeout("host agent timed out") from exc
        except OSError as exc:
            raise PlanAgentUnavailable("host agent I/O failed") from exc
        finally:
            sock.close()

        if not response.get("ok"):
            error = response.get("error") or {}
            code = str(error.get("code", "agent_error"))
            message = str(error.get("message", "host agent rejected the request"))
            raise ERROR_TYPES.get(code, PlanAgentRejected)(message, code=code)
        result = response.get("result")
        return result if isinstance(result, dict) else {}

    def apply(self, tenant_slug: str, plan: dict[str, Any]) -> dict[str, Any]:
        return self._call("apply", tenant=tenant_slug, slug=tenant_slug, plan=plan)

    def remove(self, tenant_slug: str) -> dict[str, Any]:
        return self._call("remove", tenant=tenant_slug, slug=tenant_slug)

    def verify(self, tenant_slug: str, plan: dict[str, Any]) -> dict[str, Any]:
        return self._call("verify", tenant=tenant_slug, slug=tenant_slug, plan=plan)

    def reconcile(self, desired: list[dict[str, Any]]) -> dict[str, Any]:
        return self._call(
            "reconcile",
            tenant=RECONCILE_SUBJECT,
            slug=RECONCILE_SUBJECT,
            desired=desired,
        )

    def capacity(self) -> dict[str, Any]:
        """Read the real host totals; never mutates or measures tenant usage."""
        return self._call(
            "capacity",
            tenant=RECONCILE_SUBJECT,
            slug=RECONCILE_SUBJECT,
        )

    def endpoint(self, tenant_slug: str) -> CellEndpoint:
        """Resolve the relay endpoint of one cell; never mutates the host."""
        result = self._call(
            "endpoint", tenant=tenant_slug, slug=tenant_slug
        )
        return CellEndpoint.from_result(result)
