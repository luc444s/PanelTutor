"""Privileged host agent for tenant resource plans (A.SPEC 0102).

Runs as a controlled systemd service and exposes a Unix Domain Socket with a
restricted protocol: ``apply`` / ``remove`` / ``verify`` / ``reconcile`` of
tenant plans and nothing else. On every call it validates:

* the peer's ``SO_PEERCRED`` uid/gid (the socket alone is not authorization);
* a short-lived HMAC capability bound to (tenant, slug, operation);
* tenant authorization (the slug must be an allocated cell);
* plan parameters (memory > 0, cpus > 0, pids > 0, valid slug/cpuset).

The agent never accepts a path or a unit name from the client: every slice and
drop-in name is derived from the validated slug by the existing
``PlanMaterializer``. The mutation gate lives only in this host process.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import alloc, materializer, network, plans, relay

ALLOWED_OPS = (
    "apply", "apply_in_place", "remove", "verify", "probe", "reconcile",
    "migrate_all", "nat_apply", "nat_remove",
)
# A.SPEC 0104: ``endpoint`` is a read-only host fact, deliberately kept out of
# the mutation allowlist (ALLOWED_OPS) so existing callers keep the same gate.
READ_OPS = ("endpoint", "nat_status")
ALL_OPS = ALLOWED_OPS + READ_OPS
RECONCILE_SUBJECT = "*"
REQUEST_KEYS = {
    "op", "tenant", "slug", "token", "plan", "desired", "dry_run",
    "only", "exclude", "stop_on_failure", "memory_mb", "seconds",
}
PLAN_KEYS = plans.PLAN_KEYS
DESIRED_KEYS = {"tenant", "slug", "plan", "status", "desired_hash"}
MAX_FRAME = 1 << 20
MAX_DESIRED = 1000

# Shared error vocabulary with plugins/apps/backend/plans_client.py.
ERR_PEER = "peer_denied"
ERR_CAP = "invalid_capability"
ERR_EXPIRED = "capability_expired"
ERR_REQUEST = "invalid_request"
ERR_FORBIDDEN = "forbidden"
ERR_PLAN = "invalid_plan"
ERR_TENANT = "tenant_not_allowed"
ERR_PROTOCOL = "protocol_error"
ERR_AGENT = "agent_error"


class AuthorizationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Peer:
    uid: int
    gid: int


def peer_credential(sock: Any) -> Peer:
    """Read the kernel-provided credentials of the Unix socket peer."""
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, gid = struct.unpack("3i", raw)
    return Peer(uid, gid)


# --- capability verification (mirrors plans_client.issue_capability) --------


def _b64d(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def verify_capability(
    secret: str,
    token: Any,
    *,
    op: str,
    tenant: str,
    slug: str,
    now: float | None = None,
) -> dict[str, Any]:
    """Validate signature, expiry and the (tenant, slug, op) binding."""
    if not isinstance(token, str) or token.count(".") != 1:
        raise AuthorizationError(ERR_CAP, "capability token is malformed")
    body_b64, signature_b64 = token.split(".")
    try:
        body = _b64d(body_b64)
        signature = _b64d(signature_b64)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuthorizationError(ERR_CAP, "capability token is not base64") from exc
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise AuthorizationError(ERR_CAP, "capability signature is invalid")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise AuthorizationError(ERR_CAP, "capability payload is invalid") from exc
    if not isinstance(payload, dict):
        raise AuthorizationError(ERR_CAP, "capability payload is invalid")
    current = time.time() if now is None else now
    if not isinstance(payload.get("exp"), (int, float)) or payload["exp"] <= current:
        raise AuthorizationError(ERR_EXPIRED, "capability token has expired")
    if (
        payload.get("op") != op
        or payload.get("tenant") != tenant
        or payload.get("slug") != slug
    ):
        raise AuthorizationError(ERR_CAP, "capability does not match this request")
    return payload


# --- framing (mirrors plans_client framing) ---------------------------------


def _read_exact(sock: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ValueError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(sock: Any) -> dict[str, Any]:
    header = _read_exact(sock, 4)
    (size,) = struct.unpack("!I", header)
    if not 0 < size <= MAX_FRAME:
        raise ValueError("invalid request frame size")
    data = json.loads(_read_exact(sock, size))
    if not isinstance(data, dict):
        raise TypeError("request must be a JSON object")
    return data


def write_frame(sock: Any, payload: dict[str, Any]) -> None:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def resolve_endpoint(slug: str, data_root: str | Path) -> dict[str, Any]:
    """Read-only cell endpoint derived from the registry and network.py."""
    allocation = alloc.load_registry(data_root)["allocations"].get(slug)
    if allocation is None:
        raise AuthorizationError(ERR_TENANT, f"tenant {slug} has no cell allocation")
    return relay.endpoint_for_allocation(allocation)


# --- agent ------------------------------------------------------------------


class PlanAgent:
    """Authorization boundary plus a thin dispatcher over ``PlanMaterializer``."""

    def __init__(
        self,
        materializer_: materializer.PlanMaterializer,
        *,
        secret: str,
        allowed_uids: set[int] | frozenset[int],
        data_root: str | Path,
        allowed_gids: set[int] | frozenset[int] | None = None,
        clock: Callable[[], float] | None = None,
        peer_resolver: Callable[[Any], Peer] | None = None,
        endpoint_resolver: Callable[[str, str | Path], dict[str, Any]] | None = None,
        migration_handler: Callable[..., dict[str, Any]] | None = None,
        nat_handler: Callable[[str, str], dict[str, Any]] | None = None,
    ) -> None:
        if not secret:
            raise ValueError("the host agent requires a shared secret")
        if not allowed_uids:
            raise ValueError("the host agent requires at least one allowed peer uid")
        self.materializer = materializer_
        self.secret = secret
        self.allowed_uids = frozenset(allowed_uids)
        self.allowed_gids = frozenset(allowed_gids) if allowed_gids is not None else None
        self.data_root = Path(data_root)
        self.clock = clock or time.time
        self.peer_resolver = peer_resolver or peer_credential
        self.endpoint_resolver = endpoint_resolver or resolve_endpoint
        self.migration_handler = migration_handler
        self.nat_handler = nat_handler

    def authorize_peer(self, peer: Peer) -> None:
        if peer.uid not in self.allowed_uids:
            raise AuthorizationError(ERR_PEER, f"peer uid {peer.uid} is not allowed")
        if self.allowed_gids is not None and peer.gid not in self.allowed_gids:
            raise AuthorizationError(ERR_PEER, f"peer gid {peer.gid} is not allowed")

    def _authorize_tenant(self, slug: str) -> None:
        if slug not in alloc.load_registry(self.data_root)["allocations"]:
            raise AuthorizationError(ERR_TENANT, f"tenant {slug} has no cell allocation")

    def _validate_plan(self, payload: Any) -> None:
        if not isinstance(payload, dict) or set(payload) - PLAN_KEYS:
            raise AuthorizationError(ERR_PLAN, "plan must only carry memory/cpus/pids/cpuset")
        if not {"memory", "cpus", "pids"} <= set(payload):
            raise AuthorizationError(ERR_PLAN, "plan is missing memory/cpus/pids")
        plans.validate_plan(payload["memory"], payload["cpus"], payload["pids"])

    def _validate_desired(self, desired: Any) -> None:
        if not isinstance(desired, list) or len(desired) > MAX_DESIRED:
            raise AuthorizationError(ERR_PLAN, "desired must be a bounded list")
        for entry in desired:
            if not isinstance(entry, dict) or set(entry) - DESIRED_KEYS:
                raise AuthorizationError(ERR_PLAN, "invalid desired entry")
            plans.validate_slug(str(entry.get("slug", "")))
            self._validate_plan(entry.get("plan"))

    def authorize(self, request: dict[str, Any], peer: Peer) -> str:
        self.authorize_peer(peer)
        if set(request) - REQUEST_KEYS:
            raise AuthorizationError(ERR_REQUEST, "request carries unsupported fields")
        op = request.get("op")
        if op not in ALL_OPS:
            raise AuthorizationError(ERR_FORBIDDEN, f"operation {op!r} is not supported")
        tenant, slug = request.get("tenant"), request.get("slug")
        verify_capability(
            self.secret, request.get("token"), op=op,
            tenant=str(tenant), slug=str(slug), now=self.clock(),
        )
        if op in ("reconcile", "migrate_all"):
            if tenant != RECONCILE_SUBJECT or slug != RECONCILE_SUBJECT:
                raise AuthorizationError(ERR_FORBIDDEN, f"{op} has no tenant subject")
            if op == "reconcile":
                self._validate_desired(request.get("desired"))
            elif request.get("only") not in (None, "static", "wordpress", "app"):
                raise AuthorizationError(ERR_REQUEST, "invalid migration kind")
            return op
        checked = plans.validate_slug(str(slug))
        if tenant != checked:
            raise AuthorizationError(ERR_FORBIDDEN, "tenant and slug do not match")
        self._authorize_tenant(checked)
        if op in ("apply", "apply_in_place", "verify", "probe"):
            self._validate_plan(request.get("plan"))
        return op

    def dispatch(self, request: dict[str, Any], peer: Peer) -> dict[str, Any]:
        try:
            op = self.authorize(request, peer)
            if op == "reconcile":
                result = self.materializer.reconcile(request["desired"])
            elif op == "migrate_all":
                if self.migration_handler is None:
                    raise RuntimeError("migration handler is not configured")
                if not request.get("dry_run") and not plans.mutation_allowed():
                    raise plans.MutationDisabled("local mutations are disabled")
                result = self.migration_handler(
                    dry_run=bool(request.get("dry_run")),
                    only=request.get("only"),
                    exclude=set(request.get("exclude") or []),
                    stop_on_failure=bool(request.get("stop_on_failure", True)),
                )
            elif op == "endpoint":
                slug = plans.validate_slug(str(request["slug"]))
                result = self.endpoint_resolver(slug, self.data_root)
            elif op in ("nat_status", "nat_apply", "nat_remove"):
                if self.nat_handler is None:
                    raise RuntimeError("cell NAT handler is not configured")
                slug = plans.validate_slug(str(request["slug"]))
                result = self.nat_handler(op, slug)
            else:
                slug = plans.validate_slug(str(request["slug"]))
                if op in ("apply", "apply_in_place"):
                    result = self.materializer.apply(slug, request["plan"])
                elif op == "remove":
                    result = self.materializer.remove(slug)
                elif op == "probe":
                    result = self.materializer.probe(
                        slug,
                        request["plan"],
                        memory_mb=int(request.get("memory_mb", 64)),
                        seconds=int(request.get("seconds", 3)),
                    )
                else:
                    result = self.materializer.verify(slug, request["plan"])
            return {"ok": True, "result": result}
        except AuthorizationError as exc:
            return {"ok": False, "error": {"code": exc.code, "message": exc.message}}
        except (plans.InvalidPlan, alloc.InvalidSlug) as exc:
            return {"ok": False, "error": {"code": ERR_PLAN, "message": str(exc)}}
        except Exception as exc:  # noqa: BLE001 - never leak a stack trace to a peer
            return {
                "ok": False,
                "error": {"code": ERR_AGENT, "message": str(exc)[:300]},
            }

    def handle_connection(self, conn: Any) -> dict[str, Any]:
        try:
            peer = self.peer_resolver(conn)
            response = self.dispatch(read_frame(conn), peer)
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            response = {
                "ok": False,
                "error": {"code": ERR_PROTOCOL, "message": str(exc)[:300]},
            }
        try:
            write_frame(conn, response)
        except OSError:
            pass
        finally:
            conn.close()
        return response

    def serve_forever(self, server: Any) -> None:
        """Accept loop; ``server`` is a listening AF_UNIX socket."""
        while True:
            conn, _address = server.accept()
            self.handle_connection(conn)


def allowed_uids_from_env(value: str) -> set[int]:
    result: set[int] = set()
    for part in value.replace(" ", "").split(","):
        if part.isdigit():
            result.add(int(part))
    return result


def build_agent_from_env(data_root: str | Path) -> PlanAgent:
    """Build the production agent from the host process environment."""
    import os

    secret_file = Path(
        os.environ.get("SPANEL_PLAN_AGENT_TOKEN_FILE", "/etc/spanel/plan_agent_token")
    )
    secret = read_secret(secret_file)
    executor = _local_executor()
    return PlanAgent(
        materializer.PlanMaterializer(executor, data_root),
        secret=secret,
        allowed_uids=allowed_uids_from_env(
            os.environ.get("SPANEL_PLAN_AGENT_ALLOWED_UIDS", "")
        ),
        data_root=data_root,
        nat_handler=lambda op, slug: _cell_nat(executor, data_root, op, slug),
    )


def read_secret(path: str | Path) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError("plan agent token file is empty")
    return value


def _local_executor() -> Any:
    from .executor import LocalExecutor

    return LocalExecutor()


def _cell_nat(
    executor: Any, data_root: str | Path, op: str, slug: str
) -> dict[str, Any]:
    """Observe or force cell NAT without ever entering the host network namespace."""
    if not plans.mutation_allowed():
        raise plans.MutationDisabled("local mutations are disabled")
    allocation = alloc.load_registry(data_root)["allocations"].get(slug)
    if allocation is None:
        raise AuthorizationError(ERR_TENANT, f"tenant {slug} has no cell allocation")
    uid = int(allocation["uid"])
    subnet = network.egress_subnet()
    if op == "nat_apply":
        executor.ensure_cell_egress(uid, subnet)
    elif op == "nat_remove":
        executor.remove_cell_egress(uid, subnet)
    pid = executor.cell_dockerd_pid(uid)
    if pid <= 0:
        raise RuntimeError(f"cell {slug} has no running dockerd")
    enabled = executor.cell_egress_enabled(uid, subnet)
    return {
        "slug": slug,
        "dockerd_pid": pid,
        "subnet": subnet,
        "enabled": enabled,
        "namespace": "cell",
    }


def socket_path_from_env() -> Path:
    import os

    return Path(
        os.environ.get("SPANEL_PLAN_AGENT_SOCKET", "/run/spanel/plan-agent.sock")
    )
