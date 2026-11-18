"""Unprivileged TCP edge relay for rootless cells (A.SPEC 0104).

The single parent Traefik lives on the ``proxy`` bridge and cannot reach the
per-cell loopback addresses. This relay listens on the bridge gateway (by
default ``172.18.0.1``), accepts only the detected Traefik source IP, and pipes
bytes to the cell loopback. It never speaks HTTP or TLS, never sees a Docker
socket, and never accepts an exec/path/unit: its control socket only allows
``apply`` / ``remove`` / ``status`` / ``reload`` of cell endpoints.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from . import network

logger = logging.getLogger(__name__)

BIND_ENV = "SPANEL_EDGE_RELAY_BIND"
SOURCES_ENV = "SPANEL_EDGE_RELAY_SOURCES"
TRAEFIK_CONTAINER_ENV = "SPANEL_TRAEFIK_CONTAINER"
PROXY_NETWORK = "proxy"
DEFAULT_BIND = "172.18.0.1"
DEFAULT_TRAEFIK_CONTAINER = "traefik"
SOCKET_ENV = "SPANEL_EDGE_RELAY_SOCKET"
DEFAULT_SOCKET = "/run/spanel/edge-relay.sock"

CONTROL_OPS = ("apply", "remove", "status", "reload")
REQUEST_KEYS = {"op", "endpoint", "slug", "endpoints"}
MAX_FRAME = 1 << 16
CONNECT_TIMEOUT = 5.0
PUMP_CHUNK = 65536


# --- configuration derived from the host environment ------------------------


def default_bind() -> str:
    """Gateway address the relay listens on; configurable for other labs."""
    return os.environ.get(BIND_ENV, DEFAULT_BIND).strip() or DEFAULT_BIND


def sources_from_env() -> tuple[str, ...]:
    raw = os.environ.get(SOURCES_ENV, "")
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def detect_traefik_ip(runner: Callable[[list[str]], str] | None = None) -> str:
    """Best-effort Traefik IP in the proxy network; empty means unknown."""
    import subprocess

    container = os.environ.get(TRAEFIK_CONTAINER_ENV, DEFAULT_TRAEFIK_CONTAINER)
    fmt = f'{{{{(index .NetworkSettings.Networks "{PROXY_NETWORK}").IPAddress}}}}'
    argv = ["docker", "inspect", "-f", fmt, container]
    try:
        if runner is not None:
            output = runner(argv)
        else:
            result = subprocess.run(
                argv, capture_output=True, text=True, check=False, timeout=10
            )
            output = result.stdout if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""
    return output.strip()


def allowed_sources(
    *, detect: bool = True, runner: Callable[[list[str]], str] | None = None
) -> tuple[str, ...]:
    """Explicit override, else the detected Traefik IP (never a wildcard)."""
    explicit = sources_from_env()
    if explicit:
        return explicit
    if detect:
        address = detect_traefik_ip(runner)
        if address:
            return (address,)
    return ()


def socket_path_from_env() -> str:
    return os.environ.get(SOCKET_ENV, DEFAULT_SOCKET) or DEFAULT_SOCKET


def endpoint_for_allocation(
    allocation: dict[str, Any],
    *,
    bind: str | None = None,
    sources: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Derive a cell endpoint from a registry allocation (read-only)."""
    index = int(allocation["index"])
    return {
        "slug": str(allocation["slug"]),
        "loopback_address": network.loopback_address(index),
        "publish_port": network.publish_port(index),
        "relay_port": network.relay_port(index),
        "bind": bind or default_bind(),
        "allowed_sources": list(
            sources if sources is not None else allowed_sources()
        ),
    }


def endpoints_from_registry(
    data_root: str | os.PathLike[str],
    *,
    bind: str | None = None,
    sources: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    """Build every cell endpoint from registry.json without mutating it."""
    from . import alloc

    registry = alloc.load_registry(data_root)
    return [
        endpoint_for_allocation(allocation, bind=bind, sources=sources)
        for allocation in registry["allocations"].values()
    ]


# --- TCP relay ---------------------------------------------------------------


@dataclass(frozen=True)
class RelayTarget:
    host: str
    port: int


@dataclass
class _Listener:
    server: socket.socket
    thread: threading.Thread
    stop: threading.Event
    endpoint: dict[str, Any]


@dataclass(frozen=True)
class EndpointError(ValueError):
    """An endpoint descriptor failed validation; never a host mutation."""


def _validate_endpoint(endpoint: Any) -> dict[str, Any]:
    if not isinstance(endpoint, dict):
        raise EndpointError("endpoint must be an object")
    required = {"slug", "loopback_address", "publish_port", "relay_port", "bind"}
    if not required <= set(endpoint):
        raise EndpointError("endpoint is missing required fields")
    from . import alloc

    slug = alloc.validate_slug(str(endpoint["slug"]))
    relay_port = int(endpoint["relay_port"])
    publish_port = int(endpoint["publish_port"])
    if not 1 <= relay_port <= 65535 or not 1 <= publish_port <= 65535:
        raise EndpointError("endpoint ports must be between 1 and 65535")
    host = str(endpoint["loopback_address"])
    bind = str(endpoint["bind"])
    if not host or not bind:
        raise EndpointError("endpoint host and bind are required")
    return {
        "slug": slug,
        "loopback_address": host,
        "publish_port": publish_port,
        "relay_port": relay_port,
        "bind": bind,
        "allowed_sources": list(endpoint.get("allowed_sources", [])),
    }


class TCPRelay:
    """Threaded byte relay with an explicit source IP allowlist."""

    def __init__(
        self,
        bind: str | None = None,
        sources: tuple[str, ...] | None = None,
        *,
        connect_timeout: float = CONNECT_TIMEOUT,
    ) -> None:
        self.bind = bind or default_bind()
        self.allowed = frozenset(
            sources if sources is not None else allowed_sources()
        )
        self.connect_timeout = float(connect_timeout)
        self._listeners: dict[str, _Listener] = {}
        self._lock = threading.Lock()

    def _source_allowed(self, peer_ip: str) -> bool:
        # An empty allowlist denies everything: fail closed, never a wildcard.
        return bool(self.allowed) and peer_ip in self.allowed

    def apply(self, endpoint: Any) -> dict[str, Any]:
        """Start (or replace) the listener for one cell endpoint."""
        clean = _validate_endpoint(endpoint)
        slug = clean["slug"]
        with self._lock:
            if slug in self._listeners:
                self._remove_locked(slug)
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # A blocking accept() cannot be interrupted by close() from another
            # thread on every platform; a short timeout lets remove() reclaim
            # the port deterministically.
            server.settimeout(0.25)
            try:
                server.bind((self.bind, clean["relay_port"]))
                server.listen(16)
            except OSError:
                server.close()
                raise
            stop = threading.Event()
            target = RelayTarget(clean["loopback_address"], clean["publish_port"])
            thread = threading.Thread(
                target=self._accept_loop,
                args=(server, stop, target),
                name=f"edge-relay-{slug}",
                daemon=True,
            )
            self._listeners[slug] = _Listener(server, thread, stop, clean)
            thread.start()
        return dict(clean)

    def remove(self, slug: str) -> bool:
        from . import alloc

        with self._lock:
            return self._remove_locked(alloc.validate_slug(str(slug)))

    def _remove_locked(self, slug: str) -> bool:
        listener = self._listeners.pop(slug, None)
        if listener is None:
            return False
        listener.stop.set()
        try:
            listener.server.close()
        except OSError:
            pass
        if listener.thread is not threading.current_thread():
            listener.thread.join(timeout=1)
        return True

    def status(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item.endpoint) for item in self._listeners.values()]

    def reload(self, endpoints: Any) -> list[dict[str, Any]]:
        """Reconcile listeners with a desired set of endpoints."""
        if not isinstance(endpoints, list):
            raise EndpointError("endpoints must be a list")
        validated = [_validate_endpoint(item) for item in endpoints]
        desired = {item["slug"] for item in validated}
        with self._lock:
            for slug in list(self._listeners):
                if slug not in desired:
                    self._remove_locked(slug)
        for item in validated:
            self.apply(item)
        return self.status()

    def close(self) -> None:
        with self._lock:
            for slug in list(self._listeners):
                self._remove_locked(slug)

    def _accept_loop(
        self, server: socket.socket, stop: threading.Event, target: RelayTarget
    ) -> None:
        try:
            while not stop.is_set():
                try:
                    conn, address = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                conn.settimeout(None)
                threading.Thread(
                    target=self._handle,
                    args=(conn, address, target),
                    daemon=True,
                ).start()
        finally:
            server.close()

    def _handle(
        self, client: socket.socket, address: Any, target: RelayTarget
    ) -> None:
        if not self._source_allowed(str(address[0])):
            logger.warning("edge_relay_source_denied source=%s", address[0])
            client.close()
            return
        try:
            upstream = socket.create_connection(
                (target.host, target.port), timeout=self.connect_timeout
            )
        except OSError:
            client.close()
            return
        downstream = threading.Thread(
            target=self._pump, args=(client, upstream), daemon=True
        )
        upstreamward = threading.Thread(
            target=self._pump, args=(upstream, client), daemon=True
        )
        downstream.start()
        upstreamward.start()
        downstream.join()
        upstreamward.join()
        client.close()
        upstream.close()

    @staticmethod
    def _pump(source: socket.socket, destination: socket.socket) -> None:
        try:
            while True:
                data = source.recv(PUMP_CHUNK)
                if not data:
                    break
                destination.sendall(data)
        except OSError:
            pass
        finally:
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass


# --- control plane (Unix socket, SO_PEERCRED, verb allowlist) ----------------


def _read_frame(sock: Any) -> dict[str, Any]:
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise ValueError("connection closed mid-frame")
        header += chunk
    (size,) = struct.unpack("!I", header)
    if not 0 < size <= MAX_FRAME:
        raise ValueError("invalid request frame size")
    body = b""
    while len(body) < size:
        chunk = sock.recv(size - len(body))
        if not chunk:
            raise ValueError("connection closed mid-frame")
        body += chunk
    data = json.loads(body)
    if not isinstance(data, dict):
        raise TypeError("request must be a JSON object")
    return data


def _write_frame(sock: Any, payload: dict[str, Any]) -> None:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sock.sendall(struct.pack("!I", len(raw)) + raw)


class ControlError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class RelayControlAgent:
    """Authorization boundary plus a thin dispatcher over ``TCPRelay``."""

    def __init__(
        self,
        relay: TCPRelay,
        *,
        allowed_uids: set[int] | frozenset[int],
        peer_resolver: Callable[[Any], Any] | None = None,
    ) -> None:
        if not allowed_uids:
            raise ValueError("the relay control plane requires an allowed uid")
        self.relay = relay
        self.allowed_uids = frozenset(allowed_uids)
        if peer_resolver is None:
            from .host_agent import peer_credential as peer_resolver
        self.peer_resolver = peer_resolver

    def authorize_peer(self, peer: Any) -> None:
        if peer.uid not in self.allowed_uids:
            raise ControlError("peer_denied", f"peer uid {peer.uid} is not allowed")

    def dispatch(self, request: Any, peer: Any) -> dict[str, Any]:
        try:
            self.authorize_peer(peer)
            if not isinstance(request, dict) or set(request) - REQUEST_KEYS:
                raise ControlError("invalid_request", "unsupported request fields")
            op = request.get("op")
            if op not in CONTROL_OPS:
                raise ControlError("forbidden", f"operation {op!r} is not supported")
            if op == "status":
                result: Any = self.relay.status()
            elif op == "apply":
                result = self.relay.apply(request.get("endpoint"))
            elif op == "remove":
                result = {"removed": self.relay.remove(str(request.get("slug", "")))}
            else:
                result = self.relay.reload(request.get("endpoints"))
            return {"ok": True, "result": result}
        except ControlError as exc:
            return {"ok": False, "error": {"code": exc.code, "message": exc.message}}
        except (EndpointError, ValueError) as exc:
            return {
                "ok": False,
                "error": {"code": "invalid_request", "message": str(exc)[:300]},
            }
        except Exception as exc:  # noqa: BLE001 - never leak a stack trace
            return {
                "ok": False,
                "error": {"code": "agent_error", "message": str(exc)[:300]},
            }

    def handle_connection(self, conn: Any) -> dict[str, Any]:
        try:
            peer = self.peer_resolver(conn)
            response = self.dispatch(_read_frame(conn), peer)
        except (ValueError, TypeError, OSError, json.JSONDecodeError) as exc:
            response = {
                "ok": False,
                "error": {"code": "protocol_error", "message": str(exc)[:300]},
            }
        try:
            _write_frame(conn, response)
        except OSError:
            pass
        finally:
            conn.close()
        return response

    def serve_forever(self, server: Any) -> None:
        while True:
            conn, _address = server.accept()
            self.handle_connection(conn)


__all__ = [
    "CONTROL_OPS",
    "DEFAULT_BIND",
    "RelayControlAgent",
    "RelayTarget",
    "TCPRelay",
    "allowed_sources",
    "default_bind",
    "detect_traefik_ip",
    "endpoint_for_allocation",
    "endpoints_from_registry",
    "socket_path_from_env",
]
