"""Ephemeral, session-scoped TCP relays for rootless tenant databases.

A single Core phpMyAdmin cannot reach a MariaDB that lives inside a tenant's
rootless Docker daemon. This module keeps one short-lived listener per
authorized panel session and one ephemeral connector inside the cell; both are
removed when the session closes or expires. It never parses SQL, never stores a
credential and never opens a port outside a bounded loopback range.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import select
import socket
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import alloc

BIND_ENV = "SPANEL_DB_BROKER_BIND"
PORT_RANGE_ENV = "SPANEL_DB_BROKER_PORTS"
CONNECTOR_PORTS_ENV = "SPANEL_PMA_CONNECTOR_PORTS"
SOURCES_ENV = "SPANEL_DB_BROKER_SOURCES"
CONNECTOR_IMAGE_ENV = "SPANEL_PMA_CONNECTOR_IMAGE"
CONNECTOR_READ_ONLY_ENV = "SPANEL_PMA_CONNECTOR_READ_ONLY"
CONNECTOR_NETWORK_ENV = "SPANEL_PMA_CONNECTOR_NETWORK"
CONNECTOR_LABEL = "spanel.role=pma-connector"
DEFAULT_PORTS = "41000-41999"
DEFAULT_CONNECTOR_PORTS = "42000-42999"
MAX_TTL, MAX_PUMP = 3600, 1 << 20
logger = logging.getLogger(__name__)
OPS = ("db_relay_open", "db_relay_status", "db_relay_close", "db_relay_reconcile")


class BrokerError(ValueError):
    """A relay request failed validation or a bounded resource is exhausted."""


# --- capabilities (same wire format as the plan agent) ----------------------


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def issue_capability(
    secret: str,
    *,
    op: str,
    tenant: str,
    slug: str,
    ttl: int = 60,
    now: float | None = None,
    nonce: str | None = None,
) -> str:
    if op not in OPS:
        raise BrokerError(f"unknown operation: {op!r}")
    issued = int(time.time() if now is None else now)
    payload = {
        "op": op,
        "tenant": tenant,
        "slug": slug,
        "iat": issued,
        "exp": issued + int(ttl),
        "nonce": nonce or os.urandom(8).hex(),
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    return f"{_b64e(body)}.{_b64e(signature)}"

# --- configuration ----------------------------------------------------------


def broker_bind() -> str:
    return os.environ.get(BIND_ENV, "172.23.0.1").strip() or "172.23.0.1"


def broker_source_ips() -> tuple[str, ...]:
    raw = os.environ.get(SOURCES_ENV, "")
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def connector_image() -> str:
    return os.environ.get(CONNECTOR_IMAGE_ENV, "").strip()


def connector_network() -> str:
    return os.environ.get(CONNECTOR_NETWORK_ENV, "bridge").strip() or "bridge"


def connector_read_only() -> bool:
    raw = os.environ.get(CONNECTOR_READ_ONLY_ENV, "1").strip().lower()
    return raw not in {"0", "no", "off", "false"}


def port_range(env: str = PORT_RANGE_ENV, default: str = DEFAULT_PORTS) -> tuple[int, int]:
    raw = os.environ.get(env, default).strip()
    low, _, high = raw.partition("-")
    try:
        first, last = int(low), int(high or low)
    except ValueError as exc:
        raise BrokerError("invalid SPANEL_DB_BROKER_PORTS") from exc
    if not (1024 <= first <= last <= 65535):
        raise BrokerError("broker ports must be between 1024 and 65535")
    return first, last


# --- entries ----------------------------------------------------------------


@dataclass
class RelayEntry:
    relay_id: str
    tenant_id: str
    slug: str
    site_id: str
    pma_session_id: str
    source_ip: str
    listen_port: int
    target_host: str
    target_port: int
    created_at: float
    expires_at: float
    connector_port: int = 0
    state: str = "open"
    connector: str = ""
    bytes_in: int = 0
    bytes_out: int = 0
    server: socket.socket | None = field(default=None, repr=False)
    stop: threading.Event | None = field(default=None, repr=False)
    def public(self) -> dict[str, Any]:
        keys = (
            "relay_id", "tenant_id", "slug", "site_id", "pma_session_id",
            "listen_port", "target_port", "created_at", "expires_at", "state",
            "bytes_in", "bytes_out",
        )
        return {key: getattr(self, key) for key in keys}


# --- connector inside the rootless cell -------------------------------------


class CellConnector:
    """Create/remove the rootless connector container for one relay."""
    def __init__(
        self,
        data_root: str | Path,
        *,
        image: str | None = None,
        runner: Callable[[list[str], dict[str, str]], subprocess.CompletedProcess] | None = None,
        read_only: bool | None = None,
        network: str | None = None,
    ) -> None:
        self.data_root = Path(data_root)
        self.image = image or connector_image()
        self.read_only = connector_read_only() if read_only is None else read_only
        self.network = network or connector_network()
        self.runner = runner or _run
    def _docker(self, slug: str, args: list[str]) -> subprocess.CompletedProcess:
        allocation = alloc.load_registry(self.data_root)["allocations"].get(slug)
        if allocation is None:
            raise BrokerError(f"tenant {slug} has no cell allocation")
        env = os.environ.copy()
        env["DOCKER_HOST"] = f"unix://{self.data_root}/cells/{slug}/docker.sock"
        env["XDG_RUNTIME_DIR"] = f"/run/user/{allocation['uid']}"
        return self.runner(["docker", *args], env)
    def _argv(
        self, entry: RelayEntry, db_container: str, name: str, private_network: str
    ) -> list[str]:
        args = ["create", "--name", name]
        if self.read_only:
            args.append("--read-only")
        args += [
            # The private network is internal; joining the cell edge network
            # makes rootless port publishing possible without extra routes.
            "--network", self.network,
            "--user", "65534:65534",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "64",
            "--memory", "64m",
            "--label", "spanel.managed=true",
            "--label", CONNECTOR_LABEL,
            "--label", f"spanel.tenant={entry.tenant_id}",
            "--label", f"spanel.site={entry.site_id}",
            "--label", f"spanel.relay={entry.relay_id}",
            # RootlessKit only implements wildcard port publishing; a fixed
            # HostIp is silently left unbound. The port stays ephemeral.
            "-p", f"{entry.connector_port}:3306",
            self.image,
            "TCP-LISTEN:3306,fork,reuseaddr",
            f"TCP:{db_container}:3306",
        ]
        return args
    def open(
        self, entry: RelayEntry, *, db_container: str, private_network: str
    ) -> str:
        if not self.image:
            raise BrokerError("SPANEL_PMA_CONNECTOR_IMAGE is not configured")
        if "@sha256:" not in self.image:
            raise BrokerError("the connector image must be pinned by digest")
        name = f"spanel-pma-{entry.relay_id}"
        args = self._argv(entry, db_container, name, private_network)
        if self._docker(entry.slug, ["image", "inspect", self.image]).returncode:
            pulled = self._docker(entry.slug, ["pull", self.image])
            if pulled.returncode:
                raise BrokerError("could not pull the pinned connector image")
        created = self._docker(entry.slug, args)
        if created.returncode:
            detail = (created.stderr or created.stdout or "").strip()[:300]
            raise BrokerError(f"could not create the database connector: {detail}")
        joined = self._docker(
            entry.slug, ["network", "connect", private_network, name]
        )
        if joined.returncode:
            self.close(entry.slug, name)
            raise BrokerError("could not attach the connector to the site network")
        started = self._docker(entry.slug, ["start", name])
        if started.returncode:
            self.close(entry.slug, name)
            raise BrokerError("could not start the database connector")
        for _ in range(20):
            info = self._docker(
                entry.slug, ["inspect", "--format", "{{json .State}}", name]
            )
            if info.returncode:
                break
            try:
                state = json.loads(info.stdout)
            except ValueError:
                break
            if state.get("Running"):
                return name
            if state.get("Status") in {"exited", "dead"} or state.get("Error"):
                self.close(entry.slug, name)
                raise BrokerError(
                    "the database connector did not start: "
                    + str(state.get("Error") or state.get("Status"))[:300]
                )
            time.sleep(0.5)
        self.close(entry.slug, name)
        raise BrokerError("the database connector did not become ready")
    def close(self, slug: str, name: str) -> None:
        if not name:
            return
        self._docker(slug, ["rm", "-f", name])
    def orphans(self, slug: str, active: set[str]) -> list[str]:
        result = self._docker(
            slug, ["ps", "-aq", "--filter", f"label={CONNECTOR_LABEL}"]
        )
        names: list[str] = []
        for container_id in result.stdout.split():
            inspect = self._docker(
                slug,
                ["inspect", "-f", "{{.Name}}", container_id],
            )
            name = inspect.stdout.strip().lstrip("/")
            if name and name not in active:
                names.append(name)
        return names


def _run(argv: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, check=False, env=env, timeout=120)


# --- broker -----------------------------------------------------------------


class DBBroker:
    """Bounded listener pool; source allowlist is mandatory and never a wildcard."""
    def __init__(
        self,
        bind: str | None = None,
        sources: tuple[str, ...] | None = None,
        *,
        ports: tuple[int, int] | None = None,
        connector: CellConnector | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.bind = bind or broker_bind()
        self.sources = frozenset(sources if sources is not None else broker_source_ips())
        self.first_port, self.last_port = ports or port_range()
        self.first_connector, self.last_connector = port_range(
            CONNECTOR_PORTS_ENV, DEFAULT_CONNECTOR_PORTS
        )
        self.connector = connector
        self.clock = clock or time.time
        self._entries: dict[str, RelayEntry] = {}
        self._lock = threading.RLock()
        self._sweeper: threading.Thread | None = None

    # -- validation ---------------------------------------------------------
    def _source_allowed(self, ip: str) -> bool:
        return bool(self.sources) and ip in self.sources
    def _allocate_port(self) -> int:
        used = {entry.listen_port for entry in self._entries.values()}
        for port in range(self.first_port, self.last_port + 1):
            if port in used:
                continue
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.bind((self.bind, port))
            except OSError:
                continue
            finally:
                probe.close()
            return port
        raise BrokerError("no free broker port in the configured range")
    def _allocate_connector_port(self, slug: str) -> int:
        used = {entry.connector_port for entry in self._entries.values() if entry.slug == slug}
        for port in range(self.first_connector, self.last_connector + 1):
            if port not in used:
                return port
        raise BrokerError("no free connector port in the configured range")

    # -- lifecycle ----------------------------------------------------------
    def open(
        self,
        *,
        relay_id: str,
        tenant_id: str,
        slug: str,
        site_id: str,
        pma_session_id: str,
        source_ip: str,
        target_host: str,
        target_port: int,
        ttl: int,
        db_container: str,
        private_network: str,
    ) -> dict[str, Any]:
        if not self._source_allowed(source_ip):
            raise BrokerError("source address is not allowed by the broker")
        if not 1 <= int(target_port) <= 65535:
            raise BrokerError("invalid target port")
        if not 1 <= int(ttl) <= MAX_TTL:
            raise BrokerError("invalid relay TTL")
        required = {
            "relay_id": relay_id, "tenant": tenant_id, "slug": slug,
            "site_id": site_id, "pma_session_id": pma_session_id, "target": target_host,
        }
        for label, value in required.items():
            if not isinstance(value, str) or not value.strip():
                raise BrokerError(f"{label} is required")
        with self._lock:
            existing = self._entries.get(relay_id)
            if existing is not None and existing.state == "open":
                return {
                    **existing.public(),
                    "broker_host": self.bind,
                    "broker_port": existing.listen_port,
                }
            port = self._allocate_port()
            connector_port = (
                self._allocate_connector_port(slug) if self.connector is not None else 0
            )
            entry = RelayEntry(
                relay_id=relay_id, tenant_id=tenant_id, slug=slug, site_id=site_id,
                pma_session_id=pma_session_id, source_ip=source_ip,
                listen_port=port,
                target_host=target_host,
                target_port=connector_port or int(target_port),
                created_at=self.clock(),
                expires_at=self.clock() + int(ttl),
                connector_port=connector_port,
            )
            if self.connector is not None:
                entry.connector = self.connector.open(
                    entry, db_container=db_container, private_network=private_network
                )
            try:
                self._start(entry)
            except Exception:
                if self.connector is not None:
                    self.connector.close(slug, entry.connector)
                raise
            self._entries[relay_id] = entry
            return {**entry.public(), "broker_host": self.bind, "broker_port": port}
    def _start(self, entry: RelayEntry) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(0.25)
        try:
            server.bind((self.bind, entry.listen_port))
            server.listen(16)
        except OSError:
            server.close()
            raise
        self._ensure_sweeper()
        stop = threading.Event()
        entry.server, entry.stop = server, stop
        thread = threading.Thread(
            target=self._accept_loop,
            args=(entry, server, stop),
            name=f"db-broker-{entry.relay_id}",
            daemon=True,
        )
        thread.start()
    def _ensure_sweeper(self) -> None:
        if self._sweeper is not None:
            return
        self._sweeper = threading.Thread(
            target=self._sweep, name="db-broker-expiry", daemon=True
        )
        self._sweeper.start()

    def _sweep(self) -> None:
        while True:
            time.sleep(5)
            try:
                self.expire()
            except Exception:
                logger.warning("hosting.phpmyadmin.relay_expire_failed", exc_info=True)

    def _accept_loop(
        self, entry: RelayEntry, server: socket.socket, stop: threading.Event
    ) -> None:
        while not stop.is_set():
            try:
                conn, address = server.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            if not self._source_allowed(str(address[0])):
                conn.close()
                continue
            threading.Thread(target=self._pump, args=(entry, conn), daemon=True).start()
    def _pump(self, entry: RelayEntry, conn: socket.socket) -> None:
        try:
            upstream = socket.create_connection(
                (entry.target_host, entry.target_port), timeout=5
            )
        except OSError:
            conn.close()
            return
        try:
            peers = {conn: upstream, upstream: conn}
            while True:
                readable, _, _ = select.select(list(peers), [], [], 30)
                if not readable:
                    break
                for source in readable:
                    try:
                        data = source.recv(65536)
                    except OSError:
                        return
                    if not data:
                        return
                    peers[source].sendall(data)
                    if source is conn:
                        entry.bytes_in += len(data)
                    else:
                        entry.bytes_out += len(data)
        finally:
            conn.close()
            upstream.close()
    def close(self, relay_id: str) -> dict[str, Any]:
        with self._lock:
            entry = self._entries.pop(relay_id, None)
            if entry is None:
                return {"relay_id": relay_id, "closed": False}
            if entry.stop is not None:
                entry.stop.set()
            if entry.server is not None:
                try:
                    entry.server.close()
                except OSError:
                    pass
            if self.connector is not None:
                try:
                    self.connector.close(entry.slug, entry.connector)
                except Exception:
                    logger.warning("db_relay_connector_close_failed", exc_info=True)
            entry.state = "closed"
            return {"relay_id": relay_id, "closed": True}
    def status(self, relay_id: str) -> dict[str, Any]:
        with self._lock:
            entry = self._entries.get(relay_id)
            if entry is None:
                return {"relay_id": relay_id, "state": "absent"}
            expired = entry.expires_at <= self.clock()
            return {**entry.public(), "state": "expired" if expired else entry.state}
    def list(self, slug: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            return [
                entry.public()
                for entry in self._entries.values()
                if slug is None or entry.slug == slug
            ]
    def expire(self) -> list[str]:
        now = self.clock()
        expired = [
            relay_id
            for relay_id, entry in self._entries.items()
            if entry.expires_at <= now
        ]
        for relay_id in expired:
            entry = self._entries.get(relay_id)
            if entry is not None:
                logger.info(
                    "hosting.phpmyadmin.relay_expired relay=%s tenant=%s site=%s "
                    "bytes_in=%s bytes_out=%s",
                    relay_id, entry.tenant_id, entry.site_id,
                    entry.bytes_in, entry.bytes_out,
                )
            self.close(relay_id)
        return expired
    def reconcile(self) -> dict[str, Any]:
        """Close expired relays and remove connectors that outlived their entry."""
        closed = self.expire()
        orphans: list[str] = []
        if self.connector is not None:
            active = {entry.connector for entry in self._entries.values()}
            slugs = {entry.slug for entry in self._entries.values()}
            try:
                registry = alloc.load_registry(self.connector.data_root)
            except (OSError, ValueError):
                registry = {"allocations": {}}
            slugs |= set(registry["allocations"])
            for slug in sorted(slugs):
                try:
                    for name in self.connector.orphans(slug, active):
                        self.connector.close(slug, name)
                        orphans.append(name)
                except Exception:
                    logger.warning("db_relay_reconcile_failed slug=%s", slug, exc_info=True)
                    continue
        return {"closed": closed, "orphans": orphans, "open": len(self._entries)}

# --- host-agent handler -----------------------------------------------------


class DBRelayHandler:
    """Bridge between the host-agent protocol and the broker/connector."""
    def __init__(
        self,
        broker: DBBroker,
        resolver: Callable[[str, str], dict[str, Any]],
    ) -> None:
        self.broker = broker
        self.resolver = resolver
    def __call__(self, op: str, request: dict[str, Any]) -> dict[str, Any]:
        try:
            result = self._dispatch(op, request)
        except Exception as exc:
            logger.warning(
                "hosting.phpmyadmin.relay_rejected op=%s tenant=%s site=%s reason=%s",
                op,
                request.get("slug"),
                request.get("site_id"),
                type(exc).__name__,
            )
            raise
        if op == "db_relay_open":
            logger.info(
                "hosting.phpmyadmin.relay_opened relay=%s tenant=%s site=%s expires_at=%s",
                result["relay_id"], request.get("tenant"), request.get("site_id"),
                result["expires_at"],
            )
        elif op == "db_relay_close":
            logger.info("hosting.phpmyadmin.relay_closed relay=%s", request.get("relay_id"))
        return result
    def _dispatch(self, op: str, request: dict[str, Any]) -> dict[str, Any]:
        if op == "db_relay_open":
            descriptor = self.resolver(str(request["slug"]), str(request["site_id"]))
            opened = self.broker.open(
                relay_id=str(request["relay_id"]),
                tenant_id=str(request.get("tenant_id") or request["tenant"]),
                slug=str(request["slug"]),
                site_id=str(request["site_id"]),
                pma_session_id=str(request["pma_session_id"]),
                source_ip=str(request["source_ip"]),
                target_host=str(descriptor["target_host"]),
                target_port=3306,
                ttl=int(request["ttl"]),
                db_container=str(descriptor["db_container"]),
                private_network=str(descriptor["private_network"]),
            )
            keys = ("relay_id", "broker_host", "broker_port", "expires_at")
            return {key: opened[key] for key in keys}
        if op == "db_relay_status":
            relay_id = request.get("relay_id")
            if relay_id:
                return self.broker.status(str(relay_id))
            return {"relays": self.broker.list(str(request["slug"]))}
        if op == "db_relay_close":
            return self.broker.close(str(request["relay_id"]))
        return self.broker.reconcile()
