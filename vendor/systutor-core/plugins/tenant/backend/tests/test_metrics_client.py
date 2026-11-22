"""Cliente Unix del daemon de métricas (A.SPEC 0113)."""

from __future__ import annotations

import json
import shutil
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

# Test this checkout, not whatever editable `systutor` happens to be installed.
_CORE_ROOT = Path(__file__).resolve().parents[4]
for _path in (str(_CORE_ROOT / "src"), str(_CORE_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import pytest

from plugins.tenant.backend.metrics_client import (
    MetricsClient,
    MetricsDenied,
    MetricsProtocolError,
    MetricsUnavailable,
    read_token,
)

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


class FakeDaemon:
    """Servidor AF_UNIX de un solo accept que registra el comando recibido."""

    def __init__(self, path: Path, handler: Callable[[socket.socket], None]) -> None:
        self.path = path
        self.handler = handler
        self.received: list[str] = []
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(path))
        self.server.listen(1)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            connection, _ = self.server.accept()
        except OSError:
            return
        with connection:
            with connection.makefile("rb") as reader:
                self.received.append(reader.readline().decode("utf-8", "replace"))
            try:
                self.handler(connection)
            except OSError:
                pass
        self.server.close()

    def close(self) -> None:
        self.server.close()


def _token_file(tmp_path: Path, token: str = "secret-token") -> Path:
    path = tmp_path / "token"
    path.write_text(f"{token}\n", encoding="utf-8")
    return path


@pytest.fixture()
def short_dir() -> Iterator[Path]:
    """AF_UNIX paths are limited to ~108 bytes; pytest's tmp_path is longer."""
    path = Path(tempfile.mkdtemp(prefix="cm-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _client(
    base: Path,
    handler: Callable[[socket.socket], None],
    *,
    timeout: float = 1.0,
) -> tuple[MetricsClient, FakeDaemon]:
    daemon = FakeDaemon(base / "metrics.sock", handler)
    client = MetricsClient(
        socket_path=daemon.path,
        token_file=_token_file(base),
        timeout=timeout,
        read_timeout=timeout,
    )
    return client, daemon


def _send(*lines: str) -> Callable[[socket.socket], None]:
    def handler(connection: socket.socket) -> None:
        for line in lines:
            connection.sendall(f"{line}\n".encode("utf-8"))

    return handler


def test_subscribe_frames_the_request_and_parses_lines(short_dir: Path) -> None:
    first = json.dumps(SAMPLE, separators=(",", ":"))
    second = json.dumps({**SAMPLE, "ts_ms": SAMPLE["ts_ms"] + 1000}, separators=(",", ":"))
    client, daemon = _client(short_dir, _send(first, second))

    samples = list(client.subscribe("demo", 1000))

    assert [sample["ts_ms"] for sample in samples] == [SAMPLE["ts_ms"], SAMPLE["ts_ms"] + 1000]
    assert samples[0]["memory"]["max_bytes"] == 4096
    assert daemon.received == ["SUBSCRIBE demo 1000 secret-token\n"]


def test_snapshot_reads_exactly_one_line(short_dir: Path) -> None:
    line = json.dumps(SAMPLE, separators=(",", ":"))
    client, daemon = _client(short_dir, _send(line))

    sample = client.snapshot("demo")

    assert sample["slug"] == "demo"
    assert daemon.received == ["SNAPSHOT demo secret-token\n"]


def test_ping_accepts_the_pong(short_dir: Path) -> None:
    client, daemon = _client(short_dir, _send('{"ok":true,"pong":true}'))

    assert client.ping() is True
    assert daemon.received == ["PING\n"]


def test_error_unauthorized_raises_denied(short_dir: Path) -> None:
    client, _daemon = _client(short_dir, _send("ERROR unauthorized token inválido"))

    with pytest.raises(MetricsDenied, match="token inválido"):
        list(client.subscribe("demo", 1000))


def test_error_peer_denied_raises_denied(short_dir: Path) -> None:
    client, _daemon = _client(short_dir, _send("ERROR peer_denied uid de peer no permitido"))

    with pytest.raises(MetricsDenied, match="peer"):
        client.snapshot("demo")


def test_error_unavailable_raises_unavailable(short_dir: Path) -> None:
    client, _daemon = _client(short_dir, _send("ERROR unavailable no existe cgroup"))

    with pytest.raises(MetricsUnavailable, match="cgroup"):
        client.snapshot("demo")


def test_malformed_line_raises_protocol_error(short_dir: Path) -> None:
    client, _daemon = _client(short_dir, _send("not-json"))

    with pytest.raises(MetricsProtocolError, match="JSON"):
        list(client.subscribe("demo", 1000))


def test_closed_daemon_without_lines_is_a_protocol_error(short_dir: Path) -> None:
    client, _daemon = _client(short_dir, lambda _connection: None)

    with pytest.raises(MetricsProtocolError, match="snapshot"):
        client.snapshot("demo")


def test_missing_socket_raises_unavailable(short_dir: Path) -> None:
    client = MetricsClient(
        socket_path=short_dir / "missing.sock",
        token_file=_token_file(short_dir),
        timeout=0.2,
    )

    with pytest.raises(MetricsUnavailable, match="no se pudo conectar"):
        next(client.subscribe("demo", 1000))


def test_missing_or_empty_token_raises_unavailable(tmp_path: Path) -> None:
    with pytest.raises(MetricsUnavailable, match="token"):
        read_token(tmp_path / "missing-token")
    empty = tmp_path / "empty-token"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(MetricsUnavailable, match="vacío"):
        read_token(empty)


def test_timeout_raises_unavailable(short_dir: Path) -> None:
    def slow(_connection: socket.socket) -> None:
        time.sleep(0.6)

    client, _daemon = _client(short_dir, slow, timeout=0.2)

    with pytest.raises(MetricsUnavailable, match="timeout"):
        next(client.subscribe("demo", 1000))


def test_closing_the_generator_closes_the_socket(short_dir: Path) -> None:
    closed = threading.Event()

    def handler(connection: socket.socket) -> None:
        connection.sendall(b'{"ts_ms":1}\n')
        connection.settimeout(3.0)
        try:
            if connection.recv(1) == b"":
                closed.set()
        except OSError:
            pass

    client, _daemon = _client(short_dir, handler)
    stream = client.subscribe("demo", 1000)

    assert next(stream)["ts_ms"] == 1
    stream.close()

    assert closed.wait(2.0), "el socket debe cerrarse al abandonar el generador"


def test_rejects_invalid_slug_and_interval_before_connecting(short_dir: Path) -> None:
    client = MetricsClient(
        socket_path=short_dir / "missing.sock",
        token_file=_token_file(short_dir),
        timeout=0.2,
    )

    with pytest.raises(MetricsProtocolError, match="slug"):
        next(client.subscribe("Demo", 1000))
    with pytest.raises(MetricsProtocolError, match="interval"):
        next(client.subscribe("demo", 100))


def test_reads_configuration_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SPANEL_CELL_METRICS_SOCKET", str(tmp_path / "env.sock"))
    monkeypatch.setenv("SPANEL_CELL_METRICS_TOKEN_FILE", str(tmp_path / "env-token"))
    monkeypatch.setenv("SPANEL_CELL_METRICS_TIMEOUT", "1.5")

    client = MetricsClient.from_env()

    assert client.socket_path == str(tmp_path / "env.sock")
    assert client.token_file == str(tmp_path / "env-token")
    assert client.timeout == 1.5
