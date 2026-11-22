"""Cliente Unix del daemon de métricas de celda (A.SPEC 0113).

Habla el protocolo de líneas del binario `spanel-cell-metrics --serve`:

    SUBSCRIBE <slug> <interval_ms> <token>
    SNAPSHOT <slug> <token>
    PING

No calcula métricas ni toca cgroups: solo abre el socket, envía el comando y
expone las líneas JSON como un iterador. Los errores son tipados para que el
router SSE pueda distinguir "daemon ausente" de "protocolo roto".
"""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

DEFAULT_SOCKET_PATH = "/run/spanel/cell-metrics.sock"
DEFAULT_TOKEN_FILE = "/run/secrets/cell_metrics_token"
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_LINE_BYTES = 1 << 20

MIN_INTERVAL_MS = 250
MAX_INTERVAL_MS = 60_000


class MetricsError(Exception):
    """Base de todos los errores del cliente de métricas."""


class MetricsUnavailable(MetricsError):
    """El daemon no está disponible, el token falta o la lectura expira."""


class MetricsDenied(MetricsError):
    """El daemon rechazó el peer o el token."""


class MetricsProtocolError(MetricsError):
    """El daemon respondió algo que no es una línea JSON válida."""


def _timeout_from_env() -> float:
    raw = os.environ.get("SPANEL_CELL_METRICS_TIMEOUT", "").strip()
    if not raw:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    return value if value > 0 else DEFAULT_TIMEOUT_SECONDS


def read_token(path: str | Path | None = None) -> str:
    """Lee el token compartido; ausente, vacío o ilegible es `unavailable`."""
    target = Path(
        path
        or os.environ.get("SPANEL_CELL_METRICS_TOKEN_FILE")
        or DEFAULT_TOKEN_FILE
    )
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise MetricsUnavailable(f"no se pudo leer el token de métricas: {exc}") from exc
    token = raw.strip()
    if not token:
        raise MetricsUnavailable("el token de métricas está vacío")
    return token


def _validate_request(slug: str, interval_ms: int | None = None) -> None:
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789-"
    if not slug or len(slug) > 63 or slug[0] not in allowed[:36]:
        raise MetricsProtocolError(f"slug inválido: {slug!r}")
    if any(character not in allowed for character in slug):
        raise MetricsProtocolError(f"slug inválido: {slug!r}")
    if interval_ms is not None and not MIN_INTERVAL_MS <= interval_ms <= MAX_INTERVAL_MS:
        raise MetricsProtocolError(
            f"interval_ms fuera de rango: {interval_ms} "
            f"({MIN_INTERVAL_MS}-{MAX_INTERVAL_MS})"
        )


def _raise_error_line(line: str) -> None:
    parts = line.split(" ", 2)
    code = parts[1] if len(parts) > 1 else ""
    message = parts[2] if len(parts) > 2 else line
    if code in {"unauthorized", "peer_denied"}:
        raise MetricsDenied(message)
    if code in {"unknown_user", "unavailable"}:
        raise MetricsUnavailable(message)
    raise MetricsProtocolError(message)


def _parse_line(line: str) -> dict[str, Any]:
    text = line.strip()
    if not text:
        raise MetricsProtocolError("línea vacía del daemon de métricas")
    if text.startswith("ERROR"):
        _raise_error_line(text)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MetricsProtocolError(f"línea JSON inválida: {text!r}") from exc
    if not isinstance(payload, dict):
        raise MetricsProtocolError("el sample del daemon no es un objeto JSON")
    return payload


class MetricsClient:
    """Cliente de una sola conexión por operación.

    La configuración sale del entorno salvo que se pase explícitamente:

    - ``SPANEL_CELL_METRICS_SOCKET`` (defecto ``/run/spanel/cell-metrics.sock``)
    - ``SPANEL_CELL_METRICS_TOKEN_FILE`` (defecto ``/run/secrets/cell_metrics_token``)
    - ``SPANEL_CELL_METRICS_TIMEOUT`` (defecto 5 s)
    """

    def __init__(
        self,
        *,
        socket_path: str | Path | None = None,
        token_file: str | Path | None = None,
        timeout: float | None = None,
        read_timeout: float | None = None,
    ) -> None:
        self.socket_path = str(
            socket_path
            or os.environ.get("SPANEL_CELL_METRICS_SOCKET")
            or DEFAULT_SOCKET_PATH
        )
        self.token_file = str(
            token_file
            or os.environ.get("SPANEL_CELL_METRICS_TOKEN_FILE")
            or DEFAULT_TOKEN_FILE
        )
        self.timeout = _timeout_from_env() if timeout is None else float(timeout)
        self.read_timeout = None if read_timeout is None else float(read_timeout)
        self._token: str | None = None

    @classmethod
    def from_env(cls) -> MetricsClient:
        return cls()

    @property
    def token(self) -> str:
        if self._token is None:
            self._token = read_token(self.token_file)
        return self._token

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
        except OSError as exc:
            sock.close()
            raise MetricsUnavailable(
                f"no se pudo conectar al daemon de métricas en {self.socket_path}: {exc}"
            ) from exc
        return sock

    def _send(self, sock: socket.socket, line: str) -> None:
        try:
            sock.sendall(line.encode("utf-8"))
        except OSError as exc:
            raise MetricsUnavailable(f"no se pudo enviar el comando: {exc}") from exc

    def _readline(self, reader: Any) -> str | None:
        try:
            raw = reader.readline(MAX_LINE_BYTES)
        except (TimeoutError, socket.timeout) as exc:
            raise MetricsUnavailable("timeout esperando al daemon de métricas") from exc
        except OSError as exc:
            raise MetricsUnavailable(f"fallo leyendo del daemon de métricas: {exc}") from exc
        if not raw:
            return None
        if len(raw) >= MAX_LINE_BYTES and not raw.endswith(b"\n"):
            raise MetricsProtocolError("línea del daemon demasiado larga")
        return raw.decode("utf-8", errors="replace")

    def ping(self) -> bool:
        sock = self._connect()
        try:
            self._send(sock, "PING\n")
            with sock.makefile("rb") as reader:
                line = self._readline(reader)
        finally:
            sock.close()
        if line is None:
            raise MetricsProtocolError("el daemon cerró sin responder a PING")
        payload = _parse_line(line)
        return bool(payload.get("pong"))

    def snapshot(self, slug: str) -> dict[str, Any]:
        _validate_request(slug)
        sock = self._connect()
        try:
            self._send(sock, f"SNAPSHOT {slug} {self.token}\n")
            with sock.makefile("rb") as reader:
                line = self._readline(reader)
        finally:
            sock.close()
        if line is None:
            raise MetricsProtocolError("el daemon cerró sin enviar el snapshot")
        return _parse_line(line)

    def subscribe(self, slug: str, interval_ms: int = 1000) -> Iterator[dict[str, Any]]:
        """Itera samples hasta que el daemon o el consumidor cierren.

        El socket se cierra en el ``finally`` también cuando el consumidor
        abandona el generador (por ejemplo, al desconectarse el cliente SSE).
        """
        _validate_request(slug, interval_ms)
        sock = self._connect()
        # SSE may ask for a long interval (up to 60 s); the read timeout must
        # outlive the next sample or a healthy stream would look unavailable.
        read_timeout = self.read_timeout
        if read_timeout is None:
            read_timeout = max(self.timeout, interval_ms / 1000.0 + 5.0)
        sock.settimeout(read_timeout)
        try:
            self._send(sock, f"SUBSCRIBE {slug} {interval_ms} {self.token}\n")
            with sock.makefile("rb") as reader:
                while True:
                    line = self._readline(reader)
                    if line is None:
                        return
                    if line.strip():
                        yield _parse_line(line)
        finally:
            sock.close()
