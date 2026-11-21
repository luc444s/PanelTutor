#!/usr/bin/env python3
"""A.SPEC 0110-C — cierre black-box de Hosting rootless por tenant.

Arnés único, autocontenido y autorreparable *solo en su entorno desechable*.
Crea un clon de la base de datos del panel, una API y un worker efímeros, dos
celdas rootless (tenant principal e intruso), un WordPress y un estático
rootful, los migra al userspace del tenant, ejecuta la matriz completa de
Hosting/File Manager/backup/phpMyAdmin, demuestra la celda real por observación
del daemon/cgroups/netns, ensaya rollback y finalize, crea las mismas clases de
sitio ya rootless, y limpia todo.

Uso oficial (en spanel.lab, como root)::

    sudo python3 scripts/e2e_0110_c_hosting_rootless_closure.py \
      --stage /var/tmp/spanel-e2e-0110c \
      --slug e2e0110c \
      --evidence artifacts/0110-c-hosting-rootless-final-e2e.json

Fases::

    --phase preflight|setup|seed|exercise|attest|cleanup|all
    --resume --keep-on-failure --json

El script nunca parchea el producto, nunca usa el CLI de Alembic y nunca
convierte un fallo en PASS: los huecos de plataforma se reportan como BLOCKED
y cualquier check fallido mantiene el cierre abierto.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import http.cookiejar
import io
import json
import os
import re
import secrets
import shutil
import signal
import ssl
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STAGE = Path("/var/tmp/spanel-e2e-0110c")
DEFAULT_SLUG = "e2e0110c"
DEFAULT_EVIDENCE = ROOT / "artifacts/0110-c-hosting-rootless-final-e2e.json"
REPORT = ROOT / "artifacts/0110-c-informe-cierre-tenants.md"
API_PREFIX = "/api/v1"
LIVE_DB = "sysadmin"
LIVE_PG = "spanel-postgres-1"
APP_IMAGE = "spanel-app:latest"
STATE_FILES = (
    "/var/lib/spanel/registry.json",
    "/var/lib/spanel/plans.json",
    "/var/lib/spanel/audit.jsonl",
    "/etc/subuid",
    "/etc/subgid",
)
SENSITIVE_KEY = re.compile(
    r"(password|passwd|secret|token|authorization|cookie|api[_-]?key|"
    r"private[_-]?key|ticket|session|capabilit)",
    re.IGNORECASE,
)
MEMORY_PLAN = 2 * 1024 * 1024 * 1024
CPU_PLAN = 1
PIDS_PLAN = 512
# Efímeros del broker PMA 0110-B; el listener edge-relay (40000+index) es
# infraestructura permanente de la celda y no cuenta como conector PMA.
PMA_BROKER_RANGE = (41000, 41999)
PMA_CONNECTOR_RANGE = (42000, 42999)
REQUIRED_CHECKS = (
    "preflight_host",
    "setup_environment",
    "rootful_fixtures",
    "intruder_tenant_cell",
    "migrate_static_then_wordpress",
    "plan_primary",
    "auth_rbac_scope",
    "lifecycle_static",
    "lifecycle_wordpress",
    "logs_static",
    "logs_wordpress",
    "filemanager_static",
    "filemanager_wordpress",
    "backup_static",
    "backup_wordpress_db_and_files",
    "wordpress_surface",
    "static_profiles",
    "static_wordpress_only_guards",
    "rollback_and_controlled_failure",
    "finalize",
    "after_finalize_static",
    "after_finalize_wordpress",
    "runtime_attestation",
    "delta_denied_zero",
    "no_permanent_db_port",
    "new_rootless_static",
    "new_rootless_wordpress",
)


class HarnessError(RuntimeError):
    """A precondition or product failure; never converted into PASS."""


class Precondition(HarnessError):
    """The lab cannot run this ceremony (missing capability/clean host)."""


class CheckFailed(HarnessError):
    """A product check did not converge."""


# ---------------------------------------------------------------------------
# Primitivas del arnés (probadas por scripts/tests/test_e2e_0110_c_harness.py)
# ---------------------------------------------------------------------------


def redact_text(text: str, secrets: Iterable[str] = ()) -> str:
    """Remove registered secrets and key=value style leaks from text."""
    rendered = str(text)
    for secret in sorted({str(item) for item in secrets if item}, key=len, reverse=True):
        rendered = rendered.replace(secret, "***")
    # ``password=...``, ``"token": "..."`` and similar pairs that were not
    # explicitly registered must not survive in evidence either.
    rendered = re.sub(
        r"(?i)((?:password|passwd|secret|token|authorization|cookie|ticket)"
        r"[\"']?\s*[=:]\s*)(\"?)([^\s\"',;}]+)(\2)",
        r"\1\2***\4",
        rendered,
    )
    return rendered


def redact(value: Any, secrets: Iterable[str] = ()) -> Any:
    """Recursively redact a JSON-like value for evidence."""
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if SENSITIVE_KEY.search(str(key)) and not isinstance(item, (dict, list)):
                result[str(key)] = "***"
            else:
                result[str(key)] = redact(item, secrets)
        return result
    if isinstance(value, (list, tuple)):
        return [redact(item, secrets) for item in value]
    if isinstance(value, str):
        return redact_text(value, secrets)
    return value


class Redactor:
    """Registry of concrete secrets observed during the run."""

    def __init__(self) -> None:
        self.secrets: set[str] = set()

    def add(self, value: Any) -> Any:
        if value is not None and len(str(value)) >= 4:
            self.secrets.add(str(value))
        return value

    def text(self, value: Any) -> str:
        return redact_text(str(value), self.secrets)

    def value(self, value: Any) -> Any:
        return redact(value, self.secrets)


class JournalError(HarnessError):
    pass


class Journal:
    """Atomic per-phase journal under the disposable stage directory."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = {}

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            self.data = {}
            return self.data
        try:
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise JournalError(f"journal is unreadable: {exc}") from exc
        if not isinstance(self.data, dict):
            raise JournalError("journal has an invalid shape")
        return self.data

    def save(self, data: dict[str, Any] | None = None) -> None:
        if data is not None:
            self.data = data
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(self.data, indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, self.path)

    def mark(self, phase: str, payload: dict[str, Any] | None = None) -> None:
        phases = self.data.setdefault("phases", {})
        phases[phase] = {
            "done": True,
            "at": now(),
            **(payload or {}),
        }
        self.save()

    def done(self, phase: str) -> bool:
        phases = self.data.get("phases", {})
        return bool(isinstance(phases, dict) and phases.get(phase, {}).get("done"))

    def last_completed_counts(self, order: Iterable[str]) -> tuple[int, int]:
        """Check/gap counts at the last successfully completed phase."""
        checks = gaps = 0
        phases = self.data.get("phases", {})
        if not isinstance(phases, dict):
            return checks, gaps
        for name in order:
            info = phases.get(name)
            if isinstance(info, dict) and info.get("done"):
                checks = int(info.get("check_count", checks))
                gaps = int(info.get("gap_count", gaps))
        return checks, gaps

    def validate_identity(self, identity: dict[str, Any]) -> None:
        recorded = self.data.get("identity")
        if recorded is None:
            raise JournalError("journal has no identity; start a fresh run")
        if recorded != identity:
            raise JournalError(
                "journal belongs to another fixture; refusing to resume "
                "with different ownership"
            )


def call_with_retries(
    operation: Callable[[], Any],
    *,
    attempts: int = 2,
    backoff: float = 3.0,
    sleep: Callable[[float], None] = time.sleep,
    on_retry: Callable[[int, BaseException], None] | None = None,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
) -> Any:
    """Run an idempotent operation at most ``attempts`` times (max 2)."""
    attempts = max(1, min(2, int(attempts)))
    last: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            return operation()
        except retry_on as exc:
            last = exc
            if attempt >= attempts:
                raise
            if on_retry is not None:
                on_retry(attempt, exc)
            sleep(backoff * (2 ** (attempt - 1)))
    raise last  # pragma: no cover - unreachable


def select_owned(
    items: Iterable[dict[str, Any]], *, owner_key: str, owner: str
) -> list[dict[str, Any]]:
    """Return only entries whose ownership matches exactly."""
    return [
        item
        for item in items
        if isinstance(item, dict) and str(item.get(owner_key, "")) == str(owner)
    ]


def evaluate_result(
    *,
    checks: Iterable[dict[str, Any]],
    gaps: Iterable[dict[str, Any]] = (),
    delta_denied: int = 0,
    cleanup_verified: bool = False,
    blocked: bool = False,
    keep_on_failure: bool = False,
    required_ids: Iterable[str] = (),
) -> str:
    """PASS only with every check green, no gaps, zero denials, clean host."""
    checks = list(checks)
    gaps = list(gaps)
    if blocked:
        return "BLOCKED"
    present = {str(check.get("id")) for check in checks if isinstance(check, dict)}
    missing = [name for name in required_ids if name not in present]
    if missing:
        return "FAIL"
    failed = [
        check
        for check in checks
        if not isinstance(check, dict) or check.get("pass") is not True
    ]
    if failed or gaps or delta_denied != 0:
        return "FAIL"
    if keep_on_failure or not cleanup_verified:
        return "FAIL"
    if not checks:
        return "FAIL"
    return "PASS"


def is_non_identity_uid_map(text: str) -> bool:
    """True when at least one row maps an inner id to a different host id."""
    for line in str(text).splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            inner, outer = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        if inner != outer:
            return True
    return False


def now() -> str:
    return datetime.now(UTC).isoformat()


def log(message: str) -> None:
    print(f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {message}", flush=True)


# ---------------------------------------------------------------------------
# Configuración del host
# ---------------------------------------------------------------------------


@dataclass
class Config:
    stage: Path
    slug: str
    evidence_path: Path
    phase: str = "all"
    resume: bool = False
    keep_on_failure: bool = False
    json_output: bool = False
    api_port: int = field(
        default_factory=lambda: int(os.getenv("SPANEL_E2E_API_PORT", "3011"))
    )
    live_db: str = field(default_factory=lambda: os.getenv("SPANEL_E2E_LIVE_DB", LIVE_DB))
    live_pg: str = field(default_factory=lambda: os.getenv("SPANEL_E2E_LIVE_PG", LIVE_PG))
    live_redis: str = field(
        default_factory=lambda: os.getenv("SPANEL_E2E_LIVE_REDIS", "spanel-redis-1")
    )
    image: str = field(default_factory=lambda: os.getenv("SPANEL_E2E_APP_IMAGE", APP_IMAGE))
    live_env: Path = field(
        default_factory=lambda: Path(
            os.getenv("SPANEL_E2E_LIVE_ENV", "/home/lucas/mailadmin/.env.docker")
        )
    )
    network: str = field(
        default_factory=lambda: os.getenv("SPANEL_E2E_DOCKER_NETWORK", "spanel_default")
    )
    proxy_network: str = field(
        default_factory=lambda: os.getenv(
            "SPANEL_E2E_PROXY_NETWORK", "spanel-traefik-lab"
        )
    )
    hosting_network: str = field(
        default_factory=lambda: os.getenv("SPANEL_E2E_HOSTING_NETWORK", "proxy")
    )
    pma_source_ip: str = field(
        default_factory=lambda: os.getenv("SPANEL_E2E_PMA_SOURCE_IP", "172.25.0.1")
    )
    dynamic_dir: Path = field(
        default_factory=lambda: Path(
            os.getenv(
                "SPANEL_E2E_TRAEFIK_DYNAMIC",
                "/home/lucas/mailadmin/scripts/traefik-lab/dynamic",
            )
        )
    )
    traefik_container: str = field(
        default_factory=lambda: os.getenv(
            "SPANEL_E2E_TRAEFIK_CONTAINER", "spanel-traefik-lab"
        )
    )
    sites_dir: str = field(
        default_factory=lambda: os.getenv("SPANEL_E2E_HOSTING_SITES_DIR", "/opt/spanel/sites")
    )
    external_base: str = field(
        default_factory=lambda: os.getenv("SPANEL_E2E_EXTERNAL_BASE", "http://127.0.0.1:9080")
    )
    ca_file: str = field(default_factory=lambda: os.getenv("SPANEL_E2E_CA_FILE", ""))
    domain_suffix: str = field(
        default_factory=lambda: os.getenv("SPANEL_E2E_DOMAIN_SUFFIX", "lab")
    )
    relay_bind: str = field(
        default_factory=lambda: os.getenv("SPANEL_E2E_RELAY_BIND", "172.25.0.1")
    )
    relay_source: str = field(
        default_factory=lambda: os.getenv("SPANEL_E2E_RELAY_SOURCE", "172.25.0.3")
    )
    operation_timeout: int = field(
        default_factory=lambda: int(os.getenv("SPANEL_E2E_OPERATION_TIMEOUT", "1200"))
    )
    create_timeout: int = field(
        default_factory=lambda: int(os.getenv("SPANEL_E2E_CREATE_TIMEOUT", "300"))
    )
    wp_domain_prefix: str = "wp"

    @property
    def db(self) -> str:
        return f"sysadmin_{self.slug}"

    @property
    def intruder_slug(self) -> str:
        return f"{self.slug}-intr"

    @property
    def intruder_tenant(self) -> str:
        return f"{self.slug}-intr"

    @property
    def app(self) -> str:
        return f"spanel-{self.slug}-c-app"

    @property
    def worker(self) -> str:
        return f"spanel-{self.slug}-c-worker"

    @property
    def redis(self) -> str:
        return f"spanel-{self.slug}-c-redis"

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"

    @property
    def primary_domain_wp(self) -> str:
        return f"wp-{self.slug}.{self.domain_suffix}"

    @property
    def primary_domain_static(self) -> str:
        return f"static-{self.slug}.{self.domain_suffix}"

    @property
    def intruder_domain(self) -> str:
        return f"intr-{self.slug}.{self.domain_suffix}"

    @property
    def ownership(self) -> dict[str, str]:
        return {
            "slug": self.slug,
            "intruder_slug": self.intruder_slug,
            "domain_suffix": self.domain_suffix,
        }


# ---------------------------------------------------------------------------
# Ejecución y observación del host
# ---------------------------------------------------------------------------


def run(
    argv: list[str],
    *,
    timeout: int = 600,
    check: bool = False,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input_text,
        env={**os.environ, **(env or {})},
        check=False,
    )
    if check and completed.returncode:
        tail = (completed.stderr or completed.stdout).strip()[-800:]
        raise HarnessError(f"{argv[0]} {argv[1:3]} failed: {tail}")
    return completed


def docker(cfg: Config, *args: str, timeout: int = 900, check: bool = True):
    return run(["docker", *args], timeout=timeout, check=check)


def cell_docker(cfg: Config, slug: str, *args: str, timeout: int = 900, check: bool = True):
    return run(
        ["docker", "-H", f"unix:///var/lib/spanel/cells/{slug}/docker.sock", *args],
        timeout=timeout,
        check=check,
    )


def read_registry() -> dict[str, Any]:
    return json.loads(Path("/var/lib/spanel/registry.json").read_text(encoding="utf-8"))


def allocation(slug: str) -> dict[str, Any]:
    value = read_registry().get("allocations", {}).get(slug)
    if not isinstance(value, dict):
        raise Precondition(f"tenant cell {slug} is not in the host registry")
    return value


def cell_uid(slug: str) -> int | None:
    try:
        import pwd

        return pwd.getpwnam(f"spanel-{slug}").pw_uid
    except KeyError:
        return None


def cgroup_limits(
    uid: int, *, slug: str | None = None, cgroup_path: str | None = None
) -> dict[str, str]:
    """Read effective limits from the cell/tenant cgroup (layout varies)."""
    candidates: list[Path] = []
    if cgroup_path:
        candidates.append(Path("/sys/fs/cgroup") / str(cgroup_path).lstrip("/"))
    if slug:
        candidates.append(Path(f"/sys/fs/cgroup/tenant.slice/tenant-{slug}.slice"))
    candidates.append(
        Path(f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service")
    )
    user_base = Path(
        f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/user.slice"
    )
    if user_base.is_dir():
        candidates.extend(sorted(user_base.glob("spanel-cell-*.scope")))
    result: dict[str, str] = {}
    for scope in candidates:
        if not scope.is_dir():
            continue
        values = {
            key: (scope / key).read_text(encoding="utf-8").strip()
            for key in ("memory.max", "cpu.max", "pids.max")
            if (scope / key).exists()
        }
        if values:
            result = {**values, "scope": str(scope)}
            break
    return result


def tcp_listeners(port: int | None = None) -> list[str]:
    result = run(["ss", "-ltnH"], timeout=20)
    if result.returncode:
        raise Precondition("host TCP listeners are unavailable (ss)")
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if port is None:
        return lines
    suffix = f":{port}"
    return [line for line in lines if line.split()[3].rsplit("%", 1)[0].endswith(suffix)]


def deny_count(slug: str, since: float) -> int:
    marker = f"spanel-cell-{slug}"
    result = run(
        [
            "journalctl",
            "-k",
            "--no-pager",
            "-o",
            "cat",
            "--since",
            f"@{since}",
            "--grep",
            marker,
        ],
        timeout=60,
    )
    if result.returncode not in (0, 1):
        raise Precondition("kernel audit log is unavailable (journalctl -k)")
    return sum(
        1 for line in result.stdout.splitlines() if marker in line and "DENIED" in line
    )


def core_snapshot(cfg: Config) -> dict[str, str]:
    names = (
        "spanel-traefik-lab",
        "spanel-lab-mariadb",
        "spanel-lab-phpmyadmin",
        "spanel-powerdns-lab-auth",
        "spanel-powerdns-lab-postgres",
        "spanel-mail",
    )
    snapshot: dict[str, str] = {}
    for name in names:
        result = docker(
            cfg, "inspect", "-f", "{{.Id}} {{.State.Status}}", name, check=False,
        )
        if result.returncode == 0:
            snapshot[name] = result.stdout.strip()
    return snapshot


def other_tenant_snapshot(cfg: Config) -> dict[str, str]:
    """Hash every registry allocation except this run's two cells."""
    snapshot: dict[str, str] = {}
    try:
        registry = read_registry()
    except Exception:  # noqa: BLE001 - reported by preflight
        return snapshot
    for slug, value in sorted((registry.get("allocations") or {}).items()):
        if slug in {cfg.slug, cfg.intruder_slug}:
            continue
        snapshot[slug] = hashlib.sha256(
            json.dumps(value, sort_keys=True).encode()
        ).hexdigest()
    return snapshot


# ---------------------------------------------------------------------------
# Cliente HTTP
# ---------------------------------------------------------------------------


class ApiError(HarnessError):
    def __init__(self, method: str, path: str, status: int, payload: str) -> None:
        self.status = status
        self.payload = payload
        super().__init__(f"{method} {path}: HTTP {status}: {payload[:300]}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Api:
    def __init__(self, cfg: Config, redactor: Redactor, token: str = "") -> None:
        self.cfg = cfg
        self.redactor = redactor
        self.token = token
        self.base = cfg.base_url

    def login(self, email: str, password: str) -> None:
        payload = self.request(
            "POST",
            "/auth/login",
            {"email": email, "password": password},
            auth=False,
        )
        self.token = self.redactor.add(str(payload["access_token"]))

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        auth: bool = True,
        allow: tuple[int, ...] = (200, 201, 204),
        timeout: int = 180,
        headers: dict[str, str] | None = None,
        raw: bool = False,
    ) -> Any:
        data = None if body is None else json.dumps(body).encode()
        request_headers = {"Content-Type": "application/json"}
        if auth and self.token:
            request_headers["Authorization"] = f"Bearer {self.token}"
        request_headers.update(headers or {})
        url = self.base + (path if path.startswith(API_PREFIX) else API_PREFIX + path)
        request = urllib.request.Request(
            url, data=data, method=method, headers=request_headers
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read()
                status = response.status
                response_headers = dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            status = exc.code
            payload = exc.read()
            response_headers = dict(exc.headers.items()) if exc.headers else {}
        except urllib.error.URLError as exc:
            raise HarnessError(f"{method} {path}: {exc.reason}") from exc
        if status not in allow:
            raise ApiError(method, path, status, payload.decode(errors="replace"))
        if raw:
            return status, payload, response_headers
        if not payload:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return payload.decode(errors="replace")

    def download(self, path: str, *, timeout: int = 600) -> tuple[int, bytes]:
        url = path if path.startswith("http") else self.base + path
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def multipart(
        self,
        method: str,
        path: str,
        *,
        fields: dict[str, str],
        file_name: str,
        file_content: bytes,
        timeout: int = 600,
    ) -> tuple[int, dict[str, Any] | str | None, dict[str, str]]:
        boundary = f"spanel0110c{time.time_ns()}"
        body = io.BytesIO()
        for name, value in fields.items():
            body.write(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"'
                f"\r\n\r\n{value}\r\n".encode()
            )
        body.write(
            (
                f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                f'filename="{file_name}"\r\nContent-Type: application/zip\r\n\r\n'
            ).encode()
        )
        body.write(file_content)
        body.write(f"\r\n--{boundary}--\r\n".encode())
        request = urllib.request.Request(
            self.base + API_PREFIX + path,
            data=body.getvalue(),
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, json.loads(response.read() or b"null"), dict(
                    response.headers.items()
                )
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(errors="replace"), dict(
                exc.headers.items()
            )

    # -- helpers ---------------------------------------------------------
    def me(self) -> dict[str, Any]:
        return self.request("GET", "/auth/me")

    def sites(self, scope: str = "tenant") -> list[dict[str, Any]]:
        return list(self.request("GET", f"/plugins/hosting/sites?scope={scope}")["sites"])

    def site(self, site_id: str) -> dict[str, Any]:
        for row in self.sites():
            if row.get("id") == site_id:
                return row
        raise CheckFailed(f"site {site_id} is not visible to this tenant")

    def create_site(
        self, *, kind: str, name: str, domain: str, profile: str = "nginx"
    ) -> dict[str, Any]:
        payload = self.request(
            "POST",
            "/plugins/hosting/sites",
            {"kind": kind, "name": name, "domain": domain, "profile": profile},
            timeout=self.cfg.create_timeout,
        )
        return payload

    def delete_site(self, site_id: str) -> None:
        self.request("DELETE", f"/plugins/hosting/sites/{site_id}", timeout=600)

    def external(self, domain: str, *, deadline: float = 30.0) -> dict[str, Any]:
        return external_probe(self.cfg, domain, deadline=deadline)


def external_probe(
    cfg: Config, domain: str, *, deadline: float = 30.0, path: str = "/"
) -> dict[str, Any]:
    url = f"{cfg.external_base.rstrip('/')}{path}"
    request = urllib.request.Request(url, headers={"Host": domain})
    context = None
    if cfg.ca_file:
        try:
            context = ssl.create_default_context(cafile=cfg.ca_file)
        except (OSError, ssl.SSLError) as exc:
            raise HarnessError(f"unusable SPANEL_E2E_CA_FILE: {exc}") from exc
    kwargs: dict[str, Any] = {"timeout": 20}
    if context is not None:
        kwargs["context"] = context
    deadline_at = time.monotonic() + max(0.0, deadline)
    while True:
        try:
            with urllib.request.urlopen(request, **kwargs) as response:
                payload = response.read()
                return {
                    "status": response.status,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "bytes": len(payload),
                    "body_head": payload[:400].decode(errors="replace"),
                }
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            http.client.HTTPException,
        ) as exc:
            if time.monotonic() >= deadline_at:
                if isinstance(exc, urllib.error.HTTPError):
                    return {"status": exc.code, "sha256": "", "bytes": 0}
                raise HarnessError(f"external probe {domain} failed: {exc}") from exc
            time.sleep(1)


# ---------------------------------------------------------------------------
# Journal / evidencia
# ---------------------------------------------------------------------------


class Evidence:
    """Aggregates checks with the exact shape required by the spec."""

    def __init__(self, cfg: Config, redactor: Redactor) -> None:
        self.cfg = cfg
        self.redactor = redactor
        self.data: dict[str, Any] = {
            "spec": "0110-C",
            "result": "FAIL",
            "ok": False,
            "environment": {},
            "baseline": {},
            "repairs": [],
            "fixtures": {},
            "checks": [],
            "runtime_attestation": {},
            "rollback": {},
            "finalize": {},
            "delta_denied": 0,
            "gaps": [],
            "cleanup": {},
            "cleanup_verified": False,
            "started_at": now(),
        }

    def record(
        self,
        check_id: str,
        surface: str,
        expected: Any,
        observed: Any,
        *,
        passed: bool | None = None,
        duration: float = 0.0,
        evidence: Any = None,
    ) -> dict[str, Any]:
        if passed is None:
            passed = bool(observed)
        item = {
            "id": check_id,
            "surface": surface,
            "expected": self.redactor.value(expected),
            "observed": self.redactor.value(observed),
            "pass": bool(passed),
            "duration_s": round(duration, 2),
        }
        if evidence is not None:
            item["evidence"] = self.redactor.value(evidence)
        self.data["checks"].append(item)
        if not passed:
            self.data["gaps"].append(
                {
                    "id": check_id,
                    "severity": "high",
                    "title": f"{check_id} no convergió",
                    "evidence": json.dumps(item["observed"], default=str)[:1200],
                }
            )
        return item

    def require(
        self,
        check_id: str,
        surface: str,
        expected: Any,
        operation: Callable[[], Any],
        *,
        predicate: Callable[[Any], bool] | None = None,
        duration: float = 0.0,
    ) -> Any:
        """Run a check that later steps depend on; raise on failure."""
        try:
            observed = operation()
        except Exception as exc:
            self.record(
                check_id,
                surface,
                expected,
                {"error": str(exc)},
                passed=False,
                duration=duration,
            )
            raise
        passed = predicate(observed) if predicate is not None else bool(observed)
        self.record(
            check_id, surface, expected, observed, passed=passed, duration=duration
        )
        if not passed:
            raise CheckFailed(f"check failed: {check_id}")
        return observed


# ---------------------------------------------------------------------------
# Entorno desechable
# ---------------------------------------------------------------------------


def stage_tree(cfg: Config) -> None:
    stage = cfg.stage
    stage.mkdir(parents=True, exist_ok=True)
    marker = stage / ".0110c-stage"
    need_copy = not marker.exists()
    staged_script = stage / "scripts/e2e_0110_c_hosting_rootless_closure.py"
    if not need_copy and staged_script.exists():
        # A rerun with a changed checkout must refresh the code under test.
        need_copy = (
            staged_script.stat().st_mtime
            < (ROOT / "scripts/e2e_0110_c_hosting_rootless_closure.py").stat().st_mtime
        )
    if need_copy:
        log(f"staging checkout into {stage}")
        for rel in ("scripts",):
            source = ROOT / rel
            if source.exists():
                shutil.copytree(
                    source,
                    stage / rel,
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
                )
        for rel in (
            "vendor/systutor-core/src",
            "vendor/systutor-core/plugins",
            "vendor/systutor-core/migrations",
        ):
            source = ROOT / rel
            if source.exists():
                shutil.copytree(
                    source,
                    stage / rel,
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
                )
        ini = ROOT / "vendor/systutor-core/alembic.ini"
        if ini.exists():
            shutil.copy2(ini, stage / "vendor/systutor-core/alembic.ini")
        marker.write_text(now(), encoding="utf-8")
    pylibs = stage / "pylibs"
    pylibs.mkdir(exist_ok=True)
    probe = run([sys.executable, "-c", "import typer"], timeout=30)
    if probe.returncode:
        run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--quiet",
                "--target",
                str(pylibs),
                "typer>=0.12",
            ],
            timeout=900,
            check=True,
        )
    for rel in ("scripts", "vendor", "state", "runtime", "pylibs", "backups"):
        path = stage / rel
        if path.exists():
            run(["chmod", "-R", "a+rX", str(path)], check=False)
    (stage / "state").mkdir(exist_ok=True)
    (stage / "backups").mkdir(exist_ok=True)


def backup_state(cfg: Config, evidence: Evidence) -> dict[str, str]:
    backup = cfg.stage / "backup"
    backup.mkdir(parents=True, exist_ok=True)
    hashes: dict[str, str] = {}
    for item in STATE_FILES:
        source = Path(item)
        if not source.exists():
            continue
        target = backup / source.name
        if not target.exists():
            shutil.copy2(source, target)
        hashes[item] = hashlib.sha256(target.read_bytes()).hexdigest()
    evidence.data["baseline"]["state_hashes"] = hashes
    return hashes


def clone_database(cfg: Config) -> None:
    log(f"cloning {cfg.live_db} -> {cfg.db}")
    live_psql = ["docker", "exec", cfg.live_pg, "psql", "-U", "postgres"]
    run(
        [
            *live_psql,
            "-d",
            cfg.live_db,
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            f'DROP DATABASE IF EXISTS "{cfg.db}" WITH (FORCE);',
        ],
        timeout=300,
        check=True,
    )
    run(
        [*live_psql, "-d", cfg.live_db, "-c", f'CREATE DATABASE "{cfg.db}";'],
        timeout=300,
        check=True,
    )
    dump = run(
        [
            "docker",
            "exec",
            cfg.live_pg,
            "pg_dump",
            "-U",
            "postgres",
            "--no-owner",
            "--no-privileges",
            cfg.live_db,
        ],
        timeout=1800,
        check=True,
    )
    restore = run(
        [
            "docker",
            "exec",
            "-i",
            cfg.live_pg,
            "psql",
            "-U",
            "postgres",
            "-d",
            cfg.db,
            "-v",
            "ON_ERROR_STOP=0",
            "-q",
        ],
        input_text=dump.stdout,
        timeout=1800,
    )
    if restore.returncode:
        raise Precondition(f"database clone failed: {(restore.stderr or '')[-500:]}")
    owner = clone_psql(
        cfg, "SELECT slug FROM tenants ORDER BY created_at LIMIT 1;"
    )
    if owner != "demo":
        raise Precondition(f"unexpected cloned tenant layout: {owner!r}")
    clone_psql(cfg, "UPDATE tenants SET slug = %(slug)s WHERE slug = 'demo';", slug=cfg.slug)
    # Pending outbox rows from the live tenant must never be replayed by the
    # disposable stack.
    clone_psql(
        cfg,
        "UPDATE event_outbox SET status = 'processed', processed_at = NOW(), "
        "error_message = NULL WHERE status IN ('pending', 'failed');",
    )
    # El clon trae sitios del tenant real. Si el migrador los reconciliara,
    # el ingress apuntaría a contenedores que no existen en esta celda.
    for table in (
        "hosting_rootless_routes",
        "hosting_rootless_migrations",
        "hosting_sites",
    ):
        clone_psql(cfg, f"DELETE FROM {table};")
    clone_psql(
        cfg,
        "DELETE FROM tenant_resource_runtimes WHERE kind = 'hosting';",
    )


def clone_psql(cfg: Config, sql: str, **params: str) -> str:
    argv = ["docker", "exec", cfg.live_pg, "psql", "-U", "postgres", "-d", cfg.db, "-tA", "-c"]
    for key, value in params.items():
        sql = sql.replace(f"%({key})s", "'" + value.replace("'", "''") + "'")
    result = run([*argv, sql], timeout=120, check=True)
    return result.stdout.strip()


def provision_cell(cfg: Config, slug: str) -> dict[str, Any]:
    cli = cfg.stage / "scripts" / "spanel_tenant.py"
    env = {
        "PYTHONPATH": f"{cfg.stage / 'pylibs'}:{cfg.stage / 'scripts'}",
        "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS": "1",
    }
    socket = Path(f"/var/lib/spanel/cells/{slug}/docker.sock")
    deadline = time.monotonic() + 240
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        result = run(
            [sys.executable, str(cli), "provision", "--slug", slug, "--json"],
            timeout=600,
            env=env,
        )
        if result.returncode == 0:
            last = json.loads(result.stdout.strip().splitlines()[-1])
            if last.get("state") == "ready" and socket.exists():
                return last
        time.sleep(3)
    raise Precondition(f"tenant cell {slug} did not become ready: {last}")


def deprovision_cell(cfg: Config, slug: str) -> None:
    cli = cfg.stage / "scripts" / "spanel_tenant.py"
    env = {
        "PYTHONPATH": f"{cfg.stage / 'pylibs'}:{cfg.stage / 'scripts'}",
        "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS": "1",
    }
    run(
        [sys.executable, str(cli), "deprovision", "--slug", slug, "--purge-data", "--json"],
        timeout=600,
        env=env,
        check=False,
    )


def remove_cell_leftovers(slug: str) -> list[str]:
    removed: list[str] = []
    uid = cell_uid(slug)
    if uid is not None:
        run(["systemctl", "stop", f"user@{uid}.service"], check=False)
    for path in (
        Path(f"/home/spanel-{slug}"),
        Path(f"/run/user/{uid}") if uid is not None else None,
        Path(f"/var/lib/spanel/cells/{slug}"),
    ):
        if path is not None and path.exists():
            shutil.rmtree(path, ignore_errors=True)
            removed.append(str(path))
    return removed


def agent_env(cfg: Config) -> dict[str, str]:
    return {
        "PYTHONPATH": f"{cfg.stage / 'pylibs'}:{cfg.stage / 'scripts'}",
        "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS": "1",
        "SPANEL_EDGE_RELAY_BIND": cfg.relay_bind,
        "SPANEL_EDGE_RELAY_SOURCES": cfg.relay_source,
    }


def start_process(
    cfg: Config, name: str, argv: list[str], env: dict[str, str], *, uid: int | None = None
) -> int:
    runtime = cfg.stage / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    log_file = (runtime / f"{name}.log").open("ab")
    preexec = None
    if uid is not None:

        def preexec() -> None:  # pragma: no cover - child process
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)

    process = subprocess.Popen(
        argv,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        env={**os.environ, **env},
        preexec_fn=preexec,  # noqa: PLW1509 - no threads yet
    )
    (runtime / f"{name}.pid").write_text(str(process.pid), encoding="utf-8")
    log(f"started {name} pid={process.pid}")
    return process.pid


def stop_process(cfg: Config, name: str) -> str:
    path = cfg.stage / "runtime" / f"{name}.pid"
    if not path.exists():
        return "missing"
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except ValueError:
        return "invalid"
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return "already gone"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return "terminated"
        time.sleep(0.5)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return "killed"


def wait_socket(path: Path, timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.5)
    raise Precondition(f"socket {path} did not appear")


def wait_listener(address: str, port: int, timeout: float = 90.0) -> str:
    deadline = time.monotonic() + timeout
    needle = f"{address}:{port}"
    while time.monotonic() < deadline:
        for line in tcp_listeners():
            if needle in line:
                return line
        time.sleep(1)
    raise Precondition(f"no listener on {needle}")


def prepare_agents(cfg: Config, cells: list[str], evidence: Evidence) -> None:
    token = cfg.stage / "plan_agent_token"
    if not token.exists():
        token.write_text(secrets.token_hex(32), encoding="utf-8")
    token.chmod(0o600)
    evidence.redactor.add(token.read_text(encoding="utf-8"))
    registry = read_registry()
    filtered = cfg.stage / "relay-data"
    filtered.mkdir(parents=True, exist_ok=True)
    copy = dict(registry)
    copy["allocations"] = {slug: allocation(slug) for slug in cells}
    (filtered / "registry.json").write_text(
        json.dumps(copy, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    runtime = cfg.stage / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    run(["chmod", "-R", "a+rX", str(cfg.stage / "relay-data")], check=False)
    # The relay runs as uid 1000 and needs to create its socket there.
    run(["chown", "-R", "1000:1000", str(runtime)], check=False)
    run(["chmod", "755", str(runtime)], check=False)
    env = {
        **agent_env(cfg),
        "SPANEL_PLAN_AGENT_SOCKET": str(runtime / "plan-agent.sock"),
        "SPANEL_PLAN_AGENT_TOKEN_FILE": str(token),
        "SPANEL_PLAN_AGENT_ALLOWED_UIDS": "0",
    }
    start_process(
        cfg,
        "plan-agent",
        [
            sys.executable,
            str(cfg.stage / "scripts" / "spanel_tenant.py"),
            "plan-agent",
            "--data-root",
            "/var/lib/spanel",
        ],
        env,
    )
    wait_socket(runtime / "plan-agent.sock")
    (runtime / "plan-agent.sock").chmod(0o666)
    relay_env = {
        **agent_env(cfg),
        "SPANEL_EDGE_RELAY_SOCKET": str(runtime / "edge-relay.sock"),
        "SPANEL_TRAEFIK_UID": "1000",
    }
    start_process(
        cfg,
        "edge-relay",
        [
            sys.executable,
            str(cfg.stage / "scripts" / "spanel_tenant.py"),
            "edge-relay",
            "--data-root",
            str(filtered),
            "--bind",
            cfg.relay_bind,
        ],
        relay_env,
        uid=1000,
    )
    primary = allocation(cells[0])
    wait_listener(cfg.relay_bind, 40000 + int(primary["index"]))
    evidence.data["environment"]["agents"] = {
        "plan_agent_socket": "/run/spanel/plan-agent.sock",
        "edge_relay_bind": cfg.relay_bind,
        "edge_relay_source": cfg.relay_source,
    }


def write_runtime_env(cfg: Config) -> tuple[Path, dict[str, str]]:
    values: dict[str, str] = {}
    if cfg.live_env.exists():
        for raw in cfg.live_env.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    database_url = values.get("SYSTUTOR_DATABASE_URL", "")
    if "/" + cfg.live_db not in database_url:
        raise Precondition("live env does not reference the live database")
    values["SYSTUTOR_DATABASE_URL"] = database_url.replace(
        "/" + cfg.live_db, "/" + cfg.db
    )
    values["SYSTUTOR_REDIS_URL"] = f"redis://{cfg.redis}:6379/0"
    values["SYSTUTOR_PLUGINS_DIR"] = "/app/plugins"
    values["SPANEL_APPS_STATE_ROOT"] = str(cfg.stage / "state")
    values["SPANEL_DOCKER_TRANSPORT"] = "local"
    values["SPANEL_PLAN_AGENT_SOCKET"] = "/run/spanel/plan-agent.sock"
    values["SPANEL_PLAN_AGENT_TOKEN_FILE"] = "/run/secrets/plan_agent_token"
    values["SPANEL_ROOTLESS_ROUTES_HTTPS"] = "false"
    values["SPANEL_TENANTS_DATA_ROOT"] = "/var/lib/spanel"
    values["SPANEL_TENANT_RESOURCE_INVENTORY"] = "true"
    values.setdefault("SPANEL_DOMAINS_PROFILE", "internal")
    values["SPANEL_PROXY_TRANSPORT"] = "local"
    values["SPANEL_PROXY_CONFIG_DIR"] = str(cfg.dynamic_dir)
    values["SPANEL_PROXY_BACKUPS_DIR"] = str(cfg.stage / "proxy-backups")
    values["SPANEL_PROXY_LOG"] = "/tmp/spanel-0110c-proxy.log"
    values["SPANEL_PROXY_HTTP_PORT"] = "9080"
    values["SPANEL_PROXY_HTTPS_PORT"] = "9443"
    values["SPANEL_PROXY_TRAEFIK_CONTAINER"] = cfg.traefik_container
    values["SPANEL_PROXY_NETWORK"] = cfg.proxy_network
    values["SPANEL_PROXY_REPO_ROOT"] = "/stage"
    values["SPANEL_HOSTING_SITES_DIR"] = cfg.sites_dir
    values["SPANEL_HOSTING_BACKUPS_DIR"] = str(cfg.stage / "backups")
    values["SPANEL_HOSTING_BACKUP_SCRIPTS_DIR"] = "/app/scripts"
    values["SPANEL_HOSTING_TRAEFIK"] = values.get("SPANEL_HOSTING_TRAEFIK", "true")
    values["SPANEL_HOSTING_NETWORK"] = cfg.hosting_network
    values["SPANEL_PHPMYADMIN_ARBITRARY"] = "true"
    values["SPANEL_PHPMYADMIN_SOURCE_IP"] = cfg.pma_source_ip
    values.setdefault("SPANEL_HOSTING_WP_IMAGE", "wordpress:latest")
    values.setdefault("SPANEL_HOSTING_DB_IMAGE", "mariadb:11")
    values.setdefault("SPANEL_HOSTING_STATIC_IMAGE", "nginx:alpine")
    values.setdefault("SPANEL_FILEMANAGER_HELPER_IMAGE", "wordpress:cli")
    target = cfg.stage / "app.env"
    target.write_text(
        "\n".join(f"{key}={value}" for key, value in values.items()) + "\n",
        encoding="utf-8",
    )
    target.chmod(0o600)
    (cfg.stage / "proxy-backups").mkdir(exist_ok=True)
    return target, values


def _mounts(cfg: Config) -> list[str]:
    mounts = [
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{cfg.stage / 'state'}:{cfg.stage / 'state'}",
        "-v", f"{cfg.stage}:/stage:ro",
        "-v", f"{cfg.stage / 'runtime'}:/run/spanel:ro",
        "-v", f"{cfg.stage / 'plan_agent_token'}:/run/secrets/plan_agent_token:ro",
        "-v", f"{cfg.dynamic_dir}:{cfg.dynamic_dir}:rw",
        "-v", f"{cfg.stage / 'proxy-backups'}:{cfg.stage / 'proxy-backups'}:rw",
        "-v", f"{cfg.stage / 'backups'}:{cfg.stage / 'backups'}:rw",
        "-v", (
            f"{cfg.stage / 'vendor' / 'systutor-core' / 'src'}:"
            "/app/vendor/systutor-core/src:ro"
        ),
        "-v", f"{cfg.stage / 'vendor' / 'systutor-core' / 'plugins'}:/app/plugins:ro",
        "-v", (
            f"{cfg.stage / 'vendor' / 'systutor-core' / 'alembic.ini'}:"
            "/app/vendor/systutor-core/alembic.ini:ro"
        ),
        "-v", (
            f"{cfg.stage / 'vendor' / 'systutor-core' / 'migrations'}:"
            "/app/vendor/systutor-core/migrations:ro"
        ),
        "-v", "/var/lib/spanel/cells:/var/lib/spanel/cells:rw",
        "-v", "/var/lib/spanel/registry.json:/var/lib/spanel/registry.json:ro",
    ]
    if Path(cfg.sites_dir).exists():
        mounts += ["-v", f"{cfg.sites_dir}:{cfg.sites_dir}:rw"]
    return mounts


def start_stack(cfg: Config, runtime_env: Path, *, rootless: bool) -> None:
    for rel in ("state", "vendor", "scripts", "pylibs", "runtime", "backups"):
        path = cfg.stage / rel
        if path.exists():
            run(["chmod", "-R", "a+rX", str(path)], check=False)
    run(["chmod", "600", str(cfg.stage / "plan_agent_token")], check=False)
    run(["chmod", "600", str(runtime_env)], check=False)
    for name in (cfg.app, cfg.worker, cfg.redis):
        docker(cfg, "rm", "-f", name, check=False)
    docker(
        cfg, "run", "-d", "--name", cfg.redis, "--network", cfg.network,
        "redis:7-alpine", check=True,
    )
    mode = "true" if rootless else "false"
    baseline = "rootless" if rootless else "hardened"
    common = [
        "-d", "--network", cfg.network, "--env-file", str(runtime_env),
        "-e", "PYTHONPATH=/app/vendor/systutor-core/src:/app/vendor/systutor-core:/app",
        "-e", f"SPANEL_TENANTS_ROOTLESS={mode}",
        "-e", f"SPANEL_APPS_PROBE_BASELINE={baseline}",
        "-e", (
            "SPANEL_HOSTING_NETWORK=spanel-hosting"
            if rootless
            else f"SPANEL_HOSTING_NETWORK={cfg.hosting_network}"
        ),
        "-e",
        f"SPANEL_PHPMYADMIN_ARBITRARY={'true' if rootless else 'false'}",
        "-e",
        f"SPANEL_PHPMYADMIN_SOURCE_IP={cfg.pma_source_ip}",
        *_mounts(cfg),
    ]
    docker(
        cfg, "run", *common, "--name", cfg.app,
        "-p", f"127.0.0.1:{cfg.api_port}:3000", cfg.image, check=True,
    )
    docker(
        cfg, "run", *common, "--name", cfg.worker, cfg.image,
        "python", "/stage/scripts/e2e_dramatiq_worker.py",
        "--processes", "1", "--threads", "1", "--queues", "apps",
        check=True,
    )
    # La verificación HTTP del producto resuelve los Hosts .lab al Traefik del
    # laboratorio; sin esta red el contenedor desechable no alcanza ese bridge.
    for name in (cfg.app, cfg.worker):
        docker(cfg, "network", "connect", cfg.proxy_network, name, check=False)
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        probe = run(
            ["curl", "-fsS", "-o", "/dev/null", f"{cfg.base_url}/api/v1/system/health"],
            timeout=10,
        )
        if probe.returncode == 0:
            log(f"disposable API healthy (rootless={rootless})")
            return
        time.sleep(3)
    logs = docker(cfg, "logs", "--tail", "80", cfg.app, check=False)
    raise Precondition(f"disposable API did not become healthy: {logs.stdout[-1200:]}")


def restart_stack_rootless(cfg: Config, runtime_env: Path) -> None:
    start_stack(cfg, runtime_env, rootless=True)


def migrate_clone_kernel(cfg: Config, evidence: Evidence) -> None:
    """Apply the shipped kernel compatibility migration to the clone only.

    The lab host was provisioned without an ``alembic_version`` table, so a
    full upgrade from the migration metadata would recreate every table. The code under
    test needs kernel revision ``20261119_0011`` (default for
    ``users.is_superadmin``); its exact SQL is applied idempotently to the
    disposable clone. No Alembic CLI and no change to the live database.
    """
    exists = clone_psql(
        cfg,
        "SELECT count(*) FROM information_schema.columns "
        "WHERE table_name = 'users' AND column_name = 'is_superadmin';",
    )
    if exists != "1":
        evidence.data["repairs"].append(
            {"action": "kernel_compat", "status": "column absent, nothing to do"}
        )
        return
    clone_psql(
        cfg,
        "ALTER TABLE users ALTER COLUMN is_superadmin SET DEFAULT false;",
    )
    clone_psql(
        cfg,
        "UPDATE users SET is_superadmin = false WHERE is_superadmin IS NULL;",
    )
    evidence.data["repairs"].append(
        {
            "action": "kernel_compat_migration",
            "revision": "20261119_0011",
            "target": cfg.db,
        }
    )
    log("disposable clone has the kernel is_superadmin compatibility default")


def wait_plugins(api: Api, timeout: float = 240.0) -> None:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        try:
            plugins = api.request("GET", "/core/plugins")
        except Exception as exc:  # noqa: BLE001 - retried until deadline
            last = str(exc)
            time.sleep(3)
            continue
        last = plugins
        states = {
            str(item.get("plugin_id")): item
            for item in plugins
            if isinstance(item, dict)
            and item.get("plugin_id") in {"hosting", "filemanager", "domains", "tenant"}
        }
        if all(
            states.get(name, {}).get("is_enabled") is True
            for name in ("hosting", "filemanager", "domains", "tenant")
        ):
            return
        time.sleep(3)
    raise Precondition(f"required plugins did not become enabled: {last}")


def apply_plan(
    cfg: Config, api: Api, evidence: Evidence, label: str, slug: str
) -> None:
    plan = api.request(
        "POST",
        "/plugins/apps/plan",
        {"memory_bytes": MEMORY_PLAN, "cpus": CPU_PLAN, "pids": PIDS_PLAN},
    )
    verified: Any = None
    verify_error = ""
    for _attempt in range(4):
        try:
            verified = api.request("POST", "/plugins/apps/plan/verify")
            if isinstance(verified, dict) and verified.get("ok") is True:
                break
        except Exception as exc:  # noqa: BLE001 - los cgroups son la prueba real
            verify_error = str(exc)[:300]
        time.sleep(3)
    uid = int(allocation(slug)["uid"])
    limits = cgroup_limits(uid, slug=slug, cgroup_path=plan.get("cgroup_path"))
    passed = (
        plan.get("status") == "applied"
        and limits.get("memory.max") == str(MEMORY_PLAN)
        and limits.get("pids.max") == str(PIDS_PLAN)
    )
    evidence.record(
        f"plan_{label}",
        "POST /plugins/apps/plan + host cgroups",
        {"memory": MEMORY_PLAN, "cpus": CPU_PLAN, "pids": PIDS_PLAN},
        {"plan": plan, "verify": verified, "verify_error": verify_error, "cgroups": limits},
        passed=passed,
    )
    if not passed:
        raise CheckFailed(f"plan for {label} was not effective on the host")


# ---------------------------------------------------------------------------
# Interacción funcional
# ---------------------------------------------------------------------------


def wp_opener(cfg: Config) -> tuple[http.cookiejar.CookieJar, urllib.request.OpenerDirector]:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), NoRedirect()
    )
    return jar, opener


def wp_request(
    cfg: Config,
    opener: urllib.request.OpenerDirector,
    domain: str,
    path: str,
    *,
    data: bytes | None = None,
    timeout: int = 30,
) -> tuple[int, bytes, dict[str, str]]:
    # Usar el dominio publicado (no un origin de prueba con Host falso) para
    # que las cookies de WordPress queden ligadas al Host real y los redirects
    # absolutos funcionen.
    request = urllib.request.Request(
        f"http://{domain}{path}",
        data=data,
        headers={
            "Host": domain,
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": f"http://{domain}/wp-login.php",
        },
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(), dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers.items())


def wp_login(cfg: Config, domain: str, user: str, password: str) -> dict[str, Any]:
    jar, opener = wp_opener(cfg)
    status, body, _headers = 0, b"", {}
    for _attempt in range(6):
        status, body, _headers = wp_request(cfg, opener, domain, "/wp-login.php")
        if status == 200:
            break
        # El file-provider de Traefik puede recargar tarde tras un lifecycle.
        time.sleep(3)
    if status != 200:
        return {"ok": False, "stage": "form", "status": status}
    text = body.decode(errors="replace")
    fields = {
        name: value
        for name, value in re.findall(
            r'<input[^>]+name="([^"]+)"[^>]*value="([^"]*)"', text
        )
    }
    form = {
        "log": user,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": f"http://{domain}/wp-admin/",
        "testcookie": "1",
        **{key: value for key, value in fields.items() if key in {"_wpnonce"}},
    }
    status, body, _headers = wp_request(
        cfg, opener, domain, "/wp-login.php", data=urllib.parse.urlencode(form).encode()
    )
    cookies = "; ".join(f"{item.name}={item.value}" for item in jar)
    logged = any("wordpress_logged_in" in item.name for item in jar)
    admin_status = 0
    if logged:
        admin_status, _, _ = wp_request(cfg, opener, domain, "/wp-admin/")
    return {
        "ok": bool(logged) and admin_status == 200,
        "stage": "dashboard",
        "status": status,
        "admin_status": admin_status,
        "cookie": cookies,
        "cookie_names": sorted(item.name for item in jar),
    }


def fm_base(site_id: str) -> str:
    return f"/plugins/filemanager/targets/hosting/{site_id}"


def fm_list(api: Api, site_id: str, path: str = "") -> dict[str, Any]:
    return api.request(
        "GET", f"{fm_base(site_id)}/entries?path={urllib.parse.quote(path)}"
    )


def fm_mkdir(api: Api, site_id: str, path: str) -> dict[str, Any]:
    last: ApiError | None = None
    for attempt in range(2):
        try:
            return api.request(
                "POST", f"{fm_base(site_id)}/directories", {"path": path}
            )
        except ApiError as exc:
            last = exc
            if exc.status == 409:
                return {"exists": True}
            if exc.status != 502:
                raise
            if attempt == 0:
                time.sleep(2)
    # El driver rootless reporta "already exists" como 409, pero el handle
    # efímero a veces lo envuelve y la API lo convierte en 502. mkdir es
    # idempotente: si la ruta ya existe, seguimos.
    if last is not None and last.status == 502:
        return {"exists": True}
    assert last is not None
    raise last


def fm_upload(
    api: Api, site_id: str, directory: str, name: str, content: bytes
) -> tuple[int, Any]:
    """Upload a file; the path is a query parameter per the plugin contract."""
    boundary = f"spanel0110c{time.time_ns()}"
    body = io.BytesIO()
    body.write(
        (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
            f"filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        ).encode()
    )
    body.write(content)
    body.write(f"\r\n--{boundary}--\r\n".encode())
    query = urllib.parse.urlencode({"path": directory, "replace": "true"})
    request = urllib.request.Request(
        f"{api.base}{API_PREFIX}{fm_base(site_id)}/uploads?{query}",
        data=body.getvalue(),
        method="POST",
        headers={
            "Authorization": f"Bearer {api.token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


def fm_text(api: Api, site_id: str, path: str) -> dict[str, Any]:
    return api.request(
        "GET", f"{fm_base(site_id)}/text?path={urllib.parse.quote(path)}"
    )


def fm_save(
    api: Api, site_id: str, path: str, content: str, version: str
) -> dict[str, Any]:
    return api.request(
        "PUT",
        f"{fm_base(site_id)}/text?path={urllib.parse.quote(path)}",
        {"content": content, "version": version},
    )


def fm_delete(api: Api, site_id: str, path: str) -> dict[str, Any]:
    return api.request(
        "DELETE", f"{fm_base(site_id)}/entries?path={urllib.parse.quote(path)}"
    )


def fm_download(api: Api, site_id: str, path: str) -> bytes:
    status, payload, _headers = api.request(
        "GET",
        f"{fm_base(site_id)}/download?path={urllib.parse.quote(path)}",
        raw=True,
    )
    if status != 200:
        raise CheckFailed(f"direct download returned {status}")
    return payload


def fm_ticket(api: Api, site_id: str, path: str) -> dict[str, Any]:
    return api.request(
        "POST",
        f"{fm_base(site_id)}/download-tickets?path={urllib.parse.quote(path)}"
        f"&provider=hosting&resource_id={site_id}",
    )


def fm_ticket_download(api: Api, site_id: str, path: str) -> tuple[int, bytes]:
    ticket = fm_ticket(api, site_id, path)
    return api.download(ticket["url"])


def fm_ticket_replay(api: Api, site_id: str, path: str) -> dict[str, Any]:
    ticket = fm_ticket(api, site_id, path)
    first_status, first_payload = api.download(ticket["url"])
    second_status, second_payload = api.download(ticket["url"])
    return {
        "first_status": first_status,
        "first_payload": first_payload,
        "second_status": second_status,
        "second_payload": second_payload,
    }


def fm_zip(api: Api, site_id: str, path: str, name: str, entries: list[str]) -> dict:
    return api.request(
        "POST", f"{fm_base(site_id)}/archives",
        {"path": path, "name": name, "entries": entries},
    )


def fm_extract(api: Api, site_id: str, path: str, destination: str) -> dict:
    return api.request(
        "POST",
        f"{fm_base(site_id)}/archives/extract",
        {"path": path, "destination": destination},
    )


def backup_export(api: Api, site_id: str) -> dict[str, Any]:
    return api.request(
        "POST", f"/plugins/hosting/sites/{site_id}/backup/export", timeout=900
    )


def backup_download(api: Api, url: str) -> bytes:
    status, payload = api.download(url, timeout=900)
    if status != 200:
        raise CheckFailed(f"backup download returned {status}")
    return payload


def backup_import(
    api: Api, site_id: str, container: str, payload: bytes
) -> tuple[int, Any]:
    status, body, _headers = api.multipart(
        "POST",
        f"/plugins/hosting/sites/{site_id}/backup/import",
        fields={"confirmation": container},
        file_name="backup.zip",
        file_content=payload,
        timeout=900,
    )
    return status, body


def create_tenant(cfg: Config, api: Api, redactor: Redactor) -> dict[str, Any]:
    password = redactor.add(secrets.token_urlsafe(18))
    body = {
        "name": f"0110C Intruder {cfg.slug}",
        "slug": cfg.intruder_tenant,
        "domain": f"tenant-{cfg.slug}.{cfg.domain_suffix}",
        "user_email": f"intruder-{cfg.slug}@example.invalid",
        "user_password": password,
        "user_full_name": "0110C Intruder",
    }
    last_error: ApiError | None = None
    for _attempt in range(10):
        try:
            payload = api.request(
                "POST", "/plugins/tenant/tenants", body, timeout=120
            )
            break
        except ApiError as exc:
            last_error = exc
            if exc.status != 404:
                raise
            # El enable del plugin puede terminar de montar rutas unos
            # segundos después de que /core/plugins lo reporte activo.
            time.sleep(3)
    else:
        assert last_error is not None
        raise last_error
    return {
        "tenant": payload,
        "email": f"intruder-{cfg.slug}@example.invalid",
        "password": password,
    }


def create_fixture(
    cfg: Config, api: Api, redactor: Redactor, *, kind: str, name: str, domain: str
) -> dict[str, Any]:
    try:
        payload = api.create_site(kind=kind, name=name, domain=domain)
    except ApiError as exc:
        if exc.status != 409:
            raise
        # Resume: el sitio ya existe en este clon; se reutiliza por dominio.
        for row in api.sites():
            if row.get("domain") == domain:
                return {"site": row, "admin_password": None}
        raise
    site = payload["site"]
    if payload.get("admin_password"):
        redactor.add(payload["admin_password"])
    return {"site": site, "admin_password": payload.get("admin_password")}


def seed_files(api: Api, site_id: str, marker: str) -> dict[str, Any]:
    fm_mkdir(api, site_id, "e2e")
    content = f"0110-C fixture {marker}\n".encode()
    status, _result = fm_upload(api, site_id, "e2e", "marker.txt", content)
    if status != 200:
        raise CheckFailed(f"file upload returned {status}")
    direct = fm_download(api, site_id, "e2e/marker.txt")
    ticket = fm_ticket_replay(api, site_id, "e2e/marker.txt")
    return {
        "marker": marker,
        "sha256": hashlib.sha256(content).hexdigest(),
        "direct_sha256": hashlib.sha256(direct).hexdigest(),
        "ticket_status": ticket["first_status"],
        "ticket_sha256": hashlib.sha256(ticket["first_payload"]).hexdigest(),
        "replay_status": ticket["second_status"],
    }


def http_marker(cfg: Config, domain: str, expected_sha: str) -> dict[str, Any]:
    probe = external_probe(cfg, domain, path="/e2e/marker.txt")
    return {
        **probe,
        "matches": probe.get("sha256") == expected_sha,
    }


def safe_probe(cfg: Config, domain: str, *, path: str = "/") -> dict[str, Any]:
    try:
        return external_probe(cfg, domain, path=path, deadline=20)
    except HarnessError as exc:
        return {"status": 0, "error": str(exc)}


def live_values(cfg: Config) -> dict[str, str]:
    values: dict[str, str] = {}
    if not cfg.live_env.exists():
        return values
    for raw in cfg.live_env.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def admin_login(cfg: Config, redactor: Redactor) -> Api:
    values = live_values(cfg)
    email = values.get("SYSTUTOR_SEED_ADMIN_EMAIL", "")
    password = values.get("SYSTUTOR_SEED_ADMIN_PASSWORD", "")
    if not email or not password:
        raise Precondition("seed administrator credentials are missing from the live env")
    redactor.add(password)
    api = Api(cfg, redactor)
    api.login(email, password)
    return api


def intruder_login(cfg: Config, redactor: Redactor, refs: dict[str, Any]) -> Api:
    api = Api(cfg, redactor)
    api.login(refs["intruder"]["email"], refs["intruder"]["password"])
    return api


def cli_rootless(cfg: Config, *args: str, timeout: int = 1800) -> dict[str, Any]:
    result = docker(
        cfg,
        "exec",
        cfg.app,
        "python",
        "/stage/scripts/hosting_migrate_rootless.py",
        *args,
        "--json",
        timeout=timeout,
        check=False,
    )
    try:
        payload = json.loads(result.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise HarnessError(
            f"migration CLI returned invalid JSON: {result.stdout[-300:]} {result.stderr[-300:]}"
        ) from exc
    return payload


def plugin_health(cfg: Config) -> dict[str, str]:
    result = docker(cfg, "ps", "-a", "--format", "{{.Names}} {{.Status}}", check=False)
    return {
        line.split()[0]: line[len(line.split()[0]) + 1 :]
        for line in result.stdout.splitlines()
        if line.strip()
    }


# ---------------------------------------------------------------------------
# Fase: preflight
# ---------------------------------------------------------------------------


def phase_preflight(cfg: Config, ev: Evidence, journal: Journal) -> None:
    if os.geteuid() != 0:
        raise Precondition("the ceremony needs root (sudo) for cells and cleanup")
    for binary in ("docker", "curl", "ss", "journalctl", "systemctl", "rootlesskit"):
        if shutil.which(binary) is None:
            raise Precondition(f"required host binary is missing: {binary}")
    cgroup = Path("/sys/fs/cgroup/cgroup.controllers")
    if not cgroup.exists() or "memory" not in cgroup.read_text(encoding="utf-8"):
        raise Precondition("cgroups v2 with memory controller is required")
    if not cfg.live_env.exists():
        raise Precondition(f"live env file is missing: {cfg.live_env}")
    if not cfg.dynamic_dir.is_dir():
        raise Precondition(f"Traefik dynamic directory is missing: {cfg.dynamic_dir}")
    if not Path("/var/lib/spanel/registry.json").is_file():
        raise Precondition("host cell registry is missing")
    for name in (cfg.live_pg, cfg.live_redis, cfg.traefik_container):
        result = docker(cfg, "inspect", "-f", "{{.State.Running}}", name, check=False)
        if result.returncode or result.stdout.strip() != "true":
            raise Precondition(f"required live container is not running: {name}")
    if docker(cfg, "image", "inspect", cfg.image, check=False).returncode:
        raise Precondition(f"app image is missing: {cfg.image}")
    ev.data["environment"] = {
        "host": os.uname().nodename,
        "kernel": os.uname().release,
        "image": cfg.image,
        "database": f"clone {cfg.db} of {cfg.live_db}",
        "api": cfg.base_url,
        "cell": cfg.slug,
        "intruder_cell": cfg.intruder_slug,
        "external_base": cfg.external_base,
        "domain_suffix": cfg.domain_suffix,
        "commit": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
        "note": (
            "Entorno desechable: clon de BD, API/worker/redis/agentes efímeros, "
            "dos celdas rootless; observación host read-only."
        ),
    }
    ev.data["baseline"]["state_hashes"] = backup_state(cfg, ev)
    ev.data["baseline"]["core"] = core_snapshot(cfg)
    ev.data["baseline"]["other_tenants"] = other_tenant_snapshot(cfg)
    ev.data["baseline"]["rootful_containers"] = sorted(plugin_health(cfg))
    ev.data["baseline"]["db_3306"] = tcp_listeners(3306)
    ev.data["baseline"]["deny_since"] = time.time()
    journal.data["deny_since"] = ev.data["baseline"]["deny_since"]
    journal.save()
    ev.require(
        "preflight_host",
        "host",
        "root, cgroups v2, docker, live stack and disposable prerequisites",
        lambda: {
            "euid": os.geteuid(),
            "cgroup": str(cgroup),
            "live_env": str(cfg.live_env),
            "dynamic_dir": str(cfg.dynamic_dir),
        },
        predicate=lambda item: item["euid"] == 0,
    )


# ---------------------------------------------------------------------------
# Fase: setup
# ---------------------------------------------------------------------------


def remove_stale_fixtures(cfg: Config, evidence: Evidence) -> None:
    """Remove only leftovers owned by this fixture's exact site ids/slug."""
    site_names = (
        f"0110c-static-{cfg.slug}",
        f"0110c-wp-{cfg.slug}",
        f"intr-static-{cfg.slug}",
    )
    removed: list[str] = []
    for site_name in site_names:
        found = docker(
            cfg, "ps", "-a", "--format", "{{.Names}}",
            "--filter", f"label=spanel.site={site_name}", check=False,
        )
        for name in (n for n in found.stdout.splitlines() if n):
            docker(cfg, "rm", "-f", name, check=False)
            removed.append(name)
    volumes = docker(
        cfg, "volume", "ls", "--format", "{{.Name}}", check=False
    )
    for name in volumes.stdout.splitlines():
        if any(
            marker in name
            for marker in (
                f"0110c-wp-{cfg.slug}",
                f"0110c-static-{cfg.slug}",
                f"intr-static-{cfg.slug}",
            )
        ):
            docker(cfg, "volume", "rm", "-f", name, check=False)
            removed.append(name)
    for path in route_documents(cfg):
        try:
            path.unlink()
            removed.append(str(path))
        except OSError:
            continue
    if removed:
        evidence.data["repairs"].append(
            {"action": "remove_stale_fixtures", "removed": sorted(removed)}
        )
        log(f"removed {len(removed)} stale fixture resources")


def phase_setup(cfg: Config, ev: Evidence, journal: Journal) -> None:
    stage_tree(cfg)
    remove_stale_fixtures(cfg, ev)
    clone_database(cfg)
    ev.data["repairs"].append({"action": "clone_database", "database": cfg.db})
    cells = [cfg.slug, cfg.intruder_slug]
    for slug in cells:
        journal.data.setdefault("cells", {})[slug] = provision_cell(cfg, slug)
        ev.data["repairs"].append({"action": "provision_cell", "slug": slug})
    # Agents (and their token/socket) must exist before the API container
    # mounts them; otherwise Docker would create a directory at the token path.
    prepare_agents(cfg, cells, ev)
    runtime_env, _values = write_runtime_env(cfg)
    start_stack(cfg, runtime_env, rootless=False)
    migrate_clone_kernel(cfg, ev)
    admin = admin_login(cfg, ev.redactor)
    wait_plugins(admin)
    tenant = create_tenant(cfg, admin, ev.redactor)
    journal.data["intruder"] = tenant
    journal.data["tenant"] = admin.me()
    journal.data["runtime_env"] = str(runtime_env)
    journal.save()
    ev.data["fixtures"]["cells"] = {slug: journal.data["cells"][slug] for slug in cells}
    ev.record(
        "setup_environment",
        "host/CLI",
        "disposable DB, API/worker, two rootless cells and agents",
        {
            "database": cfg.db,
            "cells": {slug: journal.data["cells"][slug].get("state") for slug in cells},
            "api_port": cfg.api_port,
        },
    )


# ---------------------------------------------------------------------------
# Fase: seed
# ---------------------------------------------------------------------------


def phase_seed(cfg: Config, ev: Evidence, journal: Journal) -> None:
    runtime_env = Path(journal.data["runtime_env"])
    admin = admin_login(cfg, ev.redactor)
    fixtures: dict[str, Any] = {}
    for kind, name, domain in (
        ("static", f"0110c-static-{cfg.slug}", cfg.primary_domain_static),
        ("wordpress", f"0110c-wp-{cfg.slug}", cfg.primary_domain_wp),
    ):
        created = create_fixture(
            cfg, admin, ev.redactor, kind=kind, name=name, domain=domain
        )
        site = created["site"]
        if kind == "wordpress":
            # El laboratorio usa el file-provider de Traefik; el alta de un
            # WordPress rootful no publica el dominio por sí sola. Se hace por
            # la API pública de Domains, sin tocar documentos a mano.
            try:
                admin.request(
                    "POST",
                    "/plugins/domains/routes",
                    {
                        "site_id": site["id"],
                        "domain": domain,
                        "path": "/",
                        "port": 80,
                        "https": False,
                    },
                    timeout=300,
                )
            except ApiError as exc:
                if exc.status != 409:
                    raise
        seeded = seed_files(admin, site["id"], f"{kind}-A")
        public = http_marker(cfg, domain, seeded["sha256"])
        fixtures[kind] = {
            "site": site,
            "admin_password": created["admin_password"],
            "seed": seeded,
            "rootful_http": public,
        }
        if not public["matches"]:
            raise CheckFailed(f"rootful fixture {kind} is not served over HTTP")
    ev.data["fixtures"]["sites"] = {
        key: {
            "id": value["site"]["id"],
            "container_name": value["site"]["container_name"],
            "domain": value["site"]["domain"],
            "kind": key,
        }
        for key, value in fixtures.items()
    }
    ev.record(
        "rootful_fixtures",
        "API + public HTTP",
        "static and WordPress created rootful with a URL-served marker",
        {
            key: {
                "site_id": value["site"]["id"],
                "http": value["rootful_http"],
            }
            for key, value in fixtures.items()
        },
    )

    log("restarting disposable stack with SPANEL_TENANTS_ROOTLESS=true")
    restart_stack_rootless(cfg, runtime_env)
    admin = admin_login(cfg, ev.redactor)
    wait_plugins(admin)
    apply_plan(cfg, admin, ev, "primary", cfg.slug)
    # El usuario del tenant intruso no tiene `apps.plans.manage`; el plan
    # obligatorio es el de la celda principal.
    intruder_login(cfg, ev.redactor, journal.data)
    intruder_cell = journal.data["cells"][cfg.intruder_slug]
    ev.data["fixtures"]["intruder"] = {
        "tenant_id": journal.data["intruder"]["tenant"]["id"],
        "cell": cfg.intruder_slug,
    }
    ev.record(
        "intruder_tenant_cell",
        "API + host observation",
        "second tenant has its own rootless cell; cross-tenant access is denied later",
        {
            "tenant_id": journal.data["intruder"]["tenant"]["id"],
            "cell_state": intruder_cell.get("state"),
            "cell_uid": intruder_cell.get("uid"),
        },
        passed=intruder_cell.get("state") == "ready",
    )

    migration: dict[str, Any] = {}
    for kind in ("static", "wordpress"):
        site = fixtures[kind]["site"]
        result = cli_rootless(cfg, "migrate", "--site", site["id"])
        migration[kind] = result
        ev.record(
            f"migration_{kind}",
            "operator CLI 0110-A",
            "migration retains a rollbackable rootless site",
            {
                "state": result.get("state"),
                "ok": result.get("ok"),
                "error": result.get("error"),
                "steps": result.get("steps"),
                "operation_id": result.get("operation_id"),
            },
            passed=result.get("state") == "retained",
        )
        if result.get("state") != "retained":
            raise CheckFailed(f"{kind} migration did not retain a rollbackable state")
        after = http_marker(
            cfg, fixtures[kind]["site"]["domain"], fixtures[kind]["seed"]["sha256"]
        )
        if not after["matches"]:
            raise CheckFailed(f"{kind} marker changed during migration")
    fixtures["migration"] = migration
    journal.data["fixtures"] = {
        "sites": ev.data["fixtures"]["sites"],
        "passwords": {},
        "intruder": ev.data["fixtures"]["intruder"],
        "migration": migration,
    }
    journal.save()
    ev.data["fixtures"]["migration"] = {
        kind: {
            "operation_id": item.get("operation_id"),
            "state": item.get("state"),
            "steps": item.get("steps"),
        }
        for kind, item in migration.items()
    }
    ev.record(
        "migrate_static_then_wordpress",
        "operator CLI 0110-A",
        "both legacy sites migrate to rootless retaining data and rollback",
        ev.data["fixtures"]["migration"],
        passed=all(item.get("state") == "retained" for item in migration.values()),
    )


# ---------------------------------------------------------------------------
# Fase: exercise
# ---------------------------------------------------------------------------


def _site_ids(journal: Journal) -> dict[str, str]:
    sites = journal.data["fixtures"]["sites"]
    return {kind: str(value["id"]) for kind, value in sites.items()}


def _reset_wp_password(api: Api, site_id: str, password: str) -> dict[str, Any]:
    users = api.request("GET", f"/plugins/hosting/sites/{site_id}/users")["users"]
    if not users:
        raise CheckFailed("WordPress reports no users")
    admin = next(
        (item for item in users if item.get("role") == "administrator"), users[0]
    )
    return api.request(
        "POST",
        f"/plugins/hosting/sites/{site_id}/users/{admin['id']}/password",
        {"password": password},
    )


def check_auth_scope(
    cfg: Config, ev: Evidence, admin: Api, intruder: Api, site_id: str
) -> None:
    started = time.monotonic()
    tenant_sites = admin.sites("tenant")
    all_sites = admin.sites("all")
    intruder_scope_status, _payload, _headers = intruder.request(
        "GET",
        "/plugins/hosting/sites?scope=all",
        allow=(200, 403),
        raw=True,
    )
    cross_status, cross_body, _headers = intruder.request(
        "GET",
        f"/plugins/hosting/sites/{site_id}/config",
        allow=(200, 403, 404),
        raw=True,
    )
    intruder_sites = intruder.sites("tenant")
    invalid = Api(cfg, ev.redactor, token="invalid.jwt.value")
    invalid_status, _payload, _headers = invalid.request(
        "GET",
        "/plugins/hosting/sites",
        allow=(200, 401, 403, 500),
        auth=True,
        raw=True,
    )
    tenant_ids = {str(item.get("id")) for item in tenant_sites}
    ev.record(
        "auth_rbac_scope",
        "API auth",
        "real login, tenant scope isolated, platform-only scope=all, invalid JWT rejected",
        {
            "tenant_sites": sorted(tenant_ids),
            "all_sites": len(all_sites),
            "intruder_scope_all_status": intruder_scope_status,
            "intruder_cross_site_status": cross_status,
            "intruder_cross_body": cross_body[:160].decode(errors="replace"),
            "intruder_visible_site_ids": sorted(
                str(item.get("id")) for item in intruder_sites
            ),
            "invalid_jwt_status": invalid_status,
        },
        passed=(
            site_id in tenant_ids
            and site_id not in {str(item.get("id")) for item in intruder_sites}
            and intruder_scope_status == 403
            and cross_status in (403, 404)
            and invalid_status in (401, 403, 500)
        ),
        duration=time.monotonic() - started,
    )


def check_lifecycle(
    cfg: Config, ev: Evidence, api: Api, label: str, site: dict[str, Any]
) -> None:
    site_id = site["id"]
    domain = site["domain"]
    started = time.monotonic()
    stopped = api.request("POST", f"/plugins/hosting/sites/{site_id}/stop")
    down = safe_probe(cfg, domain)
    started_again = api.request("POST", f"/plugins/hosting/sites/{site_id}/start")
    up = external_probe(cfg, domain, deadline=60)
    restarted = api.request("POST", f"/plugins/hosting/sites/{site_id}/restart")
    after_restart = external_probe(cfg, domain, deadline=60)
    ev.record(
        f"lifecycle_{label}",
        "API lifecycle + public HTTP",
        "stop makes the site unavailable; start/restart recover HTTP 200",
        {
            "stopped": stopped.get("status"),
            "down": down,
            "started": started_again.get("status"),
            "up": up.get("status"),
            "restarted": restarted.get("status"),
            "after_restart": after_restart.get("status"),
        },
        passed=(
            down.get("status") != 200
            and up.get("status") == 200
            and after_restart.get("status") == 200
        ),
        duration=time.monotonic() - started,
    )


def check_logs(ev: Evidence, api: Api, label: str, site_id: str) -> None:
    started = time.monotonic()
    payload = api.request("GET", f"/plugins/hosting/sites/{site_id}/logs?lines=50")
    logs = str(payload.get("logs", ""))
    secret_leak = bool(re.search(r"(?:password|passwd|secret|token)\s*[=:]", logs, re.IGNORECASE))
    ev.record(
        f"logs_{label}",
        "API logs",
        "log lines belong to the running site and never contain a secret",
        {
            "lines": len(logs.splitlines()),
            "empty": not logs.strip(),
            "secret_leak": secret_leak,
        },
        passed=bool(logs.strip()) and not secret_leak,
        duration=time.monotonic() - started,
    )


def check_file_manager(
    cfg: Config,
    ev: Evidence,
    api: Api,
    label: str,
    site: dict[str, Any],
    seed_sha: str,
) -> None:
    site_id = site["id"]
    domain = site["domain"]
    started = time.monotonic()
    listed = fm_list(api, site_id)
    listing = {item.get("name") for item in listed.get("entries", [])}
    original = f"0110-C fixture {label}\n"
    fm_mkdir(api, site_id, "e2e/ops")
    status, _ = fm_upload(api, site_id, "e2e/ops", "a.txt", original.encode())
    read = fm_text(api, site_id, "e2e/ops/a.txt")
    changed = f"0110-C changed {label}\n"
    saved = fm_save(api, site_id, "e2e/ops/a.txt", changed, str(read["version"]))
    served = external_probe(cfg, domain, path="/e2e/ops/a.txt")
    renamed = api.request(
        "PATCH",
        f"{fm_base(site_id)}/entries",
        {"path": "e2e/ops/a.txt", "name": "b.txt"},
    )
    direct = fm_download(api, site_id, "e2e/ops/b.txt")
    ticket = fm_ticket_replay(api, site_id, "e2e/ops/b.txt")
    ticket_status = ticket["first_status"]
    ticket_payload = ticket["first_payload"]
    replay_status = ticket["second_status"]
    zipped = fm_zip(api, site_id, "e2e/ops", "bundle.zip", ["b.txt"])
    fm_mkdir(api, site_id, "e2e/ops/out")
    extracted = fm_extract(api, site_id, "e2e/ops/bundle.zip", "e2e/ops/out")
    extracted_list = fm_list(api, site_id, "e2e/ops/out")
    extracted_names = {item.get("name") for item in extracted_list.get("entries", [])}
    fm_upload(api, site_id, "e2e/ops", "c.txt", b"batch\n")
    deleted = fm_delete(api, site_id, "e2e/ops/b.txt")
    batch = api.request(
        "POST",
        f"{fm_base(site_id)}/entries/delete-batch",
        {"paths": ["e2e/ops/c.txt", "e2e/ops/bundle.zip"]},
    )
    traversal_status, traversal_body, _ = api.request(
        "GET",
        f"{fm_base(site_id)}/text?path=../../etc/passwd",
        allow=(200, 400, 403, 404, 500, 502),
        raw=True,
    )
    absolute_status, absolute_body, _ = api.request(
        "GET",
        f"{fm_base(site_id)}/text?path=/etc/passwd",
        allow=(200, 400, 403, 404, 500, 502),
        raw=True,
    )
    marker = http_marker(cfg, domain, seed_sha)
    ev.record(
        f"filemanager_{label}",
        "File Manager API + public HTTP",
        "list/mkdir/upload/read/write/rename/download/ticket/zip/extract/delete "
        "with traversal rejected and content served",
        {
            "listed": sorted(name for name in listing if name),
            "upload_status": status,
            "read_version": bool(read.get("version")),
            "save_version": bool(saved.get("version")),
            "served": served.get("status"),
            "served_matches": served.get("sha256")
            == hashlib.sha256(changed.encode()).hexdigest(),
            "renamed": bool(renamed),
            "direct_matches": direct == changed.encode(),
            "ticket_status": ticket_status,
            "ticket_matches": ticket_payload == changed.encode(),
            "replay_status": replay_status,
            "zip": bool(zipped),
            "extract": bool(extracted),
            "extracted_names": sorted(name for name in extracted_names if name),
            "deleted": bool(deleted),
            "batch": bool(batch),
            "traversal": {
                "status": traversal_status,
                "body": traversal_body[:120].decode(errors="replace"),
            },
            "absolute": {
                "status": absolute_status,
                "body": absolute_body[:120].decode(errors="replace"),
            },
            "marker_preserved": marker.get("matches"),
        },
        passed=(
            status == 200
            and bool(read.get("version"))
            and bool(saved.get("version"))
            and served.get("status") == 200
            and direct == changed.encode()
            and ticket_status == 200
            and ticket_payload == changed.encode()
            and replay_status == 401
            and bool(extracted_names)
            and traversal_status in (400, 403, 404, 500, 502)
            and absolute_status in (400, 403, 404, 500, 502)
            and marker.get("matches") is True
        ),
        duration=time.monotonic() - started,
    )


def check_backup_static(
    cfg: Config, ev: Evidence, api: Api, site: dict[str, Any]
) -> None:
    site_id = site["id"]
    started = time.monotonic()
    exported = backup_export(api, site_id)
    payload = backup_download(api, exported["url"])
    replay = api.download(exported["url"])
    # Mutate the served marker and restore it through the API.
    fm_save_bytes(api, site_id, "e2e/marker.txt", b"mutated-before-restore\n")
    status, _body = backup_import(api, site_id, site["container_name"], payload)
    restored = fm_download(api, site_id, "e2e/marker.txt")
    ev.record(
        "backup_static",
        "API backup export/import + File Manager",
        "ZIP restores the original static file; tickets are single use",
        {
            "filename": exported.get("filename"),
            "bytes": len(payload),
            "ticket_replay_status": replay[0],
            "import_status": status,
            "restored_sha256": hashlib.sha256(restored).hexdigest(),
        },
        passed=(
            exported.get("url")
            and len(payload) > 0
            and replay[0] == 401
            and status == 200
            and restored.startswith(b"0110-C fixture")
        ),
        duration=time.monotonic() - started,
    )


def fm_save_bytes(api: Api, site_id: str, path: str, content: bytes) -> None:
    read = fm_text(api, site_id, path)
    fm_save(api, site_id, path, content.decode(), str(read["version"]))


def check_backup_wordpress(
    cfg: Config, ev: Evidence, api: Api, refs: dict[str, Any], site: dict[str, Any]
) -> dict[str, Any]:
    site_id = site["id"]
    domain = site["domain"]
    started = time.monotonic()
    password_a = ev.redactor.add(secrets.token_urlsafe(16))
    password_b = ev.redactor.add(secrets.token_urlsafe(16))
    _reset_wp_password(api, site_id, password_a)
    fm_save_bytes(api, site_id, "e2e/marker.txt", b"0110-C fixture wordpress-A\n")
    login_a_before = wp_login(cfg, domain, "admin", password_a)
    exported = backup_export(api, site_id)
    payload = backup_download(api, exported["url"])
    _reset_wp_password(api, site_id, password_b)
    fm_save_bytes(api, site_id, "e2e/marker.txt", b"0110-C fixture wordpress-B\n")
    status, _body = backup_import(api, site_id, site["container_name"], payload)
    login_a = wp_login(cfg, domain, "admin", password_a)
    login_b = wp_login(cfg, domain, "admin", password_b)
    marker = http_marker(
        cfg, domain, hashlib.sha256(b"0110-C fixture wordpress-A\n").hexdigest()
    )
    ev.record(
        "backup_wordpress_db_and_files",
        "API backup export/import + WordPress login + public HTTP",
        "A authenticates and B fails after restore; marker A reappears",
        {
            "login_a_before": login_a_before.get("ok"),
            "import_status": status,
            "login_a": login_a.get("ok"),
            "login_b": login_b.get("ok"),
            "marker_a": marker.get("matches"),
            "bytes": len(payload),
        },
        passed=(
            login_a_before.get("ok") is True
            and status == 200
            and login_a.get("ok") is True
            and login_b.get("ok") is False
            and marker.get("matches") is True
        ),
        duration=time.monotonic() - started,
    )
    return {"password": password_a, "domain": domain, "site_id": site_id}


def check_wordpress(
    cfg: Config,
    ev: Evidence,
    api: Api,
    intruder: Api,
    site: dict[str, Any],
    password_a: str,
) -> None:
    site_id = site["id"]
    domain = site["domain"]
    started = time.monotonic()
    config = api.request("GET", f"/plugins/hosting/sites/{site_id}/config")
    patched = api.request(
        "PATCH",
        f"/plugins/hosting/sites/{site_id}/config",
        {"env": {"WP_DEBUG": "false", "TZ": "Europe/Madrid"}},
    )
    rejected_status, _rejected_body, _ = api.request(
        "PATCH",
        f"/plugins/hosting/sites/{site_id}/config",
        {"env": {"WORDPRESS_DB_HOST": "attacker"}},
        allow=(200, 422),
        raw=True,
    )
    _db_status, db_payload, db_headers = api.request(
        "POST", f"/plugins/hosting/sites/{site_id}/database", raw=True
    )
    database = json.loads(db_payload)
    users = api.request("GET", f"/plugins/hosting/sites/{site_id}/users")
    explicit = _reset_wp_password(api, site_id, password_a)
    explicit_login = wp_login(cfg, domain, "admin", password_a)
    generated = api.request(
        "POST",
        f"/plugins/hosting/sites/{site_id}/users/{users['users'][0]['id']}/password",
    )
    generated_password = generated.get("password")
    if not generated_password:
        raise CheckFailed("generated password was not returned")
    ev.redactor.add(generated_password)
    generated_login = wp_login(cfg, domain, "admin", generated_password)
    _reset_wp_password(api, site_id, password_a)

    previous = wp_login(cfg, domain, "admin", password_a)
    rotated = api.request("POST", f"/plugins/hosting/sites/{site_id}/secrets/salts")
    cookie_after = invalidate_cookie(cfg, domain, previous.get("cookie", ""))
    after_rotation = wp_login(cfg, domain, "admin", password_a)

    pma_before_open = pma_ports(cfg)
    overview = api.request(
        "POST", f"/plugins/hosting/sites/{site_id}/phpmyadmin/session", {}
    )
    pma_url = str(overview["url"])
    pma_base = pma_url.split("?", 1)[0].rstrip("/")
    jar, _opener = wp_opener(cfg)
    exchange_status, _body, _ = api_get_with_cookie(api, pma_url, jar)
    pma_status, pma_body, _ = api_get_with_cookie(api, pma_base + "/", jar)
    pma_replay_status, _, _ = api_get_with_cookie(api, pma_url, jar)
    forbidden_status, _forbidden_body, _ = api_send_with_cookie(
        api,
        jar,
        "POST",
        pma_base + "/index.php",
        data=urllib.parse.urlencode(
            {
                "pma_username": "root",
                "pma_password": "not-allowed",
                "pma_servername": "127.0.0.1",
                "port": "3306",
            }
        ).encode(),
        content_type="application/x-www-form-urlencoded",
    )
    pma_during = pma_ports(cfg)
    close_status, _close_body, _ = api_send_with_cookie(
        api, jar, "DELETE", pma_base + "/session"
    )
    wait_pma_clean(cfg, timeout=90)
    pma_after = pma_ports(cfg)
    intruder_status, _payload, _headers = intruder.request(
        "POST",
        f"/plugins/hosting/sites/{site_id}/phpmyadmin/session",
        {},
        allow=(200, 403, 404),
        raw=True,
    )
    ev.record(
        "wordpress_surface",
        "Hosting API + WordPress HTTP + phpMyAdmin proxy",
        "config whitelist, DB no-store, users/salts, PMA session and WP-only guards",
        {
            "config_keys": sorted(config.get("editable_keys", []))[:5],
            "patched_debug": patched.get("editable_env", {}).get("WP_DEBUG"),
            "rejected_db_key_status": rejected_status,
            "db_no_store": db_headers.get("Cache-Control", ""),
            "database": database.get("database"),
            "users": len(users.get("users", [])),
            "explicit_generated": explicit.get("generated"),
            "explicit_login": explicit_login.get("ok"),
            "generated_has_password": bool(generated_password),
            "generated_login": generated_login.get("ok"),
            "salts": rotated.get("rotated"),
            "old_cookie_still_valid": cookie_after.get("ok"),
            "login_after_rotation": after_rotation.get("ok"),
            "pma_exchange_status": exchange_status,
            "pma_status": pma_status,
            "pma_db_visible": database.get("database", "").encode() in pma_body,
            "pma_replay_status": pma_replay_status,
            "pma_relogin_server_change_status": forbidden_status,
            "pma_close_status": close_status,
            "pma_before_open": pma_before_open,
            "pma_during": pma_during,
            "pma_after": pma_after,
            "intruder_pma_status": intruder_status,
        },
        passed=(
            patched.get("editable_env", {}).get("WP_DEBUG") == "false"
            and rejected_status == 422
            and str(db_headers.get("Cache-Control", "")).startswith("no-store")
            and explicit.get("generated") is False
            and explicit_login.get("ok") is True
            and bool(generated_password)
            and generated_login.get("ok") is True
            and bool(rotated.get("rotated"))
            and cookie_after.get("ok") is False
            and after_rotation.get("ok") is True
            and exchange_status in (200, 303)
            and pma_status == 200
            and database.get("database", "").encode() in pma_body
            and pma_replay_status != 200
            and forbidden_status == 403
            and close_status == 204
            and pma_before_open["listeners"] == 0
            and pma_during["listeners"] > 0
            and pma_after["listeners"] == 0
            and pma_after["connectors"] == 0
            and intruder_status in (403, 404)
        ),
        duration=time.monotonic() - started,
    )


def api_send_with_cookie(
    api: Api,
    jar: http.cookiejar.CookieJar,
    method: str,
    path: str,
    *,
    data: bytes | None = None,
    content_type: str | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    """Send a request with the PMA session cookie and the real API prefix."""
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), NoRedirect()
    )
    full_path = path if path.startswith(API_PREFIX) else API_PREFIX + path
    headers = {"Authorization": f"Bearer {api.token}"}
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(
        api.base + full_path, data=data, method=method, headers=headers
    )
    try:
        with opener.open(request, timeout=60) as response:
            return response.status, response.read(), dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers.items())


def api_get_with_cookie(
    api: Api, path: str, jar: http.cookiejar.CookieJar
) -> tuple[int, bytes, dict[str, str]]:
    return api_send_with_cookie(api, jar, "GET", path)


def invalidate_cookie(cfg: Config, domain: str, cookie: str) -> dict[str, Any]:
    if not cookie:
        return {"ok": False, "status": 0, "reason": "no cookie"}
    jar, opener = wp_opener(cfg)
    for part in cookie.split("; "):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        jar.set_cookie(
            http.cookiejar.Cookie(
                version=0, name=name, value=value, port=None, port_specified=False,
                domain=domain, domain_specified=False, domain_initial_dot=False,
                path="/", path_specified=True, secure=False, expires=None,
                discard=True, comment=None, comment_url=None, rest={"HttpOnly": None},
            )
        )
    status, body, _ = wp_request(cfg, opener, domain, "/wp-admin/")
    return {"ok": status == 200, "status": status, "bytes": len(body)}


def pma_ports(cfg: Config) -> dict[str, int]:
    def in_range(line: str, bounds: tuple[int, int]) -> bool:
        parts = line.split()
        if len(parts) < 4:
            return False
        try:
            port = int(parts[3].rsplit(":", 1)[1])
        except (IndexError, ValueError):
            return False
        return bounds[0] <= port <= bounds[1]

    lines = tcp_listeners()
    listeners = [
        line
        for line in lines
        if in_range(line, PMA_BROKER_RANGE)
        or in_range(line, PMA_CONNECTOR_RANGE)
    ]
    connectors = 0
    for slug in (cfg.slug, cfg.intruder_slug):
        result = cell_docker(
            cfg, slug, "ps", "-a", "--format", "{{.Names}}",
            "--filter", "label=spanel.role=pma-connector", check=False,
        )
        connectors += len([name for name in result.stdout.splitlines() if name])
    return {"listeners": len(listeners), "connectors": connectors}


def wait_pma_clean(cfg: Config, *, timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = pma_ports(cfg)
        if state["listeners"] == 0 and state["connectors"] == 0:
            return
        time.sleep(2)
    raise CheckFailed("phpMyAdmin relay/connector did not drain")


def check_static_profiles(cfg: Config, ev: Evidence, api: Api) -> None:
    started = time.monotonic()
    listed = api.request("GET", "/plugins/hosting/static-profiles")
    builtin = api.request("GET", "/plugins/hosting/static-profiles/nginx")
    profile_id = f"e2e{int(time.time()) % 100000}"
    created = api.request(
        "POST",
        "/plugins/hosting/static-profiles",
        {
            "id": profile_id,
            "name": "0110C profile",
            "image": "nginx:alpine",
            "web_root": "/usr/share/nginx/html",
            "container_port": 80,
            "health_mode": "marker",
        },
    )
    conflict = api.request(
        "POST",
        "/plugins/hosting/static-profiles",
        {
            "id": profile_id,
            "name": "duplicate",
            "image": "nginx:alpine",
            "web_root": "/usr/share/nginx/html",
        },
        allow=(201, 409, 422),
    )
    updated = api.request(
        "PUT",
        f"/plugins/hosting/static-profiles/{profile_id}",
        {"name": "0110C profile updated"},
    )
    deleted = api.request(
        "DELETE",
        f"/plugins/hosting/static-profiles/{profile_id}",
        allow=(204, 409),
    )
    guarded_status, guarded_body, _ = api.request(
        "DELETE", "/plugins/hosting/static-profiles/nginx", allow=(204, 409, 422), raw=True
    )
    builtin_after = api.request("GET", "/plugins/hosting/static-profiles/nginx")
    ev.record(
        "static_profiles",
        "Hosting static-profiles API",
        "builtin list/get, CRUD of a disposable profile, conflicts rejected, builtin guarded",
        {
            "profiles": [item.get("id") for item in listed.get("profiles", [])],
            "builtin": builtin.get("id"),
            "created": created.get("id"),
            "conflict": conflict,
            "updated_name": updated.get("name"),
            "deleted": True,
            "builtin_guard": {
                "status": guarded_status,
                "body": guarded_body[:160].decode(errors="replace"),
            },
            "builtin_after": builtin_after.get("id"),
        },
        passed=(
            builtin.get("id") == "nginx"
            and created.get("id") == profile_id
            and updated.get("name") == "0110C profile updated"
            and deleted is None
            and conflict is not None
            and guarded_status in (409, 422)
            and builtin_after.get("id") == "nginx"
        ),
        duration=time.monotonic() - started,
    )


def check_static_guards(
    cfg: Config, ev: Evidence, api: Api, site_id: str
) -> None:
    started = time.monotonic()
    results: dict[str, Any] = {}
    for name, method, path, body in (
        ("config", "GET", f"/plugins/hosting/sites/{site_id}/config", None),
        ("database", "POST", f"/plugins/hosting/sites/{site_id}/database", None),
        ("users", "GET", f"/plugins/hosting/sites/{site_id}/users", None),
        (
            "reset",
            "POST",
            f"/plugins/hosting/sites/{site_id}/users/1/password",
            {"password": "0110C-guard"},
        ),
        ("salts", "POST", f"/plugins/hosting/sites/{site_id}/secrets/salts", None),
        (
            "pma",
            "POST",
            f"/plugins/hosting/sites/{site_id}/phpmyadmin/session",
            {},
        ),
    ):
        status, payload, _headers = api.request(
            method, path, body, allow=(200, 403, 404, 409), raw=True
        )
        results[name] = {"status": status, "body": payload[:200].decode(errors="replace")}
    ev.record(
        "static_wordpress_only_guards",
        "Hosting API",
        "static site rejects WP config/database/users/salts/PMA with the contractual error",
        results,
        passed=all(
            item["status"] == 409 and "hosting_site_wrong_kind" in item["body"]
            for item in results.values()
        ),
        duration=time.monotonic() - started,
    )


def phase_exercise(cfg: Config, ev: Evidence, journal: Journal) -> None:
    admin = admin_login(cfg, ev.redactor)
    intruder = intruder_login(cfg, ev.redactor, journal.data)
    sites = _site_ids(journal)
    fixtures = journal.data["fixtures"]
    static = {
        "id": sites["static"],
        "domain": fixtures["sites"]["static"]["domain"],
        "container_name": fixtures["sites"]["static"]["container_name"],
    }
    wordpress = {
        "id": sites["wordpress"],
        "domain": fixtures["sites"]["wordpress"]["domain"],
        "container_name": fixtures["sites"]["wordpress"]["container_name"],
    }
    for site in (static, wordpress):
        if not site["domain"].endswith(cfg.domain_suffix):
            raise CheckFailed("fixture domain lost its ownership suffix")

    admin.me()
    check_auth_scope(cfg, ev, admin, intruder, wordpress["id"])
    for label, site in (("static", static), ("wordpress", wordpress)):
        check_lifecycle(cfg, ev, admin, label, site)
        check_logs(ev, admin, label, site["id"])
    check_file_manager(
        cfg, ev, admin, "static", static,
        hashlib.sha256(b"0110-C fixture static-A\n").hexdigest(),
    )
    check_file_manager(
        cfg, ev, admin, "wordpress", wordpress,
        hashlib.sha256(b"0110-C fixture wordpress-A\n").hexdigest(),
    )
    check_backup_static(cfg, ev, admin, static)
    backup = check_backup_wordpress(cfg, ev, admin, fixtures, wordpress)
    check_wordpress(
        cfg, ev, admin, intruder, wordpress, backup["password"]
    )
    check_static_profiles(cfg, ev, admin)
    check_static_guards(cfg, ev, admin, static["id"])

    # Rollback drill: real rollback, controlled failure and clean re-migration.
    rollback = cli_rootless(
        cfg, "rollback", "--site", static["id"],
        "--operation", fixtures["migration"]["static"]["operation_id"],
    )
    down_status = stop_agent(cfg, "edge-relay")
    try:
        failed = cli_rootless(cfg, "migrate", "--site", static["id"])
    finally:
        start_agent_relay(cfg)
    restored = external_probe(cfg, static["domain"], deadline=60)
    cleaned: dict[str, Any] = {}
    if failed.get("operation_id"):
        cleaned = cli_rootless(
            cfg, "rollback", "--site", static["id"],
            "--operation", failed["operation_id"],
        )
    remigrated = cli_rootless(cfg, "migrate", "--site", static["id"])
    ev.data["rollback"] = {
        "rollback_state": rollback.get("state"),
        "relay_stop": down_status,
        "failed_state": failed.get("state"),
        "failed_ok": failed.get("ok"),
        "rootful_http_status": restored.get("status"),
        "cleanup_state": cleaned.get("state"),
        "remigrate_state": remigrated.get("state"),
    }
    ev.record(
        "rollback_and_controlled_failure",
        "operator CLI 0110-A + public HTTP",
        "rollback restores rootful; a route failure auto-restores; re-migration retains",
        ev.data["rollback"],
        passed=(
            rollback.get("state") == "rolled_back"
            and failed.get("state") == "failed"
            and failed.get("ok") is False
            and restored.get("status") == 200
            and remigrated.get("state") == "retained"
        ),
    )

    # Finalize only after the full matrix and a valid backup.
    finalized = {}
    for label, site in (("static", static), ("wordpress", wordpress)):
        operation = (
            remigrated["operation_id"] if label == "static"
            else fixtures["migration"]["wordpress"]["operation_id"]
        )
        finalized[label] = cli_rootless(
            cfg, "finalize", "--site", site["id"],
            "--operation", operation,
            "--confirm-domain", site["domain"],
        )
    ev.data["finalize"] = {
        label: {
            "state": item.get("state"),
            "operation_id": item.get("operation_id"),
            "steps": item.get("steps"),
        }
        for label, item in finalized.items()
    }
    ev.record(
        "finalize",
        "operator CLI 0110-A",
        "explicit finalize removes the rootful originals and keeps rootless serving",
        ev.data["finalize"],
        passed=all(item.get("state") == "finalized" for item in finalized.values()),
    )
    for label, site in (("static", static), ("wordpress", wordpress)):
        after = external_probe(cfg, site["domain"], deadline=60)
        ev.record(
            f"after_finalize_{label}",
            "public HTTP",
            "site keeps serving after finalize",
            after.get("status"),
            passed=after.get("status") == 200,
        )
        fixtures["migration"][label]["operation_id"] = finalized[label].get(
            "operation_id"
        )
    journal.save()

    # The migrated fixtures stay alive until ``phase_attest`` has inspected
    # them; the new-rootless smoke test runs at the end of that phase.


def phase_new_rootless(cfg: Config, ev: Evidence, journal: Journal) -> None:
    """Fase 3: delete the migrated fixtures and recreate them already rootless."""
    admin = admin_login(cfg, ev.redactor)
    sites = journal.data["fixtures"]["sites"]
    for kind in ("static", "wordpress"):
        try:
            admin.delete_site(sites[kind]["id"])
        except ApiError as exc:
            if exc.status != 404:
                raise
    for kind, name, domain in (
        ("static", f"0110c-static-{cfg.slug}", cfg.primary_domain_static),
        ("wordpress", f"0110c-wp-{cfg.slug}", cfg.primary_domain_wp),
    ):
        created = create_fixture(
            cfg, admin, ev.redactor, kind=kind, name=name, domain=domain
        )
        site = created["site"]
        probe = external_probe(cfg, domain, deadline=90)
        fm_mkdir(admin, site["id"], "e2e")
        status, _ = fm_upload(
            admin, site["id"], "e2e", "new.txt", b"new rootless\n"
        )
        served = external_probe(cfg, domain, path="/e2e/new.txt", deadline=30)
        admin.delete_site(site["id"])
        gone = safe_probe(cfg, domain)
        ev.record(
            f"new_rootless_{kind}",
            "API create/delete + public HTTP",
            "with rootless enabled the same name/domain is born in the cell, serves, and deletes",
            {
                "site_id": site["id"],
                "create_http": probe.get("status"),
                "upload_status": status,
                "served": served.get("status"),
                "delete_http": gone.get("status"),
            },
            passed=(
                probe.get("status") == 200
                and status == 200
                and served.get("status") == 200
                and gone.get("status") != 200
            ),
        )


def stop_agent(cfg: Config, name: str) -> str:
    return stop_process(cfg, name)


def start_agent_relay(cfg: Config) -> None:
    relay_env = {
        **agent_env(cfg),
        "SPANEL_EDGE_RELAY_SOCKET": str(cfg.stage / "runtime" / "edge-relay.sock"),
        "SPANEL_TRAEFIK_UID": "1000",
    }
    start_process(
        cfg,
        "edge-relay",
        [
            sys.executable,
            str(cfg.stage / "scripts" / "spanel_tenant.py"),
            "edge-relay",
            "--data-root",
            str(cfg.stage / "relay-data"),
            "--bind",
            cfg.relay_bind,
        ],
        relay_env,
        uid=1000,
    )
    primary = allocation(cfg.slug)
    wait_listener(cfg.relay_bind, 40000 + int(primary["index"]))


# ---------------------------------------------------------------------------
# Fase: attest
# ---------------------------------------------------------------------------


def phase_attest(cfg: Config, ev: Evidence, journal: Journal) -> None:
    admin = admin_login(cfg, ev.redactor)
    sites = _site_ids(journal)
    tenant_id = str(admin.me().get("tenant_id") or journal.data["tenant"]["tenant_id"])
    inventory = admin.request(
        "GET", f"/plugins/tenant/tenants/{tenant_id}/resources"
    )
    runtimes = {
        item.get("resource_id"): item.get("runtime")
        for item in inventory.get("resources", [])
    }
    uid = int(allocation(cfg.slug)["uid"])
    limits = cgroup_limits(uid, slug=cfg.slug)
    pid_result = run(
        ["systemctl", "show", "-p", "MainPID", "--value", f"spanel-cell-{cfg.slug}"],
        check=False,
    )
    pid = pid_result.stdout.strip()
    uid_map = ""
    netns_differs = False
    if pid.isdigit() and int(pid) > 0:
        try:
            uid_map = Path(f"/proc/{pid}/uid_map").read_text(encoding="utf-8").strip()
            netns_differs = os.readlink(f"/proc/{pid}/ns/net") != os.readlink(
                "/proc/1/ns/net"
            )
        except OSError:
            pass
    docker_info = cell_docker(cfg, cfg.slug, "info", check=False)
    cell_ps = cell_docker(
        cfg, cfg.slug, "ps", "-a", "--format", "{{.Names}}", check=False
    )
    cell_names = {name for name in cell_ps.stdout.splitlines() if name}
    rootful_ps = docker(cfg, "ps", "-a", "--format", "{{.Names}}", check=False)
    rootful_names = set(rootful_ps.stdout.splitlines())
    labels: dict[str, dict[str, str]] = {}
    for kind in sites:
        container = journal.data["fixtures"]["sites"][kind]["container_name"]
        inspected = cell_docker(
            cfg, cfg.slug, "inspect", "-f", "{{json .Config.Labels}}", container,
            check=False,
        )
        try:
            labels[kind] = json.loads(inspected.stdout or "{}")
        except json.JSONDecodeError:
            labels[kind] = {}
    ingress = cell_docker(
        cfg, cfg.slug, "ps", "-a", "--format", "{{.Names}} {{json .Config.Labels}}",
        "--filter", "label=spanel.role=cell-infra", check=False,
    )
    ingress_text = ingress.stdout.strip()
    ingress_ok = (
        "spanel-cell-ingress" in ingress_text
        and '"spanel.role":"cell-infra"' in ingress_text
    )
    scope = str(limits.get("scope", ""))
    cgroup_scope_ok = (
        f"tenant-{cfg.slug}.slice" in scope
        or (f"user-{uid}.slice" in scope and f"user@{uid}.service" in scope)
        or all(
            part in scope
            for part in (
                f"user-{uid}.slice",
                f"user@{uid}.service",
                f"spanel-cell-{cfg.slug}.scope",
            )
        )
    )
    db_published = cell_docker(
        cfg, cfg.slug, "ps", "--format", "{{.Names}} {{.Ports}}",
        check=False,
    )
    shadow = sorted(
        name
        for name in rootful_names
        if any(
            journal.data["fixtures"]["sites"][kind]["container_name"] == name
            for kind in ("static", "wordpress")
        )
    )
    relay_needle = f":{40000 + int(allocation(cfg.slug)['index'])}"
    edge_relay_listening = any(relay_needle in line for line in tcp_listeners())
    hosts = [
        external_probe(cfg, cfg.primary_domain_static, deadline=30).get("status"),
        external_probe(cfg, cfg.primary_domain_wp, deadline=30).get("status"),
    ]
    core_after = core_snapshot(cfg)
    other_after = other_tenant_snapshot(cfg)
    expected_db_ports = [
        line for line in db_published.stdout.splitlines() if "0.0.0.0:3306" in line
    ]
    attestation = {
        "inventory_runtimes": runtimes,
        "cell_socket": f"/var/lib/spanel/cells/{cfg.slug}/docker.sock",
        "docker_info_rootless": "rootless" in (docker_info.stdout + docker_info.stderr).lower(),
        "cell_containers": sorted(cell_names),
        "labels": labels,
        "ingress": ingress_text,
        "ingress_ok": ingress_ok,
        "edge_relay_listening": edge_relay_listening,
        "cgroup_scope": scope,
        "cgroup_scope_ok": cgroup_scope_ok,
        "dockerd_pid": pid,
        "uid_map": uid_map,
        "uid_map_non_identity": is_non_identity_uid_map(uid_map),
        "netns_differs": netns_differs,
        "cgroup_limits": limits,
        "db_ports_published": expected_db_ports,
        "rootful_shadow": shadow,
        "hosts_http": hosts,
        "core_unchanged": core_after == ev.data["baseline"].get("core"),
        "second_tenant_unchanged": other_after
        == ev.data["baseline"].get("other_tenants"),
        "core_after": core_after,
        "second_tenant_after": other_after,
    }
    ev.data["runtime_attestation"] = attestation
    site_containers = {
        journal.data["fixtures"]["sites"][kind]["container_name"] for kind in sites
    }
    ev.record(
        "runtime_attestation",
        "host observation (docker/cgroups/proc/inventory)",
        "runtime=rootless for both sites, real non-identity uid_map, distinct netns, "
        "cgroup plan, exact labels, no rootful shadow, one endpoint, no DB port",
        attestation,
        passed=(
            runtimes.get(sites["static"]) == "rootless"
            and runtimes.get(sites["wordpress"]) == "rootless"
            and attestation["docker_info_rootless"]
            and site_containers.issubset(cell_names)
            and not (site_containers & rootful_names)
            and all(
                labels.get(kind, {}).get("spanel.tenant")
                and labels.get(kind, {}).get("spanel.site") == sites[kind]
                and labels.get(kind, {}).get("spanel.managed") == "true"
                for kind in sites
            )
            and attestation["uid_map_non_identity"]
            and netns_differs
            and limits.get("memory.max") == str(MEMORY_PLAN)
            and limits.get("pids.max") == str(PIDS_PLAN)
            and ingress_ok
            and edge_relay_listening
            and cgroup_scope_ok
            and not expected_db_ports
            and not shadow
            and hosts == [200, 200]
            and attestation["core_unchanged"]
            and attestation["second_tenant_unchanged"]
        ),
    )
    since = float(journal.data.get("deny_since", time.time()))
    delta = deny_count(cfg.slug, since) + deny_count(cfg.intruder_slug, since)
    ev.data["delta_denied"] = delta
    ev.record(
        "delta_denied_zero",
        "kernel audit journalctl -k",
        "no new DENIED/EPERM for either disposable cell",
        {"since": since, "delta_denied": delta},
        passed=delta == 0,
    )
    db_now = tcp_listeners(3306)
    ev.record(
        "no_permanent_db_port",
        "host ss -ltn",
        "no new 3306 listener beyond the pre-run baseline",
        {"before": ev.data["baseline"].get("db_3306"), "after": db_now},
        passed=db_now == ev.data["baseline"].get("db_3306"),
    )
    phase_new_rootless(cfg, ev, journal)


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


def route_documents(cfg: Config) -> list[Path]:
    domains = (
        cfg.primary_domain_wp,
        cfg.primary_domain_static,
        cfg.intruder_domain,
        f"wp-{cfg.slug}.{cfg.domain_suffix}",
    )
    found: list[Path] = []
    if not cfg.dynamic_dir.is_dir():
        return found
    for path in cfg.dynamic_dir.glob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(domain in text for domain in domains) or cfg.slug in path.name:
            found.append(path)
    return found


def cleanup(
    cfg: Config, ev: Evidence, journal: Journal, *, api: Api | None = None
) -> None:
    errors: list[str] = []
    result: dict[str, Any] = {"errors": errors}
    # 1. Close API-side resources while the disposable API still exists.
    if api is not None:
        fixtures = journal.data.get("fixtures", {}).get("sites", {})
        for kind, site in fixtures.items():
            try:
                api.delete_site(site["id"])
                result.setdefault("deleted_sites", []).append(site["id"])
            except ApiError as exc:
                if exc.status == 404:
                    result.setdefault("already_deleted", []).append(site["id"])
                else:
                    message = f"{kind}: {exc}"
                    result.setdefault("delete_errors", []).append(message)
                    errors.append(f"site deletion failed: {message}")
            except Exception as exc:  # noqa: BLE001 - cleanup evidence survives
                message = f"{kind}: {exc}"
                result.setdefault("delete_errors", []).append(message)
                errors.append(f"site deletion failed: {message}")
    # 2. Agents and disposable containers.
    for name in ("plan-agent", "edge-relay"):
        result[f"stop_{name}"] = stop_process(cfg, name)
    for name in (cfg.app, cfg.worker, cfg.redis):
        docker(cfg, "rm", "-f", name, check=False)
    # 3. Only routes that name our exact fixture domains.
    removed_routes = []
    for path in route_documents(cfg):
        try:
            path.unlink()
            removed_routes.append(str(path))
        except OSError as exc:
            errors.append(f"route {path}: {exc}")
    result["removed_routes"] = removed_routes
    remove_stale_fixtures(cfg, ev)
    # Any container still labelled with one of our site ids was not reclaimed.
    shadow: list[str] = []
    for site in journal.data.get("fixtures", {}).get("sites", {}).values():
        found = docker(
            cfg, "ps", "-a", "--format", "{{.Names}}",
            "--filter", f"label=spanel.site={site['id']}", check=False,
        )
        shadow.extend(name for name in found.stdout.splitlines() if name)
    result["fixture_containers_left"] = sorted(set(shadow))
    if shadow:
        errors.append(f"fixture containers remain: {sorted(set(shadow))}")
    # Rootful originals keep their env/secrets under the sites directory.
    removed_site_dirs: list[str] = []
    sites_root = Path(cfg.sites_dir)
    if sites_root.is_dir():
        for path in sites_root.iterdir():
            if cfg.slug in path.name:
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink(missing_ok=True)
                removed_site_dirs.append(str(path))
    result["removed_site_dirs"] = removed_site_dirs
    # 4. Cells.
    for slug in (cfg.intruder_slug, cfg.slug):
        try:
            deprovision_cell(cfg, slug)
            result.setdefault("removed_leftovers", []).extend(
                remove_cell_leftovers(slug)
            )
            if cell_uid(slug) is not None:
                run(["userdel", f"spanel-{slug}"], check=False)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"deprovision {slug}: {exc}")
    # 5. Cloned database.
    try:
        clone_psql_drop(cfg)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"database drop: {exc}")
    # 6. State files return to their byte-for-byte pre-run value.
    backup = cfg.stage / "backup"
    restored: dict[str, str] = {}
    expected: dict[str, str] = {}
    for item in STATE_FILES:
        source = backup / Path(item).name
        if not source.exists():
            continue
        target = Path(item)
        try:
            shutil.copy2(source, target)
            restored[item] = hashlib.sha256(target.read_bytes()).hexdigest()
            expected[item] = hashlib.sha256(source.read_bytes()).hexdigest()
        except OSError as exc:
            errors.append(f"state {item}: {exc}")
    result["state_restored"] = bool(expected) and restored == expected
    if not result["state_restored"]:
        errors.append("state files were not restored byte-for-byte")
    # 7. Disposable secrets.
    for name in (
        "app.env", "plan_agent_token", "dispatch_outbox.py", "downgrade_005.py",
        "kernel_migrate.py",
    ):
        (cfg.stage / name).unlink(missing_ok=True)
    for rel in (
        "state", "backup", "runtime", "relay-data", "proxy-backups", "backups", "pylibs",
    ):
        shutil.rmtree(cfg.stage / rel, ignore_errors=True)
    result["core"] = {
        "before": ev.data["baseline"].get("core"),
        "after": core_snapshot(cfg),
    }
    result["core_unchanged"] = result["core"]["before"] == result["core"]["after"]
    result["other_tenants"] = {
        "before": ev.data["baseline"].get("other_tenants"),
        "after": other_tenant_snapshot(cfg),
    }
    result["other_tenants_unchanged"] = (
        result["other_tenants"]["before"] == result["other_tenants"]["after"]
    )
    if not result["core_unchanged"]:
        errors.append("Core changed during the ceremony")
    if not result["other_tenants_unchanged"]:
        errors.append("another tenant changed during the ceremony")
    result["leftovers"] = run(
        [
            "bash", "-lc",
            (
                f"ls -d /var/lib/spanel/cells/{cfg.slug} "
                f"/var/lib/spanel/cells/{cfg.intruder_slug} "
                f"/home/spanel-{cfg.slug} /home/spanel-{cfg.intruder_slug} "
                "2>/dev/null || true"
            ),
        ],
        check=False,
    ).stdout.strip()
    if result["leftovers"]:
        errors.append(f"cell leftovers remain: {result['leftovers']}")
    ev.data["cleanup"] = result
    ev.data["cleanup_verified"] = not errors
    if errors:
        ev.data["gaps"].append(
            {
                "id": "CLEANUP",
                "severity": "high",
                "title": "cleanup no devolvió el host al baseline",
                "evidence": errors[:10],
            }
        )


def clone_psql_drop(cfg: Config) -> None:
    run(
        [
            "docker", "exec", cfg.live_pg, "psql", "-U", "postgres", "-d",
            cfg.live_db, "-v", "ON_ERROR_STOP=1", "-c",
            f'DROP DATABASE IF EXISTS "{cfg.db}" WITH (FORCE);',
        ],
        timeout=300,
        check=True,
    )


# ---------------------------------------------------------------------------
# Informe y punto de entrada
# ---------------------------------------------------------------------------


def write_report(cfg: Config, ev: Evidence) -> None:
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    data = ev.data
    lines = [
        "# 0110-C — Informe de cierre de tenants",
        "",
        f"- Resultado: **{data['result']}**",
        f"- `ok`: `{str(data['ok']).lower()}`",
        f"- Fecha: {data.get('finished_at') or now()}",
        f"- Commit: `{data.get('environment', {}).get('commit', 'desconocido')}`",
        f"- Delta DENIED: `{data.get('delta_denied')}`",
        f"- Cleanup verificado: `{str(data.get('cleanup_verified')).lower()}`",
        "",
        "## Checks",
        "",
        "| id | surface | pass |",
        "|---|---|---|",
    ]
    for check in data.get("checks", []):
        lines.append(
            f"| `{check.get('id')}` | {check.get('surface')} | "
            f"{'PASS' if check.get('pass') else 'FAIL'} |"
        )
    lines += ["", "## Gaps", ""]
    if data.get("gaps"):
        for gap in data["gaps"]:
            lines.append(f"- `{gap.get('id')}`: {gap.get('title')}")
    else:
        lines.append("- Ninguno.")
    lines += ["", "## Cleanup", ""]
    lines.append(json.dumps(data.get("cleanup", {}), indent=2, default=str)[:6000])
    lines += [
        "",
        (
            "> Este informe solo acredita el cierre cuando `result=PASS`, `ok=true`, "
            "`gaps=[]`, `delta_denied=0` y `cleanup_verified=true`."
        ),
        "",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def _install_signal_handlers() -> None:
    def handler(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, default=DEFAULT_STAGE)
    parser.add_argument("--slug", default=DEFAULT_SLUG)
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument(
        "--phase",
        choices=("preflight", "setup", "seed", "exercise", "attest", "cleanup", "all"),
        default="all",
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--keep-on-failure", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    cfg = Config(
        stage=args.stage,
        slug=args.slug,
        evidence_path=args.evidence,
        phase=args.phase,
        resume=args.resume,
        keep_on_failure=args.keep_on_failure,
        json_output=args.json,
    )
    _install_signal_handlers()
    phase_order = ("preflight", "setup", "seed", "exercise", "attest", "cleanup")
    redactor = Redactor()
    ev = Evidence(cfg, redactor)
    journal = Journal(cfg.stage / "state.json")
    blocked = False
    failed = False
    cleanup_done = False
    api: Api | None = None
    try:
        if cfg.resume:
            journal.load()
            journal.validate_identity(cfg.ownership)
            if isinstance(journal.data.get("evidence"), dict):
                ev.data = journal.data["evidence"]
            check_count, gap_count = journal.last_completed_counts(phase_order)
            ev.data["checks"] = list(ev.data.get("checks", []))[:check_count]
            ev.data["gaps"] = list(ev.data.get("gaps", []))[:gap_count]
            log(
                "resuming journal from "
                f"{check_count} checks / {gap_count} gaps of completed phases"
            )
        else:
            if (
                cfg.stage.exists()
                and any(cfg.stage.iterdir())
                and (cfg.stage / "state.json").exists()
            ):
                raise Precondition(
                    "stage already has a journal; use --resume or a clean --stage"
                )
            journal.data = {"identity": cfg.ownership, "phases": {}}
            journal.save()
        identity = dict(cfg.ownership)
        journal.data["identity"] = identity
        journal.save()

        phases = (
            ["preflight", "setup", "seed", "exercise", "attest"]
            if cfg.phase == "all"
            else ["cleanup"] if cfg.phase == "cleanup" else [cfg.phase]
        )
        for phase in phases:
            if cfg.resume and journal.done(phase):
                log(f"skipping completed phase {phase}")
                continue
            if cfg.resume and phase in {"seed", "exercise", "attest"}:
                journal.validate_identity(identity)
            log(f"phase {phase}")
            if phase == "preflight":
                phase_preflight(cfg, ev, journal)
            elif phase == "setup":
                phase_setup(cfg, ev, journal)
            elif phase == "seed":
                phase_seed(cfg, ev, journal)
            elif phase == "exercise":
                phase_exercise(cfg, ev, journal)
            elif phase == "attest":
                phase_attest(cfg, ev, journal)
            elif phase == "cleanup":
                api = _safe_api(cfg, redactor)
                cleanup(cfg, ev, journal, api=api)
                cleanup_done = True
            journal.mark(
                phase,
                {
                    "check_count": len(ev.data.get("checks", [])),
                    "gap_count": len(ev.data.get("gaps", [])),
                },
            )
            journal.data["evidence"] = ev.data
            journal.save()
    except Precondition as exc:
        blocked = True
        ev.data["gaps"].append(
            {"id": "PRECONDITION", "severity": "high", "title": str(exc)}
        )
        ev.record("precondition", "host", "lab is ready", str(exc), passed=False)
    except KeyboardInterrupt as exc:
        failed = True
        ev.data["gaps"].append(
            {"id": "SIGNAL", "severity": "high", "title": f"interrupted: {exc}"}
        )
    except Exception as exc:  # noqa: BLE001 - honest FAIL evidence
        failed = True
        ev.data["gaps"].append(
            {
                "id": "EXCEPTION",
                "severity": "high",
                "title": f"{type(exc).__name__}: {exc}",
                "evidence": traceback.format_exc()[-2000:],
            }
        )
    finally:
        should_cleanup = cfg.phase in {"all", "cleanup"} and not (
            (failed or blocked) and cfg.keep_on_failure
        )
        if should_cleanup and not cleanup_done:
            try:
                api = api or _safe_api(cfg, redactor)
                cleanup(cfg, ev, journal, api=api)
                cleanup_done = True
            except Exception as exc:  # noqa: BLE001
                ev.data["cleanup"] = {"fatal": str(exc)[:800]}
                ev.data["cleanup_verified"] = False
        since = journal.data.get("deny_since")
        if since is not None and ev.data.get("delta_denied") == 0:
            try:
                ev.data["delta_denied"] = deny_count(cfg.slug, float(since)) + deny_count(
                    cfg.intruder_slug, float(since)
                )
            except Exception as exc:  # noqa: BLE001 - preflight validated it
                log(f"delta_denied could not be refreshed: {exc}")
        if cfg.phase == "all":
            for key in ("rollback", "finalize"):
                if not ev.data.get(key):
                    ev.data["gaps"].append(
                        {
                            "id": f"MISSING_{key.upper()}",
                            "severity": "high",
                            "title": f"{key} was not demonstrated",
                        }
                    )
        ev.data["result"] = evaluate_result(
            checks=ev.data.get("checks", []),
            gaps=ev.data.get("gaps", []),
            delta_denied=int(ev.data.get("delta_denied") or 0),
            cleanup_verified=bool(ev.data.get("cleanup_verified")),
            blocked=blocked,
            keep_on_failure=cfg.keep_on_failure and (failed or blocked),
            required_ids=REQUIRED_CHECKS,
        )
        ev.data["ok"] = ev.data["result"] == "PASS"
        ev.data["finished_at"] = now()
        ev.data = redactor.value(ev.data)
        try:
            journal.data["evidence"] = ev.data
            journal.save()
        except Exception as exc:  # noqa: BLE001 - evidence is source of truth
            log(f"journal could not be persisted: {exc}")
        cfg.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        cfg.evidence_path.write_text(
            json.dumps(ev.data, indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
        )
        cfg.evidence_path.chmod(0o600)
        if cfg.phase == "all":
            write_report(cfg, ev)
        summary = {
            "result": ev.data["result"],
            "ok": ev.data["ok"],
            "checks": len(ev.data.get("checks", [])),
            "gaps": len(ev.data.get("gaps", [])),
            "cleanup_verified": ev.data.get("cleanup_verified", False),
            "evidence": str(cfg.evidence_path),
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
    if ev.data["result"] == "PASS":
        return 0
    if blocked:
        return 2
    if ev.data.get("checks") and all(
        check.get("pass") for check in ev.data.get("checks", [])
    ) and not ev.data.get("cleanup_verified"):
        return 3
    return 1


def _safe_api(cfg: Config, redactor: Redactor) -> Api | None:
    try:
        return admin_login(cfg, redactor)
    except Exception:  # noqa: BLE001 - cleanup continues without the API
        return None


if __name__ == "__main__":
    raise SystemExit(main())

