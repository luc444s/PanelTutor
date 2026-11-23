#!/usr/bin/env python3
"""One-run Hosting migration from rootful Docker to rootless tenant cells.

The tool orchestrates the already-tested operator CLIs instead of
reimplementing their safety rules:

* ``scripts/spanel_tenant.py`` (host, root): doctor, provision, plan
  apply/verify and the rootless cell itself.
* ``scripts/hosting_migrate_rootless.py`` (app container): plan, migrate,
  status, finalize and rollback of every Hosting site of one tenant.

The default flow is:

    preflight + agent install -> provision cell -> apply resource plan ->
    plan sites -> migrate sites -> (optional) Apps -> (optional) finalize ->
    report

Every phase is idempotent, so a failed run can be executed again. The default
end state is ``retained``: the rootless site is serving traffic and the
rootful container is kept stopped with a verified recovery backup, so
``rollback`` is still possible. ``--finalize`` removes the rootful copy after
the migration.

Apps are migrated by re-deploying their signed active release through the Apps
API; the worker selects the tenant's rootless cell. Apps without a signed
release need an explicit harden first and are reported, never guessed.

``--storage`` is a *declared* limit (A.SPEC 0111), not a filesystem quota: the
script validates it against the host's free space and includes it in the plan
summary, but the enforced value must still be saved from the Resources tab
(Apps plan API), which is the source of truth.

Examples::

    # Interactive wizard on the host
    sudo ./scripts/spanel-migrator-to-rootless

    # Non-interactive, migrate every site and keep rollback available
    sudo ./scripts/spanel-migrator-to-rootless --tenant demo \\
        --memory 1G --cpus 1.5 --pids 512 --storage 10G --yes

    # Preview only (no host mutation)
    sudo ./scripts/spanel-migrator-to-rootless --tenant demo --dry-run

Exit codes: 0 ok, 1 a phase failed, 2 usage or preflight refused.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TENANT_SCRIPT = ROOT / "scripts" / "spanel_tenant.py"
HOSTING_SCRIPT = ROOT / "scripts" / "hosting_migrate_rootless.py"
AGENTS_SCRIPT = ROOT / "scripts" / "install_tenant_agents.py"
APPS_SCRIPT = ROOT / "scripts" / "migrate_tenant_apps.py"
DEFAULT_DATA_ROOT = "/var/lib/spanel"
DEFAULT_APP_CONTAINER = "spanel-app-1"
CONTAINER_ROOT = "/app"
CONTAINER_SCRIPT_DIR = "/tmp/spanel-migrator"
DEFAULT_UNITS = ("spanel-plan-agent.service", "spanel-edge-relay.service")
AGENT_SOCKET = Path("/run/spanel/plan-agent.sock")
RELAY_SOCKET = Path("/run/spanel/edge-relay.sock")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,61}$")
SIZE_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([KMGTPE]?)(?:i?B)?$", re.IGNORECASE)
SIZE_MULT = {
    "": 1,
    "K": 1024,
    "M": 1024**2,
    "G": 1024**3,
    "T": 1024**4,
    "P": 1024**5,
    "E": 1024**6,
}
KINDS = ("static", "wordpress")


class MigratorError(RuntimeError):
    """A failure already explained to the operator."""


class UsageError(MigratorError):
    """Invalid flags or missing values in non-interactive mode."""


class PreflightError(MigratorError):
    """The host is not ready and must not be mutated."""


class OperatorError(MigratorError):
    """An operator CLI failed or returned an unusable payload."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def parse_size(value: str | int, *, what: str) -> int:
    """Parse ``512M``, ``1.5G``, ``10GiB`` or a plain byte count."""
    if isinstance(value, bool):
        raise UsageError(f"{what} must be a positive size")
    if isinstance(value, int):
        if value <= 0:
            raise UsageError(f"{what} must be > 0")
        return value
    text = str(value).strip()
    match = SIZE_RE.fullmatch(text)
    if match is None or float(match.group(1)) <= 0:
        raise UsageError(f"invalid {what}: {value!r} (use e.g. 512M or 10G)")
    number = float(match.group(1))
    return int(number * SIZE_MULT[match.group(2).upper()])


def human_size(value: int) -> str:
    number = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if number < 1024 or unit == "PiB":
            if unit == "B":
                return f"{int(number)}B"
            return f"{number:.1f}{unit}"
        number /= 1024
    return f"{value}B"


def nearest_existing(path: Path) -> Path:
    for candidate in (path, *path.parents):
        if candidate.exists():
            return candidate
    return Path("/")


def load_env_file(path: Path) -> dict[str, str]:
    """Read ``KEY=VALUE`` without executing or expanding anything."""
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def last_json_object(text: str) -> dict[str, Any] | None:
    """Return the last JSON object printed by an operator CLI."""
    for line in reversed(text.strip().splitlines()):
        candidate = line.strip()
        if not candidate.startswith("{"):
            continue
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def redact(value: Any) -> Any:
    """Keep evidence readable: no command output is expected to contain secrets."""
    if isinstance(value, dict):
        return {
            key: redact(item)
            for key, item in value.items()
            if key.lower() not in {"password", "token", "secret", "api_key"}
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str) and len(value) > 4000:
        return value[:4000] + "…"
    return value


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------


class Console:
    """Minimal console that keeps stdout valid JSON when ``--json`` is used."""

    def __init__(self, *, json_mode: bool = False, interactive: bool = False) -> None:
        self.json_mode = json_mode
        self.interactive = interactive
        self.out = sys.stderr if json_mode else sys.stdout

    def step(self, message: str) -> None:
        print(f"\n== {message}", file=self.out)

    def info(self, message: str) -> None:
        print(f"   {message}", file=self.out)

    def ok(self, message: str) -> None:
        print(f"   OK  {message}", file=self.out)

    def warn(self, message: str) -> None:
        print(f"   !!  {message}", file=self.out)

    def fail(self, message: str) -> None:
        print(f"   XX  {message}", file=self.out)

    def ask(self, label: str, default: str | None = None) -> str:
        if not self.interactive:
            raise UsageError(f"{label} is required in non-interactive mode")
        suffix = f" [{default}]" if default else ""
        answer = input(f"{label}{suffix}: ").strip()
        return answer or (default or "")

    def confirm(self, question: str, *, default: bool = False) -> bool:
        if not self.interactive:
            return True
        hint = "Y/n" if default else "y/N"
        answer = input(f"{question} [{hint}]: ").strip().lower()
        if not answer:
            return default
        return answer in {"y", "yes", "s", "si", "sí"}


# ---------------------------------------------------------------------------
# Operator adapter: reuses the existing CLIs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommandOutput:
    returncode: int
    stdout: str = ""
    stderr: str = ""


Runner = Callable[[list[str], dict[str, str], int], CommandOutput]


def default_runner(argv: list[str], env: dict[str, str], timeout: int) -> CommandOutput:
    try:
        completed = subprocess.run(
            argv,
            env=env,
            timeout=timeout,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        return CommandOutput(127, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return CommandOutput(124, stdout, f"timeout after {timeout}s: {stderr}")
    return CommandOutput(completed.returncode, completed.stdout, completed.stderr)


class Operator:
    """Thin, testable wrapper around the two operator CLIs and the host."""

    def __init__(
        self,
        *,
        root: Path = ROOT,
        data_root: str = DEFAULT_DATA_ROOT,
        app_container: str = DEFAULT_APP_CONTAINER,
        hosting_mode: str = "auto",
        env_file: Path | None = None,
        runner: Runner | None = None,
        python: str | None = None,
    ) -> None:
        self.root = root
        self.data_root = Path(data_root)
        self.app_container = app_container
        self.hosting_mode = hosting_mode
        self.env_file = env_file
        self.runner = runner or default_runner
        venv_python = root / ".venv" / "bin" / "python"
        self.python = (
            python
            or os.environ.get("SPANEL_PYTHON")
            or (str(venv_python) if venv_python.is_file() else sys.executable)
        )
        self._container_prepared = False
        self._resolved_mode: str | None = (
            hosting_mode if hosting_mode in {"local", "container"} else None
        )

    # -- process plumbing ---------------------------------------------------

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        # A.SPEC 0102: the host CLI must be explicitly allowed to mutate.
        env.setdefault("SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS", "1")
        if self.env_file is not None and self.env_file.is_file():
            for key, value in load_env_file(self.env_file).items():
                env.setdefault(key, value)
        return env

    def _run(self, argv: Sequence[str], *, timeout: int) -> CommandOutput:
        return self.runner(list(argv), self._env(), timeout)

    def _payload(
        self, output: CommandOutput, argv: Sequence[str], *, label: str
    ) -> dict[str, Any]:
        payload = last_json_object(output.stdout)
        if payload is None:
            detail = (output.stderr or output.stdout).strip()[-600:]
            raise OperatorError(
                f"{label} returned no JSON (rc={output.returncode}): {detail}"
            )
        if output.returncode != 0 and not payload.get("error"):
            payload = {**payload, "ok": False, "error": payload.get("error")}
        payload.setdefault(
            "_command", " ".join(argv[:4]) + (" …" if len(argv) > 4 else "")
        )
        return payload

    # -- tenant CLI (host) --------------------------------------------------

    def tenant(self, *args: str, timeout: int = 120) -> dict[str, Any]:
        argv = [self.python, str(self.root / "scripts" / "spanel_tenant.py")]
        argv.extend(args)
        argv.append("--json")
        return self._payload(self._run(argv, timeout=timeout), argv, label="tenant CLI")

    # -- hosting CLI (app container or local) -------------------------------

    def _container_running(self) -> bool:
        output = self._run(
            ["docker", "inspect", "-f", "{{.State.Running}}", self.app_container],
            timeout=20,
        )
        return output.returncode == 0 and output.stdout.strip() == "true"

    def hosting_mode_effective(self) -> str:
        if self._resolved_mode is not None:
            return self._resolved_mode
        inside = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
        if inside:
            self._resolved_mode = "local"
        elif shutil.which("docker") and self._container_running():
            self._resolved_mode = "container"
        else:
            self._resolved_mode = "local"
        return self._resolved_mode

    def _prepare_container_script(self) -> None:
        if self._container_prepared:
            return
        target = (
            f"{self.app_container}:{CONTAINER_SCRIPT_DIR}/hosting_migrate_rootless.py"
        )
        mkdir = self._run(
            ["docker", "exec", self.app_container, "mkdir", "-p", CONTAINER_SCRIPT_DIR],
            timeout=30,
        )
        if mkdir.returncode != 0:
            raise OperatorError(
                "cannot prepare the app container: "
                + (mkdir.stderr or mkdir.stdout).strip()[:400]
            )
        copied = self._run(
            [
                "docker",
                "cp",
                str(self.root / "scripts" / "hosting_migrate_rootless.py"),
                target,
            ],
            timeout=60,
        )
        if copied.returncode != 0:
            raise OperatorError(
                "cannot copy the hosting CLI into the app container: "
                + (copied.stderr or copied.stdout).strip()[:400]
            )
        self._container_prepared = True

    def hosting(self, *args: str, timeout: int = 1800) -> dict[str, Any]:
        mode = self.hosting_mode_effective()
        if mode == "container":
            self._prepare_container_script()
            argv = [
                "docker",
                "exec",
                "-e",
                f"PYTHONPATH={CONTAINER_ROOT}:{CONTAINER_ROOT}/vendor/systutor-core",
                "-e",
                f"SYSTUTOR_PLUGINS_DIR={CONTAINER_ROOT}/plugins",
                "-e",
                "PYTHONUNBUFFERED=1",
                self.app_container,
                "python",
                f"{CONTAINER_SCRIPT_DIR}/hosting_migrate_rootless.py",
            ]
        else:
            argv = [
                self.python,
                str(self.root / "scripts" / "hosting_migrate_rootless.py"),
            ]
        argv.extend(args)
        argv.append("--json")
        return self._payload(
            self._run(argv, timeout=timeout), argv, label="hosting CLI"
        )

    # -- system / host reads ------------------------------------------------

    def service_active(self, unit: str) -> bool:
        output = self._run(["systemctl", "is-active", unit], timeout=15)
        return output.stdout.strip() == "active"

    def unit_loaded(self, unit: str) -> bool:
        output = self._run(
            ["systemctl", "show", "-p", "LoadState", "--value", unit], timeout=15
        )
        return output.returncode == 0 and output.stdout.strip() == "loaded"

    def start_service(self, unit: str) -> None:
        output = self._run(["systemctl", "start", unit], timeout=90)
        if output.returncode != 0:
            detail = (output.stderr or output.stdout).strip()[-400:]
            raise PreflightError(f"cannot start {unit}: {detail}")

    def capacity(self) -> dict[str, Any]:
        memory = 0
        meminfo = Path("/proc/meminfo")
        if meminfo.is_file():
            for raw in meminfo.read_text(encoding="utf-8").splitlines():
                if raw.startswith("MemTotal:"):
                    memory = int(raw.split()[1]) * 1024
                    break
        stat = os.statvfs(str(nearest_existing(self.data_root)))
        return {
            "memory_bytes": memory,
            "cpus": float(os.cpu_count() or 0),
            "storage_bytes": int(stat.f_blocks) * int(stat.f_frsize),
            "storage_available_bytes": int(stat.f_bavail) * int(stat.f_frsize),
        }

    # -- orchestration helpers ----------------------------------------------

    def provision(
        self,
        slug: str,
        *,
        dry_run: bool = False,
        timeout: float = 240.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> dict[str, Any]:
        if dry_run:
            return self.tenant("provision", "--slug", slug, "--dry-run", timeout=120)
        deadline = time.monotonic() + timeout
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            last = self.tenant("provision", "--slug", slug, timeout=600)
            if last.get("state") == "ready" and self.cell_socket(slug).exists():
                return last
            if last.get("error"):
                raise PreflightError(f"provision refused: {last.get('error')}")
            sleep(3)
        raise PreflightError(
            f"cell {slug} did not become ready in {int(timeout)}s: {last}"
        )

    def cell_socket(self, slug: str) -> Path:
        return self.data_root / "cells" / slug / "docker.sock"

    def plan_show(self, slug: str) -> dict[str, Any] | None:
        try:
            payload = self.tenant("plan", "show", "--slug", slug, timeout=60)
        except OperatorError:
            return None
        if payload.get("error") or not payload.get("plan"):
            return None
        return payload

    def plan_apply(
        self,
        slug: str,
        *,
        memory: str,
        cpus: float,
        pids: int,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        args = [
            "plan",
            "apply",
            "--slug",
            slug,
            "--memory",
            memory,
            "--cpus",
            str(cpus),
            "--pids",
            str(pids),
        ]
        if dry_run:
            args.append("--dry-run")
        return self.tenant(*args, timeout=180)

    def plan_verify(self, slug: str) -> dict[str, Any]:
        return self.tenant("plan", "verify", "--slug", slug, timeout=180)

    def hosting_sites(
        self, tenant: str, kinds: Sequence[str], site_ids: Sequence[str] = ()
    ) -> list[dict[str, Any]]:
        if site_ids:
            return [
                self.hosting("plan", "--site", site_id, timeout=300)
                for site_id in site_ids
            ]
        args = ["plan", "--tenant", tenant, "--all"]
        if len(kinds) == 1:
            args.extend(["--kind", kinds[0]])
        payload = self.hosting(*args, timeout=300)
        results = payload.get("results")
        if not isinstance(results, list):
            return [payload]
        return [item for item in results if isinstance(item, dict)]

    def hosting_migrate(
        self, site_id: str, *, shared_db: str | None = None
    ) -> dict[str, Any]:
        args = ["migrate", "--site", site_id]
        if shared_db:
            args.extend(["--shared-db", shared_db])
        return self.hosting(*args, timeout=3600)

    def hosting_finalize(
        self, site_id: str, operation_id: str, domain: str
    ) -> dict[str, Any]:
        return self.hosting(
            "finalize",
            "--site",
            site_id,
            "--operation",
            operation_id,
            "--confirm-domain",
            domain,
            timeout=1200,
        )

    def hosting_rollback(self, site_id: str, operation_id: str) -> dict[str, Any]:
        return self.hosting(
            "rollback", "--site", site_id, "--operation", operation_id, timeout=1200
        )

    def hosting_status(self, site_id: str) -> dict[str, Any]:
        return self.hosting("status", "--site", site_id, timeout=300)

    # -- host agents and Apps ------------------------------------------------

    def install_agents(
        self,
        *,
        traefik_uid: int | None = None,
        dry_run: bool = False,
        timeout: int = 180,
    ) -> dict[str, Any]:
        argv = [
            self.python,
            str(self.root / "scripts" / "install_tenant_agents.py"),
            "--app-container",
            self.app_container,
            "--data-root",
            str(self.data_root),
            "--json",
        ]
        if traefik_uid is not None:
            argv.extend(["--traefik-uid", str(traefik_uid)])
        if dry_run:
            argv.append("--dry-run")
        return self._payload(
            self._run(argv, timeout=timeout), argv, label="agents installer"
        )

    def migrate_apps(
        self,
        tenant: str,
        *,
        api_url: str | None,
        token_file: Path | None,
        env_file: Path | None = None,
        app_ids: Sequence[str] = (),
        timeout: int = 1800,
        verify_cell: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        argv = [
            self.python,
            str(self.root / "scripts" / "migrate_tenant_apps.py"),
            "--tenant",
            tenant,
            "--data-root",
            str(self.data_root),
            "--json",
        ]
        if api_url:
            argv.extend(["--api-url", api_url])
        if token_file is not None:
            argv.extend(["--token-file", str(token_file)])
        if env_file is not None:
            argv.extend(["--env-file", str(env_file)])
        if timeout:
            argv.extend(["--timeout", str(timeout)])
        for app_id in app_ids:
            argv.extend(["--app", app_id])
        if not verify_cell:
            argv.append("--no-cell-verify")
        argv.append("--apply" if not dry_run else "--dry-run")
        return self._payload(
            self._run(argv, timeout=timeout + 120), argv, label="apps migrator"
        )


# ---------------------------------------------------------------------------
# Run plan and journal
# ---------------------------------------------------------------------------


@dataclass
class MigrationPlan:
    tenant: str
    memory: str | None = None
    cpus: float | None = None
    pids: int | None = None
    storage: str | None = None
    storage_bytes: int | None = None
    kinds: tuple[str, ...] = KINDS
    site_ids: tuple[str, ...] = ()
    shared_db: str | None = None
    skip_plan: bool = False
    skip_sites: bool = False
    finalize: bool = False
    rollback_on_failure: bool = False
    dry_run: bool = False
    start_services: bool = True
    skip_service_check: bool = False
    install_agents: bool = True
    traefik_uid: int | None = None
    migrate_apps: bool = False
    apps_api_url: str | None = None
    apps_token_file: Path | None = None
    apps_ids: tuple[str, ...] = ()
    apps_timeout: int = 1800
    apps_verify_cell: bool = True
    continue_on_failure: bool = False
    provision_timeout: float = 240.0
    data_root: str = DEFAULT_DATA_ROOT
    app_container: str = DEFAULT_APP_CONTAINER
    hosting_mode: str = "auto"
    env_file: Path | None = None


@dataclass
class Journal:
    path: Path
    payload: dict[str, Any]
    events: list[dict[str, Any]] = field(default_factory=list)

    def event(self, phase: str, action: str, *, ok: bool, detail: Any = None) -> None:
        entry = {
            "at": datetime.now(UTC).isoformat(),
            "phase": phase,
            "action": action,
            "ok": bool(ok),
        }
        if detail is not None:
            entry["detail"] = redact(detail)
        self.events.append(entry)
        self.save()

    def save(self) -> None:
        self.payload["events"] = self.events
        self.payload["updated_at"] = datetime.now(UTC).isoformat()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(self.path.name + ".tmp")
            temporary.write_text(
                json.dumps(self.payload, indent=2, sort_keys=True, default=str) + "\n",
                encoding="utf-8",
            )
            temporary.replace(self.path)
        except OSError:
            # Evidence must never turn a successful migration into a failure.
            pass


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class Migrator:
    def __init__(
        self,
        plan: MigrationPlan,
        ops: Operator,
        console: Console,
        journal: Journal,
        *,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.plan = plan
        self.ops = ops
        self.console = console
        self.journal = journal
        self.sleep = sleep
        self.sites: list[dict[str, Any]] = []
        self.migrated: list[dict[str, Any]] = []
        self.finalized: list[dict[str, Any]] = []
        self.skipped: list[dict[str, Any]] = []
        self.rolled_back = False

    # -- phases -------------------------------------------------------------

    def preflight(self) -> None:
        self.console.step("Preflight")
        self._require_scripts()
        if not self.plan.dry_run and os.geteuid() != 0:
            raise PreflightError("run as root (sudo) for cells, systemd and plans")
        capacity = self.ops.capacity()
        self.journal.payload["capacity"] = capacity
        self.console.info(
            "host: "
            f"RAM {human_size(capacity['memory_bytes'])} | "
            f"CPU {capacity['cpus']:g} cores | "
            f"disk free {human_size(capacity['storage_available_bytes'])}"
        )
        self._validate_capacity(capacity)

        doctor = self.ops.tenant("doctor", timeout=120)
        if not doctor.get("ready"):
            failed = [
                name
                for name, item in (doctor.get("capabilities") or {}).items()
                if not item.get("ok")
            ]
            raise PreflightError(
                "host doctor is not ready"
                + (f": {', '.join(failed)}" if failed else "")
            )
        self.journal.event("preflight", "doctor", ok=True, detail=doctor)
        self.console.ok("host doctor is green")

        if self.plan.skip_plan and self.plan.skip_sites and not self.plan.migrate_apps:
            self.console.info("services: not required for this partial run")
        elif not self.plan.skip_service_check:
            if self.plan.install_agents:
                self._install_agents()
            self._ensure_services(capacity)
        if self.plan.migrate_apps:
            self._require_apps_credentials()
        self.journal.payload["hosting_mode"] = self.ops.hosting_mode_effective()
        self.console.info(
            f"hosting CLI mode: {self.plan.hosting_mode} -> "
            f"{self.ops.hosting_mode_effective()}"
        )

    def _require_scripts(self) -> None:
        required = [TENANT_SCRIPT, HOSTING_SCRIPT]
        if self.plan.install_agents and not self.plan.skip_service_check:
            required.append(AGENTS_SCRIPT)
        if self.plan.migrate_apps:
            required.append(APPS_SCRIPT)
        for path in required:
            if not path.is_file():
                raise PreflightError(f"operator script is missing: {path}")
        if shutil.which("systemctl") is None and not self.plan.dry_run:
            raise PreflightError("systemctl is not available on this host")

    def _validate_capacity(self, capacity: dict[str, Any]) -> None:
        if self.plan.memory is not None:
            memory = parse_size(self.plan.memory, what="memory")
            if capacity["memory_bytes"] and memory > capacity["memory_bytes"]:
                self.console.warn(
                    f"plan RAM {self.plan.memory} exceeds host RAM "
                    f"{human_size(capacity['memory_bytes'])} (overcommit is allowed)"
                )
        if (
            self.plan.cpus is not None
            and capacity["cpus"]
            and self.plan.cpus > capacity["cpus"]
        ):
            self.console.warn(
                f"plan CPU {self.plan.cpus:g} exceeds host cores "
                f"{capacity['cpus']:g} (overcommit is allowed)"
            )
        if (
            self.plan.storage_bytes is not None
            and self.plan.storage_bytes > capacity["storage_available_bytes"]
        ):
            self.console.warn(
                f"declared storage {self.plan.storage} exceeds free disk "
                f"{human_size(capacity['storage_available_bytes'])}"
            )
        if self.plan.storage_bytes is not None:
            self.console.warn(
                "storage is a declared limit (A.SPEC 0111), not a filesystem "
                "quota; save it from Resources/Apps plan API to make it effective"
            )

    def _ensure_services(self, capacity: dict[str, Any]) -> None:
        del capacity
        needs_relay = not self.plan.skip_sites
        units = list(DEFAULT_UNITS) if needs_relay else [DEFAULT_UNITS[0]]
        for unit in units:
            if self.ops.service_active(unit):
                self.console.ok(f"{unit} is active")
                continue
            if self.plan.dry_run:
                self.console.warn(f"{unit} is inactive (dry-run: would start it)")
                continue
            if not self.plan.start_services:
                raise PreflightError(
                    f"{unit} is inactive; start it or pass --start-services"
                )
            if not self.ops.unit_loaded(unit):
                raise PreflightError(
                    f"{unit} is not installed; deploy scripts/tenant_cell/deploy/{unit}"
                )
            self.console.warn(f"{unit} is inactive; starting it")
            self.ops.start_service(unit)
            if not self._wait_active(unit):
                raise PreflightError(f"{unit} did not become active")
            self.console.ok(f"{unit} started")
        if self.plan.dry_run:
            return
        for path in (AGENT_SOCKET, RELAY_SOCKET):
            if path.exists():
                continue
            if path == RELAY_SOCKET and self.plan.skip_sites:
                continue
            raise PreflightError(f"expected socket is missing: {path}")

    def _wait_active(self, unit: str, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.ops.service_active(unit):
                return True
            self.sleep(1)
        return False

    def _install_agents(self) -> None:
        self.console.info("agents: ensure plan-agent and edge-relay are installed")
        result = self.ops.install_agents(
            traefik_uid=self.plan.traefik_uid,
            dry_run=self.plan.dry_run,
        )
        self.journal.event(
            "preflight",
            "install_agents",
            ok=bool(result.get("ok")),
            detail=result,
        )
        if not result.get("ok"):
            message = result.get("error") or "agent installation failed"
            if self.plan.dry_run:
                self.console.warn(f"agents preview incomplete: {message}")
                return
            raise PreflightError(f"agent installation failed: {message}")
        self.console.ok("host agents installed and running")

    def _host_env(self, key: str) -> str:
        for path in (self.plan.env_file, ROOT / ".env.docker", ROOT / ".env"):
            if path is None or not path.is_file():
                continue
            value = load_env_file(path).get(key, "").strip()
            if value:
                return value
        return ""

    def _require_apps_credentials(self) -> None:
        token_file = self.plan.apps_token_file
        has_token = (
            bool(token_file and token_file.is_file())
            or bool(os.environ.get("SPANEL_APPS_TOKEN"))
            or bool(os.environ.get("SPANEL_ACCESS_TOKEN"))
            or bool(self._host_env("SPANEL_APPS_TOKEN"))
            or bool(self._host_env("SPANEL_ACCESS_TOKEN"))
        )
        has_url = bool(
            self.plan.apps_api_url
            or os.environ.get("SPANEL_DOMAIN")
            or self._host_env("SPANEL_DOMAIN")
        )
        if not has_token:
            raise PreflightError(
                "Apps migration needs SPANEL_APPS_TOKEN or --apps-token-file"
            )
        if not has_url:
            raise PreflightError(
                "Apps migration needs SPANEL_DOMAIN in .env.docker or --apps-api-url"
            )

    def provision(self) -> dict[str, Any]:
        self.console.step(
            "Provision cell" + (" (preview)" if self.plan.dry_run else "")
        )
        result = self.ops.provision(
            self.plan.tenant,
            dry_run=self.plan.dry_run,
            timeout=self.plan.provision_timeout,
            sleep=self.sleep,
        )
        if result.get("error"):
            raise PreflightError(f"provision failed: {result['error']}")
        state = result.get("state", "preview" if self.plan.dry_run else "unknown")
        self.journal.event(
            "provision", "provision", ok=state != "degraded", detail=result
        )
        self.console.ok(f"cell state: {state}")
        return result

    def apply_plan(self) -> dict[str, Any] | None:
        if self.plan.skip_plan:
            self.console.step("Resource plan (skipped)")
            return None
        self.console.step(
            "Apply resource plan" + (" (preview)" if self.plan.dry_run else "")
        )
        if self.plan.memory is None or self.plan.cpus is None or self.plan.pids is None:
            raise UsageError(
                "memory, cpus and pids are required unless --skip-plan is used"
            )
        result = self.ops.plan_apply(
            self.plan.tenant,
            memory=self.plan.memory,
            cpus=self.plan.cpus,
            pids=self.plan.pids,
            dry_run=self.plan.dry_run,
        )
        if result.get("error"):
            if self.plan.dry_run:
                self.console.warn(
                    f"plan preview unavailable until the cell exists: {result['error']}"
                )
                return result
            raise MigratorError(f"plan apply failed: {result['error']}")
        self.journal.event("plan", "apply", ok=True, detail=result)
        self.console.ok(
            f"RAM {self.plan.memory} | CPU {self.plan.cpus:g} | "
            f"PIDs {self.plan.pids}"
            + (
                f" | storage {self.plan.storage} (declared)"
                if self.plan.storage
                else ""
            )
        )
        if self.plan.dry_run:
            self.console.info("dry-run: plan not written and not verified")
            return result
        verified = self.ops.plan_verify(self.plan.tenant)
        self.journal.event(
            "plan", "verify", ok=bool(verified.get("ok")), detail=verified
        )
        if not verified.get("ok"):
            raise MigratorError(f"plan verification failed: {verified}")
        self.console.ok("kernel enforces the plan")
        return result

    def plan_sites(self) -> list[dict[str, Any]]:
        if self.plan.skip_sites:
            self.console.step("Hosting sites (skipped)")
            return []
        self.console.step("Plan Hosting sites")
        try:
            raw = self.ops.hosting_sites(
                self.plan.tenant,
                self.plan.kinds,
                self.plan.site_ids,
            )
        except OperatorError as exc:
            if self.plan.dry_run:
                self.console.warn(f"cannot enumerate sites yet: {exc}")
                return []
            raise
        sites: list[dict[str, Any]] = []
        for item in raw:
            site_id = str(item.get("site_id") or "")
            source = item.get("from_runtime")
            if source == "rootless":
                self.skipped.append(
                    {"site_id": site_id, "reason": "already rootless", "plan": item}
                )
                continue
            if not item.get("ok"):
                message = item.get("error") or "site cannot be migrated"
                if self.plan.dry_run and not item.get("site_id"):
                    self.console.warn(f"site preview unavailable: {message}")
                    return []
                raise PreflightError(f"site {site_id or '?'}: {message}")
            sites.append(item)
        self.sites = sites
        self.journal.payload["sites_planned"] = sites
        self.journal.event("sites", "plan", ok=True, detail=sites)
        if not sites:
            self.console.info("no rootful sites need migration")
        for site in sites:
            domain = (site.get("inventory") or {}).get("domain") or "(sin dominio)"
            self.console.info(f"{site.get('site_id')} [{site.get('kind')}] {domain}")
        return sites

    def migrate_sites(self) -> list[dict[str, Any]]:
        if self.plan.skip_sites:
            return []
        self.console.step("Migrate sites" + (" (preview)" if self.plan.dry_run else ""))
        for site in self.sites:
            site_id = str(site["site_id"])
            if self.plan.dry_run:
                self.console.info(f"{site_id}: would migrate")
                self.journal.event("sites", "migrate_preview", ok=True, detail=site)
                continue
            try:
                result = self.ops.hosting_migrate(
                    site_id, shared_db=self.plan.shared_db
                )
            except OperatorError as exc:
                result = {"ok": False, "site_id": site_id, "error": str(exc)}
            self.journal.event(
                "sites", "migrate", ok=bool(result.get("ok")), detail=result
            )
            if not result.get("ok"):
                self.console.fail(
                    f"{site_id}: {result.get('error') or 'migration failed'}"
                )
                self._rollback_if_requested()
                if not self.plan.continue_on_failure:
                    raise MigratorError(
                        f"migration failed for {site_id}; previous sites stay retained"
                    )
                self.skipped.append(
                    {"site_id": site_id, "reason": "failed", "result": result}
                )
                continue
            self.migrated.append({"site": site, "result": result})
            self.console.ok(
                f"{site_id}: {result.get('state', 'done')} "
                f"(rollback_available={result.get('rollback_available')})"
            )
        return self.migrated

    def finalize_sites(self) -> list[dict[str, Any]]:
        if self.plan.skip_sites or not self.plan.finalize or self.rolled_back:
            return []
        self.console.step("Finalize (remove rootful copies)")
        for entry in self.migrated:
            site = entry["site"]
            result = entry["result"]
            site_id = str(site["site_id"])
            operation = result.get("operation_id")
            domain = (site.get("inventory") or {}).get("domain")
            if result.get("state") != "retained":
                self.console.warn(
                    f"{site_id}: state {result.get('state')}, not retained"
                )
                continue
            if not operation or not domain:
                self.console.warn(f"{site_id}: missing operation id or domain")
                continue
            finalized = self.ops.hosting_finalize(site_id, str(operation), str(domain))
            self.journal.event(
                "sites", "finalize", ok=bool(finalized.get("ok")), detail=finalized
            )
            if not finalized.get("ok"):
                raise MigratorError(
                    f"finalize failed for {site_id}: {finalized.get('error')}"
                )
            self.finalized.append(finalized)
            self.console.ok(f"{site_id}: finalized")
        return self.finalized

    def _rollback_if_requested(self) -> None:
        if not self.plan.rollback_on_failure:
            return
        self.rolled_back = True
        self.console.warn("rolling back sites migrated in this run")
        for entry in reversed(self.migrated):
            site = entry["site"]
            result = entry["result"]
            operation = result.get("operation_id")
            if not operation:
                continue
            site_id = str(site["site_id"])
            try:
                rolled = self.ops.hosting_rollback(site_id, str(operation))
            except OperatorError as exc:
                rolled = {"ok": False, "error": str(exc)}
            self.journal.event(
                "sites", "rollback", ok=bool(rolled.get("ok")), detail=rolled
            )
            if rolled.get("ok"):
                self.console.ok(f"{site_id}: rollback complete")
            else:
                self.console.fail(f"{site_id}: rollback failed: {rolled.get('error')}")

    def status_summary(self) -> list[dict[str, Any]]:
        if self.plan.dry_run:
            return []
        rows: list[dict[str, Any]] = []
        for entry in self.migrated:
            site_id = str(entry["site"]["site_id"])
            try:
                status = self.ops.hosting_status(site_id)
            except OperatorError as exc:
                status = {"ok": False, "error": str(exc)}
            rows.append({"site_id": site_id, "status": status})
        self.journal.payload["status"] = rows
        return rows

    def migrate_apps(self) -> dict[str, Any] | None:
        if not self.plan.migrate_apps:
            return None
        self.console.step("Migrate Apps" + (" (preview)" if self.plan.dry_run else ""))
        try:
            result = self.ops.migrate_apps(
                self.plan.tenant,
                api_url=self.plan.apps_api_url,
                token_file=self.plan.apps_token_file,
                env_file=self.plan.env_file,
                app_ids=self.plan.apps_ids,
                timeout=self.plan.apps_timeout,
                verify_cell=self.plan.apps_verify_cell,
                dry_run=self.plan.dry_run,
            )
        except OperatorError as exc:
            result = {"ok": False, "error": str(exc)}
        self.journal.event("apps", "migrate", ok=bool(result.get("ok")), detail=result)
        for item in result.get("results") or []:
            state = item.get("state")
            name = item.get("name") or item.get("app_id")
            if item.get("ok"):
                self.console.ok(f"{name}: {state}")
            else:
                self.console.fail(
                    f"{name}: {item.get('error') or item.get('reason') or state}"
                )
        if not result.get("ok"):
            self.console.warn(
                "Apps migration is incomplete; Hosting changes stay retained"
            )
        return result

    def run(self) -> dict[str, Any]:
        self.preflight()
        self.provision()
        self.apply_plan()
        self.plan_sites()
        self.migrate_sites()
        apps = self.migrate_apps()
        self.finalize_sites()
        self.status_summary()
        ok = apps is None or bool(apps.get("ok"))
        payload = {
            "ok": ok,
            "tenant": self.plan.tenant,
            "dry_run": self.plan.dry_run,
            "migrated": [entry["result"] for entry in self.migrated],
            "finalized": self.finalized,
            "skipped": self.skipped,
            "apps": apps,
            "journal": str(self.journal.path),
        }
        self.journal.payload.update(
            {
                "ok": ok,
                "migrated": payload["migrated"],
                "finalized": payload["finalized"],
                "skipped": payload["skipped"],
                "apps": apps,
            }
        )
        self.journal.save()
        if not self.plan.dry_run and self.migrated:
            self.console.step("Rollback available")
            for entry in self.migrated:
                result = entry["result"]
                if not result.get("operation_id"):
                    continue
                self.console.info(
                    "python3 scripts/hosting_migrate_rootless.py rollback "
                    f"--site {entry['site']['site_id']} "
                    f"--operation {result['operation_id']} --json"
                )
        return payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spanel-migrator-to-rootless",
        description=(
            "One-run migration of a tenant's Hosting sites (and optional Apps) "
            "to a rootless cell, including host agent installation. Reuses "
            "spanel_tenant.py, hosting_migrate_rootless.py, "
            "install_tenant_agents.py and migrate_tenant_apps.py."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Run as root on the host. The hosting CLI runs inside the app "
            "container unless --hosting-mode local is used."
        ),
    )
    parser.add_argument("--tenant", help="Validated tenant slug.")
    parser.add_argument("--memory", help="Plan RAM, e.g. 512M or 1G.")
    parser.add_argument("--cpus", type=float, help="Plan CPU quota in cores, e.g. 1.5.")
    parser.add_argument("--pids", type=int, help="Plan TasksMax (positive integer).")
    parser.add_argument(
        "--storage",
        help="Declared storage limit, e.g. 10G (not a kernel quota).",
    )
    parser.add_argument(
        "--only",
        choices=KINDS,
        help="Migrate only one site kind (default: static and wordpress).",
    )
    parser.add_argument(
        "--site",
        action="append",
        default=[],
        help="Restrict the migration to this site id (repeatable).",
    )
    parser.add_argument(
        "--shared-db",
        default=None,
        help=(
            "Legacy shared database container for WordPress (explicit opt-in, "
            "e.g. mariadb). Forces a maintenance window."
        ),
    )
    parser.add_argument(
        "--skip-plan",
        action="store_true",
        help="Do not apply/verify the resource plan (keep the current one).",
    )
    parser.add_argument(
        "--skip-sites",
        action="store_true",
        help="Provision and plan the cell, but do not migrate Hosting sites.",
    )
    parser.add_argument(
        "--finalize",
        action="store_true",
        help="Remove rootful copies after a successful retained migration.",
    )
    parser.add_argument(
        "--rollback-on-failure",
        action="store_true",
        help="Roll back every site migrated in this run if a later one fails.",
    )
    parser.add_argument(
        "--continue-on-failure",
        action="store_true",
        help="Keep migrating remaining sites after one fails.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview every phase without host mutation.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Do not ask for confirmation (missing values still fail).",
    )
    parser.add_argument(
        "--non-interactive",
        "--no-input",
        action="store_true",
        dest="non_interactive",
        help="Never prompt; require every value as a flag.",
    )
    parser.add_argument(
        "--start-services",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Start inactive plan-agent/edge-relay units (default: yes).",
    )
    parser.add_argument(
        "--skip-service-check",
        action="store_true",
        help="Do not require plan-agent/edge-relay (lab or partial runs).",
    )
    parser.add_argument(
        "--install-agents",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Install/repair plan-agent and edge-relay units (default: yes).",
    )
    parser.add_argument(
        "--traefik-uid",
        type=int,
        default=None,
        help="Host UID for the edge relay (default: SPANEL_TRAEFIK_UID or 1000).",
    )
    parser.add_argument(
        "--apps",
        action="store_true",
        help="Also redeploy the tenant's signed Apps releases into the cell.",
    )
    parser.add_argument(
        "--apps-api-url",
        default=None,
        help="Apps API base URL override (default: SPANEL_DOMAIN in .env.docker).",
    )
    parser.add_argument(
        "--apps-token-file",
        type=Path,
        default=None,
        help="File with the platform/tenant API token (never in argv).",
    )
    parser.add_argument(
        "--app",
        action="append",
        default=[],
        dest="apps_ids",
        help="Restrict Apps migration to this application id (repeatable).",
    )
    parser.add_argument(
        "--apps-timeout",
        type=int,
        default=1800,
        help="Seconds to wait per Apps deployment (default: 1800).",
    )
    parser.add_argument(
        "--apps-no-cell-verify",
        action="store_true",
        help="Do not require Apps containers to appear in the cell socket.",
    )
    parser.add_argument(
        "--provision-timeout",
        type=float,
        default=240.0,
        help="Seconds to wait for the cell to become ready (default: 240).",
    )
    parser.add_argument(
        "--data-root",
        default=DEFAULT_DATA_ROOT,
        help=f"Host cell registry root (default: {DEFAULT_DATA_ROOT}).",
    )
    parser.add_argument(
        "--app-container",
        default=os.environ.get("SPANEL_APP_CONTAINER", DEFAULT_APP_CONTAINER),
        help=f"App container for the hosting CLI (default: {DEFAULT_APP_CONTAINER}).",
    )
    parser.add_argument(
        "--hosting-mode",
        choices=("auto", "local", "container"),
        default="auto",
        help="Where to run hosting_migrate_rootless.py (default: auto).",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="Optional KEY=VALUE file for local hosting mode.",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        help="Evidence JSON path (default: logs/migrator-to-rootless-<tenant>-<ts>.json).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit one JSON document on stdout; human logs go to stderr.",
    )
    return parser


def _tenant_slug(raw: str) -> str:
    slug = raw.strip().lower()
    if not SLUG_RE.fullmatch(slug):
        raise UsageError(f"invalid tenant slug: {raw!r}")
    return slug


def build_plan(
    args: argparse.Namespace, ops: Operator, console: Console
) -> MigrationPlan:
    interactive = console.interactive
    if args.skip_plan and any(
        value is not None for value in (args.memory, args.cpus, args.pids, args.storage)
    ):
        raise UsageError("--skip-plan cannot be combined with plan values")

    tenant_raw = args.tenant
    if not tenant_raw:
        tenant_raw = console.ask("Tenant slug")
    tenant = _tenant_slug(tenant_raw)

    memory = args.memory
    cpus = args.cpus
    pids = args.pids
    storage = args.storage
    if not args.skip_plan:
        existing: dict[str, Any] | None = None
        if interactive and (memory is None or cpus is None or pids is None):
            existing = ops.plan_show(tenant)
        current = (existing or {}).get("plan") or {}
        if memory is None:
            memory = console.ask(
                "Plan RAM (e.g. 512M, 1G)",
                current.get("memory") and str(current["memory"]),
            )
        if cpus is None:
            default_cpu = current.get("cpus")
            raw_cpus = console.ask(
                "Plan CPU cores (e.g. 1.0)",
                f"{float(default_cpu):g}" if default_cpu else None,
            )
            try:
                cpus = float(raw_cpus)
            except ValueError as exc:
                raise UsageError(f"invalid cpus: {raw_cpus!r}") from exc
        if pids is None:
            default_pids = current.get("pids")
            raw_pids = console.ask(
                "Plan PIDs (TasksMax, e.g. 512)",
                str(default_pids) if default_pids else None,
            )
            try:
                pids = int(raw_pids)
            except ValueError as exc:
                raise UsageError(f"invalid pids: {raw_pids!r}") from exc
        if storage is None and interactive:
            storage = console.ask(
                "Declared storage (e.g. 10G; not a kernel quota)", "10G"
            )

    storage_bytes = None
    if storage:
        storage_bytes = parse_size(storage, what="storage")
    if not args.skip_plan:
        assert memory is not None and cpus is not None and pids is not None
        memory = str(memory).strip()
        parse_size(memory, what="memory")
        if cpus <= 0:
            raise UsageError("cpus must be > 0")
        if pids <= 0:
            raise UsageError("pids must be a positive integer")

    kinds = (args.only,) if args.only else KINDS
    return MigrationPlan(
        tenant=tenant,
        memory=memory,
        cpus=cpus,
        pids=pids,
        storage=storage,
        storage_bytes=storage_bytes,
        kinds=kinds,
        site_ids=tuple(args.site),
        shared_db=args.shared_db,
        skip_plan=args.skip_plan,
        skip_sites=args.skip_sites,
        finalize=args.finalize,
        rollback_on_failure=args.rollback_on_failure,
        dry_run=args.dry_run,
        start_services=args.start_services,
        skip_service_check=args.skip_service_check,
        install_agents=args.install_agents,
        traefik_uid=args.traefik_uid,
        migrate_apps=args.apps,
        apps_api_url=args.apps_api_url,
        apps_token_file=args.apps_token_file,
        apps_ids=tuple(args.apps_ids),
        apps_timeout=args.apps_timeout,
        apps_verify_cell=not args.apps_no_cell_verify,
        continue_on_failure=args.continue_on_failure,
        provision_timeout=args.provision_timeout,
        data_root=args.data_root,
        app_container=args.app_container,
        hosting_mode=args.hosting_mode,
        env_file=args.env_file,
    )


def print_summary(plan: MigrationPlan, console: Console) -> None:
    console.step("Migration plan")
    console.info(f"tenant:        {plan.tenant}")
    console.info(f"data root:     {plan.data_root}")
    if plan.skip_plan:
        console.info("resources:     keep the current plan")
    else:
        console.info(
            f"resources:     RAM {plan.memory} | CPU {plan.cpus:g} | PIDs {plan.pids}"
        )
        if plan.storage:
            console.info(f"storage:       {plan.storage} (declared, not enforced)")
    if plan.skip_sites:
        console.info("sites:         skipped")
    else:
        which = "all" if plan.site_ids == () else ", ".join(plan.site_ids)
        console.info(f"sites:         {which} ({', '.join(plan.kinds)})")
        if plan.shared_db:
            console.info(f"shared DB:     {plan.shared_db} (legacy maintenance window)")
        console.info(f"end state:     {'finalized' if plan.finalize else 'retained'}")
        console.info(
            f"on failure:    {'rollback all migrated' if plan.rollback_on_failure else 'stop'}"
        )
    console.info(
        f"agents:        {'install/repair' if plan.install_agents else 'assume installed'}"
    )
    if plan.migrate_apps:
        which = "all" if not plan.apps_ids else ", ".join(plan.apps_ids)
        console.info(f"apps:          {which} (signed releases)")
    else:
        console.info("apps:          skipped")
    console.info(f"hosting mode:  {plan.hosting_mode} ({plan.app_container})")
    if plan.dry_run:
        console.info("dry-run:       no host mutation")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    interactive = (
        not args.non_interactive
        and not args.yes
        and sys.stdin.isatty()
        and not args.json
    )
    console = Console(json_mode=args.json, interactive=interactive)
    ops = Operator(
        data_root=args.data_root,
        app_container=args.app_container,
        hosting_mode=args.hosting_mode,
        env_file=args.env_file,
    )
    parsed: MigrationPlan | None = None
    journal_path = args.state_file
    try:
        parsed = build_plan(args, ops, console)
        if journal_path is None:
            suffix = "-dry-run" if parsed.dry_run else ""
            journal_path = (
                ROOT
                / "logs"
                / f"migrator-to-rootless-{parsed.tenant}-{utc_stamp()}{suffix}.json"
            )
        journal = Journal(
            path=journal_path,
            payload={
                "tool": "spanel-migrator-to-rootless",
                "started_at": datetime.now(UTC).isoformat(),
                "plan": {
                    "tenant": parsed.tenant,
                    "memory": parsed.memory,
                    "cpus": parsed.cpus,
                    "pids": parsed.pids,
                    "storage": parsed.storage,
                    "storage_bytes": parsed.storage_bytes,
                    "kinds": parsed.kinds,
                    "site_ids": parsed.site_ids,
                    "skip_plan": parsed.skip_plan,
                    "skip_sites": parsed.skip_sites,
                    "finalize": parsed.finalize,
                    "rollback_on_failure": parsed.rollback_on_failure,
                    "dry_run": parsed.dry_run,
                    "data_root": parsed.data_root,
                    "app_container": parsed.app_container,
                    "hosting_mode": parsed.hosting_mode,
                },
            },
        )
        print_summary(parsed, console)
        if (
            not args.yes
            and not parsed.dry_run
            and not console.confirm(
                "Proceed with this one-run migration?", default=False
            )
        ):
            console.warn("aborted by the operator")
            return 2
        migrator = Migrator(parsed, ops, console, journal)
        payload = migrator.run()
        journal.event("report", "complete", ok=bool(payload.get("ok")), detail=payload)
        journal.payload["ok"] = bool(payload.get("ok"))
        journal.payload["finished_at"] = datetime.now(UTC).isoformat()
        journal.save()
        if args.json:
            print(json.dumps(payload, sort_keys=True, default=str))
        else:
            console.step("Done")
            console.ok(
                f"{len(payload['migrated'])} site(s) migrated, "
                f"{len(payload['finalized'])} finalized"
            )
            if payload["skipped"]:
                console.info(f"skipped: {len(payload['skipped'])}")
            apps = payload.get("apps")
            if apps is not None:
                count = len(apps.get("results") or [])
                console.info(f"apps: {count} processed, ok={apps.get('ok')}")
            console.info(f"evidence: {journal_path}")
        return 0 if payload.get("ok") else 1
    except PreflightError as exc:
        console.fail(f"preflight refused: {exc}")
        return 2
    except UsageError as exc:
        console.fail(f"usage: {exc}")
        return 2
    except MigratorError as exc:
        console.fail(str(exc))
        return 1
    except KeyboardInterrupt:
        console.fail("interrupted")
        return 1
    finally:
        if parsed is not None and "journal" in locals():
            journal.payload.setdefault("ok", False)
            if "payload" not in locals():
                journal.payload["finished_at"] = datetime.now(UTC).isoformat()
            journal.save()


if __name__ == "__main__":
    raise SystemExit(main())
