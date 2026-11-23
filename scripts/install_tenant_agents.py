#!/usr/bin/env python3
"""Install the two privileged host agents for rootless tenant cells.

The agents are reusable host infrastructure, not per-tenant state:

* ``spanel-plan-agent.service`` materializes tenant plans and answers capacity
  queries over ``/run/spanel/plan-agent.sock``;
* ``spanel-edge-relay.service`` carries Traefik traffic to the loopback port of
  each rootless cell over ``/run/spanel/edge-relay.sock``.

This installer is idempotent and never rotates an existing token. It renders
the units from ``scripts/tenant_cell/deploy/`` with the real repository path,
Python interpreter, data root, app-container UID and Traefik UID.

Usage (as root, from the repository):

    python3 scripts/install_tenant_agents.py --check
    python3 scripts/install_tenant_agents.py --dry-run
    python3 scripts/install_tenant_agents.py
    python3 scripts/install_tenant_agents.py --app-container spanel-app-1 \\
        --traefik-uid 1000

Exit codes: 0 ok, 1 error, 2 usage.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import secrets
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "scripts" / "tenant_cell" / "deploy"
PLAN_UNIT = "spanel-plan-agent.service"
RELAY_UNIT = "spanel-edge-relay.service"
PLAN_TEMPLATE = TEMPLATES / PLAN_UNIT
RELAY_TEMPLATE = TEMPLATES / RELAY_UNIT
RUNTIME_TMPFILES = "spanel.conf"
RUNTIME_TEMPLATE = TEMPLATES / "spanel-runtime.conf"
DEFAULT_DATA_ROOT = "/var/lib/spanel"
DEFAULT_APP_CONTAINER = "spanel-app-1"
DEFAULT_TRAEFIK_UID = 1000
DEFAULT_TMPFILES_DIR = Path("/etc/tmpfiles.d")
AGENT_SOCKET = "/run/spanel/plan-agent.sock"
RELAY_SOCKET = "/run/spanel/edge-relay.sock"


class InstallError(RuntimeError):
    """A safe-to-print installer failure."""


@dataclass(frozen=True)
class Output:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def run(argv: list[str], *, timeout: int = 60, dry_run: bool = False) -> Output:
    if dry_run:
        return Output(0, "", "")
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, check=False, timeout=timeout
        )
    except FileNotFoundError as exc:
        return Output(127, "", str(exc))
    except subprocess.TimeoutExpired:
        return Output(124, "", f"timeout after {timeout}s")
    return Output(completed.returncode, completed.stdout, completed.stderr)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def ensure_directory(path: Path, mode: int, *, dry_run: bool) -> None:
    if path.is_dir():
        return
    if dry_run:
        return
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


def ensure_token(path: Path, *, dry_run: bool) -> str:
    """Create the shared plan token once; never overwrite an existing one."""
    if path.is_file() and path.read_text(encoding="utf-8").strip():
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            if dry_run:
                return "would-tighten"
            path.chmod(0o600)
            return "tightened"
        return "existing"
    if path.exists() and not path.is_file():
        raise InstallError(f"{path} exists and is not a regular file")
    if dry_run:
        return "would-create"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(secrets.token_urlsafe(32) + "\n")
    return "created"


def detect_app_uid(container: str, *, dry_run: bool = False) -> int:
    """Read the UID the app container uses; the image normally runs as root."""
    inspected = run(
        ["docker", "inspect", "-f", "{{.Config.User}}", container], dry_run=dry_run
    )
    if inspected.returncode != 0:
        raise InstallError(
            f"cannot inspect app container {container}: "
            + (inspected.stderr or inspected.stdout).strip()[:300]
        )
    raw = inspected.stdout.strip().split(":", 1)[0]
    if not raw:
        return 0
    if raw.isdigit():
        return int(raw)
    resolved = run(["docker", "exec", container, "id", "-u", raw], dry_run=dry_run)
    if resolved.returncode != 0 or not resolved.stdout.strip().isdigit():
        raise InstallError(
            f"cannot resolve app container user {raw!r}: "
            + (resolved.stderr or resolved.stdout).strip()[:300]
        )
    return int(resolved.stdout.strip())


def resolve_traefik_uid(override: int | None) -> int:
    raw = override if override is not None else os.environ.get("SPANEL_TRAEFIK_UID")
    try:
        uid = int(raw) if raw is not None else DEFAULT_TRAEFIK_UID
    except (TypeError, ValueError) as exc:
        raise InstallError("SPANEL_TRAEFIK_UID must be an integer") from exc
    if not 0 < uid < 2**32:
        raise InstallError("Traefik UID is out of range")
    return uid


def render_unit(
    template: str,
    *,
    script: str,
    python: str,
    repo: Path,
    data_root: str,
    replacements: dict[str, object],
) -> str:
    text = template
    for placeholder, value in replacements.items():
        text = text.replace(placeholder, str(value))
    lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("ExecStart="):
            line = (
                f"ExecStart={python} {repo / 'scripts' / 'spanel_tenant.py'} "
                f"{script} --data-root {data_root}"
            )
        lines.append(line)
    return "\n".join(lines).rstrip() + "\n"


def write_unit(path: Path, content: str, *, dry_run: bool, force: bool = False) -> str:
    current = read_text(path)
    if current == content:
        return "unchanged"
    if path.exists() and current and not dry_run and not force:
        # Never silently replace an operator customization.
        raise InstallError(
            f"{path} already exists with different content; inspect it and use --force"
        )
    if dry_run:
        return "would-write"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.chmod(0o644)
    temporary.replace(path)
    return "written"


def wait_socket(path: Path, *, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_socket():
            return True
        time.sleep(0.25)
    return path.is_socket()


def capacity_check(socket_path: Path, token_path: Path) -> dict[str, Any]:
    """Prove the agent, token and peer credentials end to end."""
    if not socket_path.is_socket():
        return {"ok": False, "error": f"socket is missing: {socket_path}"}
    for path in (
        str(ROOT / "vendor" / "systutor-core"),
        str(ROOT / "vendor" / "systutor-core" / "src"),
    ):
        if path not in sys.path:
            sys.path.insert(0, path)
    try:
        from plugins.apps.backend.plans_client import HostPlanMaterializerClient
    except Exception as exc:  # noqa: BLE001 - importer error is reported verbatim
        return {"ok": False, "error": f"cannot import plans client: {exc}"}
    try:
        client = HostPlanMaterializerClient(socket_path, token_path, timeout=5)
        return {"ok": True, "capacity": client.capacity()}
    except Exception as exc:  # noqa: BLE001 - agent boundary
        return {"ok": False, "error": str(exc)[:300]}


def interpreter_ready(python: str) -> tuple[bool, str]:
    # The unit only needs typer at startup. SQLAlchemy is imported lazily for
    # the optional db-relay operation, so it is reported separately and does
    # not block installing the agent.
    checked = run([python, "-c", "import typer"], timeout=30)
    if checked.returncode == 0:
        return True, ""
    detail = (checked.stderr or checked.stdout).strip()[-300:]
    return False, f"{python} cannot import typer: {detail}"


def sqlalchemy_ready(python: str) -> tuple[bool, str]:
    checked = run([python, "-c", "import sqlalchemy"], timeout=30)
    if checked.returncode == 0:
        return True, ""
    detail = (checked.stderr or checked.stdout).strip()[-300:]
    return False, f"{python} cannot import sqlalchemy: {detail}"


class Installer:
    def __init__(
        self,
        *,
        repo: Path = ROOT,
        data_root: str = DEFAULT_DATA_ROOT,
        app_container: str = DEFAULT_APP_CONTAINER,
        traefik_uid: int | None = None,
        etc_dir: Path = Path("/etc/spanel"),
        unit_dir: Path = Path("/etc/systemd/system"),
        runtime_dir: Path = Path("/run/spanel"),
        tmpfiles_dir: Path = DEFAULT_TMPFILES_DIR,
        python: str | None = None,
    ) -> None:
        self.repo = repo
        self.data_root = data_root
        self.app_container = app_container
        self.traefik_uid_override = traefik_uid
        self.etc_dir = etc_dir
        self.unit_dir = unit_dir
        self.runtime_dir = runtime_dir
        self.tmpfiles_dir = tmpfiles_dir
        venv_python = repo / ".venv" / "bin" / "python"
        system_python = Path("/usr/bin/python3")
        candidates: list[str] = []
        for candidate in (
            python,
            os.environ.get("SPANEL_PYTHON"),
            str(venv_python) if venv_python.is_file() else None,
            sys.executable,
            str(system_python) if system_python.is_file() else None,
        ):
            if candidate and candidate not in candidates:
                candidates.append(candidate)
        # Prefer an interpreter that can actually import the agent runtime; the
        # system python on hosts with a dedicated host-venv often cannot.
        self.python = (
            next((item for item in candidates if interpreter_ready(item)[0]), "")
            or (candidates[0] if candidates else sys.executable)
        )
        self.token_path = etc_dir / "plan_agent_token"
        self.agent_socket = runtime_dir / "plan-agent.sock"
        self.relay_socket = runtime_dir / "edge-relay.sock"
        self.tmpfiles_path = tmpfiles_dir / RUNTIME_TMPFILES

    def inspect(self) -> dict[str, Any]:
        plan_template = read_text(
            self.repo / "scripts" / "tenant_cell" / "deploy" / PLAN_UNIT
        )
        relay_template = read_text(
            self.repo / "scripts" / "tenant_cell" / "deploy" / RELAY_UNIT
        )
        runtime_template = read_text(RUNTIME_TEMPLATE)
        if not plan_template or not relay_template or not runtime_template:
            raise InstallError("agent unit templates are missing")
        try:
            traefik_uid = resolve_traefik_uid(self.traefik_uid_override)
        except InstallError as exc:
            traefik_uid = 0
            traefik_error = str(exc)
        else:
            traefik_error = ""
        try:
            app_uid = detect_app_uid(self.app_container)
            app_error = ""
        except InstallError as exc:
            app_uid = -1
            app_error = str(exc)
        plan = render_unit(
            plan_template,
            script="plan-agent",
            python=self.python,
            repo=self.repo,
            data_root=self.data_root,
            replacements={"<app-container-uid>": max(app_uid, 0)},
        )
        relay = render_unit(
            relay_template,
            script="edge-relay",
            python=self.python,
            repo=self.repo,
            data_root=self.data_root,
            replacements={"<SPANEL_TRAEFIK_UID>": traefik_uid or DEFAULT_TRAEFIK_UID},
        )
        runtime = runtime_template.replace(
            "<SPANEL_TRAEFIK_UID>", str(traefik_uid or DEFAULT_TRAEFIK_UID)
        )
        units = {}
        for name, content in ((PLAN_UNIT, plan), (RELAY_UNIT, relay)):
            path = self.unit_dir / name
            units[name] = {
                "path": str(path),
                "installed": path.is_file(),
                "matches": read_text(path) == content,
                "active": run(["systemctl", "is-active", name]).stdout.strip()
                == "active",
            }
        token_mode = (
            stat.S_IMODE(self.token_path.stat().st_mode)
            if self.token_path.is_file()
            else None
        )
        interpreter_ok, interpreter_error = interpreter_ready(self.python)
        sqlalchemy_ok, sqlalchemy_error = sqlalchemy_ready(self.python)
        result: dict[str, Any] = {
            "ok": True,
            "repo": str(self.repo),
            "python": self.python,
            "interpreter": {
                "ok": interpreter_ok,
                "error": interpreter_error,
                "sqlalchemy": {"ok": sqlalchemy_ok, "error": sqlalchemy_error},
            },
            "data_root": self.data_root,
            "app_container": self.app_container,
            "app_uid": app_uid,
            "traefik_uid": traefik_uid,
            "token": {
                "path": str(self.token_path),
                "exists": self.token_path.is_file(),
                "mode": f"{token_mode:o}" if token_mode is not None else None,
            },
            "units": units,
            "runtime": {
                "path": str(self.tmpfiles_path),
                "installed": self.tmpfiles_path.is_file(),
                "matches": read_text(self.tmpfiles_path) == runtime,
            },
            "sockets": {
                "plan_agent": str(self.agent_socket),
                "plan_agent_exists": self.agent_socket.is_socket(),
                "edge_relay": str(self.relay_socket),
                "edge_relay_exists": self.relay_socket.is_socket(),
            },
        }
        if traefik_error:
            result["ok"] = False
            result["error"] = traefik_error
        elif not interpreter_ok:
            result["ok"] = False
            result["error"] = interpreter_error
        elif traefik_uid and not _user_exists(traefik_uid):
            result["ok"] = False
            result["error"] = f"Traefik UID {traefik_uid} has no host user"
        if app_error:
            result["ok"] = False
            result["error"] = app_error
        if self.agent_socket.is_socket():
            result["capacity"] = capacity_check(self.agent_socket, self.token_path)
            if not result["capacity"].get("ok"):
                result["ok"] = False
        return result

    def install(
        self, *, dry_run: bool = False, force: bool = False, start: bool = True
    ) -> dict[str, Any]:
        if not dry_run and os.geteuid() != 0:
            raise InstallError("run as root (sudo) to install systemd units")
        inspect = self.inspect()
        if not inspect.get("ok") and inspect.get("error", "").startswith(
            "cannot inspect app"
        ):
            raise InstallError(str(inspect["error"]))
        interpreter_ok, interpreter_error = interpreter_ready(self.python)
        if not interpreter_ok:
            raise InstallError(interpreter_error)
        traefik_uid = int(inspect["traefik_uid"])
        if inspect.get("app_uid", -1) < 0:
            raise InstallError(
                "cannot resolve the app container UID: "
                + str(inspect.get("error", "unknown error"))
            )
        if not _user_exists(traefik_uid):
            raise InstallError(f"Traefik UID {traefik_uid} has no host user")
        plan_template = read_text(
            self.repo / "scripts" / "tenant_cell" / "deploy" / PLAN_UNIT
        )
        relay_template = read_text(
            self.repo / "scripts" / "tenant_cell" / "deploy" / RELAY_UNIT
        )
        runtime_template = read_text(RUNTIME_TEMPLATE)
        if not plan_template or not relay_template or not runtime_template:
            raise InstallError("agent unit templates are missing")
        plan = render_unit(
            plan_template,
            script="plan-agent",
            python=self.python,
            repo=self.repo,
            data_root=self.data_root,
            replacements={"<app-container-uid>": inspect["app_uid"]},
        )
        relay = render_unit(
            relay_template,
            script="edge-relay",
            python=self.python,
            repo=self.repo,
            data_root=self.data_root,
            replacements={"<SPANEL_TRAEFIK_UID>": traefik_uid},
        )
        runtime = runtime_template.replace("<SPANEL_TRAEFIK_UID>", str(traefik_uid))

        ensure_directory(self.etc_dir, 0o755, dry_run=dry_run)
        token = ensure_token(self.token_path, dry_run=dry_run)
        results: dict[str, Any] = {
            "ok": True,
            "dry_run": dry_run,
            "token": token,
            "app_uid": inspect["app_uid"],
            "traefik_uid": traefik_uid,
            "python": self.python,
            "units": {},
        }
        for name, content in ((PLAN_UNIT, plan), (RELAY_UNIT, relay)):
            path = self.unit_dir / name
            if (
                path.exists()
                and read_text(path) != content
                and not force
                and not dry_run
            ):
                raise InstallError(
                    f"{path} differs from the template; inspect it and rerun with --force"
                )
            results["units"][name] = write_unit(
                path, content, dry_run=dry_run, force=force
            )
        results["runtime"] = write_unit(
            self.tmpfiles_path, runtime, dry_run=dry_run, force=force
        )
        if dry_run:
            results["started"] = False
            return results
        reloaded = run(["systemctl", "daemon-reload"], timeout=60)
        if reloaded.returncode != 0:
            raise InstallError(
                "systemctl daemon-reload failed: "
                + (reloaded.stderr or reloaded.stdout).strip()[:300]
            )
        created = run(
            ["systemd-tmpfiles", "--create", str(self.tmpfiles_path)], timeout=60
        )
        if created.returncode != 0:
            raise InstallError(
                "systemd-tmpfiles --create failed: "
                + (created.stderr or created.stdout).strip()[:300]
            )
        if start:
            for name in (PLAN_UNIT, RELAY_UNIT):
                enabled = run(["systemctl", "enable", "--now", name], timeout=90)
                if enabled.returncode != 0:
                    raise InstallError(
                        f"cannot enable {name}: "
                        + (enabled.stderr or enabled.stdout).strip()[:300]
                    )
            if not wait_socket(self.agent_socket):
                raise InstallError(
                    f"plan-agent socket did not appear: {self.agent_socket}"
                )
            if not wait_socket(self.relay_socket):
                raise InstallError(
                    f"edge-relay socket did not appear: {self.relay_socket}"
                )
            results["started"] = True
        else:
            results["started"] = False
        results["inspect"] = self.inspect()
        if not results["inspect"].get("ok"):
            results["ok"] = False
        return results


def _user_exists(uid: int) -> bool:
    try:
        pwd.getpwuid(uid)
    except KeyError:
        return False
    return True


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="install_tenant_agents.py", description=__doc__
    )
    parser.add_argument(
        "--check", action="store_true", help="Read-only status; no writes."
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show writes without doing them."
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    parser.add_argument(
        "--force", action="store_true", help="Replace differing unit files."
    )
    parser.add_argument(
        "--no-start", action="store_true", help="Install but do not start."
    )
    parser.add_argument("--data-root", default=DEFAULT_DATA_ROOT)
    parser.add_argument("--app-container", default=DEFAULT_APP_CONTAINER)
    parser.add_argument("--traefik-uid", type=int, default=None)
    parser.add_argument("--python", default=None, help="Interpreter used in the units.")
    parser.add_argument("--etc-dir", type=Path, default=Path("/etc/spanel"))
    parser.add_argument("--unit-dir", type=Path, default=Path("/etc/systemd/system"))
    parser.add_argument("--runtime-dir", type=Path, default=Path("/run/spanel"))
    parser.add_argument(
        "--tmpfiles-dir", type=Path, default=DEFAULT_TMPFILES_DIR
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    installer = Installer(
        data_root=args.data_root,
        app_container=args.app_container,
        traefik_uid=args.traefik_uid,
        etc_dir=args.etc_dir,
        unit_dir=args.unit_dir,
        runtime_dir=args.runtime_dir,
        tmpfiles_dir=args.tmpfiles_dir,
        python=args.python,
    )
    try:
        if args.check:
            payload = installer.inspect()
        else:
            payload = installer.install(
                dry_run=args.dry_run, force=args.force, start=not args.no_start
            )
    except InstallError as exc:
        payload = {"ok": False, "error": str(exc)}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        _print_human(payload)
    return 0 if payload.get("ok") else 1


def _print_human(payload: dict[str, Any]) -> None:
    if not payload.get("ok"):
        print(f"ERROR: {payload.get('error')}", file=sys.stderr)
        return
    print(f"repo:      {payload.get('repo', '')}")
    print(f"python:    {payload.get('python', '')}")
    print(f"app uid:   {payload.get('app_uid')}")
    print(f"traefik:   {payload.get('traefik_uid')}")
    token = payload.get("token")
    print(f"token:     {token}")
    for name, info in (payload.get("units") or {}).items():
        print(
            f"{name}: installed={info.get('installed')} "
            f"matches={info.get('matches')} active={info.get('active')}"
        )
    sockets = payload.get("sockets") or {}
    if sockets:
        print(
            f"sockets:   plan={sockets.get('plan_agent_exists')} "
            f"relay={sockets.get('edge_relay_exists')}"
        )
    capacity = payload.get("capacity")
    if capacity:
        print(f"capacity:  {capacity}")


if __name__ == "__main__":
    raise SystemExit(main())
