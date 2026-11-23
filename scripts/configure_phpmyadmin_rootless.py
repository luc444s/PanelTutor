#!/usr/bin/env python3
"""Configure the rootless phpMyAdmin broker without hardcoded addresses.

The broker needs four facts that depend on this host:

* the shared phpMyAdmin container and the network where it can reach the host;
* the PMA source IP from that network's perspective;
* a Postgres URL reachable by the *host* plan-agent (not the app container);
* the pinned connector image and the UFW rule for the relay ports.

This script discovers those facts, writes a root-only EnvironmentFile for the
plan-agent, updates the app's ``SPANEL_PHPMYADMIN_SOURCE_IP`` and restarts only
what changed. Re-run it after recreating phpMyAdmin or Postgres.

Usage (as root, from the repository):

    python3 scripts/configure_phpmyadmin_rootless.py --dry-run
    python3 scripts/configure_phpmyadmin_rootless.py
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PMA = "spanel-phpmyadmin"
DEFAULT_APP = "spanel-app-1"
DEFAULT_POSTGRES_SERVICE = "postgres"
DEFAULT_POSTGRES_CONTAINER = "spanel-postgres-1"
DEFAULT_PLAN_ENV = Path("/etc/spanel/plan-agent.env")
DEFAULT_DROPIN = Path(
    "/etc/systemd/system/spanel-plan-agent.service.d/20-pma-broker.conf"
)
DEFAULT_ENV_FILE = ROOT / ".env.docker"
DEFAULT_PYTHON = "/opt/spanel/host-venv/bin/python"
SOURCE_KEY = "SPANEL_PHPMYADMIN_SOURCE_IP"
ENV_FILE_KEY = "SPANEL_PLAN_AGENT_ENV_FILE"
BROKER_PORTS = "41000-41999"
CONNECTOR_IMAGE = (
    "alpine/socat@sha256:"
    "beb4a68d9e4fe6b0f21ea774a0fde6c31f580dde6368939ed70100c5385b015e"
)


class SetupError(RuntimeError):
    """A safe-to-print configuration failure."""


@dataclass
class Context:
    pma: str
    app: str
    postgres_service: str
    postgres_container: str
    plan_env: Path
    dropin: Path
    env_file: Path
    python: str
    pma_network: str = ""
    pma_ip: str = ""
    broker_bind: str = ""
    database_url: str = ""
    changes: list[str] = field(default_factory=list)


def run(
    argv: list[str],
    *,
    timeout: int = 60,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SetupError(f"cannot run {argv[0]}: {exc}") from exc


def docker_json(*args: str) -> Any:
    checked = run(["docker", *args])
    if checked.returncode != 0:
        detail = (checked.stderr or checked.stdout).strip()[:300]
        raise SetupError(f"docker {' '.join(args[:3])} failed: {detail}")
    try:
        return json.loads(checked.stdout or "[]")
    except ValueError as exc:
        raise SetupError("docker returned invalid JSON") from exc


def inspect(name: str) -> dict[str, Any]:
    rows = docker_json("inspect", name)
    if not isinstance(rows, list) or not rows:
        raise SetupError(f"container not found: {name}")
    return rows[0]


def is_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def pick_pma_network(info: dict[str, Any]) -> tuple[str, str, str]:
    """Return (network name, PMA IP, host-reachable gateway).

    Prefer the proxy network because it is also the edge-relay network; fall
    back to any network that has both a valid IPv4 address and gateway.
    """
    networks = (info.get("NetworkSettings") or {}).get("Networks") or {}
    candidates: list[tuple[int, str, str, str]] = []
    for name, data in networks.items():
        ip = str((data or {}).get("IPAddress") or "").strip()
        gateway = str((data or {}).get("Gateway") or "").strip()
        if not ip or not is_ipv4(ip) or not gateway or not is_ipv4(gateway):
            continue
        rank = 0 if name == "proxy" else 1
        candidates.append((rank, name, ip, gateway))
    if not candidates:
        raise SetupError("phpMyAdmin has no network with a valid IPv4 gateway")
    _rank, name, ip, gateway = sorted(candidates)[0]
    return name, ip, gateway


def env_from_container(info: dict[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in (info.get("Config") or {}).get("Env") or []:
        if "=" in raw:
            key, value = raw.split("=", 1)
            values[key] = value
    return values


def postgres_ip(service: str, fallback: str) -> str:
    """Find the Postgres container IP reachable from the host."""
    ids = run(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            f"label=com.docker.compose.service={service}",
        ]
    ).stdout.split()
    name = ids[0] if ids else fallback
    info = inspect(name)
    networks = (info.get("NetworkSettings") or {}).get("Networks") or {}
    for _name, data in sorted(networks.items()):
        ip = str((data or {}).get("IPAddress") or "").strip()
        if ip and is_ipv4(ip):
            return ip
    raise SetupError(f"cannot determine the IP of Postgres container {name}")


def host_database_url(app_url: str, ip: str) -> str:
    """Rewrite the app's Docker-DNS Postgres URL for the host process."""
    parts = urllib.parse.urlsplit(app_url)
    if not parts.scheme or not parts.hostname:
        raise SetupError(f"invalid SYSTUTOR_DATABASE_URL: {app_url!r}")
    netloc = parts.netloc
    userinfo = ""
    if "@" in netloc:
        userinfo, _host = netloc.rsplit("@", 1)
        userinfo += "@"
    port = f":{parts.port}" if parts.port else ""
    rebuilt = f"{userinfo}{ip}{port}"
    return urllib.parse.urlunsplit(
        (parts.scheme, rebuilt, parts.path, parts.query, parts.fragment)
    )


def deps_ready(python: str) -> bool:
    checked = run([python, "-c", "import sqlalchemy, psycopg"], timeout=30)
    return checked.returncode == 0


def install_deps(python: str, *, dry_run: bool) -> None:
    argv = [
        python,
        "-m",
        "pip",
        "install",
        "sqlalchemy>=2,<3",
        "psycopg[binary]>=3,<4",
    ]
    if dry_run:
        print("would install plan-agent dependencies:", " ".join(argv[3:]))
        return
    checked = run(argv, timeout=600)
    if checked.returncode != 0:
        detail = (checked.stderr or checked.stdout).strip()[-500:]
        raise SetupError(f"cannot install plan-agent dependencies: {detail}")
    if not deps_ready(python):
        raise SetupError("dependencies installed but still not importable")


def verify_database(python: str, url: str, *, dry_run: bool) -> None:
    if dry_run:
        return
    script = (
        "import sqlalchemy as sa\n"
        f"url = {url!r}\n"
        "engine = sa.create_engine(url, pool_pre_ping=True)\n"
        "with engine.connect() as conn:\n"
        "    print(conn.execute(sa.text('select 1')).scalar())\n"
    )
    checked = run([python, "-c", script], timeout=30)
    if checked.returncode != 0:
        detail = (checked.stderr or checked.stdout).strip()[-500:]
        raise SetupError(f"the host cannot reach the panel database: {detail}")


def write_if_changed(
    path: Path, content: str, *, mode: int, dry_run: bool
) -> bool:
    current = path.read_text(encoding="utf-8") if path.is_file() else ""
    if current == content:
        return False
    if dry_run:
        print(f"would write {path}")
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.chmod(mode)
    temporary.replace(path)
    return True


def render_plan_env(ctx: Context) -> str:
    return (
        "# Generated by scripts/configure_phpmyadmin_rootless.py\n"
        f"SYSTUTOR_DATABASE_URL={ctx.database_url}\n"
        f"SPANEL_DB_BROKER_BIND={ctx.broker_bind}\n"
        f"SPANEL_DB_BROKER_SOURCES={ctx.pma_ip}\n"
        f"SPANEL_PMA_CONNECTOR_IMAGE={CONNECTOR_IMAGE}\n"
        "SPANEL_PMA_CONNECTOR_READ_ONLY=false\n"
    )


def render_dropin() -> str:
    return (
        "[Service]\n"
        "# Rootless phpMyAdmin DB broker (A.SPEC 0110-B).\n"
        "EnvironmentFile=-/etc/spanel/plan-agent.env\n"
    )


def update_dotenv(path: Path, value: str, *, dry_run: bool) -> bool:
    current = path.read_text(encoding="utf-8") if path.is_file() else ""
    lines = current.splitlines()
    output: list[str] = []
    replaced = False
    for line in lines:
        if line.startswith(f"{SOURCE_KEY}="):
            if not replaced:
                output.append(f"{SOURCE_KEY}={value}")
                replaced = True
            continue
        output.append(line)
    if not replaced:
        output.append(f"{SOURCE_KEY}={value}")
    content = "\n".join(output).rstrip() + "\n"
    return write_if_changed(path, content, mode=0o600, dry_run=dry_run)


def ufw_active() -> bool:
    if shutil.which("ufw") is None:
        return False
    checked = run(["ufw", "status"])
    return checked.returncode == 0 and "Status: active" in checked.stdout


def ensure_ufw(ip: str, *, dry_run: bool) -> None:
    if not ufw_active():
        print("UFW is not active or not installed; open the broker range manually")
        return
    argv = [
        "ufw",
        "allow",
        "from",
        ip,
        "to",
        "any",
        "port",
        BROKER_PORTS.replace("-", ":"),
        "proto",
        "tcp",
        "comment",
        "spanel-pma-broker",
    ]
    if dry_run:
        print("would run:", " ".join(argv))
        return
    checked = run(argv)
    if checked.returncode != 0:
        detail = (checked.stderr or checked.stdout).strip()[:300]
        raise SetupError(f"cannot open the PMA broker range: {detail}")


def preload_connector(cells: list[str], *, dry_run: bool) -> None:
    for slug in cells:
        socket = Path("/var/lib/spanel/cells") / slug / "docker.sock"
        if not socket.exists():
            continue
        env = os.environ.copy()
        env["DOCKER_HOST"] = f"unix://{socket}"
        argv = ["docker", "image", "inspect", CONNECTOR_IMAGE]
        if run(argv, timeout=30, env=env).returncode == 0:
            continue
        if dry_run:
            print(f"would pull {CONNECTOR_IMAGE} into cell {slug}")
            continue
        pulled = run(
            ["docker", "pull", CONNECTOR_IMAGE], timeout=600, env=env
        )
        if pulled.returncode != 0:
            print(
                f"warning: could not preload {CONNECTOR_IMAGE} in {slug}: "
                f"{(pulled.stderr or pulled.stdout).strip()[:200]}"
            )


def ready_cells() -> list[str]:
    try:
        registry = json.loads(
            Path("/var/lib/spanel/registry.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return []
    return [
        str(row.get("slug"))
        for row in registry.get("allocations", {}).values()
        if row.get("state") == "ready"
    ]


def restart_plan_agent(*, dry_run: bool) -> None:
    if dry_run:
        print("would run: systemctl daemon-reload")
        print("would run: systemctl restart spanel-plan-agent")
        return
    reloaded = run(["systemctl", "daemon-reload"])
    if reloaded.returncode != 0:
        raise SetupError("systemctl daemon-reload failed")
    restarted = run(["systemctl", "restart", "spanel-plan-agent"], timeout=90)
    if restarted.returncode != 0:
        detail = (restarted.stderr or restarted.stdout).strip()[:300]
        raise SetupError(f"cannot restart spanel-plan-agent: {detail}")


def recreate_app(ctx: Context, *, dry_run: bool) -> None:
    if dry_run:
        print("would run: docker compose up -d --no-deps app apps-worker")
        return
    checked = run(
        ["docker", "compose", "up", "-d", "--no-deps", "app", "apps-worker"],
        cwd=ROOT,
        timeout=300,
    )
    if checked.returncode != 0:
        detail = (checked.stderr or checked.stdout).strip()[-400:]
        raise SetupError(f"cannot recreate app/worker: {detail}")


def app_source_ip(ctx: Context) -> str:
    try:
        info = inspect(ctx.app)
    except SetupError:
        return ""
    return env_from_container(info).get(SOURCE_KEY, "")


def configure(ctx: Context, args: argparse.Namespace) -> None:
    pma = inspect(ctx.pma)
    ctx.pma_network, ctx.pma_ip, ctx.broker_bind = pick_pma_network(pma)
    print(f"phpMyAdmin: {ctx.pma} network={ctx.pma_network} ip={ctx.pma_ip} "
          f"gateway={ctx.broker_bind}")

    app_env = env_from_container(inspect(ctx.app))
    app_url = app_env.get("SYSTUTOR_DATABASE_URL", "").strip()
    if not app_url:
        raise SetupError(f"{ctx.app} does not expose SYSTUTOR_DATABASE_URL")
    ip = postgres_ip(ctx.postgres_service, ctx.postgres_container)
    ctx.database_url = host_database_url(app_url, ip)
    print(f"postgres:  {ip}")
    print(f"plan-agent SYSTUTOR_DATABASE_URL={ctx.database_url}")

    deps_before = deps_ready(ctx.python)
    if not deps_before:
        if args.no_install_deps:
            raise SetupError(
                f"{ctx.python} lacks sqlalchemy/psycopg; rerun without "
                "--no-install-deps"
            )
        install_deps(ctx.python, dry_run=args.dry_run)
    verify_database(ctx.python, ctx.database_url, dry_run=args.dry_run)

    if write_if_changed(
        ctx.plan_env, render_plan_env(ctx), mode=0o600, dry_run=args.dry_run
    ):
        ctx.changes.append(str(ctx.plan_env))
    if write_if_changed(
        ctx.dropin, render_dropin(), mode=0o644, dry_run=args.dry_run
    ):
        ctx.changes.append(str(ctx.dropin))

    # A freshly installed dependency only becomes visible after a restart,
    # even when the EnvironmentFiles did not change.
    if ctx.changes or (not deps_before and not args.dry_run):
        restart_plan_agent(dry_run=args.dry_run)
    elif args.dry_run and not deps_before:
        restart_plan_agent(dry_run=True)

    env_changed = update_dotenv(ctx.env_file, ctx.pma_ip, dry_run=args.dry_run)
    if env_changed:
        ctx.changes.append(str(ctx.env_file))
    if env_changed or app_source_ip(ctx) != ctx.pma_ip:
        recreate_app(ctx, dry_run=args.dry_run)

    ensure_ufw(ctx.pma_ip, dry_run=args.dry_run)

    if not args.skip_connector:
        preload_connector(ready_cells(), dry_run=args.dry_run)

    if ctx.changes:
        print("changed:", ", ".join(ctx.changes))
    else:
        print("no file changes; services already configured")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pma-container", default=DEFAULT_PMA)
    p.add_argument("--app-container", default=DEFAULT_APP)
    p.add_argument("--postgres-service", default=DEFAULT_POSTGRES_SERVICE)
    p.add_argument("--postgres-container", default=DEFAULT_POSTGRES_CONTAINER)
    p.add_argument("--plan-env", type=Path, default=DEFAULT_PLAN_ENV)
    p.add_argument("--dropin", type=Path, default=DEFAULT_DROPIN)
    p.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE)
    p.add_argument("--python", default=DEFAULT_PYTHON)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-install-deps", action="store_true")
    p.add_argument("--skip-connector", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    ctx = Context(
        pma=args.pma_container,
        app=args.app_container,
        postgres_service=args.postgres_service,
        postgres_container=args.postgres_container,
        plan_env=args.plan_env,
        dropin=args.dropin,
        env_file=args.env_file,
        python=args.python,
    )
    if os.geteuid() != 0 and not args.dry_run:
        print("run as root (or use --dry-run)", file=sys.stderr)
        return 2
    try:
        configure(ctx, args)
    except SetupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
