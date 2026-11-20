#!/usr/bin/env python3
"""Black-box E2E for A.SPEC 0109-R4 on the lab host (run as root).

One script, no manual loops.  It creates an isolated environment (cloned
database, disposable app + worker + redis, real rootless tenant cell), deploys
``luc444s/software-de-gestion-para-editores`` through the real HTTP API and
Dramatiq worker, proves every release container lives in the cell's daemon
(never in the rootful daemon), probes the frontend from inside that cell,
rehearses a rollback, and cleans everything up.

Phases keep the run debuggable without hiding failures::

    python3 e2e_0109_r4_blackbox.py --stage /var/tmp/spanel-e2e-0109r4 \
        --phase all --evidence /var/tmp/0190r4.json

    --phase setup|run|cleanup|all   --keep skips cleanup on purpose.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time
import traceback
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

STAGE = Path("/var/tmp/spanel-e2e-0109r4")
SLUG = "e2e0109r4v3"
DB = "sysadmin_" + SLUG
LIVE_DB = "sysadmin"
LIVE_PG = "spanel-postgres-1"
LIVE_REDIS = "spanel-redis-1"
IMAGE = "spanel-app:latest"
PROBE_IMAGE = (
    "curlimages/curl@sha256:"
    "d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b"
)
REPOSITORY = "luc444s/software-de-gestion-para-editores"
BRANCH = "feature/workflow-diseno"
COMPOSE_FILE = "docker-compose.dokploy.yml"
STATE_FILES = (
    "/var/lib/spanel/registry.json",
    "/var/lib/spanel/plans.json",
    "/var/lib/spanel/audit.jsonl",
    "/etc/subuid",
    "/etc/subgid",
)
APP_CONTAINER = "spanel-e2e-r4-app"
WORKER_CONTAINER = "spanel-e2e-r4-worker"
REDIS_CONTAINER = "spanel-e2e-r4-redis"
PROBE_TIMEOUT = 30
RELAY_BIND = "172.25.0.1"
TRAEFIK_SOURCE = "172.25.0.3"
TRAEFIK_CONTAINER = "spanel-traefik-lab"
DYNAMIC_DIR = Path("/home/lucas/mailadmin/scripts/traefik-lab/dynamic")
PLAN_AGENT_SOCKET = "/run/spanel/plan-agent.sock"
PLAN_AGENT_TOKEN = "/run/secrets/plan_agent_token"
AGENT_TOKEN_FILE = "plan_agent_token"
LIVE_ROOTFUL_PREFIX = "software-de-gestion-para-editores-main"
CORE_CONTAINERS = (
    "spanel-traefik-lab",
    "spanel-lab-mariadb",
    "spanel-lab-phpmyadmin",
    "spanel-powerdns-lab-auth",
    "spanel-powerdns-lab-postgres",
    "spanel-mail",
)
MEMORY_PLAN = 2 * 1024 * 1024 * 1024
PER_SERVICE_MEMORY = MEMORY_PLAN // 3


def app_host_domain(slug: str) -> str:
    return f"editores-{slug}.lab"


class E2E(Exception):
    """Abort the current step with a safe message."""


def now() -> str:
    return datetime.now(UTC).isoformat()


def log(message: str) -> None:
    print(f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {message}", flush=True)


def run(
    argv: list[str],
    *,
    timeout: int = 600,
    input_text: str | None = None,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    log("$ " + " ".join(argv[:8]) + (" ..." if len(argv) > 8 else ""))
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
        raise E2E(f"{argv[0]} {argv[1:3]} failed ({completed.returncode}): {tail}")
    return completed


def docker(*args: str, timeout: int = 600, check: bool = True):
    return run(["docker", *args], timeout=timeout, check=check)


def cell_docker(slug: str, *args: str, timeout: int = 600, check: bool = True):
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
        raise E2E(f"cell {slug} is not in the registry")
    return value


def loopback_for_index(index: int) -> str:
    i = int(index) % (254**3)
    a = 1 + i % 254
    b = 1 + (i // 254) % 254
    c = 1 + (i // (254 * 254)) % 254
    return f"127.{a}.{b}.{c}"


def cell_endpoint(slug: str) -> dict[str, Any]:
    index = int(allocation(slug)["index"])
    return {
        "slug": slug,
        "index": index,
        "loopback_address": loopback_for_index(index),
        "publish_port": 20000 + index % 20000,
        "relay_port": 40000 + index,
    }


def wait_listener(address: str, port: int, timeout: float = 60.0) -> dict[str, str]:
    deadline = time.monotonic() + timeout
    needle = f"{address}:{port}"
    while time.monotonic() < deadline:
        result = run(["ss", "-ltnp"], check=False, timeout=30)
        for line in result.stdout.splitlines():
            if needle in line:
                return {"line": line.strip()}
        time.sleep(1)
    raise E2E(f"no listener on {needle} after {timeout:.0f}s")


def wait_socket(path: Path, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.5)
    raise E2E(f"socket {path} did not appear")


def start_process(
    stage: Path, name: str, argv: list[str], env: dict[str, str],
    *, uid: int | None = None,
) -> int:
    runtime = stage / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    log_path = runtime / f"{name}.log"
    log_file = log_path.open("ab")
    preexec = None
    if uid is not None:
        def preexec() -> None:  # pragma: no cover - executed in the child
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
        preexec_fn=preexec,  # noqa: PLW1509 - started before any thread exists
    )
    (runtime / f"{name}.pid").write_text(str(process.pid), encoding="utf-8")
    log(f"started {name} pid={process.pid} log={log_path}")
    return process.pid


def stop_process(stage: Path, name: str) -> str:
    path = stage / "runtime" / f"{name}.pid"
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


def agent_env(stage: Path) -> dict[str, str]:
    return {
        "PYTHONPATH": f"{stage / 'pylibs'}:{stage / 'scripts'}",
        "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS": "1",
        "SPANEL_EDGE_RELAY_BIND": RELAY_BIND,
        "SPANEL_EDGE_RELAY_SOURCES": TRAEFIK_SOURCE,
    }


def prepare_agents(stage: Path, evidence: dict[str, Any]) -> None:
    """Start a disposable plan-agent and a filtered edge relay for this cell."""
    run(["chmod", "755", str(stage)])
    for rel in ("scripts", "pylibs", "vendor"):
        path = stage / rel
        if path.exists():
            run(["chmod", "-R", "a+rX", str(path)])
    runtime = stage / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    token = stage / AGENT_TOKEN_FILE
    if not token.exists():
        token.write_text(secrets.token_hex(32), encoding="utf-8")
    token.chmod(0o600)
    registry = read_registry()
    filtered = stage / "relay-data"
    filtered.mkdir(parents=True, exist_ok=True)
    copy = dict(registry)
    copy["allocations"] = {SLUG: allocation(SLUG)}
    (filtered / "registry.json").write_text(
        json.dumps(copy, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    run(["chmod", "-R", "a+rX", str(stage / "relay-data")])
    run(["chown", "-R", "1000:1000", str(runtime)])
    run(["chmod", "755", str(runtime)])
    python = sys.executable
    env = {
        **agent_env(stage),
        "SPANEL_PLAN_AGENT_SOCKET": str(runtime / "plan-agent.sock"),
        "SPANEL_PLAN_AGENT_TOKEN_FILE": str(token),
        "SPANEL_PLAN_AGENT_ALLOWED_UIDS": "0",
    }
    plan_pid = start_process(
        stage,
        "plan-agent",
        [python, str(stage / "scripts" / "spanel_tenant.py"),
         "plan-agent", "--data-root", "/var/lib/spanel"],
        env,
    )
    wait_socket(runtime / "plan-agent.sock")
    (runtime / "plan-agent.sock").chmod(0o666)
    relay_python = "/home/lucas/mailadmin/.venv/bin/python"
    if not Path(relay_python).exists():
        relay_python = python
    relay_env = {
        **agent_env(stage),
        "SPANEL_EDGE_RELAY_SOCKET": str(runtime / "edge-relay.sock"),
        "SPANEL_TRAEFIK_UID": "1000",
    }
    relay_pid = start_process(
        stage,
        "edge-relay",
        [relay_python, str(stage / "scripts" / "spanel_tenant.py"),
         "edge-relay", "--data-root", str(stage / "relay-data"),
         "--bind", RELAY_BIND],
        relay_env,
        uid=1000,
    )
    endpoint = cell_endpoint(SLUG)
    listener = wait_listener(RELAY_BIND, endpoint["relay_port"], 90)
    evidence["agents"] = {
        "plan_agent": {"pid": plan_pid, "socket": PLAN_AGENT_SOCKET},
        "edge_relay": {
            "pid": relay_pid,
            "bind": RELAY_BIND,
            "source": TRAEFIK_SOURCE,
            "relay_port": endpoint["relay_port"],
            "listener": listener["line"],
        },
        "token_sha256": hashlib.sha256(token.read_bytes()).hexdigest(),
    }



def psql(db: str, sql: str, timeout: int = 120) -> str:
    out = docker(
        "exec", LIVE_PG, "psql", "-U", "postgres", "-d", db, "-tA", "-v",
        "ON_ERROR_STOP=1", "-c", sql, timeout=timeout,
    )
    return out.stdout.strip()


def env_file(keys: dict[str, str]) -> str:
    return "\n".join(f"{key}={value}" for key, value in keys.items()) + "\n"


def load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def evidence_write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n")
    path.chmod(0o600)


# --------------------------------------------------------------------------
# setup
# --------------------------------------------------------------------------


def stage_tree(stage: Path) -> Path:
    """Stage the working tree (already uploaded) and install the cell CLI deps."""
    if not (stage / "scripts" / "tenant_cell" / "cli.py").exists():
        raise E2E(f"stage tree is incomplete at {stage}")
    if not (stage / "vendor" / "systutor-core" / "src" / "systutor").exists():
        raise E2E(f"stage vendor tree is incomplete at {stage}")
    pylibs = stage / "pylibs"
    if not (pylibs / "typer").exists():
        run(
            [sys.executable, "-m", "pip", "install", "--quiet", "--target",
             str(pylibs), "typer>=0.12"],
            timeout=600,
        )
    return stage


def backup_state(stage: Path) -> dict[str, str]:
    backup = stage / "backup"
    backup.mkdir(parents=True, exist_ok=True)
    hashes: dict[str, str] = {}
    for item in STATE_FILES:
        source = Path(item)
        if not source.exists():
            continue
        target = backup / source.name
        # Keep the first (pre-run) snapshot across restarted phases.
        if not target.exists():
            shutil.copy2(source, target)
        hashes[item] = run(["sha256sum", str(target)]).stdout.split()[0]
    return hashes


def clone_database() -> None:
    log(f"cloning {LIVE_DB} -> {DB}")
    psql(LIVE_DB, 'SELECT pg_terminate_backend(pid) FROM pg_stat_activity '
                  "WHERE datname = current_database() AND pid <> pg_backend_pid();")
    psql(LIVE_DB, f'DROP DATABASE IF EXISTS "{DB}" WITH (FORCE);')
    psql(LIVE_DB, f'CREATE DATABASE "{DB}";')
    # Plain SQL keeps the transfer text-safe through docker exec stdin.
    dump = docker("exec", LIVE_PG, "pg_dump", "-U", "postgres", "--no-owner",
                  "--no-privileges", LIVE_DB, timeout=1800)
    restore = run(
        ["docker", "exec", "-i", LIVE_PG, "psql", "-U", "postgres", "-d", DB,
         "-v", "ON_ERROR_STOP=0", "-q"],
        input_text=dump.stdout,
        timeout=1800,
        check=False,
    )
    if restore.returncode != 0:
        raise E2E(f"psql restore failed: {(restore.stderr or '').strip()[-500:]}")
    owners = psql(DB, "SELECT slug FROM tenants ORDER BY created_at LIMIT 1;")
    if owners != "demo":
        raise E2E(f"unexpected live tenant layout: {owners!r}")
    psql(DB, f"UPDATE tenants SET slug = '{SLUG}' WHERE slug = 'demo';")
    # The clone may carry hundreds of pending outbox rows from the live
    # tenant.  They belong to other apps/domains and must never be replayed
    # against the live Traefik directory from this disposable run.
    psql(
        DB,
        "UPDATE event_outbox SET status = 'processed', processed_at = NOW(), "
        "error_message = NULL WHERE status IN ('pending', 'failed');",
    )
    log("disposable tenant slug updated; clone outbox isolated")


def provision_cell(stage: Path) -> dict[str, Any]:
    cli = stage / "scripts" / "spanel_tenant.py"
    env = {
        "PYTHONPATH": f"{stage / 'pylibs'}:{stage / 'scripts'}",
        "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS": "1",
        "SPANEL_TENANT_CELL_DNS": "192.168.18.1",
    }
    socket = Path(f"/var/lib/spanel/cells/{SLUG}/docker.sock")
    deadline = time.monotonic() + 180
    last: dict[str, Any] = {}
    # Provisioning starts the user unit asynchronously and may observe the
    # daemon one instant too early.  Re-running provision is idempotent and
    # refreshes the stored state from live host evidence.
    while time.monotonic() < deadline:
        result = run([sys.executable, str(cli), "provision", "--slug", SLUG,
                      "--json"], timeout=600, env=env, check=False)
        if result.returncode == 0:
            last = json.loads(result.stdout.strip().splitlines()[-1])
            if last.get("state") == "ready" and socket.exists():
                return last
        time.sleep(3)
    raise E2E(f"cell did not become ready: {last}")


def write_runtime_env(stage: Path, live_env: Path) -> tuple[Path, dict[str, str]]:
    values = load_dotenv(live_env)
    database_url = values["SYSTUTOR_DATABASE_URL"]
    if "/" + LIVE_DB not in database_url:
        raise E2E("live database URL does not reference the live database")
    database_url = database_url.replace("/" + LIVE_DB, "/" + DB)
    values["SYSTUTOR_DATABASE_URL"] = database_url
    values["SYSTUTOR_REDIS_URL"] = f"redis://{REDIS_CONTAINER}:6379/0"
    values["SPANEL_APPS_STATE_ROOT"] = str(stage / "state")
    values["SPANEL_DOCKER_TRANSPORT"] = "local"
    values["SPANEL_PLAN_AGENT_SOCKET"] = PLAN_AGENT_SOCKET
    values["SPANEL_PLAN_AGENT_TOKEN_FILE"] = PLAN_AGENT_TOKEN
    values["SPANEL_ROOTLESS_ROUTES_HTTPS"] = "false"
    values["SPANEL_TENANTS_ROOTLESS"] = "true"
    values["SPANEL_TENANTS_DATA_ROOT"] = "/var/lib/spanel"
    values["SPANEL_APPS_PROBE_BASELINE"] = "rootless"
    values["SPANEL_APPS_PROBE_STARTUP_SECONDS"] = "300"
    values["SPANEL_APPS_PROBE_TIMEOUT_SECONDS"] = "15"
    values.setdefault("SPANEL_DOMAINS_PROFILE", "internal")
    values["SPANEL_PROXY_TRANSPORT"] = "local"
    values["SPANEL_PROXY_CONFIG_DIR"] = str(DYNAMIC_DIR)
    values["SPANEL_PROXY_BACKUPS_DIR"] = str(stage / "proxy-backups")
    values["SPANEL_PROXY_LOG"] = "/tmp/spanel-proxy.log"
    values["SPANEL_PROXY_HTTP_PORT"] = "9080"
    values["SPANEL_PROXY_HTTPS_PORT"] = "9443"
    values["SPANEL_PROXY_TRAEFIK_CONTAINER"] = TRAEFIK_CONTAINER
    values["SPANEL_PROXY_NETWORK"] = "spanel-traefik-lab"
    values["SPANEL_PROXY_REPO_ROOT"] = "/stage"
    (stage / "proxy-backups").mkdir(parents=True, exist_ok=True)
    (stage / "state").mkdir(parents=True, exist_ok=True)
    target = stage / "app.env"
    target.write_text(env_file(values))
    target.chmod(0o600)
    return target, values


def _mounts(stage: Path, live_env: dict[str, str]) -> list[str]:
    key = live_env.get("SPANEL_APPS_ENCRYPTION_KEY_PATH", "")
    key_path = str(Path(key).expanduser()) if key else ""
    # The state root is mounted at its host path: the cell daemon resolves bind
    # sources on the host, so container and host paths must be identical.
    mounts = [
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{stage / 'state'}:{stage / 'state'}",
        "-v", f"{stage}:/stage:ro",
        "-v", f"{stage / 'runtime'}:/run/spanel:ro",
        "-v", f"{stage / AGENT_TOKEN_FILE}:{PLAN_AGENT_TOKEN}:ro",
        "-v", f"{DYNAMIC_DIR}:{DYNAMIC_DIR}:rw",
        "-v", f"{stage / 'proxy-backups'}:{stage / 'proxy-backups'}:rw",
        "-v", (
            f"{stage / 'vendor' / 'systutor-core' / 'src'}:"
            "/app/vendor/systutor-core/src:ro"
        ),
        "-v", f"{stage / 'vendor' / 'systutor-core' / 'plugins'}:/app/plugins:ro",
        "-v", "/var/lib/spanel/cells:/var/lib/spanel/cells:ro",
    ]
    if key_path and Path(key_path).exists():
        mounts += ["-v", f"{key_path}:/run/secrets/apps_key:ro"]
    return mounts


def start_worker(
    stage: Path, runtime_env: Path, live_env: dict[str, str], *,
    rootless: bool = True,
) -> None:
    """Start only the Dramatiq worker (used by restart-recovery drills)."""
    mode = "true" if rootless else "false"
    baseline = "rootless" if rootless else "hardened"
    docker("rm", "-f", WORKER_CONTAINER, check=False)
    docker(
        "run", "-d", "--network", "spanel_default",
        "--env-file", str(runtime_env),
        "-e", "PYTHONPATH=/app/vendor/systutor-core/src:/app/vendor/systutor-core:/app",
        "-e", f"SPANEL_TENANTS_ROOTLESS={mode}",
        "-e", f"SPANEL_APPS_PROBE_BASELINE={baseline}",
        "-e", f"SPANEL_PLAN_AGENT_SOCKET={PLAN_AGENT_SOCKET}",
        *_mounts(stage, live_env),
        "--name", WORKER_CONTAINER,
        IMAGE, "python", "/stage/scripts/e2e_dramatiq_worker.py",
        "--processes", "1", "--threads", "1", "--queues", "apps",
    )


def start_stack(
    stage: Path, runtime_env: Path, live_env: dict[str, str], *,
    rootless: bool = True,
) -> None:
    # The cell daemon runs as the tenant user and must be able to traverse and
    # read bind sources, while ``app.env`` (secrets) stays mode 0600.
    run(["chmod", "755", str(stage)])
    for rel in ("state", "vendor", "scripts", "pylibs", "runtime"):
        path = stage / rel
        if path.exists():
            run(["chmod", "-R", "a+rX", str(path)])
    run(["chmod", "600", str(stage / AGENT_TOKEN_FILE)])
    run(["chmod", "600", str(runtime_env)])
    for name in (APP_CONTAINER, WORKER_CONTAINER, REDIS_CONTAINER):
        docker("rm", "-f", name, check=False)
    docker("run", "-d", "--name", REDIS_CONTAINER, "--network", "spanel_default",
           "redis:7-alpine")
    mode = "true" if rootless else "false"
    baseline = "rootless" if rootless else "hardened"
    common = [
        "-d", "--network", "spanel_default", "--env-file", str(runtime_env),
        "-e", "PYTHONPATH=/app/vendor/systutor-core/src:/app/vendor/systutor-core:/app",
        "-e", f"SPANEL_TENANTS_ROOTLESS={mode}",
        "-e", f"SPANEL_APPS_PROBE_BASELINE={baseline}",
        "-e", f"SPANEL_PLAN_AGENT_SOCKET={PLAN_AGENT_SOCKET}",
        *_mounts(stage, live_env),
    ]
    docker("run", *common, "--name", APP_CONTAINER,
           "-p", "127.0.0.1:3010:3000", IMAGE)
    start_worker(stage, runtime_env, live_env, rootless=rootless)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        probe = run(
            ["curl", "-fsS", "-o", "/dev/null", "http://127.0.0.1:3010/api/v1/system/health"],
            timeout=10, check=False,
        )
        if probe.returncode == 0:
            log(f"disposable API is healthy (rootless={rootless})")
            return
        time.sleep(3)
    logs = docker("logs", "--tail", "60", APP_CONTAINER, check=False)
    raise E2E(f"disposable API did not become healthy: {logs.stdout[-1500:]}")


def setup(stage: Path, evidence: dict[str, Any]) -> None:
    stage_tree(stage)
    evidence["host_facts"] = _host_facts()
    evidence["code_hashes"] = _code_hashes(stage)
    evidence["state_hashes_before"] = backup_state(stage)
    evidence["host_nat_before"] = run(
        ["iptables", "-t", "nat", "-S", "POSTROUTING"], check=False
    ).stdout.splitlines()
    evidence["dmesg_denied_before"] = _dmesg_denied()
    evidence["rootful_fixture_before"] = _rootful_fixture()
    evidence["core_before"] = _core_snapshot()
    evidence["other_tenants_before"] = _other_tenant_status()
    clone_database()
    evidence["cell"] = provision_cell(stage)
    live_env_path = Path("/home/lucas/mailadmin/.env.docker")
    runtime_env, live_env = write_runtime_env(stage, live_env_path)
    prepare_agents(stage, evidence)
    evidence["runtime"] = {
        "database": DB,
        "redis": REDIS_CONTAINER,
        "rootless": True,
        "probe_baseline": "rootless",
        "cell_socket": f"/var/lib/spanel/cells/{SLUG}/docker.sock",
        "plan_agent_socket": PLAN_AGENT_SOCKET,
        "relay_bind": RELAY_BIND,
        "relay_source": TRAEFIK_SOURCE,
    }
    start_stack(stage, runtime_env, live_env, rootless=True)
    log("setup complete; keep resources for the run phase")


def _dmesg_denied() -> int:
    result = run(
        ["bash", "-lc", "dmesg 2>/dev/null | grep -c DENIED || true"], check=False
    )
    text = result.stdout.strip()
    return int(text) if text.isdigit() else 0


def _rootful_fixture() -> dict[str, Any]:
    result = docker(
        "ps", "-a", "--format", "{{.Names}}\t{{.ID}}\t{{.Status}}", check=False
    )
    rows: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0].startswith(LIVE_ROOTFUL_PREFIX):
            rows[parts[0]] = f"{parts[1]} {parts[2]}"
    return rows


def _core_snapshot() -> dict[str, str]:
    result = docker(
        "ps", "-a", "--format", "{{.Names}}\t{{.ID}}\t{{.Status}}", check=False
    )
    rows: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0] in CORE_CONTAINERS:
            rows[parts[0]] = f"{parts[1]} {parts[2]}"
    return rows


def _other_tenant_status() -> dict[str, str]:
    result = run(
        ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
         "--connect-timeout", "5", "--max-time", "10",
         "-H", "Host: spanel.lab", "http://127.0.0.1:9080/"],
        check=False,
    )
    return {"spanel.lab": result.stdout.strip() or "no-response"}


def _code_hashes(stage: Path) -> dict[str, str]:
    paths = (
        "scripts/tenant_cell/executor.py",
        "scripts/tenant_cell/cells.py",
        "scripts/tenant_cell/host_agent.py",
        "scripts/tenant_cell/network.py",
        "vendor/systutor-core/plugins/domains/migrations/005_rootless_app_hosts.py",
        "vendor/systutor-core/src/systutor/contracts/app_hosts.py",
        "vendor/systutor-core/plugins/apps/backend/rootless_routes.py",
        "vendor/systutor-core/plugins/apps/backend/worker.py",
        "vendor/systutor-core/plugins/apps/backend/runtime/deployment.py",
        "vendor/systutor-core/plugins/apps/backend/runtime/probes.py",
        "vendor/systutor-core/plugins/apps/backend/releases/execution.py",
        "vendor/systutor-core/plugins/apps/backend/releases/scoped_execution.py",
    )
    values: dict[str, str] = {}
    for rel in paths:
        path = stage / rel
        if path.exists():
            values[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def _host_facts() -> dict[str, str]:
    return {
        "hostname": os.uname().nodename,
        "kernel": os.uname().release,
        "docker": run(
            ["docker", "version", "--format", "{{.Server.Version}}"], check=False
        ).stdout.strip(),
        "apparmor": run(
            ["aa-status", "--enabled"], check=False
        ).stdout.strip() or "unknown",
        "cgroups": run(
            ["bash", "-lc", "stat -fc %T /sys/fs/cgroup"], check=False
        ).stdout.strip(),
    }


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------


def api_module():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import e2e_apps_api

    return e2e_apps_api


def login(email: str, password: str):
    api = api_module()
    client = api.ApiClient("http://127.0.0.1:3010")
    body = client.request("POST", "/api/v1/auth/login",
                          {"email": email, "password": password})
    token = body.get("access_token") if isinstance(body, dict) else None
    if not token:
        raise E2E("login did not return an access token")
    client.token = token
    return client


def find_repository(client) -> tuple[str, str]:
    api = api_module()
    return api.find_repository(client)


def create_application(client) -> dict[str, Any]:
    installation_id, repository_id = find_repository(client)
    suffix = secrets.token_hex(4)
    app = client.request(
        "POST", "/api/v1/plugins/apps/applications",
        {
            "name": f"E2E Software Editores {suffix}",
            "installation_id": installation_id,
            "repository_id": repository_id,
            "branch": BRANCH,
            "compose_file": COMPOSE_FILE,
        },
    )
    if not isinstance(app, dict) or not app.get("id"):
        raise E2E("application creation returned an invalid response")
    return app


def deploy(client, api, app_id: str, environment: list[list[str]],
           timeout: int) -> dict[str, Any]:
    root = f"/api/v1/plugins/apps/applications/{app_id}"
    return api.queue(client, "POST", f"{root}/deployments",
                     {"environment": environment}, timeout, "deploy")


def service_details(detail: dict[str, Any]) -> list[dict[str, Any]]:
    active = detail.get("active_deployment") or {}
    services = active.get("service_details")
    if not isinstance(services, list) or not services:
        raise E2E("deployment does not expose service details")
    return [item for item in services if isinstance(item, dict)]


def verify_in_cell(slug: str, detail: dict[str, Any],
                   evidence: dict[str, Any]) -> dict[str, Any]:
    cell_socket = f"/var/lib/spanel/cells/{slug}/docker.sock"
    containers: dict[str, Any] = {}
    active = detail.get("active_deployment") or {}
    network = ""
    for item in service_details(detail):
        name = str(item.get("name"))
        cid = item.get("container_id")
        if not isinstance(cid, str) or not cid:
            raise E2E(f"service {name} has no container identity")
        inspected = cell_docker(
            slug, "inspect", cid,
            "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}"
                        "{{else}}none{{end}}|{{.HostConfig.NetworkMode}}"
                        "|{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}"
                        "|{{.HostConfig.PidsLimit}}|{{json .HostConfig.PortBindings}}",
        )
        fields = inspected.stdout.strip().split("|", 6)
        if len(fields) != 7:
            raise E2E(f"could not inspect cell container {name}: {inspected.stdout!r}")
        state, health, mode, memory, nano_cpus, pids, bindings_raw = fields
        if state != "running":
            raise E2E(f"cell container {name} is {state}, not running")
        if health not in {"healthy", "none"}:
            raise E2E(f"cell container {name} health is {health}")
        network = network or mode
        rootful = docker("inspect", cid, check=False)
        if rootful.returncode == 0:
            raise E2E(f"container {name} also exists in the rootful daemon")
        try:
            port_bindings = json.loads(bindings_raw or "{}")
        except json.JSONDecodeError:
            port_bindings = {}
        containers[name] = {
            "container_id": cid,
            "image_id": item.get("image_id"),
            "state": state,
            "health": health,
            "network": mode,
            "daemon": cell_socket,
            "absent_from_rootful": True,
            "host_config": {
                "memory": int(memory) if memory.isdigit() else 0,
                "nano_cpus": int(nano_cpus) if nano_cpus.isdigit() else 0,
                "pids_limit": int(pids) if pids.isdigit() else 0,
                "port_bindings": port_bindings,
            },
        }
    if not network:
        raise E2E("could not resolve the release network")
    evidence["containers"] = containers
    evidence["network"] = network
    evidence["active_deployment"] = active.get("id")
    return containers


def probe_frontend(slug: str, network: str) -> dict[str, Any]:
    result = cell_docker(
        slug, "run", "--rm", "--network", network, "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--pids-limit", "64",
        "--memory", "128m", "--cpus", "1", "--user", "65534:65534",
        PROBE_IMAGE, "curl", "-sS", "-o", "/dev/null", "--write-out",
        "%{http_code}", "--connect-timeout", "5", "--max-time", "15",
        "http://frontend:8080/", timeout=PROBE_TIMEOUT,
    )
    status = result.stdout.strip()
    if status != "200":
        raise E2E(f"frontend readiness probe returned {status!r}")
    return {"http_status": status, "target": "http://frontend:8080/"}


def _operation_payload(operation: dict[str, Any]) -> dict[str, Any]:
    result = operation.get("result")
    return result if isinstance(result, dict) else operation


def _dockerd_pid(uid: int, fallback: int | None = None) -> int:
    found = run(["pgrep", "-u", str(uid), "-x", "dockerd"], check=False).stdout.split()
    for value in reversed(found):
        if value.isdigit():
            return int(value)
    return int(fallback or 0)


def _cgroup_limits(uid: int) -> dict[str, str]:
    base = Path(
        f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service"
    )
    values: dict[str, str] = {}
    for name in ("memory.max", "cpu.max", "pids.max"):
        path = base / name
        values[name] = path.read_text(encoding="utf-8").strip() if path.exists() else ""
    return values


def check_egress(stage: Path, evidence: dict[str, Any]) -> None:
    """Check 1: egress lives in the cell netns; no host rule, no manual NAT."""
    log("check 1/4: egress without manual NAT")
    alloc = allocation(SLUG)
    uid = int(alloc["uid"])
    pid = _dockerd_pid(uid, alloc.get("daemon_pid"))
    if pid <= 0 or not Path(f"/proc/{pid}").exists():
        raise E2E("cell dockerd is not running")
    net_cell = os.readlink(f"/proc/{pid}/ns/net")
    net_host = os.readlink("/proc/1/ns/net")
    inside = run(
        ["nsenter", "-t", str(pid), "-n", "iptables", "-t", "nat",
         "-S", "POSTROUTING"], check=False,
    )
    host_after = run(
        ["iptables", "-t", "nat", "-S", "POSTROUTING"], check=False
    ).stdout.splitlines()
    cell_rule = any(
        re.fullmatch(
            r"-A POSTROUTING -s 172\.17\.0\.0/16 -j MASQUERADE",
            line.strip(),
        )
        for line in inside.stdout.splitlines()
    )
    host_simple = any(
        line.strip() == "-A POSTROUTING -s 172.17.0.0/16 -j MASQUERADE"
        for line in host_after
    )
    unit = Path(f"/etc/systemd/user/spanel-cell-{SLUG}.service")
    unit_text = unit.read_text(encoding="utf-8") if unit.exists() else ""
    egress = cell_docker(
        SLUG, "run", "--rm", "alpine:3.20", "sh", "-c",
        "wget -q -O /dev/null https://registry.npmjs.org/vite && echo NET_OK",
        timeout=240, check=False,
    )
    dmesg_after = _dmesg_denied()
    profile = Path(f"/etc/apparmor.d/spanel-cell-{SLUG}")
    profile_text = profile.read_text(encoding="utf-8") if profile.exists() else ""
    audit_deny = sum(
        1 for line in profile_text.splitlines()
        if line.strip().startswith("audit deny")
    )
    passed = (
        net_cell != net_host
        and cell_rule
        and not host_simple
        and "NET_OK" in egress.stdout
        and "ExecStartPost" not in unit_text
        and "ExecStopPost" not in unit_text
        and "--iptables=false" in unit_text
        and "--ip6tables=false" in unit_text
        and audit_deny >= 8
        and dmesg_after <= evidence.get("dmesg_denied_before", dmesg_after)
    )
    evidence["checks"]["egress_without_manual_nat"] = {
        "pass": passed,
        "uid": uid,
        "dockerd_pid": pid,
        "netns_cell": net_cell,
        "netns_host": net_host,
        "cell_postrouting": inside.stdout.splitlines(),
        "host_postrouting": host_after,
        "host_rule_absent": not host_simple,
        "egress_exit": egress.returncode,
        "egress_output": (egress.stdout or egress.stderr).strip()[-400:],
        "unit": str(unit),
        "unit_has_exec_post": "ExecStartPost" in unit_text or "ExecStopPost" in unit_text,
        "iptables_false": "--iptables=false" in unit_text,
        "ip6tables_false": "--ip6tables=false" in unit_text,
        "audit_deny_rules": audit_deny,
        "dmesg_denied_before": evidence.get("dmesg_denied_before"),
        "dmesg_denied_after": dmesg_after,
    }
    if not passed:
        raise E2E("check 1 failed; see evidence")


def apply_plan(client, evidence: dict[str, Any]) -> None:
    """Check 2 (first half): the 2 GiB aggregate plan is applied before deploy."""
    log("check 2/4: apply the 2 GiB aggregate plan")
    plan = client.request(
        "POST", "/api/v1/plugins/apps/plan",
        {"memory_bytes": MEMORY_PLAN, "cpus": 1, "pids": 512},
    )
    verified: dict[str, Any] | None = None
    verify_error: str | None = None
    for _attempt in range(4):
        try:
            verified = client.request(
                "POST", "/api/v1/plugins/apps/plan/verify"
            )
            if isinstance(verified, dict) and verified.get("ok") is True:
                break
        except Exception as exc:  # noqa: BLE001 - the cgroup is the real check
            verify_error = str(exc)
        time.sleep(3)
    uid = int(allocation(SLUG)["uid"])
    limits = _cgroup_limits(uid)
    passed = (
        isinstance(plan, dict)
        and plan.get("status") == "applied"
        and limits["memory.max"] == str(MEMORY_PLAN)
        and limits["pids.max"] == "512"
    )
    evidence["checks"]["aggregate_2gb_from_first_deploy"] = {
        "pass": passed,
        "plan": plan,
        "verify": verified,
        "verify_error": verify_error,
        "cgroup_uid": uid,
        "cgroup_limits_before_deploy": limits,
    }
    if not passed:
        raise E2E("check 2 plan application failed; see evidence")


def _manifest(active_id: str) -> dict[str, Any]:
    raw = psql(
        DB, f"SELECT manifest::text FROM apps_deployments WHERE id = '{active_id}';"
    )
    if not raw:
        raise E2E("active deployment has no manifest")
    value = json.loads(raw)
    return value if isinstance(value, dict) else {}


def verify_deploy(
    slug: str, detail: dict[str, Any], operation: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Check 2 (second half): 3 services, 2 GiB split, all in the cell."""
    log("check 2/4: verify the rootless deployment and aggregate limits")
    active = detail.get("active_deployment") or {}
    active_id = active.get("id")
    if not isinstance(active_id, str) or not active_id:
        raise E2E("deployment did not activate")
    containers = verify_in_cell(slug, detail, evidence)
    manifest = _manifest(active_id)
    probes = manifest.get("probes") if isinstance(manifest.get("probes"), dict) else {}
    services = manifest.get("service_details") or {}
    del services
    uid = int(allocation(slug)["uid"])
    limits = _cgroup_limits(uid)
    payload = _operation_payload(operation)
    effective = payload.get("scope", {}).get("effective_services") if isinstance(
        payload.get("scope"), dict
    ) else None
    memory_values = {
        name: item.get("host_config", {}).get("memory")
        for name, item in containers.items()
    }
    passed = (
        len(containers) == 3
        and all(value == PER_SERVICE_MEMORY for value in memory_values.values())
        and limits["memory.max"] == str(MEMORY_PLAN)
        and limits["pids.max"] == "512"
    )
    evidence["checks"]["aggregate_2gb_from_first_deploy"].update({
        "pass": passed,
        "active_deployment": active_id,
        "effective_services": effective,
        "containers": sorted(containers),
        "per_service_memory": memory_values,
        "expected_per_service_memory": PER_SERVICE_MEMORY,
        "manifest_probes": probes,
        "cgroup_limits_after_deploy": limits,
        "deploy_operation": {
            "status": operation.get("status"),
            "phase": operation.get("phase"),
            "result": payload,
        },
    })
    if not passed:
        raise E2E("check 2 deployment limits did not converge; see evidence")
    return manifest


def _write_dispatch_script(stage: Path) -> Path:
    path = stage / "dispatch_outbox.py"
    path.write_text(
        "\n".join([  # noqa: FLY002 - generated script is clearer as lines
            "import json",
            "from app.main import app",
            "from systutor.core.config import get_settings",
            "from systutor.core.database import build_session_factory",
            "factory = build_session_factory(get_settings())",
            "batches = []",
            "with factory() as db:",
            "    for _attempt in range(20):",
            "        result = app.state.event_bus.dispatch_pending(",
            "            db, limit=200, max_retries=3",
            "        )",
            "        db.commit()",
            "        batches.append(result)",
            "        if not result.get('processed'):",
            "            break",
            "print(json.dumps({'batches': batches, 'processed': sum(",
            "    int(item.get('processed', 0)) for item in batches",
            ")}, sort_keys=True))",
        ]) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o644)
    return path


def dispatch_outbox(stage: Path) -> dict[str, Any]:
    script = _write_dispatch_script(stage)
    # The stage is mounted at /stage inside the disposable app; the host path
    # is not visible there.
    result = run(
        ["docker", "exec", APP_CONTAINER, "python",
         f"/stage/{script.name}"],
        timeout=180, check=False,
    )
    text = (result.stdout or "").strip().splitlines()
    for line in reversed(text):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return {
        "returncode": result.returncode,
        "stdout": result.stdout[-800:],
        "stderr": result.stderr[-800:],
    }


def publish_app_host(
    client, app_id: str, domain: str, evidence: dict[str, Any]
) -> dict[str, Any]:
    log("check 3/4: publish the domains-owned Host")
    created = client.request(
        "POST", "/api/v1/plugins/domains/app-hosts",
        {
            "application_id": app_id,
            "service": "frontend",
            "domain": domain,
            "https": False,
        },
    )
    if not isinstance(created, dict) or created.get("domain") != domain:
        raise E2E("app-host creation did not return the requested Host")
    evidence["app_host"] = created
    return created


def _route_documents(domain: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if not DYNAMIC_DIR.exists():
        return found
    for path in sorted(DYNAMIC_DIR.glob("spanel-*.yml")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if domain in text:
            found.append({
                "path": str(path),
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
                "content": text,
            })
    return found


def check_route(
    stage: Path, client, app_id: str, evidence: dict[str, Any]
) -> None:
    domain = app_host_domain(SLUG)
    publish_app_host(client, app_id, domain, evidence)
    dispatched = dispatch_outbox(stage)
    endpoint = cell_endpoint(SLUG)
    deadline = time.monotonic() + 90
    documents: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        documents = _route_documents(domain)
        if documents:
            break
        time.sleep(2)
    relay_listener = wait_listener(RELAY_BIND, endpoint["relay_port"], 30)
    loop_listener = wait_listener(
        endpoint["loopback_address"], endpoint["publish_port"], 30
    )
    backend = f"{RELAY_BIND}:{endpoint['relay_port']}"
    document_ok = bool(documents) and any(
        backend in item["content"] for item in documents
    )
    body_path = Path("/var/tmp/0109-r4-route-body.html")
    status = ""
    body = b""
    http_deadline = time.monotonic() + 60
    while time.monotonic() < http_deadline:
        curl = run(
            ["curl", "-sS", "-o", str(body_path), "-w", "%{http_code}",
             "--connect-timeout", "5", "--max-time", "20",
             "-H", f"Host: {domain}", "http://127.0.0.1:9080/"],
            check=False,
        )
        status = curl.stdout.strip()
        body = body_path.read_bytes() if body_path.exists() else b""
        if status == "200" and body:
            break
        time.sleep(3)
    passed = (
        isinstance(dispatched, dict)
        and int(dispatched.get("processed", 0)) > 0
        and document_ok
        and status == "200"
        and len(body) > 0
        and "socat" not in loop_listener["line"].lower()
    )
    evidence["checks"]["published_route_no_bridge"] = {
        "pass": passed,
        "domain": domain,
        "endpoint": endpoint,
        "outbox_dispatch": dispatched,
        "route_documents": documents,
        "relay_listener": relay_listener["line"],
        "cell_listener": loop_listener["line"],
        "backend": backend,
        "http_status": status,
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest() if body else "",
        "body_preview": body[:300].decode("utf-8", "replace"),
        "manual_tcp_bridge": False,
    }
    if not passed:
        raise E2E("check 3 route did not converge; see evidence")


def runtime_rows(app_id: str) -> list[str]:
    tenant_id = psql(
        DB, f"SELECT tenant_id FROM apps_applications WHERE id = '{app_id}';"
    )
    if not tenant_id:
        return []
    raw = psql(
        DB,
        "SELECT resource_id || '=' || runtime FROM tenant_resource_runtimes "
        f"WHERE tenant_id = '{tenant_id}' AND kind = 'app' "
        f"AND resource_id LIKE '{app_id}:%' ORDER BY resource_id;",
    )
    return [line for line in raw.splitlines() if line.strip()]


def check_rollback(
    client, app_id: str, first: dict[str, Any], evidence: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Check 4: real second deploy, rollback restores previous release/runtime."""
    log("check 4/4: second rootless deploy and rollback rehearsal")
    root = f"/api/v1/plugins/apps/applications/{app_id}"
    api = api_module()
    first_id = first["id"]
    first_release = first["release"]
    deploy_environment = api.environment()
    second_op = deploy(client, api, app_id, deploy_environment, args.deploy_timeout)
    detail = client.request("GET", root)
    second = detail.get("active_deployment") or {}
    if not second.get("id") or second.get("id") == first_id:
        raise E2E("second deployment did not activate a new deployment")
    verify_in_cell(args.slug, detail, evidence)
    runtime_before = runtime_rows(app_id)
    rollback_op = api.queue(
        client, "POST", f"{root}/rollback",
        {"to_deployment_id": first_id}, args.deploy_timeout, "rollback",
    )
    detail = client.request("GET", root)
    restored = detail.get("active_deployment") or {}
    verify_in_cell(args.slug, detail, evidence)
    runtime_after = runtime_rows(app_id)
    route_after = _route_documents(app_host_domain(args.slug))
    rootful_after = _rootful_fixture()
    passed = (
        restored.get("release") == first_release
        and restored.get("commit") == first.get("commit")
        and runtime_before == runtime_after
        and bool(runtime_after)
        and any(row.endswith("=rootless") for row in runtime_after)
        and bool(route_after)
        and rootful_after == evidence.get("rootful_fixture_before")
    )
    evidence["checks"]["rollback_rehearsal"] = {
        "pass": passed,
        "first_deployment": first_id,
        "second_deployment": second.get("id"),
        "restored_deployment": restored.get("id"),
        "restored_release": restored.get("release"),
        "restored_commit": restored.get("commit"),
        "runtime_before_rollback": runtime_before,
        "runtime_after_rollback": runtime_after,
        "route_documents_after": [item["path"] for item in route_after],
        "rootful_fixture_before": evidence.get("rootful_fixture_before"),
        "rootful_fixture_after": rootful_after,
        "second_operation": _operation_payload(second_op),
        "rollback_operation": _operation_payload(rollback_op),
    }
    if not passed:
        raise E2E("check 4 rollback did not converge; see evidence")
    return detail


def check_flag_false(
    stage: Path, client, app_id: str, detail: dict[str, Any],
    evidence: dict[str, Any],
) -> None:
    """The flag must not rewrite runtime records already migrated to rootless."""
    log("check 4b: SPANEL_TENANTS_ROOTLESS=false does not rewrite runtimes")
    before = runtime_rows(app_id)
    runtime_env = stage / "app.env"
    live_values = load_dotenv(runtime_env)
    for name in (APP_CONTAINER, WORKER_CONTAINER, REDIS_CONTAINER):
        docker("rm", "-f", name, check=False)
    start_stack(stage, runtime_env, live_values, rootless=False)
    wait_plugins(client)
    after = runtime_rows(app_id)
    cell_ps = cell_docker(SLUG, "ps", "--format", "{{.Names}}\t{{.Status}}",
                          check=False).stdout.splitlines()
    still_error: str | None = None
    active: object = None
    try:
        still = client.request(
            "GET", f"/api/v1/plugins/apps/applications/{app_id}"
        )
        active = (still.get("active_deployment") or {}).get("release")
    except Exception as exc:  # noqa: BLE001 - the DB/cell assertions are the check
        still_error = str(exc)
    passed = (
        before == after
        and bool(before)
        and any(row.endswith("=rootless") for row in after)
        and bool(cell_ps)
    )
    evidence["checks"]["rollback_rehearsal"].update({
        "flag_false_runtime_before": before,
        "flag_false_runtime_after": after,
        "flag_false_cell_containers": cell_ps,
        "flag_false_active_release": active,
        "flag_false_api_error": still_error,
        "flag_false_pass": passed,
    })
    if not passed:
        raise E2E("flag=false rewrote runtime records or lost containers")
    # Return to the rootless runtime for the product cleanup path.
    for name in (APP_CONTAINER, WORKER_CONTAINER, REDIS_CONTAINER):
        docker("rm", "-f", name, check=False)
    start_stack(stage, runtime_env, live_values, rootless=True)
    wait_plugins(client)


def _write_downgrade_script(stage: Path) -> Path:
    path = stage / "downgrade_005.py"
    path.write_text(
        "\n".join([  # noqa: FLY002 - generated script is clearer as lines
            "import json",
            "from systutor.core.config import get_settings",
            "from systutor.core.database import build_session_factory",
            "from systutor.kernel.plugins.persistent import downgrade_plugin",
            "from systutor.kernel.plugins.runtime import PluginManifestRegistry",
            "settings = get_settings()",
            "registry = PluginManifestRegistry(settings.plugins_dir)",
            "registry.discover()",
            "factory = build_session_factory(settings)",
            "with factory() as db:",
            "    record = downgrade_plugin(",
            "        db, registry=registry, plugin_id='domains',",
            "        target_revision='004_create_cloudflare_oauth',",
            "    )",
            "    db.commit()",
            "    print(json.dumps({",
            "        'migration_version': record.migration_version,",
            "    }, sort_keys=True))",
        ]) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o644)
    return path


def check_downgrade(stage: Path, evidence: dict[str, Any]) -> None:
    """Downgrade 005 through the runtime migrator: only app_hosts disappears."""
    log("check 5: downgrade migration 005 and verify legacy intact")
    legacy_sql = (
        "SELECT id || '=' || COALESCE(domain, '') FROM apps_applications "
        "WHERE domain IS NOT NULL ORDER BY id;"
    )
    legacy_before = [
        line for line in psql(DB, legacy_sql).splitlines() if line.strip()
    ]
    hosts_before = psql(DB, "SELECT count(*) FROM domains_app_hosts;")
    legacy_column = psql(
        DB,
        "SELECT count(*) FROM information_schema.columns "
        "WHERE table_name = 'apps_applications' AND column_name = 'domain';",
    )
    script = _write_downgrade_script(stage)
    result = run(
        ["docker", "exec", APP_CONTAINER, "python", f"/stage/{script.name}"],
        timeout=180, check=False,
    )
    response: dict[str, Any] | None = None
    for line in reversed((result.stdout or "").strip().splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            response = value
            break
    legacy_after = [
        line for line in psql(DB, legacy_sql).splitlines() if line.strip()
    ]
    table = psql(DB, "SELECT COALESCE(to_regclass('domains_app_hosts')::text, '');")
    version = psql(
        DB,
        "SELECT COALESCE(migration_version, '') FROM plugin_registry "
        "WHERE plugin_id = 'domains';",
    )
    passed = (
        result.returncode == 0
        and isinstance(response, dict)
        and response.get("migration_version") == "004_create_cloudflare_oauth"
        and legacy_after == legacy_before
        and legacy_column == "1"
        and table == ""
        and version == "004_create_cloudflare_oauth"
    )
    evidence["downgrade_005"] = {
        "pass": passed,
        "app_hosts_before": hosts_before,
        "app_hosts_after_to_regclass": table or None,
        "legacy_column_present": legacy_column == "1",
        "migration_version": version,
        "legacy_before": legacy_before,
        "legacy_after": legacy_after,
        "response": response,
        "returncode": result.returncode,
        "stderr": (result.stderr or "")[-800:],
    }
    if not passed:
        raise E2E("downgrade 005 did not remove only app_hosts")


def _route_cleanup(evidence: dict[str, Any]) -> None:
    domain = app_host_domain(SLUG)
    leftovers = _route_documents(domain)
    for item in leftovers:
        try:
            Path(item["path"]).unlink()
        except OSError:
            continue
    evidence["route_documents_after_delete"] = [
        item["path"] for item in leftovers
    ]
    evidence["route_removed_by_product"] = not leftovers


def run_phase(stage: Path, evidence: dict[str, Any], args: argparse.Namespace) -> None:
    runtime_env = stage / "app.env"
    live_values = load_dotenv(runtime_env)
    email = live_values.get("SYSTUTOR_SEED_ADMIN_EMAIL", "")
    password = live_values.get("SYSTUTOR_SEED_ADMIN_PASSWORD", "")
    if not email or not password:
        raise E2E("seed administrator credentials are missing from the runtime env")
    client = login(email, password)
    api = api_module()
    print("[1/6] real login and permission validation")
    evidence["plugins"] = wait_plugins(client)
    profile = client.request("GET", "/api/v1/auth/me")
    permissions = set(profile.get("permissions", []))
    required = {
        "apps.applications.create", "apps.applications.delete",
        "apps.applications.manage", "apps.applications.read",
        "apps.deployments.create", "apps.github.connect",
        "apps.plans.manage",
    }
    missing = required.difference(permissions)
    if missing:
        raise E2E(f"login lacks permissions: {', '.join(sorted(missing))}")
    print("[2/6] check 1: cell egress")
    check_egress(stage, evidence)
    print("[3/6] check 2: 2 GiB aggregate plan and rootless deployment")
    apply_plan(client, evidence)
    app = create_application(client)
    app_id = app["id"]
    evidence["application"] = {
        "id": app_id, "slug": app.get("slug"),
        "domain": app.get("domain"), "tenant_id": app.get("tenant_id"),
    }
    root = f"/api/v1/plugins/apps/applications/{app_id}"
    try:
        api.queue(client, "POST", f"{root}/inspect", None, args.operation_timeout,
                  "inspect")
        deploy_environment = api.environment()
        deploy_op = deploy(client, api, app_id, deploy_environment,
                           args.deploy_timeout)
        detail = client.request("GET", root)
        first = detail.get("active_deployment") or {}
        if not first.get("id") or not first.get("release"):
            raise E2E("first deployment lacks a signed release identity")
        verify_deploy(args.slug, detail, deploy_op, evidence)
        print("[4/6] check 3: published route without a TCP bridge")
        check_route(stage, client, app_id, evidence)
        print("[5/6] check 4: rollback rehearsal and flag=false invariant")
        detail = check_rollback(client, app_id, first, evidence, args)
        check_flag_false(stage, client, app_id, detail, evidence)
        print("[6/6] delete the app through the API and downgrade 005")
        api.queue(client, "DELETE", root,
                  {"confirm": app.get("slug"), "purge_data": True},
                  args.operation_timeout, "delete")
        evidence["application_deleted"] = True
        time.sleep(2)
        _route_cleanup(evidence)
        check_downgrade(stage, evidence)
    finally:
        try:
            if not evidence.get("application_deleted"):
                api.queue(client, "DELETE", root,
                          {"confirm": app.get("slug"), "purge_data": True},
                          args.operation_timeout, "delete")
                evidence["application_deleted"] = True
        except Exception as exc:  # noqa: BLE001 - reported, not hidden
            evidence["application_deleted"] = False
            evidence["application_delete_error"] = str(exc)[:400]



# --------------------------------------------------------------------------
# cleanup
# --------------------------------------------------------------------------


def _remove_cell_leftovers(slug: str, uid: int | None) -> list[str]:
    removed: list[str] = []
    home = Path(f"/home/spanel-{slug}")
    if home.exists():
        shutil.rmtree(home, ignore_errors=True)
        removed.append(str(home))
    if uid is not None:
        runtime = Path(f"/run/user/{uid}")
        if runtime.exists():
            shutil.rmtree(runtime, ignore_errors=True)
            removed.append(str(runtime))
    cell_dir = Path(f"/var/lib/spanel/cells/{slug}")
    if cell_dir.exists():
        shutil.rmtree(cell_dir, ignore_errors=True)
        removed.append(str(cell_dir))
    return removed


def _cell_uid(slug: str) -> int | None:
    try:
        import pwd

        return pwd.getpwnam(f"spanel-{slug}").pw_uid
    except KeyError:
        return None


def cleanup(stage: Path, evidence: dict[str, Any]) -> None:
    errors: list[str] = []
    for name in ("plan-agent", "edge-relay"):
        evidence[f"stop_{name}"] = stop_process(stage, name)
    # A filtered relay run under an intermediate launcher could survive its
    # parent; kill only processes whose command line carries this stage path.
    run(["pkill", "-f", f"{stage / 'relay-data'}"], check=False)
    leftover_agents = run(
        ["bash", "-lc",
         f"pgrep -af '[e]dge-relay.*{stage}/relay-data' || true"], check=False
    ).stdout.strip()
    evidence["relay_process_after_stop"] = leftover_agents
    if leftover_agents:
        errors.append(f"relay process survived: {leftover_agents[:300]}")
    for name in (APP_CONTAINER, WORKER_CONTAINER, REDIS_CONTAINER):
        docker("rm", "-f", name, check=False)
    _route_cleanup(evidence)
    cell_uid = _cell_uid(SLUG)
    if cell_uid is not None:
        # A running user manager pins the account, so stop it before userdel.
        run(["systemctl", "stop", f"user@{cell_uid}.service"], check=False)
    cli = stage / "scripts" / "spanel_tenant.py"
    env = {
        "PYTHONPATH": f"{stage / 'pylibs'}:{stage / 'scripts'}",
        "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS": "1",
    }
    dep = run([sys.executable, str(cli), "deprovision", "--slug", SLUG,
               "--purge-data", "--json"], timeout=600, check=False, env=env)
    evidence["deprovision"] = (dep.stdout or dep.stderr).strip()[-800:]
    if dep.returncode:
        errors.append("deprovision reported an error")
    evidence["removed_leftovers"] = _remove_cell_leftovers(SLUG, cell_uid)
    for probe in ("e2eprobe17690", "e2eprobe17723", "e2eprobe17768",
                  "e2eprobe17824", "e2eprobe17928"):
        evidence["removed_leftovers"] += _remove_cell_leftovers(
            probe, _cell_uid(probe)
        )
    try:
        psql(LIVE_DB, f'DROP DATABASE IF EXISTS "{DB}" WITH (FORCE);')
    except Exception as exc:  # noqa: BLE001
        errors.append(f"database drop: {exc}")
    backup = stage / "backup"
    restored: dict[str, str] = {}
    expected: dict[str, str] = {}
    for item in STATE_FILES:
        source = backup / Path(item).name
        if not source.exists():
            continue
        target = Path(item)
        shutil.copy2(source, target)
        restored[item] = run(["sha256sum", str(target)]).stdout.split()[0]
        expected[item] = run(["sha256sum", str(source)]).stdout.split()[0]
    evidence["state_hashes_before"] = expected
    evidence["state_hashes_after"] = restored
    evidence["state_restored"] = restored == expected and bool(expected)
    if not evidence["state_restored"]:
        errors.append("state files were not restored byte-for-byte")
    # deprovision removes the unit/profile/dirs; drop an orphan system account
    # if one survived so the host returns to its pre-run identity set.
    try:
        import pwd

        pwd.getpwnam(f"spanel-{SLUG}")
    except KeyError:
        pass
    else:
        allocation = run(
            ["python3", "-c",
             f"import json;print('spanel-{SLUG}' in json.load(open('/var/lib/spanel/registry.json'))['allocations'])"],
            check=False,
        ).stdout.strip()
        if allocation != "True":
            removed = run(["userdel", f"spanel-{SLUG}"], check=False)
            gone = run(["getent", "passwd", f"spanel-{SLUG}"], check=False)
            if removed.returncode == 0 and gone.returncode != 0:
                evidence["removed_orphan_user"] = f"spanel-{SLUG}"
            else:
                errors.append(f"could not remove orphan user spanel-{SLUG}")
    leftovers = run(
        ["bash", "-lc",
         f"ls -d /var/lib/spanel/cells/{SLUG} /home/spanel-{SLUG} 2>/dev/null || true"],
        check=False,
    ).stdout.strip()
    evidence["cell_leftovers"] = leftovers
    if leftovers:
        errors.append(f"cell leftovers remain: {leftovers}")
    evidence["core_after"] = _core_snapshot()
    evidence["other_tenants_after"] = _other_tenant_status()
    evidence["rootful_fixture_after"] = _rootful_fixture()
    evidence["core_intact"] = (
        evidence.get("core_before") == evidence.get("core_after")
    )
    evidence["rootful_fixture_intact"] = (
        evidence.get("rootful_fixture_before")
        == evidence.get("rootful_fixture_after")
    )
    if evidence.get("state_restored"):
        # The disposable runtime env and release tree carry tenant secrets.
        (stage / "app.env").unlink(missing_ok=True)
        (stage / AGENT_TOKEN_FILE).unlink(missing_ok=True)
        (stage / "dispatch_outbox.py").unlink(missing_ok=True)
        (stage / "downgrade_005.py").unlink(missing_ok=True)
        Path("/var/tmp/0109-r4-route-body.html").unlink(missing_ok=True)
        shutil.rmtree(stage / "state", ignore_errors=True)
        shutil.rmtree(stage / "backup", ignore_errors=True)
        shutil.rmtree(stage / "runtime", ignore_errors=True)
        shutil.rmtree(stage / "relay-data", ignore_errors=True)
        shutil.rmtree(stage / "proxy-backups", ignore_errors=True)
    evidence["cleanup_errors"] = errors
    evidence["cleanup_verified"] = not errors


# --------------------------------------------------------------------------


def wait_plugins(client, timeout: float = 180.0) -> dict[str, Any]:
    """Wait for the entrypoint's real plugin enable loop before API work."""
    deadline = time.monotonic() + timeout
    last: object = None
    while time.monotonic() < deadline:
        try:
            plugins = client.request("GET", "/api/v1/core/plugins")
        except Exception as exc:  # noqa: BLE001 - retried until the deadline
            last = str(exc)
            time.sleep(3)
            continue
        last = plugins
        states = {
            str(item.get("plugin_id")): item
            for item in plugins if isinstance(item, dict)
            and item.get("plugin_id") in {"apps", "domains"}
        }
        if all(
            states.get(name, {}).get("is_enabled") is True
            for name in ("apps", "domains")
        ):
            return states
        time.sleep(3)
    raise E2E(f"apps/domains plugins did not become enabled: {last}")


def finalize_artifact(evidence: dict[str, Any], ok: bool) -> None:
    """Publish the official artifact shape without inventing any result."""
    detail = evidence.pop("checks", {}) if isinstance(evidence.get("checks"), dict) else {}
    evidence["checks_detail"] = detail
    commands = {
        "egress_without_manual_nat": (
            "provision with SPANEL_TENANT_CELL_DNS=192.168.18.1; compare "
            "dockerd/MainPID host netns; iptables -t nat -S inside the cell "
            "netns and on the host; docker run --rm alpine wget "
            "https://registry.npmjs.org/vite; AppArmor dmesg and unit audit"
        ),
        "aggregate_2gb_from_first_deploy": (
            "POST /api/v1/plugins/apps/plan {memory_bytes:2147483648, cpus:1, "
            "pids:512} before deploy; POST /applications, inspect, deploy; "
            "verify 3 services, per-service memory, and user cgroup limits"
        ),
        "published_route_no_bridge": (
            "POST /plugins/domains/app-hosts {application_id, service:frontend, "
            "domain:editores-<slug>.lab, https:false}; process the real outbox; "
            "observe cell listener, relay listener, spanel-*.yml and curl -H Host "
            "http://127.0.0.1:9080/"
        ),
        "rollback_rehearsal": (
            "second real deploy; POST /applications/{id}/rollback to the first "
            "signed release; verify route/runtime restored, rootful fixture "
            "preserved, then restart with SPANEL_TENANTS_ROOTLESS=false and "
            "verify runtime rows are not rewritten"
        ),
    }
    checks: list[dict[str, Any]] = []
    for name, command in commands.items():
        item = detail.get(name, {})
        checks.append({
            "name": name,
            "command": command,
            "output": json.dumps(item, sort_keys=True, default=str)[:12000],
            "pass": bool(item.get("pass")) and (
                item.get("flag_false_pass") is not False
            ),
        })
    evidence["checks"] = checks
    egress = detail.get("egress_without_manual_nat", {})
    after = egress.get("dmesg_denied_after")
    before = egress.get("dmesg_denied_before")
    delta = (
        max(0, int(after) - int(before))
        if isinstance(after, int) and isinstance(before, int) else 0
    )
    evidence["delta_denied"] = delta
    evidence["apparmor"] = {
        "profile": f"spanel-cell-{SLUG} (retirado en la limpieza)",
        "denied_from_first_boot": delta,
        "audit_deny_rules_preserved": egress.get("audit_deny_rules"),
        "note": "Solo se registra el delta real de dmesg; sin parches de perfil.",
    }
    evidence["isolation"] = {
        "other_tenants": {
            "before": evidence.get("other_tenants_before"),
            "after": evidence.get("other_tenants_after"),
        },
        "core_before_after": {
            "before": evidence.get("core_before"),
            "after": evidence.get("core_after"),
            "intact": evidence.get("core_intact"),
        },
        "rootful_fixture": {
            "before": evidence.get("rootful_fixture_before"),
            "after": evidence.get("rootful_fixture_after"),
            "intact": evidence.get("rootful_fixture_intact"),
        },
    }
    facts = evidence.get("host_facts", {})
    evidence["environment"] = {
        "target": "spanel.lab (NO spanel.app)",
        "host": (
            f"{facts.get('hostname')}, Docker {facts.get('docker')}, "
            f"kernel {facts.get('kernel')}, cgroups {facts.get('cgroups')}, "
            f"AppArmor {facts.get('apparmor')}"
        ),
        "access": "SSH como root en el laboratorio; script único por fases.",
        "code_under_test": (
            f"Stage {evidence.get('stage')} sin .git. "
            f"hashes: {json.dumps(evidence.get('code_hashes', {}), sort_keys=True)}"
        ),
        "database": f"Clon desechable {DB} de {LIVE_DB}; eliminado al final.",
        "method": (
            "API pública en 127.0.0.1:3010, worker dramatiq apps, plan-agent "
            "y edge-relay desechables y privilegiados, celda rootless real. "
            "Observación externa con systemd, docker, cgroups, ss, iptables, "
            "dmesg y AppArmor. Sin MASQUERADE manual, sin puente TCP y sin "
            "Alembic CLI."
        ),
        "harness_config": (
            "SPANEL_TENANTS_ROOTLESS=true y "
            "SPANEL_APPS_PROBE_BASELINE=rootless solo en el entorno "
            "desechable. El plan-agent y el relay se ejecutan desde el stage "
            "con sus propios sockets y token; el relay usa un registro "
            "filtrado a la celda desechable."
        ),
        "fixture": f"{REPOSITORY}@{BRANCH}/{COMPOSE_FILE}",
        "migration_runtime": (
            "Runtime migrador de plugins; downgrade 005 vía "
            "POST /api/v1/core/plugin-runtime/domains/migrate/downgrade."
        ),
    }
    gaps: list[dict[str, Any]] = []
    for check in checks:
        if not check["pass"]:
            gaps.append({
                "id": f"CHECK-{check['name']}",
                "severity": "high",
                "title": f"{check['name']} no convergió",
                "evidence": check["output"][:1000],
            })
    if evidence.get("route_removed_by_product") is False:
        gaps.append({
            "id": "ROUTE-CLEANUP",
            "severity": "medium",
            "title": "El documento de ruta no fue retirado por el producto",
            "evidence": "El harness retiró el spanel-*.yml del dominio desechable.",
        })
    if not evidence.get("state_restored"):
        gaps.append({
            "id": "STATE-RESTORE",
            "severity": "high",
            "title": "Los ficheros de estado no se restauraron byte a byte",
            "evidence": json.dumps(evidence.get("state_hashes_after", {})),
        })
    if evidence.get("core_intact") is False:
        gaps.append({
            "id": "CORE-INTACT",
            "severity": "high",
            "title": "Los contenedores Core cambiaron durante el E2E",
            "evidence": json.dumps(evidence.get("isolation", {}).get(
                "core_before_after", {}
            ))[:1500],
        })
    if evidence.get("rootful_fixture_intact") is False:
        gaps.append({
            "id": "ROOTFUL-FIXTURE",
            "severity": "high",
            "title": "El fixture rootful preexistente no se conservó",
            "evidence": json.dumps(evidence.get("isolation", {}).get(
                "rootful_fixture", {}
            ))[:1500],
        })
    evidence["gaps"] = gaps
    evidence["date"] = evidence.get("finished_at") or now()
    evidence["result"] = "PASS" if ok else "BLOCKED"
    evidence["result_reason"] = (
        "Los 4 checks y el downgrade 005 convergieron con evidencia real; "
        "sin parches manuales de NAT, puertos o rutas."
        if ok else "La corrida no convergió en todos los checks; ver gaps."
    )


def main() -> int:
    global SLUG, DB
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, default=STAGE)
    parser.add_argument("--slug", default=SLUG)
    parser.add_argument("--evidence", type=Path,
                        default=Path("/var/tmp/0109-r4-blackbox-e2e.json"))
    parser.add_argument("--phase", choices=("setup", "run", "cleanup", "all"),
                        default="all")
    parser.add_argument("--keep", action="store_true",
                        help="skip cleanup even when a phase fails")
    parser.add_argument("--operation-timeout", type=int, default=600)
    parser.add_argument("--deploy-timeout", type=int, default=2400)
    args = parser.parse_args()

    SLUG, DB = args.slug, "sysadmin_" + args.slug
    evidence: dict[str, Any] = {
        "spec": "0109-r4-host-nat-and-domains-owned-hosts",
        "phase": args.phase,
        "started_at": now(),
        "stage": str(args.stage),
        "environment": {
            "host": os.uname().nodename,
            "method": "single scripted black-box: cloned DB, disposable API/"
                      "worker/redis, real rootless cell, real GitHub fixture",
            "fixture": f"{REPOSITORY}@{BRANCH}/{COMPOSE_FILE}",
            "cell": SLUG,
            "code_under_test": str(args.stage),
        },
        "checks": {},
        "ok": False,
    }
    failed = False
    try:
        if args.phase in {"setup", "all"}:
            setup(args.stage, evidence)
            evidence["checks"]["setup"] = {"pass": True}
        if args.phase in {"run", "all"}:
            try:
                run_phase(args.stage, evidence, args)
                evidence["checks"]["blackbox"] = {"pass": True}
            except Exception as exc:  # noqa: BLE001
                failed = True
                evidence["checks"]["blackbox"] = {
                    "pass": False, "error": str(exc)[:1200],
                    "trace": traceback.format_exc()[-2000:],
                }
        if args.phase == "cleanup" or args.phase == "all" and (not args.keep or not failed):
            cleanup(args.stage, evidence)
        elif failed and args.keep:
            log("keeping resources for inspection (--keep)")
    except Exception as exc:  # noqa: BLE001
        failed = True
        evidence["fatal"] = {"error": str(exc)[:1200],
                             "trace": traceback.format_exc()[-2000:]}
        if args.phase == "all" and not args.keep:
            try:
                cleanup(args.stage, evidence)
            except Exception as cleanup_exc:  # noqa: BLE001
                evidence["fatal_cleanup"] = str(cleanup_exc)[:800]
    finally:
        evidence["finished_at"] = now()
        detail = evidence.get("checks", {})
        required_checks = (
            "egress_without_manual_nat",
            "aggregate_2gb_from_first_deploy",
            "published_route_no_bridge",
            "rollback_rehearsal",
        )
        checks_ok = all(
            isinstance(detail.get(name), dict)
            and detail[name].get("pass") is True
            for name in required_checks
        )
        downgrade_ok = (
            isinstance(evidence.get("downgrade_005"), dict)
            and evidence["downgrade_005"].get("pass") is True
        )
        evidence["ok"] = (
            not failed
            and not evidence.get("fatal")
            and evidence.get("cleanup_verified", args.keep) is not False
            and checks_ok
            and downgrade_ok
            and evidence.get("route_removed_by_product") is not False
            and evidence.get("state_restored") is True
            and evidence.get("core_intact") is True
            and evidence.get("rootful_fixture_intact") is True
        )
        finalize_artifact(evidence, evidence["ok"])
        evidence_write(args.evidence, evidence)
        print(json.dumps({"ok": evidence["ok"],
                          "evidence": str(args.evidence)}, sort_keys=True))
    return 0 if evidence["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
