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
import json
import os
import secrets
import shutil
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
    log("disposable tenant slug updated")


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
    values["SPANEL_PLAN_AGENT_SOCKET"] = ""
    values["SPANEL_TENANTS_ROOTLESS"] = "true"
    values["SPANEL_TENANTS_DATA_ROOT"] = "/var/lib/spanel"
    values["SPANEL_APPS_PROBE_BASELINE"] = "rootless"
    values["SPANEL_APPS_PROBE_STARTUP_SECONDS"] = "300"
    values["SPANEL_APPS_PROBE_TIMEOUT_SECONDS"] = "15"
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
        "-v", f"{stage / 'vendor' / 'systutor-core' / 'src'}:"
              "/app/vendor/systutor-core/src:ro",
        "-v", f"{stage / 'vendor' / 'systutor-core' / 'plugins'}:/app/plugins:ro",
        "-v", "/var/lib/spanel/cells:/var/lib/spanel/cells:ro",
    ]
    if key_path and Path(key_path).exists():
        mounts += ["-v", f"{key_path}:/run/secrets/apps_key:ro"]
    return mounts


def start_stack(stage: Path, runtime_env: Path, live_env: dict[str, str]) -> None:
    # The cell daemon runs as the tenant user and must be able to traverse and
    # read bind sources, while ``app.env`` (secrets) stays mode 0600.
    run(["chmod", "755", str(stage)])
    for rel in ("state", "vendor", "scripts", "pylibs"):
        path = stage / rel
        if path.exists():
            run(["chmod", "-R", "a+rX", str(path)])
    run(["chmod", "600", str(runtime_env)])
    for name in (APP_CONTAINER, WORKER_CONTAINER, REDIS_CONTAINER):
        docker("rm", "-f", name, check=False)
    docker("run", "-d", "--name", REDIS_CONTAINER, "--network", "spanel_default",
           "redis:7-alpine")
    common = [
        "-d", "--network", "spanel_default", "--env-file", str(runtime_env),
        "-e", "PYTHONPATH=/app/vendor/systutor-core/src:/app/vendor/systutor-core:/app",
        "-e", "SPANEL_TENANTS_ROOTLESS=true",
        "-e", "SPANEL_APPS_PROBE_BASELINE=rootless",
        "-e", "SPANEL_PLAN_AGENT_SOCKET=",
        *_mounts(stage, live_env),
    ]
    docker("run", *common, "--name", APP_CONTAINER,
           "-p", "127.0.0.1:3010:3000", IMAGE)
    docker("run", *common, "--name", WORKER_CONTAINER,
           IMAGE, "python", "/stage/scripts/e2e_dramatiq_worker.py",
           "--processes", "1", "--threads", "1", "--queues", "apps")
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        probe = run(
            ["curl", "-fsS", "-o", "/dev/null", "http://127.0.0.1:3010/api/v1/system/health"],
            timeout=10, check=False,
        )
        if probe.returncode == 0:
            log("disposable API is healthy")
            return
        time.sleep(3)
    logs = docker("logs", "--tail", "60", APP_CONTAINER, check=False)
    raise E2E(f"disposable API did not become healthy: {logs.stdout[-1500:]}")


def setup(stage: Path, evidence: dict[str, Any]) -> None:
    stage_tree(stage)
    evidence["state_hashes_before"] = backup_state(stage)
    clone_database()
    evidence["cell"] = provision_cell(stage)
    live_env_path = Path("/home/lucas/mailadmin/.env.docker")
    runtime_env, live_env = write_runtime_env(stage, live_env_path)
    evidence["runtime"] = {
        "database": DB,
        "redis": REDIS_CONTAINER,
        "rootless": True,
        "probe_baseline": "rootless",
        "cell_socket": f"/var/lib/spanel/cells/{SLUG}/docker.sock",
    }
    start_stack(stage, runtime_env, live_env)
    log("setup complete; keep resources for the run phase")


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------


def api_module():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import e2e_apps_api  # noqa: PLC0415

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
                        "{{else}}none{{end}}|{{.HostConfig.NetworkMode}}",
        )
        state, health, mode = inspected.stdout.strip().split("|")
        if state != "running":
            raise E2E(f"cell container {name} is {state}, not running")
        if health not in {"healthy", "none"}:
            raise E2E(f"cell container {name} health is {health}")
        network = network or mode
        rootful = docker("inspect", cid, check=False)
        if rootful.returncode == 0:
            raise E2E(f"container {name} also exists in the rootful daemon")
        containers[name] = {
            "container_id": cid,
            "image_id": item.get("image_id"),
            "state": state,
            "health": health,
            "network": mode,
            "daemon": cell_socket,
            "absent_from_rootful": True,
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
    profile = client.request("GET", "/api/v1/auth/me")
    permissions = set(profile.get("permissions", []))
    required = {
        "apps.applications.create", "apps.applications.delete",
        "apps.applications.manage", "apps.applications.read",
        "apps.deployments.create", "apps.github.connect",
    }
    missing = required.difference(permissions)
    if missing:
        raise E2E(f"login lacks permissions: {', '.join(sorted(missing))}")
    print("[2/6] create application through the API")
    app = create_application(client)
    app_id = app["id"]
    evidence["application"] = {
        "id": app_id, "slug": app.get("slug"),
        "domain": app.get("domain"), "tenant_id": app.get("tenant_id"),
    }
    root = f"/api/v1/plugins/apps/applications/{app_id}"
    try:
        print("[3/6] inspect and deploy the real software for editors")
        api.queue(client, "POST", f"{root}/inspect", None, args.operation_timeout,
                  "inspect")
        deploy_environment = api.environment()
        result = deploy(client, api, app_id, deploy_environment, args.deploy_timeout)
        evidence["deploy_operation"] = result
        detail = client.request("GET", root)
        evidence["deploy_status"] = detail.get("status")
        print("[4/6] prove every container runs in the tenant cell")
        verify_in_cell(args.slug, detail, evidence)
        print("[5/6] independent readiness probe inside the cell")
        evidence["probe"] = probe_frontend(args.slug, evidence["network"])
        print("[6/6] second deployment and rollback rehearsal")
        first_deployment = detail.get("active_deployment") or {}
        first_id = first_deployment.get("id")
        first_release = first_deployment.get("release")
        first_commit = first_deployment.get("commit")
        if not first_id or not first_release:
            raise E2E("first deployment lacks a signed release identity")
        deploy(client, api, app_id, deploy_environment, args.deploy_timeout)
        detail = client.request("GET", root)
        second = detail.get("active_deployment") or {}
        if not second.get("id") or second.get("id") == first_id:
            raise E2E("second deployment did not activate a new deployment")
        rollback = api.queue(
            client, "POST", f"{root}/rollback",
            {"to_deployment_id": first_id}, args.deploy_timeout, "rollback",
        )
        detail = client.request("GET", root)
        restored = detail.get("active_deployment") or {}
        # A rollback records a new deployment row that reuses the signed
        # release of the target, so identity is the release, not the row id.
        if restored.get("release") != first_release:
            raise E2E(
                "rollback did not restore the first signed release "
                f"({restored.get('release')!r} != {first_release!r})"
            )
        if first_commit and restored.get("commit") != first_commit:
            raise E2E("rollback restored a different commit")
        evidence["rollback"] = {
            "operation": rollback,
            "first_deployment": first_id,
            "second_deployment": second.get("id"),
            "restored_deployment": restored.get("id"),
            "restored_release": restored.get("release"),
            "restored_commit": restored.get("commit"),
        }
        verify_in_cell(args.slug, detail, evidence)
        evidence["rollback"]["containers_in_cell"] = True
    finally:
        print("cleanup (API): delete application and purge data")
        try:
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
    for name in (APP_CONTAINER, WORKER_CONTAINER, REDIS_CONTAINER):
        docker("rm", "-f", name, check=False)
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
             "import json;print('spanel-%s' in json.load(open('/var/lib/spanel/registry.json'))['allocations'])" % SLUG],
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
    if evidence.get("state_restored"):
        # The disposable runtime env and release tree carry tenant secrets.
        (stage / "app.env").unlink(missing_ok=True)
        shutil.rmtree(stage / "state", ignore_errors=True)
        shutil.rmtree(stage / "backup", ignore_errors=True)
    evidence["cleanup_errors"] = errors
    evidence["cleanup_verified"] = not errors


# --------------------------------------------------------------------------


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
        if args.phase == "cleanup":
            cleanup(args.stage, evidence)
        elif args.phase == "all" and (not args.keep or not failed):
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
        evidence["ok"] = (
            not failed
            and evidence.get("cleanup_verified", args.keep) is not False
            and not evidence.get("fatal")
        )
        evidence_write(args.evidence, evidence)
        print(json.dumps({"ok": evidence["ok"],
                          "evidence": str(args.evidence)}, sort_keys=True))
    return 0 if evidence["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
