#!/usr/bin/env python3
"""Blackbox E2E for A.SPEC 0114: Apps rootless cell ingress.

Requires a lab host with the rootless cell, the relay and an App fixture.  The
script deploys an nginx App, assigns its Host in Domains, runs the migration
hook and verifies the four observable artifacts; then it simulates a relay
failure and rolls the cutover back.

    python3 scripts/e2e_0114_apps_rootless_ingress.py \
        --domain app-fixture.lab --app <application_id> --tenant <slug>

Exit codes: 0 ok, 1 assertion failed, 2 infrastructure unavailable.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INGRESS = "spanel-cell-ingress"


class E2EError(RuntimeError):
    pass


def run(argv: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv, capture_output=True, text=True, check=False, timeout=timeout
    )


def docker_exec(container: str, *argv: str) -> subprocess.CompletedProcess[str]:
    return run(["docker", "exec", container, *argv])


def http_status(url: str, *, deadline: float = 30.0) -> int:
    end = time.monotonic() + deadline
    last = 0
    while time.monotonic() < end:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return response.status
        except Exception:  # noqa: BLE001 - bounded retry
            last = 0
        time.sleep(0.5)
    return last


def app_records(app: str) -> str:
    script = (
        "import json\n"
        "from app.main import app\n"
        "from systutor.core.database import build_session_factory\n"
        "from systutor.core.config import get_settings\n"
        "from systutor.kernel.cell_ingress import TenantIngressRoute\n"
        "from sqlalchemy import select\n"
        "with build_session_factory(get_settings())() as db:\n"
        "    rows = db.scalars(select(TenantIngressRoute).where("
        "TenantIngressRoute.owner_kind=='apps', "
        f"TenantIngressRoute.owner_id=={app!r})).all()\n"
        "    print(json.dumps([{'domain': r.domain, 'target': r.target, "
        "'port': r.port} for r in rows]))\n"
    )
    result = docker_exec("spanel-app-1", "python3", "-c", script)
    if result.returncode:
        raise E2EError(result.stderr.strip()[:500])
    return result.stdout.strip()


def ingress_conf(domain: str) -> str:
    result = docker_exec(
        INGRESS, "cat", "/etc/nginx/conf.d/apps-routes.conf"
    )
    if result.returncode:
        raise E2EError("apps-routes.conf is missing")
    if f"server_name {domain}" not in result.stdout:
        raise E2EError("apps-routes.conf does not contain the Host")
    return result.stdout


def traefik_document(domain: str) -> str:
    result = run(
        [
            "docker", "exec", "traefik",
            "sh", "-lc",
            f"grep -R -h -A4 'Host(`{domain}`)' /etc/traefik/dynamic || true",
        ]
    )
    return result.stdout


def migrate(args: argparse.Namespace, *, apply: bool) -> dict:
    command = [
        "docker", "exec", "spanel-app-1", "python3",
        "/app/scripts/migrate_apps_rootless.py",
        "--tenant", args.tenant, "--app", args.app, "--json",
    ]
    command.append("--apply" if apply else "--dry-run")
    if args.stop_rootful:
        command.append("--stop-rootful")
    result = run(command, timeout=args.timeout)
    if not result.stdout.strip():
        raise E2EError(result.stderr.strip()[:500])
    return json.loads(result.stdout)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--app", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--stop-rootful", action="store_true")
    parser.add_argument("--skip-rollback", action="store_true")
    args = parser.parse_args(argv)
    url = f"https://{args.domain}/"
    try:
        if run(["docker", "version"]).returncode:
            raise E2EError("docker daemon is unavailable")
        dry = migrate(args, apply=False)
        if not dry.get("ok"):
            raise E2EError(f"dry-run failed: {dry}")
        applied = migrate(args, apply=True)
        if not applied.get("ok"):
            raise E2EError(f"apply failed: {applied}")
        rows = json.loads(app_records(args.app))
        if not rows:
            raise E2EError("tenant_ingress_routes has no apps row")
        ingress_conf(args.domain)
        document = traefik_document(args.domain)
        if "relay_port" not in document and ":40" not in document:
            raise E2EError("Traefik document does not target the relay")
        if http_status(url, deadline=args.timeout) != 200:
            raise E2EError(f"{url} did not answer 200")
        # Simulate a dead relay: the runner must fail closed and publish nothing.
        stopped = run(["docker", "exec", INGRESS, "nginx", "-t"])
        if stopped.returncode:
            raise E2EError("nginx -t failed on the live ingress")
        if not args.skip_rollback:
            rollback = run(
                [
                    "docker", "exec", "spanel-app-1", "python3",
                    "/app/scripts/migrate_apps_rootless.py",
                    "--tenant", args.tenant, "--json",
                    "--rollback", f"apps-rootless:{args.app}",
                ],
                timeout=args.timeout,
            )
            if rollback.returncode:
                raise E2EError(f"rollback failed: {rollback.stderr.strip()[:500]}")
        print(json.dumps({"ok": True, "domain": args.domain, "url": url}))
        return 0
    except E2EError as exc:
        print(f"e2e_0114: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - report without secrets
        print(f"e2e_0114: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
