#!/usr/bin/env python3
"""A.SPEC 0110-B black-box ceremony: one shared phpMyAdmin, ephemeral relays.

This ceremony never reads a cell socket or a DB password to make an assertion:
it uses the public panel API, the operator CLI and host facts. It opens two
rootless WordPress sessions at once, proves each dashboard sees only its own DB,
replays ticket/cookie across sites, closes relays, waits for TTL expiry and (as
root) kills the broker and reconciles orphans.

Two tenants with rootless cells and a rootful WordPress fixture are reported as
``blocked`` when the lab does not have them; the result is then ``PARTIAL``,
never an invented PASS.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from contextlib import suppress
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE = "http://127.0.0.1:3000"
BROKER_RANGE = (41000, 41999)
CONNECTOR_RANGE = (42000, 42999)


class LabError(RuntimeError):
    """A lab precondition or probe failed; never a product PASS."""


def run(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


class Api:
    def __init__(self, base: str, email: str, password: str) -> None:
        self.base = base.rstrip("/")
        self.email = email
        self.password = password
        self.token = ""

    def login(self) -> None:
        payload = self.request(
            "POST",
            "/api/v1/auth/login",
            {"email": self.email, "password": self.password},
            auth=False,
        )
        self.token = str(payload["access_token"])

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        timeout: int = 180,
        auth: bool = True,
    ) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode()
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(
            self.base + path, data=data, method=method, headers=headers
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
        return json.loads(raw) if raw else {}

    def opener(self) -> tuple[http.cookiejar.CookieJar, urllib.request.OpenerDirector]:
        jar = http.cookiejar.CookieJar()
        return jar, urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar)
        )

    def get(
        self,
        opener: urllib.request.OpenerDirector,
        path: str,
        *,
        cookie: str | None = None,
        timeout: int = 120,
    ) -> tuple[int, bytes]:
        headers = {"Authorization": f"Bearer {self.token}"}
        if cookie:
            headers["Cookie"] = cookie
        request = urllib.request.Request(self.base + path, headers=headers)
        try:
            with opener.open(request, timeout=timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()


class Session:
    def __init__(self, site: str, db: str, expires_in: int) -> None:
        self.site = site
        self.db = db
        self.expires_in = expires_in
        self.jar: http.cookiejar.CookieJar | None = None
        self.opener: urllib.request.OpenerDirector | None = None
        self.body = b""
        self.status = 0
        self.ticket = ""
        self.relay_id = ""

    def cookie(self) -> str:
        if self.jar is None:
            return ""
        return "; ".join(f"{item.name}={item.value}" for item in self.jar)


def host_listeners() -> list[int]:
    result = run(["ss", "-ltnH"])
    if result.returncode:
        raise LabError("host TCP listeners are unavailable")
    ports: set[int] = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            port = int(parts[3].rsplit(":", 1)[1])
        except (IndexError, ValueError):
            continue
        if BROKER_RANGE[0] <= port <= BROKER_RANGE[1] or (
            CONNECTOR_RANGE[0] <= port <= CONNECTOR_RANGE[1]
        ):
            ports.add(port)
    return sorted(ports)


def cell_env(slug: str) -> tuple[dict[str, str], str]:
    registry = json.loads(Path("/var/lib/spanel/registry.json").read_text())
    allocation = (registry.get("allocations") or {}).get(slug)
    if allocation is None:
        raise LabError(f"tenant {slug} has no cell allocation")
    env = os.environ.copy()
    env["DOCKER_HOST"] = f"unix:///var/lib/spanel/cells/{slug}/docker.sock"
    env["XDG_RUNTIME_DIR"] = f"/run/user/{allocation['uid']}"
    return env, str(allocation["uid"])


def connectors(slug: str) -> list[str]:
    env, _uid = cell_env(slug)
    result = run(
        [
            "docker",
            "ps",
            "--format",
            "{{.Names}}",
            "--filter",
            "label=spanel.role=pma-connector",
        ],
        env=env,
    )
    if result.returncode:
        raise LabError(f"cell docker is unavailable: {result.stderr[-200:]}")
    return sorted(name for name in result.stdout.splitlines() if name)


def db_ports_published(slug: str) -> list[str]:
    env, _uid = cell_env(slug)
    result = run(
        [
            "docker",
            "ps",
            "--format",
            "{{.Names}} {{.Ports}}",
            "--filter",
            "name=-db",
        ],
        env=env,
    )
    if result.returncode:
        raise LabError("cell docker is unavailable")
    return [line for line in result.stdout.splitlines() if "0.0.0.0:3306" in line]


def operator(
    token_file: str, *args: str
) -> dict[str, Any]:
    env = os.environ.copy()
    env["SPANEL_PLAN_AGENT_TOKEN_FILE"] = token_file
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    result = run(
        [sys.executable, str(ROOT / "scripts/spanel_tenant.py"), *args, "--json"],
        env=env,
        timeout=180,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise LabError(
            f"operator CLI returned invalid JSON: {result.stdout[-300:]}"
        ) from exc
    if result.returncode:
        raise LabError(f"operator CLI failed: {payload}")
    return payload


def relays(token_file: str, slug: str) -> list[dict[str, Any]]:
    return list(operator(token_file, "db-relay", "list", "--slug", slug).get("relays", []))


def relay_ids(entries: list[dict[str, Any]], site: str) -> list[str]:
    return [str(item["relay_id"]) for item in entries if item.get("site_id") == site]


def wait_for(
    predicate: Any, timeout: float, interval: float = 1.0, label: str = "condition"
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    raise LabError(f"timeout waiting for {label}")


def open_session(api: Api, site: str) -> Session:
    db = api.request(
        "POST", f"/api/v1/plugins/hosting/sites/{site}/database"
    )["database"]
    created = api.request(
        "POST", f"/api/v1/plugins/hosting/sites/{site}/phpmyadmin/session", {}
    )
    record = Session(site, str(db), int(created["expires_in"]))
    record.ticket = str(created["url"]).split("ticket=", 1)[1]
    record.jar, record.opener = api.opener()
    assert record.opener is not None
    record.status, record.body = api.get(
        record.opener,
        f"/api/v1/plugins/hosting/sites/{site}/phpmyadmin/?ticket={record.ticket}",
    )
    if record.status != 200:
        raise LabError(f"phpMyAdmin proxy for {site} returned {record.status}")
    return record


def close_session(api: Api, record: Session) -> int:
    if record.opener is None:
        return 0
    headers = {"Authorization": f"Bearer {api.token}"}
    request = urllib.request.Request(
        api.base + f"/api/v1/plugins/hosting/sites/{record.site}/phpmyadmin/session",
        method="DELETE",
        headers=headers,
    )
    try:
        with record.opener.open(request, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


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
        raise LabError("kernel audit log is unavailable")
    return sum(
        1 for line in result.stdout.splitlines() if marker in line and "DENIED" in line
    )


def restart_agent_and_app(unit: str, container: str, base: str) -> None:
    if os.geteuid() != 0:
        raise LabError("crash/reconcile drill requires root")
    restarted = run(["systemctl", "restart", unit])
    if restarted.returncode:
        raise LabError(f"cannot restart {unit}: {restarted.stderr[-200:]}")
    time.sleep(3)
    app = run(["docker", "restart", container])
    if app.returncode:
        raise LabError(f"cannot restart {container}: {app.stderr[-200:]}")
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(base + "/openapi.json", timeout=5) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(2)
    raise LabError("the app did not become ready after the crash drill")


def write_artifact(evidence: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


def run_checks(args: argparse.Namespace) -> dict[str, Any]:
    api = Api(args.base, args.email, args.password)
    api.login()
    started = time.time()
    evidence: dict[str, Any] = {
        "spec": "0110-B",
        "started_at": started,
        "base": args.base,
        "tenant_slug": args.tenant_slug,
        "site_a": args.site_a,
        "site_b": args.site_b,
        "checks": {},
        "blocked": [],
        "cleanup_complete": False,
    }
    checks: dict[str, Any] = evidence["checks"]
    sessions: list[Session] = []

    def check(name: str, ok: bool, detail: Any = None) -> None:
        checks[name] = {"ok": bool(ok)}
        if detail is not None:
            checks[name]["detail"] = detail
        if not ok:
            raise LabError(f"check failed: {name}")

    try:
        baseline = {
            "relays": relays(args.token_file, args.tenant_slug),
            "listeners": host_listeners(),
            "connectors": connectors(args.tenant_slug),
            "db_published": db_ports_published(args.tenant_slug),
        }
        check(
            "zero_resources_before",
            not baseline["relays"]
            and not baseline["listeners"]
            and not baseline["connectors"]
            and not baseline["db_published"],
            baseline,
        )

        first = open_session(api, args.site_a)
        second = open_session(api, args.site_b)
        sessions.extend([first, second])
        check(
            "session_a_dashboard",
            first.status == 200 and first.db.encode() in first.body,
            {"status": first.status, "bytes": len(first.body)},
        )
        check(
            "session_b_dashboard",
            second.status == 200 and second.db.encode() in second.body,
            {"status": second.status, "bytes": len(second.body)},
        )
        check(
            "simultaneous_isolation",
            first.db != second.db
            and first.db.encode() not in second.body
            and second.db.encode() not in first.body,
            {"db_a": first.db, "db_b": second.db},
        )

        during_entries = relays(args.token_file, args.tenant_slug)
        ids_a = relay_ids(during_entries, args.site_a)
        ids_b = relay_ids(during_entries, args.site_b)
        first.relay_id = ids_a[0] if ids_a else ""
        during_connectors = connectors(args.tenant_slug)
        check(
            "bounded_during_session",
            len(ids_a) >= 1
            and len(ids_b) >= 1
            and len(during_connectors) >= 2
            and len(host_listeners()) >= 2,
            {
                "relays": during_entries,
                "connectors": during_connectors,
                "listeners": host_listeners(),
            },
        )

        # A one-time ticket must not cross to another site, while a fresh
        # ticket for site A still opens a real session (the rejection is
        # target-scoped, not a broken ticket exchange).
        cross = api.request(
            "POST",
            f"/api/v1/plugins/hosting/sites/{args.site_a}/phpmyadmin/session",
            {},
        )
        cross_ticket = str(cross["url"]).split("ticket=", 1)[1]
        _, cross_opener = api.opener()
        cross_status, _ = api.get(
            cross_opener,
            f"/api/v1/plugins/hosting/sites/{args.site_b}/phpmyadmin/?ticket={cross_ticket}",
        )
        own = open_session(api, args.site_a)
        sessions.append(own)
        check(
            "cross_site_ticket_rejected",
            cross_status in (401, 403) and own.status == 200,
            {
                "cross_status": cross_status,
                "own_status": own.status,
                "cross_ticket": cross_ticket[:12] + "...",
            },
        )
        _, opener_x = api.opener()
        cookie_status, _ = api.get(
            opener_x,
            f"/api/v1/plugins/hosting/sites/{args.site_b}/phpmyadmin/",
            cookie=first.cookie(),
        )
        check(
            "cross_site_cookie_rejected",
            cookie_status in (401, 403),
            {"status": cookie_status},
        )

        # Closing relay A through the operator CLI must break A's PMA session
        # while B keeps working.
        if first.relay_id:
            operator(
                args.token_file,
                "db-relay",
                "close",
                "--slug",
                args.tenant_slug,
                "--relay",
                first.relay_id,
            )
        after_close = relays(args.token_file, args.tenant_slug)
        dead_status, dead_body = api.get(
            first.opener,
            f"/api/v1/plugins/hosting/sites/{args.site_a}/phpmyadmin/",
        )
        closed_relay_gone = not any(
            item["relay_id"] == first.relay_id for item in after_close
        )
        b_still_works = (
            api.get(
                second.opener,
                f"/api/v1/plugins/hosting/sites/{args.site_b}/phpmyadmin/",
            )[1].count(second.db.encode())
            >= 1
        )
        check(
            "relay_close_breaks_only_a",
            closed_relay_gone
            and (dead_status != 200 or first.db.encode() not in dead_body)
            and b_still_works,
            {
                "dead_status": dead_status,
                "closed_relay_gone": closed_relay_gone,
                "b_still_works": b_still_works,
            },
        )

        for record in sessions:
            close_session(api, record)
        sessions.clear()
        wait_for(
            lambda: not relays(args.token_file, args.tenant_slug)
            and not connectors(args.tenant_slug)
            and not any(
                BROKER_RANGE[0] <= port <= CONNECTOR_RANGE[1]
                for port in host_listeners()
            ),
            60,
            label="logout cleanup",
        )
        check(
            "logout_cleanup",
            True,
            {"listeners": host_listeners(), "connectors": connectors(args.tenant_slug)},
        )

        ttl_session = open_session(api, args.site_a)
        sessions.append(ttl_session)
        ttl_entries = relays(args.token_file, args.tenant_slug)
        ttl_ids = relay_ids(ttl_entries, args.site_a)
        wait_seconds = ttl_session.expires_in + 20
        if wait_seconds > args.max_ttl_wait:
            evidence["blocked"].append(
                f"TTL drill needs {wait_seconds}s (limit {args.max_ttl_wait}); "
                "configure SPANEL_PHPMYADMIN_SESSION_TTL<=30 for this lab run."
            )
        else:
            wait_for(
                lambda: not any(
                    item["relay_id"] in ttl_ids
                    for item in relays(args.token_file, args.tenant_slug)
                )
                and not connectors(args.tenant_slug),
                wait_seconds + 30,
                interval=2,
                label="TTL expiry cleanup",
            )
            check(
                "ttl_expiry_cleanup",
                True,
                {"expires_in": ttl_session.expires_in, "relay_ids": ttl_ids},
            )

        # Rootful legacy path: only if the caller provides a live rootful site.
        if args.rootful_site:
            before = relays(args.token_file, args.tenant_slug)
            legacy = open_session(api, args.rootful_site)
            sessions.append(legacy)
            after = relays(args.token_file, args.tenant_slug)
            check(
                "rootful_legacy_path",
                legacy.status == 200
                and legacy.db.encode() in legacy.body
                and len(after) == len(before),
                {"db": legacy.db, "relays_before": len(before), "relays_after": len(after)},
            )
            close_session(api, legacy)
        else:
            evidence["blocked"].append(
                "No live rootful WordPress fixture: the lab tenant is rootless and "
                "the old demowp/lucas-wp containers are gone."
            )

        evidence["blocked"].append(
            "Single-tenant lab: demo holds both sites and no second user/tenant "
            "with a rootless cell exists; cross-tenant isolation is covered by "
            "host-agent unit tests, not by a live second tenant."
        )

        if os.geteuid() == 0:
            crash = open_session(api, args.site_b)
            sessions.append(crash)
            restart_agent_and_app(args.agent_unit, args.app_container, args.base)
            operator(args.token_file, "db-relay", "reconcile")
            wait_for(
                lambda: not connectors(args.tenant_slug)
                and not any(
                    BROKER_RANGE[0] <= port <= CONNECTOR_RANGE[1]
                    for port in host_listeners()
                ),
                60,
                label="crash/reconcile cleanup",
            )
            check(
                "crash_reconcile_cleanup",
                True,
                {"connectors": connectors(args.tenant_slug), "listeners": host_listeners()},
            )
        else:
            evidence["blocked"].append(
                "Crash/reconcile drill requires root (systemctl + cell docker); "
                "run the ceremony through sudo."
            )

        denied = deny_count(args.tenant_slug, started)
        check("delta_denied_zero", denied == 0, {"denied": denied})
        check(
            "no_permanent_db_port",
            not db_ports_published(args.tenant_slug),
            {"published": db_ports_published(args.tenant_slug)},
        )
    except Exception as exc:  # noqa: BLE001 - report the real failure
        evidence["error"] = f"{type(exc).__name__}: {exc}"
        evidence["traceback"] = traceback.format_exc()[-2000:]
    finally:
        for record in sessions:
            with suppress(Exception):
                close_session(api, record)
        try:
            # Cross-site replays may leave a provisional session whose relay is
            # bounded by the TTL; drain it before declaring cleanup complete.
            with suppress(Exception):
                wait_for(
                    lambda: not relays(args.token_file, args.tenant_slug)
                    and not connectors(args.tenant_slug)
                    and not any(
                        BROKER_RANGE[0] <= port <= CONNECTOR_RANGE[1]
                        for port in host_listeners()
                    ),
                    args.max_ttl_wait,
                    interval=2,
                    label="final cleanup",
                )
            evidence["final"] = {
                "relays": relays(args.token_file, args.tenant_slug),
                "listeners": host_listeners(),
                "connectors": connectors(args.tenant_slug),
            }
            evidence["cleanup_complete"] = (
                not evidence["final"]["relays"]
                and not evidence["final"]["listeners"]
                and not evidence["final"]["connectors"]
            )
        except Exception as exc:  # noqa: BLE001 - keep the artifact
            evidence["final"] = {"error": str(exc)}
            evidence["cleanup_complete"] = False

    required = list(checks)
    passed = all(checks[name]["ok"] for name in required) and evidence[
        "cleanup_complete"
    ]
    if "error" in evidence or not passed:
        evidence["result"] = "FAIL"
    elif evidence["blocked"]:
        evidence["result"] = "PARTIAL"
    else:
        evidence["result"] = "PASS"
    evidence["finished_at"] = time.time()
    evidence["duration_s"] = round(evidence["finished_at"] - started, 1)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=os.getenv("SPANEL_E2E_BASE", DEFAULT_BASE))
    parser.add_argument("--email", default=os.getenv("SPANEL_E2E_EMAIL", ""))
    parser.add_argument("--password", default=os.getenv("SPANEL_E2E_PASSWORD", ""))
    parser.add_argument("--site-a", default=os.getenv("SPANEL_E2E_SITE_A", ""))
    parser.add_argument("--site-b", default=os.getenv("SPANEL_E2E_SITE_B", ""))
    parser.add_argument("--rootful-site", default=os.getenv("SPANEL_E2E_ROOTFUL_SITE", ""))
    parser.add_argument(
        "--tenant-slug", default=os.getenv("SPANEL_E2E_TENANT_SLUG", "demo")
    )
    parser.add_argument(
        "--token-file",
        default=os.getenv("SPANEL_PLAN_AGENT_TOKEN_FILE", ""),
    )
    parser.add_argument(
        "--agent-unit",
        default=os.getenv("SPANEL_E2E_AGENT_UNIT", "spanel-plan-agent.service"),
    )
    parser.add_argument(
        "--app-container",
        default=os.getenv("SPANEL_E2E_APP_CONTAINER", "spanel-app-1"),
    )
    parser.add_argument(
        "--artifact",
        default=os.getenv(
            "SPANEL_E2E_ARTIFACT",
            str(ROOT / "artifacts/0110-b-shared-core-phpmyadmin-e2e.json"),
        ),
    )
    parser.add_argument(
        "--max-ttl-wait",
        type=int,
        default=int(os.getenv("SPANEL_E2E_MAX_TTL_WAIT", "180")),
    )
    args = parser.parse_args()
    missing = [
        name
        for name in ("email", "password", "site_a", "site_b", "token_file")
        if not getattr(args, name)
    ]
    if missing:
        parser.error("missing required values: " + ", ".join(missing))
    evidence = run_checks(args)
    write_artifact(evidence, Path(args.artifact))
    summary = {
        key: evidence[key]
        for key in ("result", "checks", "blocked", "cleanup_complete")
    }
    print(json.dumps(summary, indent=2))
    return 0 if evidence["result"] != "FAIL" else 1


if __name__ == "__main__":
    sys.exit(main())
