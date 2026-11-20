#!/usr/bin/env python3
"""Black-box lab ceremony for A.SPEC 0110-A.

Only public HTTP surfaces, operator CLIs, external HTTP and host-level network
observation are used. Missing legacy fixtures or lab capabilities produce
BLOCKED evidence, never a synthetic PASS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/0110-a-hosting-rootless-sites-e2e.json"


class LabError(RuntimeError):
    pass


class Api:
    def __init__(self, base: str, token: str) -> None:
        self.base = base.rstrip("/")
        self.token = token

    def request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        *,
        timeout: float = 60,
    ) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            self.base + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raise LabError(
                f"{method} {path}: HTTP {exc.code}: {exc.read().decode()[:500]}"
            ) from exc

    def upload(self, site_id: str, name: str, content: bytes) -> None:
        boundary = f"spanel0110{time.time_ns()}"
        body = (
            (
                f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                f'filename="{name}"\r\nContent-Type: application/octet-stream\r\n\r\n'
            ).encode()
            + content
            + f"\r\n--{boundary}--\r\n".encode()
        )
        request = urllib.request.Request(
            f"{self.base}/api/v1/plugins/filemanager/targets/hosting/{site_id}/uploads",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                if response.status != 200:
                    raise LabError(f"file upload returned {response.status}")
        except urllib.error.HTTPError as exc:
            raise LabError(
                f"file upload HTTP {exc.code}: {exc.read().decode()[:300]}"
            ) from exc

    def download(self, site_id: str, path: str) -> bytes:
        ticket = self.request(
            "POST",
            f"/api/v1/plugins/filemanager/targets/hosting/{site_id}"
            f"/download-tickets?path={urllib.parse.quote(path)}",
        )
        request = urllib.request.Request(
            self.base + ticket["url"], headers={"Authorization": f"Bearer {self.token}"}
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()


def external(
    domain: str, base: str | None = None, *, ready_deadline: float = 30.0
) -> dict[str, Any]:
    """Probe one Host, tolerating bounded Traefik file-provider reloads."""
    url = f"{base.rstrip('/')}/" if base else f"http://{domain}/"
    request = urllib.request.Request(url, headers={"Host": domain})
    context = tls_context()
    kwargs: dict[str, Any] = {"timeout": 20}
    if context is not None:
        kwargs["context"] = context
    deadline = time.monotonic() + max(0.0, ready_deadline)
    while True:
        try:
            with urllib.request.urlopen(request, **kwargs) as response:
                payload = response.read()
                return {
                    "status": response.status,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
        except (urllib.error.HTTPError, urllib.error.URLError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)


def tls_context() -> ssl.SSLContext | None:
    """Trust the lab CA for HTTPS routes, or keep the system store."""
    cafile = os.environ.get("SPANEL_E2E_CA_FILE", "").strip()
    if not cafile:
        return None
    try:
        return ssl.create_default_context(cafile=cafile)
    except (OSError, ssl.SSLError) as exc:
        raise LabError(f"unusable SPANEL_E2E_CA_FILE: {exc}") from exc


def operator(*args: str, check: bool = True) -> dict[str, Any]:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/hosting_migrate_rootless.py"),
            *args,
            "--json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=1800,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise LabError(
            f"operator CLI returned invalid JSON: {result.stdout[-300:]}"
        ) from exc
    if check and (result.returncode or not payload.get("ok")):
        raise LabError(f"operator CLI failed: {payload}")
    return payload


def command_json(argv: list[str]) -> dict[str, Any]:
    result = subprocess.run(
        argv, cwd=ROOT, capture_output=True, text=True, check=False, timeout=120
    )
    if result.returncode:
        raise LabError(
            f"command failed ({result.returncode}): {' '.join(argv)}: {result.stderr[-300:]}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise LabError(f"command returned invalid JSON: {' '.join(argv)}") from exc


def deny_count(slug: str, since: float) -> int:
    marker = f"spanel-cell-{slug}"
    result = subprocess.run(
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
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if result.returncode not in (0, 1):
        raise LabError("kernel audit log is unavailable")
    return sum(
        1 for line in result.stdout.splitlines() if marker in line and "DENIED" in line
    )


def tcp_listeners(port: int) -> list[str]:
    result = subprocess.run(
        ["ss", "-ltnH"], capture_output=True, text=True, check=False, timeout=20
    )
    if result.returncode:
        raise LabError("host TCP listeners are unavailable")
    suffix = f":{port}"
    return sorted(
        line.strip()
        for line in result.stdout.splitlines()
        if line.split()[3].rsplit("%", 1)[0].endswith(suffix)
    )


def create_site(api: Api, kind: str, name: str, domain: str) -> dict[str, Any]:
    return api.request(
        "POST",
        "/api/v1/plugins/hosting/sites",
        {"kind": kind, "name": name, "domain": domain, "profile": "nginx"},
        timeout=300,
    )["site"]


def write_artifact(evidence: dict[str, Any]) -> None:
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


def run(args: argparse.Namespace) -> dict[str, Any]:
    suffix = str(int(time.time()))
    evidence: dict[str, Any] = {
        "spec": "0110-A",
        "started_at": time.time(),
        "result": "FAIL",
        "checks": {},
        "cleanup": [],
        "errors": [],
    }
    api = Api(args.base_url, args.token)
    created: list[str] = []
    relay_stopped = False
    try:
        if not args.legacy_static or not args.legacy_wordpress:
            evidence["result"] = "BLOCKED"
            evidence["errors"].append(
                "Two API-created rootful legacy fixture ids are required; the running app "
                "cannot safely toggle SPANEL_TENANTS_ROOTLESS at request time."
            )
            return evidence

        core_before = external(args.core_domain, args.external_base)
        second_before = external(args.second_tenant_domain, args.external_base)
        denied_before = deny_count(args.tenant_slug, evidence["started_at"])
        database_listeners_before = tcp_listeners(3306)
        cell_before = command_json(
            [
                sys.executable,
                str(ROOT / "scripts/spanel_tenant.py"),
                "status",
                "--slug",
                args.tenant_slug,
                "--json",
            ]
        )
        if cell_before.get("state") != "ready":
            raise LabError(f"tenant cell is not ready: {cell_before}")

        domains = {
            "new_static_1": f"a-{suffix}.{args.domain_suffix}",
            "new_static_2": f"b-{suffix}.{args.domain_suffix}",
            "new_wp": f"wp-{suffix}.{args.domain_suffix}",
        }
        sites: dict[str, dict[str, Any]] = {}
        for key, domain in domains.items():
            site = create_site(
                api,
                "wordpress" if key == "new_wp" else "static",
                f"{key.replace('_', '-')}-{suffix}",
                domain,
            )
            sites[key] = site
            created.append(site["id"])
        public = {
            key: external(domain, args.external_base) for key, domain in domains.items()
        }
        if any(row["status"] != 200 for row in public.values()):
            raise LabError("new rootless Hosts did not all return HTTP 200")
        evidence["checks"]["new_rootless_multi_host"] = {
            "ok": True,
            "sites": sites,
            "http": public,
        }

        fixture = f"0110-static-{suffix}".encode()
        static_fixture = f"0110-fixture-{suffix}.txt"
        api.upload(args.legacy_static, static_fixture, fixture)
        before_static = hashlib.sha256(
            api.download(args.legacy_static, static_fixture)
        ).hexdigest()
        migrated_static = operator("migrate", "--site", args.legacy_static)
        after_static = hashlib.sha256(
            api.download(args.legacy_static, static_fixture)
        ).hexdigest()
        if before_static != after_static:
            raise LabError("static fixture hash changed during migration")
        evidence["checks"]["static_shadow_copy"] = {
            "ok": True,
            "before": before_static,
            "after": after_static,
            "operation_id": migrated_static["operation_id"],
        }

        wp_fixture = f"0110-wordpress-upload-{suffix}".encode()
        wordpress_fixture = f"0110-wp-fixture-{suffix}.txt"
        api.upload(args.legacy_wordpress, wordpress_fixture, wp_fixture)
        users_before = api.request(
            "GET", f"/api/v1/plugins/hosting/sites/{args.legacy_wordpress}/users"
        )
        wp_before = hashlib.sha256(
            api.download(args.legacy_wordpress, wordpress_fixture)
        ).hexdigest()
        migrated_wp = operator("migrate", "--site", args.legacy_wordpress)
        users_after = api.request(
            "GET", f"/api/v1/plugins/hosting/sites/{args.legacy_wordpress}/users"
        )
        wp_after = hashlib.sha256(
            api.download(args.legacy_wordpress, wordpress_fixture)
        ).hexdigest()
        if wp_before != wp_after or users_before != users_after:
            raise LabError("WordPress files or users changed during migration")
        evidence["checks"]["wordpress_shadow_copy"] = {
            "ok": True,
            "before": wp_before,
            "after": wp_after,
            "users_preserved": True,
            "operation_id": migrated_wp["operation_id"],
        }

        rolled = operator(
            "rollback",
            "--site",
            args.legacy_static,
            "--operation",
            migrated_static["operation_id"],
        )
        if rolled["state"] != "rolled_back":
            raise LabError("rollback did not restore rootful runtime")
        evidence["checks"]["rollback"] = {"ok": True, "result": rolled}

        stop = subprocess.run(
            ["systemctl", "stop", "spanel-edge-relay.service"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if stop.returncode:
            evidence["result"] = "BLOCKED"
            raise LabError(
                "cannot run post-cutover failure drill: spanel-edge-relay.service "
                f"could not be stopped: {stop.stderr[-300:]}"
            )
        relay_stopped = True
        failed = operator("migrate", "--site", args.legacy_static, check=False)
        if failed.get("state") != "failed" or failed.get("rollback_available"):
            raise LabError(
                f"route failure did not fail and auto-restore rootful: {failed}"
            )
        if external(args.legacy_static_domain, args.external_base)["status"] != 200:
            raise LabError(
                "rootful site was not externally restored after route failure"
            )
        subprocess.run(
            ["systemctl", "start", "spanel-edge-relay.service"],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        relay_stopped = False
        cleaned_failure = operator(
            "rollback",
            "--site",
            args.legacy_static,
            "--operation",
            failed["operation_id"],
        )
        evidence["checks"]["post_cutover_failure_rollback"] = {
            "ok": cleaned_failure["state"] == "rolled_back",
            "failed_operation": failed,
            "cleanup_operation": cleaned_failure,
        }

        finalized = operator(
            "finalize",
            "--site",
            args.legacy_wordpress,
            "--operation",
            migrated_wp["operation_id"],
            "--confirm-domain",
            args.legacy_wordpress_domain,
        )
        evidence["checks"]["finalize"] = {
            "ok": finalized["state"] == "finalized",
            "result": finalized,
        }

        database_listeners_after = tcp_listeners(3306)
        new_database_listeners = sorted(
            set(database_listeners_after) - set(database_listeners_before)
        )
        evidence["checks"]["no_database_publish"] = {
            "ok": not new_database_listeners,
            "before": database_listeners_before,
            "after": database_listeners_after,
            "new": new_database_listeners,
            "observation": "ss -ltnH",
        }
        if not evidence["checks"]["no_database_publish"]["ok"]:
            raise LabError("a new host listener on port 3306 was observed")

        cell_after = command_json(
            [
                sys.executable,
                str(ROOT / "scripts/spanel_tenant.py"),
                "status",
                "--slug",
                args.tenant_slug,
                "--json",
            ]
        )
        denied_after = deny_count(args.tenant_slug, evidence["started_at"])
        core_after = external(args.core_domain, args.external_base)
        second_after = external(args.second_tenant_domain, args.external_base)
        invariants_ok = (
            cell_after.get("state") == "ready"
            and cell_after.get("limits") == cell_before.get("limits")
            and denied_after - denied_before == 0
            and core_after == core_before
            and second_after == second_before
        )
        evidence["checks"]["isolation_and_limits"] = {
            "ok": invariants_ok,
            "cell_before": cell_before,
            "cell_after": cell_after,
            "delta_denied": denied_after - denied_before,
            "core_unchanged": core_after == core_before,
            "second_tenant_unchanged": second_after == second_before,
        }
        if not invariants_ok:
            raise LabError("cell limits, audit, Core, or second tenant changed")

        evidence["result"] = "PASS"
        return evidence
    except (
        LabError,
        OSError,
        urllib.error.URLError,
        subprocess.SubprocessError,
    ) as exc:
        evidence["errors"].append(str(exc))
        return evidence
    finally:
        if relay_stopped:
            subprocess.run(
                ["systemctl", "start", "spanel-edge-relay.service"],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        for site_id in reversed(created):
            try:
                api.request("DELETE", f"/api/v1/plugins/hosting/sites/{site_id}")
                evidence["cleanup"].append({"site_id": site_id, "ok": True})
            except Exception as exc:  # noqa: BLE001 - cleanup evidence must survive
                evidence["cleanup"].append(
                    {"site_id": site_id, "ok": False, "error": str(exc)}
                )
        evidence["cleanup_complete"] = all(row["ok"] for row in evidence["cleanup"])
        evidence["finished_at"] = time.time()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument(
        "--token",
        default=os.environ.get("SPANEL_E2E_TOKEN"),
        required="SPANEL_E2E_TOKEN" not in os.environ,
        help="API bearer token (or SPANEL_E2E_TOKEN)",
    )
    parser.add_argument(
        "--external-base",
        default=os.environ.get("SPANEL_E2E_EXTERNAL_BASE"),
        help=(
            "HTTP origin used for external probes while preserving each Host header "
            "(or SPANEL_E2E_EXTERNAL_BASE)"
        ),
    )
    parser.add_argument("--domain-suffix", required=True)
    parser.add_argument("--legacy-static")
    parser.add_argument("--legacy-wordpress")
    parser.add_argument("--legacy-wordpress-domain", default="")
    parser.add_argument("--legacy-static-domain", required=True)
    parser.add_argument("--tenant-slug", required=True)
    parser.add_argument("--core-domain", required=True)
    parser.add_argument("--second-tenant-domain", required=True)
    args = parser.parse_args()
    evidence = run(args)
    write_artifact(evidence)
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0 if evidence["result"] == "PASS" and evidence.get("cleanup_complete") else 1


if __name__ == "__main__":
    raise SystemExit(main())
