#!/usr/bin/env python3
"""Black-box A.SPEC 0115: create a tenant with its cell and plan in one call."""

from __future__ import annotations

import argparse
import json
import secrets
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class E2EError(RuntimeError):
    pass


class Api:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = ""

    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> Any:
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:1000]
            raise E2EError(f"{method} {path} returned {exc.code}: {detail}") from exc


def run(args: argparse.Namespace) -> dict[str, Any]:
    api = Api(args.base_url)
    password = Path(args.password_file).read_text(encoding="utf-8").strip()
    login = api.request(
        "POST", "/api/v1/auth/login", {"email": args.email, "password": password}
    )
    api.token = str(login.get("access_token") or "")
    if not api.token:
        raise E2EError("login did not return an access token")

    # A fresh disposable lab DB starts with plugins disabled; the entrypoint
    # enables them right after health. Wait for the public route to exist.
    for attempt in range(60):
        try:
            api.request("GET", "/api/v1/plugins/tenant/tenants")
            break
        except E2EError:
            if attempt == 59:
                raise
            time.sleep(1)

    me = api.request("GET", "/api/v1/auth/me")
    required = {"core.platform.admin", "tenant.tenants.manage", "apps.plans.manage"}
    missing = required.difference(me.get("permissions") or [])
    if missing:
        raise E2EError(f"administrator lacks permissions: {sorted(missing)}")

    suffix = str(int(time.time()))
    slug = args.slug or f"e2e0115-{suffix}"
    tenant_password = secrets.token_urlsafe(24)
    created = api.request(
        "POST",
        "/api/v1/plugins/tenant/tenants",
        {
            "name": f"E2E 0115 {suffix}",
            "slug": slug,
            "user_email": f"admin-{suffix}@e2e.invalid",
            "user_password": tenant_password,
            "resource_plan": {
                "memory_bytes": args.memory_gib * 1024**3,
                "cpus": args.cpus,
                "pids": args.pids,
                "storage_bytes": args.storage_gib * 1024**3,
            },
        },
    )
    tenant_password = ""
    tenant_id = str(created.get("id") or "")
    if not tenant_id:
        raise E2EError("tenant creation did not return an id")

    query = f"?tenant_id={tenant_id}"
    plan = api.request("GET", "/api/v1/plugins/apps/plan" + query)
    # The first probe may pull its disposable image and exceed the bounded
    # client timeout; retry only verification, never tenant creation.
    verification: dict[str, Any] = {}
    for attempt in range(args.verify_attempts):
        try:
            verification = api.request(
                "POST", "/api/v1/plugins/apps/plan/verify" + query
            )
        except E2EError as exc:
            if attempt + 1 == args.verify_attempts:
                raise
            print(f"verify attempt {attempt + 1} failed: {exc}")
            time.sleep(3)
            continue
        if verification.get("ok") is True:
            break
    stored = api.request("GET", "/api/v1/plugins/apps/plan" + query)
    tenants = api.request("GET", "/api/v1/plugins/tenant/tenants")
    listed = any(item.get("id") == tenant_id for item in tenants.get("tenants", []))
    checks = {
        "tenant_listed": listed,
        "plan_applied": plan.get("status") == "applied",
        "plan_still_applied": stored.get("status") == "applied",
        "plan_tenant_matches": plan.get("tenant_id") == tenant_id,
        "cell_slug_matches": plan.get("tenant_slug") == slug,
        "storage_matches": plan.get("storage_bytes") == args.storage_gib * 1024**3,
        "kernel_verify_ok": verification.get("ok") is True,
    }
    if not all(checks.values()):
        raise E2EError(f"postconditions failed: {checks}")
    return {
        "spec": "0115",
        "result": "PASS",
        "observed_at": datetime.now(UTC).isoformat(),
        "target": args.base_url,
        "tenant": created,
        "plan": plan,
        "verification": verification,
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--slug")
    parser.add_argument("--memory-gib", type=int, default=1)
    parser.add_argument("--cpus", type=float, default=1)
    parser.add_argument("--pids", type=int, default=256)
    parser.add_argument("--storage-gib", type=int, default=10)
    parser.add_argument("--verify-attempts", type=int, default=4)
    parser.add_argument(
        "--evidence", default="artifacts/0115-tenant-create-resources-e2e.json"
    )
    args = parser.parse_args()
    try:
        evidence = run(args)
    except Exception as exc:  # noqa: BLE001 - black-box runner reports exact failure
        print(f"E2E FAILED: {exc}")
        return 1
    path = Path(args.evidence)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(f"E2E PASS: tenant {evidence['tenant']['slug']} created with applied resources")
    print(f"Evidence: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
