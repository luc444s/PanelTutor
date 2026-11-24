#!/usr/bin/env python3
"""Re-deploy a tenant's Apps into its rootless cell.

Apps are not copied like Hosting volumes: an App is a Compose project built
from a repository. The safe rootless cutover is to deploy the **signed release**
that is already active, this time with the tenant's rootless Docker runtime.
The Apps worker automatically selects the cell socket when
``SPANEL_TENANTS_ROOTLESS=true``, publishes the route and records the runtime.

This tool:

* lists the tenant's applications through the Apps HTTP API;
* reads each active deployment and requires a signed
  ``release_summary.operation_id``;
* skips applications whose containers already exist in the cell socket;
* reports whether those containers carry the ``spanel.managed``/
  ``spanel.tenant`` labels required by the cell ingress (A.SPEC 0114);
* optionally re-deploys already rootless applications whose containers predate
  those labels (``--redeploy-rootless``) so the migration can publish a route;
* optionally previews with ``--dry-run``;
* re-deploys each signed release and polls the operation;
* verifies the new deployment is running and its containers live in the cell.

Apps without a signed release are reported and left untouched: they need an
explicit ``harden`` first (service users and writable paths are operator
decisions, never guessed here).

Usage (token never goes in argv; the origin is read from SPANEL_DOMAIN):

    export SPANEL_APPS_TOKEN=...           # or --token-file
    python3 scripts/migrate_tenant_apps.py --tenant demo --dry-run
    python3 scripts/migrate_tenant_apps.py --tenant demo --apply

Exit codes: 0 ok, 1 failure, 2 usage/configuration.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.spanel_apps import Client, CliError
from scripts.tenant_cell.slugs import cell_slug_for

DEFAULT_DATA_ROOT = "/var/lib/spanel"


class AppsMigrationError(RuntimeError):
    """A failure already explained to the operator."""


class ClientLike(Protocol):
    def request(
        self,
        method: str,
        path: str,
        payload: object | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> Any: ...

    def poll(self, operation_id: str, timeout: int = 900) -> Any: ...


@dataclass(frozen=True)
class CommandOutput:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class AppPlan:
    app_id: str
    name: str
    operation_id: str | None
    deployment_id: str | None
    container_ids: tuple[str, ...]
    already_rootless: bool
    # ``None`` means "not inspected" (no cell socket or no containers); only an
    # explicit ``False`` forces a relabel redeploy when requested.
    managed_labels: bool | None = None
    reason: str = ""


def run_docker(argv: list[str], *, timeout: int = 60) -> CommandOutput:
    import subprocess

    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, check=False, timeout=timeout
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandOutput(127, "", str(exc))
    return CommandOutput(completed.returncode, completed.stdout, completed.stderr)


def cell_socket(data_root: str, slug: str) -> Path:
    return Path(data_root) / "cells" / slug / "docker.sock"


class AppsMigrator:
    def __init__(
        self,
        client: ClientLike,
        *,
        tenant: str,
        data_root: str = DEFAULT_DATA_ROOT,
        dry_run: bool = False,
        app_ids: tuple[str, ...] = (),
        timeout: int = 1800,
        verify_cell: bool = True,
        redeploy_rootless: bool = False,
        runner: Any = run_docker,
    ) -> None:
        self.client = client
        self.tenant = tenant
        self.data_root = data_root
        self.dry_run = dry_run
        self.app_ids = app_ids
        self.timeout = timeout
        self.verify_cell = verify_cell
        self.redeploy_rootless = redeploy_rootless
        self.runner = runner
        self.socket = cell_socket(data_root, tenant)

    def _application_detail(self, app_id: str) -> dict[str, Any]:
        detail = self.client.request("GET", f"/applications/{app_id}")
        if not isinstance(detail, dict):
            raise AppsMigrationError(f"application {app_id}: invalid API response")
        return detail

    def _plan(self, application: dict[str, Any]) -> AppPlan:
        app_id = str(application.get("id") or "").strip()
        if not app_id:
            raise AppsMigrationError("an application without id cannot be migrated")
        active = application.get("active_deployment")
        release = (
            (active or {}).get("release_summary") if isinstance(active, dict) else None
        )
        operation = (
            (release or {}).get("operation_id") if isinstance(release, dict) else None
        )
        deployment = (active or {}).get("id") if isinstance(active, dict) else None
        details = (
            (active or {}).get("service_details") if isinstance(active, dict) else None
        )
        container_ids = tuple(
            str(item.get("container_id"))
            for item in (details or [])
            if isinstance(item, dict) and item.get("container_id")
        )
        already = False
        reason = ""
        if self.verify_cell and container_ids:
            already, reason = self._containers_in_cell(list(container_ids))
        if already:
            reason = reason or "already rootless"
        elif not operation:
            reason = "no signed release on the active deployment; harden it first"
        managed_labels = (
            self._managed_labels(list(container_ids))
            if already and container_ids
            else None
        )
        return AppPlan(
            app_id=app_id,
            name=str(application.get("name") or app_id),
            operation_id=str(operation) if operation else None,
            deployment_id=str(deployment) if deployment else None,
            container_ids=container_ids,
            already_rootless=already,
            managed_labels=managed_labels,
            reason=reason,
        )

    def _containers_in_cell(self, container_ids: list[str]) -> tuple[bool, str]:
        if not self.socket.is_socket():
            return False, f"cell socket is missing: {self.socket}"
        if not container_ids:
            return False, "deployment has no container ids"
        for container_id in container_ids:
            inspected = self.runner(
                [
                    "docker",
                    "-H",
                    f"unix://{self.socket}",
                    "inspect",
                    "-f",
                    "{{.State.Status}}",
                    container_id,
                ]
            )
            if inspected.returncode != 0:
                detail = " ".join(
                    (inspected.stderr or inspected.stdout or "").split()
                )[:200]
                return False, (
                    f"container {container_id[:12]} is not in the cell"
                    + (f": {detail}" if detail else "")
                )
        return True, "containers already run in the cell"

    def _managed_labels(self, container_ids: list[str]) -> bool | None:
        """Whether every container proves ingress ownership (A.SPEC 0114).

        Docker labels are immutable after creation: a container deployed before
        the labels existed must be recreated by a signed deploy.
        """
        if not self.socket.is_socket() or not container_ids:
            return None
        for container_id in container_ids:
            inspected = self.runner(
                [
                    "docker",
                    "-H",
                    f"unix://{self.socket}",
                    "inspect",
                    "-f",
                    "{{json .Config.Labels}}",
                    container_id,
                ]
            )
            if inspected.returncode != 0:
                return None
            try:
                labels = json.loads(inspected.stdout or "{}")
            except ValueError:
                return None
            if not isinstance(labels, dict):
                return None
            if (
                labels.get("spanel.managed") != "true"
                or not labels.get("spanel.tenant")
            ):
                return False
        return True

    def plans(self) -> list[AppPlan]:
        listed = self.client.request("GET", "/applications")
        if not isinstance(listed, list):
            raise AppsMigrationError(
                "the Apps API returned an invalid application list"
            )
        wanted = set(self.app_ids)
        result: list[AppPlan] = []
        for item in listed:
            if not isinstance(item, dict):
                continue
            app_id = str(item.get("id") or "")
            if wanted and app_id not in wanted:
                continue
            detail = self._application_detail(app_id)
            result.append(self._plan(detail))
        if wanted:
            missing = wanted - {plan.app_id for plan in result}
            if missing:
                raise AppsMigrationError(
                    "application not found for this tenant: "
                    + ", ".join(sorted(missing))
                )
        return result

    def migrate(self, plans: list[AppPlan]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for plan in plans:
            relabel = (
                plan.already_rootless
                and self.redeploy_rootless
                and plan.managed_labels is False
            )
            if plan.already_rootless and not relabel:
                results.append(
                    {
                        "ok": True,
                        "app_id": plan.app_id,
                        "name": plan.name,
                        "state": "skipped",
                        "reason": plan.reason,
                    }
                )
                continue
            if not plan.operation_id:
                results.append(
                    {
                        "ok": False,
                        "app_id": plan.app_id,
                        "name": plan.name,
                        "state": "requires_hardening",
                        "reason": plan.reason,
                    }
                )
                continue
            if self.dry_run:
                results.append(
                    {
                        "ok": True,
                        "app_id": plan.app_id,
                        "name": plan.name,
                        "state": "relabel_planned" if relabel else "planned",
                        "hardened_operation_id": plan.operation_id,
                        "reason": (
                            "containers predate spanel.managed/spanel.tenant"
                            if relabel
                            else plan.reason
                        ),
                    }
                )
                continue
            results.append(self._redeploy(plan))
        return results

    def _redeploy(self, plan: AppPlan) -> dict[str, Any]:
        try:
            operation = self.client.request(
                "POST",
                f"/applications/{plan.app_id}/deployments",
                {
                    "environment": [],
                    "hardened_operation_id": plan.operation_id,
                },
                idempotency_key=uuid4().hex,
            )
            if not isinstance(operation, dict) or not operation.get("operation_id"):
                raise AppsMigrationError("the Apps API did not return an operation id")
            finished = self.client.poll(
                str(operation["operation_id"]), timeout=self.timeout
            )
        except (CliError, AppsMigrationError) as exc:
            return {
                "ok": False,
                "app_id": plan.app_id,
                "name": plan.name,
                "state": "failed",
                "error": str(exc)[:400],
            }
        # A failed deploy leaves ``active_deployment`` pointing at the previous
        # (non-rootless) deployment, so checking it alone would blame the cell
        # instead of reporting why the operation failed.  The operation is the
        # only source of truth for this deploy attempt.
        finished = finished if isinstance(finished, dict) else {}
        operation_status = str(finished.get("status") or "")
        if operation_status != "succeeded":
            public_error = str(finished.get("public_error") or "").strip()
            return {
                "ok": False,
                "app_id": plan.app_id,
                "name": plan.name,
                "state": "failed",
                "error": (
                    public_error
                    or f"deploy operation finished as {operation_status or 'unknown'}"
                )[:400],
                "operation": finished,
            }
        detail = self._application_detail(plan.app_id)
        active = detail.get("active_deployment") or {}
        if not isinstance(active, dict) or active.get("status") != "running":
            return {
                "ok": False,
                "app_id": plan.app_id,
                "name": plan.name,
                "state": "failed",
                "error": "deployment did not become active",
                "operation": finished,
            }
        new_details = active.get("service_details") or []
        container_ids = [
            str(item.get("container_id"))
            for item in new_details
            if isinstance(item, dict) and item.get("container_id")
        ]
        if self.verify_cell and container_ids:
            ok, reason = self._containers_in_cell(container_ids)
            if not ok:
                return {
                    "ok": False,
                    "app_id": plan.app_id,
                    "name": plan.name,
                    "state": "failed",
                    "error": f"deployment is not running in the cell: {reason}",
                    "operation": finished,
                }
        elif self.verify_cell:
            return {
                "ok": False,
                "app_id": plan.app_id,
                "name": plan.name,
                "state": "failed",
                "error": "deployment has no container ids to verify in the cell",
                "operation": finished,
            }
        return {
            "ok": True,
            "app_id": plan.app_id,
            "name": plan.name,
            "state": "rootless",
            "deployment_id": active.get("id"),
            "operation_id": operation["operation_id"],
            "containers": container_ids,
        }


def load_env_file(path: Path) -> dict[str, str]:
    """Read ``KEY=VALUE`` from the host checkout without executing it."""
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def env_values(explicit: Path | None = None) -> dict[str, str]:
    """Merge the env files the host deployment already uses."""
    paths = ([explicit] if explicit is not None else []) + [
        ROOT / ".env.docker",
        ROOT / ".env",
    ]
    merged: dict[str, str] = {}
    for path in paths:
        if path is None or not path.is_file():
            continue
        for key, value in load_env_file(path).items():
            merged.setdefault(key, value)
    return merged


def read_token(path: Path | None, *, env_file: Path | None = None) -> str:
    if path is not None:
        try:
            value = path.read_text(encoding="utf-8").splitlines()[0].strip()
        except (OSError, IndexError) as exc:
            raise AppsMigrationError(f"cannot read token file {path}: {exc}") from exc
        if not value:
            raise AppsMigrationError(f"token file is empty: {path}")
        return value
    values = env_values(env_file)
    value = (
        os.environ.get("SPANEL_APPS_TOKEN")
        or os.environ.get("SPANEL_ACCESS_TOKEN")
        or values.get("SPANEL_APPS_TOKEN")
        or values.get("SPANEL_ACCESS_TOKEN")
        or ""
    ).strip()
    if not value:
        raise AppsMigrationError("SPANEL_APPS_TOKEN is required (or pass --token-file)")
    return value


def api_url(override: str | None, *, env_file: Path | None = None) -> str:
    """Resolve the panel origin from --api-url or the real SPANEL_DOMAIN."""
    value = (override or "").strip()
    if not value:
        values = env_values(env_file)
        domain = (
            os.environ.get("SPANEL_DOMAIN") or values.get("SPANEL_DOMAIN") or ""
        ).strip()
        if domain:
            value = domain if "://" in domain else f"https://{domain}"
    if not value:
        raise AppsMigrationError(
            "SPANEL_DOMAIN is required in .env.docker (or pass --api-url)"
        )
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="migrate_tenant_apps.py", description=__doc__)
    parser.add_argument(
        "--tenant", required=True, help="Tenant slug (DB); the cell slug is derived."
    )
    parser.add_argument("--api-url", default=None)
    parser.add_argument("--token-file", type=Path, default=None)
    parser.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="Optional env file; default: .env.docker then .env at the repo root.",
    )
    parser.add_argument(
        "--app", action="append", default=[], help="App id (repeatable)."
    )
    parser.add_argument("--data-root", default=DEFAULT_DATA_ROOT)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--json", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Plan only (default).")
    mode.add_argument("--apply", action="store_true", help="Redeploy signed releases.")
    parser.add_argument(
        "--no-cell-verify",
        action="store_true",
        help="Do not require the containers to appear in the cell socket.",
    )
    parser.add_argument(
        "--redeploy-rootless",
        action="store_true",
        help=(
            "Recreate already rootless containers that predate the "
            "spanel.managed/spanel.tenant labels required by the cell ingress."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    serialized: dict[str, Any]
    try:
        token = read_token(args.token_file, env_file=args.env_file)
        client = Client(
            api_url(args.api_url, env_file=args.env_file), token, timeout=60
        )
        cell_slug = cell_slug_for(args.tenant)
        migrator = AppsMigrator(
            client,
            tenant=cell_slug,
            data_root=args.data_root,
            dry_run=not args.apply,
            app_ids=tuple(args.app),
            timeout=args.timeout,
            verify_cell=not args.no_cell_verify,
            redeploy_rootless=args.redeploy_rootless,
        )
        plans = migrator.plans()
        results = migrator.migrate(plans)
        ok = all(item.get("ok") for item in results)
        serialized = {
            "ok": ok,
            "tenant": args.tenant,
            "cell_slug": cell_slug,
            "dry_run": not args.apply,
            "apps": [
                {
                    "app_id": plan.app_id,
                    "name": plan.name,
                    "already_rootless": plan.already_rootless,
                    "managed_labels": plan.managed_labels,
                    "signed_release": plan.operation_id,
                    "reason": plan.reason,
                }
                for plan in plans
            ],
            "results": results,
        }
    except (AppsMigrationError, CliError) as exc:
        serialized = {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - operator boundary
        serialized = {"ok": False, "error": f"unexpected failure: {exc}"[:400]}
    if args.json:
        print(json.dumps(serialized, indent=2, sort_keys=True, default=str))
    else:
        _print_human(serialized)
    return 0 if serialized.get("ok") else 1


def _print_human(payload: dict[str, Any]) -> None:
    if not payload.get("ok") and payload.get("error"):
        print(f"ERROR: {payload['error']}", file=sys.stderr)
        return
    print(f"tenant: {payload.get('tenant')}  dry-run: {payload.get('dry_run')}")
    for item in payload.get("results", []):
        print(
            f"- {item.get('name')} ({item.get('app_id')}): "
            f"{item.get('state')}"
            + (f" — {item.get('reason')}" if item.get("reason") else "")
            + (f" — {item.get('error')}" if item.get("error") else "")
        )


if __name__ == "__main__":
    raise SystemExit(main())
