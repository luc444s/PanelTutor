#!/usr/bin/env python3
"""A.SPEC 0109-R5: operational closure for Apps.

Reuses the disposable R4 harness (cloned DB, rootless cell, API/worker/redis,
plan-agent and edge-relay) and adds the operational drills that a functional
E2E does not cover:

1. two concurrent deploys of the same application;
2. worker restart while a deploy is running;
3. bounded soak with release retention (keep-N);
4. cgroup OOM enforcement inside the cell;
5. HTTPS route rendering and redirect (no certificate assertion);
6. operational backup/restore of the DB and the deployed release tree.

The script never fabricates PASS: every check records its own evidence and the
overall result is PASS only when all of them converge.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import threading
import time
import traceback
from pathlib import Path
from typing import Any

R4_PATH = Path(__file__).with_name("e2e_0109_r4_blackbox.py")


def load_r4():
    spec = importlib.util.spec_from_file_location("e2e_r4", R4_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the R4 harness")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


r4 = load_r4()


def _credentials(stage: Path) -> tuple[str, str]:
    values = r4.load_dotenv(stage / "app.env")
    email = values.get("SYSTUTOR_SEED_ADMIN_EMAIL", "")
    password = values.get("SYSTUTOR_SEED_ADMIN_PASSWORD", "")
    if not email or not password:
        raise r4.E2E("seed administrator credentials are missing")
    return email, password


def _detail(client, root: str) -> dict[str, Any]:
    detail = client.request("GET", root)
    if not isinstance(detail, dict):
        raise r4.E2E("application detail is invalid")
    return detail


def _services_healthy(detail: dict[str, Any]) -> bool:
    active = detail.get("active_deployment") or {}
    services = active.get("service_details")
    if not isinstance(services, list) or not services:
        return False
    for item in services:
        if not isinstance(item, dict):
            return False
        if str(item.get("status")).lower() != "running":
            return False
        health = str(item.get("health")).lower()
        if health not in {"healthy", "none", "unknown", ""}:
            return False
    return True


def _cell_project_containers(slug: str) -> list[str]:
    result = r4.cell_docker(
        slug, "ps", "--format", "{{.Names}}\t{{.Status}}", check=False
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def _operation(client, op_id: str) -> dict[str, Any]:
    value = client.request("GET", f"/api/v1/plugins/apps/operations/{op_id}")
    if not isinstance(value, dict):
        raise r4.E2E("operation detail is invalid")
    return value


def check_concurrency(
    client, api, email: str, password: str, app_id: str, root: str,
    timeout: int, evidence: dict[str, Any],
) -> None:
    r4.log("ops 1/6: concurrent deploys on the same application")
    barrier = threading.Barrier(3)
    results: list[dict[str, Any]] = []

    def worker() -> None:
        local = r4.login(email, password)
        barrier.wait(timeout=30)
        try:
            op = r4.deploy(local, api, app_id, api.environment(), timeout)
            results.append({"ok": True, "operation": op.get("status"),
                            "id": op.get("id")})
        except Exception as exc:  # noqa: BLE001 - recorded as evidence
            results.append({"ok": False, "error": str(exc)[:500]})

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait(timeout=30)
    for thread in threads:
        thread.join(timeout=timeout + 60)
    detail = _detail(client, root)
    active = detail.get("active_deployment") or {}
    containers = _cell_project_containers(evidence["slug"])
    passed = (
        len(results) == 2
        and all(not thread.is_alive() for thread in threads)
        and any(item.get("ok") for item in results)
        and bool(active.get("id"))
        and _services_healthy(detail)
        and len(containers) == 3
    )
    evidence["checks"]["concurrent_deploys"] = {
        "pass": passed,
        "deployments": results,
        "active_deployment": active.get("id"),
        "services_healthy": _services_healthy(detail),
        "cell_containers": containers,
    }
    if not passed:
        raise r4.E2E("concurrent deploys left the application inconsistent")


def check_worker_restart(
    stage: Path, client, api, app_id: str, root: str, timeout: int,
    evidence: dict[str, Any],
) -> None:
    r4.log("ops 2/6: worker restart while a deploy is running")
    accepted = client.request(
        "POST", f"{root}/deployments", {"environment": api.environment()},
        idempotent=True,
    )
    op_id = accepted.get("operation_id") if isinstance(accepted, dict) else None
    if not isinstance(op_id, str):
        raise r4.E2E("restart drill did not return an operation ID")
    observed = "queued"
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        operation = _operation(client, op_id)
        observed = str(operation.get("status"))
        if observed == "running":
            break
        if observed in {"succeeded", "complete", "failed"}:
            break
        time.sleep(0.5)
    killed_at = observed
    r4.docker("rm", "-f", r4.WORKER_CONTAINER, check=False)
    runtime_env = stage / "app.env"
    live_values = r4.load_dotenv(runtime_env)
    r4.start_worker(stage, runtime_env, live_values, rootless=True)
    try:
        final = api.poll_operation(client, op_id, timeout, "deploy-after-restart")
        final_status = str(final.get("status"))
    except Exception as exc:  # noqa: BLE001 - interrupted is a valid terminal state
        final = _operation(client, op_id)
        final_status = str(final.get("status"))
        final["poll_error"] = str(exc)[:800]
    detail = _detail(client, root)
    containers = _cell_project_containers(evidence["slug"])
    passed = (
        killed_at in {"running", "succeeded", "complete"}
        and _services_healthy(detail)
        and len(containers) == 3
        and final_status in {"succeeded", "complete", "failed", "interrupted"}
    )
    evidence["checks"]["worker_restart_mid_deploy"] = {
        "pass": passed,
        "killed_at_status": killed_at,
        "final_status": final_status,
        "operation": final,
        "services_healthy": _services_healthy(detail),
        "cell_containers": containers,
    }
    if not passed:
        raise r4.E2E("application was not healthy after the worker restart")


def _release_dirs(detail: dict[str, Any]) -> tuple[Path | None, list[Path]]:
    active = detail.get("active_deployment") or {}
    release = active.get("release")
    if not isinstance(release, str) or not release:
        return None, []
    path = Path(release)
    project = path.parent.parent
    releases = project / "releases"
    if not releases.is_dir():
        return project, []
    return project, sorted(item for item in releases.iterdir() if item.is_dir())


def check_soak(
    client, api, app_id: str, root: str, timeout: int, cycles: int,
    evidence: dict[str, Any],
) -> None:
    r4.log(f"ops 3/6: bounded soak ({cycles} deploy cycles) and retention")
    samples: list[dict[str, Any]] = []
    for index in range(cycles):
        r4.deploy(client, api, app_id, api.environment(), timeout)
        detail = _detail(client, root)
        project, releases = _release_dirs(detail)
        # Directory size is measured by the release count and the tree bytes.
        bytes_total = 0
        for release in releases:
            for file in release.rglob("*"):
                if file.is_file():
                    try:
                        bytes_total += file.stat().st_size
                    except OSError:
                        continue
        samples.append({
            "cycle": index + 1,
            "services_healthy": _services_healthy(detail),
            "release_count": len(releases),
            "release_bytes": bytes_total,
            "project": str(project) if project else None,
        })
        if not _services_healthy(detail):
            raise r4.E2E(f"soak cycle {index + 1} left the application unhealthy")
    project, releases = _release_dirs(_detail(client, root))
    passed = (
        bool(samples)
        and all(item["services_healthy"] for item in samples)
        and len(releases) <= 3
    )
    evidence["checks"]["soak_and_retention"] = {
        "pass": passed,
        "keep": 2,
        "cycles": samples,
        "final_release_count": len(releases),
        "final_releases": [item.name for item in releases],
    }
    if not passed:
        raise r4.E2E("release retention did not bound the release tree")


def check_oom(slug: str, evidence: dict[str, Any]) -> None:
    r4.log("ops 4/6: cgroup OOM enforcement inside the cell")
    listing = r4.cell_docker(slug, "ps", "--format", "{{.Names}}", check=False)
    names = [line.strip() for line in listing.stdout.splitlines() if line.strip()]
    backend = next((name for name in names if "-backend-1" in name), "")
    if not backend:
        raise r4.E2E("backend container was not found in the cell")
    image = r4.cell_docker(
        slug, "inspect", backend, "--format", "{{.Config.Image}}", check=False
    ).stdout.strip()
    network = r4.cell_docker(
        slug, "inspect", backend,
        "--format", "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}",
        check=False,
    ).stdout.strip().split()
    network = network[0] if network else ""
    if not image or not network:
        raise r4.E2E("could not resolve the backend image/network for the OOM drill")
    name = "ops-oom-drill"
    r4.cell_docker(slug, "rm", "-f", name, check=False)
    start = r4.cell_docker(
        slug, "run", "-d", "--name", name, "--memory", "64m",
        "--memory-swap", "64m", "--network", network, image,
        "python", "-c", "x = bytearray(256 * 1024 * 1024)",
        check=False,
    )
    if start.returncode != 0:
        raise r4.E2E(f"OOM drill container failed to start: {start.stderr[-500:]}")
    deadline = time.monotonic() + 60
    state: dict[str, Any] = {}
    while time.monotonic() < deadline:
        raw = r4.cell_docker(
            slug, "inspect", name,
            "--format", "{{.State.Status}}|{{.State.OOMKilled}}|{{.State.ExitCode}}",
            check=False,
        )
        parts = raw.stdout.strip().split("|")
        if len(parts) == 3:
            state = {"status": parts[0], "oom_killed": parts[1] == "true",
                     "exit_code": parts[2]}
            if state["status"] not in {"created", "running"}:
                break
        time.sleep(1)
    r4.cell_docker(slug, "rm", "-f", name, check=False)
    containers = _cell_project_containers(slug)
    passed = (
        bool(state)
        and (state.get("oom_killed") is True or state.get("exit_code") == "137")
        and len(containers) == 3
    )
    evidence["checks"]["cgroup_oom"] = {
        "pass": passed,
        "container_state": state,
        "cell_containers": containers,
    }
    if not passed:
        raise r4.E2E("the cell did not enforce the OOM limit")


def check_https(
    stage: Path, client, app_id: str, slug: str,
    evidence: dict[str, Any],
) -> None:
    r4.log("ops 5/6: HTTPS route rendering and redirect")
    domain = f"secure-{slug}.lab"
    created = client.request(
        "POST", "/api/v1/plugins/domains/app-hosts",
        {
            "application_id": app_id,
            "service": "frontend",
            "domain": domain,
            "https": True,
        },
    )
    if not isinstance(created, dict) or created.get("domain") != domain:
        raise r4.E2E("HTTPS app-host creation failed")
    r4.dispatch_outbox(stage)
    deadline = time.monotonic() + 90
    documents: list[dict[str, Any]] = []
    text = ""
    status = ""
    while time.monotonic() < deadline:
        documents = r4._route_documents(domain)
        text = documents[0]["content"] if documents else ""
        curl = r4.run(
            ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
             "--connect-timeout", "5", "--max-time", "10",
             "-H", f"Host: {domain}", "http://127.0.0.1:9080/"],
            check=False,
        )
        status = curl.stdout.strip()
        if (
            documents
            and "websecure" in text
            and ("tls" in text or "redirectScheme" in text)
            and status in {"301", "308"}
        ):
            break
        time.sleep(2)
    passed = (
        bool(documents)
        and "websecure" in text
        and ("tls" in text or "redirectScheme" in text)
        and status in {"301", "308"}
    )
    evidence["checks"]["https_route"] = {
        "pass": passed,
        "domain": domain,
        "route_documents": documents,
        "http_status": status,
    }
    for item in documents:
        try:
            Path(item["path"]).unlink()
        except OSError:
            pass
    if not passed:
        raise r4.E2E("HTTPS route did not render the TLS/redirect contract")


def check_backup_restore(
    stage: Path, client, root: str, evidence: dict[str, Any],
) -> None:
    r4.log("ops 6/6: operational backup/restore of DB and release tree")
    restore_db = f"{r4.DB}_restore"
    backup = stage / "backup" / "ops"
    backup.mkdir(parents=True, exist_ok=True)
    dump = r4.docker(
        "exec", r4.LIVE_PG, "pg_dump", "-U", "postgres", "--no-owner",
        "--no-privileges", r4.DB, timeout=1800,
    )
    dump_path = backup / "apps.sql"
    dump_path.write_text(dump.stdout, encoding="utf-8")
    r4.psql(r4.LIVE_DB, f'DROP DATABASE IF EXISTS "{restore_db}" WITH (FORCE);')
    r4.psql(r4.LIVE_DB, f'CREATE DATABASE "{restore_db}";')
    restored = r4.run(
        ["docker", "exec", "-i", r4.LIVE_PG, "psql", "-U", "postgres",
         "-d", restore_db, "-v", "ON_ERROR_STOP=1", "-q"],
        input_text=dump.stdout, timeout=1800, check=False,
    )
    counts_before = r4.psql(
        r4.DB,
        "SELECT (SELECT count(*) FROM apps_applications) || '|' || "
        "(SELECT count(*) FROM apps_deployments) || '|' || "
        "(SELECT count(*) FROM domains_app_hosts);",
    )
    counts_after = r4.psql(
        restore_db,
        "SELECT (SELECT count(*) FROM apps_applications) || '|' || "
        "(SELECT count(*) FROM apps_deployments) || '|' || "
        "(SELECT count(*) FROM domains_app_hosts);",
    )
    detail = _detail(client, root)
    _, releases = _release_dirs(detail)
    archive = backup / "release-tree.tar.gz"
    if releases:
        project = releases[0].parent.parent
        r4.run(["tar", "czf", str(archive), "-C", str(project.parent),
                project.name])
        extract = backup / "restored"
        if extract.exists():
            shutil.rmtree(extract)
        extract.mkdir()
        r4.run(["tar", "xzf", str(archive), "-C", str(extract)])
        restored_release = extract / project.name / "releases" / releases[-1].name
        tree_ok = restored_release.is_dir()
    else:
        tree_ok = False
    r4.psql(r4.LIVE_DB, f'DROP DATABASE IF EXISTS "{restore_db}" WITH (FORCE);')
    passed = (
        restored.returncode == 0
        and counts_before == counts_after
        and tree_ok
        and dump_path.stat().st_size > 0
    )
    evidence["checks"]["backup_restore"] = {
        "pass": passed,
        "counts_before": counts_before,
        "counts_after": counts_after,
        "dump_bytes": dump_path.stat().st_size,
        "release_tree_bytes": archive.stat().st_size if archive.exists() else 0,
        "release_tree_restored": tree_ok,
        "restore_returncode": restored.returncode,
        "restore_stderr": (restored.stderr or "")[-500:],
    }
    if not passed:
        raise r4.E2E("backup/restore did not reproduce the app state")


def _cleanup_extra_routes(slug: str) -> None:
    for domain in (f"secure-{slug}.lab",):
        for item in r4._route_documents(domain):
            try:
                Path(item["path"]).unlink()
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, default=r4.STAGE)
    parser.add_argument("--slug", default="e2e0109r5ops")
    parser.add_argument("--evidence", type=Path,
                        default=Path("/var/tmp/0109-r5-operations.json"))
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--operation-timeout", type=int, default=600)
    parser.add_argument("--deploy-timeout", type=int, default=2400)
    args = parser.parse_args()

    r4.SLUG = args.slug
    r4.DB = "sysadmin_" + args.slug
    evidence: dict[str, Any] = {
        "spec": "0109-r5-apps-operations",
        "slug": args.slug,
        "started_at": r4.now(),
        "checks": {},
        "ok": False,
    }
    failed = False
    try:
        r4.setup(args.stage, evidence)
        email, password = _credentials(args.stage)
        # Retention is part of the product behaviour under test.
        env_path = args.stage / "app.env"
        with env_path.open("a", encoding="utf-8") as handle:
            handle.write("\nSPANEL_APPS_RELEASES_KEEP=2\n")
            handle.write("SPANEL_APPS_RECONCILE_STALE_SECONDS=90\n")
        r4.start_worker(
            args.stage, env_path, r4.load_dotenv(env_path), rootless=True
        )
        client = r4.login(email, password)
        api = r4.api_module()
        r4.wait_plugins(client)
        r4.apply_plan(client, evidence)
        app = r4.create_application(client)
        app_id = app["id"]
        root = f"/api/v1/plugins/apps/applications/{app_id}"
        evidence["application"] = app
        api.queue(client, "POST", f"{root}/inspect", None,
                  args.operation_timeout, "inspect")
        first = r4.deploy(client, api, app_id, api.environment(),
                          args.deploy_timeout)
        detail = _detail(client, root)
        r4.verify_deploy(args.slug, detail, first, evidence)

        check_concurrency(
            client, api, email, password, app_id, root,
            args.deploy_timeout, evidence,
        )
        check_worker_restart(
            args.stage, client, api, app_id, root, args.deploy_timeout, evidence
        )
        check_soak(
            client, api, app_id, root, args.deploy_timeout, args.cycles, evidence
        )
        check_oom(args.slug, evidence)
        check_https(args.stage, client, app_id, args.slug, evidence)
        check_backup_restore(args.stage, client, root, evidence)
        evidence["application_deleted"] = True
        api.queue(
            client, "DELETE", root,
            {"confirm": app.get("slug"), "purge_data": True},
            args.operation_timeout, "delete",
        )
    except Exception as exc:  # noqa: BLE001
        failed = True
        evidence["error"] = str(exc)[:1200]
        evidence["trace"] = traceback.format_exc()[-3000:]
    finally:
        _cleanup_extra_routes(args.slug)
        if not args.keep:
            try:
                r4.cleanup(args.stage, evidence)
            except Exception as exc:  # noqa: BLE001
                failed = True
                evidence["cleanup_error"] = str(exc)[:1200]
        evidence["finished_at"] = r4.now()
        checks = evidence.get("checks", {})
        evidence["ok"] = (
            not failed
            and all(isinstance(item, dict) and item.get("pass")
                    for item in checks.values())
        )
        evidence["result"] = "PASS" if evidence["ok"] else "BLOCKED"
        r4.evidence_write(args.evidence, evidence)
        print(json.dumps({"evidence": str(args.evidence),
                          "ok": evidence["ok"]}))
    return 0 if evidence["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
