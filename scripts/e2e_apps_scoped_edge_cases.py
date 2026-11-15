#!/usr/bin/env python3
"""Real edge-case E2E for A.SPEC 0088 scoped deployments.

Covers the additional cases after the mandatory frontend canary:

1. per-service deploy of one service;
2. per-service rollback to the previous deployment;
3. a later global deploy clearing the service override;
4. a failed partial deploy restoring only the touched service, then a
   subsequent global deploy proving the published state is still consistent.

The run uses the real lab API, worker, Git remote and Docker host.  It leaves the
branch without the canary file and the application deployed on the restored
release.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import secrets
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"{path.name} is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


scoped = _load("spanel_scoped_e2e", ROOT / "e2e_apps_scoped_deploy.py")
api = scoped.api
ApiClient = scoped.ApiClient
E2EError = api.E2EError

CANARY_FILE = scoped.CANARY_FILE
TITLE_FILE = "frontend/index.html"
BASELINE_TITLE = "<title>Panel Editor</title>"
BROKEN_TITLE = "<title>Panel E2E Broken</title>"


def _commit_push(checkout: Path, message: str, token: str) -> str:
    scoped._run_git(checkout, ["add", "-A"])
    scoped._run_git(checkout, ["commit", "-m", message])
    scoped._run_git(checkout, ["push", "origin", f"HEAD:{scoped.BRANCH}"], token=token)
    return scoped._run_git(checkout, ["rev-parse", "HEAD"]).stdout.strip()


def _write_canary(checkout: Path, canary: str, token: str) -> str:
    path = checkout / CANARY_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canary + "\n", encoding="utf-8")
    return _commit_push(checkout, f"e2e: edge canary {canary}", token)


def _remove_canary(checkout: Path, token: str) -> str:
    scoped._run_git(checkout, ["rm", "--quiet", "--", CANARY_FILE])
    return _commit_push(checkout, "e2e: edge revert canary", token)


def _break_title(checkout: Path, token: str) -> str:
    path = checkout / TITLE_FILE
    text = path.read_text(encoding="utf-8")
    if BASELINE_TITLE not in text:
        raise E2EError("the fixture title is not the expected baseline")
    path.write_text(text.replace(BASELINE_TITLE, BROKEN_TITLE), encoding="utf-8")
    return _commit_push(checkout, "e2e: break frontend probe", token)


def _restore_branch(checkout: Path, initial_commit: str, token: str) -> None:
    scoped._run_git(checkout, ["checkout", initial_commit, "--", TITLE_FILE])
    if (checkout / CANARY_FILE).exists():
        scoped._run_git(checkout, ["rm", "--quiet", "--", CANARY_FILE])
    status = scoped._run_git(checkout, ["status", "--porcelain"]).stdout.strip()
    if status:
        _commit_push(checkout, "e2e: restore edge fixture", token)


def _deploy(
    client: ApiClient, root: str, payload: dict[str, Any], timeout: int, label: str
) -> dict[str, Any]:
    body = {**payload, "hardening": scoped.HARDENING_POLICY}
    return api.queue(client, "POST", f"{root}/deployments", body, timeout, label)


def _rollback(
    client: ApiClient,
    root: str,
    deployment_id: str,
    scope: dict[str, Any],
    timeout: int,
    label: str,
) -> dict[str, Any]:
    body = {"to_deployment_id": deployment_id, "scope": scope}
    return api.queue(client, "POST", f"{root}/rollback", body, timeout, label)


def _queue_expect_failure(
    client: ApiClient,
    path: str,
    body: object,
    timeout: int,
    label: str,
) -> dict[str, Any]:
    accepted = client.request("POST", path, body, idempotent=True)
    operation_id = accepted.get("operation_id") if isinstance(accepted, dict) else None
    if not isinstance(operation_id, str):
        raise E2EError(f"{label} did not return an operation ID")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        operation = client.request(
            "GET", f"/api/v1/plugins/apps/operations/{operation_id}"
        )
        if operation["status"] in api.TERMINAL:
            if operation["status"] == "succeeded":
                raise E2EError(f"{label} unexpectedly succeeded")
            return operation
        time.sleep(2)
    raise E2EError(f"{label} did not finish within {timeout}s")


def _service_state(detail: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    return scoped.service_state(detail, label)


def _assert_unchanged(
    before: Mapping[str, dict[str, Any]],
    after: Mapping[str, dict[str, Any]],
    names: Sequence[str],
    label: str,
) -> None:
    for name in names:
        for key in ("container_id", "image_id", "started_at"):
            if before[name][key] != after[name][key]:
                raise E2EError(f"{label}: {name} changed {key}")
        if after[name]["restart_count"] != 0:
            raise E2EError(f"{label}: {name} restarted")


def _assert_changed(
    before: Mapping[str, dict[str, Any]],
    after: Mapping[str, dict[str, Any]],
    names: Sequence[str],
    label: str,
) -> None:
    for name in names:
        if before[name]["container_id"] == after[name]["container_id"]:
            raise E2EError(f"{label}: {name} was not recreated")


def _active(detail: dict[str, Any], label: str) -> dict[str, Any]:
    active = detail.get("active_deployment")
    if not isinstance(active, dict):
        raise E2EError(f"{label}: active deployment is missing")
    return active


def _assert_scope(result: Mapping[str, Any], scope: str, services: Sequence[str],
                  service: str | None, label: str) -> Mapping[str, Any]:
    plan = result.get("scope")
    if not isinstance(plan, Mapping):
        raise E2EError(f"{label}: planner scope is missing")
    if plan.get("requested_scope") != scope:
        raise E2EError(f"{label}: expected {scope} scope")
    if plan.get("requested_service") != service:
        raise E2EError(f"{label}: unexpected requested service")
    if plan.get("effective_services") != list(services):
        raise E2EError(f"{label}: unexpected effective services")
    return plan


def _docker_service_container(project: str, service: str) -> str:
    output = scoped._docker([
        "ps", "--filter", f"label=com.docker.compose.project={project}",
        "--filter", f"label=com.docker.compose.service={service}",
        "--format", "{{.ID}}",
    ]).strip().splitlines()
    if len(output) != 1:
        raise E2EError(f"expected one running {service} container")
    return output[0]


def run(args: argparse.Namespace) -> int:
    base_url = api.validate_base_url(args.base_url)
    email = os.environ.get("SPANEL_E2E_EMAIL", "").strip()
    password_path = os.environ.get("SPANEL_E2E_PASSWORD_FILE", "").strip()
    if not email or not password_path:
        raise E2EError("SPANEL_E2E_EMAIL and SPANEL_E2E_PASSWORD_FILE are required")
    token = (
        args.git_token or os.environ.get("SPANEL_E2E_GIT_TOKEN", "").strip()
        or os.environ.get("GH_TOKEN", "").strip()
    )
    canary = f"edge-{secrets.token_hex(12)}"
    evidence: dict[str, Any] = {
        "base_url": base_url, "repository": args.repository,
        "branch": args.branch, "compose_file": args.compose_file,
        "canary": canary, "status": "failed",
    }
    client = ApiClient(base_url)
    password = api.read_password(Path(password_path))
    checkout: Path | None = None
    initial_commit = ""
    started = time.monotonic()
    try:
        print("[1/12] Login")
        login = client.request(
            "POST", "/api/v1/auth/login", {"email": email, "password": password}
        )
        password = ""
        token_value = login.get("access_token") if isinstance(login, dict) else None
        if not isinstance(token_value, str) or not token_value:
            raise E2EError("login did not return an access token")
        client.token = token_value
        profile = client.request("GET", "/api/v1/auth/me")
        missing = scoped.REQUIRED_PERMISSIONS.difference(
            set(profile.get("permissions", []))
        )
        if missing:
            raise E2EError(f"login lacks permissions: {', '.join(sorted(missing))}")

        print("[2/12] Clone and validate the real branch")
        with tempfile.TemporaryDirectory(prefix="spanel-scoped-edge-") as temporary:
            checkout = Path(temporary) / "checkout"
            scoped.clone_branch(
                args.repository, args.branch, token, args.git_remote, checkout
            )
            initial_commit = scoped.remote_is_clean(checkout, args.branch)
            evidence["initial_commit"] = initial_commit

            print("[3/12] Create application and run the baseline deploy")
            installation_id, repository_id = scoped.find_repository(
                client, args.repository
            )
            suffix = secrets.token_hex(5)
            application = client.request(
                "POST",
                "/api/v1/plugins/apps/applications",
                {
                    "name": f"Scoped Edge E2E {suffix}",
                    "installation_id": installation_id,
                    "repository_id": repository_id,
                    "branch": args.branch,
                    "compose_file": args.compose_file,
                },
            )
            if not isinstance(application, dict) or not application.get("id"):
                raise E2EError("create application returned an invalid response")
            application_id = application["id"]
            root = f"/api/v1/plugins/apps/applications/{application_id}"
            detail = client.request("GET", root)
            project = detail.get("runtime_project")
            if not isinstance(project, str) or not project:
                raise E2EError("application runtime project is missing")
            evidence.update({
                "application_id": application_id,
                "application_slug": application.get("slug"),
                "runtime_project": project,
            })
            baseline = _deploy(
                client, root, {"environment": []}, args.deploy_timeout, "baseline"
            )
            baseline_result = baseline.get("result") or {}
            baseline_release = baseline_result.get("release_id")
            if not isinstance(baseline_release, str):
                raise E2EError("baseline deploy did not expose a release")
            detail = client.request("GET", root)
            baseline_state = _service_state(detail, "baseline")
            scoped.assert_probes((_active(detail, "baseline")).get("probes"))
            deployments = client.request("GET", f"{root}/deployments")
            baseline_deployment = next(
                (
                    item["id"] for item in deployments
                    if isinstance(item, dict)
                    and item.get("release_id") == baseline_release
                ),
                None,
            )
            if not isinstance(baseline_deployment, str):
                raise E2EError("baseline deployment id is missing")
            evidence["baseline"] = {
                "release_id": baseline_release,
                "deployment_id": baseline_deployment,
                "services": baseline_state,
            }

            print("[4/12] Per-service deploy of frontend")
            canary_commit = _write_canary(checkout, canary, token)
            evidence["canary_commit"] = canary_commit
            service_scope = {"type": "service", "service": "frontend"}
            deployed = _deploy(
                client, root,
                {"environment": [], "scope": service_scope},
                args.deploy_timeout, "service deploy",
            )
            deployed_result = deployed.get("result") or {}
            _assert_scope(
                deployed_result, "service", ["frontend"], "frontend", "service deploy"
            )
            deployed_release = deployed_result.get("release_id")
            detail = client.request("GET", root)
            service_state = _service_state(detail, "service deploy")
            _assert_changed(baseline_state, service_state, ["frontend"], "service deploy")
            _assert_unchanged(
                baseline_state, service_state, ["backend", "database"], "service deploy"
            )
            active = _active(detail, "service deploy")
            if active.get("overrides") != ["frontend"]:
                raise E2EError("service deploy did not record the frontend override")
            if (active.get("service_releases") or {}).get("frontend") != deployed_release:
                raise E2EError("service deploy did not publish the frontend release")
            if active.get("global_release_id") != baseline_release:
                raise E2EError("service deploy changed the global release")
            evidence["service_deploy"] = {
                "release_id": deployed_release,
                "scope": deployed_result.get("scope"),
                "services": service_state,
                "overrides": active.get("overrides"),
            }

            print("[5/12] Per-service rollback of frontend")
            rolled_back = _rollback(
                client, root, baseline_deployment, service_scope,
                args.deploy_timeout, "service rollback",
            )
            rollback_result = rolled_back.get("result") or {}
            _assert_scope(
                rollback_result, "service", ["frontend"], "frontend",
                "service rollback",
            )
            detail = client.request("GET", root)
            rollback_state = _service_state(detail, "service rollback")
            _assert_changed(
                service_state, rollback_state, ["frontend"], "service rollback"
            )
            _assert_unchanged(
                service_state, rollback_state, ["backend", "database"],
                "service rollback",
            )
            active = _active(detail, "service rollback")
            if active.get("overrides") != []:
                raise E2EError("service rollback did not clear the override")
            if (active.get("service_releases") or {}).get("frontend") != baseline_release:
                raise E2EError("service rollback did not restore the baseline release")
            evidence["service_rollback"] = {
                "release_id": rollback_result.get("release_id"),
                "scope": rollback_result.get("scope"),
                "services": rollback_state,
                "overrides": active.get("overrides"),
            }

            print("[6/12] Recreate the override with another service deploy")
            again = _deploy(
                client, root,
                {"environment": [], "scope": service_scope},
                args.deploy_timeout, "override deploy",
            )
            detail = client.request("GET", root)
            override_state = _service_state(detail, "override deploy")
            _assert_changed(
                rollback_state, override_state, ["frontend"], "override deploy"
            )
            _assert_unchanged(
                rollback_state, override_state, ["backend", "database"],
                "override deploy",
            )
            if (_active(detail, "override deploy").get("overrides")) != ["frontend"]:
                raise E2EError("override deploy did not re-create the override")
            evidence["override_deploy"] = {
                "release_id": (again.get("result") or {}).get("release_id"),
                "services": override_state,
            }

            print("[7/12] Global deploy clears the service override")
            clean_commit = _remove_canary(checkout, token)
            evidence["clean_commit"] = clean_commit
            cleared = _deploy(
                client, root, {"environment": []}, args.deploy_timeout,
                "global clear",
            )
            cleared_result = cleared.get("result") or {}
            _assert_scope(
                cleared_result, "global", ["frontend"], None, "global clear"
            )
            cleared_release = cleared_result.get("release_id")
            detail = client.request("GET", root)
            cleared_state = _service_state(detail, "global clear")
            _assert_changed(
                override_state, cleared_state, ["frontend"], "global clear"
            )
            _assert_unchanged(
                override_state, cleared_state, ["backend", "database"],
                "global clear",
            )
            active = _active(detail, "global clear")
            if active.get("overrides") != []:
                raise E2EError("global deploy did not clear the override")
            if active.get("global_release_id") != cleared_release:
                raise E2EError("global deploy did not publish the new global release")
            if any(
                value != cleared_release
                for value in (active.get("service_releases") or {}).values()
            ):
                raise E2EError("global deploy left a service release behind")
            evidence["global_clear"] = {
                "release_id": cleared_release,
                "scope": cleared_result.get("scope"),
                "services": cleared_state,
                "overrides": active.get("overrides"),
            }

            print("[8/12] Break only the frontend release")
            broken_commit = _break_title(checkout, token)
            evidence["broken_commit"] = broken_commit
            before_failure = cleared_state
            before_active = _active(detail, "before failure")

            print("[9/12] Service deploy must fail and restore frontend only")
            failed = _queue_expect_failure(
                client,
                f"{root}/deployments",
                {
                    "environment": [],
                    "scope": service_scope,
                    "hardening": scoped.HARDENING_POLICY,
                },
                args.deploy_timeout,
                "failing service deploy",
            )
            if failed.get("status") != "failed":
                raise E2EError("failing service deploy was not reported as failed")
            detail = client.request("GET", root)
            restored_active = _active(detail, "restored")
            restored_state = _service_state(detail, "restored")
            if restored_active.get("id") == before_active.get("id"):
                raise E2EError("restoration did not publish a new active deployment")
            if detail.get("status") != "running":
                raise E2EError("application is not running after restoration")
            if restored_active.get("global_release_id") != cleared_release:
                raise E2EError("restoration changed the global release")
            if (restored_active.get("service_releases") or {}).get("frontend") != cleared_release:
                raise E2EError("restoration did not return frontend to the global release")
            _assert_unchanged(
                before_failure, restored_state, ["backend", "database"], "restoration"
            )
            live_frontend = _docker_service_container(project, "frontend")
            live_image = scoped._docker(
                ["inspect", "-f", "{{.Image}}", live_frontend]
            ).strip()
            if live_image != before_failure["frontend"]["image_id"]:
                raise E2EError("restored frontend is not running the previous image")
            evidence["failed_restore"] = {
                "operation_error": failed.get("public_error") or failed.get("error_code"),
                "active_deployment_id": restored_active.get("id"),
                "services": restored_state,
                "frontend_container_id": live_frontend,
                "frontend_image_id": live_image,
            }

            print("[10/12] Restore the branch and prove the state is still deployable")
            _restore_branch(checkout, initial_commit, token)
            final = _deploy(
                client, root, {"environment": []}, args.deploy_timeout,
                "post-restore global",
            )
            final_result = final.get("result") or {}
            _assert_scope(
                final_result, "global", [], None, "post-restore global"
            )
            detail = client.request("GET", root)
            final_state = _service_state(detail, "post-restore global")
            _assert_unchanged(
                restored_state, final_state, ["frontend", "backend", "database"],
                "post-restore global",
            )
            scoped.assert_probes((_active(detail, "post-restore global")).get("probes"))
            evidence["post_restore_global"] = {
                "scope": final_result.get("scope"),
                "services": final_state,
            }

            print("[11/12] Validate branch hygiene")
            status = scoped._run_git(checkout, ["status", "--porcelain"]).stdout.strip()
            if status or (checkout / CANARY_FILE).exists():
                raise E2EError("the branch is not clean after the edge run")
            evidence["branch_clean"] = True
            evidence["application_left_deployed"] = True
            evidence["status"] = "passed"
            evidence["elapsed_seconds"] = round(time.monotonic() - started, 2)
            print("[12/12] Edge cases passed")
    except Exception as exc:
        evidence["error"] = str(exc)
        raise
    finally:
        if checkout is not None and initial_commit and token:
            try:
                _restore_branch(checkout, initial_commit, token)
            except Exception as cleanup_exc:  # noqa: BLE001
                evidence["cleanup_error"] = str(cleanup_exc)
        client.token = None
        token = ""
        evidence_path = Path(args.evidence) if args.evidence else None
        if evidence_path is not None:
            scoped.write_evidence(evidence_path, evidence)
            print(f"evidence written: {evidence_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url", default=os.environ.get("SPANEL_E2E_BASE_URL", "").strip()
    )
    parser.add_argument("--repository", default=scoped.REPOSITORY)
    parser.add_argument("--branch", default=scoped.BRANCH)
    parser.add_argument("--compose-file", default=scoped.COMPOSE_FILE)
    parser.add_argument("--git-token", default="")
    parser.add_argument("--git-remote", default=None)
    parser.add_argument("--deploy-timeout", type=int, default=3600)
    parser.add_argument("--evidence", default=os.environ.get("SPANEL_E2E_EVIDENCE", ""))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(build_parser().parse_args(argv))
    except (E2EError, api.E2EError) as exc:
        print(f"E2E FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
