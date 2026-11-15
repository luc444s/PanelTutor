#!/usr/bin/env python3
"""Real, incremental Apps deployment E2E for A.SPEC 0088.

The flow uses the lab API and worker (not a fake runner), pushes a real commit
to the configured branch and proves, with host Docker inspection, that only the
frontend service is recreated by a global deployment.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import shlex
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent


def _load_api():
    spec = importlib.util.spec_from_file_location(
        "spanel_e2e_scoped_api", ROOT / "e2e_apps_api.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("the shared Apps E2E helpers are unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


api = _load_api()
E2EError = api.E2EError
ApiClient = api.ApiClient

REPOSITORY = "luc444s/software-de-gestion-para-editores"
BRANCH = "feature/workflow-diseno"
COMPOSE_FILE = "docker-compose.dokploy.yml"
CANARY_FILE = "frontend/public/test.md"
REQUIRED_PERMISSIONS = frozenset({
    "apps.applications.read",
    "apps.applications.create",
    "apps.deployments.create",
})
# The fixture database image runs as postgres (uid/gid 70) and needs its
# runtime socket directory writable even with a read-only root filesystem.
HARDENING_POLICY = {
    "service_users": {
        "backend": {"uid": 10001, "gid": 10001},
        "frontend": {"uid": 101, "gid": 101},
        "database": {"uid": 70, "gid": 70},
    },
    "writable_paths": [
        {"service": "database", "path": "/var/run/postgresql", "mode": "0775"}
    ],
}


def _run_git(
    checkout: Path, args: Sequence[str], *, token: str = ""
) -> subprocess.CompletedProcess[str]:
    environment = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "PanelTutor E2E",
        "GIT_AUTHOR_EMAIL": "e2e@spanel.invalid",
        "GIT_COMMITTER_NAME": "PanelTutor E2E",
        "GIT_COMMITTER_EMAIL": "e2e@spanel.invalid",
    }
    completed = subprocess.run(
        ["git", *args],
        cwd=checkout,
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    if completed.returncode:
        stderr = completed.stderr.replace(token, "[REDACTED]") if token else completed.stderr
        raise E2EError(f"git {' '.join(args[:2])} failed: {stderr.strip()[-500:]}")
    return completed


def _remote(repository: str, token: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    if token:
        return f"https://x-access-token:{token}@github.com/{repository}.git"
    return f"https://github.com/{repository}.git"


def clone_branch(
    repository: str, branch: str, token: str, remote: str | None, target: Path
) -> Path:
    _run_git(
        target.parent,
        ["clone", "--branch", branch, "--depth", "1", _remote(repository, token, remote),
         str(target)],
        token=token,
    )
    return target


def remote_is_clean(checkout: Path, branch: str) -> str:
    _run_git(checkout, ["fetch", "--depth", "1", "origin", branch])
    _run_git(checkout, ["reset", "--hard", f"origin/{branch}"])
    status = _run_git(checkout, ["status", "--porcelain"]).stdout.strip()
    if status:
        raise E2EError("the real branch checkout is not clean")
    if (checkout / CANARY_FILE).exists():
        raise E2EError("the configured branch already contains frontend/public/test.md")
    return _run_git(checkout, ["rev-parse", "HEAD"]).stdout.strip()


def commit_canary(checkout: Path, branch: str, canary: str, token: str) -> str:
    path = checkout / CANARY_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canary + "\n", encoding="utf-8")
    _run_git(checkout, ["add", CANARY_FILE])
    _run_git(checkout, ["commit", "-m", f"e2e: canary {canary}"])
    _run_git(checkout, ["push", "origin", f"HEAD:{branch}"], token=token)
    return _run_git(checkout, ["rev-parse", "HEAD"]).stdout.strip()


def revert_canary(checkout: Path, branch: str, token: str) -> str:
    path = checkout / CANARY_FILE
    _run_git(checkout, ["rm", "--quiet", "--", CANARY_FILE])
    _run_git(checkout, ["commit", "-m", "e2e: revert canary"])
    _run_git(checkout, ["push", "origin", f"HEAD:{branch}"], token=token)
    if path.exists():
        raise E2EError("the canary file still exists after revert")
    return _run_git(checkout, ["rev-parse", "HEAD"]).stdout.strip()


def find_repository(client: ApiClient, repository: str) -> tuple[str, str]:
    installations = client.request("GET", "/api/v1/plugins/apps/github/installations")
    for installation in installations if isinstance(installations, list) else []:
        installation_id = installation.get("id") if isinstance(installation, dict) else None
        if not isinstance(installation_id, str):
            continue
        repositories = client.request(
            "GET",
            f"/api/v1/plugins/apps/github/installations/{installation_id}/repositories",
        )
        for item in repositories if isinstance(repositories, list) else []:
            if isinstance(item, dict) and item.get("full_name") == repository:
                repository_id = item.get("id")
                if isinstance(repository_id, str):
                    return installation_id, repository_id
    raise E2EError(f"GitHub repository {repository} is not available to this tenant")


def _docker(argv: Sequence[str]) -> str:
    completed = subprocess.run(
        ["docker", *argv], capture_output=True, text=True, check=False
    )
    if completed.returncode:
        raise E2EError(f"docker {argv[0]} failed: {completed.stderr.strip()[-300:]}")
    return completed.stdout


def inspect_mounts(container_id: str) -> list[dict[str, Any]]:
    payload = json.loads(_docker(["inspect", "-f", "{{json .Mounts}}", container_id]))
    if not isinstance(payload, list):
        raise E2EError("container mounts evidence is invalid")
    return [
        {
            "type": item.get("Type"),
            "name": item.get("Name"),
            "destination": item.get("Destination"),
            "source": item.get("Source"),
        }
        for item in payload if isinstance(item, dict)
    ]


def service_state(detail: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    active = detail.get("active_deployment")
    services = active.get("service_details") if isinstance(active, dict) else None
    if not isinstance(services, list) or not services:
        raise E2EError(f"{label}: the deployment does not expose service details")
    result: dict[str, dict[str, Any]] = {}
    for item in services:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise E2EError(f"{label}: invalid service detail")
        name = item["name"]
        container_id = item.get("container_id")
        image_id = item.get("image_id")
        started_at = item.get("started_at")
        if not all(isinstance(value, str) and value for value in (
            container_id, image_id, started_at,
        )):
            raise E2EError(f"{label}: service {name} lacks container identity evidence")
        result[name] = {
            "container_id": container_id,
            "image_id": image_id,
            "started_at": started_at,
            "restart_count": item.get("restart_count"),
            "release_id": item.get("release_id"),
            "mounts": inspect_mounts(container_id),
        }
    return result


def _http_body(container_id: str, port: int, path: str) -> str:
    script = (
        f"wget -qO- http://127.0.0.1:{port}{path} 2>/dev/null "
        f"|| curl -fsS http://127.0.0.1:{port}{path} 2>/dev/null"
    )
    return _docker(["exec", container_id, "sh", "-c", script])


def assert_canary_http(detail: dict[str, Any], canary: str) -> dict[str, Any]:
    active = detail.get("active_deployment") or {}
    details = active.get("service_details") or []
    frontend = next(
        (item for item in details
         if isinstance(item, dict) and item.get("name") == "frontend"),
        None,
    )
    if frontend is None or not frontend.get("container_id"):
        raise E2EError("frontend container evidence is missing")
    ports = [item for item in frontend.get("ports") or [] if isinstance(item, int)]
    ports += [8080, 3000, 5173, 80]
    attempts: list[str] = []
    for port in dict.fromkeys(ports):
        try:
            body = _http_body(frontend["container_id"], port, "/test.md").strip()
        except E2EError as exc:
            attempts.append(f"{port}: {exc}")
            continue
        if body == canary:
            return {"port": port, "path": "/test.md", "sha256": _sha(body)}
        attempts.append(f"{port}: unexpected body")
    raise E2EError(f"/test.md did not return the pushed canary ({'; '.join(attempts[-4:])})")


def _sha(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode()).hexdigest()


def _database_service(states: dict[str, dict[str, Any]]) -> str | None:
    for name in states:
        if name.lower() in {"database", "db", "postgres", "mysql", "mariadb"}:
            return name
    return None


def create_sentinel(container_id: str, value: str) -> None:
    sql = (
        "CREATE TABLE IF NOT EXISTS spanel_e2e_sentinel(v text);"
        f"INSERT INTO spanel_e2e_sentinel(v) VALUES ('{value}');"
    )
    script = (
        'if command -v psql >/dev/null 2>&1; then '
        'psql -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}" '
        f'-v ON_ERROR_STOP=1 -c {shlex.quote(sql)}; '
        'elif command -v mysql >/dev/null 2>&1; then '
        'mysql -u"${MYSQL_USER:-root}" -p"${MYSQL_PASSWORD:-}" '
        f'"${{MYSQL_DATABASE:-mysql}}" -e {shlex.quote(sql)}; '
        'else exit 42; fi'
    )
    _docker(["exec", container_id, "sh", "-c", script])


def assert_sentinel(container_id: str, value: str) -> None:
    sql = f"SELECT count(*) AS n FROM spanel_e2e_sentinel WHERE v = '{value}';"
    script = (
        'if command -v psql >/dev/null 2>&1; then '
        'psql -tA -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}" '
        f'-v ON_ERROR_STOP=1 -c {shlex.quote(sql)}; '
        'elif command -v mysql >/dev/null 2>&1; then '
        'mysql -N -u"${MYSQL_USER:-root}" -p"${MYSQL_PASSWORD:-}" '
        f'"${{MYSQL_DATABASE:-mysql}}" -e {shlex.quote(sql)}; '
        'else exit 42; fi'
    )
    output = _docker(["exec", container_id, "sh", "-c", script]).strip()
    if "1" not in output.split():
        raise E2EError("database sentinel was lost after the incremental deployment")


def assert_probes(probes: object) -> None:
    if not isinstance(probes, dict):
        raise E2EError("global probes are missing")
    isolation = probes.get("isolation")
    if not isinstance(isolation, dict) or not isolation:
        raise E2EError("global isolation evidence is missing")
    stability = probes.get("stability")
    counts = stability.get("restart_counts") if isinstance(stability, dict) else None
    if not isinstance(counts, dict) or any(value != 0 for value in counts.values()):
        raise E2EError("a service restarted during the global probe window")
    functional = probes.get("functional")
    checks = functional.get("checks") if isinstance(functional, dict) else None
    if not isinstance(checks, list) or not checks:
        raise E2EError("global functional probes are missing")


def assert_scope(result: dict[str, Any], services: Sequence[str]) -> dict[str, Any]:
    scope = result.get("scope") if isinstance(result, dict) else None
    if not isinstance(scope, dict):
        raise E2EError("the deployment result does not expose the planner scope")
    if scope.get("requested_scope") != "global":
        raise E2EError("the deployment did not request global scope")
    if scope.get("strategy") != "incremental":
        raise E2EError(f"unexpected deployment strategy: {scope.get('strategy')}")
    if scope.get("fallback_reason") is not None:
        raise E2EError("the planner used a fallback instead of a safe subset")
    if scope.get("effective_services") != list(services):
        raise E2EError(
            f"unexpected effective services: {scope.get('effective_services')}"
        )
    return scope


def write_evidence(path: Path, payload: dict[str, Any]) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    path.chmod(0o600)


def deploy(client: ApiClient, root: str, payload: dict[str, Any], timeout: int,
           label: str) -> dict[str, Any]:
    body = {**payload, "hardening": HARDENING_POLICY}
    return api.queue(client, "POST", f"{root}/deployments", body, timeout, label)


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
    canary = f"canary-{secrets.token_hex(12)}"
    sentinel = f"sentinel-{secrets.token_hex(8)}"
    environment = api.environment()
    sensitive = api.sensitive_values(environment)
    password = api.read_password(Path(password_path))
    client = ApiClient(base_url)
    evidence_path = Path(args.evidence) if args.evidence else None
    evidence: dict[str, Any] = {
        "base_url": base_url, "repository": args.repository, "branch": args.branch,
        "compose_file": args.compose_file, "canary": canary,
        "sentinel": sentinel, "status": "failed",
    }
    started = time.monotonic()
    canary_commit = ""
    reverted = False
    checkout: Path | None = None
    try:
        print("[1/15] Login and permissions")
        login = client.request(
            "POST", "/api/v1/auth/login", {"email": email, "password": password}
        )
        password = ""
        token_value = login.get("access_token") if isinstance(login, dict) else None
        if not isinstance(token_value, str) or not token_value:
            raise E2EError("login did not return an access token")
        client.token = token_value
        profile = client.request("GET", "/api/v1/auth/me")
        missing = REQUIRED_PERMISSIONS.difference(set(profile.get("permissions", [])))
        if missing:
            raise E2EError(f"login lacks permissions: {', '.join(sorted(missing))}")

        print("[2/15] Cloning and checking the real branch")
        with tempfile.TemporaryDirectory(prefix="spanel-scoped-e2e-") as temporary:
            checkout = Path(temporary) / "checkout"
            clone_branch(
                args.repository, args.branch, token,
                args.git_remote, checkout,
            )
            initial_commit = remote_is_clean(checkout, args.branch)
            evidence["initial_commit"] = initial_commit

            print("[3/15] Resolving the authorized GitHub repository")
            installation_id, repository_id = find_repository(client, args.repository)
            suffix = secrets.token_hex(5)
            application = client.request(
                "POST", "/api/v1/plugins/apps/applications",
                {
                    "name": f"Scoped E2E {suffix}",
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
            evidence["application_id"] = application_id
            evidence["application_slug"] = application.get("slug")

            print("[4/15] Initial global deploy from the clean commit")
            initial = deploy(
                client, root, {"environment": environment},
                args.deploy_timeout, "initial deploy",
            )
            detail = client.request("GET", root)
            initial_state = service_state(detail, "initial")
            if set(initial_state) != {"frontend", "backend", "database"}:
                raise E2EError(
                    f"unexpected services: {', '.join(sorted(initial_state))}"
                )
            if any(item["restart_count"] != 0 for item in initial_state.values()):
                raise E2EError("a service restarted after the initial deployment")
            assert_probes((detail.get("active_deployment") or {}).get("probes"))
            evidence["initial"] = {
                "release_id": (initial.get("result") or {}).get("release_id"),
                "scope": (initial.get("result") or {}).get("scope"),
                "services": initial_state,
            }
            database = _database_service(initial_state)
            if database is None:
                raise E2EError("the fixture does not expose a database service")
            create_sentinel(initial_state[database]["container_id"], sentinel)
            evidence["database_sentinel_created"] = True

            print("[5/15] Pushing the real frontend canary commit")
            canary_commit = commit_canary(
                checkout, args.branch, canary, token
            )
            evidence["canary_commit"] = canary_commit

            print("[6/15] Global deploy without selecting a service")
            canary_deploy = deploy(
                client, root, {"environment": []},
                args.deploy_timeout, "canary deploy",
            )
            scope = assert_scope(canary_deploy.get("result") or {}, ["frontend"])
            detail = client.request("GET", root)
            canary_state = service_state(detail, "canary")
            evidence["canary_scope"] = scope
            evidence["canary"] = {
                "release_id": (canary_deploy.get("result") or {}).get("release_id"),
                "services": canary_state,
            }

            print("[7/15] Asserting only frontend changed")
            for name in ("backend", "database"):
                for key in ("container_id", "image_id", "started_at"):
                    if canary_state[name][key] != initial_state[name][key]:
                        raise E2EError(f"{name} changed {key} during a frontend-only deploy")
                if canary_state[name]["restart_count"] != 0:
                    raise E2EError(f"{name} restarted during a frontend-only deploy")
            if canary_state[database]["mounts"] != initial_state[database]["mounts"]:
                raise E2EError("database mounts changed during a frontend-only deploy")
            assert_sentinel(canary_state[database]["container_id"], sentinel)
            assert_probes((detail.get("active_deployment") or {}).get("probes"))

            print("[8/15] Verifying /test.md returns the pushed canary")
            evidence["http_canary"] = assert_canary_http(detail, canary)

            print("[9/15] Reverting the canary commit and pushing")
            revert_commit = revert_canary(checkout, args.branch, token)
            reverted = True
            evidence["revert_commit"] = revert_commit

            print("[10/15] Final global deploy from the revert commit")
            final = deploy(
                client, root, {"environment": []},
                args.deploy_timeout, "revert deploy",
            )
            final_scope = assert_scope(final.get("result") or {}, ["frontend"])
            detail = client.request("GET", root)
            final_state = service_state(detail, "final")
            for name in ("backend", "database"):
                for key in ("container_id", "image_id", "started_at"):
                    if final_state[name][key] != canary_state[name][key]:
                        raise E2EError(f"{name} changed during the revert deploy")
            if final_state["frontend"]["container_id"] == canary_state["frontend"]["container_id"]:
                raise E2EError("frontend was not recreated by the revert deploy")
            assert_probes((detail.get("active_deployment") or {}).get("probes"))
            evidence["final"] = {
                "release_id": (final.get("result") or {}).get("release_id"),
                "scope": final_scope,
                "services": final_state,
            }

            print("[11/15] Checking the branch no longer contains the canary")
            if (checkout / CANARY_FILE).exists():
                raise E2EError("the canary file remains on the branch")
            evidence["branch_clean_after_revert"] = True
            evidence["application_left_deployed"] = True
            evidence["status"] = "passed"
            evidence["elapsed_seconds"] = round(time.monotonic() - started, 2)
    except Exception as exc:
        evidence["error"] = str(exc)
        if checkout is not None and canary_commit and not reverted:
            try:
                revert_canary(checkout, args.branch, token)
                evidence["revert_commit"] = _run_git(
                    checkout, ["rev-parse", "HEAD"]
                ).stdout.strip()
                evidence["branch_clean_after_failure"] = True
            except Exception as cleanup_exc:  # noqa: BLE001
                evidence["revert_error"] = str(cleanup_exc)
        raise
    finally:
        client.token = None
        token = ""
        api.assert_no_secrets(json.dumps(evidence, default=str), sensitive, "evidence")
        if evidence_path is not None:
            write_evidence(evidence_path, evidence)
            print(f"evidence written: {evidence_path}")
    print("E2E OK")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url", default=os.environ.get("SPANEL_E2E_BASE_URL", "").strip()
    )
    parser.add_argument("--repository", default=REPOSITORY)
    parser.add_argument("--branch", default=BRANCH)
    parser.add_argument("--compose-file", default=COMPOSE_FILE)
    parser.add_argument("--git-token", default="")
    parser.add_argument("--git-remote", default=None)
    parser.add_argument("--deploy-timeout", type=int, default=3600)
    parser.add_argument("--evidence", default=os.environ.get("SPANEL_E2E_EVIDENCE", ""))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(build_parser().parse_args(argv))
    except E2EError as exc:
        print(f"E2E FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
