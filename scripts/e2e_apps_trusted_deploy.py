#!/usr/bin/env python3
"""Black-box trusted-deploy E2E for the Apps frontend contract.

Real HTTP login plus worker/Docker execution.  Admission is isolation-only:
the signed release must pass isolation and probes; the app's internal
dependencies (CVEs, old runtimes) are the owner's responsibility.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
import secrets
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent


def _load_api():
    spec = importlib.util.spec_from_file_location(
        "spanel_e2e_apps_api", ROOT / "e2e_apps_api.py"
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

FIXTURE_REPOSITORY = "luc444s/software-de-gestion-para-editores"
REQUIRED_PERMISSIONS = frozenset(
    {
        "apps.applications.read",
        "apps.applications.create",
        "apps.deployments.create",
    }
)
DEFAULT_POLICY: dict[str, Any] = {
    "service_users": {
        "backend": {"uid": 10001, "gid": 10001},
        "frontend": {"uid": 101, "gid": 101},
        "database": {"uid": 70, "gid": 70},
    },
    "writable_paths": [
        {"service": "database", "path": "/var/run/postgresql", "mode": "0775"}
    ],
}


def parse_policy(raw: str | None) -> dict[str, Any]:
    if not raw:
        return copy.deepcopy(DEFAULT_POLICY)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise E2EError("SPANEL_E2E_POLICY is not valid JSON") from None
    if not isinstance(value, dict):
        raise E2EError("SPANEL_E2E_POLICY must be a JSON object")
    users = value.get("service_users")
    paths = value.get("writable_paths", [])
    if not isinstance(users, dict) or not users or not isinstance(paths, list):
        raise E2EError("SPANEL_E2E_POLICY must declare service_users and writable_paths")
    for service, user in users.items():
        if (
            not isinstance(service, str)
            or not isinstance(user, dict)
            or not isinstance(user.get("uid"), int)
            or not isinstance(user.get("gid"), int)
        ):
            raise E2EError("SPANEL_E2E_POLICY has an invalid service user")
    return value


def policy_for(
    services: Sequence[str],
    base_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Exact coverage: a missing or extra service is a hard failure."""

    names = sorted({str(service) for service in services})
    if not names:
        raise E2EError("inspection did not expose any services")
    policy = copy.deepcopy(base_policy or DEFAULT_POLICY)
    declared = set(policy.get("service_users") or {})
    expected = set(names)
    missing = sorted(expected.difference(declared))
    extra = sorted(declared.difference(expected))
    if missing:
        raise E2EError(f"hardening policy does not cover: {', '.join(missing)}")
    if extra:
        raise E2EError(f"hardening policy declares unknown services: {', '.join(extra)}")
    policy["service_users"] = {
        service: policy["service_users"][service] for service in names
    }
    return policy


def environment_pairs(raw: str | None) -> list[list[str]]:
    if not raw:
        return [list(item) for item in api.environment()]
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise E2EError("SPANEL_E2E_ENV_JSON is not valid JSON") from None
    if isinstance(value, dict):
        value = [[name, item] for name, item in value.items()]
    if not isinstance(value, list):
        raise E2EError("SPANEL_E2E_ENV_JSON must be a JSON object or an array of pairs")
    pairs: list[list[str]] = []
    for item in value:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not all(isinstance(part, str) for part in item)
        ):
            raise E2EError("SPANEL_E2E_ENV_JSON contains an invalid pair")
        pairs.append([item[0], item[1]])
    return pairs


def assert_probes(probes: object) -> dict[str, Any]:
    if not isinstance(probes, dict):
        raise E2EError("the deployment did not expose probes")
    isolation = probes.get("isolation")
    if not isinstance(isolation, dict) or not isolation:
        raise E2EError("isolation probes are missing")
    for service, evidence in isolation.items():
        if not isinstance(evidence, dict):
            raise E2EError(f"isolation evidence for {service} is invalid")
        processes = evidence.get("processes")
        user = str(evidence.get("user") or "")
        if not isinstance(processes, int) or processes <= 0:
            raise E2EError(f"service {service} reports no isolated processes")
        if not user or user.split(":", 1)[0] in {"", "0", "root"}:
            raise E2EError(f"service {service} is not running as a non-root user")
    functional = probes.get("functional")
    checks = functional.get("checks") if isinstance(functional, dict) else None
    if not isinstance(checks, list) or not checks:
        raise E2EError("functional probes are missing")
    for check in checks:
        if (
            not isinstance(check, dict)
            or check.get("returncode") != 0
            or not isinstance(check.get("bytes"), int)
            or check["bytes"] <= 0
        ):
            raise E2EError("a functional probe did not return evidence")
    stability = probes.get("stability")
    if not isinstance(stability, dict):
        raise E2EError("stability probes are missing")
    if not isinstance(stability.get("checks"), int) or stability["checks"] < 1:
        raise E2EError("the stability probe window is empty")
    restart_counts = stability.get("restart_counts")
    if not isinstance(restart_counts, dict) or not restart_counts:
        raise E2EError("stability probes did not report restart counts")
    if any(value != 0 for value in restart_counts.values()):
        raise E2EError("a service restarted during the stability window")
    return {
        "services": sorted(isolation),
        "functional_checks": len(checks),
        "restart_counts": restart_counts,
    }


def assert_runtime(detail: dict[str, Any], release_id: str) -> dict[str, Any]:
    active = detail.get("active_deployment")
    if not isinstance(active, dict):
        raise E2EError("the application has no active deployment")
    if str(active.get("status")) != "running":
        raise E2EError("the active deployment is not running")
    summary = active.get("release_summary")
    if not isinstance(summary, dict) or summary.get("release_id") != release_id:
        raise E2EError("the active deployment does not match the signed release")
    services = active.get("service_details")
    if not isinstance(services, list) or not services:
        raise E2EError("the deployment did not expose service_details")
    users: dict[str, str] = {}
    for service in services:
        if not isinstance(service, dict) or not isinstance(service.get("name"), str):
            raise E2EError("the deployment exposed an invalid service detail")
        user = str(service.get("user") or "")
        if not user or user.split(":", 1)[0] in {"", "0", "root"}:
            raise E2EError(f"service {service['name']} does not expose a non-root user")
        if service.get("restart_count") != 0:
            raise E2EError(f"service {service['name']} restarted before verification")
        users[service["name"]] = user
    return {"users": users, "probes": assert_probes(active.get("probes"))}


def expect_http_error(
    client: ApiClient,
    method: str,
    path: str,
    body: object,
    status: int,
    marker: str,
    label: str,
) -> None:
    try:
        client.request(method, path, body, idempotent=True)
    except E2EError as exc:
        text = str(exc)
        if f"HTTP {status}" not in text:
            raise E2EError(f"{label} returned an unexpected error: {text}") from None
        if marker not in text:
            raise E2EError(f"{label} did not report {marker}") from None
        return
    raise E2EError(f"{label} unexpectedly succeeded")


def find_repository(client: ApiClient, repository: str) -> tuple[str, str]:
    installations = client.request(
        "GET", "/api/v1/plugins/apps/github/installations"
    )
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
    raise E2EError(
        f"GitHub repository {repository} is not available to this tenant; "
        "authorize it in the GitHub App and sync the installation"
    )


def write_evidence(path: Path, payload: dict[str, Any]) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise E2EError("evidence path must not be a symlink")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    path.chmod(0o600)


def _cleanup(
    client: ApiClient,
    application_id: str,
    slug: str,
    timeout: int,
) -> None:
    detail_path = f"/api/v1/plugins/apps/applications/{application_id}"
    api.queue(
        client,
        "DELETE",
        detail_path,
        {"confirm": slug, "purge_data": True},
        timeout,
        "delete",
    )
    api.expect_missing(client, detail_path, "application")


def run(args: argparse.Namespace) -> int:
    base_url = api.validate_base_url(args.base_url)
    repository = args.repository.strip()
    email = os.environ.get("SPANEL_E2E_EMAIL", "").strip()
    password_path = os.environ.get("SPANEL_E2E_PASSWORD_FILE", "").strip()
    if not email or not password_path:
        raise E2EError("SPANEL_E2E_EMAIL and SPANEL_E2E_PASSWORD_FILE are required")
    requested_policy = parse_policy(args.policy_json) if args.policy_json else None
    deploy_environment = environment_pairs(args.env_json)
    canary = f"canary-{secrets.token_hex(8)}"
    deploy_environment.append(["E2E_LOG_CANARY", canary])
    sensitive = api.sensitive_values(deploy_environment)
    password = api.read_password(Path(password_path))
    client = ApiClient(base_url)
    application: dict[str, Any] | None = None
    application_id: str | None = None
    primary_error: Exception | None = None
    cleanup_error: Exception | None = None
    result: dict[str, Any] = {}
    started = time.monotonic()
    print(f"Black-box trusted deploy target: {base_url}")
    try:
        print("[1/10] Real login and permission validation")
        login = client.request(
            "POST", "/api/v1/auth/login", {"email": email, "password": password}
        )
        password = ""
        token = login.get("access_token") if isinstance(login, dict) else None
        if not isinstance(token, str) or not token:
            raise E2EError("login did not return an access token")
        client.token = token
        profile = client.request("GET", "/api/v1/auth/me")
        permissions = set(profile.get("permissions", []))
        missing = REQUIRED_PERMISSIONS.difference(permissions)
        if missing:
            raise E2EError(f"login lacks permissions: {', '.join(sorted(missing))}")
        print("login ok")

        print("[2/10] Resolve the authorized GitHub repository")
        installation_id, repository_id = find_repository(client, repository)
        print(f"source {repository}")

        suffix = secrets.token_hex(5)
        application = client.request(
            "POST",
            "/api/v1/plugins/apps/applications",
            {
                "name": f"Trusted E2E {suffix}",
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
        print(f"app created ({application.get('slug')})")

        print("[3/10] Inspect through the API and worker")
        api.queue(client, "POST", f"{root}/inspect", None, args.operation_timeout, "inspect")
        detail = client.request("GET", root)
        services = detail.get("services")
        if not isinstance(services, list) or not services:
            raise E2EError("inspection did not expose any services")
        explicit_policy = (
            policy_for(services, requested_policy)
            if requested_policy is not None
            else None
        )
        print(f"inspect: succeeded ({len(services)} services)")

        print("[4/10] Deploy with the engine-owned runtime policy")
        deploy_body: dict[str, Any] = {"environment": deploy_environment}
        if explicit_policy is not None:
            deploy_body["hardening"] = explicit_policy
        operation = api.queue(
            client,
            "POST",
            f"{root}/deployments",
            deploy_body,
            args.deploy_timeout,
            "deploy",
        )
        deploy_result = operation.get("result") if isinstance(operation, dict) else None
        release_id = (
            deploy_result.get("release_id") if isinstance(deploy_result, dict) else None
        )
        detail = client.request("GET", root)
        active = detail.get("active_deployment")
        summary = active.get("release_summary") if isinstance(active, dict) else None
        release_id = release_id or (
            summary.get("release_id") if isinstance(summary, dict) else None
        )
        if not isinstance(release_id, str) or not release_id:
            raise E2EError("the deployment did not expose a release id")
        if not isinstance(deploy_result, dict) or not all(
            isinstance(deploy_result.get(name), str) and deploy_result[name]
            for name in ("artifact_sha256", "compose_sha256", "hardened_tree_sha256", "key_id")
        ):
            raise E2EError("the deployment did not expose the signed hashes")
        print(f"automatic hardened deploy succeeded (release {release_id})")

        print("[5/10] Verify the signed release is listed")
        releases = client.request("GET", f"{root}/releases")
        listed = next(
            (
                item for item in releases
                if isinstance(item, dict) and item.get("release_id") == release_id
            ),
            None,
        ) if isinstance(releases, list) else None
        if listed is None:
            raise E2EError("the signed release is not listed by the API")
        if listed.get("insecure") or listed.get("gate") or listed.get("advisories"):
            raise E2EError("the release exposes insecure or advisory metadata")
        print("release: signed, no insecure metadata")

        print("[6/10] Verify probes and non-root runtime")
        runtime = assert_runtime(detail, release_id)
        print("runtime: running, non-root, probes green")

        print("[7/10] Cryptographic verification")
        verification = client.request(
            "POST", f"{root}/releases/{release_id}/verify"
        )
        if not isinstance(verification, dict) or verification.get("status") != "valid":
            raise E2EError("release verification did not return valid")
        checks = verification.get("checks")
        if not isinstance(checks, dict) or not all(checks.values()):
            raise E2EError("release verification reported a failed check")
        print("verify: valid")

        print("[8/10] Evidence without secrets")
        evidence = client.request("GET", f"{root}/releases/{release_id}/evidence")
        api.assert_no_secrets(
            json.dumps(evidence, default=str, sort_keys=True), sensitive, "evidence"
        )
        api.assert_no_secrets(
            json.dumps(releases, default=str, sort_keys=True), sensitive, "releases"
        )
        print("evidence: ok")

        print("[9/10] Redeploy the signed release")
        api.queue(
            client,
            "POST",
            f"{root}/deployments",
            {"environment": [], "hardened_operation_id": release_id},
            args.deploy_timeout,
            "redeploy",
        )
        print("redeploy release: succeeded")

        result = {
            "base_url": base_url,
            "repository": repository,
            "branch": args.branch,
            "compose_file": args.compose_file,
            "application_id": application_id,
            "application_slug": application.get("slug"),
            "release_id": release_id,
            "commit": deploy_result.get("commit"),
            "hashes": {
                name: deploy_result.get(name)
                for name in (
                    "artifact_sha256",
                    "compose_sha256",
                    "hardened_tree_sha256",
                    "policy_sha256",
                    "gate_sha256",
                )
            },
            "admission": "isolation+probes+signature+real-build",
            "runtime": runtime,
            "cleanup": "pending",
        }

        print("[10/10] Cleanup the temporary application")
        if args.keep:
            print(
                "application preserved: "
                f"{application.get('slug')} ({application_id})"
            )
            result["cleanup"] = "preserved"
        else:
            _cleanup(
                client, application_id, str(application.get("slug")),
                args.operation_timeout,
            )
            result["cleanup"] = "application deleted (404 verified)"
            print("cleanup: application deleted")
    except Exception as exc:  # noqa: BLE001 -- cleanup must always run
        primary_error = exc
    finally:
        password = ""
        if application is not None and application_id is not None and client.token:
            keep = args.keep or (primary_error is not None and args.keep_failed)
            if keep:
                print(
                    "application preserved for manual review: "
                    f"{application.get('slug')} ({application_id})"
                )
                result["cleanup"] = "preserved"
            elif result.get("cleanup") != "application deleted (404 verified)":
                print("Cleanup after failure")
                try:
                    _cleanup(
                        client,
                        application_id,
                        str(application.get("slug")),
                        args.operation_timeout,
                    )
                    result["cleanup"] = "application deleted (404 verified)"
                except Exception as exc:  # noqa: BLE001 -- report separately
                    cleanup_error = exc
                    result["cleanup"] = "failed"
        client.token = None

    if primary_error:
        print(f"E2E FAILED: {primary_error}", file=sys.stderr)
    if cleanup_error:
        slug = application.get("slug") if isinstance(application, dict) else None
        print(
            f"E2E CLEANUP FAILED for {slug} ({application_id}): {cleanup_error}",
            file=sys.stderr,
        )
    if primary_error or cleanup_error:
        return 1
    result["duration_seconds"] = round(time.monotonic() - started, 2)
    if args.evidence:
        write_evidence(Path(args.evidence), result)
        print(f"evidence written: {args.evidence}")
    print("E2E OK")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default=os.environ.get("SPANEL_E2E_BASE_URL", "").strip(),
    )
    parser.add_argument(
        "--repository",
        default=os.environ.get("SPANEL_E2E_REPOSITORY", "").strip() or FIXTURE_REPOSITORY,
    )
    parser.add_argument(
        "--branch",
        default=os.environ.get("SPANEL_E2E_BRANCH", "").strip() or api.BRANCH,
    )
    parser.add_argument(
        "--compose-file",
        default=os.environ.get("SPANEL_E2E_COMPOSE_FILE", "").strip() or api.COMPOSE_FILE,
    )
    parser.add_argument(
        "--policy-json",
        default=os.environ.get("SPANEL_E2E_POLICY", "").strip() or None,
    )
    parser.add_argument(
        "--env-json",
        default=os.environ.get("SPANEL_E2E_ENV_JSON", "").strip() or None,
    )
    parser.add_argument(
        "--operation-timeout",
        type=int,
        default=int(os.environ.get("SPANEL_E2E_OPERATION_TIMEOUT", "900")),
    )
    parser.add_argument(
        "--deploy-timeout",
        type=int,
        default=int(os.environ.get("SPANEL_E2E_DEPLOY_TIMEOUT", "2400")),
    )
    parser.add_argument(
        "--evidence",
        default=os.environ.get("SPANEL_E2E_EVIDENCE", "").strip() or None,
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        default=os.environ.get("SPANEL_E2E_KEEP") == "1",
    )
    parser.add_argument(
        "--keep-failed",
        action="store_true",
        default=os.environ.get("SPANEL_E2E_KEEP_FAILED") == "1",
    )
    return parser


# --- tenant-rootless expectations (A.SPEC 0096) ----------------------------
# Pure helpers shared with the live E2E.  They assert the shape of the
# per-deploy evidence without contacting a daemon; the lab-only steps
# (two tenants, runsc, AppArmor, nftables) remain a documented GAP.


def tenant_rootless_expectations(environ: dict[str, str] | None = None) -> dict[str, Any]:
    env = dict(os.environ if environ is None else environ)
    profile = env.get("SPANEL_APPS_RUNTIME", "hardened").strip() or "hardened"
    return {
        "profile": profile,
        "enabled": profile == "tenant-rootless",
        "required_evidence": [
            "tenant", "socket", "profile", "runtime", "apparmor_label",
            "uid_mapping", "hashes", "containers", "preflight", "probes",
        ],
    }


def assert_tenant_rootless_evidence(manifest: dict[str, Any], tenant: str) -> None:
    """Validate the evidence carried by a tenant-rootless deployment manifest."""
    evidence = manifest.get("tenant_rootless")
    if not isinstance(evidence, dict):
        raise E2EError("tenant-rootless evidence is missing from the manifest")
    expected = tenant_rootless_expectations()
    for key in expected["required_evidence"]:
        if key not in evidence:
            raise E2EError(f"tenant-rootless evidence is missing {key}")
    if evidence.get("tenant") != tenant:
        raise E2EError("tenant-rootless evidence has the wrong tenant")
    if evidence.get("runtime") != "runsc":
        raise E2EError("tenant-rootless evidence is not runsc")
    if evidence.get("profile") != "tenant-rootless":
        raise E2EError("tenant-rootless evidence has the wrong profile")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.base_url:
        print("E2E FAILED: --base-url or SPANEL_E2E_BASE_URL is required", file=sys.stderr)
        return 1
    try:
        return run(args)
    except (E2EError, OSError) as exc:
        print(f"E2E FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
