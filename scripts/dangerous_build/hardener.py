"""Transactional orchestration for the isolation-first hardener."""
from __future__ import annotations

import difflib
import json
import shutil
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from apps.backend.runtime import AppDeployError, audit_project  # type: ignore

from .compose import ComposeHardeningError, ServicePolicy, harden_compose
from .dockerfile import DockerfileHardeningError, WritablePath, harden_dockerfile
from .transaction import PublicationError, publish, tree_digest


class HardeningError(RuntimeError):
    """The candidate cannot be proven safe and deployable."""


GateRunner = Callable[[Path, Any], dict[str, Any]]


def _copy_checkout(source: Path, target: Path) -> None:
    ignored = shutil.ignore_patterns(".git", ".spanel-build-backups")
    shutil.copytree(source, target, symlinks=True, ignore=ignored)


def _policies(args: Any, services: set[str]) -> dict[str, ServicePolicy]:
    names = [name for name, _user in args.service_user]
    if len(names) != len(set(names)):
        raise HardeningError("duplicate runtime user policy")
    users = dict(args.service_user)
    writable: dict[str, list[WritablePath]] = {service: [] for service in services}
    for service, item in args.writable_path:
        if service not in services:
            raise HardeningError(f"writable path references unknown service: {service}")
        writable[service].append(item)
    missing = sorted(services.difference(users))
    unknown = sorted(set(users).difference(services))
    if missing:
        raise HardeningError("explicit runtime user required for: " + ", ".join(missing))
    if unknown:
        raise HardeningError("runtime user references unknown service: " + ", ".join(unknown))
    return {
        service: ServicePolicy(users[service][0], users[service][1], tuple(writable[service]))
        for service in sorted(services)
    }


def _candidate_changes(source: Path, candidate: Path, args: Any) -> tuple[Path, ...]:
    result = audit_project(
        source,
        args.compose_file,
        non_root=args.non_root,
        require_build=args.require_build,
    )
    services = {str(name) for name in result.data["services"]}
    policies = _policies(args, services)
    compose_relative = result.compose.relative_to(source)
    compose_source = source / compose_relative
    compose_fixed = harden_compose(compose_source.read_text(encoding="utf-8"), policies)
    (candidate / compose_relative).write_text(compose_fixed, encoding="utf-8")
    changed: set[Path] = {compose_relative}

    dockerfile_policies: dict[Path, ServicePolicy] = {}
    for service, dockerfile in result.dockerfiles.items():
        policy = policies[service]
        previous = dockerfile_policies.get(dockerfile)
        if previous is not None and previous != policy:
            raise HardeningError(
                f"services sharing {dockerfile.relative_to(source)} need the same runtime policy"
            )
        dockerfile_policies[dockerfile] = policy
    for dockerfile, policy in dockerfile_policies.items():
        relative = dockerfile.relative_to(source)
        original = dockerfile.read_text(encoding="utf-8")
        fixed = harden_dockerfile(
            original,
            uid=policy.uid,
            gid=policy.gid,
            writable_paths=policy.writable_paths,
        )
        if fixed != original:
            (candidate / relative).write_text(fixed, encoding="utf-8")
            changed.add(relative)
    return tuple(sorted(changed))


def _write_preview(
    source: Path, candidate: Path, relatives: tuple[Path, ...], output: Path
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for relative in relatives:
        original = (source / relative).read_text(encoding="utf-8")
        fixed = (candidate / relative).read_text(encoding="utf-8")
        fixed_path = output / relative.with_name(relative.name + ".hardened")
        patch_path = output / relative.with_name(relative.name + ".hardened.patch")
        fixed_path.parent.mkdir(parents=True, exist_ok=True)
        fixed_path.write_text(fixed, encoding="utf-8")
        patch_path.write_text(
            "".join(
                difflib.unified_diff(
                    original.splitlines(keepends=True),
                    fixed.splitlines(keepends=True),
                    fromfile=relative.as_posix(),
                    tofile=relative.as_posix() + ".hardened",
                )
            ),
            encoding="utf-8",
        )


def _policy_report(args: Any) -> dict[str, Any]:
    return {
        "service_users": {
            service: f"{user[0]}:{user[1]}" for service, user in args.service_user
        },
        "writable_paths": [
            {"service": service, "path": item.path, "mode": item.mode}
            for service, item in args.writable_path
        ],
        "isolation": {
            "cap_drop": ["ALL"],
            "no_new_privileges": True,
            "read_only_root": True,
            "runtime_egress": False,
            "host_binds": False,
            "published_ports": False,
        },
        "external_env": bool(args.env_file),
    }


def _validate_env_file(value: Path | None) -> Path | None:
    if value is None:
        return None
    try:
        info = value.lstat()
        resolved = value.resolve(strict=True)
    except OSError as exc:
        raise HardeningError("external env file does not exist") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise HardeningError("external env file must be a regular non-symlink file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise HardeningError("external env file must have mode 0600")
    return resolved


def run_hardener(args: Any, gate_runner: GateRunner) -> tuple[int, dict[str, Any]]:
    source = Path(args.source_dir).resolve()
    try:
        if args.apply and args.out_dir:
            raise HardeningError("--out-dir cannot be combined with --apply")
        args.env_file = _validate_env_file(args.env_file)
        policy = _policy_report(args)
        with tempfile.TemporaryDirectory(prefix="spanel-hardener-") as temporary:
            candidate = Path(temporary) / "candidate"
            _copy_checkout(source, candidate)
            relatives = _candidate_changes(source, candidate, args)
            gate = gate_runner(candidate, args)
            report: dict[str, Any] = {
                "status": "blocked" if gate["status"] != "passed" else "validated",
                "source": str(source),
                "changes": [item.as_posix() for item in relatives],
                "gate": gate,
                "applied": False,
                "backup": None,
                "policy": policy,
            }
            if gate["status"] != "passed":
                return 2, report
            if args.out_dir:
                _write_preview(source, candidate, relatives, Path(args.out_dir).resolve())
            if not args.apply:
                return 0, report

            candidate_digest = tree_digest(candidate)
            publication = publish(source, candidate, relatives, metadata={"policy": policy})
            published_digest = tree_digest(source)
            if published_digest != candidate_digest:
                publication.rollback()
                report["status"] = "rolled_back"
                report["gate_after_apply"] = {
                    "status": "digest_mismatch",
                    "candidate_sha256": candidate_digest,
                    "published_sha256": published_digest,
                }
                report["backup"] = str(publication.backup_root)
                return 2, report
            if args.revalidate_after_apply:
                published_gate = gate_runner(source, args)
                if published_gate["status"] != "passed":
                    publication.rollback()
                    report["status"] = "rolled_back"
                    report["gate_after_apply"] = published_gate
                    report["backup"] = str(publication.backup_root)
                    return 2, report
            else:
                published_gate = {
                    "status": "reused",
                    "evidence_reused": True,
                    "tree_sha256": candidate_digest,
                }
            report["status"] = "applied"
            report["applied"] = True
            report["backup"] = str(publication.backup_root)
            report["gate_after_apply"] = published_gate
            return 0, report
    except (
        AppDeployError,
        ComposeHardeningError,
        DockerfileHardeningError,
        HardeningError,
        PublicationError,
        OSError,
        UnicodeError,
    ) as exc:
        return 2, {
            "status": "blocked",
            "source": str(source),
            "changes": [],
            "gate": None,
            "applied": False,
            "backup": None,
            "policy": _policy_report(args),
            "error": str(exc),
        }


def emit_report(code: int, report: dict[str, Any], output_format: str) -> int:
    if output_format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"Hardener {report['status']}: changes={len(report.get('changes', []))} "
            f"applied={str(report.get('applied', False)).lower()}"
        )
        if report.get("error"):
            print(f"ERROR: {report['error']}")
    return code
