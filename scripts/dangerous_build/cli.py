#!/usr/bin/env python3
"""Detect and normalize unsafe Dockerfiles and Docker Compose projects."""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = ROOT / "vendor" / "systutor-core" / "plugins"
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

import yaml  # type: ignore
from apps.backend.runtime import (  # type: ignore
    AppDeployError,
    AuditResult,
    audit_project,
)

from .cache import ImageValidationCache, scanner_fingerprint
from .dockerfile import WritablePath
from .hardener import emit_report, run_hardener

DEFAULT_UID = 10001
DEFAULT_GID = 10001
SEVERITY_RANK = {"info": 0, "warning": 1, "error": 2}
FAIL_ON = {
    "low": "info",
    "medium": "warning",
    "high": "error",
    "info": "info",
    "warning": "warning",
    "error": "error",
}
FIXED_COMPOSE = "docker-compose.fixed.yml"
HADOLINT_RANK = {"ignore": 0, "style": 1, "info": 2, "warning": 3, "error": 4}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise AppDeployError(f"cannot read {path.name}") from exc


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _diff(original: str, fixed: str, source: str, target: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            fixed.splitlines(keepends=True),
            fromfile=source,
            tofile=target,
        )
    )


def _finding_dict(finding: Any) -> dict[str, Any]:
    return {
        "severity": finding.severity,
        "code": finding.code,
        "service": finding.service,
        "path": finding.path,
        "line": finding.line,
        "message": finding.message,
        "remediation": finding.remediation,
    }


def _visible_findings(result: AuditResult, args: argparse.Namespace) -> list[Any]:
    findings = list(result.findings)
    if getattr(args, "allow_env_file", False):
        findings = [item for item in findings if item.code != "compose_repo_env_file"]
    if getattr(args, "allow_docker_socket", False):
        socket_locations = {
            (item.path, item.line, item.service)
            for item in findings
            if item.code == "compose_docker_socket"
        }
        findings = [
            item
            for item in findings
            if not (
                (item.path, item.line, item.service) in socket_locations
                and item.code
                in {
                    "compose_docker_socket",
                    "compose_bind_absolute",
                    "compose_mount_sensitive",
                }
            )
        ]
    if getattr(args, "allow_published_ports", False):
        findings = [item for item in findings if item.code != "compose_published_port"]
    return findings


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.source_dir).resolve()
    try:
        result = audit_project(
            root,
            args.compose_file,
            non_root=args.non_root,
            require_build=args.require_build,
        )
    except AppDeployError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    findings = _visible_findings(result, args)
    threshold = SEVERITY_RANK[FAIL_ON[args.fail_on]]
    blocking = [
        finding
        for finding in findings
        if SEVERITY_RANK.get(finding.severity, 0) >= threshold
    ]
    if args.format == "json":
        print(
            json.dumps(
                {
                    "compose": result.compose.relative_to(result.root).as_posix(),
                    "findings": [_finding_dict(item) for item in findings],
                    "blocking": len(blocking),
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for finding in findings:
            print(
                f"[{finding.severity.upper()}] {finding.path}:{finding.line} "
                f"{finding.code} - {finding.message}"
            )
        print(f"\nTotal findings: {len(findings)} (blocking: {len(blocking)})")
    return 2 if blocking else 0


def _is_root_user(value: Any) -> bool:
    text = str(value).strip().lower()
    first = text.split(":", 1)[0]
    return text in {"", "root", "0", "0:0", "root:root"} or first == "root" or (
        first.isdigit() and int(first) == 0
    )


def _fix_dockerfile(
    text: str, uid: int, gid: int, *, ensure_readable_workdir: bool = False
) -> str:
    lines = text.splitlines()
    total_stages = sum(line.strip().upper().startswith("FROM ") for line in lines)
    if total_stages == 0:
        return text

    transformed: list[str] = []
    stage = 0
    for raw in lines:
        line = raw
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            stage += 1
        if re.search(r"\bchmod\s+(?:-[^ ]+\s+)*777\b", line):
            line = re.sub(r"(\bchmod\s+(?:-[^ ]+\s+)*)777\b", r"\g<1>755", line)
        if stage == total_stages and _dockerfile_user_is_root(line):
            indentation = line[: len(line) - len(line.lstrip())]
            line = f"{indentation}USER {uid}:{gid}"
        transformed.append(line)

    final_from = max(
        index
        for index, line in enumerate(transformed)
        if line.strip().upper().startswith("FROM ")
    )
    final_lines = transformed[final_from:]
    has_user = any(line.strip().upper().startswith("USER ") for line in final_lines)
    has_healthcheck = any(
        line.strip().upper().startswith("HEALTHCHECK ") for line in final_lines
    )
    workdirs = [
        line.strip().split(maxsplit=1)[1]
        for line in final_lines
        if line.strip().upper().startswith("WORKDIR ")
        and len(line.strip().split(maxsplit=1)) == 2
    ]
    insertion = next(
        (
            index
            for index in range(final_from, len(transformed))
            if transformed[index]
            .strip()
            .upper()
            .startswith(("USER ", "CMD ", "ENTRYPOINT "))
        ),
        len(transformed),
    )
    additions: list[str] = []
    if ensure_readable_workdir and workdirs and workdirs[-1].startswith("/"):
        additions.append(f"RUN chmod -R a+rX {workdirs[-1]}")
    if not has_user:
        additions.append(f"USER {uid}:{gid}")
    if not has_healthcheck:
        additions.append(
            "HEALTHCHECK --interval=30s --timeout=3s --retries=3 "
            "CMD echo ok || exit 1  # TODO: replace with an application probe"
        )
    if additions:
        transformed[insertion:insertion] = [*additions, ""]
    ending = "\n" if text.endswith("\n") else ""
    return "\n".join(transformed) + ending


def _dockerfile_user_is_root(line: str) -> bool:
    match = re.match(r"^\s*USER\s+([^\s]+)", line, re.IGNORECASE)
    return bool(match and _is_root_user(match.group(1)))


def _volume_parts(volume: Any) -> tuple[str, str, bool]:
    if isinstance(volume, str):
        parts = volume.split(":")
        if len(parts) < 2:
            return "", parts[0], False
        source, target = parts[0], parts[1]
        bind = source.startswith((".", "/")) or "/" in source or "\\" in source
        return source, target, bind
    if isinstance(volume, dict):
        return (
            str(volume.get("source", "")),
            str(volume.get("target", "")),
            volume.get("type") == "bind",
        )
    return "", "", False


def _unsafe_volume(volume: Any) -> bool:
    source, target, bind = _volume_parts(volume)
    source_lower = source.rstrip("/").lower()
    normalized_target = "/" + target.strip().lstrip("/")
    sensitive = any(
        normalized_target == blocked or normalized_target.startswith(blocked + "/")
        for blocked in ("/", "/proc", "/sys", "/dev", "/var/run")
    )
    docker_socket = source_lower.endswith("/docker.sock") or source_lower == "docker.sock"
    absolute_bind = bind and Path(source).is_absolute()
    return docker_socket or sensitive or absolute_bind


def _docker_socket_volume(volume: Any) -> bool:
    source, _, _ = _volume_parts(volume)
    normalized = source.rstrip("/").lower()
    return normalized.endswith("/docker.sock") or normalized == "docker.sock"


def _fix_environment(value: Any) -> Any:
    if isinstance(value, dict):
        for name, content in list(value.items()):
            if (
                re.search(r"(?i)(secret|password|passwd|token|api[_-]?key|private[_-]?key|credential)", str(name))
                and isinstance(content, str)
                and content
                and not content.startswith("${")
            ):
                value[name] = "${" + str(name) + "}"
    elif isinstance(value, list):
        fixed: list[Any] = []
        for item in value:
            name, separator, content = str(item).partition("=")
            if (
                separator
                and re.search(r"(?i)(secret|password|passwd|token|api[_-]?key|private[_-]?key|credential)", name)
                and content
                and not content.startswith("${")
            ):
                fixed.append(f"{name}=${{{name}}}")
            else:
                fixed.append(item)
        return fixed
    return value


def _fix_compose(
    text: str,
    uid: int,
    gid: int,
    *,
    allow_env_file: bool,
    allow_published_ports: bool,
    allow_docker_socket: bool,
    deployment_copy: bool,
    service_users: dict[str, str],
) -> str:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise AppDeployError("Compose file is invalid YAML") from exc
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict):
        raise AppDeployError("Compose must contain a services mapping")

    for service, config in data["services"].items():
        if not isinstance(config, dict):
            continue
        if service in service_users:
            config["user"] = service_users[service]
        if "user" in config and _is_root_user(config["user"]):
            config["user"] = f"{uid}:{gid}"
        for key in ("privileged", "cap_add", "devices", "container_name"):
            config.pop(key, None)
        for key in ("network_mode", "pid", "ipc", "uts", "userns", "cgroup"):
            if str(config.get(key, "")).strip().lower() == "host":
                config.pop(key, None)
        healthcheck = config.get("healthcheck")
        if isinstance(healthcheck, dict) and healthcheck.get("disable") is True:
            config.pop("healthcheck", None)
        options = config.get("security_opt")
        if options is not None:
            values = options if isinstance(options, list) else [options]
            safe = [
                option
                for option in values
                if "unconfined" not in str(option).lower().replace(" ", "")
                and str(option).lower().replace(" ", "")
                not in {"no-new-privileges:false", "no-new-privileges=false"}
            ]
            if safe:
                config["security_opt"] = safe
            else:
                config.pop("security_opt", None)
        if not allow_published_ports:
            config.pop("ports", None)
        if not allow_env_file and "env_file" in config:
            config.pop("env_file", None)
            config["x-spanel-external-env"] = True
        if "environment" in config:
            config["environment"] = _fix_environment(config["environment"])
        if deployment_copy and isinstance(config.get("volumes"), list):
            volumes = [
                item
                for item in config["volumes"]
                if not _unsafe_volume(item)
                or (allow_docker_socket and _docker_socket_volume(item))
            ]
            if volumes:
                config["volumes"] = volumes
            else:
                config.pop("volumes", None)
        if deployment_copy:
            config.pop("secrets", None)

    for section in ("networks", "volumes"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for config in entries.values():
            if not isinstance(config, dict):
                continue
            config.pop("name", None)
            if deployment_copy:
                config.pop("external", None)
    if deployment_copy:
        data.pop("secrets", None)
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False)


def _changes(
    result: AuditResult, args: argparse.Namespace
) -> dict[Path, tuple[str, str]]:
    changes: dict[Path, tuple[str, str]] = {}
    compose = result.compose
    original = _read(compose)
    fixed = _fix_compose(
        original,
        args.uid,
        args.gid,
        allow_env_file=args.allow_env_file,
        allow_published_ports=args.allow_published_ports,
        allow_docker_socket=args.allow_docker_socket,
        deployment_copy=args.deployment_copy,
        service_users=dict(args.service_user),
    )
    changes[compose] = (original, fixed)
    for dockerfile in sorted(set(result.dockerfiles.values())):
        original = _read(dockerfile)
        changes[dockerfile] = (
            original,
            _fix_dockerfile(
                original,
                args.uid,
                args.gid,
                ensure_readable_workdir=args.deployment_copy,
            ),
        )
    return changes


def _copy_for_audit(
    root: Path, changes: dict[Path, tuple[str, str]], temporary: Path
) -> Path:
    target = temporary / "checkout"
    shutil.copytree(root, target, symlinks=True)
    for source, (_, fixed) in changes.items():
        _write(target / source.relative_to(root), fixed)
    return target


def _audit_fixed(
    root: Path,
    changes: dict[Path, tuple[str, str]],
    args: argparse.Namespace,
) -> AuditResult:
    if args.apply:
        return audit_project(
            root,
            args.compose_file,
            non_root=args.non_root,
            require_build=args.require_build,
        )
    with tempfile.TemporaryDirectory(prefix="spanel-normalize-audit-") as temporary:
        audit_root = _copy_for_audit(root, changes, Path(temporary))
        return audit_project(
            audit_root,
            args.compose_file,
            non_root=args.non_root,
            require_build=args.require_build,
        )


def _apply_changes(root: Path, changes: dict[Path, tuple[str, str]]) -> None:
    backups = [path.with_name(path.name + ".bak") for path in changes]
    existing = [path for path in backups if path.exists()]
    if existing:
        names = ", ".join(path.relative_to(root).as_posix() for path in existing)
        raise AppDeployError(f"backup already exists: {names}")
    for path, backup in zip(changes, backups, strict=True):
        shutil.copy2(path, backup)
    for path, (_, fixed) in changes.items():
        _write(path, fixed)


def _write_preview(
    root: Path,
    result: AuditResult,
    changes: dict[Path, tuple[str, str]],
    out_dir: Path,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for source, (original, fixed) in changes.items():
        relative = source.relative_to(root)
        if source == result.compose:
            fixed_relative = Path(FIXED_COMPOSE)
            patch_relative = Path("docker-compose.patch")
        else:
            fixed_relative = relative.with_name(relative.name + ".fixed")
            patch_relative = relative.with_name(relative.name + ".patch")
        target = out_dir / fixed_relative
        _write(target, fixed)
        _write(
            out_dir / patch_relative,
            _diff(
                original,
                fixed,
                relative.as_posix(),
                fixed_relative.as_posix(),
            ),
        )


def cmd_fix(args: argparse.Namespace) -> int:
    root = Path(args.source_dir).resolve()
    if args.apply and args.out_dir:
        print("ERROR: --out-dir cannot be combined with --apply", file=sys.stderr)
        return 2
    names = [name for name, _user in args.service_user]
    if len(names) != len(set(names)):
        print("ERROR: --service-user contains a duplicate service", file=sys.stderr)
        return 2
    try:
        initial = audit_project(
            root,
            args.compose_file,
            non_root=args.non_root,
            require_build=args.require_build,
        )
        changes = _changes(initial, args)
        if args.apply:
            _apply_changes(root, changes)
            print("Applied fixes; one .bak file was created beside each changed source.")
        else:
            output = Path(args.out_dir).resolve() if args.out_dir else root
            _write_preview(root, initial, changes, output)
            print(f"Dry-run: fixed files and patches written under {output}.")
        result = _audit_fixed(root, changes, args)
    except AppDeployError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    residual = _visible_findings(result, args)
    errors = [item for item in residual if item.severity == "error"]
    print(
        f"Re-audit: findings={len(residual)} errors={len(errors)} "
        f"source={'applied' if args.apply else 'normalized-preview'}"
    )
    for finding in errors:
        print(
            f"[ERROR] {finding.path}:{finding.line} {finding.code} - {finding.message}",
            file=sys.stderr,
        )
    return 2 if errors else 0


def _tool_error(message: str) -> dict[str, Any]:
    return {"available": False, "blocking": 1, "findings": [], "error": message}


def _run_tool(
    command: list[str], root: Path, timeout: int, *, accepted: set[int]
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AppDeployError(f"{Path(command[0]).name} could not execute") from exc
    if completed.returncode not in accepted:
        raise AppDeployError(f"{Path(command[0]).name} execution failed")
    return completed


def _trivy_findings(payload: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in payload.get("Results", []) if isinstance(payload, dict) else []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target", "."))
        for item in result.get("Vulnerabilities") or []:
            if isinstance(item, dict):
                findings.append(
                    {
                        "kind": "vulnerability",
                        "severity": str(item.get("Severity", "UNKNOWN")).lower(),
                        "code": str(item.get("VulnerabilityID", "trivy_vulnerability")),
                        "path": target,
                        "package": str(item.get("PkgName", "")),
                        "message": str(item.get("Title") or "Known vulnerable dependency"),
                    }
                )
        for item in result.get("Misconfigurations") or []:
            if isinstance(item, dict):
                metadata = item.get("CauseMetadata") or {}
                findings.append(
                    {
                        "kind": "misconfiguration",
                        "severity": str(item.get("Severity", "UNKNOWN")).lower(),
                        "code": str(item.get("ID", "trivy_misconfiguration")),
                        "path": target,
                        "line": metadata.get("StartLine") if isinstance(metadata, dict) else None,
                        "message": str(item.get("Title") or item.get("Message") or "Misconfiguration"),
                    }
                )
        for item in result.get("Secrets") or []:
            if isinstance(item, dict):
                findings.append(
                    {
                        "kind": "secret",
                        "severity": str(item.get("Severity", "UNKNOWN")).lower(),
                        "code": str(item.get("RuleID", "trivy_secret")),
                        "path": target,
                        "line": item.get("StartLine"),
                        "message": str(item.get("Category") or item.get("Title") or "Secret detected"),
                    }
                )
    return findings


def _trivy_command_gate(command: list[str], root: Path, args: argparse.Namespace) -> dict[str, Any]:
    try:
        completed = _run_tool(command, root, args.tool_timeout, accepted={0})
        payload = json.loads(completed.stdout)
    except (AppDeployError, json.JSONDecodeError):
        return _tool_error("scan failed or returned invalid JSON")
    findings = _trivy_findings(payload)
    return {
        "available": True,
        "blocking": len(findings),
        "findings": findings,
        "error": None,
    }


def _trivy_gate(root: Path, args: argparse.Namespace) -> dict[str, Any]:
    executable = shutil.which("trivy")
    if not executable:
        return _tool_error("required executable is unavailable")
    return _trivy_command_gate(
        [
            executable,
            "fs",
            "--quiet",
            "--format",
            "json",
            "--exit-code",
            "0",
            "--scanners",
            "vuln,misconfig,secret",
            "--severity",
            args.trivy_severity,
            ".",
        ],
        root,
        args,
    )


def _trivy_image_gate(tag: str, root: Path, args: argparse.Namespace) -> dict[str, Any]:
    executable = shutil.which("trivy")
    if not executable:
        return _tool_error("required executable is unavailable")
    return _trivy_command_gate(
        [
            executable,
            "image",
            "--quiet",
            "--format",
            "json",
            "--exit-code",
            "0",
            "--scanners",
            "vuln,misconfig,secret",
            "--severity",
            args.trivy_severity,
            tag,
        ],
        root,
        args,
    )


def _image_cache(args: argparse.Namespace) -> ImageValidationCache:
    configured = getattr(args, "cache_dir", None)
    environment = os.getenv("SPANEL_HARDENER_CACHE_DIR", "").strip()
    directory = (
        Path(configured).expanduser()
        if configured
        else Path(environment).expanduser()
        if environment
        else Path.home() / ".cache" / "spanel-hardener"
    )
    return ImageValidationCache(
        directory,
        scan_ttl=args.image_cache_ttl,
        pull_ttl=args.pull_cache_ttl,
        enabled=not args.no_image_cache,
    )


def _discover_dockerfiles(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("Dockerfile*")
        if path.is_file()
        and ".git" not in path.parts
        and not path.name.endswith((".bak", ".fixed", ".patch"))
    )


def _hadolint_gate(root: Path, args: argparse.Namespace) -> dict[str, Any]:
    executable = shutil.which("hadolint")
    if not executable:
        return _tool_error("required executable is unavailable")
    dockerfiles = _discover_dockerfiles(root)
    if not dockerfiles:
        return {
            "available": True,
            "blocking": 0,
            "findings": [],
            "error": None,
            "dockerfiles": [],
            "skipped": "Compose uses external images only",
        }
    command = [
        executable,
        "--format",
        "json",
        *(path.relative_to(root).as_posix() for path in dockerfiles),
    ]
    try:
        completed = _run_tool(command, root, args.tool_timeout, accepted={0, 1})
        payload = json.loads(completed.stdout or "[]")
    except (AppDeployError, json.JSONDecodeError):
        return _tool_error("scan failed or returned invalid JSON")
    if not isinstance(payload, list):
        return _tool_error("scan returned an unexpected JSON document")
    threshold = HADOLINT_RANK[args.hadolint_failure_threshold]
    findings = [
        {
            "severity": str(item.get("level", "warning")).lower(),
            "code": str(item.get("code", "hadolint")),
            "path": str(item.get("file", "Dockerfile")),
            "line": item.get("line"),
            "column": item.get("column"),
            "message": str(item.get("message", "Dockerfile lint finding")),
        }
        for item in payload
        if isinstance(item, dict)
    ]
    blocking = 0
    if args.hadolint_failure_threshold != "ignore":
        blocking = sum(
            HADOLINT_RANK.get(str(item["severity"]), HADOLINT_RANK["warning"])
            >= threshold
            for item in findings
        )
    return {
        "available": True,
        "blocking": blocking,
        "findings": findings,
        "error": None,
        "dockerfiles": [path.relative_to(root).as_posix() for path in dockerfiles],
    }


def _build_context(result: AuditResult, service: str) -> Path:
    config = result.data["services"][service]
    build = config["build"]
    context = build if isinstance(build, str) else build.get("context", ".")
    return (result.compose.parent / str(context)).resolve()


def _inspect_image(
    executable: str,
    reference: str,
    root: Path,
    args: argparse.Namespace,
    environment: dict[str, str],
) -> dict[str, Any] | None:
    try:
        completed = subprocess.run(
            [
                executable,
                "image",
                "inspect",
                reference,
                "--format",
                "{{json .}}",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=args.tool_timeout,
            check=False,
            env=environment,
        )
        payload = json.loads(completed.stdout) if completed.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _has_healthcheck(config: dict[str, Any], image: dict[str, Any]) -> bool:
    compose_health = config.get("healthcheck")
    if isinstance(compose_health, dict) and compose_health.get("disable") is not True:
        return bool(compose_health.get("test"))
    image_config = image.get("Config") or {}
    return bool(image_config.get("Healthcheck")) if isinstance(image_config, dict) else False


def _runtime_isolation_errors(result: AuditResult) -> list[str]:
    errors: list[str] = []
    for service, config in result.data["services"].items():
        if not isinstance(config, dict):
            errors.append(f"{service}: invalid service mapping")
            continue
        options = config.get("security_opt") or []
        options = [options] if isinstance(options, str) else options
        drops = config.get("cap_drop") or []
        drops = [drops] if isinstance(drops, str) else drops
        if config.get("read_only") is not False:
            errors.append(f"{service}: root filesystem is not explicitly writable")
        if "ALL" not in {str(item).upper() for item in drops}:
            errors.append(f"{service}: capabilities are not fully dropped")
        if "no-new-privileges:true" not in {
            str(item).lower().replace("=", ":") for item in options
        }:
            errors.append(f"{service}: no-new-privileges is absent")
        normalized_options = {
            str(item).lower().replace(":", "=") for item in options
        }
        if "apparmor=docker-default" not in normalized_options:
            errors.append(f"{service}: docker-default AppArmor profile is absent")
        if "seccomp=builtin" not in normalized_options:
            errors.append(f"{service}: default seccomp profile is absent")
        if config.get("runtime") != "runc":
            errors.append(f"{service}: runtime is not explicitly runc")
        if config.get("pids_limit") != 256:
            errors.append(f"{service}: PID limit is invalid")
        if config.get("mem_limit") != "512m":
            errors.append(f"{service}: memory limit is invalid")
        if config.get("cpus") != 1.0:
            errors.append(f"{service}: CPU limit is invalid")
        if "user" not in config or _is_root_user(config.get("user")):
            errors.append(f"{service}: runtime user is not explicitly non-root")
        if config.get("ports") or config.get("privileged"):
            errors.append(f"{service}: host publication or privilege remains")
        for volume in config.get("volumes") or []:
            _source, _target, bind = _volume_parts(volume)
            if bind:
                errors.append(f"{service}: host bind remains")
    networks = result.data.get("networks") or {}
    if not isinstance(networks, dict) or not networks:
        errors.append("runtime network is not explicitly internal")
    else:
        for name, config in networks.items():
            if not isinstance(config, dict) or config.get("internal") is not True:
                errors.append(f"network {name}: egress is not disabled")
    return errors


def _runtime_smoke(
    result: AuditResult,
    args: argparse.Namespace,
    executable: str,
    environment: dict[str, str],
    tags: dict[str, str],
) -> dict[str, Any]:
    errors = _runtime_isolation_errors(result)
    if errors:
        return {"attempted": False, "passed": False, "errors": errors}
    project = f"spanel-gate-{os.getpid()}"
    override = result.root / f".spanel-gate-{os.getpid()}.yml"
    override.write_text(
        yaml.safe_dump(
            {"services": {service: {"image": tag} for service, tag in tags.items()}},
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    base = [
        executable,
        "compose",
        *(["--env-file", str(args.env_file)] if getattr(args, "env_file", None) else []),
        "--project-name",
        project,
        "--file",
        str(result.compose),
        "--file",
        str(override),
    ]
    try:
        completed = subprocess.run(
            [
                *base,
                "up",
                "--detach",
                "--no-build",
                "--wait",
                "--wait-timeout",
                str(args.runtime_timeout),
            ],
            cwd=result.root,
            capture_output=True,
            text=True,
            timeout=args.runtime_timeout + args.tool_timeout,
            check=False,
            env=environment,
        )
        passed = completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        passed = False
    finally:
        try:
            subprocess.run(
                [*base, "down", "--volumes", "--remove-orphans"],
                cwd=result.root,
                capture_output=True,
                text=True,
                timeout=args.tool_timeout,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired):
            passed = False
        override.unlink(missing_ok=True)
    return {"attempted": True, "passed": passed, "errors": []}


def _buildkit_gate(
    result: AuditResult, args: argparse.Namespace, *, static_blocking: bool
) -> dict[str, Any]:
    started = time.perf_counter()
    if args.skip_build:
        return {"attempted": False, "passed": None, "services": [], "error": None}
    if static_blocking:
        return {
            "attempted": False,
            "passed": None,
            "services": [],
            "error": "skipped because static checks are blocking",
        }
    executable = shutil.which("docker")
    if not executable:
        return {
            "attempted": False,
            "passed": False,
            "services": [],
            "error": "required executable is unavailable",
        }
    services: list[dict[str, Any]] = []
    tags: dict[str, str] = {}
    ephemeral_tags: dict[str, str] = {}
    passed = True
    environment = {**os.environ, "DOCKER_BUILDKIT": "1"}
    validation_cache = _image_cache(args)
    trivy_executable = shutil.which("trivy") or ""
    trivy_fingerprint = scanner_fingerprint(trivy_executable) if trivy_executable else "unavailable"
    for index, (service, dockerfile) in enumerate(sorted(result.dockerfiles.items())):
        context = _build_context(result, service)
        try:
            dockerfile_arg = dockerfile.relative_to(context).as_posix()
        except ValueError:
            services.append({"service": service, "passed": False})
            passed = False
            continue
        safe_service = re.sub(r"[^a-z0-9_.-]+", "-", service.lower()).strip("-.")
        tag = f"spanel-gate-{os.getpid()}-{index}-{safe_service or 'service'}"
        tags[service] = tag
        ephemeral_tags[service] = tag
        command = [
            executable,
            "build",
            "--file",
            dockerfile_arg,
            "--tag",
            tag,
            ".",
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=context,
                capture_output=True,
                text=True,
                timeout=args.build_timeout,
                check=False,
                env=environment,
            )
            service_passed = completed.returncode == 0
            metadata = (
                _inspect_image(executable, tag, context, args, environment)
                if service_passed
                else None
            )
            healthcheck = bool(
                metadata
                and _has_healthcheck(result.data["services"][service], metadata)
            )
            if service_passed and metadata:
                image_scan = _trivy_image_gate(tag, context, args)
            else:
                image_scan = _tool_error("image was not produced")
            service_passed = (
                service_passed
                and metadata is not None
                and healthcheck
                and image_scan["blocking"] == 0
            )
        except (OSError, subprocess.TimeoutExpired):
            service_passed = False
            healthcheck = False
            image_scan = _tool_error("image build could not execute")
        services.append(
            {
                "service": service,
                "source": "build",
                "passed": service_passed,
                "healthcheck": healthcheck,
                "image_scan": image_scan,
            }
        )
        passed = passed and service_passed
    image_services = sorted(set(result.data["services"]).difference(result.dockerfiles))
    for service in image_services:
        config = result.data["services"][service]
        reference = str(config.get("image", "")).strip() if isinstance(config, dict) else ""
        if not reference:
            services.append(
                {
                    "service": service,
                    "source": "external",
                    "passed": False,
                    "image_scan": _tool_error("service has no image reference"),
                }
            )
            passed = False
            continue
        try:
            resolved = validation_cache.reference(reference)
            metadata = (
                _inspect_image(executable, resolved, result.root, args, environment)
                if resolved
                else None
            )
            pull_source = "cache" if metadata else "registry"
            if metadata is None:
                pulled = subprocess.run(
                    [executable, "pull", reference],
                    cwd=result.root,
                    capture_output=True,
                    text=True,
                    timeout=args.build_timeout,
                    check=False,
                    env=environment,
                )
                metadata = _inspect_image(
                    executable, reference, result.root, args, environment
                )
                digests = (metadata.get("RepoDigests") or []) if metadata else []
                resolved = (
                    str(digests[0])
                    if isinstance(digests, list) and digests
                    else reference
                )
                if pulled.returncode == 0:
                    validation_cache.save_reference(reference, resolved)
            healthcheck = bool(
                metadata
                and _has_healthcheck(result.data["services"][service], metadata)
            )
            cached_scan = validation_cache.scan(
                resolved,
                severity=args.trivy_severity,
                scanner_fingerprint=trivy_fingerprint,
            )
            if cached_scan is not None:
                image_scan = {**cached_scan, "cache": "hit"}
            elif metadata is not None:
                image_scan = _trivy_image_gate(resolved, result.root, args)
                if image_scan.get("available"):
                    validation_cache.save_scan(
                        resolved,
                        image_scan,
                        severity=args.trivy_severity,
                        scanner_fingerprint=trivy_fingerprint,
                    )
                image_scan = {**image_scan, "cache": "miss"}
            else:
                image_scan = _tool_error("external image pull or inspection failed")
                image_scan["cache"] = "miss"
            service_passed = healthcheck and image_scan["blocking"] == 0
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            resolved = reference
            pull_source = "error"
            healthcheck = False
            image_scan = _tool_error("external image validation could not execute")
            service_passed = False
        tags[service] = resolved
        services.append(
            {
                "service": service,
                "source": "external",
                "reference": reference,
                "resolved": resolved,
                "pull": pull_source,
                "healthcheck": healthcheck,
                "passed": service_passed,
                "image_scan": image_scan,
            }
        )
        passed = passed and service_passed
    runtime = {"attempted": False, "passed": None, "errors": []}
    if passed and getattr(args, "runtime_smoke", False):
        runtime = _runtime_smoke(result, args, executable, environment, tags)
        passed = runtime["passed"] is True
    for service, tag in ephemeral_tags.items():
        try:
            subprocess.run(
                [executable, "image", "rm", "--force", tag],
                cwd=_build_context(result, service),
                capture_output=True,
                text=True,
                timeout=args.tool_timeout,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    return {
        "attempted": True,
        "passed": passed,
        "services": services,
        "runtime": runtime,
        "duration_seconds": round(time.perf_counter() - started, 6),
        "error": None if passed else "build, image, or runtime validation failed",
    }


def _gate_payload(root: Path, args: argparse.Namespace) -> dict[str, Any]:
    started = time.perf_counter()
    internal_started = time.perf_counter()
    internal = audit_project(
        root,
        args.compose_file,
        non_root=args.non_root,
        require_build=args.require_build,
    )
    internal_findings = _visible_findings(internal, args)
    threshold = SEVERITY_RANK[FAIL_ON[args.fail_on]]
    internal_blocking = sum(
        SEVERITY_RANK.get(item.severity, 0) >= threshold
        for item in internal_findings
    )
    internal_seconds = time.perf_counter() - internal_started
    external_started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="spanel-static") as pool:
        trivy_future = pool.submit(_trivy_gate, root, args)
        hadolint_future = pool.submit(_hadolint_gate, root, args)
        trivy = trivy_future.result()
        hadolint = hadolint_future.result()
    external_seconds = time.perf_counter() - external_started
    static_blocking = bool(
        internal_blocking or trivy["blocking"] or hadolint["blocking"]
    )
    buildkit = _buildkit_gate(internal, args, static_blocking=static_blocking)
    blocked = static_blocking or buildkit.get("passed") is False
    payload = {
        "status": "blocked" if blocked else "passed",
        "internal": {
            "blocking": internal_blocking,
            "findings": [_finding_dict(item) for item in internal_findings],
        },
        "trivy": trivy,
        "hadolint": hadolint,
        "buildkit": buildkit,
        "timings": {
            "internal_seconds": round(internal_seconds, 6),
            "external_static_seconds": round(external_seconds, 6),
            "build_image_runtime_seconds": buildkit.get("duration_seconds", 0.0),
            "total_seconds": round(time.perf_counter() - started, 6),
        },
    }
    return payload


def cmd_gate(args: argparse.Namespace) -> int:
    try:
        payload = _gate_payload(Path(args.source_dir).resolve(), args)
    except AppDeployError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    internal_blocking = payload["internal"]["blocking"]
    trivy = payload["trivy"]
    hadolint = payload["hadolint"]
    buildkit = payload["buildkit"]
    if args.format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            f"Gate {payload['status']}: internal={internal_blocking} "
            f"trivy={trivy['blocking']} hadolint={hadolint['blocking']} "
            f"buildkit={'skipped' if not buildkit['attempted'] else buildkit['passed']}"
        )
        for name in ("trivy", "hadolint"):
            if payload[name].get("error"):
                print(f"ERROR: {name}: {payload[name]['error']}", file=sys.stderr)
        if buildkit.get("error"):
            print(f"ERROR: buildkit: {buildkit['error']}", file=sys.stderr)
    return 2 if payload["status"] == "blocked" else 0


def _isolation_gate_payload(root: Path, args: argparse.Namespace) -> dict[str, Any]:
    """Admission gate for ``harden``: isolation audit only.

    Trivy, Hadolint and BuildKit never participate in hardening.  The real
    build runs during deployment; here only the isolation envelope is audited.
    """

    result = audit_project(
        root,
        args.compose_file,
        non_root=True,
        require_build=False,
    )
    errors = result.errors
    return {
        "status": "blocked" if errors else "passed",
        "isolation": {
            "blocking": len(errors),
            "findings": [_finding_dict(item) for item in errors],
        },
    }


def cmd_harden(args: argparse.Namespace) -> int:
    code, report = run_hardener(args, _isolation_gate_payload)
    return emit_report(code, report, args.format)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan")
    scan.add_argument("source_dir", nargs="?", default=".")
    scan.add_argument("--compose-file")
    scan.add_argument("--non-root", action="store_true")
    scan.add_argument("--require-build", action="store_true")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument(
        "--fail-on",
        choices=("high", "medium", "low", "error", "warning", "info"),
        default="high",
    )
    scan.add_argument("--allow-docker-socket", action="store_true")
    scan.add_argument("--allow-env-file", action="store_true")
    scan.set_defaults(func=cmd_scan)

    fix = subcommands.add_parser("fix")
    fix.add_argument("source_dir", nargs="?", default=".")
    fix.add_argument("--compose-file")
    fix.add_argument("--apply", action="store_true")
    fix.add_argument("--dry-run", action="store_true")
    fix.add_argument("--out-dir")
    fix.add_argument("--uid", type=int, default=DEFAULT_UID)
    fix.add_argument("--gid", type=int, default=DEFAULT_GID)
    fix.add_argument("--non-root", action="store_true")
    fix.add_argument("--require-build", action="store_true")
    fix.add_argument("--allow-docker-socket", action="store_true")
    fix.add_argument("--allow-env-file", action="store_true")
    fix.add_argument("--allow-published-ports", action="store_true")
    fix.add_argument(
        "--service-user",
        action="append",
        default=[],
        type=_parse_service_user,
        metavar="SERVICE=USER",
        help="set an explicit non-root Compose user for one service",
    )
    fix.add_argument(
        "--deployment-copy",
        action="store_true",
        help=(
            "remove level-C host access and Compose secrets from a disposable "
            "deployment checkout; never use this on the canonical repository"
        ),
    )
    fix.set_defaults(func=cmd_fix)

    gate = subcommands.add_parser(
        "gate",
        help="combine the built-in audit, Trivy, Hadolint, and a BuildKit build",
    )
    gate.add_argument("source_dir", nargs="?", default=".")
    gate.add_argument("--compose-file")
    gate.add_argument("--non-root", action="store_true")
    gate.add_argument("--require-build", action="store_true")
    gate.add_argument("--format", choices=("text", "json"), default="text")
    gate.add_argument(
        "--fail-on",
        choices=("high", "medium", "low", "error", "warning", "info"),
        default="high",
    )
    gate.add_argument("--allow-docker-socket", action="store_true")
    gate.add_argument("--allow-env-file", action="store_true")
    gate.add_argument(
        "--trivy-severity",
        default="HIGH,CRITICAL",
        help="comma-separated Trivy severities that block the gate",
    )
    gate.add_argument(
        "--hadolint-failure-threshold",
        choices=("error", "warning", "info", "style", "ignore"),
        default="warning",
    )
    gate.add_argument("--tool-timeout", type=int, default=300)
    gate.add_argument("--build-timeout", type=int, default=1800)
    gate.add_argument("--runtime-timeout", type=int, default=120)
    gate.add_argument("--image-cache-ttl", type=int, default=3600)
    gate.add_argument("--pull-cache-ttl", type=int, default=900)
    gate.add_argument("--cache-dir", type=Path)
    gate.add_argument("--no-image-cache", action="store_true")
    gate.add_argument(
        "--runtime-smoke",
        action="store_true",
        help="start the project only after verifying the strict isolation envelope",
    )
    gate.add_argument(
        "--skip-build",
        action="store_true",
        help="run the three static gates without invoking BuildKit",
    )
    gate.set_defaults(func=cmd_gate)

    harden = subcommands.add_parser(
        "harden",
        help="stage, isolate, audit isolation, and transactionally publish a hardened checkout",
    )
    harden.add_argument("source_dir", nargs="?", default=".")
    harden.add_argument("--compose-file")
    harden.add_argument("--apply", action="store_true")
    harden.add_argument("--out-dir")
    harden.add_argument("--format", choices=("text", "json"), default="text")
    harden.add_argument(
        "--service-user",
        action="append",
        default=[],
        required=True,
        type=_parse_numeric_service_user,
        metavar="SERVICE=UID:GID",
    )
    harden.add_argument(
        "--writable-path",
        action="append",
        default=[],
        type=_parse_writable_path,
        metavar="SERVICE=/PATH:MODE",
    )
    harden.add_argument(
        "--authorized-external-network",
        action="append",
        default=[],
        metavar="NETWORK",
        help="authorize a Compose network declared as external: true",
    )
    harden.add_argument(
        "--egress-network",
        action="append",
        default=[],
        metavar="NETWORK",
        help="authorize a Compose network declared as internal: false",
    )
    harden.set_defaults(func=cmd_harden)
    return parser


def _parse_service_user(value: str) -> tuple[str, str]:
    service, separator, user = value.partition("=")
    if (
        not separator
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", service)
        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*|[0-9]+(?::[0-9]+)?", user)
        or _is_root_user(user)
    ):
        raise argparse.ArgumentTypeError(
            "service user must be SERVICE=USER with an explicit non-root user"
        )
    return service, user


def _parse_numeric_service_user(value: str) -> tuple[str, tuple[int, int]]:
    service, separator, user = value.partition("=")
    match = re.fullmatch(r"([1-9][0-9]*):([1-9][0-9]*)", user)
    if not separator or not re.fullmatch(r"[A-Za-z0-9_.-]+", service) or not match:
        raise argparse.ArgumentTypeError("service user must be SERVICE=UID:GID with positive IDs")
    return service, (int(match.group(1)), int(match.group(2)))


def _parse_writable_path(value: str) -> tuple[str, WritablePath]:
    service, separator, target = value.partition("=")
    path, mode_separator, mode = target.rpartition(":")
    if not mode_separator or not re.fullmatch(r"0?[0-7]{3}", mode):
        path, mode = target, "0750"
    if not separator or not re.fullmatch(r"[A-Za-z0-9_.-]+", service) or not path.startswith("/"):
        raise argparse.ArgumentTypeError("writable path must be SERVICE=/ABSOLUTE/PATH[:MODE]")
    return service, WritablePath(path, mode)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "dry_run", False) and getattr(args, "apply", False):
        print("ERROR: --dry-run and --apply are mutually exclusive", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
