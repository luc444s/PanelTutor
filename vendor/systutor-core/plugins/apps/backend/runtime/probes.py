"""Independent deployment probes.

The repository healthcheck is a prerequisite, never the proof.  These probes
inspect the effective isolation, execute a disposable functional check from
inside the release network, and watch stability for a bounded window.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .deployment import _compose_command
from .docker_audit import _is_definitely_non_root_user
from .transport import Runner
from .types import AppDeployError

PROBE_USER = "65534:65534"
MAX_OUTPUT_BYTES = 64 * 1024
_DIGEST_IMAGE = re.compile(r".+@sha256:[0-9a-f]{64}\Z")


class ProbeFailed(AppDeployError):
    """A safe, bounded probe failure."""


def _int_env(environ: Mapping[str, str], name: str, default: int) -> int:
    raw = environ.get(name, "").strip()
    if not raw:
        return default
    if not raw.isdigit():
        raise ProbeFailed(f"{name} is invalid")
    return int(raw)


def probe_image(environ: Mapping[str, str]) -> str:
    value = environ.get("SPANEL_APPS_PROBE_IMAGE", "").strip()
    if not value or not _DIGEST_IMAGE.fullmatch(value):
        raise ProbeFailed("a digest-pinned probe image is required")
    return value


def probe_command(environ: Mapping[str, str]) -> list[str]:
    raw = environ.get("SPANEL_APPS_PROBE_COMMAND", "").strip()
    if not raw:
        raise ProbeFailed("an independent probe command is required")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise ProbeFailed("the probe command is invalid") from None
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 32
        or any(not isinstance(item, str) or not item or len(item) > 2048 for item in value)
    ):
        raise ProbeFailed("the probe command is invalid")
    return value


def _container(container: dict[str, Any]) -> dict[str, Any]:
    state = container.get("State") or {}
    host = container.get("HostConfig") or {}
    config = container.get("Config") or {}
    return {"state": state, "host": host, "config": config}


def _process_users(runner: Runner, container_id: str) -> list[str]:
    result = runner.run(["docker", "top", container_id, "-eo", "pid,uid"], check=False)
    if result.returncode:
        raise ProbeFailed("cannot inspect effective process users")
    rows = [line.split() for line in result.stdout.splitlines() if line.strip()]
    try:
        index = [item.lower() for item in rows[0]].index("uid")
        return [row[index].lower() for row in rows[1:]]
    except (IndexError, ValueError):
        raise ProbeFailed("effective process users are uninspectable") from None


def check_isolation(
    runner: Runner, containers: Mapping[str, str]
) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    for service, container_id in containers.items():
        values = _inspect_container(runner, container_id)
        state, host, config = values["state"], values["host"], values["config"]
        if not _is_definitely_non_root_user(config.get("user")):
            raise ProbeFailed(f"service {service} does not declare a non-root user")
        if host.get("Privileged") is True:
            raise ProbeFailed(f"service {service} is privileged")
        if host.get("Devices"):
            raise ProbeFailed(f"service {service} accesses host devices")
        if host.get("Binds"):
            raise ProbeFailed(f"service {service} contains a host bind")
        if host.get("PortBindings"):
            raise ProbeFailed(f"service {service} publishes host ports")
        if str(host.get("PidMode", "")) == "host":
            raise ProbeFailed(f"service {service} uses the host PID namespace")
        if str(host.get("NetworkMode", "")) in {"host", "container:host"}:
            raise ProbeFailed(f"service {service} uses the host network")
        caps = {str(item).upper() for item in (host.get("CapDrop") or [])}
        if "ALL" not in caps:
            raise ProbeFailed(f"service {service} does not drop all capabilities")
        options = " ".join(
            str(item).lower().replace(" ", "")
            for item in (host.get("SecurityOpt") or [])
        )
        if "no-new-privileges" not in options:
            raise ProbeFailed(f"service {service} allows privilege escalation")
        if host.get("ReadonlyRootfs") is not True:
            raise ProbeFailed(f"service {service} has a writable root filesystem")
        if str(state.get("Status", "")) != "running":
            raise ProbeFailed(f"service {service} is not running")
        users = _process_users(runner, container_id)
        if not users or any(
            user == "root" or (user.isdigit() and int(user) == 0) for user in users
        ):
            raise ProbeFailed(f"service {service} has root processes")
        networks = _network_names_from_config(values)
        if not networks:
            raise ProbeFailed(f"service {service} has no internal network")
        for network in networks:
            internal = runner.run(
                [
                    "docker",
                    "network",
                    "inspect",
                    "-f",
                    "{{.Internal}}",
                    network,
                ],
                check=False,
            )
            if internal.returncode or internal.stdout.strip().lower() != "true":
                raise ProbeFailed(f"service {service} network is not internal")
        evidence[service] = {
            "user": str(config.get("user")),
            "networks": networks,
            "processes": len(users),
        }
    return evidence


def _network_names_from_config(values: Mapping[str, Any]) -> list[str]:
    """Read network names captured from the original inspect payload."""

    networks = values.get("networks") or []
    return sorted(str(name) for name in networks)


def _capture_networks(payload: dict[str, Any]) -> list[str]:
    networks = (payload.get("NetworkSettings") or {}).get("Networks") or {}
    if not isinstance(networks, dict):
        return []
    return sorted(str(name) for name in networks)


def _inspect_container(runner: Runner, container_id: str) -> dict[str, Any]:
    result = runner.run(["docker", "container", "inspect", container_id], check=False)
    if result.returncode:
        raise ProbeFailed("cannot inspect deployment isolation")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ProbeFailed("deployment isolation evidence is invalid") from None
    if (
        not isinstance(payload, list)
        or len(payload) != 1
        or not isinstance(payload[0], dict)
    ):
        raise ProbeFailed("deployment isolation evidence is invalid")
    value = payload[0]
    values = _container(value)
    values["networks"] = _capture_networks(value)
    return values


def _probe_argv(
    image: str,
    command: Sequence[str],
    network: str,
    limits: tuple[int, int, int],
) -> list[str]:
    pids, memory_mb, cpus = limits
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        network,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        str(pids),
        "--memory",
        f"{memory_mb}m",
        "--cpus",
        str(cpus),
        "--user",
        PROBE_USER,
        image,
        *command,
    ]


def run_functional_probe(
    runner: Runner,
    *,
    network: str,
    image: str,
    command: Sequence[str],
    timeout: int,
    limits: tuple[int, int, int] = (64, 128, 1),
) -> dict[str, Any]:
    if str(runner.transport) == "ssh":
        raise ProbeFailed("functional probes require a local Docker runner")
    result = runner.run(
        _probe_argv(image, command, network, limits),
        timeout=timeout,
        check=False,
    )
    output = (result.stdout + result.stderr).encode()
    evidence = {
        "returncode": result.returncode,
        "sha256": hashlib.sha256(output).hexdigest(),
        "bytes": min(len(output), MAX_OUTPUT_BYTES),
    }
    if result.returncode:
        raise ProbeFailed("the independent functional probe failed")
    return evidence


def assert_compose_healthchecks(
    runner: Runner,
    release: Path,
    compose_rel: str,
    project: str,
    services: Sequence[str],
) -> None:
    result = runner.run(
        _compose_command(
            release, compose_rel, project, True, "config", "--format", "json"
        ),
        check=False,
    )
    if result.returncode:
        raise ProbeFailed("cannot resolve the hardened Compose configuration")
    try:
        payload = json.loads(result.stdout)
        configured = payload["services"]
    except (json.JSONDecodeError, KeyError, TypeError):
        raise ProbeFailed("the hardened Compose configuration is invalid") from None
    for service in services:
        config = configured.get(service)
        healthcheck = config.get("healthcheck") if isinstance(config, dict) else None
        test = healthcheck.get("test") if isinstance(healthcheck, dict) else None
        if not test or test == ["NONE"] or test == "NONE":
            raise ProbeFailed(f"service {service} has no effective healthcheck")


def _inspect_stability(
    runner: Runner, containers: Mapping[str, str]
) -> dict[str, Any]:
    restart_counts: dict[str, int] = {}
    for service, container_id in containers.items():
        values = _inspect_container(runner, container_id)
        state = values["state"]
        health = state.get("Health") or {}
        status = str(health.get("Status", "")).lower()
        if status != "healthy":
            raise ProbeFailed(f"service {service} is not healthy during the probe window")
        restart_count = state.get("RestartCount", 0)
        if not isinstance(restart_count, int) or restart_count != 0:
            raise ProbeFailed(f"service {service} restarted during the probe window")
        restart_counts[service] = restart_count
    return restart_counts


def run_probes(
    runner: Runner,
    *,
    release: Path,
    compose_rel: str,
    project: str,
    services: Sequence[str],
    containers: Mapping[str, str],
    environ: Mapping[str, str] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    environ = dict(os.environ if environ is None else environ)
    image = probe_image(environ)
    command = probe_command(environ)
    checks = _int_env(environ, "SPANEL_APPS_PROBE_CHECKS", 3)
    window = _int_env(environ, "SPANEL_APPS_PROBE_WINDOW_SECONDS", 30)
    timeout = _int_env(environ, "SPANEL_APPS_PROBE_TIMEOUT_SECONDS", 30)
    if not 1 <= checks <= 60 or not 0 <= window <= 3600:
        raise ProbeFailed("the probe window is invalid")
    assert_compose_healthchecks(runner, release, compose_rel, project, services)
    isolation = check_isolation(runner, containers)
    networks: set[str] = set()
    for values in isolation.values():
        networks.update(values["networks"])
    if len(networks) != 1:
        raise ProbeFailed("the release must use exactly one internal network")
    network = next(iter(networks))
    functional: list[dict[str, Any]] = []
    restart_counts: dict[str, int] = {}
    interval = window / checks if checks else 0
    for index in range(checks):
        functional.append(
            run_functional_probe(
                runner,
                network=network,
                image=image,
                command=command,
                timeout=timeout,
            )
        )
        restart_counts = _inspect_stability(runner, containers)
        if index + 1 < checks and interval:
            sleep(interval)
    return {
        "isolation": isolation,
        "functional": {
            "image": image,
            "checks": functional,
        },
        "stability": {
            "checks": checks,
            "window_seconds": window,
            "restart_counts": restart_counts,
        },
    }
