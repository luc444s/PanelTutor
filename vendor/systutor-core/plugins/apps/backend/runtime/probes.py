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

import yaml

from .deployment import _compose_command
from .docker_audit import _is_definitely_non_root_user
from .probe_defaults import DEFAULT_PROBE_IMAGE
from .transport import Runner
from .types import AppDeployError

PROBE_USER = "65534:65534"
MAX_OUTPUT_BYTES = 64 * 1024
MAX_APP_PIDS = 256
MAX_APP_MEMORY = 512 * 1024 * 1024
MAX_APP_NANO_CPUS = 1_000_000_000
_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
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
    if not value:
        value = DEFAULT_PROBE_IMAGE
    if not _DIGEST_IMAGE.fullmatch(value):
        raise ProbeFailed("a digest-pinned probe image is required")
    return value


def _default_probe_command(target: tuple[str, int]) -> list[str]:
    service, port = target
    if not isinstance(service, str) or not _SERVICE_NAME.fullmatch(service):
        raise ProbeFailed("the probe target service is invalid")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ProbeFailed("the probe target port is invalid")
    # Any HTTP response, including 4xx/5xx, proves the ingress is reachable;
    # connection failures still exit non-zero.  The status code is written to
    # stdout as bounded evidence while the response body is discarded.
    return [
        "curl", "-sS", "-o", "/dev/null",
        "--write-out", "%{http_code}",
        "--connect-timeout", "5", "--max-time", "10",
        f"http://{service}:{port}/",
    ]


def probe_command(
    environ: Mapping[str, str],
    target: tuple[str, int] | None = None,
) -> list[str]:
    raw = environ.get("SPANEL_APPS_PROBE_COMMAND", "").strip()
    if not raw:
        if target is None:
            raise ProbeFailed("an independent probe command is required")
        return _default_probe_command(target)
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
    return {
        "state": state,
        "host": host,
        "config": config,
        "apparmor": container.get("AppArmorProfile"),
        "mounts": container.get("Mounts") or [],
    }


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


def _signed_networks(
    release_root: Path | None,
    compose_rel: str | None,
) -> dict[str, dict[str, Any]]:
    """Read the signed Compose network declarations, if available."""
    if release_root is None or not compose_rel:
        return {}
    try:
        payload = yaml.safe_load((release_root / compose_rel).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        return {}
    networks = payload.get("networks") if isinstance(payload, dict) else None
    if not isinstance(networks, dict):
        return {}
    return {
        str(name): (options if isinstance(options, dict) else {})
        for name, options in networks.items()
    }


def _signed_network_options(
    signed: Mapping[str, dict[str, Any]],
    network: str,
) -> dict[str, Any] | None:
    for name, options in signed.items():
        if network == name or network.endswith("_" + name):
            return options
    return None


def check_isolation(
    runner: Runner,
    containers: Mapping[str, str],
    release_root: Path | None = None,
    compose_rel: str | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    signed = _signed_networks(release_root, compose_rel)
    for service, container_id in containers.items():
        values = _inspect_container(runner, container_id)
        state, host, config = values["state"], values["host"], values["config"]
        if not _is_definitely_non_root_user(config.get("User")):
            raise ProbeFailed(f"service {service} does not declare a non-root user")
        if host.get("Privileged") is True:
            raise ProbeFailed(f"service {service} is privileged")
        if host.get("Devices"):
            raise ProbeFailed(f"service {service} accesses host devices")
        if any(
            isinstance(mount, Mapping)
            and mount.get("Type") == "bind"
            for mount in values["mounts"]
        ):
            raise ProbeFailed(f"service {service} contains a host bind")
        sysctls = host.get("Sysctls") or {}
        if sysctls != {} and sysctls != {
            "net.ipv4.ip_unprivileged_port_start": "0"
        }:
            raise ProbeFailed(f"service {service} contains an unsafe sysctl")
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
        if "apparmor=docker-default" not in options:
            raise ProbeFailed(f"service {service} does not use docker-default AppArmor")
        if "seccomp=builtin" not in options:
            raise ProbeFailed(f"service {service} does not use the default seccomp profile")
        if values.get("apparmor") != "docker-default":
            raise ProbeFailed(f"service {service} effective AppArmor profile is invalid")
        if host.get("Runtime") != "runc":
            raise ProbeFailed(f"service {service} does not use runc")
        pids = host.get("PidsLimit")
        if (
            isinstance(pids, bool)
            or not isinstance(pids, int)
            or not 0 < pids <= MAX_APP_PIDS
        ):
            raise ProbeFailed(f"service {service} PID limit is invalid")
        memory = host.get("Memory")
        if (
            isinstance(memory, bool)
            or not isinstance(memory, int)
            or not 0 < memory <= MAX_APP_MEMORY
        ):
            raise ProbeFailed(f"service {service} memory limit is invalid")
        nano_cpus = host.get("NanoCpus")
        if (
            isinstance(nano_cpus, bool)
            or not isinstance(nano_cpus, int)
            or not 0 < nano_cpus <= MAX_APP_NANO_CPUS
        ):
            raise ProbeFailed(f"service {service} CPU limit is invalid")
        if host.get("ReadonlyRootfs") is not False:
            raise ProbeFailed(f"service {service} root filesystem is not writable")
        if str(state.get("Status", "")) != "running":
            raise ProbeFailed(f"service {service} is not running")
        users = _process_users(runner, container_id)
        if not users or any(
            user == "root" or (user.isdigit() and int(user) == 0) for user in users
        ):
            raise ProbeFailed(f"service {service} has root processes")
        networks = _network_names_from_config(values)
        if not networks:
            raise ProbeFailed(f"service {service} has no network")
        topology: dict[str, bool] = {}
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
            is_internal = (
                not internal.returncode
                and internal.stdout.strip().lower() == "true"
            )
            if not is_internal:
                declared = _signed_network_options(signed, network)
                if declared is None or declared.get("internal") is not False:
                    raise ProbeFailed(
                        f"service {service} network {network} is not internal "
                        "and is not authorized for egress"
                    )
            topology[network] = is_internal
        evidence[service] = {
            "user": str(config.get("User")),
            "networks": networks,
            "network_internal": topology,
            "processes": len(users),
            "runtime": "runc",
            "writable_rootfs": True,
            "apparmor": "docker-default",
            "seccomp": "builtin",
            "limits": {"pids": pids, "memory": memory, "nano_cpus": nano_cpus},
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
    try:
        result = runner.run(
            _probe_argv(image, command, network, limits),
            timeout=timeout,
            check=False,
        )
    except AppDeployError as exc:
        raise ProbeFailed("the independent functional probe did not complete") from exc
    output = (result.stdout + result.stderr).encode()
    evidence = {
        "returncode": result.returncode,
        "sha256": hashlib.sha256(output).hexdigest(),
        "bytes": min(len(output), MAX_OUTPUT_BYTES),
    }
    if result.returncode:
        raise ProbeFailed(
            f"the independent functional probe failed (exit {result.returncode})"
        )
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
        if not isinstance(config, dict):
            raise ProbeFailed(
                f"service {service} is missing from the hardened Compose configuration"
            )


def _inspect_stability(
    runner: Runner, containers: Mapping[str, str]
) -> dict[str, Any]:
    restart_counts: dict[str, int] = {}
    for service, container_id in containers.items():
        values = _inspect_container(runner, container_id)
        state = values["state"]
        if str(state.get("Status", "")).lower() != "running":
            raise ProbeFailed(f"service {service} stopped during the probe window")
        health = state.get("Health")
        if isinstance(health, dict):
            status = str(health.get("Status", "")).lower()
            if status != "healthy":
                raise ProbeFailed(
                    f"service {service} is not healthy during the probe window"
                )
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
    target: tuple[str, int] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    one_shot: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    environ = dict(os.environ if environ is None else environ)
    image = probe_image(environ)
    command = probe_command(environ, target)
    checks = _int_env(environ, "SPANEL_APPS_PROBE_CHECKS", 3)
    window = _int_env(environ, "SPANEL_APPS_PROBE_WINDOW_SECONDS", 30)
    timeout = _int_env(environ, "SPANEL_APPS_PROBE_TIMEOUT_SECONDS", 30)
    startup = _int_env(environ, "SPANEL_APPS_PROBE_STARTUP_SECONDS", 180)
    if (
        not 1 <= checks <= 60
        or not 0 <= window <= 3600
        or not 0 <= startup <= 3600
    ):
        raise ProbeFailed("the probe window is invalid")
    completed = set(one_shot)
    active = {
        service: container for service, container in containers.items()
        if service not in completed
    }
    assert_compose_healthchecks(runner, release, compose_rel, project, services)
    isolation = check_isolation(runner, active, release, compose_rel)
    signed = _signed_networks(release, compose_rel)
    service_networks = {
        service: sorted(values["networks"])
        for service, values in isolation.items()
    }
    target_service = target[0] if target else None
    if target_service and service_networks.get(target_service):
        candidates = list(service_networks[target_service])
    else:
        candidates = sorted({
            name for values in service_networks.values() for name in values
        })
    if not candidates:
        raise ProbeFailed("no release network is available for the functional probe")

    def _egress(network: str) -> bool:
        options = _signed_network_options(signed, network)
        return bool(options and options.get("internal") is False)

    internal = [name for name in candidates if not _egress(name)]
    network = sorted(internal or candidates)[0]
    functional: list[dict[str, Any]] = []
    restart_counts: dict[str, int] = {}
    interval = window / checks if checks else 0
    for index in range(checks):
        if index == 0:
            startup_deadline = time.monotonic() + startup
            while True:
                try:
                    functional.append(
                        run_functional_probe(
                            runner,
                            network=network,
                            image=image,
                            command=command,
                            timeout=timeout,
                        )
                    )
                    break
                except ProbeFailed:
                    remaining = startup_deadline - time.monotonic()
                    if remaining <= 0:
                        raise
                    sleep(min(2, remaining))
        else:
            functional.append(
                run_functional_probe(
                    runner,
                    network=network,
                    image=image,
                    command=command,
                    timeout=timeout,
                )
            )
        restart_counts = _inspect_stability(runner, active)
        if index + 1 < checks and interval:
            sleep(interval)
    return {
        "isolation": isolation,
        "network": network,
        "service_networks": service_networks,
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
