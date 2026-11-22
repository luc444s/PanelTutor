"""Independent deployment probes.

The repository healthcheck is a prerequisite, never the proof.  These probes
inspect the effective isolation, execute a disposable functional check from
inside the release network, and watch stability for a bounded window.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .deployment import _compose_command
from .docker_audit import _is_definitely_non_root_user
from .probe_defaults import DEFAULT_PROBE_IMAGE
from .tenant_plan import current_tenant_plan
from .transport import Runner
from .types import AppDeployError

PROBE_USER = "65534:65534"
MAX_OUTPUT_BYTES = 64 * 1024
MAX_APP_PIDS = 256
MAX_APP_MEMORY = 512 * 1024 * 1024
MAX_APP_NANO_CPUS = 1_000_000_000
_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_DIGEST_IMAGE = re.compile(r".+@sha256:[0-9a-f]{64}\Z")

# Isolation checks are split into three explicit groups.  Prohibited
# conditions and mandatory properties hold in every runtime; optional
# properties only hold in the hardened (rootful) baseline.  A rootless cell
# gets its isolation from the tenant's user namespace, not from a non-root
# container user or docker-default AppArmor, so those checks are optional.
PROHIBITED: frozenset[str] = frozenset({
    "privileged", "host_devices", "host_binds", "unsafe_sysctls",
    "port_bindings", "host_pid", "host_network", "rootful_socket",
})
MANDATORY: frozenset[str] = frozenset({
    "no_new_privileges", "seccomp", "runc", "limits", "writable_rootfs",
    "running", "network_topology",
})
OPTIONAL: frozenset[str] = frozenset({
    "non_root_user", "cap_drop_all", "apparmor_docker_default",
    "no_uid0_processes",
})


@dataclass(frozen=True)
class ProbeBaseline:
    """Which optional isolation checks are active for a deployment."""

    name: str
    mandatory: frozenset[str] = MANDATORY
    optional: frozenset[str] = OPTIONAL
    prohibited: frozenset[str] = PROHIBITED


HARDENED_BASELINE = ProbeBaseline("hardened")
ROOTLESS_BASELINE = ProbeBaseline(
    "rootless",
    mandatory=frozenset({*MANDATORY, "user_namespace"}),
    optional=frozenset(),
)


def resolve_baseline(environ: Mapping[str, str]) -> ProbeBaseline:
    """Select the probe baseline; hardened stays the default."""
    value = environ.get("SPANEL_APPS_PROBE_BASELINE", "").strip().lower()
    if value == "rootless":
        return ROOTLESS_BASELINE
    if value and value != "hardened":
        raise ProbeFailed("unknown probe baseline")
    return HARDENED_BASELINE


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


def _signed_compose(
    release_root: Path | None,
    compose_rel: str | None,
) -> dict[str, Any]:
    """Load the signed Compose from either the release root or its source tree."""
    if release_root is None or not compose_rel:
        return {}
    for candidate in (release_root / compose_rel, release_root / "source" / compose_rel):
        try:
            payload = yaml.safe_load(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError):
            continue
        return payload if isinstance(payload, dict) else {}
    return {}


def _override_networks(release_root: Path | None) -> dict[str, dict[str, Any]]:
    """Read the product-generated override's network declarations.

    ``_override`` may add the non-internal ``spanel-ingress`` network used by
    the rootless port driver.  It is product policy, not a change to the
    signed developer Compose, so the isolation probe authorizes it from the
    staged override while the signed service topology stays authoritative.
    """
    if release_root is None:
        return {}
    path = release_root / "override.yaml"
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        return {}
    networks = payload.get("networks") if isinstance(payload, dict) else None
    if not isinstance(networks, dict):
        return {}
    return {
        str(name): (options if isinstance(options, dict) else {})
        for name, options in networks.items()
    }


def _signed_networks(
    release_root: Path | None,
    compose_rel: str | None,
) -> dict[str, dict[str, Any]]:
    """Read the signed Compose network declarations, if available."""
    networks = _signed_compose(release_root, compose_rel).get("networks")
    result = (
        {
            str(name): (options if isinstance(options, dict) else {})
            for name, options in networks.items()
        }
        if isinstance(networks, dict)
        else {}
    )
    for name, options in _override_networks(release_root).items():
        result.setdefault(name, options)
    return result


def _signed_service_networks(
    release_root: Path | None,
    compose_rel: str | None,
    project: str,
) -> dict[str, list[str]]:
    """Map each service to its project-scoped networks in the signed Compose."""
    services = _signed_compose(release_root, compose_rel).get("services")
    if not isinstance(services, dict):
        return {}
    result: dict[str, list[str]] = {}
    for raw_name, raw_config in services.items():
        declared = raw_config.get("networks") if isinstance(raw_config, dict) else None
        if isinstance(declared, list):
            names = [str(item) for item in declared if isinstance(item, str)]
        elif isinstance(declared, dict):
            names = [str(item) for item in declared]
        else:
            names = []
        result[str(raw_name)] = [f"{project}_{name}" for name in names]
    return result


def _signed_network_options(
    signed: Mapping[str, dict[str, Any]],
    network: str,
) -> dict[str, Any] | None:
    for name, options in signed.items():
        if network == name or network.endswith("_" + name):
            return options
    return None


def _rootless_userns(runner: Runner) -> bool:
    """Prove the daemon runs inside a user namespace before relaxing checks.

    ``docker info`` reports ``rootless`` in SecurityOptions when dockerd runs
    through rootlesskit.  UID 0 inside that namespace maps to a non-root host
    subuid, so it is not host root.
    """
    result = runner.run(
        ["docker", "info", "--format", "{{json .SecurityOptions}}"],
        check=False,
    )
    return result.returncode == 0 and "rootless" in result.stdout.lower()


def memory_budget_bytes() -> int:
    """Per-service memory ceiling accepted by the isolation probe.

    Without a tenant plan the historical 512 MiB cap still applies.  With a
    plan bound for the deploy, the tenant *aggregate* is the ceiling: the
    policy in ``tenant_plan.service_limits`` splits that aggregate across the
    services, so a 2 GiB / 3-service plan must be deployable from the first
    attempt instead of being rejected as a 715 MiB "per-service" limit.
    """
    plan = current_tenant_plan()
    if plan is None or plan.memory_bytes <= MAX_APP_MEMORY:
        return MAX_APP_MEMORY
    return plan.memory_bytes


def _loopback_port_bindings(value: Any) -> bool:
    """True only when every host port binds a dedicated loopback address.

    Rootless cells publish their ingress on ``127.x.y.z:20000+`` so the edge
    relay can reach them.  That is not a host-wide publication: 0.0.0.0,
    public IPs and missing host ports remain forbidden.
    """
    if not isinstance(value, Mapping) or not value:
        return False
    for bindings in value.values():
        if not isinstance(bindings, list) or not bindings:
            return False
        for binding in bindings:
            if not isinstance(binding, Mapping):
                return False
            host = str(binding.get("HostIp", "")).strip()
            port = str(binding.get("HostPort", "")).strip()
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                return False
            if not address.is_loopback:
                return False
            if not port.isdigit() or not 1 <= int(port) <= 65535:
                return False
    return True


def _assert_prohibited(
    service: str,
    values: Mapping[str, Any],
    baseline: ProbeBaseline = HARDENED_BASELINE,
) -> None:
    """Conditions that are forbidden in every runtime baseline."""
    host = values["host"]
    if host.get("Privileged") is True:
        raise ProbeFailed(f"service {service} is privileged")
    if host.get("Devices"):
        raise ProbeFailed(f"service {service} accesses host devices")
    if any(
        isinstance(mount, Mapping) and mount.get("Type") == "bind"
        for mount in values["mounts"]
    ):
        raise ProbeFailed(f"service {service} contains a host bind")
    sysctls = host.get("Sysctls") or {}
    if sysctls != {} and sysctls != {
        "net.ipv4.ip_unprivileged_port_start": "0"
    }:
        raise ProbeFailed(f"service {service} contains an unsafe sysctl")
    bindings = host.get("PortBindings")
    if bindings:
        allowed = (
            baseline.name == "rootless"
            and _loopback_port_bindings(bindings)
        )
        if not allowed:
            raise ProbeFailed(f"service {service} publishes host ports")
    if str(host.get("PidMode", "")) == "host":
        raise ProbeFailed(f"service {service} uses the host PID namespace")
    if str(host.get("NetworkMode", "")) in {"host", "container:host"}:
        raise ProbeFailed(f"service {service} uses the host network")


def _assert_mandatory(
    service: str, values: Mapping[str, Any]
) -> tuple[set[str], dict[str, Any]]:
    """Properties required in every runtime; returns options and limits."""
    host, state = values["host"], values["state"]
    options = " ".join(
        str(item).lower().replace(" ", "")
        for item in (host.get("SecurityOpt") or [])
    )
    if "no-new-privileges" not in options:
        raise ProbeFailed(f"service {service} allows privilege escalation")
    if "seccomp=builtin" not in options:
        raise ProbeFailed(f"service {service} does not use the default seccomp profile")
    if host.get("Runtime") != "runc":
        raise ProbeFailed(f"service {service} does not use runc")
    pids = host.get("PidsLimit")
    if isinstance(pids, bool) or not isinstance(pids, int) or not 0 < pids <= MAX_APP_PIDS:
        raise ProbeFailed(f"service {service} PID limit is invalid")
    memory = host.get("Memory")
    budget = memory_budget_bytes()
    if (
        isinstance(memory, bool)
        or not isinstance(memory, int)
        or not 0 < memory <= budget
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
    return options, {"pids": pids, "memory": memory, "nano_cpus": nano_cpus}


def _assert_optional(
    service: str, values: Mapping[str, Any], options: str, baseline: ProbeBaseline
) -> None:
    """Properties that are mandatory only for the hardened baseline."""
    host, config = values["host"], values["config"]
    if "non_root_user" in baseline.optional and not _is_definitely_non_root_user(
        config.get("User")
    ):
        raise ProbeFailed(f"service {service} does not declare a non-root user")
    if "cap_drop_all" in baseline.optional:
        caps = {str(item).upper() for item in (host.get("CapDrop") or [])}
        if "ALL" not in caps:
            raise ProbeFailed(f"service {service} does not drop all capabilities")
    if "apparmor_docker_default" in baseline.optional:
        if "apparmor=docker-default" not in options:
            raise ProbeFailed(
                f"service {service} does not use docker-default AppArmor"
            )
        if values.get("apparmor") != "docker-default":
            raise ProbeFailed(
                f"service {service} effective AppArmor profile is invalid"
            )


def check_isolation(
    runner: Runner,
    containers: Mapping[str, str],
    release_root: Path | None = None,
    compose_rel: str | None = None,
    *,
    baseline: ProbeBaseline = HARDENED_BASELINE,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    signed = _signed_networks(release_root, compose_rel)
    user_namespace = False
    if "user_namespace" in baseline.mandatory:
        if not _rootless_userns(runner):
            raise ProbeFailed("rootless baseline requires a user namespace")
        user_namespace = True
    for service, container_id in containers.items():
        values = _inspect_container(runner, container_id)
        _assert_prohibited(service, values, baseline)
        options, limits = _assert_mandatory(service, values)
        _assert_optional(service, values, options, baseline)
        users = _process_users(runner, container_id)
        # UID 0 in a user namespace is a tenant subuid, never host root.
        if "no_uid0_processes" in baseline.optional and (
            not users
            or any(
                user == "root" or (user.isdigit() and int(user) == 0)
                for user in users
            )
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
            "user": str(values["config"].get("User")),
            "networks": networks,
            "network_internal": topology,
            "processes": len(users),
            "runtime": "runc",
            "writable_rootfs": True,
            "apparmor": str(values.get("apparmor") or ""),
            "seccomp": "builtin",
            "limits": limits,
            "memory_budget_bytes": memory_budget_bytes(),
            "baseline": baseline.name,
            "user_namespace": user_namespace,
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
    *,
    read_only: bool = True,
) -> list[str]:
    pids, memory_mb, cpus = limits
    argv = [
        "docker",
        "run",
        "--rm",
        "--network",
        network,
    ]
    if read_only:
        argv.append("--read-only")
    argv.extend([
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
    ])
    return argv


def run_functional_probe(
    runner: Runner,
    *,
    network: str,
    image: str,
    command: Sequence[str],
    timeout: int,
    limits: tuple[int, int, int] = (64, 128, 1),
    read_only: bool = True,
) -> dict[str, Any]:
    if str(runner.transport) == "ssh":
        raise ProbeFailed("functional probes require a local Docker runner")
    try:
        result = runner.run(
            _probe_argv(
                image, command, network, limits, read_only=read_only
            ),
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
        "read_only": read_only,
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
    baseline: ProbeBaseline | None = None,
) -> dict[str, Any]:
    environ = dict(os.environ if environ is None else environ)
    baseline = baseline if baseline is not None else resolve_baseline(environ)
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
    isolation = check_isolation(
        runner, active, release, compose_rel, baseline=baseline
    )
    signed = _signed_networks(release, compose_rel)
    service_networks = {
        service: sorted(values["networks"])
        for service, values in isolation.items()
    }
    target_service = target[0] if target else None
    candidates: list[str] = []
    if target_service and service_networks.get(target_service):
        candidates = list(service_networks[target_service])
    elif target_service:
        # A scoped deploy may only inspect the services it changed.  The probe
        # target can be outside that set, so fall back to the signed topology.
        candidates = list(
            _signed_service_networks(release, compose_rel, project).get(
                target_service, []
            )
        )
    if not candidates:
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
    # runc implements --read-only with a rootfs remount. The cell AppArmor
    # profile intentionally does not grant remounting `/`; the tenant user
    # namespace is the rootless boundary, while this disposable probe still
    # runs as uid 65534 with no capabilities and no-new-privileges.
    probe_read_only = "user_namespace" not in baseline.mandatory
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
                            read_only=probe_read_only,
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
                    read_only=probe_read_only,
                )
            )
        restart_counts = _inspect_stability(runner, active)
        if index + 1 < checks and interval:
            sleep(interval)
    return {
        "baseline": baseline.name,
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
