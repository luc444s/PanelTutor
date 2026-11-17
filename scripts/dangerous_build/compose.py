"""Compose hardening that establishes the runtime isolation envelope."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .dockerfile import WritablePath


class ComposeHardeningError(ValueError):
    """Compose cannot be hardened without an explicit operator decision."""


@dataclass(frozen=True)
class ServicePolicy:
    uid: int
    gid: int
    writable_paths: tuple[WritablePath, ...] = ()


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
    raise ComposeHardeningError("unsupported volume entry")


def _container_port(value: Any) -> str | None:
    if isinstance(value, int):
        return str(value)
    if isinstance(value, dict):
        target = value.get("target")
        return str(target) if target else None
    text = str(value).split("/", 1)[0]
    target = text.rsplit(":", 1)[-1]
    return target if target.isdigit() else None


def _managed_volume(service: str, path: str) -> str:
    digest = hashlib.sha256(path.encode()).hexdigest()[:10]
    safe = re.sub(r"[^a-z0-9]+", "-", service.lower()).strip("-") or "service"
    return f"spanel-{safe}-{digest}"


_NETWORK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


def _hardened_networks(
    data: dict[str, Any],
    authorized_external: frozenset[str],
    egress: frozenset[str],
) -> dict[str, dict[str, Any]]:
    """Preserve declared networks, applying the explicit network policy."""
    declared = data.get("networks")
    if declared is None:
        declared = {}
    if not isinstance(declared, dict):
        raise ComposeHardeningError("Compose networks must be a mapping")
    names = {str(name) for name in declared}
    unknown = sorted((authorized_external | egress) - names)
    if unknown:
        raise ComposeHardeningError(
            "network policy references undeclared networks: " + ", ".join(unknown)
        )
    if not declared:
        return {"default": {"internal": True}}
    result: dict[str, dict[str, Any]] = {}
    for raw_name, raw_options in declared.items():
        name = str(raw_name)
        if _NETWORK_NAME.fullmatch(name) is None:
            raise ComposeHardeningError(f"invalid network name: {name}")
        options = dict(raw_options) if isinstance(raw_options, dict) else {}
        external = bool(options.get("external"))
        if external and name not in authorized_external:
            raise ComposeHardeningError(f"external network {name} is not authorized")
        if options.get("name") and not (external and name in authorized_external):
            raise ComposeHardeningError(f"network {name} declares a fixed name")
        if str(options.get("driver", "")).lower() == "host":
            raise ComposeHardeningError(f"network {name} uses the host driver")
        if external:
            if "internal" in options:
                raise ComposeHardeningError(
                    f"external network {name} cannot declare internal"
                )
        else:
            value = options.get("internal", True)
            if value not in (True, False):
                raise ComposeHardeningError(f"network {name} internal must be boolean")
            if value is False and name not in egress:
                raise ComposeHardeningError(
                    f"network {name} allows egress but is not authorized"
                )
            options["internal"] = value
        result[name] = options
    return result


def _hardened_service_networks(
    config: dict[str, Any],
    aliases: list[str],
    declared: dict[str, dict[str, Any]],
    service: str,
) -> dict[str, dict[str, Any]] | None:
    """Keep every declared attachment and merge the normalized aliases."""
    raw = config.get("networks")
    if raw is None:
        return {"default": {"aliases": list(aliases)}} if aliases else None
    if isinstance(raw, str):
        raw = [raw]
    if isinstance(raw, (list, dict)) and not raw:
        return raw  # type: ignore[return-value]
    if isinstance(raw, list):
        if not all(isinstance(item, str) for item in raw):
            raise ComposeHardeningError(f"service {service} has an invalid network list")
        targets: dict[str, dict[str, Any]] = {str(item): {} for item in raw}
    elif isinstance(raw, dict):
        targets = {}
        for raw_name, raw_options in raw.items():
            name = str(raw_name)
            if isinstance(raw_options, dict):
                targets[name] = dict(raw_options)
            elif raw_options is None:
                targets[name] = {}
            else:
                raise ComposeHardeningError(
                    f"service {service} network {name} is not a mapping"
                )
    else:
        raise ComposeHardeningError(f"service {service} has invalid networks")
    for name, options in targets.items():
        if name not in declared:
            raise ComposeHardeningError(
                f"service {service} references undeclared network {name}"
            )
        current = options.get("aliases")
        if current is None:
            aliases_for_network: list[str] = []
        elif isinstance(current, str):
            aliases_for_network = [current]
        elif isinstance(current, list) and all(isinstance(item, str) for item in current):
            aliases_for_network = list(current)
        else:
            raise ComposeHardeningError(
                f"service {service} network {name} has invalid aliases"
            )
        for alias in aliases:
            if alias not in aliases_for_network:
                aliases_for_network.append(alias)
        if aliases_for_network:
            options["aliases"] = aliases_for_network
    return targets


def harden_compose(
    text: str,
    policies: dict[str, ServicePolicy],
    checkout_root: Path | None = None,
    compose_file: str | Path | None = None,
    *,
    authorized_external_networks: frozenset[str] = frozenset(),
    egress_networks: frozenset[str] = frozenset(),
) -> str:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ComposeHardeningError("Compose file is invalid YAML") from exc
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict):
        raise ComposeHardeningError("Compose must contain a services mapping")

    hardened_networks = _hardened_networks(
        data, authorized_external_networks, egress_networks
    )
    generated_volumes: dict[str, dict[str, Any]] = {}
    for service, config in data["services"].items():
        if not isinstance(config, dict):
            raise ComposeHardeningError(f"service {service} is not a mapping")
        policy = policies.get(str(service))
        if policy is None:
            raise ComposeHardeningError(f"service {service} needs an explicit runtime user")

        published = config.pop("ports", []) or []
        exposed = {str(item) for item in config.get("expose", []) or []}
        exposed.update(filter(None, (_container_port(item) for item in published)))
        if exposed:
            config["expose"] = sorted(exposed)

        normalized_sysctl = config.get("sysctls") == {
            "net.ipv4.ip_unprivileged_port_start": "0"
        }
        normalized_aliases = config.pop("x-spanel-normalized-aliases", None)
        normalized_aliases = (
            sorted(set(normalized_aliases))
            if isinstance(normalized_aliases, list)
            and all(isinstance(item, str) for item in normalized_aliases)
            else []
        )
        readonly_files = config.pop("x-spanel-readonly-files", None)
        readonly_files = (
            readonly_files
            if isinstance(readonly_files, list)
            and all(
                isinstance(item, dict)
                and set(item) == {"source", "target"}
                and all(isinstance(value, str) for value in item.values())
                for item in readonly_files
            )
            else []
        )
        for key in (
            "privileged",
            "cap_add",
            "devices",
            "container_name",
            "device_cgroup_rules",
            "credential_spec",
            "external_links",
            "group_add",
            "dns",
            "dns_search",
            "dns_opt",
            "storage_opt",
            "ulimits",
            "use_api_socket",
            "volumes_from",
        ):
            config.pop(key, None)
        if config.get("network_mode") is not None:
            raise ComposeHardeningError(
                f"service {service} uses network_mode {config['network_mode']!r}; "
                "network_mode is not permitted"
            )
        for key in ("pid", "ipc", "uts", "userns", "cgroup"):
            config.pop(key, None)
        config.pop("extra_hosts", None)
        config.pop("deploy", None)
        service_networks = _hardened_service_networks(
            config, normalized_aliases, hardened_networks, str(service)
        )
        if service_networks is None:
            config.pop("networks", None)
        else:
            config["networks"] = service_networks
        if readonly_files:
            config["x-spanel-readonly-files"] = readonly_files
        if normalized_sysctl:
            config["sysctls"] = {
                "net.ipv4.ip_unprivileged_port_start": "0"
            }
        else:
            config.pop("sysctls", None)
        config["user"] = f"{policy.uid}:{policy.gid}"
        config["cap_drop"] = ["ALL"]
        config["security_opt"] = [
            "no-new-privileges:true",
            "apparmor=docker-default",
            "seccomp=builtin",
        ]
        config["runtime"] = "runc"
        config["read_only"] = False
        tmpfs = ["/tmp:rw,noexec,nosuid,nodev"]
        config["tmpfs"] = tmpfs
        config["init"] = True
        config["pids_limit"] = 256
        config["mem_limit"] = "512m"
        config["cpus"] = 1.0
        config["shm_size"] = "64m"
        build = config.get("build")
        if isinstance(build, dict):
            for key in ("network", "entitlements", "privileged", "ssh", "secrets"):
                build.pop(key, None)

        if "env_file" in config:
            config.pop("env_file", None)
            config["x-spanel-external-env"] = True

        kept: list[Any] = []
        for volume in config.get("volumes", []) or []:
            source, target, bind = _volume_parts(volume)
            if bind:
                continue
            if not source:
                name = _managed_volume(str(service), target)
                generated_volumes[name] = {}
                kept.append({
                    "type": "volume",
                    "source": name,
                    "target": target,
                })
                continue
            # The platform owns these volumes: it creates them with the signed
            # non-root user and a 0700 mode.  Docker copies the image mountpoint
            # metadata over the volume root on first use, which would replace
            # that ownership (and break non-root initdb).  Disable the copy-up.
            entry = dict(volume) if isinstance(volume, dict) else {}
            entry["type"] = "volume"
            entry["source"] = source
            entry["target"] = target
            options = entry.get("volume")
            options = dict(options) if isinstance(options, dict) else {}
            options["nocopy"] = True
            entry["volume"] = options
            kept.append(entry)
        for item in policy.writable_paths:
            if item.path == "/tmp":
                continue
            if item.path.startswith(("/run/", "/var/run/")):
                tmpfs.append(
                    f"{item.path}:rw,noexec,nosuid,nodev,"
                    f"mode={item.mode},uid={policy.uid},gid={policy.gid}"
                )
                continue
            name = _managed_volume(str(service), item.path)
            generated_volumes[name] = {}
            kept.append({
                "type": "volume",
                "source": name,
                "target": item.path,
                "volume": {"nocopy": True},
            })
        if kept:
            config["volumes"] = kept
        else:
            config.pop("volumes", None)

        if config.get("secrets"):
            raise ComposeHardeningError(
                f"service {service} uses Compose secrets; migrate them to the managed external env interface"
            )

    data["networks"] = hardened_networks

    volumes = data.get("volumes")
    if not isinstance(volumes, dict):
        volumes = {}
    for config in volumes.values():
        if isinstance(config, dict):
            config.pop("external", None)
            config.pop("name", None)
    volumes.update(generated_volumes)
    if volumes:
        data["volumes"] = volumes
    data.pop("secrets", None)
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
