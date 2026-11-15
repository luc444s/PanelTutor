"""Compose hardening that establishes the runtime isolation envelope."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

import yaml

from .dockerfile import WritablePath

SECRET_NAME = re.compile(
    r"(?i)(secret|password|passwd|token|api[_-]?key|private[_-]?key|credential)"
)


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


def _environment(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            name: "${" + str(name) + "}"
            if SECRET_NAME.search(str(name))
            and isinstance(content, str)
            and content
            and not content.startswith("${")
            else content
            for name, content in value.items()
        }
    if isinstance(value, list):
        result: list[Any] = []
        for raw in value:
            name, separator, content = str(raw).partition("=")
            if separator and SECRET_NAME.search(name) and content and not content.startswith("${"):
                result.append(f"{name}=${{{name}}}")
            else:
                result.append(raw)
        return result
    return value


def _managed_volume(service: str, path: str) -> str:
    digest = hashlib.sha256(path.encode()).hexdigest()[:10]
    safe = re.sub(r"[^a-z0-9]+", "-", service.lower()).strip("-") or "service"
    return f"spanel-{safe}-{digest}"


def harden_compose(text: str, policies: dict[str, ServicePolicy]) -> str:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ComposeHardeningError("Compose file is invalid YAML") from exc
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict):
        raise ComposeHardeningError("Compose must contain a services mapping")

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
            "sysctls",
            "ulimits",
            "use_api_socket",
            "volumes_from",
        ):
            config.pop(key, None)
        for key in ("network_mode", "pid", "ipc", "uts", "userns", "cgroup"):
            config.pop(key, None)
        config.pop("extra_hosts", None)
        config["user"] = f"{policy.uid}:{policy.gid}"
        config["cap_drop"] = ["ALL"]
        config["security_opt"] = ["no-new-privileges:true"]
        config["read_only"] = True
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

        if "environment" in config:
            config["environment"] = _environment(config["environment"])
        if "env_file" in config:
            config.pop("env_file", None)
            config["x-spanel-external-env"] = True

        kept: list[Any] = []
        for volume in config.get("volumes", []) or []:
            _source, _target, bind = _volume_parts(volume)
            if not bind:
                kept.append(volume)
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
            kept.append(f"{name}:{item.path}")
        if kept:
            config["volumes"] = kept
        else:
            config.pop("volumes", None)

        if config.get("secrets"):
            raise ComposeHardeningError(
                f"service {service} uses Compose secrets; migrate them to the managed external env interface"
            )

    networks = data.get("networks")
    if not isinstance(networks, dict):
        networks = {}
    networks.setdefault("default", {})
    for config in networks.values():
        if not isinstance(config, dict):
            raise ComposeHardeningError("network configuration must be a mapping")
        config.pop("external", None)
        config.pop("name", None)
        config["internal"] = True
    data["networks"] = networks

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
