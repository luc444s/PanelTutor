"""Named-volume discovery and fail-closed runtime user resolution."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from ..hardening.contracts import (
    HardeningPolicy,
    RuntimeUserEvidence,
    RuntimeUserPolicy,
    RuntimeVolumePolicy,
)
from .probe_defaults import DEFAULT_PROBE_IMAGE
from .transport import Runner
from .types import OWNER_LABEL, AppDeployError

_VOLUME_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z")
_OWNER = re.compile(r"([0-9]{1,10}):([0-9]{1,10})\Z")
_PROBE_IMAGE = re.compile(r".+@sha256:[0-9a-f]{64}\Z")
_HELPER_USER = "65534:65534"


def _probe_image(runner: Runner) -> str:
    image = runner.environ.get("SPANEL_APPS_PROBE_IMAGE", "").strip()
    image = image or DEFAULT_PROBE_IMAGE
    if not _PROBE_IMAGE.fullmatch(image):
        raise AppDeployError("a digest-pinned probe image is required")
    return image


def _is_bind_source(source: str) -> bool:
    return source.startswith(("/", "./", "../", "~")) or re.match(
        r"[A-Za-z]:[\\/]", source
    ) is not None


def _volume_definition(data: Mapping[str, Any], key: str, project: str) -> tuple[str, bool]:
    definitions = data.get("volumes")
    definitions = definitions if isinstance(definitions, Mapping) else {}
    raw = definitions.get(key, {})
    config = raw if isinstance(raw, Mapping) else {}
    external_raw = config.get("external", False)
    external = external_raw is True or isinstance(external_raw, Mapping)
    explicit = config.get("name")
    if explicit is None and isinstance(external_raw, Mapping):
        explicit = external_raw.get("name")
    name = str(explicit) if explicit is not None else (key if external else f"{project}_{key}")
    if not _VOLUME_NAME.fullmatch(name):
        raise AppDeployError(f"volume name for {key} is invalid")
    return name, external


def _service_mounts(
    data: Mapping[str, Any], project: str
) -> tuple[dict[str, set[str]], dict[str, bool], dict[tuple[str, str], bool]]:
    by_volume: dict[str, set[str]] = defaultdict(set)
    external: dict[str, bool] = {}
    read_only: dict[tuple[str, str], bool] = {}
    services = data.get("services")
    services = services if isinstance(services, Mapping) else {}
    for service in sorted(services):
        config = services[service]
        config = config if isinstance(config, Mapping) else {}
        mounts = config.get("volumes")
        mounts = mounts if isinstance(mounts, Sequence) and not isinstance(mounts, str) else ()
        for mount in mounts:
            key: str | None = None
            readonly = False
            if isinstance(mount, str):
                parts = mount.split(":")
                if len(parts) < 2 or _is_bind_source(parts[0]):
                    continue
                key = parts[0]
                readonly = len(parts) > 2 and "ro" in parts[-1].split(",")
            elif isinstance(mount, Mapping):
                source = mount.get("source")
                mount_type = mount.get("type")
                if not isinstance(source, str) or not source:
                    continue
                if mount_type == "bind" or (mount_type is None and _is_bind_source(source)):
                    continue
                if mount_type not in {None, "volume"}:
                    continue
                key = source
                readonly = bool(mount.get("read_only"))
            if key is None:
                continue
            name, is_external = _volume_definition(data, key, project)
            by_volume[name].add(str(service))
            external[name] = is_external
            read_only[(str(service), name)] = readonly
    return dict(by_volume), external, read_only


def _volume_exists(runner: Runner, name: str) -> bool:
    inspected = runner.run(["docker", "volume", "inspect", name], check=False)
    if inspected.returncode not in {0, 1}:
        raise AppDeployError(f"volume {name} could not be inspected")
    return inspected.returncode == 0


def _helper_command(
    image: str,
    name: str,
    user: str,
    entrypoint: str,
    *command: str,
    cap_chown: bool = False,
) -> list[str]:
    argv = [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--user", user, "-v", f"{name}:/volume",
    ]
    if cap_chown:
        argv.extend(("--cap-add", "CHOWN"))
    return [*argv, "--entrypoint", entrypoint, image, *command]


def _volume_owner(runner: Runner, name: str, services: Sequence[str] = ()) -> str:
    result = runner.run(
        _helper_command(
            _probe_image(runner), name, _HELPER_USER, "stat", "-c", "%u:%g", "/volume",
        ),
        check=False,
    )
    owner = result.stdout.strip()
    match = _OWNER.fullmatch(owner)
    if result.returncode or match is None:
        raise AppDeployError(f"volume {name} owner could not be read")
    if int(match.group(1)) == 0:
        affected = ", ".join(sorted(services)) or "service"
        raise AppDeployError(
            f"volume {name} is owned by root; refusing to run {affected} as root"
        )
    if int(match.group(2)) == 0:
        raise AppDeployError(f"volume {name} has a root group; refusing to use it")
    return f"{int(match.group(1))}:{int(match.group(2))}"


def _verify_readable(runner: Runner, name: str, user: str, service: str) -> None:
    result = runner.run(
        _helper_command(
            _probe_image(runner), name, user, "sh", "-c", "test -r /volume",
        ),
        check=False,
    )
    if result.returncode:
        raise AppDeployError(f"volume {name} is not readable by service {service}")


def resolve_runtime_volumes(
    runner: Runner,
    data: Mapping[str, Any],
    project: str,
    policy: HardeningPolicy,
) -> HardeningPolicy:
    """Resolve effective users without creating or modifying any volume."""
    mounts, external, read_only = _service_mounts(data, project)
    requested = {
        item.service: f"{item.uid}:{item.gid}" for item in policy.service_users
    }
    base_evidence = {item.service: item for item in policy.runtime_users}
    owners: dict[str, str | None] = {}
    for name in sorted(mounts):
        exists = _volume_exists(runner, name)
        if not exists and external[name]:
            raise AppDeployError(f"external volume {name} does not exist")
        owners[name] = _volume_owner(runner, name, tuple(mounts[name])) if exists else None
        if owners[name] is None:
            desired = {requested[service] for service in mounts[name]}
            if len(desired) != 1:
                services = ", ".join(sorted(mounts[name]))
                raise AppDeployError(
                    f"volume {name} is shared by services with different users: {services}"
                )

    service_volumes: dict[str, list[str]] = defaultdict(list)
    for name, services in mounts.items():
        for service in services:
            service_volumes[service].append(name)
    effective = dict(requested)
    for service in sorted(requested):
        existing = {
            owners[name] for name in service_volumes.get(service, ()) if owners[name]
        }
        if len(existing) > 1:
            raise AppDeployError(
                f"service {service} mounts volumes with incompatible owners"
            )
        if existing:
            effective[service] = next(iter(existing))  # type: ignore[arg-type]

    evidence: list[RuntimeUserEvidence] = []
    users: list[RuntimeUserPolicy] = []
    for service in sorted(requested):
        uid, gid = (int(item) for item in effective[service].split(":"))
        users.append(RuntimeUserPolicy(service, uid, gid))
        volumes = sorted(service_volumes.get(service, ()))
        owner_volume = next((name for name in volumes if owners[name]), None)
        original = base_evidence.get(service)
        source = original.source if original is not None else "policy"
        if effective[service] != requested[service]:
            source = "volume-owner"
        evidence.append(RuntimeUserEvidence(
            service,
            requested[service],
            effective[service],
            source,
            owner_volume or (volumes[0] if volumes else None),
        ))
        for name in volumes:
            if owners[name] and read_only.get((service, name)):
                _verify_readable(runner, name, effective[service], service)

    volume_policy = []
    for name in sorted(mounts):
        users_for_volume = {effective[service] for service in mounts[name]}
        if len(users_for_volume) != 1:
            raise AppDeployError(f"volume {name} has incompatible effective users")
        volume_policy.append(RuntimeVolumePolicy(
            name,
            tuple(mounts[name]),
            next(iter(users_for_volume)),
            initialize=owners[name] is None,
            external=external[name],
        ))
    return replace(
        policy,
        service_users=tuple(users),
        runtime_users=tuple(evidence),
        runtime_volumes=tuple(volume_policy),
    )


def prepare_runtime_volumes(
    runner: Runner,
    project: str,
    policy: HardeningPolicy,
    services: Sequence[str],
) -> None:
    """Create and initialize only volumes declared new by the signed policy."""
    selected = set(services)
    image = _probe_image(runner)
    for volume in policy.runtime_volumes:
        if not selected.intersection(volume.services):
            continue
        if not volume.initialize:
            if not _volume_exists(runner, volume.name):
                raise AppDeployError(f"volume {volume.name} no longer exists")
            if _volume_owner(runner, volume.name, volume.services) != volume.user:
                raise AppDeployError(f"volume {volume.name} owner changed after signing")
            continue
        if volume.external:
            raise AppDeployError(f"external volume {volume.name} cannot be initialized")
        if _volume_exists(runner, volume.name):
            if _volume_owner(runner, volume.name, volume.services) != volume.user:
                raise AppDeployError(
                    f"volume {volume.name} appeared with an incompatible owner"
                )
            continue
        created = runner.run([
            "docker", "volume", "create", "--label", f"{OWNER_LABEL}={project}",
            volume.name,
        ], check=False)
        if created.returncode:
            raise AppDeployError(f"volume {volume.name} could not be created")
        empty = runner.run(
            _helper_command(
                image, volume.name, _HELPER_USER,
                "sh", "-c", 'test -z "$(ls -A /volume)"',
            ),
            check=False,
        )
        if empty.returncode:
            raise AppDeployError(f"new volume {volume.name} is not empty")
        initialized = runner.run(
            _helper_command(
                image, volume.name, _HELPER_USER, "chown",
                volume.user, "/volume", cap_chown=True,
            ),
            check=False,
        )
        if (
            initialized.returncode
            or _volume_owner(runner, volume.name, volume.services) != volume.user
        ):
            raise AppDeployError(f"volume {volume.name} could not be initialized")
