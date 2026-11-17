"""Validated, immutable admission-policy contracts for signed releases.

``service_users``, ``writable_paths``, ``runtime_users`` and ``runtime_volumes``
are retained so releases signed before the invasive hardener was retired can
still be verified and rolled back.  New releases no longer apply them: the
only policy still enforced here is the host-resource authorization carried by
``authorized_external_networks`` and ``egress_networks``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

_SERVICE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_NETWORK_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_MAX_SERVICES = 64
_MAX_WRITABLE_PATHS = 256
_RUNTIME_USER = re.compile(r"([1-9][0-9]{0,9})(?::([0-9]{1,10}))?\Z")


class HardeningRejected(RuntimeError):
    """Safe, bounded failure that never embeds hardener output."""


def _service_name(value: object) -> str:
    if not isinstance(value, str) or not _SERVICE.fullmatch(value):
        raise ValueError("service is invalid")
    return value


@dataclass(frozen=True, slots=True)
class RuntimeUserPolicy:
    service: str
    uid: int
    gid: int

    def __post_init__(self) -> None:
        _service_name(self.service)
        if (
            isinstance(self.uid, bool)
            or not isinstance(self.uid, int)
            or not 0 < self.uid <= 2**31 - 1
        ):
            raise ValueError("uid must be a positive non-root integer")
        if (
            isinstance(self.gid, bool)
            or not isinstance(self.gid, int)
            or not 0 <= self.gid <= 2**31 - 1
        ):
            raise ValueError("gid must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class RuntimeUserEvidence:
    service: str
    requested: str
    effective: str
    source: str
    volume: str | None = None

    def __post_init__(self) -> None:
        _service_name(self.service)
        if not _RUNTIME_USER.fullmatch(self.requested):
            raise ValueError("requested runtime user is invalid")
        if not _RUNTIME_USER.fullmatch(self.effective):
            raise ValueError("effective runtime user is invalid")
        if self.source not in {"policy", "compose", "dockerfile", "volume-owner"}:
            raise ValueError("runtime user source is invalid")
        if self.volume is not None and (
            not self.volume or len(self.volume) > 255 or "\n" in self.volume
        ):
            raise ValueError("runtime user volume is invalid")


@dataclass(frozen=True, slots=True)
class RuntimeVolumePolicy:
    name: str
    services: tuple[str, ...]
    user: str
    initialize: bool = False
    external: bool = False

    def __post_init__(self) -> None:
        if not self.name or len(self.name) > 255 or "\n" in self.name:
            raise ValueError("runtime volume name is invalid")
        services = tuple(sorted(self.services))
        object.__setattr__(self, "services", services)
        if not services or any(_service_name(item) != item for item in services):
            raise ValueError("runtime volume services are invalid")
        if len(services) != len(set(services)):
            raise ValueError("runtime volume services contain duplicates")
        if not _RUNTIME_USER.fullmatch(self.user):
            raise ValueError("runtime volume user is invalid")
        if self.external and self.initialize:
            raise ValueError("external runtime volume cannot be initialized")


@dataclass(frozen=True, slots=True)
class WritablePathPolicy:
    service: str
    path: str
    mode: str = "0750"

    def __post_init__(self) -> None:
        _service_name(self.service)
        if not isinstance(self.path, str) or len(self.path) > 1024 or not self.path.startswith("/"):
            raise ValueError("writable path must be absolute")
        path = PurePosixPath(self.path)
        if ".." in path.parts or self.path != path.as_posix() or self.path == "/":
            raise ValueError("writable path must be normalized without traversal")
        if not isinstance(self.mode, str) or not re.fullmatch(r"0[0-7]{3}", self.mode):
            raise ValueError("writable path mode is invalid")
        numeric = int(self.mode, 8)
        if numeric == 0 or numeric & 0o002:
            raise ValueError("writable path mode cannot be empty or world-writable")


@dataclass(frozen=True, slots=True)
class HardeningPolicy:
    service_users: tuple[RuntimeUserPolicy, ...]
    writable_paths: tuple[WritablePathPolicy, ...] = ()
    runtime_users: tuple[RuntimeUserEvidence, ...] = ()
    runtime_volumes: tuple[RuntimeVolumePolicy, ...] = ()
    authorized_external_networks: tuple[str, ...] = ()
    egress_networks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        users = tuple(self.service_users)
        paths = tuple(self.writable_paths)
        runtime_users = tuple(self.runtime_users)
        runtime_volumes = tuple(self.runtime_volumes)
        authorized_external = tuple(self.authorized_external_networks)
        egress = tuple(self.egress_networks)
        object.__setattr__(self, "service_users", users)
        object.__setattr__(self, "writable_paths", paths)
        object.__setattr__(self, "runtime_users", runtime_users)
        object.__setattr__(self, "runtime_volumes", runtime_volumes)
        object.__setattr__(self, "authorized_external_networks", authorized_external)
        object.__setattr__(self, "egress_networks", egress)
        for names in (authorized_external, egress):
            if any(not _NETWORK_KEY.fullmatch(name) for name in names):
                raise ValueError("network policy contains an invalid network name")
            if len(names) != len(set(names)):
                raise ValueError("network policy contains duplicate networks")
        if len(users) > _MAX_SERVICES:
            raise ValueError("hardening policy allows at most 64 services")
        if len(paths) > _MAX_WRITABLE_PATHS:
            raise ValueError("hardening policy has too many writable paths")
        names = [item.service for item in users]
        if len(names) != len(set(names)):
            raise ValueError("hardening policy contains duplicate services")
        declared = set(names)
        if any(item.service not in declared for item in paths):
            raise ValueError("writable path references an undeclared service")
        evidence_names = [item.service for item in runtime_users]
        if evidence_names and set(evidence_names) != declared:
            raise ValueError("runtime user evidence must cover every declared service")
        if len(evidence_names) != len(set(evidence_names)):
            raise ValueError("runtime user evidence contains duplicate services")
        if any(
            service not in declared
            for volume in runtime_volumes
            for service in volume.services
        ):
            raise ValueError("runtime volume references an undeclared service")
        volume_names = [item.name for item in runtime_volumes]
        if len(volume_names) != len(set(volume_names)):
            raise ValueError("runtime volume policy contains duplicate volumes")

    @classmethod
    def from_dict(cls, value: object) -> HardeningPolicy:
        if not isinstance(value, Mapping) or not set(value).issubset({
            "service_users", "writable_paths", "runtime_users", "runtime_volumes",
            "authorized_external_networks", "egress_networks",
        }):
            raise ValueError("hardening policy is invalid")
        # A release signed after the hardener was retired may carry only the
        # host-resource authorization fields (or no policy fields at all).
        raw_users = value.get("service_users", {})
        raw_paths = value.get("writable_paths", [])
        if not isinstance(raw_users, Mapping) or not isinstance(raw_paths, list):
            raise ValueError("hardening policy is invalid")
        users = []
        for service, user in raw_users.items():
            if not isinstance(user, Mapping) or set(user) != {"uid", "gid"}:
                raise ValueError("runtime user policy is invalid")
            users.append(RuntimeUserPolicy(str(service), user["uid"], user["gid"]))
        paths = []
        for item in raw_paths:
            if not isinstance(item, Mapping) or set(item) != {"service", "path", "mode"}:
                raise ValueError("writable path policy is invalid")
            paths.append(WritablePathPolicy(item["service"], item["path"], item["mode"]))
        evidence = []
        raw_evidence = value.get("runtime_users", {})
        if not isinstance(raw_evidence, Mapping):
            raise ValueError("runtime user evidence is invalid")
        for service, item in raw_evidence.items():
            if not isinstance(item, Mapping) or not set(item).issubset({
                "requested", "effective", "source", "volume"
            }) or not {"requested", "effective", "source"}.issubset(item):
                raise ValueError("runtime user evidence is invalid")
            evidence.append(RuntimeUserEvidence(
                str(service), item["requested"], item["effective"], item["source"],
                item.get("volume"),
            ))
        volumes = []
        raw_volumes = value.get("runtime_volumes", [])
        if not isinstance(raw_volumes, list):
            raise ValueError("runtime volume policy is invalid")
        for item in raw_volumes:
            if not isinstance(item, Mapping) or set(item) != {
                "name", "services", "user", "initialize", "external"
            } or not isinstance(item["services"], list):
                raise ValueError("runtime volume policy is invalid")
            volumes.append(RuntimeVolumePolicy(
                item["name"], tuple(item["services"]), item["user"],
                item["initialize"], item["external"],
            ))
        external = value.get("authorized_external_networks", [])
        egress = value.get("egress_networks", [])
        if not isinstance(external, list) or not isinstance(egress, list):
            raise ValueError("network policy is invalid")
        if any(not isinstance(name, str) for name in (*external, *egress)):
            raise ValueError("network policy is invalid")
        return cls(
            tuple(users), tuple(paths), tuple(evidence), tuple(volumes),
            tuple(external), tuple(egress),
        )

    def as_dict(self) -> dict[str, Any]:
        result = {
            "service_users": {
                item.service: {"uid": item.uid, "gid": item.gid}
                for item in self.service_users
            },
            "writable_paths": [
                {"service": item.service, "path": item.path, "mode": item.mode}
                for item in self.writable_paths
            ],
        }
        if self.runtime_users:
            result["runtime_users"] = {
                item.service: {
                    "requested": item.requested,
                    "effective": item.effective,
                    "source": item.source,
                    **({"volume": item.volume} if item.volume is not None else {}),
                }
                for item in self.runtime_users
            }
        if self.runtime_volumes:
            result["runtime_volumes"] = [
                {
                    "name": item.name,
                    "services": list(item.services),
                    "user": item.user,
                    "initialize": item.initialize,
                    "external": item.external,
                }
                for item in self.runtime_volumes
            ]
        if self.authorized_external_networks:
            result["authorized_external_networks"] = list(
                self.authorized_external_networks
            )
        if self.egress_networks:
            result["egress_networks"] = list(self.egress_networks)
        return result


def automatic_hardening_policy(
    services: object,
    dockerfile_users: Mapping[str, str | None] | None = None,
    dockerfile_images: Mapping[str, tuple[str, ...]] | None = None,
) -> HardeningPolicy:
    """Record only users the application itself declares.

    Explicit Compose ``user:`` declarations win, then the final ``USER``
    instruction of the Dockerfile.  When neither is numeric the service is
    omitted: PanelTutor no longer invents a non-root identity for it.  For
    images without a declared user the image's own ``USER`` is respected at
    runtime and the non-root admission check rejects it if it is root.
    """
    if not isinstance(services, Mapping):
        raise ValueError("inspected services are invalid")
    dockerfile_users = dockerfile_users or {}
    dockerfile_images = dockerfile_images or {}
    users = []
    evidence = []
    for service in sorted(services):
        name = _service_name(service)
        config = services[service]
        config = config if isinstance(config, Mapping) else {}
        resolved = _declared_runtime_user(
            config.get("user"), dockerfile_users.get(name)
        )
        if resolved is None:
            continue
        uid, gid, source = resolved
        users.append(RuntimeUserPolicy(name, uid, gid))
        value = f"{uid}:{gid}"
        evidence.append(RuntimeUserEvidence(name, value, value, source))
    return HardeningPolicy(
        tuple(users),
        _automatic_writable_paths(services, dockerfile_images),
        runtime_users=tuple(evidence),
    )


def _declared_runtime_user(
    compose_user: object, dockerfile_user: str | None
) -> tuple[int, int, str] | None:
    for value, source in ((compose_user, "compose"), (dockerfile_user, "dockerfile")):
        match = _RUNTIME_USER.fullmatch(str(value or ""))
        if not match:
            continue
        uid = int(match.group(1))
        gid = int(match.group(2) or match.group(1))
        if 0 < uid <= 2**31 - 1 and 0 <= gid <= 2**31 - 1:
            return uid, gid, source
    return None


def resolve_hardening_policy(
    policy: HardeningPolicy,
    services: object,
    dockerfile_users: Mapping[str, str | None] | None = None,
    dockerfile_images: Mapping[str, tuple[str, ...]] | None = None,
) -> HardeningPolicy:
    """Fill omitted services from the checkout while keeping explicit values."""
    if not isinstance(services, Mapping):
        raise ValueError("inspected services are invalid")
    dockerfile_users = dockerfile_users or {}
    dockerfile_images = dockerfile_images or {}
    declared = {item.service: (item.uid, item.gid) for item in policy.service_users}
    sources = {item.service: "policy" for item in policy.service_users}
    unknown = sorted(set(declared).difference(services))
    if unknown:
        raise ValueError(
            "runtime user references unknown service: " + ", ".join(unknown)
        )
    for service in sorted(services):
        if service in declared:
            continue
        config = services[service]
        config = config if isinstance(config, Mapping) else {}
        resolved = _declared_runtime_user(
            config.get("user"), dockerfile_users.get(service)
        )
        if resolved is None:
            # No invented identity: the image's own USER is respected.
            continue
        uid, gid, source = resolved
        declared[service] = (uid, gid)
        sources[service] = source
    return HardeningPolicy(
        tuple(
            RuntimeUserPolicy(service, uid, gid)
            for service, (uid, gid) in sorted(declared.items())
        ),
        _merge_writable_paths(
            policy.writable_paths,
            _automatic_writable_paths(services, dockerfile_images),
        ),
        tuple(
            RuntimeUserEvidence(
                service, f"{uid}:{gid}", f"{uid}:{gid}", sources[service]
            )
            for service, (uid, gid) in sorted(declared.items())
        ),
    )


def _image_repository(value: object) -> str:
    image = str(value or "").strip().lower()
    image = image.split("@", 1)[0]
    name = image.rsplit("/", 1)[-1]
    return name.split(":", 1)[0]


def _automatic_writable_paths(
    services: Mapping[object, object],
    dockerfile_images: Mapping[str, tuple[str, ...]],
) -> tuple[WritablePathPolicy, ...]:
    paths: list[WritablePathPolicy] = []
    for raw_service in sorted(services, key=str):
        service = str(raw_service)
        config = services[raw_service]
        config = config if isinstance(config, Mapping) else {}
        images = (config.get("image"), *dockerfile_images.get(service, ()))
        repositories = {_image_repository(image) for image in images}
        if "postgres" in repositories:
            paths.append(
                WritablePathPolicy(service, "/var/run/postgresql", "0775")
            )
        if repositories.intersection({"mariadb", "mysql"}):
            paths.append(WritablePathPolicy(service, "/run/mysqld", "0775"))
    return tuple(paths)


def _merge_writable_paths(
    explicit: tuple[WritablePathPolicy, ...],
    automatic: tuple[WritablePathPolicy, ...],
) -> tuple[WritablePathPolicy, ...]:
    result = {(item.service, item.path): item for item in automatic}
    result.update({(item.service, item.path): item for item in explicit})
    return tuple(result[key] for key in sorted(result))
