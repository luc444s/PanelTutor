"""Validated, immutable contracts for application hardening."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any

_SERVICE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_SERVICES = 64
_MAX_WRITABLE_PATHS = 256
_RUNTIME_USER = re.compile(r"([1-9][0-9]{0,9})(?::([1-9][0-9]{0,9}))?\Z")
_DEFAULT_RUNTIME_ID = 1000


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
        for name, value in (("uid", self.uid), ("gid", self.gid)):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 2**31 - 1:
                raise ValueError(f"{name} must be a positive non-root integer")


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

    def __post_init__(self) -> None:
        users = tuple(self.service_users)
        paths = tuple(self.writable_paths)
        runtime_users = tuple(self.runtime_users)
        runtime_volumes = tuple(self.runtime_volumes)
        object.__setattr__(self, "service_users", users)
        object.__setattr__(self, "writable_paths", paths)
        object.__setattr__(self, "runtime_users", runtime_users)
        object.__setattr__(self, "runtime_volumes", runtime_volumes)
        if not users or len(users) > _MAX_SERVICES:
            raise ValueError("hardening policy requires between 1 and 64 services")
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
            "service_users", "writable_paths", "runtime_users", "runtime_volumes"
        }) or not {"service_users", "writable_paths"}.issubset(value):
            raise ValueError("hardening policy is invalid")
        raw_users = value["service_users"]
        raw_paths = value["writable_paths"]
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
        return cls(tuple(users), tuple(paths), tuple(evidence), tuple(volumes))

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
        return result


def automatic_hardening_policy(
    services: object,
    dockerfile_users: Mapping[str, str | None] | None = None,
    dockerfile_images: Mapping[str, tuple[str, ...]] | None = None,
) -> HardeningPolicy:
    """Build the server-owned runtime policy from inspected Compose services.

    Explicit Compose ``user:`` declarations win. When a service has no numeric
    user there, fall back to the final ``USER`` instruction of its Dockerfile,
    then to the server-owned non-root policy default.
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
        uid, gid, source = resolved or (
            _DEFAULT_RUNTIME_ID,
            _DEFAULT_RUNTIME_ID,
            "policy",
        )
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
        if 0 < uid <= 2**31 - 1 and 0 < gid <= 2**31 - 1:
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
            declared[service] = (_DEFAULT_RUNTIME_ID, _DEFAULT_RUNTIME_ID)
            sources[service] = "policy"
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
        if any(_image_repository(image) == "postgres" for image in images):
            paths.append(
                WritablePathPolicy(service, "/var/run/postgresql", "0775")
            )
    return tuple(paths)


def _merge_writable_paths(
    explicit: tuple[WritablePathPolicy, ...],
    automatic: tuple[WritablePathPolicy, ...],
) -> tuple[WritablePathPolicy, ...]:
    result = {(item.service, item.path): item for item in automatic}
    result.update({(item.service, item.path): item for item in explicit})
    return tuple(result[key] for key in sorted(result))


def _json_evidence(value: object, *, depth: int = 0) -> Any:
    if depth > 12:
        raise ValueError("hardening evidence is too deeply nested")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) > 8192:
            raise ValueError("hardening evidence string is too large")
        return value
    if isinstance(value, list):
        if len(value) > 2048:
            raise ValueError("hardening evidence list is too large")
        return [_json_evidence(item, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        if len(value) > 256:
            raise ValueError("hardening evidence object is too large")
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError("hardening evidence key is invalid")
            result[key] = _json_evidence(item, depth=depth + 1)
        return result
    raise ValueError("hardening evidence contains an unsupported value")


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class HardenedCandidate:
    source_tree_sha256: str
    hardened_tree_sha256: str
    compose: str
    services: tuple[str, ...]
    changes: tuple[str, ...]
    policy: Mapping[str, Any]
    gate: Mapping[str, Any]

    @classmethod
    def from_response(
        cls,
        response: object,
        *,
        source_tree_sha256: str | None = None,
        hardened_tree_sha256: str | None = None,
        compose: str | None = None,
        policy: HardeningPolicy | None = None,
    ) -> HardenedCandidate:
        if not isinstance(response, Mapping):
            raise ValueError("hardener response is invalid")
        gate = response.get("gate")
        post_gate = response.get("gate_after_apply")
        if (
            response.get("status") != "applied"
            or response.get("applied") is not True
            or not isinstance(gate, Mapping)
            or gate.get("status") != "passed"
            or not isinstance(post_gate, Mapping)
            or post_gate.get("status") not in {"reused", "passed"}
        ):
            raise ValueError("hardener did not produce a fully validated candidate")
        source_hash = source_tree_sha256 or response.get("source_tree_sha256")
        hardened_hash = (
            hardened_tree_sha256
            or response.get("hardened_tree_sha256")
            or post_gate.get("tree_sha256")
        )
        if not isinstance(source_hash, str) or not _SHA256.fullmatch(source_hash):
            raise ValueError("source tree evidence is invalid")
        if not isinstance(hardened_hash, str) or not _SHA256.fullmatch(hardened_hash):
            raise ValueError("hardened tree evidence is invalid")
        compose_value = compose or response.get("compose")
        if not isinstance(compose_value, str) or not compose_value or compose_value.startswith("/"):
            raise ValueError("compose evidence is invalid")
        compose_path = PurePosixPath(compose_value)
        if ".." in compose_path.parts or compose_path.as_posix() != compose_value:
            raise ValueError("compose evidence is invalid")
        changes = response.get("changes")
        if not isinstance(changes, list) or len(changes) > 1024:
            raise ValueError("change evidence is invalid")
        clean_changes = []
        for value in changes:
            if not isinstance(value, str) or not value or value.startswith("/"):
                raise ValueError("change evidence is invalid")
            path = PurePosixPath(value)
            if ".." in path.parts or path.as_posix() != value:
                raise ValueError("change evidence is invalid")
            clean_changes.append(value)
        expected_policy = policy.as_dict() if policy is not None else response.get("policy")
        if not isinstance(expected_policy, Mapping):
            raise ValueError("policy evidence is invalid")
        services = tuple(sorted(expected_policy.get("service_users", {})))
        if not services or any(not isinstance(item, str) for item in services):
            raise ValueError("service evidence is invalid")
        evidence = {"primary": gate, "post_apply": post_gate}
        return cls(
            source_hash,
            hardened_hash,
            compose_value,
            services,
            tuple(clean_changes),
            _freeze_json(_json_evidence(expected_policy)),
            _freeze_json(_json_evidence(evidence)),
        )

    def as_report(self) -> dict[str, Any]:
        return {
            "status": "validated",
            "source_tree_sha256": self.source_tree_sha256,
            "hardened_tree_sha256": self.hardened_tree_sha256,
            "compose": self.compose,
            "services": list(self.services),
            "changes": list(self.changes),
            "policy": _thaw_json(self.policy),
            "gate": _thaw_json(self.gate),
        }
