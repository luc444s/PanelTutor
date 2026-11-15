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

    def __post_init__(self) -> None:
        users = tuple(self.service_users)
        paths = tuple(self.writable_paths)
        object.__setattr__(self, "service_users", users)
        object.__setattr__(self, "writable_paths", paths)
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

    @classmethod
    def from_dict(cls, value: object) -> HardeningPolicy:
        if not isinstance(value, Mapping) or set(value) != {"service_users", "writable_paths"}:
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
        return cls(tuple(users), tuple(paths))

    def as_dict(self) -> dict[str, Any]:
        return {
            "service_users": {
                item.service: {"uid": item.uid, "gid": item.gid}
                for item in self.service_users
            },
            "writable_paths": [
                {"service": item.service, "path": item.path, "mode": item.mode}
                for item in self.writable_paths
            ],
        }


def automatic_hardening_policy(services: object) -> HardeningPolicy:
    """Build the server-owned runtime policy from inspected Compose services."""
    if not isinstance(services, Mapping):
        raise ValueError("inspected services are invalid")
    users = []
    for service in sorted(services):
        name = _service_name(service)
        config = services[service]
        config = config if isinstance(config, Mapping) else {}
        match = _RUNTIME_USER.fullmatch(str(config.get("user", "")))
        uid = int(match.group(1)) if match else _DEFAULT_RUNTIME_ID
        gid = int(match.group(2) or match.group(1)) if match else _DEFAULT_RUNTIME_ID
        users.append(RuntimeUserPolicy(name, uid, gid))
    return HardeningPolicy(tuple(users))


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
