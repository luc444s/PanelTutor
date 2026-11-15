"""Server-owned planning for global and per-service release reconciliation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .trusted import ReleaseRejected, TrustedRelease


@dataclass(frozen=True)
class DeployScope:
    type: str = "global"
    service: str | None = None

    def __post_init__(self) -> None:
        if self.type not in {"global", "service"}:
            raise ReleaseRejected("deployment scope is invalid")
        if self.type == "global" and self.service is not None:
            raise ReleaseRejected("global deployment cannot select a service")
        if self.type == "service" and not self.service:
            raise ReleaseRejected("service deployment requires a service")

    def to_dict(self) -> dict[str, str]:
        if self.type == "service":
            return {"type": "service", "service": str(self.service)}
        return {"type": "global"}

    @classmethod
    def from_value(cls, value: object) -> DeployScope:
        if value is None:
            return cls()
        if isinstance(value, DeployScope):
            return value
        if not isinstance(value, Mapping):
            raise ReleaseRejected("deployment scope is invalid")
        kind = value.get("type", "global")
        service = value.get("service")
        if kind not in {"global", "service"}:
            raise ReleaseRejected("deployment scope is invalid")
        if kind == "service" and not isinstance(service, str):
            raise ReleaseRejected("service deployment requires a service")
        if kind == "global" and service is not None:
            raise ReleaseRejected("global deployment cannot select a service")
        return cls(str(kind), str(service) if service is not None else None)


@dataclass(frozen=True)
class DeployPlan:
    requested_scope: str
    effective_services: tuple[str, ...]
    strategy: str
    fallback_reason: str | None = None
    requested_service: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_scope": self.requested_scope,
            "requested_service": self.requested_service,
            "effective_services": list(self.effective_services),
            "strategy": self.strategy,
            "fallback_reason": self.fallback_reason,
        }


def target_services(release: TrustedRelease) -> list[str]:
    if release.service_fingerprints:
        return sorted(release.service_fingerprints)
    return []


def _mapping(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {
        str(key): str(item)
        for key, item in value.items()
        if isinstance(item, str) and item
    }


def plan_deployment(
    release: TrustedRelease,
    active_manifest: Mapping[str, Any] | None,
    requested: object = None,
    *,
    services: Sequence[str] | None = None,
) -> DeployPlan:
    """Choose the effective service set from signed state, never from the UI."""

    scope = DeployScope.from_value(requested)
    known = sorted(set(services or target_services(release)))
    if not known:
        raise ReleaseRejected("release does not declare service fingerprints")
    if scope.type == "service":
        service = str(scope.service)
        if service not in known:
            raise ReleaseRejected("service does not belong to the target release")
        return DeployPlan(
            requested_scope="service",
            requested_service=service,
            effective_services=(service,),
            strategy="service",
        )
    if not isinstance(active_manifest, Mapping) or not active_manifest:
        return DeployPlan(
            requested_scope="global",
            effective_services=tuple(known),
            strategy="initial",
        )
    target_fingerprints = _mapping(release.service_fingerprints)
    active_fingerprints = _mapping(active_manifest.get("service_fingerprints"))
    active_shared = active_manifest.get("shared_fingerprint")
    if not release.shared_fingerprint:
        return DeployPlan(
            requested_scope="global",
            effective_services=tuple(known),
            strategy="fallback",
            fallback_reason="target_fingerprint_unavailable",
        )
    if not isinstance(active_shared, str) or not active_shared:
        return DeployPlan(
            requested_scope="global",
            effective_services=tuple(known),
            strategy="fallback",
            fallback_reason="active_state_incomplete",
        )
    if active_shared != release.shared_fingerprint:
        return DeployPlan(
            requested_scope="global",
            effective_services=tuple(known),
            strategy="fallback",
            fallback_reason="shared_configuration_changed",
        )
    if set(active_fingerprints) != set(known):
        return DeployPlan(
            requested_scope="global",
            effective_services=tuple(known),
            strategy="fallback",
            fallback_reason="active_state_incomplete",
        )
    containers = active_manifest.get("containers")
    if not isinstance(containers, Mapping) or not set(known).issubset(containers):
        return DeployPlan(
            requested_scope="global",
            effective_services=tuple(known),
            strategy="fallback",
            fallback_reason="active_containers_incomplete",
        )
    changed = tuple(
        service for service in known
        if target_fingerprints.get(service) != active_fingerprints.get(service)
    )
    return DeployPlan(
        requested_scope="global",
        effective_services=changed,
        strategy="incremental" if changed else "noop",
    )


def active_state(
    previous_manifest: Mapping[str, Any] | None,
    release: TrustedRelease,
    plan: DeployPlan,
    services: Sequence[str],
) -> dict[str, Any]:
    """Merge the effective state without mutating historical manifests."""

    previous = previous_manifest if isinstance(previous_manifest, Mapping) else {}
    known = sorted(set(services))
    target_id = release.release_id
    previous_global = previous.get("global_release_id")
    if not isinstance(previous_global, str) or not previous_global:
        previous_global = target_id
    previous_releases = _mapping(previous.get("service_releases"))
    previous_fingerprints = _mapping(previous.get("service_fingerprints"))
    previous_overrides = previous.get("overrides")
    overrides = {
        str(item) for item in previous_overrides
    } if isinstance(previous_overrides, list) else set()
    if plan.requested_scope == "service":
        service = str(plan.requested_service)
        merged_releases = {
            item: previous_releases.get(item, previous_global) for item in known
        }
        merged_releases[service] = target_id
        merged_fingerprints = {
            item: previous_fingerprints.get(item, "") for item in known
        }
        target_fingerprints = _mapping(release.service_fingerprints)
        merged_fingerprints[service] = target_fingerprints[service]
        overrides.add(service)
        global_release_id = previous_global
    else:
        merged_releases = {item: target_id for item in known}
        merged_fingerprints = {
            item: _mapping(release.service_fingerprints).get(item, "")
            for item in known
        }
        overrides = set()
        global_release_id = target_id
    return {
        "global_release_id": global_release_id,
        "service_releases": dict(sorted(merged_releases.items())),
        "service_fingerprints": dict(sorted(merged_fingerprints.items())),
        "overrides": sorted(
            item for item in overrides if item in set(known)
        ),
        "shared_fingerprint": release.shared_fingerprint,
    }
