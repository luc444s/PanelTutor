"""Build, sign and persist a release from a validated hardening candidate."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..hardening import HardenedCandidate, HardeningPolicy
from ..runtime.audit import audit_project
from ..runtime.deployment import _git_commit
from .fingerprints import compute_fingerprints
from .store import build_artifact, release_store_root, write_release
from .trusted import (
    SCHEMA,
    ReleaseKeyRing,
    ReleaseRejected,
    TrustedRelease,
    canonical_json,
    expiry_for,
    release_ttl_seconds,
)
from .verify import tree_digest


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _plain(value: object) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _tool_versions(environ: Mapping[str, str]) -> dict[str, Any]:
    import json

    raw = environ.get("SPANEL_APPS_TOOL_VERSIONS", "").strip()
    if not raw:
        return {"schema": 1}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise ReleaseRejected("tool versions are invalid") from None
    if not isinstance(value, dict) or len(value) > 64:
        raise ReleaseRejected("tool versions are invalid")
    return value


def create_release(
    checkout: Path,
    candidate: HardenedCandidate,
    *,
    tenant_id: str,
    application_id: str,
    operation_id: str,
    repo: str,
    branch: str,
    policy: HardeningPolicy,
    environ: Mapping[str, str],
    normalization: Mapping[str, Any] | None = None,
) -> TrustedRelease:
    checkout = Path(checkout)
    audit = audit_project(checkout, candidate.compose, non_root=True)
    if audit.errors:
        raise ReleaseRejected("hardened tree has blocking audit errors")
    if tree_digest(checkout) != candidate.hardened_tree_sha256:
        raise ReleaseRejected("hardened tree does not match the hardener evidence")
    compose_rel = candidate.compose
    compose = checkout / compose_rel
    if not compose.is_file():
        raise ReleaseRejected("hardened Compose file is unavailable")
    dockerfiles: dict[str, str] = {}
    for dockerfile in audit.dockerfiles.values():
        relative = dockerfile.relative_to(checkout).as_posix()
        dockerfiles[relative] = _sha256(dockerfile)
    policy_data = policy.as_dict()
    gate = _plain(candidate.gate)
    fingerprints = compute_fingerprints(checkout, audit)
    artifact = build_artifact(checkout)
    key_ring = ReleaseKeyRing.from_environ(environ)
    created = datetime.now(UTC)
    expires = expiry_for(created, release_ttl_seconds(environ))
    tool_versions = _tool_versions(environ)
    if normalization is not None:
        tool_versions = {**tool_versions, "normalization": _plain(normalization)}
    release = TrustedRelease(
        schema=SCHEMA,
        algorithm="hmac-sha256",
        key_id=key_ring.active_key_id,
        release_id=operation_id,
        tenant_id=tenant_id,
        application_id=application_id,
        operation_id=operation_id,
        repo=repo,
        branch=branch,
        commit=_git_commit(checkout),
        artifact_sha256=hashlib.sha256(artifact).hexdigest(),
        source_tree_sha256=candidate.source_tree_sha256,
        hardened_tree_sha256=candidate.hardened_tree_sha256,
        compose_path=compose_rel,
        compose_sha256=_sha256(compose),
        dockerfiles=dockerfiles,
        policy_sha256=hashlib.sha256(canonical_json(policy_data)).hexdigest(),
        policy=policy_data,
        gate_sha256=hashlib.sha256(canonical_json(gate)).hexdigest(),
        tool_versions=tool_versions,
        created_at=created.isoformat(),
        expires_at=expires,
        service_fingerprints=fingerprints["service_fingerprints"],
        shared_fingerprint=fingerprints["shared_fingerprint"],
    ).sign(key_ring)
    write_release(release_store_root(environ), release, artifact)
    return release


def release_result(release: TrustedRelease) -> dict[str, Any]:
    """Non-secret metadata safe for operation results and CLI output."""

    result = {
        "release_id": release.release_id,
        "artifact_sha256": release.artifact_sha256,
        "compose_sha256": release.compose_sha256,
        "hardened_tree_sha256": release.hardened_tree_sha256,
        "policy_sha256": release.policy_sha256,
        "gate_sha256": release.gate_sha256,
        "key_id": release.key_id,
        "created_at": release.created_at,
        "expires_at": release.expires_at,
        "commit": release.commit,
        "repo": release.repo,
        "branch": release.branch,
        "service_fingerprints": (
            dict(release.service_fingerprints)
            if release.service_fingerprints is not None else {}
        ),
        "shared_fingerprint": release.shared_fingerprint,
    }
    # ``tool_versions`` is frozen (nested MappingProxyType).  Use the thawed
    # signed body so the result is JSON-serializable for the operation record.
    tool_versions = release.body.get("tool_versions")
    normalization = (
        tool_versions.get("normalization")
        if isinstance(tool_versions, Mapping) else None
    )
    if isinstance(normalization, Mapping):
        result["normalization"] = dict(normalization)
    return result
