"""Build, sign and persist a release from the unmodified application source.

PanelTutor no longer rewrites Dockerfiles, Compose files, entrypoints,
commands, users or volumes.  A release is a byte-for-byte snapshot of what the
developer published, signed together with the static admission checks that
were run against it.  Isolation of the runtime is infrastructure's job; the
only policy carried here is the host-resource authorization policy needed to
verify that snapshot at deploy time.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..hardening import HardeningPolicy
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


def _static_gate(audit: object) -> dict[str, Any]:
    """Evidence that admission checks ran; never a claim of a runtime sandbox."""

    errors = getattr(audit, "errors", ())
    return {
        "status": "passed" if not errors else "blocked",
        "admission": {
            "static_audit": True,
            "source_unchanged": True,
            "findings": len(getattr(audit, "findings", ())),
        },
    }


def create_release(
    checkout: Path,
    *,
    compose_file: str,
    tenant_id: str,
    application_id: str,
    operation_id: str,
    repo: str,
    branch: str,
    policy: HardeningPolicy,
    environ: Mapping[str, str],
) -> TrustedRelease:
    """Sign the application exactly as delivered, after static validation.

    The tree digest is taken directly from ``checkout`` and is used for both
    ``source_tree_sha256`` and ``hardened_tree_sha256`` so that previously
    signed releases keep the same descriptor shape while it is now guaranteed
    that no file was rewritten.  A blocking audit finding is an explicit
    rejection: without a tenant sandbox we do not lower the admission bar.
    """

    checkout = Path(checkout)
    policy_data = policy.as_dict()
    audit = audit_project(
        checkout,
        compose_file,
        non_root=True,
        authorized_external_networks=frozenset(
            policy_data.get("authorized_external_networks", [])
        ),
    )
    if audit.errors:
        raise ReleaseRejected(
            "application has blocking security findings: "
            + ", ".join(sorted({item.code for item in audit.errors}))
        )
    digest = tree_digest(checkout)
    compose_rel = audit.compose.relative_to(checkout).as_posix()
    compose = checkout / compose_rel
    if not compose.is_file():
        raise ReleaseRejected("Compose file is unavailable")
    dockerfiles: dict[str, str] = {}
    for dockerfile in audit.dockerfiles.values():
        relative = dockerfile.relative_to(checkout).as_posix()
        dockerfiles[relative] = _sha256(dockerfile)
    gate = _static_gate(audit)
    fingerprints = compute_fingerprints(checkout, audit)
    artifact = build_artifact(checkout)
    key_ring = ReleaseKeyRing.from_environ(environ)
    created = datetime.now(UTC)
    expires = expiry_for(created, release_ttl_seconds(environ))
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
        source_tree_sha256=digest,
        hardened_tree_sha256=digest,
        compose_path=compose_rel,
        compose_sha256=_sha256(compose),
        dockerfiles=dockerfiles,
        policy_sha256=hashlib.sha256(canonical_json(policy_data)).hexdigest(),
        policy=policy_data,
        gate_sha256=hashlib.sha256(canonical_json(gate)).hexdigest(),
        tool_versions=_tool_versions(environ),
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
