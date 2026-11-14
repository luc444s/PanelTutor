"""Signed, verifiable application releases.

Releases are the only object the deployment pipeline may consume.  The
descriptor is canonical JSON signed with HMAC-SHA256 and stored next to the
hardened artifact inside the Apps state root.
"""

from .pipeline import create_release, release_result
from .store import (
    artifact_path,
    build_artifact,
    descriptor_path,
    find_release,
    list_releases,
    load_artifact,
    load_release,
    release_store_root,
    write_release,
)
from .trusted import (
    ReleaseKeyRing,
    ReleaseRejected,
    ReleaseSigningUnavailable,
    TrustedRelease,
    canonical_json,
    key_id_for,
    release_ttl_seconds,
)
from .verify import VerifiedRelease, verify_release

__all__ = [
    "ReleaseKeyRing",
    "ReleaseRejected",
    "ReleaseSigningUnavailable",
    "TrustedRelease",
    "VerifiedRelease",
    "artifact_path",
    "build_artifact",
    "canonical_json",
    "create_release",
    "descriptor_path",
    "find_release",
    "key_id_for",
    "list_releases",
    "load_artifact",
    "load_release",
    "release_result",
    "release_store_root",
    "release_ttl_seconds",
    "verify_release",
    "write_release",
]
