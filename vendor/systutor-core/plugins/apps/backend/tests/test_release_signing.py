from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from plugins.apps.backend.releases import (
    ReleaseKeyRing,
    ReleaseRejected,
    ReleaseSigningUnavailable,
    TrustedRelease,
    canonical_json,
    key_id_for,
    release_ttl_seconds,
)

KEY = "k" * 32
GATE = {"primary": {"status": "passed"}, "post_apply": {"status": "reused"}}
POLICY = {
    "service_users": {"web": {"uid": 10001, "gid": 10002}},
    "writable_paths": [],
}


def digest(value: bytes | str) -> str:
    payload = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(payload).hexdigest()


def release(*, key: str = KEY, ttl: int = 3600, age: int = 0) -> TrustedRelease:
    now = datetime.now(UTC)
    created = now - timedelta(seconds=age)
    ring = ReleaseKeyRing.from_environ({"SPANEL_APPS_RELEASE_SIGNING_KEY": key})
    value = TrustedRelease(
        schema=1,
        algorithm="hmac-sha256",
        key_id=key_id_for(key.encode()),
        release_id="op-1",
        tenant_id="t1",
        application_id="a1",
        operation_id="op-1",
        repo="acme/repo",
        branch="main",
        commit="a" * 40,
        artifact_sha256=digest(b"artifact"),
        source_tree_sha256=digest(b"source"),
        hardened_tree_sha256=digest(b"tree"),
        compose_path="compose.yml",
        compose_sha256=digest(b"compose"),
        dockerfiles={"Dockerfile": digest(b"dockerfile")},
        policy_sha256=digest(canonical_json(POLICY)),
        policy=POLICY,
        gate_sha256=digest(canonical_json(GATE)),
        tool_versions={"hardener": "1"},
        created_at=created.isoformat(),
        expires_at=(created + timedelta(seconds=ttl)).isoformat(),
    )
    return value.sign(ring)


def test_canonical_json_is_ordered_compact_and_stable() -> None:
    assert canonical_json({"b": 1, "a": [2, {"d": 3, "c": 4}]}) == (
        b'{"a":[2,{"c":4,"d":3}],"b":1}'
    )
    assert canonical_json({"a": 1}) == canonical_json({"a": 1})


def test_signature_covers_every_release_field() -> None:
    value = release()
    ring = ReleaseKeyRing.from_environ({"SPANEL_APPS_RELEASE_SIGNING_KEY": KEY})
    value.verify_signature(ring)
    body = value.body
    assert "signature" not in body
    tampered = [
        "artifact_sha256", "compose_sha256", "hardened_tree_sha256",
        "policy_sha256", "gate_sha256", "commit", "tenant_id", "application_id",
    ]
    for field in tampered:
        body = value.body
        body[field] = "b" * 64 if field.endswith("sha256") else (
            "b" * 40 if field == "commit" else "other"
        )
        with pytest.raises(ReleaseRejected):
            TrustedRelease.from_dict({**body, "signature": value.signature}
                                     ).verify_signature(ring)
    docker_body = value.body
    docker_body["dockerfiles"] = {"Dockerfile": digest(b"other")}
    with pytest.raises(ReleaseRejected):
        TrustedRelease.from_dict(
            {**docker_body, "signature": value.signature}
        ).verify_signature(ring)


def test_key_rotation_and_fail_closed_key_handling() -> None:
    old = "o" * 32
    value = release(key=old)
    rotating = ReleaseKeyRing.from_environ({
        "SPANEL_APPS_RELEASE_SIGNING_KEY": KEY,
        "SPANEL_APPS_RELEASE_VERIFY_KEYS": json.dumps({key_id_for(old.encode()): old}),
    })
    value.verify_signature(rotating)
    unknown = ReleaseKeyRing.from_environ({
        "SPANEL_APPS_RELEASE_SIGNING_KEY": KEY,
    })
    with pytest.raises(ReleaseSigningUnavailable):
        value.verify_signature(unknown)
    with pytest.raises(ReleaseSigningUnavailable):
        ReleaseKeyRing.from_environ({}).sign(b"payload")
    with pytest.raises(ReleaseSigningUnavailable):
        ReleaseKeyRing.from_environ({"SPANEL_APPS_RELEASE_SIGNING_KEY": "short"})
    with pytest.raises(ReleaseSigningUnavailable):
        ReleaseKeyRing.from_environ({"SPANEL_APPS_RELEASE_VERIFY_KEYS": "not-json"})


def test_secret_key_never_appears_in_descriptor_or_repr() -> None:
    value = release()
    ring = ReleaseKeyRing.from_environ({"SPANEL_APPS_RELEASE_SIGNING_KEY": KEY})
    encoded = canonical_json(value.to_dict()).decode()
    assert KEY not in encoded
    assert KEY not in repr(ring)
    assert KEY not in str(value)


def test_release_accepts_external_image_only_stacks() -> None:
    from dataclasses import replace

    value = replace(release(), dockerfiles={}).sign(
        ReleaseKeyRing.from_environ({"SPANEL_APPS_RELEASE_SIGNING_KEY": KEY})
    )
    value.verify_signature(
        ReleaseKeyRing.from_environ({"SPANEL_APPS_RELEASE_SIGNING_KEY": KEY})
    )
    assert value.dockerfiles == {}


def test_expiry_and_ttl_are_bounded() -> None:
    expired = release(ttl=3600, age=7200)
    assert expired.expired()
    fresh = release()
    assert not fresh.expired()
    assert release_ttl_seconds({}) == 86400
    assert release_ttl_seconds({"SPANEL_APPS_RELEASE_TTL_SECONDS": "120"}) == 120
    with pytest.raises(ReleaseSigningUnavailable):
        release_ttl_seconds({"SPANEL_APPS_RELEASE_TTL_SECONDS": "0"})
    with pytest.raises(ReleaseSigningUnavailable):
        release_ttl_seconds({"SPANEL_APPS_RELEASE_TTL_SECONDS": "nope"})
