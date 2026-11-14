"""Canonical, signed ``TrustedRelease`` descriptors."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any

SCHEMA = 1
ALGORITHM = "hmac-sha256"
MIN_KEY_BYTES = 32
DEFAULT_TTL_SECONDS = 86400

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"[0-9a-f]{8}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}\Z")
_COMMIT = re.compile(r"[0-9a-f]{7,64}\Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_FIELDS = {
    "schema",
    "algorithm",
    "key_id",
    "release_id",
    "tenant_id",
    "application_id",
    "operation_id",
    "repo",
    "branch",
    "commit",
    "artifact_sha256",
    "source_tree_sha256",
    "hardened_tree_sha256",
    "compose_path",
    "compose_sha256",
    "dockerfiles",
    "policy_sha256",
    "policy",
    "gate_sha256",
    "tool_versions",
    "created_at",
    "expires_at",
    "signature",
}
_MAX_DOCKERFILES = 64


class ReleaseRejected(RuntimeError):
    """Safe, bounded failure that never embeds artifact or key contents."""

    code = "apps.release_invalid"


class ReleaseSigningUnavailable(ReleaseRejected):
    """The deployment pipeline cannot sign or verify releases."""

    code = "apps.release_signing_unavailable"


def canonical_json(value: object) -> bytes:
    """Serialise a descriptor deterministically without whitespace."""

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def key_id_for(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:8]


def _safe_relative(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise ReleaseRejected(f"{field} is invalid")
    path = PurePosixPath(value)
    if ".." in path.parts or path.as_posix() != value or len(value) > 1024:
        raise ReleaseRejected(f"{field} is invalid")
    return value


def _hash(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ReleaseRejected(f"{field} is invalid")
    return value


def _identifier(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ReleaseRejected(f"{field} is invalid")
    return value


def _timestamp(value: object, *, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ReleaseRejected(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ReleaseRejected(f"{field} is invalid") from None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _json_mapping(value: object, *, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReleaseRejected(f"{field} is invalid")
    value = _thaw(value)
    try:
        encoded = canonical_json(value)
        decoded = json.loads(encoded)
    except (TypeError, ValueError):
        raise ReleaseRejected(f"{field} is invalid") from None
    if not isinstance(decoded, dict) or len(decoded) > 256:
        raise ReleaseRejected(f"{field} is invalid")
    return decoded


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class TrustedRelease:
    schema: int
    algorithm: str
    key_id: str
    release_id: str
    tenant_id: str
    application_id: str
    operation_id: str
    repo: str
    branch: str
    commit: str
    artifact_sha256: str
    source_tree_sha256: str
    hardened_tree_sha256: str
    compose_path: str
    compose_sha256: str
    dockerfiles: Mapping[str, str]
    policy_sha256: str
    policy: Mapping[str, Any]
    gate_sha256: str
    tool_versions: Mapping[str, Any]
    created_at: str
    expires_at: str
    signature: str = ""

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ReleaseRejected("release schema is unsupported")
        if self.algorithm != ALGORITHM:
            raise ReleaseRejected("release algorithm is unsupported")
        if not _KEY_ID.fullmatch(self.key_id):
            raise ReleaseRejected("release key_id is invalid")
        for field in (
            "release_id", "tenant_id", "application_id", "operation_id",
        ):
            _identifier(getattr(self, field), field=field)
        if not _REPO.fullmatch(self.repo):
            raise ReleaseRejected("release repo is invalid")
        if not _BRANCH.fullmatch(self.branch):
            raise ReleaseRejected("release branch is invalid")
        if not _COMMIT.fullmatch(self.commit):
            raise ReleaseRejected("release commit is invalid")
        for field in (
            "artifact_sha256", "source_tree_sha256", "hardened_tree_sha256",
            "compose_sha256", "policy_sha256", "gate_sha256",
        ):
            _hash(getattr(self, field), field=field)
        _safe_relative(self.compose_path, field="compose_path")
        if not isinstance(self.dockerfiles, Mapping):
            raise ReleaseRejected("release dockerfiles are invalid")
        if len(self.dockerfiles) > _MAX_DOCKERFILES:
            raise ReleaseRejected("release dockerfiles are invalid")
        dockerfiles: dict[str, str] = {}
        for name, digest in self.dockerfiles.items():
            dockerfiles[_safe_relative(name, field="dockerfile")] = _hash(
                digest, field="dockerfile"
            )
        object.__setattr__(
            self, "dockerfiles", MappingProxyType(dict(sorted(dockerfiles.items())))
        )
        if not isinstance(self.policy, Mapping):
            raise ReleaseRejected("release policy is invalid")
        object.__setattr__(
            self, "policy", _freeze(_json_mapping(self.policy, field="policy"))
        )
        object.__setattr__(
            self, "tool_versions",
            _freeze(_json_mapping(self.tool_versions, field="tool_versions")),
        )
        created = _timestamp(self.created_at, field="created_at")
        expires = _timestamp(self.expires_at, field="expires_at")
        if expires <= created:
            raise ReleaseRejected("release expiry is invalid")
        if self.signature and not _SHA256.fullmatch(self.signature):
            raise ReleaseRejected("release signature is invalid")

    @property
    def body(self) -> dict[str, Any]:
        """The signed payload, i.e. the descriptor without ``signature``."""

        return {
            "schema": self.schema,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "release_id": self.release_id,
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "operation_id": self.operation_id,
            "repo": self.repo,
            "branch": self.branch,
            "commit": self.commit,
            "artifact_sha256": self.artifact_sha256,
            "source_tree_sha256": self.source_tree_sha256,
            "hardened_tree_sha256": self.hardened_tree_sha256,
            "compose_path": self.compose_path,
            "compose_sha256": self.compose_sha256,
            "dockerfiles": dict(self.dockerfiles),
            "policy_sha256": self.policy_sha256,
            "policy": _thaw(self.policy),
            "gate_sha256": self.gate_sha256,
            "tool_versions": _thaw(self.tool_versions),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    def signed_bytes(self) -> bytes:
        return canonical_json(self.body)

    def to_dict(self) -> dict[str, Any]:
        return {**self.body, "signature": self.signature}

    def with_signature(self, signature: str) -> TrustedRelease:
        return replace(self, signature=signature)

    def sign(self, key_ring: ReleaseKeyRing) -> TrustedRelease:
        unsigned = replace(self, signature="", key_id=key_ring.active_key_id)
        return unsigned.with_signature(key_ring.sign(unsigned.signed_bytes()))

    def verify_signature(self, key_ring: ReleaseKeyRing) -> None:
        key = key_ring.verification_key(self.key_id)
        if key is None:
            raise ReleaseSigningUnavailable("release signing key is unavailable")
        expected = hmac.new(key, self.signed_bytes(), hashlib.sha256).hexdigest()
        if not self.signature or not hmac.compare_digest(expected, self.signature):
            raise ReleaseRejected("release signature is invalid")

    def expired(self, *, now: datetime | None = None) -> bool:
        return _timestamp(self.expires_at, field="expires_at") <= (
            now or datetime.now(UTC)
        )

    @classmethod
    def from_dict(cls, value: object) -> TrustedRelease:
        if not isinstance(value, Mapping) or set(value) != _FIELDS:
            raise ReleaseRejected("release descriptor is invalid")
        try:
            return cls(
                schema=value["schema"],
                algorithm=value["algorithm"],
                key_id=value["key_id"],
                release_id=value["release_id"],
                tenant_id=value["tenant_id"],
                application_id=value["application_id"],
                operation_id=value["operation_id"],
                repo=value["repo"],
                branch=value["branch"],
                commit=value["commit"],
                artifact_sha256=value["artifact_sha256"],
                source_tree_sha256=value["source_tree_sha256"],
                hardened_tree_sha256=value["hardened_tree_sha256"],
                compose_path=value["compose_path"],
                compose_sha256=value["compose_sha256"],
                dockerfiles=value["dockerfiles"],
                policy_sha256=value["policy_sha256"],
                policy=value["policy"],
                gate_sha256=value["gate_sha256"],
                tool_versions=value["tool_versions"],
                created_at=value["created_at"],
                expires_at=value["expires_at"],
                signature=value["signature"],
            )
        except ReleaseRejected:
            raise
        except (TypeError, ValueError):
            raise ReleaseRejected("release descriptor is invalid") from None


@dataclass(frozen=True, slots=True)
class _SigningKey:
    key_id: str
    key: bytes

    def __repr__(self) -> str:  # never leak key material
        return f"_SigningKey(key_id={self.key_id!r}, key='[REDACTED]')"


class ReleaseKeyRing:
    """Active signing key plus rotation-compatible verification keys."""

    __slots__ = ("_active", "_verify")

    def __init__(
        self, active: _SigningKey | None, verify: Mapping[str, bytes],
    ) -> None:
        self._active = active
        self._verify = dict(verify)

    def __repr__(self) -> str:
        return (
            f"ReleaseKeyRing(active={self.active_key_id!r}, "
            f"verify={sorted(self._verify)!r})"
        )

    @property
    def active_key_id(self) -> str:
        if self._active is None:
            raise ReleaseSigningUnavailable("release signing is unavailable")
        return self._active.key_id

    def sign(self, payload: bytes) -> str:
        if self._active is None:
            raise ReleaseSigningUnavailable("release signing is unavailable")
        return hmac.new(self._active.key, payload, hashlib.sha256).hexdigest()

    def verification_key(self, key_id: str) -> bytes | None:
        if self._active is not None and self._active.key_id == key_id:
            return self._active.key
        return self._verify.get(key_id)

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> ReleaseKeyRing:
        raw_active = environ.get("SPANEL_APPS_RELEASE_SIGNING_KEY", "")
        active: _SigningKey | None = None
        if raw_active:
            key = raw_active.encode("utf-8")
            if len(key) < MIN_KEY_BYTES:
                raise ReleaseSigningUnavailable("release signing key is too short")
            active = _SigningKey(key_id_for(key), key)
        verify: dict[str, bytes] = {}
        raw_verify = environ.get("SPANEL_APPS_RELEASE_VERIFY_KEYS", "").strip()
        if raw_verify:
            try:
                parsed = json.loads(raw_verify)
            except json.JSONDecodeError:
                raise ReleaseSigningUnavailable(
                    "release verification keys are invalid"
                ) from None
            if not isinstance(parsed, dict) or len(parsed) > 64:
                raise ReleaseSigningUnavailable("release verification keys are invalid")
            for key_id, key_text in parsed.items():
                if (
                    not isinstance(key_id, str)
                    or not _KEY_ID.fullmatch(key_id)
                    or not isinstance(key_text, str)
                    or len(key_text.encode("utf-8")) < MIN_KEY_BYTES
                ):
                    raise ReleaseSigningUnavailable(
                        "release verification keys are invalid"
                    )
                verify[key_id] = key_text.encode("utf-8")
        return cls(active, verify)


def release_ttl_seconds(environ: Mapping[str, str]) -> int:
    raw = environ.get("SPANEL_APPS_RELEASE_TTL_SECONDS", "").strip()
    if not raw:
        return DEFAULT_TTL_SECONDS
    if not raw.isdigit():
        raise ReleaseSigningUnavailable("release TTL is invalid")
    value = int(raw)
    if not 60 <= value <= 30 * 86400:
        raise ReleaseSigningUnavailable("release TTL is invalid")
    return value


def expiry_for(created: datetime, ttl_seconds: int) -> str:
    return (created + timedelta(seconds=ttl_seconds)).isoformat()
