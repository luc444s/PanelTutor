"""Immutable on-disk store for signed releases and hardened artifacts."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
import tarfile
from collections.abc import Mapping
from pathlib import Path

from .trusted import ReleaseRejected, TrustedRelease, canonical_json

MAX_DESCRIPTOR_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
MAX_RELEASE_DIRS = 512
MAX_LISTED_RELEASES = 256
_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def _segment(value: object) -> str:
    if not isinstance(value, str) or not _SEGMENT.fullmatch(value) or value == "..":
        raise ReleaseRejected("release path identifier is invalid")
    return value


def release_store_root(environ: Mapping[str, str]) -> Path:
    value = (
        environ.get("SPANEL_APPS_STATE_ROOT", "").strip()
        or environ.get("SPANEL_APP_STATE_ROOT", "").strip()
    )
    return (
        Path(value).expanduser() if value
        else Path.home() / ".local/state/spanel/apps"
    )


def release_dir(root: Path, tenant_id: str, application_id: str, digest: str) -> Path:
    return (
        Path(root) / "hardened" / _segment(tenant_id)
        / _segment(application_id) / _sha(digest)
    )


def descriptor_path(
    root: Path, tenant_id: str, application_id: str, digest: str
) -> Path:
    return release_dir(root, tenant_id, application_id, digest) / "release.json"


def artifact_path(
    root: Path, tenant_id: str, application_id: str, digest: str
) -> Path:
    return release_dir(root, tenant_id, application_id, digest) / "source.tar.gz"


def _sha(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ReleaseRejected("release artifact hash is invalid")
    return value


def _ensure_private_dir(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(parents=True, mode=0o700)
        info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ReleaseRejected("release store contains an unsafe path")
    if stat.S_IMODE(info.st_mode) != 0o700:
        path.chmod(0o700)


def _write_atomic(path: Path, payload: bytes) -> None:
    _ensure_private_dir(path.parent)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def build_artifact(root: Path) -> bytes:
    """Create the hardened tar that is hashed into the release descriptor."""

    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ReleaseRejected("release tree is unavailable")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", dereference=False) as archive:
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if ".git" in relative.parts or ".spanel-build-backups" in relative.parts:
                continue
            archive.add(
                path, arcname=relative.as_posix(), recursive=False,
            )
    return stream.getvalue()


def write_release(root: Path, release: TrustedRelease, artifact: bytes) -> Path:
    if hashlib.sha256(artifact).hexdigest() != release.artifact_sha256:
        raise ReleaseRejected("release artifact hash does not match")
    if len(artifact) > MAX_ARTIFACT_BYTES:
        raise ReleaseRejected("release artifact is too large")
    directory = release_dir(
        root, release.tenant_id, release.application_id, release.artifact_sha256
    )
    _ensure_private_dir(directory)
    payload = canonical_json(release.to_dict()) + b"\n"
    _write_atomic(directory / "source.tar.gz", artifact)
    _write_atomic(directory / "release.json", payload)
    return directory


def _read_regular(path: Path, *, maximum: int, mode: int | None) -> bytes:
    try:
        info = path.lstat()
    except OSError:
        raise ReleaseRejected("release file is unavailable") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ReleaseRejected("release file is not a regular file")
    if mode is not None and stat.S_IMODE(info.st_mode) != mode:
        raise ReleaseRejected("release file has unsafe permissions")
    if info.st_size <= 0 or info.st_size > maximum:
        raise ReleaseRejected("release file size is invalid")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise ReleaseRejected("release file is unavailable") from None
    with os.fdopen(descriptor, "rb") as handle:
        return handle.read(maximum + 1)


def read_descriptor(path: Path) -> TrustedRelease:
    payload = _read_regular(path, maximum=MAX_DESCRIPTOR_BYTES, mode=0o600)
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError):
        raise ReleaseRejected("release descriptor is invalid") from None
    return TrustedRelease.from_dict(value)


def load_release(
    root: Path, tenant_id: str, application_id: str, digest: str
) -> TrustedRelease:
    release = read_descriptor(
        descriptor_path(root, tenant_id, application_id, digest)
    )
    if (
        release.tenant_id != tenant_id
        or release.application_id != application_id
        or release.artifact_sha256 != digest
    ):
        raise ReleaseRejected("release is bound to another application or tenant")
    return release


def load_artifact(
    root: Path, release: TrustedRelease
) -> bytes:
    path = artifact_path(
        root, release.tenant_id, release.application_id, release.artifact_sha256
    )
    payload = _read_regular(path, maximum=MAX_ARTIFACT_BYTES, mode=0o600)
    if hashlib.sha256(payload).hexdigest() != release.artifact_sha256:
        raise ReleaseRejected("release artifact hash does not match")
    return payload


def _application_release_dirs(
    root: Path, tenant_id: str, application_id: str
) -> list[Path]:
    base = Path(root) / "hardened" / _segment(tenant_id) / _segment(application_id)
    try:
        info = base.lstat()
    except FileNotFoundError:
        return []
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ReleaseRejected("release store contains an unsafe path")
    entries = sorted(
        (entry for entry in base.iterdir() if entry.is_dir()),
        key=lambda item: item.name,
    )
    if len(entries) > MAX_RELEASE_DIRS:
        raise ReleaseRejected("release store contains too many releases")
    return entries


def find_release(
    root: Path, tenant_id: str, application_id: str, release_id: str
) -> TrustedRelease:
    if not isinstance(release_id, str) or len(release_id) > 128:
        raise ReleaseRejected("release identifier is invalid")
    for directory in _application_release_dirs(root, tenant_id, application_id):
        try:
            release = read_descriptor(directory / "release.json")
        except ReleaseRejected:
            continue
        if (
            release.release_id == release_id
            and release.tenant_id == tenant_id
            and release.application_id == application_id
        ):
            return release
    raise ReleaseRejected("release not found")


def list_releases(
    root: Path, tenant_id: str, application_id: str
) -> list[dict[str, object]]:
    releases: list[TrustedRelease] = []
    for directory in _application_release_dirs(root, tenant_id, application_id):
        try:
            release = read_descriptor(directory / "release.json")
        except ReleaseRejected:
            continue
        if (
            release.tenant_id == tenant_id
            and release.application_id == application_id
        ):
            releases.append(release)
    releases.sort(key=lambda item: item.created_at, reverse=True)
    return [
        {
            "release_id": item.release_id,
            "operation_id": item.operation_id,
            "artifact_sha256": item.artifact_sha256,
            "compose_sha256": item.compose_sha256,
            "commit": item.commit,
            "repo": item.repo,
            "branch": item.branch,
            "key_id": item.key_id,
            "created_at": item.created_at,
            "expires_at": item.expires_at,
            "expired": item.expired(),
            "service_fingerprints": (
                dict(item.service_fingerprints)
                if item.service_fingerprints is not None else {}
            ),
            "shared_fingerprint": item.shared_fingerprint,
        }
        for item in releases[:MAX_LISTED_RELEASES]
    ]


def discard_tree(path: Path) -> None:
    """Remove a staging tree without following symlinks."""

    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        path.unlink()
        return
    if stat.S_ISDIR(info.st_mode):
        shutil.rmtree(path)
