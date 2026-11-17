"""Fail-closed verification of a signed release before any deploy step."""

from __future__ import annotations

import hashlib
import io
import os
import stat
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..hardening import HardeningPolicy
from ..runtime.audit import audit_project
from ..runtime.types import (
    AppDeployError,
    AuditResult,
    readonly_release_file,
    volume_is_host_bind,
)
from ..symlinks import symlink_target
from .store import discard_tree, load_artifact
from .trusted import (
    ReleaseKeyRing,
    ReleaseRejected,
    TrustedRelease,
    _thaw,
    canonical_json,
)


@dataclass(frozen=True)
class VerifiedRelease:
    release: TrustedRelease
    root: Path
    audit: AuditResult
    policy: dict[str, object]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tree_digest(root: Path) -> str:
    """The hardener tree digest algorithm, applied to the extracted artifact."""

    root = Path(root)
    digest = hashlib.sha256()
    for path in sorted(
        root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
    ):
        relative = path.relative_to(root)
        if ".git" in relative.parts or ".spanel-build-backups" in relative.parts:
            continue
        digest.update(relative.as_posix().encode())
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"L" + symlink_target(path).encode())
        elif path.is_file():
            digest.update(b"F")
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
        elif path.is_dir():
            digest.update(b"D")
    return digest.hexdigest()


def _policy_dict(policy: object) -> dict[str, object]:
    if isinstance(policy, HardeningPolicy):
        return policy.as_dict()
    if isinstance(policy, Mapping):
        try:
            return HardeningPolicy.from_dict(_thaw(policy)).as_dict()
        except ValueError:
            raise ReleaseRejected("release policy is invalid") from None
    raise ReleaseRejected("release policy is invalid")


def _verify_policy(release: TrustedRelease, policy: object | None) -> dict:
    declared = _policy_dict(release.policy)
    if canonical_json(declared) != canonical_json(_thaw(release.policy)):
        raise ReleaseRejected("release policy is not canonical")
    digest = hashlib.sha256(canonical_json(declared)).hexdigest()
    if digest != release.policy_sha256:
        raise ReleaseRejected("release policy hash does not match")
    if policy is not None:
        administered = _policy_dict(policy)
        if canonical_json(administered) != canonical_json(declared):
            raise ReleaseRejected("release does not match the administered policy")
    return declared


def _safe_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    if len(members) > 100_000:
        raise ReleaseRejected("release artifact contains too many entries")
    total = 0
    for member in members:
        name = member.name
        if not name or name.startswith("/") or "\x00" in name:
            raise ReleaseRejected("release artifact contains an unsafe path")
        path = PurePosixPath(name)
        if ".." in path.parts or path.as_posix() != name:
            raise ReleaseRejected("release artifact contains an unsafe path")
        if member.isdev() or member.isfifo():
            raise ReleaseRejected("release artifact contains a special file")
        if member.issym():
            target = PurePosixPath(member.linkname)
            if target.is_absolute() or ".." in target.parts:
                raise ReleaseRejected("release artifact contains an unsafe symlink")
        if member.islnk():
            target = PurePosixPath(member.linkname)
            if target.is_absolute() or ".." in target.parts:
                raise ReleaseRejected("release artifact contains an unsafe link")
        if member.isfile():
            total += max(member.size, 0)
            if total > 4 * 1024 * 1024 * 1024:
                raise ReleaseRejected("release artifact is too large")
    return members


def _extract(root: Path, staging: Path, artifact: bytes) -> Path:
    parent = root / "private" / "staging"
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    permission = stat.S_IMODE(parent.lstat().st_mode)
    if permission != 0o700:
        parent.chmod(0o700)
    discard_tree(staging)
    staging.mkdir(parents=True, mode=0o700)
    staging.chmod(0o700)
    try:
        with tarfile.open(fileobj=io.BytesIO(artifact), mode="r:gz") as archive:
            members = _safe_members(archive)
            archive.extractall(staging, members=members, filter="data")
    except (tarfile.TarError, OSError, ValueError):
        discard_tree(staging)
        raise ReleaseRejected("release artifact is invalid") from None
    return staging


def _verify_files(release: TrustedRelease, tree: Path) -> None:
    compose = tree / release.compose_path
    try:
        info = compose.lstat()
    except OSError:
        raise ReleaseRejected("release compose file is unavailable") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ReleaseRejected("release compose file is not a regular file")
    if _sha256_file(compose) != release.compose_sha256:
        raise ReleaseRejected("release compose file does not match")
    for name, expected in release.dockerfiles.items():
        path = tree / name
        try:
            info = path.lstat()
        except OSError:
            raise ReleaseRejected("release Dockerfile is unavailable") from None
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ReleaseRejected("release Dockerfile is not a regular file")
        if _sha256_file(path) != expected:
            raise ReleaseRejected("release Dockerfile does not match")


def _assert_compose_hardened(result: AuditResult) -> None:
    data = result.data
    services = data.get("services")
    if not isinstance(services, dict) or not services:
        raise ReleaseRejected("release compose file is invalid")
    for _service, config in services.items():
        if not isinstance(config, dict):
            raise ReleaseRejected("release compose file is invalid")
        if config.get("ports"):
            raise ReleaseRejected("release compose publishes host ports")
        if config.get("privileged") is True or config.get("devices"):
            raise ReleaseRejected("release compose grants host access")
        if config.get("cap_add"):
            raise ReleaseRejected("release compose adds capabilities")
        for key in ("network_mode", "pid", "ipc"):
            if str(config.get(key, "")).strip().lower() == "host":
                raise ReleaseRejected("release compose uses a host namespace")
        for volume in config.get("volumes") or []:
            if volume_is_host_bind(volume):
                raise ReleaseRejected("release compose contains a host bind")
        readonly_files = config.get("x-spanel-readonly-files")
        if readonly_files is not None:
            if not isinstance(readonly_files, list) or not readonly_files:
                raise ReleaseRejected("release compose contains invalid file injection metadata")
            compose_file = result.compose.relative_to(result.root)
            if not all(
                readonly_release_file(item, result.root, compose_file)
                for item in readonly_files
            ):
                raise ReleaseRejected("release compose contains invalid file injection metadata")
            canonical = sorted(
                readonly_files,
                key=lambda item: (item["source"], item["target"]),
            )
            if readonly_files != canonical or len({
                (item["source"], item["target"]) for item in readonly_files
            }) != len(readonly_files):
                raise ReleaseRejected("release compose contains invalid file injection metadata")
        sysctls = config.get("sysctls") or {}
        if sysctls != {} and sysctls != {
            "net.ipv4.ip_unprivileged_port_start": "0"
        }:
            raise ReleaseRejected("release compose contains an unsafe sysctl")
        user = config.get("user")
        if user is not None:
            text = str(user).strip().lower()
            if text in {"0", "root", "0:0", "root:root"} or text.startswith("0:"):
                raise ReleaseRejected("release compose runs as root")


def verify_release(
    root: Path,
    release: TrustedRelease,
    *,
    environ: Mapping[str, str] | None = None,
    key_ring: ReleaseKeyRing | None = None,
    policy: object | None = None,
    require_expiry: bool = True,
) -> VerifiedRelease:
    """Run every pre-build check in the normative order."""

    environ = dict(os.environ if environ is None else environ)
    ring = key_ring or ReleaseKeyRing.from_environ(environ)
    # 3. known key and valid HMAC.
    release.verify_signature(ring)
    # 4. expiry.
    if require_expiry and release.expired():
        raise ReleaseRejected("release has expired")
    # 5. artifact hash (also re-checks lstat/type/mode).
    artifact = load_artifact(root, release)
    # 6/7. extraction and tree digest.
    staging = root / "private" / "staging" / release.release_id
    tree = _extract(root, staging, artifact)
    if tree_digest(tree) != release.hardened_tree_sha256:
        discard_tree(tree)
        raise ReleaseRejected("release tree does not match")
    try:
        # 8. compose and Dockerfile hashes.
        _verify_files(release, tree)
        # 9. administered policy.
        declared = _verify_policy(release, policy)
        # 10. static audit from the verified tree.
        result = audit_project(
            tree,
            release.compose_path,
            non_root=True,
            authorized_external_networks=frozenset(
                declared.get("authorized_external_networks", [])
            ),
        )
        if result.errors:
            raise ReleaseRejected("release audit found blocking errors")
        # 11. resolved/static Compose must not expose the host.
        _assert_compose_hardened(result)
    except (AppDeployError, ValueError):
        discard_tree(tree)
        raise ReleaseRejected("release verification failed") from None
    except Exception:
        discard_tree(tree)
        raise
    return VerifiedRelease(release, tree, result, declared)
