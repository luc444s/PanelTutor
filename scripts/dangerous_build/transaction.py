"""Atomic publication with verifiable backups and rollback."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class PublicationError(RuntimeError):
    """Candidate files could not be published or restored safely."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class Publication:
    root: Path
    backup_root: Path
    relatives: tuple[Path, ...]

    def rollback(self) -> None:
        failures: list[str] = []
        for relative in self.relatives:
            source = self.backup_root / "files" / relative
            target = self.root / relative
            try:
                _replace_from(source, target)
            except OSError:
                failures.append(relative.as_posix())
        if failures:
            raise PublicationError("rollback failed for: " + ", ".join(failures))


def _replace_from(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    os.close(descriptor)
    temp_path = Path(temporary)
    try:
        shutil.copy2(source, temp_path)
        os.replace(temp_path, target)
    finally:
        temp_path.unlink(missing_ok=True)


def publish(
    root: Path,
    candidate: Path,
    relatives: tuple[Path, ...],
    *,
    metadata: dict[str, object] | None = None,
) -> Publication:
    """Publish all candidate files or restore every original on failure."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    backup_root = root.parent / ".spanel-build-backups" / root.name / stamp
    files_root = backup_root / "files"
    files_root.mkdir(parents=True, mode=0o700)
    manifest: dict[str, object] = {
        "created_at": stamp,
        "root": str(root),
        "files": [],
        "metadata": metadata or {},
    }
    for relative in relatives:
        original = root / relative
        fixed = candidate / relative
        if not original.is_file() or not fixed.is_file():
            raise PublicationError(f"transaction path is not a regular file: {relative}")
        backup = files_root / relative
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, backup)
        manifest["files"].append(
            {
                "path": relative.as_posix(),
                "before_sha256": _sha256(original),
                "after_sha256": _sha256(fixed),
            }
        )
    manifest_path = backup_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path.chmod(0o600)
    publication = Publication(root, backup_root, relatives)
    published: list[Path] = []
    try:
        for relative in relatives:
            _replace_from(candidate / relative, root / relative)
            published.append(relative)
    except OSError as exc:
        try:
            for relative in reversed(published):
                _replace_from(files_root / relative, root / relative)
        except OSError as rollback_exc:
            raise PublicationError("publication and rollback both failed") from rollback_exc
        raise PublicationError("publication failed; originals were restored") from exc
    return publication
