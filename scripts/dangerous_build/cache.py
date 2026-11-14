"""Fail-closed cache keyed by immutable image identities."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import time
from pathlib import Path
from typing import Any


class ImageValidationCache:
    def __init__(self, directory: Path, *, scan_ttl: int, pull_ttl: int, enabled: bool):
        self.directory = directory
        self.scan_ttl = max(0, scan_ttl)
        self.pull_ttl = max(0, pull_ttl)
        self.enabled = enabled

    @staticmethod
    def _key(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def _read(self, path: Path, ttl: int) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                return None
            if time.time() - info.st_mtime > ttl:
                return None
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def _write(self, path: Path, payload: dict[str, Any]) -> None:
        if not self.enabled:
            return
        path.parent.mkdir(parents=True, mode=0o700)
        path.parent.chmod(0o700)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        os.close(descriptor)
        temp_path = Path(temporary)
        try:
            temp_path.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            temp_path.chmod(0o600)
            os.replace(temp_path, path)
        finally:
            temp_path.unlink(missing_ok=True)

    def reference(self, reference: str) -> str | None:
        payload = self._read(
            self.directory / "references" / f"{self._key(reference)}.json",
            self.pull_ttl,
        )
        digest = payload.get("digest") if payload else None
        return str(digest) if isinstance(digest, str) and "@sha256:" in digest else None

    def save_reference(self, reference: str, digest: str) -> None:
        if "@sha256:" not in digest:
            return
        self._write(
            self.directory / "references" / f"{self._key(reference)}.json",
            {"reference": reference, "digest": digest, "checked_at": time.time()},
        )

    def scan(
        self, digest: str, *, severity: str, scanner_fingerprint: str
    ) -> dict[str, Any] | None:
        if "@sha256:" not in digest:
            return None
        identity = f"{digest}\0{severity}\0{scanner_fingerprint}"
        payload = self._read(
            self.directory / "scans" / f"{self._key(identity)}.json",
            self.scan_ttl,
        )
        report = payload.get("report") if payload else None
        return report if isinstance(report, dict) else None

    def save_scan(
        self,
        digest: str,
        report: dict[str, Any],
        *,
        severity: str,
        scanner_fingerprint: str,
    ) -> None:
        if "@sha256:" not in digest:
            return
        identity = f"{digest}\0{severity}\0{scanner_fingerprint}"
        self._write(
            self.directory / "scans" / f"{self._key(identity)}.json",
            {
                "digest": digest,
                "severity": severity,
                "scanner": scanner_fingerprint,
                "scanned_at": time.time(),
                "report": report,
            },
        )


def scanner_fingerprint(executable: str) -> str:
    try:
        info = Path(executable).stat()
    except OSError:
        return "unavailable"
    return f"{Path(executable).resolve()}:{info.st_size}:{info.st_mtime_ns}"
