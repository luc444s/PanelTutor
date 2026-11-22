"""Secret-free JSONL audit log for mutating commands (A.SPEC 0097).

Every record carries ``tenant_slug``, ``verb`` and ``exit_code``. A sanitizer
redacts secret-looking keys/values so no log line can leak a password/token to
the backend.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

AUDIT_NAME = "audit.jsonl"
_SECRET_KEYS = {
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "credential",
    "credentials",
}
_SECRET_MARKERS = ("password=", "token=", "secret=", "sshpass", "api_key=")


def audit_path(data_root: str | Path) -> Path:
    return Path(data_root) / AUDIT_NAME


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        if any(marker in value.lower() for marker in _SECRET_MARKERS):
            return "[redacted]"
        return value
    if isinstance(value, dict):
        return {
            key: (
                "[redacted]"
                if str(key).lower() in _SECRET_KEYS
                else _clean(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_clean(item) for item in value]
    return value


def write_audit(
    data_root: str | Path,
    *,
    tenant_slug: str,
    verb: str,
    exit_code: int,
    **extra: Any,
) -> dict[str, Any]:
    """Append one sanitized JSON record and return it."""
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tenant_slug": tenant_slug,
        "verb": verb,
        "exit_code": int(exit_code),
    }
    for key, value in extra.items():
        if key not in record:
            record[key] = _clean(value)
    path = audit_path(data_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def read_audit(data_root: str | Path) -> list[dict[str, Any]]:
    """Read all audit records (used by tests and local inspection)."""
    path = audit_path(data_root)
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
