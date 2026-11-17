"""Helpers for repository symlinks shared by release hashing."""
from __future__ import annotations

import os
from pathlib import Path


def symlink_target(path: Path) -> str:
    """Return the link target as it is stored in the release tree.

    Git allows a trailing slash (``agents -> agents2/``) but tar extraction
    drops it.  Normalizing both sides keeps the signed tree digest stable.
    """
    target = os.readlink(path)
    return target.rstrip("/") or "/"
