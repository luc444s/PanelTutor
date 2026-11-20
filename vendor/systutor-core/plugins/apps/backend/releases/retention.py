"""Safe retention for deployed rootless release trees.

The signed release descriptor store is immutable and lives under
``hardened/<tenant>/<application>/<digest>``.  Each successful deployment also
stages a working tree under ``<project>/releases/<release>``; those trees are
the large part of the state root and grow with every deploy.

Retention keeps the active deployment plus the newest ``keep`` deployments of
the application (and any deployment still building).  Older release
trees are discarded.  The function is deliberately conservative: it only
deletes direct children of ``<project>/releases`` and never follows symlinks.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Deployment
from .store import discard_tree

DEFAULT_KEEP = 10
_IN_FLIGHT = {"building"}


def configured_keep(environ: Mapping[str, str] | None = None) -> int:
    raw = (environ or os.environ).get("SPANEL_APPS_RELEASES_KEEP", "").strip()
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_KEEP
    return max(1, value)


def kept_release_paths(
    db: Session,
    *,
    application_id: str,
    project_root: Path,
    keep: int,
    active_deployment_id: str | None,
) -> set[Path]:
    """Return release trees that retention must preserve."""
    rows = list(
        db.scalars(
            select(Deployment)
            .where(Deployment.application_id == application_id)
            .order_by(Deployment.created_at.desc(), Deployment.id.desc())
        )
    )
    selected = rows[: max(1, keep)]
    keep_ids = {row.id for row in selected}
    keep_ids.update(row.id for row in rows if row.status in _IN_FLIGHT)
    if active_deployment_id:
        keep_ids.add(active_deployment_id)
    roots: set[Path] = set()
    for row in rows:
        if row.id not in keep_ids or not row.release:
            continue
        path = Path(row.release)
        if path.parent.name == "releases" and path.parent.parent == project_root:
            roots.add(path)
    return roots


def prune_deployed_releases(project_root: Path, keep_paths: set[Path]) -> list[str]:
    """Discard release trees under ``project_root/releases`` not in keep_paths."""
    releases = Path(project_root) / "releases"
    if not releases.is_dir() or releases.is_symlink():
        return []
    removed: list[str] = []
    for path in sorted(releases.iterdir()):
        if path in keep_paths:
            continue
        # Only direct children: never recurse into an unknown layout.
        if path.parent != releases:
            continue
        discard_tree(path)
        removed.append(str(path))
    return removed


def prune_application_releases(
    db: Session,
    *,
    application_id: str,
    project_root: Path,
    keep: int,
    active_deployment_id: str | None,
) -> list[str]:
    keep_paths = kept_release_paths(
        db,
        application_id=application_id,
        project_root=Path(project_root),
        keep=keep,
        active_deployment_id=active_deployment_id,
    )
    return prune_deployed_releases(Path(project_root), keep_paths)
