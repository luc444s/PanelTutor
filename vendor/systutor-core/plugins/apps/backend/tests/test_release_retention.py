from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from plugins.apps.backend.releases import retention
from plugins.apps.backend.releases.retention import (
    configured_keep,
    kept_release_paths,
    prune_application_releases,
    prune_deployed_releases,
    prune_hardened_releases,
)


class _FakeDB:
    def __init__(self, rows: list[SimpleNamespace]) -> None:
        self.rows = rows

    def scalars(self, _statement: object) -> list[SimpleNamespace]:
        return sorted(
            self.rows,
            key=lambda row: (row.created_at, row.id),
            reverse=True,
        )


def _row(
    *,
    release: str,
    created_at: datetime,
    status: str = "running",
) -> SimpleNamespace:
    return SimpleNamespace(
        id=f"deployment-{Path(release).name}",
        release=release,
        status=status,
        created_at=created_at,
    )


def test_configured_keep_is_bounded_and_defaults() -> None:
    assert configured_keep({}) == 10
    assert configured_keep({"SPANEL_APPS_RELEASES_KEEP": "3"}) == 3
    assert configured_keep({"SPANEL_APPS_RELEASES_KEEP": "0"}) == 1
    assert configured_keep({"SPANEL_APPS_RELEASES_KEEP": "not-a-number"}) == 10


def test_prune_deployed_releases_only_touches_direct_children(tmp_path: Path) -> None:
    project = tmp_path / "app-demo"
    releases = project / "releases"
    releases.mkdir(parents=True)
    for name in ("r1", "r2", "r3", "r4"):
        (releases / name).mkdir()
        (releases / name / "source.tar.gz").write_text(name)
    outside = project / "keep-me"
    outside.mkdir()

    removed = prune_deployed_releases(project, {releases / "r3", releases / "r4"})

    assert sorted(Path(item).name for item in removed) == ["r1", "r2"]
    assert sorted(p.name for p in releases.iterdir()) == ["r3", "r4"]
    assert outside.is_dir()


def test_retention_keeps_active_newest_and_in_flight(tmp_path: Path) -> None:
    project = tmp_path / "app-demo"
    releases = project / "releases"
    releases.mkdir(parents=True)
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = []
    for index in range(6):
        path = releases / f"r{index}"
        path.mkdir()
        rows.append(
            _row(
                release=str(path),
                created_at=start + timedelta(minutes=index),
                status="building" if index == 1 else "succeeded",
            )
        )
    db = _FakeDB(rows)
    active = rows[0]  # oldest, but still active
    in_flight = rows[1]

    keep = kept_release_paths(
        db,  # type: ignore[arg-type]
        application_id="app-1",
        project_root=project,
        keep=2,
        active_deployment_id=active.id,
    )
    assert keep == {
        Path(rows[5].release),
        Path(rows[4].release),
        Path(active.release),
        Path(in_flight.release),
    }

    removed = prune_application_releases(
        db,  # type: ignore[arg-type]
        application_id="app-1",
        project_root=project,
        keep=2,
        active_deployment_id=active.id,
    )
    assert sorted(Path(item).name for item in removed) == ["r2", "r3"]
    assert sorted(p.name for p in releases.iterdir()) == [
        "r0", "r1", "r4", "r5",
    ]


def test_hardened_retention_prunes_old_unkept_only(
    tmp_path: Path, monkeypatch,
) -> None:
    base = tmp_path / "hardened" / "t1" / "a1"
    for name in ("d1", "d2", "d3"):
        (base / name).mkdir(parents=True)
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    descriptors = {
        base / "d1" / "release.json": SimpleNamespace(
            release_id="r1", created_at="2026-01-01T10:00:00+00:00"
        ),
        base / "d2" / "release.json": SimpleNamespace(
            release_id="r2", created_at="2026-01-01T09:00:00+00:00"
        ),
        base / "d3" / "release.json": SimpleNamespace(
            release_id="r3", created_at="2026-01-01T11:59:00+00:00"
        ),
    }
    monkeypatch.setattr(
        retention, "read_descriptor", lambda path: descriptors[path]
    )
    removed = prune_hardened_releases(
        tmp_path,
        tenant_id="t1",
        application_id="a1",
        keep_release_ids={"r1"},
        grace_seconds=1800,
        now=now,
    )
    assert removed == [str(base / "d2")]
    assert (base / "d1").is_dir()
    assert not (base / "d2").exists()
    assert (base / "d3").is_dir()
