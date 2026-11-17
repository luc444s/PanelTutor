from __future__ import annotations

import io
import tarfile
from pathlib import Path

from plugins.apps.backend.hardening.engine import _tree_digest
from plugins.apps.backend.releases.verify import tree_digest
from plugins.apps.backend.symlinks import symlink_target


def test_trailing_slash_symlink_round_trips_through_release_tar(
    tmp_path: Path,
) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "agents2").mkdir()
    (root / "agents").symlink_to("agents2/")

    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", dereference=False) as archive:
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            archive.add(path, arcname=(Path("source") / relative).as_posix(),
                        recursive=False)
    stream.seek(0)
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    with tarfile.open(fileobj=stream, mode="r:gz") as archive:
        archive.extractall(extracted, filter="data")

    assert symlink_target(root / "agents") == "agents2"
    assert _tree_digest(root) == tree_digest(root)
    assert _tree_digest(root) == tree_digest(extracted / "source")
