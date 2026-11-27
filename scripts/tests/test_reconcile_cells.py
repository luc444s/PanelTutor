from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tenant_cell import alloc
from scripts.tenant_cell import reconcile_cells as mod


def test_seccomp_profile_is_copied_and_chowned(tmp_path, monkeypatch) -> None:
    cell = alloc.allocate(str(tmp_path), "acme")
    chowns: list[tuple[Path, int, int]] = []
    monkeypatch.setattr(
        os, "chown", lambda path, uid, gid: chowns.append((Path(path), uid, gid))
    )

    first = mod.reconcile_seccomp(tmp_path)

    dest = tmp_path / "cells" / "acme" / "cell-seccomp.json"
    assert dest.read_bytes() == mod.PROFILE.read_bytes()
    assert chowns == [(dest, cell["uid"], cell["gid"])]
    assert first[0]["seccomp"] == "updated"
    assert mod.reconcile_seccomp(tmp_path)[0]["seccomp"] == "unchanged"


def test_ingress_aio_is_disabled_once(tmp_path, monkeypatch) -> None:
    from subprocess import CompletedProcess

    alloc.allocate(str(tmp_path), "acme")
    (tmp_path / "cells" / "acme").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "is_socket", lambda self: True)
    calls: list[list[str]] = []

    def fake_docker(_socket, argv):
        calls.append(argv)
        if argv[:2] == ["inspect", "-f"]:
            return CompletedProcess(argv, 0, "true\n", "")
        if any("grep -q" in str(part) for part in argv):
            return CompletedProcess(argv, 1, "", "")
        return CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(mod, "_docker", fake_docker)

    result = mod.reconcile_ingress(tmp_path)

    assert result[0]["ingress"] == "aio-disabled"
    apply = [argv for argv in calls if "sed" in " ".join(argv)]
    assert len(apply) == 1
    assert mod.AIO_LINE in " ".join(apply[0])


def test_ingress_without_a_cell_daemon_is_skipped(tmp_path) -> None:
    alloc.allocate(str(tmp_path), "acme")
    result = mod.reconcile_ingress(tmp_path)
    assert result == [{"slug": "acme", "ingress": "no-cell-daemon"}]


def test_reconcile_provision_repairs_only_incomplete_cells(
    tmp_path, monkeypatch
) -> None:
    from scripts.tenant_cell import cells

    alloc.allocate(str(tmp_path), "done")
    alloc.update_allocation(str(tmp_path), "done", state="ready")
    alloc.allocate(str(tmp_path), "half")
    alloc.update_allocation(str(tmp_path), "half", state="provisioning")
    alloc.update_allocation(str(tmp_path), "half", tenant_slug="half")
    calls: list[tuple[str, str | None]] = []

    class FakeService:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def provision(self, slug, *, tenant_slug=None):
            calls.append((slug, tenant_slug))
            alloc.update_allocation(str(tmp_path), slug, state="ready")
            return {"slug": slug}

    monkeypatch.setattr(cells, "CellService", FakeService)

    result = mod.reconcile_provision(tmp_path)

    assert calls == [("half", "half")]
    assert {item["slug"]: item["provision"] for item in result} == {
        "done": "ready",
        "half": "repaired",
    }
    assert mod.reconcile_provision(tmp_path, dry_run=True) == [
        {"slug": "done", "provision": "ready"},
        {"slug": "half", "provision": "ready"},
    ]
