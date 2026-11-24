from __future__ import annotations

from pathlib import Path

import pytest

from scripts.tenant_cell import alloc
from scripts.tenant_cell.slugs import cell_slug_for


@pytest.mark.parametrize(
    ("tenant", "expected"),
    [
        ("demo", "demo"),
        ("miltonarquez", "miltonarquez"),
        ("legalattorney", "legalattorney"),
        ("Legalattorney.pe", "legalattorney-pe"),
        ("Consorciozia", "consorciozia"),
        ("Gestión gases industriales", "gestion-gases-industriales"),
        ("  Demo  ", "demo"),
    ],
)
def test_cell_slug_for(tenant: str, expected: str) -> None:
    assert cell_slug_for(tenant) == expected


def test_cell_slug_for_is_idempotent() -> None:
    assert cell_slug_for(cell_slug_for("Legalattorney.pe")) == "legalattorney-pe"


def test_cell_slug_for_empty_is_refused() -> None:
    with pytest.raises(alloc.InvalidSlug):
        cell_slug_for("")


def test_allocation_persists_and_maps_back(tmp_path: Path) -> None:
    cell = alloc.allocate(tmp_path, "legalattorney-pe", tenant_slug="Legalattorney.pe")
    assert cell["tenant_slug"] == "Legalattorney.pe"
    assert alloc.tenant_slug_for(tmp_path, "legalattorney-pe") == "Legalattorney.pe"


def test_allocation_rejects_a_second_owner(tmp_path: Path) -> None:
    alloc.allocate(tmp_path, "legalattorney-pe", tenant_slug="Legalattorney.pe")
    with pytest.raises(alloc.SlugCollision):
        alloc.allocate(tmp_path, "legalattorney-pe", tenant_slug="legalattorney-pe")


def test_legacy_allocation_maps_to_its_own_slug(tmp_path: Path) -> None:
    alloc.allocate(tmp_path, "milton")
    assert alloc.tenant_slug_for(tmp_path, "milton") == "milton"


def test_unknown_cell_maps_to_its_own_slug(tmp_path: Path) -> None:
    assert alloc.tenant_slug_for(tmp_path, "demo") == "demo"
