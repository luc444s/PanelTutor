from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from plugins.tenant.backend.container_runtime import (
    RootlessCellProvider,
)
from systutor.contracts.tenant_slugs import InvalidCellSlug, cell_slug_for


class _Db:
    def __init__(self, slug: str) -> None:
        self._tenant = SimpleNamespace(slug=slug)

    def get(self, _model, _key):
        return self._tenant


@pytest.mark.parametrize(
    ("tenant", "expected"),
    [
        ("demo", "demo"),
        ("Legalattorney.pe", "legalattorney-pe"),
        ("Consorciozia", "consorciozia"),
        ("Gestión gases industriales", "gestion-gases-industriales"),
    ],
)
def test_cell_slug_for(tenant: str, expected: str) -> None:
    assert cell_slug_for(tenant) == expected


def test_cell_slug_for_empty_is_refused() -> None:
    with pytest.raises(InvalidCellSlug):
        cell_slug_for("")


def test_rootless_provider_looks_up_the_derived_cell_slug(tmp_path: Path) -> None:
    registry = {
        "allocations": {
            "legalattorney-pe": {"uid": 60012, "index": 12, "tenant_slug": "Legalattorney.pe"}
        }
    }
    (tmp_path / "registry.json").write_text(json.dumps(registry), encoding="utf-8")

    handle = RootlessCellProvider(str(tmp_path))(_Db("Legalattorney.pe"), "t1")

    assert handle._slug == "legalattorney-pe"
    assert str(handle._socket).endswith("/cells/legalattorney-pe/docker.sock")
