"""Slug validation and the persistent uid/subuid registry (A.SPEC 0097).

Allocation lives in a small local JSON file under the cell data root (no DB,
no backend changes in this phase). Indexes are monotonic and retired cells get
a tombstone, so a uid/subuid block is never handed to a second tenant.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,61}$")
REGISTRY_NAME = "registry.json"
DEFAULT_BASE_UID = 60000
DEFAULT_BLOCK_SIZE = 65536

# A.SPEC 0099: new cells use the systemd cgroup driver (with a user-unit
# dockerd), because cgroupfs silently ignores container resource limits on a
# cgroup v2 host. Allocations without the field are legacy cgroupfs cells and
# are NEVER migrated implicitly.
DEFAULT_CGROUP_DRIVER = "systemd"
LEGACY_CGROUP_DRIVER = "cgroupfs"
CGROUP_DRIVERS = (DEFAULT_CGROUP_DRIVER, LEGACY_CGROUP_DRIVER)


def cgroup_driver(cell: dict[str, Any]) -> str:
    """Driver persisted for a cell; missing means pre-0099 (legacy) cell."""
    return str(cell.get("cgroup_driver", LEGACY_CGROUP_DRIVER))


class InvalidSlug(ValueError):
    """Raised for any slug that does not match the contract regex."""


class SlugRetired(ValueError):
    """Raised when a retired slug tries to reclaim its (never-reused) block."""


class SlugCollision(ValueError):
    """Two DB tenant slugs derived the same cell slug."""


def validate_slug(slug: str) -> str:
    """Validate before ANY filesystem or system change (INVARIANT 2)."""
    if not isinstance(slug, str) or not SLUG_RE.fullmatch(slug):
        raise InvalidSlug(f"invalid slug: {slug!r}")
    return slug.lower()


def registry_path(data_root: str | Path) -> Path:
    return Path(data_root) / REGISTRY_NAME


def cell_dir(data_root: str | Path, slug: str) -> Path:
    """Cell paths derive only from the validated slug (INVARIANT 7)."""
    return Path(data_root) / "cells" / validate_slug(slug)


def default_registry() -> dict[str, Any]:
    return {
        "version": 1,
        "base_uid": DEFAULT_BASE_UID,
        "block_size": DEFAULT_BLOCK_SIZE,
        "next_index": 0,
        "allocations": {},
        "tombstones": [],
    }


def load_registry(data_root: str | Path) -> dict[str, Any]:
    path = registry_path(data_root)
    if not path.exists():
        return default_registry()
    data = json.loads(path.read_text(encoding="utf-8"))
    for key, value in default_registry().items():
        data.setdefault(key, value)
    return data


def save_registry(data_root: str | Path, registry: dict[str, Any]) -> None:
    path = registry_path(data_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    tmp.replace(path)


def allocate(
    data_root: str | Path, slug: str, *, tenant_slug: str | None = None
) -> dict[str, Any]:
    """Return the existing allocation or create a fresh, never-reused one.

    ``tenant_slug`` is the authoritative kernel tenant slug (it may contain
    dots or uppercase).  It is persisted on the allocation so host-side
    consumers can map a cell slug back to the DB tenant.
    """
    slug = validate_slug(slug)
    owner = str(tenant_slug).strip() if tenant_slug is not None else slug
    if not owner:
        raise SlugCollision("tenant slug must not be empty")
    reg = load_registry(data_root)
    allocations: dict[str, dict[str, Any]] = reg["allocations"]
    if slug in allocations:
        existing = str(allocations[slug].get("tenant_slug", slug))
        if existing != owner:
            raise SlugCollision(
                f"cell slug {slug!r} is already owned by tenant {existing!r}"
            )
        return dict(allocations[slug])
    if any(t["slug"] == slug for t in reg["tombstones"]):
        raise SlugRetired(f"slug {slug!r} is retired; uid blocks are never reused")

    index = int(reg["next_index"])
    retired_indexes = {int(t["index"]) for t in reg["tombstones"]}
    while index in retired_indexes:
        index += 1
    base_uid = int(reg["base_uid"])
    block = int(reg["block_size"])
    alloc: dict[str, Any] = {
        "slug": slug,
        "index": index,
        "uid": base_uid + index,
        "gid": base_uid + index,
        "subuid_base": base_uid + block + index * block,
        "subgid_base": base_uid + block + index * block,
        "state": "provisioning",
        "applied": {},
        "cgroup_driver": DEFAULT_CGROUP_DRIVER,
        "tenant_slug": owner,
    }
    allocations[slug] = alloc
    reg["next_index"] = index + 1
    save_registry(data_root, reg)
    return dict(alloc)


def update_allocation(
    data_root: str | Path, slug: str, **changes: object
) -> dict[str, Any]:
    """Merge ``changes`` into a persisted allocation and return the new copy."""
    slug = validate_slug(slug)
    reg = load_registry(data_root)
    alloc = reg["allocations"].get(slug)
    if alloc is None:
        raise KeyError(slug)
    alloc.update(changes)
    reg["allocations"][slug] = alloc
    save_registry(data_root, reg)
    return dict(alloc)


def tenant_slug_for(data_root: str | Path, cell_slug: str) -> str:
    """Map a validated cell slug back to its kernel tenant slug.

    Allocations provisioned before this mapping existed fall back to their
    cell slug: those tenants already had canonical DB slugs.
    """
    cell_slug = validate_slug(cell_slug)
    cell = load_registry(data_root)["allocations"].get(cell_slug)
    if cell is None:
        return cell_slug
    return str(cell.get("tenant_slug") or cell_slug)


def retire(data_root: str | Path, slug: str) -> bool:
    """Move an allocation to the tombstone list so its ids are never reused."""
    slug = validate_slug(slug)
    reg = load_registry(data_root)
    alloc = reg["allocations"].get(slug)
    if alloc is None:
        return False
    tomb = {
        key: alloc[key]
        for key in ("slug", "index", "uid", "gid", "subuid_base", "subgid_base")
    }
    tomb["reason"] = "deprovisioned"
    if tomb not in reg["tombstones"]:
        reg["tombstones"].append(tomb)
    del reg["allocations"][slug]
    reg["next_index"] = max(int(reg["next_index"]), int(alloc["index"]) + 1)
    save_registry(data_root, reg)
    return True


def list_allocations(data_root: str | Path) -> list[dict[str, Any]]:
    return [dict(a) for a in load_registry(data_root)["allocations"].values()]
