"""Canonical cell slug derived from a free-form kernel tenant slug.

The tenant table stores arbitrary slugs (up to 100 characters, dots,
uppercase, spaces), but rootless cells key their registry, paths, units,
cgroups and AppArmor profiles by ``[a-z0-9][a-z0-9-]{0,61}``.  Both the tenant
and apps plugins use this single derivation so the DB slug and the cell slug
never get confused.
"""

from __future__ import annotations

import re
import unicodedata

CELL_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,61}$")
MAX_CELL_SLUG = 62


class InvalidCellSlug(ValueError):
    """The tenant slug cannot produce a valid cell slug."""


def cell_slug_for(tenant_slug: str) -> str:
    """Derive the canonical, stable cell slug for a kernel tenant slug.

    ``Legalattorney.pe`` -> ``legalattorney-pe``.  Already-canonical slugs are
    returned verbatim, so the function is idempotent.
    """
    if not isinstance(tenant_slug, str) or not tenant_slug.strip():
        raise InvalidCellSlug("tenant slug must be a non-empty string")
    raw = tenant_slug.strip()
    if CELL_SLUG_RE.fullmatch(raw):
        return raw
    plain = unicodedata.normalize("NFKD", raw).encode("ascii", "ignore").decode()
    candidate = re.sub(r"[^a-z0-9]+", "-", plain.lower()).strip("-")
    candidate = candidate[:MAX_CELL_SLUG].rstrip("-")
    if not CELL_SLUG_RE.fullmatch(candidate):
        raise InvalidCellSlug(f"tenant slug {tenant_slug!r} has no valid cell slug")
    return candidate
