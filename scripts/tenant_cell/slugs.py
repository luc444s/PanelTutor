"""Canonical cell slug derived from a free-form kernel tenant slug.

The kernel ``tenants.slug`` column is arbitrary text (up to 100 characters),
but a rootless cell uses its slug for filesystem paths, systemd units,
cgroups, AppArmor profiles and the privileged agent protocol.  Those consumers
require ``[a-z0-9][a-z0-9-]{0,61}``.

This module is the single host-side definition of that derivation: the DB
tenant slug stays authoritative for panel/API lookups, while the derived cell
slug is used only for cell artifacts.
"""

from __future__ import annotations

import re
import unicodedata

from .alloc import SLUG_RE, InvalidSlug, validate_slug

MAX_CELL_SLUG = 62


def cell_slug_for(tenant_slug: str) -> str:
    """Derive the canonical, stable cell slug for a DB tenant slug.

    ``Legalattorney.pe`` -> ``legalattorney-pe``; ``Consorciozia`` ->
    ``consorciozia``.  An already-canonical slug is returned verbatim so this
    function is idempotent and existing cells keep their names.
    """
    if not isinstance(tenant_slug, str) or not tenant_slug.strip():
        raise InvalidSlug("tenant slug must be a non-empty string")
    raw = tenant_slug.strip()
    if SLUG_RE.fullmatch(raw):
        return raw
    plain = unicodedata.normalize("NFKD", raw).encode("ascii", "ignore").decode()
    candidate = re.sub(r"[^a-z0-9]+", "-", plain.lower()).strip("-")
    candidate = candidate[:MAX_CELL_SLUG].rstrip("-")
    try:
        return validate_slug(candidate)
    except InvalidSlug as exc:
        raise InvalidSlug(
            f"tenant slug {tenant_slug!r} has no valid cell slug"
        ) from exc
