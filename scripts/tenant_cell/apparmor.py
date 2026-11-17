"""Fixed AppArmor profile template with validated slug-only substitution."""

from __future__ import annotations

import hashlib

from .alloc import validate_slug

# The ONLY placeholder is {slug}. It is filled exclusively with a slug that has
# passed validate_slug, so no operator input can inject extra profile rules.
PROFILE_TEMPLATE = """#include <tunables/global>

profile spanel-cell-{slug} /usr/bin/dockerd-rootless.sh {{
  #include <abstractions/base>

  # This cell's data and runtime only -- never another tenant's cell.
  /var/lib/spanel/cells/{slug}/** rwkl,
  owner /var/lib/spanel/cells/{slug}/docker.sock rw,

  # Explicitly denied host resources.
  deny /var/run/docker.sock rw,
  deny /etc/subuid r,
  deny /etc/subgid r,
  deny /run/secrets/** r,
  deny /var/lib/spanel/cells/*/** rwkl,

  # No privilege-escalation primitives for the daemon.
  deny mount,
  deny remount,
  deny ptrace,
}}
"""


def profile_name(slug: str) -> str:
    return f"spanel-cell-{validate_slug(slug)}"


def render_profile(slug: str) -> str:
    """Render the fixed template using only a validated slug."""
    return PROFILE_TEMPLATE.format(slug=validate_slug(slug))


def profile_hash(slug: str) -> str:
    """Stable digest of the rendered profile, stored in status and compared on verify."""
    return hashlib.sha256(render_profile(slug).encode("utf-8")).hexdigest()
