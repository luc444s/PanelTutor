"""Network isolation specs for a cell (A.SPEC 0097 / 0096 §4.2).

Each cell publishes on a dedicated loopback address, never 127.0.0.1, and owns
its own nftables table: deprovisioning one tenant cannot drop another tenant's
rules. With skuid support access is restricted to the cell uid and the central
Traefik uid; without it the spec falls back to a per-cell netns.
"""

from __future__ import annotations

import os
from typing import Any

from .alloc import validate_slug

_TRAEFIK_UID_ENV = "SPANEL_TRAEFIK_UID"
_DEFAULT_TRAEFIK_UID = 1000  # host uid of the single central Traefik service


def traefik_uid() -> int:
    """Central Traefik host uid, configurable for hosts where it is not 1000."""
    raw = os.environ.get(_TRAEFIK_UID_ENV, "")
    if not raw:
        return _DEFAULT_TRAEFIK_UID
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{_TRAEFIK_UID_ENV} must be an integer") from None
    if not 0 < value < 2**32:
        raise ValueError(f"{_TRAEFIK_UID_ENV} out of range")
    return value


def loopback_address(index: int) -> str:
    """Derive a distinct 127.x.y.z address (never 127.0.0.1) from an index."""
    i = int(index) % (254**3)
    a = 1 + i % 254
    b = 1 + (i // 254) % 254
    c = 1 + (i // (254 * 254)) % 254
    return f"127.{a}.{b}.{c}"


def publish_port(index: int) -> int:
    return 20000 + (int(index) % 20000)


def build_network_spec(
    slug: str, alloc: dict[str, Any], mode: str
) -> dict[str, Any]:
    """Build the network mutation spec for ``mode`` (skuid or netns)."""
    slug = validate_slug(slug)
    index = int(alloc["index"])
    addr = loopback_address(index)
    uid = int(alloc["uid"])
    port = publish_port(index)
    table = f"spanel-cell-{slug}"
    spec: dict[str, Any] = {
        "slug": slug,
        "mode": mode,
        "table": table,
        "loopback_address": addr,
        "publish_port": port,
        "cell_uid": uid,
        "traefik_uid": traefik_uid(),
    }
    if mode == "skuid":
        spec["nft_rules"] = [
            (
                f"add rule inet {table} output oifname lo ip daddr {addr} "
                f"tcp dport {port} skuid {{ {uid}, {spec['traefik_uid']} }} accept"
            ),
            (
                f"add rule inet {table} output oifname lo ip daddr {addr} "
                f"tcp dport {port} drop"
            ),
        ]
    elif mode == "netns":
        spec["netns"] = f"spanel-{slug}"
        spec["veth"] = f"veth-{slug}"
    else:
        raise ValueError(f"unknown network mode: {mode!r}")
    return spec
