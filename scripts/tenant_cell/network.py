"""Network isolation specs for a cell (A.SPEC 0097 / 0096 §4.2).

Each cell publishes on a dedicated loopback address, never 127.0.0.1, and owns
its own nftables table: deprovisioning one tenant cannot drop another tenant's
rules. With skuid support access is restricted to the cell uid and the central
Traefik uid; without it the spec falls back to a per-cell netns.
"""

from __future__ import annotations

import os
import re
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from .alloc import validate_slug

_TRAEFIK_UID_ENV = "SPANEL_TRAEFIK_UID"
_DEFAULT_TRAEFIK_UID = 1000  # host uid of the single central Traefik service
_CELL_DNS_ENV = "SPANEL_TENANT_CELL_DNS"
_CELL_NET_ENV = "SPANEL_TENANT_CELL_NET"
# Host policy: slirp4netns is the only driver allowed for newly created cells.
# The gvisor entry stays for backwards compatibility with already-provisioned
# cells only; no new cell may select it.
_DEFAULT_CELL_NET = "slirp4netns"
# Each rootlesskit network driver has its own gateway/DNS. Passing slirp's
# 10.0.2.3 to a gvisor-tap-vsock cell leaves every container without DNS
# (`EAI_AGAIN`), which broke apt/npm inside the cell. The default follows slirp.
_CELL_NET_DNS = {
    "slirp4netns": "10.0.2.3",
    "gvisor-tap-vsock": "10.0.2.1",
}
# A.SPEC 0109-R3: the default bridge of each rootless cell.  The NAT rule that
# gives containers egress lives *inside* the cell netns; --iptables=false on the
# daemon is preserved and no host iptables rule is ever installed.
_CELL_EGRESS_ENV = "SPANEL_TENANT_CELL_EGRESS_SUBNET"
_CELL_EGRESS_IFACE_ENV = "SPANEL_TENANT_CELL_EGRESS_IFACE"
# Docker assigns the cell bridges sequentially (docker0 172.17, then 172.18,
# 172.19, ...). A single 172.17/16 rule left real WordPress containers without
# egress NAT; the whole RFC1918 /12 covers every bridge the cell can create.
# It is always paired with `-o <iface>` so intra-cell bridge traffic is never
# masqueraded. Narrow to explicit /16 CIDRs with the env var if desired.
_DEFAULT_CELL_EGRESS = "172.16.0.0/12"
_DEFAULT_CELL_EGRESS_IFACE = "tap0"  # slirp4netns side inside the cell netns
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
# The builtin rootlesskit port driver honours the requested host IP, so a cell
# can publish on its dedicated 127.x.y.z:20000+ address.  The slirp4netns port
# driver only binds 127.0.0.1, which is why the old cells had no listener.
_ROOTLESSKIT_PORT_DRIVER = "builtin"


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


def cell_network_driver() -> str:
    """RootlessKit network driver used by each cell.

    Defaults to slirp4netns per host policy; the env override exists only to
    keep legacy gvisor-tap-vsock cells reachable, never for new provisioning.
    """
    raw = os.environ.get(_CELL_NET_ENV, _DEFAULT_CELL_NET).strip().lower()
    if raw not in _CELL_NET_DNS:
        allowed = ", ".join(sorted(_CELL_NET_DNS))
        raise ValueError(f"{_CELL_NET_ENV} must be one of: {allowed}")
    return raw


def cell_dns_resolver() -> str:
    """Validated resolver for the configured rootlesskit network driver.

    ``SPANEL_TENANT_CELL_DNS`` always wins. Otherwise the default follows the
    driver: slirp4netns serves DNS on 10.0.2.3 (the host default), while
    gvisor-tap-vsock serves it on its gateway 10.0.2.1 (legacy cells only).
    """
    default = _CELL_NET_DNS[cell_network_driver()]
    raw = os.environ.get(_CELL_DNS_ENV, default).strip()
    try:
        resolver = IPv4Address(raw)
    except ValueError:
        raise ValueError(f"{_CELL_DNS_ENV} must be an IPv4 address") from None
    if resolver.is_loopback or resolver.is_multicast or resolver.is_unspecified:
        raise ValueError(f"{_CELL_DNS_ENV} must be a reachable unicast resolver")
    return str(resolver)


def loopback_address(index: int) -> str:
    """Derive a distinct 127.x.y.z address (never 127.0.0.1) from an index."""
    i = int(index) % (254**3)
    a = 1 + i % 254
    b = 1 + (i // 254) % 254
    c = 1 + (i // (254 * 254)) % 254
    return f"127.{a}.{b}.{c}"


def publish_port(index: int) -> int:
    return 20000 + (int(index) % 20000)


def _validate_egress_subnet(raw: str) -> str:
    try:
        network = IPv4Network(raw, strict=False)
    except ValueError:
        raise ValueError(f"{_CELL_EGRESS_ENV} must be an IPv4 CIDR") from None
    if network.is_loopback or network.is_multicast or network.is_unspecified:
        raise ValueError(f"{_CELL_EGRESS_ENV} must be a unicast subnet")
    if network.prefixlen == 0:
        raise ValueError(f"{_CELL_EGRESS_ENV} must not be the whole IPv4 space")
    return str(network)


def egress_subnets() -> list[str]:
    """Validated CIDRs that receive MASQUERADE inside each cell netns.

    The env var accepts a comma/whitespace separated list so a host can pin the
    exact bridges it uses (e.g. ``172.18.0.0/16,172.19.0.0/16``). The default
    RFC1918 /12 covers docker0 and every br-* network a cell may create.
    """
    raw = os.environ.get(_CELL_EGRESS_ENV, "").strip()
    if not raw:
        return [_DEFAULT_CELL_EGRESS]
    subnets: list[str] = []
    for item in re.split(r"[,\s]+", raw):
        if not item:
            continue
        value = _validate_egress_subnet(item)
        if value not in subnets:
            subnets.append(value)
    if not subnets:
        return [_DEFAULT_CELL_EGRESS]
    return subnets


def egress_subnet() -> str:
    """First configured egress CIDR, kept for legacy single-subnet callers."""
    return egress_subnets()[0]


def cell_egress_iface() -> str:
    """Egress interface inside the cell netns (slirp4netns tap0 by default).

    Restricting MASQUERADE to this interface is what keeps WP -> MariaDB traffic
    between the cell's bridges from being rewritten by the NAT rule.
    """
    iface = os.environ.get(_CELL_EGRESS_IFACE_ENV, _DEFAULT_CELL_EGRESS_IFACE).strip()
    if not _IFACE_RE.fullmatch(iface):
        raise ValueError(
            f"{_CELL_EGRESS_IFACE_ENV} must be a network interface name (1-15 chars)"
        )
    return iface


def masquerade_argv(
    subnet: str | None = None,
    action: str = "-A",
    iface: str | None = None,
) -> list[str]:
    """iptables argv for the cell-netns POSTROUTING MASQUERADE rule.

    ``action`` is ``-A`` (append), ``-C`` (check, for idempotency) or ``-D``
    (delete, for deprovision). The rule is bound to the slirp egress interface
    so intra-cell bridge traffic is never masqueraded. ``nsenter`` must enter
    both the user and network namespaces: iptables needs CAP_NET_ADMIN in the
    user namespace that owns the cell's netns.
    """
    if action not in {"-A", "-C", "-D"}:
        raise ValueError(f"unsupported iptables action: {action!r}")
    return [
        "iptables", "-t", "nat", action, "POSTROUTING",
        "-s", subnet or egress_subnet(),
        "-o", iface or cell_egress_iface(),
        "-j", "MASQUERADE",
    ]


def netns_masquerade_argv(
    dockerd_pid: int,
    subnet: str | None = None,
    action: str = "-A",
    iface: str | None = None,
) -> list[str]:
    """Build a root-only command targeting the cell dockerd network namespace."""
    pid = int(dockerd_pid)
    if pid <= 0:
        raise ValueError("dockerd pid must be positive")
    return [
        "/usr/bin/nsenter", "-t", str(pid), "-U", "-n", "--",
        *masquerade_argv(subnet, action, iface),
    ]


def rootlesskit_port_driver_env(index: int) -> dict[str, str]:
    """RootlessKit settings that publish a cell on 127.x.y.z:20000+.

    ``builtin`` binds the parent IP supplied by Docker's port binding; the
    slirp4netns port driver only ever binds 127.0.0.1, so the dedicated cell
    loopback had no listener (GAP-0109R-7).  The publish address/port are
    returned as evidence for the relay endpoint, not as extra env variables.
    """
    return {"DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER": _ROOTLESSKIT_PORT_DRIVER}


def relay_port(index: int) -> int:
    """Stable host-side relay port for a cell (A.SPEC 0104).

    Disjoint from ``publish_port``: the cell publishes on 20000+index inside
    its loopback, while the unprivileged relay listens on 40000+index on the
    gateway of the proxy network. No nft rule or cell port is changed.
    """
    return 40000 + int(index)


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
    subnets = egress_subnets()
    iface = cell_egress_iface()
    spec: dict[str, Any] = {
        "slug": slug,
        "mode": mode,
        "table": table,
        "loopback_address": addr,
        "publish_port": port,
        "cell_uid": uid,
        "traefik_uid": traefik_uid(),
        # A.SPEC 0109-R3: egress and publication are cell facts, carried on
        # every spec so provisioning and deprovisioning use the same truth.
        "egress_subnet": subnets[0],
        "egress_subnets": subnets,
        "egress_iface": iface,
        "egress": {
            "subnet": subnets[0],
            "check": masquerade_argv(subnets[0], "-C", iface),
            "add": masquerade_argv(subnets[0], "-A", iface),
            "delete": masquerade_argv(subnets[0], "-D", iface),
        },
        "egress_rules": [
            {
                "subnet": subnet,
                "check": masquerade_argv(subnet, "-C", iface),
                "add": masquerade_argv(subnet, "-A", iface),
                "delete": masquerade_argv(subnet, "-D", iface),
            }
            for subnet in subnets
        ],
        "rootlesskit_env": rootlesskit_port_driver_env(index),
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
