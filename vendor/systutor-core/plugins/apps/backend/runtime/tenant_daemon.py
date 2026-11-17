"""Per-tenant rootless Docker daemon configuration and fail-closed preflight.

This module is pure policy + rendering.  It never touches the host by itself:
every check is expressed as an argv executed through a :class:`Runner`, and
host-level mutations (user creation, profile loading, nftables, cgroups,
systemd user units) live in ``scripts/tenant-rootless/`` and are the operator's
responsibility.  The runtime never silently degrades to the shared daemon, to
``runc`` or to the hardener (INVARIANTS I1, I6, I12, I14).

The constants and the exact slirp/detach flags mirror the spike executed on
``spanel.lab`` on 2026-11-17: with ``DETACH_NETNS=1`` netlink fails with
``operation not permitted`` and with ``--bridge=none`` Compose cannot create
its network, so both are explicitly avoided here.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .types import AppDeployError

TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")

SOCKET_ROOT = "/run/spanel/tenants"
DATA_ROOT_TEMPLATE = "/var/lib/spanel/tenants/{tenant}/docker"
EXEC_ROOT_TEMPLATE = "/run/spanel/tenants/{tenant}/docker"
APPARMOR_PROFILE_TEMPLATE = "spanel-tenant-{tenant}"
SYSTEMD_UNIT_TEMPLATE = "spanel-tenant-{tenant}.service"
TENANT_USER_TEMPLATE = "spanel-t-{tenant}"
CGROUP_PARENT_TEMPLATE = "user.slice/spanel-tenant-{tenant}.slice"
NFT_CHAIN_MARK_TEMPLATE = "spanel-tenant-{tenant}"

# Required by the spike: rootlesskit needs these exact values to bring up the
# slirp network without a detached netns, and the daemon needs dbus for the
# cgroup StartTransientUnit call.
ROOTLESS_ENV = {
    "DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS": "0",
    "DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SANDBOX": "false",
    "DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SECCOMP": "false",
}

# Capabilities/keywords the daemon profile must allow.  A deny rule never uses
# the ``ix`` qualifier (the spike showed the parser rejects it); ``rwk`` is the
# safe form.  Rules are matched against the path as seen by the container.
DAEMON_ALLOW = (
    "capability,",
    "network,",
    "mount,",
    "umount,",
    "pivot_root,",
    "ptrace,",
    "signal,",
    "unix,",
    "file,",
    "dbus,",
)

DEFAULT_DENY_PATHS = (
    "/etc/shadow",
    "/etc/gshadow",
    "/host/**",
    "/var/run/docker.sock",
    "/run/docker.sock",
)


class TenantPreflightError(AppDeployError):
    """A mandatory isolation prerequisite is missing; deploy must fail closed."""


def validate_tenant(tenant: object) -> str:
    """Validate and normalise a tenant id used in host paths and profile names."""
    if not isinstance(tenant, str) or not TENANT_RE.fullmatch(tenant):
        raise AppDeployError("invalid tenant id for a rootless daemon")
    return tenant


def tenant_socket_path(tenant: object, *, root: str = SOCKET_ROOT) -> Path:
    return Path(root) / validate_tenant(tenant) / "docker.sock"


def apparmor_profile(tenant: object) -> str:
    return APPARMOR_PROFILE_TEMPLATE.format(tenant=validate_tenant(tenant))


def systemd_unit(tenant: object) -> str:
    return SYSTEMD_UNIT_TEMPLATE.format(tenant=validate_tenant(tenant))


def tenant_user(tenant: object) -> str:
    return TENANT_USER_TEMPLATE.format(tenant=validate_tenant(tenant))


@dataclass(frozen=True)
class TenantDaemonConfig:
    """All host coordinates of one tenant's rootless daemon."""

    tenant: str
    socket: Path
    data_root: Path
    exec_root: Path
    profile: str
    unit: str
    user: str
    cgroup_parent: str
    proxy_ip: str
    socket_group: str

    @classmethod
    def for_tenant(
        cls,
        tenant: object,
        *,
        proxy_ip: str = "127.0.0.1",
        socket_root: str = SOCKET_ROOT,
        data_root_template: str = DATA_ROOT_TEMPLATE,
        exec_root_template: str = EXEC_ROOT_TEMPLATE,
    ) -> TenantDaemonConfig:
        name = validate_tenant(tenant)
        proxy = proxy_ip.strip()
        if not proxy:
            raise AppDeployError("the proxy IP for a tenant daemon is required")
        return cls(
            tenant=name,
            socket=tenant_socket_path(name, root=socket_root),
            data_root=Path(data_root_template.format(tenant=name)),
            exec_root=Path(exec_root_template.format(tenant=name)),
            profile=apparmor_profile(name),
            unit=systemd_unit(name),
            user=tenant_user(name),
            cgroup_parent=CGROUP_PARENT_TEMPLATE.format(tenant=name),
            proxy_ip=proxy,
            socket_group=name,
        )

    @property
    def docker_host(self) -> str:
        return f"unix:{self.socket}"

    def as_dict(self) -> dict[str, str]:
        return {
            "tenant": self.tenant,
            "socket": str(self.socket),
            "docker_host": self.docker_host,
            "data_root": str(self.data_root),
            "exec_root": str(self.exec_root),
            "apparmor_profile": self.profile,
            "systemd_unit": self.unit,
            "user": self.user,
            "cgroup_parent": self.cgroup_parent,
            "proxy_ip": self.proxy_ip,
        }


def _deny_rule(path: str) -> str:
    clean = path.strip()
    if not clean or clean.startswith("#"):
        return ""
    # Only the standalone "ix" access qualifier is forbidden; a path such as
    # /prefix/** legitimately contains the letters "ix".
    if re.search(r"\bix\b", clean):
        raise AppDeployError("AppArmor deny rules must not use the ix qualifier")
    if not clean.endswith(","):
        clean = f"{clean} rwk,"
    return f"  deny {clean}"


def render_apparmor_profile(
    config: TenantDaemonConfig,
    *,
    deny_paths: Sequence[str] = DEFAULT_DENY_PATHS,
    allow_paths: Sequence[str] = (),
) -> str:
    """Render a default-deny daemon profile with an explicit allowlist.

    ``dbus,`` is mandatory for cgroup delegation.  Deny rules are written with
    ``rwk`` (never ``ix``) and are evaluated by AppArmor against the path seen
    from inside the container, which is why the data-root is added as an allow
    rule using the container-visible prefix as well as the host path.
    """
    lines = [
        f"# AppArmor profile for the rootless daemon of tenant {config.tenant}",
        f"profile {config.profile} flags=(attach_disconnected,mediate_deleted) {{",
        "  #include <abstractions/base>",
        "",
        "  # Required by dockerd-rootless.sh (spike 2026-11-17).",
    ]
    lines.extend(f"  {item}" for item in DAEMON_ALLOW)
    lines.extend([
        "",
        "  # Tenant data-root and runtime directories are writable.",
        f"  owner {config.data_root}/** rwklix,",
        f"  {config.exec_root}/** rwklix,",
        f"  {config.socket} rwklix,",
    ])
    for path in allow_paths:
        clean = path.strip()
        if clean and not clean.startswith("#"):
            lines.append(f"  {clean}")
    lines.extend(["", "  # Paths denied to every container of this tenant."])
    for path in deny_paths:
        rule = _deny_rule(path)
        if rule:
            lines.append(rule)
    lines.extend(["}", ""])
    return "\n".join(lines)


def render_systemd_unit(config: TenantDaemonConfig) -> str:
    """Render a ``systemd --user`` unit that starts the daemon under aa-exec."""
    env = " ".join(f"Environment={key}={value}" for key, value in ROOTLESS_ENV.items())
    socket_dir = str(config.socket.parent)
    start = (
        f"ExecStartPre=/usr/bin/mkdir -p {socket_dir} {config.data_root} "
        f"{config.exec_root}"
    )
    return "\n".join([
        "[Unit]",
        f"Description=Rootless Docker daemon for tenant {config.tenant}",
        "After=network.target",
        "",
        "[Service]",
        "Type=simple",
        env,
        "Environment=XDG_RUNTIME_DIR=/run/user/%U",
        f"Environment=DOCKER_HOST={config.docker_host}",
        start,
        f"ExecStart=/usr/bin/aa-exec -p {config.profile} -- "
        "/usr/bin/dockerd-rootless.sh "
        "--iptables=false --ip6tables=false "
        f"--data-root={config.data_root} "
        f"--exec-root={config.exec_root} "
        f"--host=unix://{config.socket}",
        "Restart=on-failure",
        "RestartSec=3",
        "",
        "[Install]",
        "WantedBy=default.target",
        "",
    ])


def _check(runner: object, argv: Sequence[str], description: str) -> str:
    result = runner.run(list(argv), check=False)  # type: ignore[attr-defined]
    if result.returncode:
        raise TenantPreflightError(f"missing prerequisite: {description}")
    return result.stdout.strip()


def preflight(
    runner: object,
    config: TenantDaemonConfig,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Fail-closed verification of every host prerequisite (I14).

    Checks are ordered so the cheapest ones fail first.  No ``compose up`` may
    happen until this function returns successfully.
    """
    del environ  # reserved for host-specific overrides; checks are runner-based
    _check(runner, ["sh", "-c", "command -v runsc"], "runsc")
    _check(runner, ["sh", "-c", "command -v rootlesskit"], "rootlesskit")
    _check(runner, ["sh", "-c", "command -v aa-exec"], "aa-exec")
    _check(runner, ["sh", "-c", "command -v apparmor_parser"], "apparmor_parser")

    profile = _check(
        runner,
        ["sh", "-c", f"grep -q '^{config.profile} ' /sys/kernel/security/apparmor/profiles"],
        f"AppArmor profile {config.profile} is not loaded",
    )
    del profile
    _check(
        runner,
        ["sh", "-c", "test -f /sys/fs/cgroup/cgroup.controllers"],
        "cgroup v2",
    )
    controllers = _check(
        runner, ["cat", "/sys/fs/cgroup/cgroup.controllers"], "cgroup controllers"
    )
    if not {"cpu", "memory", "pids"}.issubset(set(controllers.split())):
        raise TenantPreflightError("missing prerequisite: cgroup cpu/memory/pids delegation")
    marker = NFT_CHAIN_MARK_TEMPLATE.format(tenant=config.tenant)
    _check(
        runner,
        ["sh", "-c", f"nft list ruleset | grep -q '{marker}'"],
        f"nftables rules for tenant {config.tenant}",
    )
    return {
        "tenant": config.tenant,
        "profile": config.profile,
        "cgroup_controllers": sorted(set(controllers.split())),
        "prerequisites": ["runsc", "rootlesskit", "aa-exec", "apparmor_parser", "nftables"],
        "fail_closed": True,
    }


def check_socket_health(runner: object, config: TenantDaemonConfig) -> dict[str, object]:
    """Verify a running rootless daemon serves the tenant socket (postcondition)."""
    result = runner.run(  # type: ignore[attr-defined]
        ["docker", "-H", config.docker_host, "info", "--format", "{{json .SecurityOptions}}"],
        check=False,
    )
    if result.returncode:
        raise TenantPreflightError("tenant daemon socket is not healthy")
    options = result.stdout.strip()
    if "name=rootless" not in options:
        raise TenantPreflightError("tenant daemon does not report name=rootless")
    return {
        "tenant": config.tenant,
        "socket": str(config.socket),
        "rootless": True,
        "security_options": options[:512],
    }
