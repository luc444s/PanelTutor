"""AppArmor profile for a rootless cell (A.SPEC 0096/0097).

The profile is applied by systemd's ``AppArmorProfile=`` directive on the
cell unit, so it is attached to the process at exec time regardless of which
binary rootlesskit later executes. Every executable of the startup chain is
listed with ``ix`` (inherits THIS profile): there are no transitions to
unconfined. The broad capabilities and /etc//run write rules are required by
rootlesskit's copy-up inside a private mount namespace; the host paths that
matter (rootful socket, secrets, other cells) stay explicitly denied.
"""

from __future__ import annotations

import hashlib

from .alloc import validate_slug

# Only {slug} is substituted. Literal braces are doubled for str.format().
PROFILE_TEMPLATE = """#include <tunables/global>
profile spanel-cell-{slug} flags=(attach_disconnected) {{
  #include <abstractions/base>

  # Capabilities required by rootlesskit, the setuid id mappers, nsenter and
  # dockerd inside the cell's own user/mount/net namespaces.
  capability sys_admin,
  capability dac_override,
  capability dac_read_search,
  capability setuid,
  capability setgid,
  capability sys_ptrace,
  capability sys_chroot,
  capability net_admin,
  capability chown,
  capability fowner,
  capability fsetid,
  capability net_bind_service,
  capability kill,
  capability setpcap,

  # Every executable in the startup chain inherits this profile (ix).
  /usr/bin/dockerd-rootless.sh rix,
  /usr/sbin/nft ix,
  /usr/sbin/xtables-nft-multi ix,
  /usr/sbin/iptables ix,
  /usr/sbin/ip6tables ix,
  /bin/sh ix,
  /bin/bash ix,
  /usr/bin/rootlesskit ix,
  /usr/bin/dockerd rix,
  /usr/bin/containerd rix,
  /usr/bin/containerd-shim-runc-v2 rix,
  /usr/sbin/runc rix,
  /usr/bin/docker-init ix,
  /usr/bin/git ix,
  /usr/bin/slirp4netns ix,
  /usr/bin/pasta ix,
  /usr/bin/grep ix,
  /usr/bin/id ix,
  /usr/bin/realpath ix,
  /usr/bin/rm ix,
  /usr/bin/mkdir ix,
  /usr/bin/stat ix,
  /usr/bin/nsenter ix,
  /usr/bin/sysctl ix,
  /usr/sbin/sysctl ix,
  /usr/bin/selinuxenabled ix,
  /usr/bin/chcon ix,
  /usr/bin/getsubids ix,
  /usr/bin/newuidmap ix,
  /usr/bin/newgidmap ix,
  /usr/bin/getent ix,
  /usr/bin/mount ix,
  /usr/bin/umount ix,
  /usr/bin/ip ix,
  /usr/bin/unshare ix,

  # Runtime reads of proc/sys.
  / r,
  /dev/net/tun rw,
  /tmp/ r,
  /tmp/** rwkl,
  /proc/ r,
  /proc/[0-9]*/ r,
  /proc/[0-9]*/ns/* r,
  /proc/[0-9]*/cgroup r,
  /proc/[0-9]*/mountinfo r,
  /proc/[0-9]*/task/[0-9]*/mountinfo r,
  /proc/[0-9]*/loginuid r,
  /proc/[0-9]*/oom_score_adj rw,
  /proc/[0-9]*/status r,
  /proc/[0-9]*/uid_map r,
  /proc/[0-9]*/{{uid_map,gid_map,setgroups}} w,
  /proc/self/ns/net r,
  /proc/sys/kernel/random/boot_id r,
  /proc/sys/kernel/threads-max r,
  /proc/sys/user/max_user_namespaces r,
  /proc/sys/kernel/unprivileged_userns_clone r,
  /proc/sys/net/core/somaxconn r,
  /proc/sys/kernel/keys/* r,
  /sys/kernel/mm/hugepages/ r,
  /usr/share/ca-certificates/** r,
  /proc/sys/net/ipv4/ip_forward rw,
  /proc/sys/net/ipv6/conf/** rw,
  /sys/fs/cgroup/system.slice/spanel-cell-{slug}.service/** r,
  # rootlesskit/dockerd look up the delegated cgroup of the cell's uid.
  /sys/fs/cgroup/user.slice/user-[0-9]*.slice/ r,
  /sys/fs/cgroup/user.slice/user-[0-9]*.slice/** r,

  # /etc and /run writes happen only inside rootlesskit's private tmpfs
  # copy-up (--copy-up=/etc --copy-up=/run), never on the host mounts.
  /etc/{{passwd,group,nsswitch.conf,resolv.conf,hosts}} r,
  /etc/login.defs r,
  /etc/ rwkl,
  /etc/** rwkl,
  /run/ rwkl,
  /run/** rwkl,
  /etc/.ro* rwkl,
  /etc/.ro*/ rwkl,
  /run/.ro* rwkl,
  /run/.ro*/ rwkl,
  /etc/subuid r,
  /etc/subgid r,

  # Cell-owned data only (no broad /** grant: other cells are denied by default).
  /var/lib/spanel/cells/{slug}/ rwkl,
  /var/lib/spanel/cells/{slug}/** rwkl,
  owner /var/lib/spanel/cells/{slug}/docker.sock rw,
  /run/user/[0-9]*/ rwkl,
  /run/user/[0-9]*/** rwkl,
  /home/spanel-{slug}/** rwkl,

  # Mount rules observed from a real rootlesskit boot. Targets are scoped to
  # the cell's own tmpfs copy-up paths; cross-cell mounts are denied.
  mount options=(rw, private) -> /,
  mount options=(rw, rslave) -> /,
  mount options=(rw, move) /tmp/rootlesskit-*/ -> /etc/.ro*/,
  mount options=(rw, move) /tmp/rootlesskit-*/ -> /run/.ro*/,
  mount fstype=sysfs -> /sys/,
  mount options=(ro) fstype=sysfs -> /sys/,
  mount options=(rw, bind) /run/.ro*/** -> /etc/**,
  mount fstype=tmpfs -> /etc/,
  mount fstype=tmpfs -> /run/,
  mount options=(rw, rbind) /sys/fs/cgroup/ -> /tmp/rksys*/,
  mount options=(rw, move) /tmp/rksys*/ -> /sys/fs/cgroup/,
  mount options=(rw, rbind) /etc/ -> /tmp/rootlesskit-*/,
  mount options=(rw, rbind) /run/ -> /tmp/rootlesskit-*/,
  mount options=(rw, rbind) /etc/.ro*/** -> /etc/**,
  mount options=(rw, rbind) /run/.ro*/** -> /etc/**,
  mount fstype=tmpfs options=(rw, nosuid, nodev, noexec) -> /tmp/,
  mount fstype=overlay overlay -> /var/lib/spanel/cells/{slug}/**,
  mount fstype=overlay -> /var/lib/spanel/cells/{slug}/**,
  mount fstype=overlay overlay -> /run/user/[0-9]*/**,
  mount fstype=overlay -> /run/user/[0-9]*/**,
  mount fstype=overlay overlay -> /run/.ro*/**,
  mount fstype=overlay -> /run/.ro*/**,
  mount options=(rw, rbind) /var/lib/spanel/cells/{slug}/** -> /run/.ro*/**,
  mount options=(rw, rbind) /var/lib/spanel/cells/{slug}/** -> /var/lib/spanel/cells/{slug}/**,
  umount /run/.ro*/**,
  umount /var/lib/spanel/cells/{slug}/**,
  # No blanket "deny mount -> cells/*/**" here: AppArmor's '*' also matches
  # this cell and would override the allow rules above. Other cells are
  # unreachable because no rule grants their paths.

  # Container networking inside the cell's netns.
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  network unix stream,

  # setns between processes of this same cell only; cross-tenant is denied.
  ptrace (read, readby) peer=spanel-cell-{slug},

  # Host resources that must never be reachable.
  audit deny /var/run/docker.sock rw,
  audit deny /run/secrets/** r,
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
