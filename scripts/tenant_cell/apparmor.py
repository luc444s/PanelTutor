"""AppArmor profile for a rootless cell (A.SPEC 0096/0097/0105).

Inverted model (0105): instead of enumerating every executable and path an image
might need, the cell's *own* filesystem is granted broadly for read/execute and
writes are scoped to the cell/image trees. The strict rules are reserved for the
host and kernel interfaces (/proc, /sys, cgroups, devices, capabilities, dbus,
mount/ptrace). This lets real images (nginx, php-fpm, MariaDB, node, Gitea) start
without hand-patching the profile while keeping the host boundary explicit.

The profile is bound to the daemon with ``aa-exec`` (systemd driver): all execs
inherit it via ``ix`` so there is no transition to another profile. Writable
``/etc``/``/run`` rules exist only for rootlesskit's private tmpfs copy-up.
"""

from __future__ import annotations

import hashlib

from .alloc import validate_slug

# Only {slug} is substituted. Literal braces are doubled for str.format().
PROFILE_TEMPLATE = """#include <tunables/global>
profile spanel-cell-{slug} flags=(attach_disconnected) {{
  #include <abstractions/base>

  # --- Broad, image-agnostic rootfs grant (the inversion) -------------------
  # Everything this cell owns -- its data-root, image layers and every rootfs
  # mapped into it -- may be read and executed. `ix` makes each exec inherit
  # this profile, so there is never a transition to a foreign profile. `m`
  # permits PROT_EXEC mappings used by dynamic loaders and JITs (node, Go).
  # Using `owner` keeps other tenants' files (different uid) out of reach even
  # though dac_override is granted to rootlesskit below.
  owner /** r/ix,
  owner /** m,

  # Root-owned host binaries/libraries/config are shared and read-only. They
  # are not covered by `owner`, so grant them explicitly (still read/exec only).
  /{{bin,sbin,usr,lib,lib64,opt,etc,srv,var/tmp,tmp,proc,sys,dev}}/** r/ix,
  /{{bin,sbin,usr,lib,lib64,opt,etc,srv,var/tmp,tmp,proc,sys,dev}}/** m,
  /run/user/[0-9]*/** r/ix,

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
  capability net_raw,
  capability kill,
  capability setpcap,

  # --- Writes scoped to the cell / image trees ------------------------------
  # No per-image path lists: any cache/log/config the image writes lands inside
  # its own rootfs, which lives under the cell data-root or home directory.
  /var/lib/spanel/cells/{slug}/ rwkl,
  /var/lib/spanel/cells/{slug}/** rwkl,
  owner /var/lib/spanel/cells/{slug}/docker.sock rw,
  /home/spanel-{slug}/** rwkl,
  /run/user/[0-9]*/ rwkl,
  /run/user/[0-9]*/** rwkl,
  /tmp/ rwkl,
  /tmp/** rwkl,

  # /etc and /run writes happen only inside rootlesskit's private tmpfs
  # copy-up (--copy-up=/etc --copy-up=/run), never on the host mounts. The
  # .ro* paths are that private snapshot.
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

  # --- /proc and /sys reads required by the daemon and containers ----------
  / r,
  /dev/net/tun rw,
  /proc/ r,
  /proc/[0-9]*/ r,
  /proc/[0-9]*/ns/* r,
  /proc/[0-9]*/cgroup r,
  /proc/[0-9]*/mountinfo r,
  /proc/[0-9]*/task/[0-9]*/mountinfo r,
  /proc/[0-9]*/loginuid r,
  /proc/[0-9]*/oom_score_adj rw,
  /proc/[0-9]*/status r,
  /proc/[0-9]*/comm r,
  /proc/[0-9]*/task/[0-9]*/fd/ r,
  /proc/[0-9]*/task/[0-9]*/fd/* rw,
  /[0-9]*/task/[0-9]*/fd/ r,
  /[0-9]*/task/[0-9]*/fd/* rw,
  /proc/thread-self/fd/* rw,
  /proc/thread-self/fd/* ix,
  /proc/self/fd/* rw,
  /proc/self/fd/* ix,
  /proc/[0-9]*/uid_map r,
  /proc/[0-9]*/{{uid_map,gid_map,setgroups}} rw,
  /proc/self/{{setgroups,uid_map,gid_map}} rw,
  /[0-9]*/{{setgroups,uid_map,gid_map}} rw,
  /proc/self/ns/net r,
  /proc/pressure/** r,
  /proc/sys/kernel/random/boot_id r,
  /proc/sys/kernel/threads-max r,
  /proc/sys/user/max_user_namespaces r,
  /proc/sys/kernel/unprivileged_userns_clone r,
  /proc/sys/net/core/somaxconn r,
  /proc/sys/kernel/keys/* r,
  /sys/kernel/mm/hugepages/ r,
  /sys/devices/** r,
  /sys/fs/cgroup/cpuset.mems.effective r,
  /usr/share/ca-certificates/** r,
  /proc/sys/net/ipv4/* rw,
  /sys/net/ipv4/* rw,
  /proc/sys/net/ipv6/conf/** rw,
  /sys/fs/cgroup/cgroup.controllers r,
  /sys/fs/cgroup/cpuset.cpus.effective r,
  /sys/fs/cgroup/system.slice/ rwkl,
  /sys/fs/cgroup/system.slice/** rwkl,
  /sys/fs/cgroup/system.slice/cgroup.type r,
  /sys/fs/cgroup/system.slice/spanel-cell-{slug}.service/** r,
  # rootlesskit/dockerd look up the delegated cgroup of the cell's uid.
  /sys/fs/cgroup/user.slice/user-[0-9]*.slice/ r,
  /sys/fs/cgroup/user.slice/user-[0-9]*.slice/** r,
  /[0-9]*/stat r,

  # --- mount rules: scoped to this cell's own trees, never over the host ----
  mount options=(rw, private) -> /,
  mount options=(rw, private) -> /var/lib/spanel/cells/{slug}/**,
  mount options=(rw, rprivate) -> /var/lib/spanel/cells/{slug}/**,
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
  mount fstype=proc options=(rw, nosuid, nodev, noexec) -> /var/lib/spanel/cells/{slug}/**,
  mount fstype=proc -> /var/lib/spanel/cells/{slug}/**,
  # Container-internal filesystems mounted by runc into the cell rootfs.
  mount fstype=tmpfs -> /var/lib/spanel/cells/{slug}/**,
  mount fstype=tmpfs options=(ro) -> /proc/**,
  mount fstype=tmpfs options=(ro) -> /sys/**,
  mount fstype=devpts -> /var/lib/spanel/cells/{slug}/**,
  mount fstype=sysfs -> /var/lib/spanel/cells/{slug}/**,
  mount fstype=mqueue -> /var/lib/spanel/cells/{slug}/**,
  mount fstype=cgroup2 -> /var/lib/spanel/cells/{slug}/**,
  mount options=(rw, rbind) /var/lib/spanel/cells/{slug}/** -> /run/.ro*/**,
  mount options=(rw, rbind) /var/lib/spanel/cells/{slug}/** -> /var/lib/spanel/cells/{slug}/**,
  # BuildKit/runc combine bind, remount and nodev flags in one call; `in`
  # matches any combination of these flags, still only inside this cell's tree.
  mount options in (ro, rw, bind, rbind, remount, nosuid, nodev, noexec) /var/lib/spanel/cells/{slug}/** -> /var/lib/spanel/cells/{slug}/**,
  remount options in (ro, rw, nosuid, nodev, noexec, bind, rbind) /var/lib/spanel/cells/{slug}/**,
  # BuildKit reads the Dockerfile by rbind-mounting a read-only snapshot, then
  # remounts it read-only; runc remounts resolv.conf/hosts inside the rootfs.
  mount options=(ro, rbind) /var/lib/spanel/cells/{slug}/** -> /var/lib/spanel/cells/{slug}/**,
  mount options=(ro, remount, rbind) /var/lib/spanel/cells/{slug}/** -> /var/lib/spanel/cells/{slug}/**,
  mount options=(ro, nosuid, nodev, noexec, remount, rbind) /var/lib/spanel/cells/{slug}/** -> /var/lib/spanel/cells/{slug}/**,
  mount options=(rw, bind) /dev/** -> /var/lib/spanel/cells/{slug}/**,
  mount options=(rw, bind) /proc/** -> /var/lib/spanel/cells/{slug}/**,
  mount options=(rw, rbind) /proc/** -> /var/lib/spanel/cells/{slug}/**,
  mount options=(rw, rbind) /proc/** -> /proc/**,
  mount options=(rw, bind) /proc/[0-9]*/ns/* -> /run/user/[0-9]*/**,
  mount options=(rw, bind) / -> /run/.ro*/**,
  mount options=(ro, nosuid, nodev, noexec, remount, bind) /** -> /proc/**,
  remount options=(ro, nosuid, nodev, noexec, bind) /proc/**,
  umount /,
  umount /run/.ro*/**,
  pivot_root /var/lib/spanel/cells/{slug}/**,
  umount /var/lib/spanel/cells/{slug}/**,
  # No blanket "deny mount -> cells/*/**": a '*' also matches this cell and
  # would override the allow rules above. Other cells are unreachable because
  # no mount rule grants their paths.

  # Container networking inside the cell's netns.
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  network unix stream,
  network packet dgram,

  # setns between processes of this same cell only; cross-tenant is denied.
  ptrace (read, readby) peer=spanel-cell-{slug},

  # A.SPEC 0099 - systemd cgroup driver. AppArmor calls the systemd *user*
  # bus "session" (not "user"); the system bus stays denied. busctl --user
  # status is how runc reads OwnerUID to decide it is rootless.
  dbus (send, receive) bus=session,
  /proc/[0-9]*/stat r,
  /proc/[0-9]*/cmdline r,
  /proc/[0-9]*/sessionid r,
  # runc writes cgroup.subtree_control and the container's limit files inside
  # the subtree delegated to this cell's uid. Scoped to this cell's uid.
  /sys/fs/cgroup/user.slice/user-[0-9]*.slice/user@[0-9]*.service/ rwkl,
  /sys/fs/cgroup/user.slice/user-[0-9]*.slice/user@[0-9]*.service/** rwkl,

  # --- Explicit host/kernel denials -----------------------------------------
  # Deny rules override any allow rule above (including the broad `owner` and
  # read-only host grants). These are the interfaces that must never be reused.
  audit deny /var/run/docker.sock rw,
  audit deny /run/secrets/** r,
  audit deny /run/systemd/private rw,
  audit deny dbus bus=system,
  audit deny /proc/kcore r,
  audit deny /proc/[0-9]*/mem rw,
  audit deny /sys/kernel/** w,
  audit deny /dev/{{sd,vd,hd,nvme}}[a-z0-9]* rw,
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
