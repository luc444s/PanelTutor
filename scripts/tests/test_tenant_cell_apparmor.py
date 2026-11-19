"""Tests for the inverted AppArmor profile and cell seccomp profile (A.SPEC 0105).

The inverted model grants the cell's own rootfs broadly (read/exec) and keeps
strict rules only for host/kernel interfaces. These tests are the independent,
falsable truth for that contract: no real host is touched.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tenant_cell import apparmor

SECCOMP_PATH = ROOT / "scripts" / "tenant_cell" / "deploy" / "cell-seccomp.json"


def _profile(slug: str = "acme") -> str:
    return apparmor.render_profile(slug)


def _seccomp() -> dict:
    return json.loads(SECCOMP_PATH.read_text(encoding="utf-8"))


# --- profile_name / render_profile / profile_hash contract ------------------


def test_profile_name_uses_validated_slug() -> None:
    from scripts.tenant_cell.alloc import InvalidSlug

    assert apparmor.profile_name("acme") == "spanel-cell-acme"
    with pytest.raises(InvalidSlug):
        apparmor.profile_name("acme\n  deny /etc/** rw,")


def test_profile_hash_is_deterministic_and_slug_specific() -> None:
    digest = apparmor.profile_hash("acme")

    assert digest == apparmor.profile_hash("acme")
    assert digest != apparmor.profile_hash("other")
    assert re.fullmatch(r"[0-9a-f]{64}", digest)


# --- inverted filesystem model ----------------------------------------------


def test_render_profile_grants_broad_image_agnostic_rootfs_without_owner() -> None:
    profile = _profile()

    # A.SPEC 0109-R2: the trust boundary is the tenant, not the uid. The broad
    # grant is unqualified; other tenants are kept out by their own userns,
    # mountns and the per-cell nft skuid table, not by AppArmor ownership.
    for rule in ("/** rix,", "/** rwklix,", "/** m,"):
        assert rule in profile
    assert "owner /**" not in profile
    # `w` on the broad grant also covers creation (AppArmor 4 has no `c` mode).
    # runc's explicit root-owned exec exception and writable mmap of / remain.
    assert "/runc rix," in profile
    assert "/ mrw," in profile
    assert "/dev/tty rw," in profile
    # Image-specific entrypoints are never hand-listed (OUT OF SCOPE to add).
    for image_binary in (
        "/usr/sbin/nginx",
        "/docker-entrypoint.sh",
        "/usr/local/bin/docker-entrypoint.sh",
        "/bin/busybox",
        "/usr/bin/unpigz",
    ):
        assert f"{image_binary} ix," not in profile


def test_render_profile_drops_redundant_root_binary_and_datadir_grants() -> None:
    """A.SPEC 0109-R2: blocks that only compensated `owner` are gone."""
    profile = _profile()

    # Root-only binary grant (old lines 37-41) -- covered by /** rix and /** m.
    for rule in (
        "/{bin,sbin,usr,lib,lib64,opt,etc,srv,var/tmp,tmp,proc,sys,dev}/** rix,",
        "/{bin,sbin,usr,lib,lib64,opt,etc,srv,var/tmp,tmp,proc,sys,dev}/** m,",
        "/run/user/[0-9]*/** rix,",
    ):
        assert rule not in profile
    # Per-image datadir list (old lines 95-120) -- covered by /** rwklix.
    for datadir in (
        "/data", "/var/lib/mysql", "/var/cache", "/var/log", "/var/www",
        "/app", "/docker-entrypoint-initdb.d", "/run/mysqld", "/etc/mysql",
        "/var/lib/postgresql", "/home",
    ):
        assert f"{datadir}/ rwklix," not in profile
        assert f"{datadir}/** rwklix," not in profile
    # The BuildKit/runc consolidation was corrected after the real-build E2E
    # FAIL: AppArmor does not match a remount (no srcname, e.g.
    # flags="ro, remount, rbind") against a two-path `src -> dst` rule. The four
    # single-path/narrow rules below pre-existed in HEAD and are restored
    # verbatim -- restoring them is not adding new rules. Compare against rule
    # lines only, since the template comment quotes each one for E2E tracing.
    rule_lines = [
        line.strip()
        for line in profile.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    # The single-path remount rule is required (the request has no srcname).
    assert (
        "remount options in (ro, rw, nosuid, nodev, noexec, bind, rbind) "
        "/var/lib/spanel/cells/acme/**,"
    ) in rule_lines
    # The three read-only rbind/remount variants are restored too.
    for rule in (
        "mount options=(ro, rbind) /var/lib/spanel/cells/acme/** -> /var/lib/spanel/cells/acme/**,",
        "mount options=(ro, remount, rbind) /var/lib/spanel/cells/acme/** -> /var/lib/spanel/cells/acme/**,",
        "mount options=(ro, nosuid, nodev, noexec, remount, rbind) /var/lib/spanel/cells/acme/** -> /var/lib/spanel/cells/acme/**,",
    ):
        assert rule in rule_lines
    # The broad two-path union rule (identical to HEAD) is retained.
    assert (
        "mount options in (ro, rw, bind, rbind, remount, nosuid, nodev, noexec) "
        "/var/lib/spanel/cells/acme/** -> /var/lib/spanel/cells/acme/**," in rule_lines
    )


def test_rendered_profile_parses_when_apparmor_parser_is_available(
    tmp_path: Path,
) -> None:
    """Catch invalid syntax/modes before the lab does (GAP-0105-5, 0109-R2).

    Skipped with an explicit reason when apparmor_parser is not installed on
    the host; the E2E subagent validates the real build in the lab.
    """
    parser = shutil.which("apparmor_parser")
    if parser is None:
        pytest.skip("apparmor_parser is not installed on this host")
    profile_file = tmp_path / f"{apparmor.profile_name('acme')}.profile"
    profile_file.write_text(apparmor.render_profile("acme"), encoding="utf-8")
    result = subprocess.run(
        [parser, "-Q", str(profile_file)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_render_profile_scopes_writes_to_cell_and_image_trees() -> None:
    profile = _profile()

    assert "/var/lib/spanel/cells/acme/ rwkl," in profile
    assert "/var/lib/spanel/cells/acme/** rwkl," in profile
    assert "/home/spanel-acme/** rwkl," in profile
    assert "/run/user/[0-9]*/** rwkl," in profile
    # The cell's internal docker.sock stays explicitly allowed: intra-tenant
    # access is permitted by design (A.SPEC 0109-R2 trust decision).
    assert "owner /var/lib/spanel/cells/acme/docker.sock rw," in profile
    # No separate plain `/** rwkl,` grant (the broad grant is `/** rwklix,`),
    # and no `owner`-qualified global grant survived the simplification.
    assert "\n  /** rwkl," not in profile
    assert "\n  owner /** rwkl," not in profile


def test_render_matrix_covers_real_images_without_patching() -> None:
    """The same profile shape must serve nginx/php/MariaDB/node/Gitea cells."""
    for app in ("nginx", "php", "mariadb", "node", "gitea"):
        slug = f"cell-{app}"
        profile = _profile(slug)
        assert f"profile spanel-cell-{slug} " in profile
        assert f"/var/lib/spanel/cells/{slug}/** rwkl," in profile
        assert f"owner /var/lib/spanel/cells/{slug}/docker.sock rw," in profile
        assert "/** rix," in profile
        assert "owner /**" not in profile
        assert apparmor.profile_hash(slug) == apparmor.profile_hash(slug)
        # Image-specific entrypoints are never hand-listed.
        assert f"/usr/sbin/{app} ix," not in profile


# --- explicit host / kernel denials -----------------------------------------


def test_render_profile_denies_host_and_kernel_paths() -> None:
    profile = _profile()

    for rule in (
        "audit deny /var/run/docker.sock rw,",
        "audit deny /run/secrets/** r,",
        "audit deny /run/systemd/private rw,",
        "audit deny dbus bus=system,",
        "audit deny /proc/kcore r,",
        "audit deny /proc/[0-9]*/mem rw,",
        "audit deny /sys/kernel/** w,",
        "audit deny /dev/{sd,vd,hd,nvme}[a-z0-9]* rw,",
    ):
        assert rule in profile
    # All eight Core denials are still present -- none weakened or removed.
    assert sum(
        1 for line in profile.splitlines() if line.strip().startswith("audit deny ")
    ) == 8


def test_render_profile_has_no_other_tenant_paths() -> None:
    """A.SPEC 0109-R2: the profile must never name another tenant's cell."""
    profile = _profile("acme")

    assert "/var/lib/spanel/cells/other" not in profile
    assert "/var/lib/spanel/cells/*/" not in profile
    assert "/home/spanel-other" not in profile
    assert "/var/lib/spanel/cells/acme/** rwkl," in profile
    assert "/home/spanel-acme/** rwkl," in profile


def test_render_profile_allows_only_the_session_bus() -> None:
    profile = _profile()

    assert "dbus (send, receive) bus=session," in profile
    assert "dbus (send, receive) bus=system," not in profile
    # The redundant /run/user rix grant was folded into /** rix (0109-R2).
    assert "/run/user/[0-9]*/** rix," not in profile


def test_render_profile_has_no_complain_or_unconfined() -> None:
    profile = _profile()

    assert "unconfined" not in profile
    assert "complain" not in profile
    # Every exec grant inherits this profile (ix); no px/cx/ux transitions.
    for transition in (" ux,", " px,", " cx,"):
        assert transition not in profile


def test_render_profile_keeps_capabilities_ptrace_and_mounts_scoped() -> None:
    profile = _profile()

    for capability in (
        "sys_admin", "dac_override", "dac_read_search", "net_raw",
        "net_admin", "setuid", "setgid", "sys_chroot", "sys_ptrace",
    ):
        assert f"capability {capability}," in profile
    assert "ptrace (read, readby) peer=spanel-cell-acme," in profile
    assert (
        "mount options in (ro, rw, bind, rbind, remount, nosuid, nodev, noexec, rslave)"
        " /var/lib/spanel/cells/acme/** -> /var/lib/spanel/cells/acme/**" in profile
    )
    # GAP-0105-4: Gitea's bind mount propagates with MS_REC|MS_SLAVE.
    assert "mount options=(rw, rslave) -> /var/lib/spanel/cells/acme/**," in profile
    assert (
        "mount options=(rw, rbind) /var/tmp/** -> /var/lib/spanel/cells/acme/**,"
        in profile
    )
    assert "pivot_root /var/lib/spanel/cells/acme/**," in profile
    # No wildcard that allows mounting over another cell or the host.
    assert "mount /** -> /," not in profile
    assert "/var/lib/spanel/cells/other" not in profile


def test_single_path_remount_rule_is_present_for_no_srcname_remounts() -> None:
    """E2E 0109-R2: AppArmor will not match a remount (no srcname) to a
    two-path `src -> dst` rule, so the HEAD single-path rule must be restored.

    The real build failed at BuildKit's mount with 6 remount + 2 pivot DENIED,
    `flags="ro, remount, rbind"`, `info="failed flags match"`, when only the
    consolidated two-path rule was present. Restoring is not adding a rule.
    """
    profile = _profile()
    rule_lines = [
        line.strip()
        for line in profile.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    # Single-path remount rule (no `-> srcname`): mandatory for BuildKit.
    assert (
        "remount options in (ro, rw, nosuid, nodev, noexec, bind, rbind) "
        "/var/lib/spanel/cells/acme/**,"
    ) in rule_lines
    # All other HEAD mount rules in this block are restored as well.
    for rule in (
        "mount options=(ro, rbind) /var/lib/spanel/cells/acme/** -> /var/lib/spanel/cells/acme/**,",
        "mount options=(ro, remount, rbind) /var/lib/spanel/cells/acme/** -> /var/lib/spanel/cells/acme/**,",
        "mount options=(ro, nosuid, nodev, noexec, remount, rbind) /var/lib/spanel/cells/acme/** -> /var/lib/spanel/cells/acme/**,",
    ):
        assert rule in rule_lines


# --- seccomp profile ---------------------------------------------------------


def test_seccomp_profile_is_valid_json_and_fail_closed() -> None:
    data = _seccomp()

    assert data["defaultAction"] == "SCMP_ACT_ERRNO"
    assert data["defaultAction"] != "SCMP_ACT_ALLOW"
    assert "SCMP_ARCH_X86_64" in data["architectures"]
    assert isinstance(data["syscalls"], list) and data["syscalls"]


def test_seccomp_allowlist_covers_runtime_syscalls() -> None:
    allowed: set[str] = set()
    for entry in _seccomp()["syscalls"]:
        if entry["action"] == "SCMP_ACT_ALLOW":
            allowed.update(entry["names"])

    for syscall in (
        "clone", "execve", "mount", "umount2", "setns", "seccomp", "ptrace",
        "socket", "connect", "openat", "futex", "mmap", "read", "write",
        "fork", "vfork", "wait4", "pivot_root",
        # GAP-0105-3: container init resolves entrypoints via newfstatat.
        "newfstatat", "fstatat64",
        # GAP-0105-7: Gitea/MariaDB init needs chown, fifos and device nodes.
        "fchown", "fchownat", "lchown", "mkfifo", "mkfifoat", "mknod", "mknodat",
    ):
        assert syscall in allowed, syscall


def test_seccomp_handles_clone3_and_userfaultfd_explicitly() -> None:
    entries = {
        name: entry
        for entry in _seccomp()["syscalls"]
        for name in entry["names"]
    }

    assert entries["clone3"]["action"] == "SCMP_ACT_ERRNO"
    assert entries["clone3"]["errnoRet"] == 38  # ENOSYS -> glibc fallback
    assert entries["userfaultfd"]["action"] == "SCMP_ACT_ERRNO"
    assert entries["userfaultfd"]["errnoRet"] == 38
    # Dangerous kernel interfaces are not in the allowlist.
    for dangerous in ("bpf", "perf_event_open", "io_uring_setup"):
        assert entries[dangerous]["action"] == "SCMP_ACT_ERRNO"


# --- executor copies seccomp into the cell data-root -------------------------


def test_executor_installs_seccomp_and_references_it_in_daemon_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from scripts.tenant_cell import executor as exec_mod

    monkeypatch.setenv("SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS", "1")
    monkeypatch.setattr(
        exec_mod.subprocess,
        "run",
        lambda argv, **kwargs: SimpleNamespace(returncode=0),
    )
    cell_dir = tmp_path / "cells" / "acme"
    cell_dir.mkdir(parents=True)

    exec_mod.LocalExecutor().write_daemon_config(
        str(cell_dir), 60000, 60000, "systemd"
    )

    seccomp = cell_dir / "cell-seccomp.json"
    assert seccomp.exists()
    assert json.loads(seccomp.read_text())["defaultAction"] == "SCMP_ACT_ERRNO"
    daemon = json.loads((cell_dir / "daemon.json").read_text())
    assert daemon["exec-opts"] == ["native.cgroupdriver=systemd"]
    assert daemon["seccomp-profile"] == str(seccomp)
    # No extra mounts or Docker sockets are introduced.
    assert "hosts" not in daemon
