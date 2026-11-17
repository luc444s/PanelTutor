"""Read-only host capability probe and the ``doctor`` gate (A.SPEC 0097).

``HostProbe`` is injectable: tests subclass it with a fake to simulate every
capability green or red. ``LocalHostProbe`` is the read-only real view used by
the CLI on the lab host; it never mutates anything.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Exact capability set promised by the A.SPEC contract, in report order.
CAPABILITIES = (
    "kernel_cgroup2",
    "systemd_delegate",
    "apparmor_enabled",
    "apparmor_parser",
    "nftables_skuid",
    "subuid_range_free",
    "rootless_docker",
)


@dataclass
class DoctorReport:
    """Serializable result of ``run_doctor`` (``ready`` + per-capability detail)."""

    ready: bool = False
    capabilities: dict[str, dict[str, object]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _path_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _kernel_at_least(major: int, minor: int) -> bool:
    try:
        parts = os.uname().release.split(".")[:2]
        return (int(parts[0]), int(parts[1])) >= (major, minor)
    except (ValueError, IndexError):
        return False


def _parse_id_map(path: Path) -> list[dict[str, int]]:
    """Parse an /proc/<pid>/(uid|gid)_map into explicit host/inner/count rows.

    The map is *observed*, never derived from a formula: inner id 0 may map to
    the cell's real uid rather than to the first subuid (A.SPEC 0096 §4.1).
    """
    rows: list[dict[str, int]] = []
    for line in _path_text(path).splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            rows.append(
                {
                    "host_id": int(parts[0]),
                    "inner_id": int(parts[1]),
                    "count": int(parts[2]),
                }
            )
        except ValueError:
            continue
    return rows


class HostProbe:
    """Read-only view of the host. Override any method in a fake for tests."""

    def cgroup2_available(self) -> bool:
        return "cgroup2" in _path_text(Path("/proc/self/mountinfo"))

    def systemd_delegate(self) -> bool:
        conf = Path("/etc/systemd/system/user@.service.d/delegate.conf")
        return "Delegate=yes" in _path_text(conf)

    def apparmor_enabled(self) -> bool:
        flag = _path_text(Path("/sys/module/apparmor/parameters/enabled")).strip()
        return flag.startswith("Y")

    def apparmor_parser_available(self) -> bool:
        return shutil.which("apparmor_parser") is not None

    def nftables_skuid_supported(self) -> bool:
        return shutil.which("nft") is not None and _kernel_at_least(4, 19)

    def netns_supported(self) -> bool:
        return Path("/proc/self/ns/net").exists()

    def subuid_range_free(self) -> bool:
        subuid = Path("/etc/subuid")
        return subuid.exists() and any(
            line.strip() for line in _path_text(subuid).splitlines()
        )

    def rootless_docker_available(self) -> bool:
        return shutil.which("dockerd-rootless.sh") is not None

    def network_mode(self) -> str:
        """Pick the isolation mechanism the host actually supports."""
        if self.nftables_skuid_supported():
            return "skuid"
        if self.netns_supported():
            return "netns"
        return "none"

    def profile_effective(self, pid: int, profile: str) -> bool:
        """True when the running daemon is confined by ``profile``."""
        if pid <= 0:
            return False
        current = _path_text(Path(f"/proc/{pid}/attr/current")).strip()
        return current == profile or current.startswith(f"{profile} (")

    def daemon_pid(self, main_pid: int) -> int:
        """Resolve the dockerd child of rootlesskit's MainPID.

        systemd reports the rootlesskit parent, whose uid_map is the identity
        map.  The real per-cell mapping lives in the dockerd child, so evidence
        must be read from there.
        """
        if main_pid <= 0:
            return 0
        children = _path_text(
            Path(f"/proc/{main_pid}/task/{main_pid}/children")
        ).split()
        for child in children:
            cmdline = _path_text(Path(f"/proc/{child}/cmdline")).replace("\0", " ")
            if "dockerd" in cmdline:
                try:
                    return int(child)
                except ValueError:
                    continue
        return main_pid

    def read_uid_map(self, pid: int) -> list[dict[str, int]]:
        return _parse_id_map(Path(f"/proc/{pid}/uid_map")) if pid > 0 else []

    def read_gid_map(self, pid: int) -> list[dict[str, int]]:
        return _parse_id_map(Path(f"/proc/{pid}/gid_map")) if pid > 0 else []


def run_doctor(probe: HostProbe) -> DoctorReport:
    """Evaluate every capability through ``probe``; ready only when all pass.

    ``nftables_skuid`` is green when *network isolation* exists: skuid matching
    is preferred, but a per-cell netns is an accepted fallback (A.SPEC 0096 §8).
    """
    mode = probe.network_mode()
    checks: dict[str, tuple[bool, str]] = {
        "kernel_cgroup2": (probe.cgroup2_available(), "cgroup v2 mounted"),
        "systemd_delegate": (probe.systemd_delegate(), "Delegate=yes for user units"),
        "apparmor_enabled": (probe.apparmor_enabled(), "AppArmor enabled in kernel"),
        "apparmor_parser": (probe.apparmor_parser_available(), "apparmor_parser on PATH"),
        "nftables_skuid": (mode != "none", f"network isolation mode={mode}"),
        "subuid_range_free": (probe.subuid_range_free(), "free subuid/subgid block"),
        "rootless_docker": (probe.rootless_docker_available(), "dockerd-rootless.sh on PATH"),
    }
    capabilities: dict[str, dict[str, object]] = {}
    for name in CAPABILITIES:
        ok, detail = checks[name]
        capabilities[name] = {"ok": bool(ok), "detail": detail}
    return DoctorReport(
        ready=all(bool(cap["ok"]) for cap in capabilities.values()),
        capabilities=capabilities,
    )
