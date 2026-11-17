"""Provisioning orchestration: gate, idempotent apply, status and rollback.

All mutations go through the injectable ``Executor``; the service never talks
to the network or to a remote host. ``LocalExecutor`` is the gated real-world
adapter and is never invoked by tests or by ``--help``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import alloc, apparmor, audit, network
from .doctor import DoctorReport, HostProbe, run_doctor
from .executor import Executor  # re-exported for tests


class ProvisionRefused(Exception):
    """Raised when the doctor gate is red; carries the full report."""

    def __init__(self, report: DoctorReport) -> None:
        self.report = report
        super().__init__("doctor gate is not ready; refusing to provision")


class CellNotFound(Exception):
    """Raised when an operation targets a slug with no allocation."""


class CellService:
    """Doctor-gated, idempotent cell lifecycle keyed by a validated slug."""

    def __init__(
        self, probe: HostProbe, executor: Executor, data_root: str | Path
    ) -> None:
        self.probe = probe
        self.executor = executor
        self.data_root = Path(data_root)

    def cell_dir(self, slug: str) -> Path:
        return alloc.cell_dir(self.data_root, slug)

    def socket_path(self, slug: str) -> Path:
        return self.cell_dir(slug) / "docker.sock"

    def cgroup_path(self, slug: str) -> str:
        return f"/system.slice/spanel-cell-{slug}.scope"

    def status(self, slug: str) -> dict[str, Any]:
        """Effective state; uid_map is read from the host, never assumed."""
        slug = alloc.validate_slug(slug)
        reg = alloc.load_registry(self.data_root)
        cell = reg["allocations"].get(slug)
        if cell is None:
            raise CellNotFound(slug)
        main_pid = int(cell.get("daemon_pid", 0))
        pid = self.probe.daemon_pid(main_pid)
        return {
            "state": cell.get("state", "unknown"),
            "slug": slug,
            "uid": cell["uid"],
            "uid_map": self.probe.read_uid_map(pid),
            "gid_map": self.probe.read_gid_map(pid),
            "socket_path": str(self.socket_path(slug)),
            "apparmor": {
                "profile": apparmor.profile_name(slug),
                # Effective profile is observed live, never trusted from the
                # value cached at provision time (A.SPEC 0096 correction 2).
                "effective": (
                    self.probe.profile_effective(pid, apparmor.profile_name(slug))
                    if pid > 0
                    else bool(cell.get("apparmor_effective", False))
                ),
                "hash": cell.get("apparmor_hash", apparmor.profile_hash(slug)),
            },
            "cgroup_path": self.cgroup_path(slug),
            "network_mode": cell.get("network_mode", "skuid"),
        }

    def list_cells(self) -> list[dict[str, Any]]:
        return [
            {
                "slug": cell["slug"],
                "state": cell.get("state", "unknown"),
                "uid": cell["uid"],
                "socket_path": str(self.socket_path(cell["slug"])),
            }
            for cell in alloc.list_allocations(self.data_root)
        ]

    def provision(self, slug: str) -> dict[str, Any]:
        """Refuse with zero cell changes unless doctor is green; else apply once."""
        slug = alloc.validate_slug(slug)  # INVARIANT 2: before any change
        report = run_doctor(self.probe)
        if not report.ready:
            audit.write_audit(
                self.data_root,
                tenant_slug=slug,
                verb="provision",
                exit_code=2,
                ready=False,
            )
            raise ProvisionRefused(report)

        cell = alloc.allocate(self.data_root, slug)
        applied: dict[str, bool] = dict(cell.get("applied", {}))
        name = f"spanel-{slug}"

        if not applied.get("identity"):
            self.executor.ensure_user(name, cell["uid"], cell["gid"])
            self.executor.ensure_subids(
                name,
                cell["uid"],
                cell["subuid_base"],
                cell["subgid_base"],
                int(alloc.load_registry(self.data_root)["block_size"]),
            )
            applied["identity"] = True
        if not applied.get("dirs"):
            self.executor.ensure_dirs(str(self.cell_dir(slug)), cell["uid"], cell["gid"])
            applied["dirs"] = True
        if not applied.get("apparmor"):
            self.executor.install_profile(
                apparmor.profile_name(slug), apparmor.render_profile(slug)
            )
            applied["apparmor"] = True

        mode = self.probe.network_mode()
        if not applied.get("network"):
            self.executor.apply_network(
                network.build_network_spec(slug, cell, mode)
            )
            applied["network"] = True
        if not applied.get("systemd"):
            self.executor.install_systemd_unit(
                slug, cell["uid"], self.cgroup_path(slug)
            )
            applied["systemd"] = True
        if applied.get("daemon"):
            pid = int(cell.get("daemon_pid", 0))
        else:
            pid = int(self.executor.start_daemon(slug) or 0)
            applied["daemon"] = True

        alloc.update_allocation(
            self.data_root,
            slug,
            # A cell without a running daemon is degraded, never "ready".
            state="ready" if pid > 0 else "degraded",
            applied=applied,
            daemon_pid=pid,
            network_mode=mode,
            apparmor_hash=apparmor.profile_hash(slug),
            apparmor_effective=(
                pid > 0 and self.probe.profile_effective(pid, apparmor.profile_name(slug))
            ),
        )
        audit.write_audit(
            self.data_root, tenant_slug=slug, verb="provision", exit_code=0,
            state="ready",
        )
        return self.status(slug)

    def deprovision(self, slug: str, keep_data: bool = True) -> dict[str, Any]:
        """Tear down daemon/unit/network/profile; keep data unless purged."""
        slug = alloc.validate_slug(slug)
        reg = alloc.load_registry(self.data_root)
        cell = reg["allocations"].get(slug)
        if cell is None:
            state = (
                "retired"
                if any(t["slug"] == slug for t in reg["tombstones"])
                else "absent"
            )
            audit.write_audit(
                self.data_root, tenant_slug=slug, verb="deprovision",
                exit_code=0, state=state,
            )
            return {"slug": slug, "state": state, "data_kept": False}

        applied = cell.get("applied", {})
        if applied.get("daemon"):
            self.executor.stop_daemon(slug)
        if applied.get("systemd"):
            self.executor.remove_systemd_unit(slug)
        if applied.get("network"):
            spec = network.build_network_spec(
                slug, cell, cell.get("network_mode", "skuid")
            )
            self.executor.remove_network(spec)
        if applied.get("apparmor"):
            self.executor.remove_profile(apparmor.profile_name(slug))

        if keep_data:
            alloc.update_allocation(
                self.data_root,
                slug,
                state="deprovisioned",
                applied={},
                daemon_pid=0,
                apparmor_effective=False,
            )
            state = "deprovisioned"
        else:
            alloc.retire(self.data_root, slug)
            state = "retired"
        audit.write_audit(
            self.data_root, tenant_slug=slug, verb="deprovision",
            exit_code=0, state=state, keep_data=keep_data,
        )
        return {"slug": slug, "state": state, "data_kept": keep_data}

    def repair(self, slug: str) -> dict[str, Any]:
        """Re-install the profile and network rules without touching data."""
        slug = alloc.validate_slug(slug)
        reg = alloc.load_registry(self.data_root)
        cell = reg["allocations"].get(slug)
        if cell is None:
            raise CellNotFound(slug)
        applied = dict(cell.get("applied", {}))
        self.executor.install_profile(
            apparmor.profile_name(slug), apparmor.render_profile(slug)
        )
        self.executor.apply_network(
            network.build_network_spec(slug, cell, cell.get("network_mode", "skuid"))
        )
        applied["apparmor"] = True
        applied["network"] = True
        alloc.update_allocation(
            self.data_root,
            slug,
            applied=applied,
            apparmor_hash=apparmor.profile_hash(slug),
        )
        audit.write_audit(
            self.data_root, tenant_slug=slug, verb="repair", exit_code=0
        )
        return self.status(slug)

    def apparmor_install(self, slug: str) -> dict[str, Any]:
        slug = alloc.validate_slug(slug)
        self.executor.install_profile(
            apparmor.profile_name(slug), apparmor.render_profile(slug)
        )
        if slug in alloc.load_registry(self.data_root)["allocations"]:
            alloc.update_allocation(
                self.data_root, slug, apparmor_hash=apparmor.profile_hash(slug)
            )
        audit.write_audit(
            self.data_root, tenant_slug=slug, verb="apparmor_install", exit_code=0
        )
        return {"slug": slug, "profile": apparmor.profile_name(slug)}

    def apparmor_verify(self, slug: str) -> dict[str, Any]:
        """Read-only verification of the effective profile hash."""
        status = self.status(slug)
        expected = apparmor.profile_hash(slug)
        matches = status["apparmor"]["hash"] == expected
        return {
            "slug": slug,
            "effective": status["apparmor"]["effective"],
            "hash_matches": matches,
            "ok": bool(matches and status["apparmor"]["effective"]),
        }

    def apparmor_remove(self, slug: str) -> dict[str, Any]:
        slug = alloc.validate_slug(slug)
        self.executor.remove_profile(apparmor.profile_name(slug))
        audit.write_audit(
            self.data_root, tenant_slug=slug, verb="apparmor_remove", exit_code=0
        )
        return {"slug": slug, "profile": apparmor.profile_name(slug), "removed": True}
