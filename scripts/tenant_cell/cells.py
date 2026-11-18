"""Provisioning orchestration: gate, idempotent apply, status and rollback.

All mutations go through the injectable ``Executor``; the service never talks
to the network or to a remote host. ``LocalExecutor`` is the gated real-world
adapter and is never invoked by tests or by ``--help``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import alloc, apparmor, audit, network
from .alloc import DEFAULT_CGROUP_DRIVER, LEGACY_CGROUP_DRIVER, cgroup_driver
from .doctor import DoctorReport, HostProbe, run_doctor
from .executor import Executor  # re-exported for tests


class MigrationVerificationFailed(Exception):
    """Raised when the post-migration limit probe fails (rollback already ran)."""

    def __init__(self, slug: str, evidence: dict[str, Any]) -> None:
        self.slug = slug
        self.evidence = evidence
        super().__init__(f"cgroup limit verification failed for {slug!r}")


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

    def cgroup_path(
        self,
        slug: str,
        uid: int = 0,
        driver: str = LEGACY_CGROUP_DRIVER,
    ) -> str:
        if driver == DEFAULT_CGROUP_DRIVER:
            # Container scopes are siblings under the delegated user manager.
            return (
                f"/user.slice/user-{uid}.slice/user@{uid}.service/"
                f"user.slice/spanel-cell-{slug}.scope"
            )
        return f"/system.slice/spanel-cell-{slug}.scope"

    def _main_pid(self, slug: str, cell: dict[str, Any]) -> int:
        driver = cgroup_driver(cell)
        if driver == DEFAULT_CGROUP_DRIVER:
            return self.probe.user_service_main_pid(slug, int(cell["uid"]))
        return self.probe.service_main_pid(slug)

    def status(self, slug: str) -> dict[str, Any]:
        """Effective state; uid_map is read from the host, never assumed."""
        slug = alloc.validate_slug(slug)
        reg = alloc.load_registry(self.data_root)
        cell = reg["allocations"].get(slug)
        if cell is None:
            raise CellNotFound(slug)
        # Prefer the live systemd MainPID: a restarted daemon changes it, and
        # the stored value must not make effective-profile evidence go stale.
        main_pid = self._main_pid(slug, cell) or int(cell.get("daemon_pid", 0))
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
            "cgroup_path": self.cgroup_path(
                slug, int(cell["uid"]), cgroup_driver(cell)
            ),
            "cgroup_driver": cgroup_driver(cell),
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
        driver = cgroup_driver(cell)
        # A.SPEC 0099: host-wide delegation is a precondition of the systemd
        # driver. Idempotent, and skipped for legacy cgroupfs cells.
        if driver == DEFAULT_CGROUP_DRIVER and not applied.get("delegation"):
            self.executor.ensure_delegation()
            applied["delegation"] = True

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
        if not applied.get("user_manager"):
            self.executor.ensure_user_manager(name, cell["uid"])
            applied["user_manager"] = True
        if not applied.get("daemon_config"):
            self.executor.write_daemon_config(
                str(self.cell_dir(slug)), cell["uid"], cell["gid"], driver
            )
            applied["daemon_config"] = True
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
                slug,
                cell["uid"],
                self.cgroup_path(slug, int(cell["uid"]), driver),
                driver,
            )
            applied["systemd"] = True
        if applied.get("daemon"):
            pid = int(cell.get("daemon_pid", 0))
        else:
            pid = int(
                self.executor.start_daemon(slug, int(cell["uid"]), driver) or 0
            )
            applied["daemon"] = True

        alloc.update_allocation(
            self.data_root,
            slug,
            # A cell without a running daemon is degraded, never "ready".
            state="ready" if pid > 0 else "degraded",
            applied=applied,
            cgroup_driver=driver,
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
        driver = cgroup_driver(cell)
        if applied.get("daemon"):
            self.executor.stop_daemon(slug, int(cell["uid"]), driver)
        if applied.get("systemd"):
            self.executor.remove_systemd_unit(slug, int(cell["uid"]), driver)
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
        """Re-install profile, daemon config, unit and network rules.

        Data is untouched. A daemon restart is still required for a newly
        attached ``AppArmorProfile=`` to take effect on a running cell.
        """
        slug = alloc.validate_slug(slug)
        reg = alloc.load_registry(self.data_root)
        cell = reg["allocations"].get(slug)
        if cell is None:
            raise CellNotFound(slug)
        applied = dict(cell.get("applied", {}))
        # A.SPEC 0099: never rewrite artifacts with a different driver. A
        # repair of a migrated cell must not silently restore cgroupfs.
        driver = cgroup_driver(cell)
        if driver == DEFAULT_CGROUP_DRIVER:
            self.executor.ensure_delegation()
            applied["delegation"] = True
        self.executor.install_profile(
            apparmor.profile_name(slug), apparmor.render_profile(slug)
        )
        self.executor.write_daemon_config(
            str(self.cell_dir(slug)), cell["uid"], cell["gid"], driver
        )
        self.executor.install_systemd_unit(
            slug,
            cell["uid"],
            self.cgroup_path(slug, int(cell["uid"]), driver),
            driver,
        )
        self.executor.apply_network(
            network.build_network_spec(slug, cell, cell.get("network_mode", "skuid"))
        )
        applied["apparmor"] = True
        applied["daemon_config"] = True
        applied["systemd"] = True
        applied["network"] = True
        alloc.update_allocation(
            self.data_root,
            slug,
            applied=applied,
            cgroup_driver=driver,
            apparmor_hash=apparmor.profile_hash(slug),
        )
        audit.write_audit(
            self.data_root, tenant_slug=slug, verb="repair", exit_code=0
        )
        return self.status(slug)

    def verify_limits(self, slug: str) -> dict[str, Any]:
        """A.SPEC 0099: prove the kernel applies the limits, not just Docker."""
        slug = alloc.validate_slug(slug)
        cell = alloc.load_registry(self.data_root)["allocations"].get(slug)
        if cell is None:
            raise CellNotFound(slug)
        if cgroup_driver(cell) != DEFAULT_CGROUP_DRIVER:
            return {"ok": False, "error": "cgroupfs cells do not enforce limits"}
        return self.executor.run_limit_probe(slug, int(cell["uid"]))

    def migrate(
        self, slug: str, driver: str = DEFAULT_CGROUP_DRIVER
    ) -> dict[str, Any]:
        """Explicit, per-cell, reversible driver migration (A.SPEC 0099).

        Never called by ``provision``: switching the driver restarts the cell's
        daemon and therefore stops its containers. A failed limit verification
        triggers an automatic rollback before the error is reported.
        """
        slug = alloc.validate_slug(slug)
        if driver not in alloc.CGROUP_DRIVERS:
            raise ValueError(f"unsupported cgroup driver: {driver!r}")
        cell = alloc.load_registry(self.data_root)["allocations"].get(slug)
        if cell is None:
            raise CellNotFound(slug)
        current = cgroup_driver(cell)
        if current == driver:
            return self.status(slug)

        from datetime import datetime, timezone

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_dir = str(self.data_root / "backups" / slug / stamp)
        uid = int(cell["uid"])
        applied = dict(cell.get("applied", {}))
        saved = self.executor.backup_files(
            slug,
            [
                f"/etc/systemd/system/spanel-cell-{slug}.service",
                f"/etc/systemd/user/spanel-cell-{slug}.service",
                f"{self.cell_dir(slug)}/daemon.json",
                "/etc/systemd/system/user@.service.d/delegate.conf",
                f"/etc/apparmor.d/spanel-cell-{slug}",
            ],
            backup_dir,
        )
        evidence: dict[str, Any] = {}
        try:
            self.executor.stop_daemon(slug, uid, current)
            if driver == DEFAULT_CGROUP_DRIVER:
                self.executor.ensure_delegation()
                applied["delegation"] = True
            self.executor.install_profile(
                apparmor.profile_name(slug), apparmor.render_profile(slug)
            )
            self.executor.write_daemon_config(
                str(self.cell_dir(slug)), uid, int(cell["gid"]), driver
            )
            self.executor.install_systemd_unit(
                slug, uid, self.cgroup_path(slug, uid, driver), driver
            )
            # Remove the unit of the layout we are leaving.
            if driver == DEFAULT_CGROUP_DRIVER:
                self.executor.remove_systemd_unit(slug, uid, LEGACY_CGROUP_DRIVER)
            else:
                self.executor.remove_user_unit(slug, uid)

            pid = int(self.executor.start_daemon(slug, uid, driver) or 0)
            if pid <= 0:
                raise RuntimeError("migrated daemon did not start")
            if driver == DEFAULT_CGROUP_DRIVER:
                evidence = self.executor.run_limit_probe(slug, uid)
                if not evidence.get("ok"):
                    raise MigrationVerificationFailed(slug, evidence)

            alloc.update_allocation(
                self.data_root,
                slug,
                cgroup_driver=driver,
                applied=applied,
                daemon_pid=pid,
                apparmor_hash=apparmor.profile_hash(slug),
            )
            audit.write_audit(
                self.data_root,
                tenant_slug=slug,
                verb="migrate",
                exit_code=0,
                from_driver=current,
                to_driver=driver,
            )
            result = self.status(slug)
            result["migration"] = {
                "from": current,
                "to": driver,
                "backup_dir": backup_dir,
                "saved_files": sorted(saved),
                "verification": evidence,
            }
            return result
        except Exception as exc:
            self._rollback_migration(slug, uid, current, saved, applied)
            audit.write_audit(
                self.data_root,
                tenant_slug=slug,
                verb="migrate",
                exit_code=1,
                rolled_back=True,
                error=str(exc),
            )
            if isinstance(exc, MigrationVerificationFailed):
                raise
            raise RuntimeError(f"migration failed and was rolled back: {exc}") from exc

    def _rollback_migration(
        self,
        slug: str,
        uid: int,
        driver: str,
        saved: dict[str, str],
        applied: dict[str, Any],
    ) -> None:
        """Best-effort restoration of the pre-migration layout."""
        self.executor.stop_daemon(slug, uid, DEFAULT_CGROUP_DRIVER)
        self.executor.restore_files(saved)
        self.executor.install_profile(
            apparmor.profile_name(slug), apparmor.render_profile(slug)
        )
        self.executor.install_systemd_unit(
            slug, uid, self.cgroup_path(slug, uid, driver), driver
        )
        pid = int(self.executor.start_daemon(slug, uid, driver) or 0)
        applied.pop("delegation", None)
        alloc.update_allocation(
            self.data_root,
            slug,
            cgroup_driver=driver,
            applied=applied,
            daemon_pid=pid,
        )

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
