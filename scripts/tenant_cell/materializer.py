"""Host materializer for tenant resource plans (A.SPEC 0101).

The Apps plugin owns the plan in its DB and calls ``apply``/``remove``/``verify``
through an injected materializer.  This module owns the root/systemd side
effects: it renders and installs ``tenant-<slug>.slice``, reparents the cell's
user manager with a drop-in, and keeps ``plans.json`` as a cache of the last
applied state (never as a source of truth).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import alloc, audit, plans


class PlanMaterializer:
    """Slug-keyed lifecycle with validation, gating and audit on every write."""

    def __init__(
        self,
        executor: Any,
        data_root: str | Path,
        probe: Any = None,
    ) -> None:
        self.executor = executor
        self.data_root = Path(data_root)
        self.probe = probe

    def _require_gate(self) -> None:
        if not plans.mutation_allowed():
            raise plans.MutationDisabled(
                f"local plan mutations disabled; set {plans.MUTATION_GATE}=1"
            )

    def _cell(self, slug: str) -> dict[str, Any]:
        cell = alloc.load_registry(self.data_root)["allocations"].get(slug)
        if cell is None:
            raise plans.PlanCellMissing(slug)
        return cell

    def _entry(self, slug: str) -> dict[str, Any]:
        entry = plans.load_plans(self.data_root)["plans"].get(slug)
        if entry is None:
            raise plans.PlanNotFound(slug)
        return entry

    def apply(
        self,
        slug: str,
        plan: dict[str, Any] | object = None,
        cpus: object = None,
        pids: object = None,
    ) -> dict[str, Any]:
        """Validate, install the slice + drop-in, restart the manager, cache.

        ``plan`` is normally the dict sent by the backend materializer call;
        the three positional values are kept for the thin host CLI.
        """
        slug = plans.validate_slug(slug)
        payload: dict[str, Any] = (
            plan if isinstance(plan, dict)
            else {"memory": plan, "cpus": cpus, "pids": pids}
        )
        checked = plans.validate_plan(
            payload["memory"], payload["cpus"], payload["pids"]
        )
        if payload.get("cpuset"):
            # render_slice validates the exact CPU list format too.
            plans.render_slice(slug, {**checked, "cpuset": payload["cpuset"]})
        self._require_gate()
        cell = self._cell(slug)
        if alloc.cgroup_driver(cell) != alloc.DEFAULT_CGROUP_DRIVER:
            raise plans.PlanDriverError("tenant plans require the systemd cgroup driver")
        uid = int(cell["uid"])

        self.executor.install_tenant_slice(
            slug, {**checked, "cpuset": payload.get("cpuset")}
        )
        self.executor.install_user_manager_dropin(slug, uid)
        self.executor.restart_user_manager(uid)

        data = plans.load_plans(self.data_root)
        data["plans"][slug] = {"slug": slug, "uid": uid, "plan": checked}
        plans.save_plans(self.data_root, data)
        audit.write_audit(
            self.data_root,
            tenant_slug=slug,
            verb="plan_set",
            exit_code=0,
            slice=plans.slice_name(slug),
            restored_slice=plans.user_slice(uid),
        )
        return self.show(slug)

    def show(self, slug: str) -> dict[str, Any]:
        """Return the cached plan and the slice it currently materialises."""
        slug = plans.validate_slug(slug)
        entry = self._entry(slug)
        uid = int(entry.get("uid", 0)) or int(self._cell(slug)["uid"])
        return {
            "slug": slug,
            "uid": uid,
            "plan": entry["plan"],
            "slice": plans.slice_name(slug),
            "cgroup_path": plans.slice_cgroup_path(slug),
            "dropin": plans.dropin_path(uid),
        }

    def remove(self, slug: str) -> dict[str, Any]:
        """Drop the artifacts, restore user-<uid>.slice and clear the cache."""
        slug = plans.validate_slug(slug)
        self._require_gate()
        entry = self._entry(slug)
        cell = alloc.load_registry(self.data_root)["allocations"].get(slug)
        uid = int(entry.get("uid", 0)) or int(cell["uid"] if cell else 0)

        self.executor.remove_user_manager_dropin(slug, uid)
        self.executor.remove_tenant_slice(slug)
        self.executor.restart_user_manager(uid)

        data = plans.load_plans(self.data_root)
        data["plans"].pop(slug, None)
        plans.save_plans(self.data_root, data)
        restored = plans.user_slice(uid)
        audit.write_audit(
            self.data_root,
            tenant_slug=slug,
            verb="plan_remove",
            exit_code=0,
            restored_slice=restored,
        )
        return {"slug": slug, "removed": True, "restored_slice": restored}

    def verify(self, slug: str, plan: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return kernel evidence from both sides; ``plan`` may come from DB."""
        slug = plans.validate_slug(slug)
        self._require_gate()
        entry = self._entry(slug)
        source = plan if plan is not None else entry["plan"]
        effective = plans.validate_plan(
            source["memory"], source["cpus"], source["pids"]
        )
        uid = int(entry.get("uid", 0)) or int(self._cell(slug)["uid"])
        evidence = self.executor.run_plan_probe(slug, uid, effective)
        ok = bool(evidence.get("ok"))
        audit.write_audit(
            self.data_root,
            tenant_slug=slug,
            verb="plan_verify",
            exit_code=0 if ok else 1,
        )
        return {
            "slug": slug,
            "ok": ok,
            "slice": plans.slice_name(slug),
            "cgroup_path": plans.slice_cgroup_path(slug),
            "plan": effective,
            "evidence": evidence,
        }
