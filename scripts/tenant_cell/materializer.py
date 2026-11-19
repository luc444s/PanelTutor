"""Host materializer for in-place tenant resource plans.

The Apps plugin owns the plan in its DB and calls ``apply``/``remove``/``verify``
through an injected materializer.  This module owns the root/systemd side
effects: it applies properties to the existing user manager and keeps
``plans.json`` as a cache of the last applied state (never as a source of
truth).
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
        self._host_probe = probe

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
        """Validate and apply limits to the existing user manager, then cache.

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
            raise plans.InvalidPlan("cpuset cannot be applied in place")
        self._require_gate()
        cell = self._cell(slug)
        if alloc.cgroup_driver(cell) != alloc.DEFAULT_CGROUP_DRIVER:
            raise plans.PlanDriverError("tenant plans require the systemd cgroup driver")
        uid = int(cell["uid"])

        before = self.executor.read_plan_state(uid)
        expected = plans.expected_probe_limits(checked)
        if before.get("effective") != expected:
            self.executor.apply_plan_in_place(uid, checked)

        data = plans.load_plans(self.data_root)
        data["plans"][slug] = {"slug": slug, "uid": uid, "plan": checked}
        plans.save_plans(self.data_root, data)
        audit.write_audit(
            self.data_root,
            tenant_slug=slug,
            verb="plan_set",
            exit_code=0,
            slice=plans.user_slice(uid),
        )
        return self.show(slug)

    def show(self, slug: str) -> dict[str, Any]:
        """Return cached intent and host-observed effective state."""
        slug = plans.validate_slug(slug)
        entry = self._entry(slug)
        uid = int(entry.get("uid", 0)) or int(self._cell(slug)["uid"])
        state = self.executor.read_plan_state(uid)
        return {
            "slug": slug,
            "uid": uid,
            "plan": entry["plan"],
            "slice": state.get("slice") or plans.user_slice(uid),
            "properties": state.get("properties", {}),
            "effective": state.get("effective", {}),
            "owner_uid": state.get("owner_uid", ""),
            "cgroup_path": state.get("cgroup_path", ""),
        }

    def remove(self, slug: str) -> dict[str, Any]:
        """Reset plan properties without deleting cell data or units."""
        slug = plans.validate_slug(slug)
        self._require_gate()
        entry = self._entry(slug)
        cell = alloc.load_registry(self.data_root)["allocations"].get(slug)
        uid = int(entry.get("uid", 0)) or int(cell["uid"] if cell else 0)

        self.executor.reset_plan_properties(uid)

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
        return self.probe(slug, plan=plan)

    def probe(
        self,
        slug: str,
        plan: dict[str, Any] | None = None,
        memory_mb: int = 64,
        seconds: int = 3,
    ) -> dict[str, Any]:
        """Run a bounded disposable-container probe against cgroups v2."""
        slug = plans.validate_slug(slug)
        if memory_mb <= 0 or seconds <= 0:
            raise plans.InvalidPlan("probe memory and seconds must be positive")
        self._require_gate()
        entry = self._entry(slug)
        source = plan if plan is not None else entry["plan"]
        effective = plans.validate_plan(
            source["memory"], source["cpus"], source["pids"]
        )
        uid = int(entry.get("uid", 0)) or int(self._cell(slug)["uid"])
        evidence = self.executor.run_plan_probe(
            slug, uid, effective, memory_mb=memory_mb, seconds=seconds
        )
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
            "slice": evidence.get("slice", plans.user_slice(uid)),
            "properties": evidence.get("properties", {}),
            "owner_uid": evidence.get("owner_uid", ""),
            "cgroup_path": evidence.get("cgroup_path", ""),
            "plan": effective,
            "evidence": evidence,
        }

    def reconcile(self, desired: list[dict[str, Any]]) -> dict[str, Any]:
        """Repair host state to match ``desired`` plans coming from the DB.

        ``plans.json`` is used only to find stale cache entries to clean up;
        it is never the source of truth. A missing cache entry is repaired by
        re-applying from the desired plan, which is what makes reconcile safe
        after a VPS restart.
        """
        results: list[dict[str, Any]] = []
        desired_slugs: set[str] = set()
        for entry in desired:
            if not isinstance(entry, dict):
                results.append({"slug": "", "ok": False, "error": "invalid desired entry"})
                continue
            slug = plans.validate_slug(str(entry.get("slug", "")))
            desired_slugs.add(slug)
            plan = entry["plan"]
            try:
                cell = self._cell(slug)
                cleanup = getattr(self.executor, "cleanup_legacy_plan", None)
                if cleanup is not None:
                    cleanup(slug, int(cell["uid"]))
                evidence = self.verify(slug, plan)
                ok = bool(evidence.get("ok"))
                action = "verified"
                if not ok:
                    self.apply(slug, plan)
                    action = "re-applied"
                results.append({
                    "slug": slug, "tenant": entry.get("tenant"),
                    "ok": True, "action": action,
                })
            except plans.PlanNotFound:
                self.apply(slug, plan)
                results.append({
                    "slug": slug, "tenant": entry.get("tenant"),
                    "ok": True, "action": "re-applied",
                })
            except Exception as exc:  # noqa: BLE001 - one tenant must not abort all
                results.append({
                    "slug": slug, "tenant": entry.get("tenant"),
                    "ok": False, "error": str(exc)[:300],
                })

        removed: list[str] = []
        cleanup_failed: list[str] = []
        cached = set(plans.load_plans(self.data_root)["plans"])
        for slug in sorted(cached - desired_slugs):
            try:
                self.remove(slug)
                removed.append(slug)
            except Exception:  # noqa: BLE001 - one stale slug must not abort all
                cleanup_failed.append(slug)
        return {
            "ok": all(item["ok"] for item in results) and not cleanup_failed,
            "results": results,
            "removed": removed,
            "cleanup_failed": cleanup_failed,
        }
