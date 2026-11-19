"""A.SPEC 0101: tenant plans live in the Apps DB and reach the deploy override.

No host mutation is performed here: materializers are fakes and the deploy
policy is pure.  SQLite stands in for the plugin database.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session

import systutor.kernel.models  # noqa: F401
from plugins.apps.backend import plans_service, router
from plugins.apps.backend.models import AppsTenantPlan, Operation
from plugins.apps.backend.runtime.deployment import _override
from plugins.apps.backend.runtime.tenant_plan import (
    TenantPlan,
    bind_tenant_plan,
    service_limits,
)
from plugins.apps.backend.schemas import TenantPlanRequest
from systutor.core.database import Base
from systutor.core.errors import AppError
from systutor.kernel.audit.models import AuditLog
from systutor.kernel.auth.models import User
from systutor.kernel.tenants.models import Tenant

MIGRATIONS = Path(__file__).resolve().parents[2] / "migrations"
MEM = 1024 * 1024 * 1024


class FakeMaterializer:
    def __init__(
        self,
        fail: str | None = None,
        evidence: dict | None = None,
        on_apply: Any = None,
        reconcile_result: dict | None = None,
    ) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.fail = fail
        self.evidence = dict(evidence or {"ok": True})
        self.on_apply = on_apply
        self.reconcile_result = reconcile_result

    def apply(self, tenant_slug: str, plan: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("apply", tenant_slug, dict(plan)))
        if self.on_apply is not None:
            self.on_apply()
        if self.fail == "apply":
            raise RuntimeError("slice write failed")
        return {"slice": f"tenant-{tenant_slug}.slice"}

    def remove(self, tenant_slug: str) -> dict[str, Any]:
        self.calls.append(("remove", tenant_slug))
        if self.fail == "remove":
            raise RuntimeError("drop-in removal failed")
        return {"restored_slice": f"user-{tenant_slug}.slice"}

    def verify(self, tenant_slug: str, plan: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("verify", tenant_slug, dict(plan)))
        if self.fail == "verify":
            raise RuntimeError("probe failed")
        return dict(self.evidence)

    def reconcile(self, desired: list[dict[str, Any]]) -> dict[str, Any]:
        self.calls.append(("reconcile", [dict(item) for item in desired]))
        if self.fail == "reconcile":
            raise RuntimeError("agent restart failed")
        if self.reconcile_result is not None:
            return dict(self.reconcile_result)
        return {
            "ok": True,
            "results": [
                {"slug": item["slug"], "ok": True, "action": "verified"}
                for item in desired
            ],
        }


@pytest.fixture
def db(tmp_path: Path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'apps.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all([
            Tenant(id="t1", name="Acme", slug="acme"),
            Tenant(id="t2", name="Beta", slug="beta"),
            User(
                id="u1", tenant_id="t1", email="u1@example.test",
                full_name="Owner", password_hash="x",
            ),
            User(
                id="u2", tenant_id="t2", email="u2@example.test",
                full_name="Other", password_hash="x",
            ),
        ])
        session.commit()
        yield session


def body(memory: int = MEM, cpus: float = 2.0, pids: int = 100,
         cpuset: str | None = None) -> TenantPlanRequest:
    return TenantPlanRequest(
        memory_bytes=memory, cpus=cpus, pids=pids, cpuset=cpuset
    )


def audits(db: Session, action: str) -> list[AuditLog]:
    return list(db.scalars(
        select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)
    ))


# --- pure distribution policy ----------------------------------------------


def test_declared_values_win_and_missing_ones_are_split_equally() -> None:
    plan = TenantPlan(MEM, 2.0, 100, tenant_slug="acme")
    limits = service_limits(
        plan,
        {
            "web": {"mem_limit": "256M", "cpus": 0.5, "pids_limit": 10},
            "db": {"image": "postgres:16"},
            "worker": {},
        },
    )
    assert limits["web"] == {
        "mem_limit": 256 * 1024**2, "cpus": 0.5, "pids_limit": 10,
    }
    remaining = MEM - 256 * 1024**2
    for service in ("db", "worker"):
        assert limits[service]["mem_limit"] == remaining / 2
        assert limits[service]["cpus"] == pytest.approx(0.75)
        assert limits[service]["pids_limit"] == 45
    assert sum(item["mem_limit"] for item in limits.values()) <= MEM
    assert sum(item["cpus"] for item in limits.values()) <= plan.cpus
    assert sum(item["pids_limit"] for item in limits.values()) <= plan.pids


def test_derived_limits_never_exceed_the_plan_total() -> None:
    plan = TenantPlan(1000, 1.0, 10, tenant_slug="acme")
    limits = service_limits(
        plan,
        {
            "a": {"mem_limit": "10G", "cpus": 99, "pids_limit": 999},
            "b": {"mem_limit": "10G", "cpus": 99, "pids_limit": 999},
        },
    )
    assert sum(item["mem_limit"] for item in limits.values()) <= 1000
    assert sum(item["cpus"] for item in limits.values()) <= 1.0
    assert sum(item["pids_limit"] for item in limits.values()) <= 10


def test_plan_cpuset_is_used_when_the_compose_does_not_declare_one() -> None:
    plan = TenantPlan(MEM, 1.0, 10, tenant_slug="acme", cpuset="0-1")
    limits = service_limits(plan, {"web": {"cpuset": "2,3"}, "db": {}})
    assert limits["web"]["cpuset"] == "2,3"  # declared wins
    assert limits["db"]["cpuset"] == "0-1"


# --- override injection -----------------------------------------------------


def test_override_without_a_plan_keeps_the_original_defaults() -> None:
    rendered = yaml.safe_load(_override(
        {"services": {"web": {"image": "alpine:3.20"}}}, "demo", True
    ))
    web = rendered["services"]["web"]
    assert web["pids_limit"] == 256
    assert web["mem_limit"] == "512m"
    assert web["cpus"] == 1.0
    assert "cgroup_parent" not in web


def test_override_with_a_plan_injects_slice_and_derived_limits() -> None:
    plan = TenantPlan(MEM, 2.0, 300, tenant_slug="acme", cpuset="0-1")
    rendered = yaml.safe_load(_override(
        {
            "services": {
                "web": {"image": "alpine:3.20"},
                "db": {"image": "postgres:16", "mem_limit": "128M"},
            }
        },
        "demo", True, plan=plan,
    ))
    web = rendered["services"]["web"]
    db = rendered["services"]["db"]
    assert web["cgroup_parent"] == "tenant-acme.slice"
    assert db["cgroup_parent"] == "tenant-acme.slice"
    assert web["mem_limit"] == MEM - 128 * 1024**2  # remainder of the budget
    assert db["mem_limit"] == 128 * 1024**2  # declared in Compose wins
    assert web["cpus"] == 1.0  # 2.0 shared by two services
    assert web["pids_limit"] == 150  # 300 shared by two services
    assert web["cpuset"] == "0-1"


def test_bound_plan_reaches_override_without_an_explicit_argument() -> None:
    plan = TenantPlan(MEM, 1.0, 50, tenant_slug="beta")
    with bind_tenant_plan(plan):
        rendered = yaml.safe_load(_override(
            {"services": {"web": {"image": "alpine"}}}, "demo", True
        ))
    assert rendered["services"]["web"]["cgroup_parent"] == "tenant-beta.slice"
    # The binding is scoped and does not leak into later overrides.
    later = yaml.safe_load(_override(
        {"services": {"web": {"image": "alpine"}}}, "demo", True
    ))
    assert "cgroup_parent" not in later["services"]["web"]


def test_override_publishes_rootless_ingress_on_the_cell_loopback() -> None:
    rendered = yaml.safe_load(_override(
        {"services": {"frontend": {"image": "alpine", "expose": ["8080"]}}},
        "demo", True,
        ingress_publish=("frontend", "127.71.1.1", 20070, 8080),
    ))
    assert rendered["services"]["frontend"]["ports"] == [
        "127.71.1.1:20070:8080"
    ]
    assert rendered["services"]["frontend"]["networks"] == [
        "default", "spanel-ingress"
    ]
    assert rendered["networks"]["default"]["internal"] is True
    assert rendered["networks"]["spanel-ingress"]["internal"] is False


def test_override_rejects_a_non_loopback_rootless_ingress() -> None:
    from plugins.apps.backend.runtime import AppDeployError

    with pytest.raises(AppDeployError, match="publish address"):
        _override(
            {"services": {"frontend": {"image": "alpine"}}}, "demo", True,
            ingress_publish=("frontend", "0.0.0.0", 20070, 8080),
        )


# --- service lifecycle ------------------------------------------------------


def test_set_plan_persists_materializes_audits_and_returns_view(db: Session) -> None:
    fake = FakeMaterializer()
    view = plans_service.set_plan(
        db, tenant_id="t1", actor="u1", body=body(), materializer=fake
    )
    assert view["tenant_slug"] == "acme"
    assert view["slice"] == "tenant-acme.slice"
    assert view["cgroup_path"] == "/tenant.slice/tenant-acme.slice"
    assert view["memory_bytes"] == MEM
    row = plans_service.get_plan(db, "t1")
    assert row is not None and row.pids == 100
    assert fake.calls == [("apply", "acme", {
        "memory": MEM, "cpus": 2.0, "pids": 100, "cpuset": None,
    })]
    assert [item.action for item in audits(db, "apps.plan.set")] == ["apps.plan.set"]
    operation = db.scalar(select(Operation).where(Operation.kind == "plan_set"))
    assert operation is not None and operation.status == "succeeded"


def test_get_plan_returns_none_when_no_plan_is_stored(db: Session) -> None:
    assert plans_service.get_plan(db, "t1") is None
    assert plans_service.plan_view(db, "t1") is None


def test_failed_materialization_keeps_a_recoverable_failed_row(
    db: Session,
) -> None:
    fake = FakeMaterializer(fail="apply")
    with pytest.raises(AppError, match="materialization"):
        plans_service.set_plan(
            db, tenant_id="t1", actor="u1", body=body(), materializer=fake
        )
    row = plans_service.get_plan(db, "t1")
    assert row is not None
    assert row.status == "failed"
    assert row.applied_at is None
    assert row.last_error is not None and "slice write failed" in row.last_error
    failure = audits(db, "apps.plan.set")
    assert len(failure) == 1
    assert failure[0].result == "failure"
    assert "slice write failed" in failure[0].details["error"]
    operation = db.scalar(select(Operation).where(Operation.kind == "plan_set"))
    assert operation is not None and operation.status == "failed"


def test_apply_transitions_pending_applied_and_records_desired_hash(
    db: Session,
) -> None:
    seen: list[str | None] = []

    def observe() -> None:
        row = plans_service.get_plan(db, "t1")
        seen.append(None if row is None else row.status)

    view = plans_service.set_plan(
        db, tenant_id="t1", actor="u1", body=body(),
        materializer=FakeMaterializer(on_apply=observe),
    )
    assert view["status"] == "applied"
    assert view["applied_at"] is not None
    assert view["last_error"] is None
    assert seen == ["pending"]
    row = plans_service.get_plan(db, "t1")
    assert row is not None and row.status == "applied"
    assert row.desired_hash is not None and len(row.desired_hash) == 64
    # A retry with the same body produces the same desired hash.
    plans_service.set_plan(
        db, tenant_id="t1", actor="u1", body=body(), materializer=FakeMaterializer()
    )
    assert plans_service.get_plan(db, "t1").desired_hash == row.desired_hash


def test_a_failed_plan_is_retryable(db: Session) -> None:
    with pytest.raises(AppError, match="materialization"):
        plans_service.set_plan(
            db, tenant_id="t1", actor="u1", body=body(),
            materializer=FakeMaterializer(fail="apply"),
        )
    view = plans_service.set_plan(
        db, tenant_id="t1", actor="u1", body=body(), materializer=FakeMaterializer()
    )
    assert view["status"] == "applied"
    assert plans_service.get_plan(db, "t1").last_error is None


def test_verify_reports_drift_as_failed_without_deleting_the_row(db: Session) -> None:
    plans_service.set_plan(
        db, tenant_id="t1", actor="u1", body=body(), materializer=FakeMaterializer()
    )
    result = plans_service.verify_plan(
        db, tenant_id="t1", actor="u1",
        materializer=FakeMaterializer(evidence={"ok": False, "error": "cpu.max differs"}),
    )
    assert result["ok"] is False
    row = plans_service.get_plan(db, "t1")
    assert row is not None and row.status == "failed"
    assert "cpu.max differs" in row.last_error


def test_typed_client_errors_map_to_controlled_app_errors(db: Session) -> None:
    from plugins.apps.backend.plans_client import PlanAgentDenied

    class DenyingMaterializer(FakeMaterializer):
        def apply(self, tenant_slug, plan):
            raise PlanAgentDenied("tenant not allowed", code="tenant_not_allowed")

    with pytest.raises(AppError) as raised:
        plans_service.set_plan(
            db, tenant_id="t1", actor="u1", body=body(),
            materializer=DenyingMaterializer(),
        )
    assert raised.value.status_code == 502
    assert raised.value.code == "apps.plan_agent_denied"
    assert plans_service.get_plan(db, "t1").status == "failed"


def test_reconcile_repairs_states_from_the_db_desired_set(db: Session) -> None:
    plans_service.set_plan(
        db, tenant_id="t1", actor="u1", body=body(), materializer=FakeMaterializer()
    )
    row = plans_service.get_plan(db, "t1")
    row.status = "failed"
    row.last_error = "agent was down"
    row.applied_at = None
    db.commit()
    result = plans_service.reconcile(
        db, materializer=FakeMaterializer(reconcile_result={
            "ok": True,
            "results": [{"slug": "acme", "ok": True, "action": "re-applied"}],
            "removed": [],
        })
    )
    assert result["ok"] is True and result["checked"] == 1
    repaired = plans_service.get_plan(db, "t1")
    assert repaired.status == "applied"
    assert repaired.last_error is None
    assert repaired.applied_at is not None
    assert len(audits(db, "apps.plan.reconcile")) == 1


def test_reconcile_without_a_client_is_a_loud_503(db: Session) -> None:
    with pytest.raises(AppError) as raised:
        plans_service.reconcile(db, materializer=None)
    assert raised.value.status_code == 503


def test_remove_dematerializes_and_deletes_only_the_target_tenant(
    db: Session,
) -> None:
    fake = FakeMaterializer()
    plans_service.set_plan(
        db, tenant_id="t1", actor="u1", body=body(), materializer=fake
    )
    plans_service.set_plan(
        db, tenant_id="t2", actor="u2", body=body(512, 0.5, 20), materializer=fake
    )
    fake.calls.clear()
    result = plans_service.remove_plan(
        db, tenant_id="t1", actor="u1", materializer=fake
    )
    assert result["tenant_slug"] == "acme"
    assert result["restored_slice"] == "user-acme.slice"
    assert fake.calls == [("remove", "acme")]
    assert plans_service.get_plan(db, "t1") is None
    other = plans_service.get_plan(db, "t2")
    assert other is not None and other.pids == 20
    assert len(audits(db, "apps.plan.remove")) == 1


def test_remove_without_a_plan_is_refused(db: Session) -> None:
    with pytest.raises(AppError, match="no plan"):
        plans_service.remove_plan(
            db, tenant_id="t1", actor="u1", materializer=FakeMaterializer()
        )


def test_verify_reports_kernel_evidence_and_audits_it(db: Session) -> None:
    fake = FakeMaterializer(evidence={"ok": False, "error": "cpu.max differs"})
    plans_service.set_plan(
        db, tenant_id="t1", actor="u1", body=body(), materializer=FakeMaterializer()
    )
    result = plans_service.verify_plan(
        db, tenant_id="t1", actor="u1", materializer=fake
    )
    assert result["ok"] is False
    assert fake.calls[0][0] == "verify"
    assert audits(db, "apps.plan.verify")[0].result == "failure"
    assert plans_service.get_plan(db, "t1") is not None  # verify is read-only


def test_missing_materializer_is_a_loud_503(db: Session) -> None:
    with pytest.raises(AppError) as raised:
        plans_service.set_plan(
            db, tenant_id="t1", actor="u1", body=body(), materializer=None
        )
    assert raised.value.status_code == 503


# --- schema and wiring invariants -------------------------------------------


def test_plan_schema_rejects_unsafe_or_nonpositive_values() -> None:
    with pytest.raises(ValueError):
        TenantPlanRequest(memory_bytes=0, cpus=1, pids=10)
    with pytest.raises(ValueError):
        TenantPlanRequest(memory_bytes=MEM, cpus=-1, pids=10)
    with pytest.raises(ValueError):
        TenantPlanRequest(memory_bytes=MEM, cpus=1, pids=1.5)
    with pytest.raises(ValueError):
        TenantPlanRequest(memory_bytes=MEM, cpus=1, pids=10, cpuset="0; rm -rf /")
    assert body(cpuset="0-3,8").cpuset == "0-3,8"


def test_only_the_plugin_permission_and_plan_routes_are_exposed() -> None:
    manifest = json.loads(
        (Path(__file__).resolve().parents[2] / "plugin.json").read_text(
            encoding="utf-8"
        )
    )
    assert "apps.plans.manage" in manifest["permissions"]
    assert not any(
        permission.startswith("core.") for permission in manifest["permissions"]
    )
    paths: set[str] = set()
    for route in router.router.routes:
        included = getattr(route, "original_router", None)
        if included is not None:
            paths |= {
                item.path for item in included.routes if hasattr(item, "path")
            }
    assert {"/plan", "/plan/verify"} <= paths


def test_migration_006_is_idempotent_and_reversible(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location(
        "apps_migration_006",
        MIGRATIONS / "006_add_tenant_resource_plans.py",
    )
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    assert migration.revision == "006_add_tenant_resource_plans"
    assert AppsTenantPlan.__tablename__ == "apps_tenant_plans"

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'm.db'}")
    with Session(engine) as db:
        migration.upgrade(db)
        migration.upgrade(db)
        db.commit()
    columns = {
        column["name"]
        for column in inspect(engine).get_columns("apps_tenant_plans")
    }
    assert {
        "id", "tenant_id", "memory_bytes", "cpus", "pids", "cpuset", "updated_at",
    } <= columns
    migration.upgrade(engine)
    with Session(engine) as db:
        migration.downgrade(db)
        db.commit()
    assert "apps_tenant_plans" not in inspect(engine).get_table_names()


def _load_migration(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, MIGRATIONS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_007_adds_status_columns_and_is_reversible(tmp_path: Path) -> None:
    base = _load_migration("006_add_tenant_resource_plans")
    status = _load_migration("007_add_tenant_plan_status")
    assert status.revision == "007_add_tenant_plan_status"

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'm007.db'}")
    with Session(engine) as db:
        base.upgrade(db)
        db.execute(text(
            "INSERT INTO apps_tenant_plans "
            "(id, tenant_id, memory_bytes, cpus, pids, updated_at) "
            "VALUES ('p1', 't1', 1024, 1, 10, '2026-01-01 00:00:00')"
        ))
        status.upgrade(db)
        status.upgrade(db)  # idempotent
        db.commit()
    columns = {
        column["name"]
        for column in inspect(engine).get_columns("apps_tenant_plans")
    }
    assert {"status", "applied_at", "last_error", "desired_hash"} <= columns
    with Session(engine) as db:
        assert db.scalar(text(
            "SELECT status FROM apps_tenant_plans WHERE id = 'p1'"
        )) == "applied"  # legacy rows were already materialized
        status.downgrade(db)
        db.commit()
    columns = {
        column["name"]
        for column in inspect(engine).get_columns("apps_tenant_plans")
    }
    assert not {"status", "applied_at", "last_error", "desired_hash"} & columns
