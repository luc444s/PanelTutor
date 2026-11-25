from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import plugins.apps.backend.models  # noqa: F401
import plugins.tenant.backend.models  # noqa: F401
import systutor.kernel.models  # noqa: F401
from plugins.apps.backend.models import AppsTenantPlan
from plugins.apps.backend.plans_client import PlanAgentError
from plugins.tenant.backend.router import create_new_tenant
from plugins.tenant.backend.schemas import CreateTenantRequest
from systutor.core.database import Base
from systutor.core.errors import AppError
from systutor.kernel.auth.models import User
from systutor.kernel.permissions.models import Permission, Role, RolePermission, UserRole
from systutor.kernel.tenants.models import Tenant


class FakeMaterializer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, object]] = []

    def provision(self, slug: str) -> dict[str, object]:
        self.calls.append(("provision", slug, None))
        return {"slug": slug, "state": "ready"}

    def apply(self, slug: str, plan: dict[str, object]) -> dict[str, object]:
        self.calls.append(("apply", slug, plan))
        return {"slug": slug, "ok": True}


@pytest.fixture()
def db() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        platform = Tenant(id="platform", name="Platform", slug="platform")
        actor = User(
            id="actor",
            tenant_id="platform",
            email="actor@example.com",
            full_name="Actor",
            password_hash="hash",
        )
        platform_role = Role(id="platform-admin", tenant_id="platform", name="platform-admin")
        platform_permission = Permission(
            id="platform-permission", name="core.platform.admin"
        )
        session.add_all([platform, actor, platform_role, platform_permission])
        session.flush()
        session.add_all(
            [
                UserRole(user_id=actor.id, role_id=platform_role.id),
                RolePermission(
                    role_id=platform_role.id,
                    permission_id=platform_permission.id,
                ),
            ]
        )
        session.commit()
        yield session
    engine.dispose()


def payload() -> dict[str, object]:
    return {
        "name": "Acme",
        "slug": "Acme.Example",
        "user_email": "admin@acme.example",
        "user_password": "correct-horse-battery-staple",
        "resource_plan": {
            "memory_bytes": 2 * 1024**3,
            "cpus": 1,
            "pids": 256,
            "storage_bytes": 20 * 1024**3,
        },
    }


def test_create_request_requires_a_complete_resource_plan() -> None:
    data = payload()
    del data["resource_plan"]
    with pytest.raises(ValidationError):
        CreateTenantRequest.model_validate(data)

    data = payload()
    del data["resource_plan"]["storage_bytes"]  # type: ignore[index]
    with pytest.raises(ValidationError):
        CreateTenantRequest.model_validate(data)


def test_create_tenant_provisions_cell_and_applies_plan_before_commit(
    db: Session,
) -> None:
    materializer = FakeMaterializer()
    request = SimpleNamespace(
        headers={"X-Request-ID": "create-acme"},
        app=SimpleNamespace(
            state=SimpleNamespace(
                apps_resources=SimpleNamespace(plan_materializer=materializer)
            )
        ),
    )
    actor = db.get(User, "actor")
    assert actor is not None

    response = create_new_tenant(
        CreateTenantRequest.model_validate(payload()), request, db, actor
    )

    tenant = db.scalar(select(Tenant).where(Tenant.id == response.id))
    plan = db.scalar(select(AppsTenantPlan).where(AppsTenantPlan.tenant_id == response.id))
    assert tenant is not None
    assert plan is not None
    assert plan.status == "applied"
    assert plan.storage_bytes == 20 * 1024**3
    assert [call[:2] for call in materializer.calls] == [
        ("provision", "acme-example"),
        ("apply", "acme-example"),
    ]


def test_create_tenant_surfaces_the_real_agent_error(db: Session) -> None:
    class FailingMaterializer(FakeMaterializer):
        def provision(self, slug: str) -> dict[str, object]:
            raise PlanAgentError("groupadd: cannot lock /etc/group", code="agent_error")

    materializer = FailingMaterializer()
    request = SimpleNamespace(
        headers={"X-Request-ID": "create-acme"},
        app=SimpleNamespace(
            state=SimpleNamespace(
                apps_resources=SimpleNamespace(plan_materializer=materializer)
            )
        ),
    )
    actor = db.get(User, "actor")
    assert actor is not None

    with pytest.raises(AppError) as exc_info:
        create_new_tenant(
            CreateTenantRequest.model_validate(payload()), request, db, actor
        )

    assert exc_info.value.status_code == 502
    assert exc_info.value.code == "tenant.cell_provision_failed"
    assert "agent_error" in exc_info.value.message
    assert "cannot lock /etc/group" in exc_info.value.message
