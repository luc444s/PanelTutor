"""Configuración y dominios administrados por tenant.

El sufijo de sitios y el conjunto explícito de dominios viven en tablas
propias y no se mezclan con `tenants.domain`, que sigue siendo el dominio de
correo primario. La migración del plugin crea las tablas; los modelos existen
para que los servicios y los tests usen SQLAlchemy.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from systutor.core.database import Base
from systutor.kernel.tenants.models import utc_now


class TenantSiteSettings(Base):
    __tablename__ = "tenant_site_settings"

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id"),
        primary_key=True,
    )
    # PostgreSQL permite varios NULL en una columna UNIQUE: la ausencia de
    # sufijo es un estado válido y no compite con otros tenants.
    site_suffix: Mapped[str | None] = mapped_column(
        String(255), nullable=True, unique=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )


class TenantDomain(Base):
    """Dominio administrado por un tenant.

    La PK es el dominio normalizado: dos tenants no pueden poseer el mismo y
    el índice por `tenant_id` responde el conjunto de un tenant.
    """

    __tablename__ = "tenant_domains"

    domain: Mapped[str] = mapped_column(String(255), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )


class TenantResourceRuntime(Base):
    __tablename__ = "tenant_resource_runtimes"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "kind", "resource_id", name="uq_tenant_resource_runtime"
        ),
        CheckConstraint(
            "runtime in ('rootful','rootless')", name="ck_tenant_resource_runtime"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False)
    runtime: Mapped[str] = mapped_column(String(16), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    @classmethod
    def find(
        cls, db: Session, tenant_id: str, kind: str, resource_id: str
    ) -> TenantResourceRuntime | None:
        return db.scalar(
            select(cls).where(
                cls.tenant_id == tenant_id,
                cls.kind == kind,
                cls.resource_id == resource_id,
            )
        )

    @classmethod
    def get_runtime(
        cls, db: Session, tenant_id: str, kind: str, resource_id: str
    ) -> str:
        row = cls.find(db, tenant_id, kind, resource_id)
        return row.runtime if row is not None else "rootful"

    @classmethod
    def ensure_runtime(
        cls,
        db: Session,
        tenant_id: str,
        kind: str,
        resource_id: str,
        runtime: str = "rootful",
    ) -> TenantResourceRuntime:
        row = cls.find(db, tenant_id, kind, resource_id)
        return row or cls.set_runtime(db, tenant_id, kind, resource_id, runtime)

    @classmethod
    def set_runtime(
        cls,
        db: Session,
        tenant_id: str,
        kind: str,
        resource_id: str,
        runtime: str,
    ) -> TenantResourceRuntime:
        if runtime not in {"rootful", "rootless"}:
            raise ValueError("runtime must be rootful or rootless")
        row = cls.find(db, tenant_id, kind, resource_id)
        if row is None:
            row = cls(
                id=str(uuid4()),
                tenant_id=tenant_id,
                kind=kind,
                resource_id=resource_id,
                runtime=runtime,
            )
        else:
            row.runtime = runtime
        db.add(row)
        db.flush()
        return row

    @classmethod
    def list_runtimes(
        cls, db: Session, tenant_id: str | None = None
    ) -> list[TenantResourceRuntime]:
        stmt = select(cls)
        if tenant_id is not None:
            stmt = stmt.where(cls.tenant_id == tenant_id)
        return list(db.scalars(stmt.order_by(cls.tenant_id, cls.kind, cls.resource_id)))
