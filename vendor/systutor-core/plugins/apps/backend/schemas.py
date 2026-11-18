"""Public API schemas; secrets and server-owned runtime identifiers stay private."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .hardening import (
    HardeningPolicy,
    RuntimeUserPolicy,
    WritablePathPolicy,
)


class ManifestStartRequest(BaseModel):
    owner_type: Literal["personal", "organization"] = "personal"
    organization: str | None = Field(default=None, max_length=39)

    @model_validator(mode="after")
    def organization_required_for_org(self):
        if self.owner_type == "organization" and not self.organization:
            raise ValueError("organization is required for an organization app")
        if self.owner_type == "personal" and self.organization:
            raise ValueError("organization must be empty for a personal app")
        return self


class ApplicationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    installation_id: str = Field(min_length=1, max_length=36)
    repository_id: str = Field(min_length=1, max_length=36)
    branch: str | None = Field(default=None, min_length=1, max_length=255)
    compose_file: str | None = Field(default=None, max_length=510)
    domain: str | None = Field(default=None, max_length=255)
    ingress_service: str | None = Field(default=None, max_length=255)
    ingress_port: int | None = Field(default=None, ge=1, le=65535)

    @field_validator("compose_file")
    @classmethod
    def safe_compose(cls, value: str | None) -> str | None:
        if value and (value.startswith("/") or ".." in value.split("/")):
            raise ValueError("compose_file must stay inside the repository")
        return value

    @field_validator("branch")
    @classmethod
    def safe_branch(cls, value: str | None) -> str | None:
        if value and (value.startswith("-") or any(ch in value for ch in "\x00\r\n")):
            raise ValueError("branch is invalid")
        return value

    @model_validator(mode="after")
    def complete_ingress(self):
        values = (self.domain, self.ingress_service, self.ingress_port)
        if any(value is not None for value in values) and not all(
            value is not None for value in values
        ):
            raise ValueError("domain, ingress_service and ingress_port must be provided together")
        return self


class SourceUpdate(BaseModel):
    installation_id: str = Field(min_length=1, max_length=36)
    repository_id: str = Field(min_length=1, max_length=36)
    branch: str | None = Field(default=None, min_length=1, max_length=255)

    @field_validator("branch")
    @classmethod
    def safe_branch(cls, value: str | None) -> str | None:
        if value and (value.startswith("-") or any(ch in value for ch in "\x00\r\n")):
            raise ValueError("branch is invalid")
        return value


class ComposeUpdate(BaseModel):
    compose_file: str | None = Field(default=None, max_length=510)

    @field_validator("compose_file")
    @classmethod
    def safe_compose(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            return None
        if (
            len(text) > 510
            or text.startswith("/")
            or "\\" in text
            or any(ch in text for ch in "\x00\r\n")
            or any(part in {"", ".", ".."} for part in text.split("/"))
            or not text.lower().endswith((".yml", ".yaml"))
        ):
            raise ValueError("compose_file must stay inside the repository")
        return text


class HardeningRuntimeUser(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    uid: int = Field(gt=0, le=2**31 - 1, strict=True)
    gid: int = Field(gt=0, le=2**31 - 1, strict=True)


class HardeningWritablePath(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    service: str = Field(min_length=1, max_length=128)
    path: str = Field(min_length=2, max_length=1024)
    mode: str = Field(default="0750", min_length=4, max_length=4)

    @model_validator(mode="after")
    def valid_contract(self):
        WritablePathPolicy(self.service, self.path, self.mode)
        return self


class HardeningRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_users: dict[str, HardeningRuntimeUser] = Field(min_length=1, max_length=64)
    writable_paths: list[HardeningWritablePath] = Field(default_factory=list, max_length=256)
    authorized_external_networks: list[str] = Field(default_factory=list, max_length=64)
    egress_networks: list[str] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def valid_policy(self):
        self.to_policy()
        return self

    def to_policy(self) -> HardeningPolicy:
        return HardeningPolicy(
            tuple(
                RuntimeUserPolicy(service, user.uid, user.gid)
                for service, user in self.service_users.items()
            ),
            tuple(
                WritablePathPolicy(item.service, item.path, item.mode)
                for item in self.writable_paths
            ),
            (),
            (),
            tuple(self.authorized_external_networks),
            tuple(self.egress_networks),
        )


class DeployScopeRequest(BaseModel):
    """Global by default; a service scope never implies dependencies."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["global", "service"] = "global"
    service: str | None = Field(default=None, min_length=1, max_length=255)

    @model_validator(mode="after")
    def valid_scope(self):
        if self.type == "global" and self.service is not None:
            raise ValueError("global scope cannot select a service")
        if self.type == "service" and not self.service:
            raise ValueError("service scope requires a service")
        if self.service is not None and any(
            character in self.service for character in "`\r\n\t /:\\"
        ):
            raise ValueError("service is invalid")
        return self


class DeployRequest(BaseModel):
    """A deployment may only carry a hardening policy or a signed release id."""

    model_config = ConfigDict(extra="forbid")

    environment: list[tuple[str, str]] = Field(default_factory=list, max_length=100)
    hardening: HardeningRequest | None = None
    hardened_operation_id: str | None = Field(
        default=None, min_length=1, max_length=128
    )
    scope: DeployScopeRequest | None = None

    @field_validator("hardened_operation_id")
    @classmethod
    def safe_operation_id(cls, value: str | None) -> str | None:
        if value is not None and not all(
            character.isalnum() or character in "_.:-" for character in value
        ):
            raise ValueError("hardened_operation_id is invalid")
        return value

    @model_validator(mode="after")
    def one_admission_path(self):
        if self.hardening is not None and self.hardened_operation_id is not None:
            raise ValueError("hardening and hardened_operation_id are exclusive")
        return self


class RollbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_deployment_id: str = Field(min_length=1, max_length=36)
    scope: DeployScopeRequest | None = None

    @field_validator("to_deployment_id")
    @classmethod
    def safe_deployment_id(cls, value: str) -> str:
        if not all(character.isalnum() or character in "_-" for character in value):
            raise ValueError("to_deployment_id is invalid")
        return value


class ActionRequest(BaseModel):
    """Optional Compose service selector; runtime identifiers are forbidden."""

    model_config = ConfigDict(extra="forbid")

    service: str | None = Field(default=None, min_length=1, max_length=255)

    @field_validator("service")
    @classmethod
    def safe_service(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(character in value for character in "`\r\n\t /:\\"):
            raise ValueError("service is invalid")
        return value


class SecretRevealRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=4, max_length=500)

    @field_validator("reason")
    @classmethod
    def safe_reason(cls, value: str) -> str:
        reason = value.strip()
        if len(reason) < 4:
            raise ValueError("reason is required")
        return reason


class DeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: str
    purge_data: bool = False


class ApplicationView(BaseModel):
    id: str
    name: str
    slug: str
    repository: str
    branch: str
    compose_file: str | None
    domain: str | None
    ingress_service: str | None
    ingress_port: int | None
    status: str
    source_connection_user_id: str
    source_installation_id: str | None
    source_repository_id: str | None
    source_status: str
    has_saved_environment: bool = False
    tenant_id: str | None = None
    tenant_name: str | None = None

    model_config = {"from_attributes": True}


class OperationView(BaseModel):
    operation_id: str
    application_id: str | None
    kind: str
    status: str
    poll_url: str


class OperationDetail(BaseModel):
    id: str
    application_id: str | None
    subject_type: str | None
    subject_id: str | None
    kind: str
    status: str
    phase: str
    report: dict | None
    result: dict | None
    error_code: str | None
    public_error: str | None
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None

    model_config = {"from_attributes": True}


class EnvironmentVariable(BaseModel):
    name: str
    source: Literal["managed", "tenant", "image"]
    secret: bool
    revealable: bool


class ServiceDetail(BaseModel):
    name: str
    image: str | None = None
    status: str
    health: str
    ports: list[int] = Field(default_factory=list)
    restart_count: int = 0
    environment_names: list[str] = Field(default_factory=list)
    environment: list[EnvironmentVariable] = Field(default_factory=list)
    created_at: datetime | None = None


class SecretRevealResponse(BaseModel):
    name: str
    value: str


class ProviderView(BaseModel):
    id: str
    github_app_id: int
    app_slug: str
    name: str
    owner_login: str | None
    owner_type: str | None
    status: str
    created_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None

    model_config = {"from_attributes": True}


class InstallationView(BaseModel):
    id: str
    provider_id: str
    github_installation_id: int
    account_login: str
    account_type: str | None
    repository_selection: str
    permissions: dict
    status: str
    repository_count: int = 0
    installed_at: datetime | None = None
    last_synced_at: datetime | None = None
    suspended_at: datetime | None = None
    deleted_at: datetime | None = None

    model_config = {"from_attributes": True}


class RepositoryView(BaseModel):
    id: str
    github_repository_id: int
    full_name: str
    private: bool
    default_branch: str | None
    archived: bool
    disabled: bool
    observed_at: datetime | None = None
    removed_at: datetime | None = None

    model_config = {"from_attributes": True}


class TenantPlanRequest(BaseModel):
    """Aggregate limits; the host materializer owns the systemd/slice details."""

    model_config = ConfigDict(extra="forbid")

    memory_bytes: int = Field(gt=0, le=2**63 - 1, strict=True)
    cpus: float = Field(gt=0, le=4096)
    pids: int = Field(gt=0, le=1_000_000, strict=True)
    cpuset: str | None = Field(default=None, max_length=255)

    @field_validator("cpuset")
    @classmethod
    def safe_cpuset(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value or not re.fullmatch(
            r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*", value
        ):
            raise ValueError("cpuset must be a list of CPU ids/ranges")
        return value


class TenantPlanView(BaseModel):
    tenant_id: str
    tenant_slug: str
    memory_bytes: int
    cpus: float
    pids: int
    cpuset: str | None = None
    updated_at: datetime | None = None
    slice: str
    cgroup_path: str

    model_config = {"from_attributes": True}
