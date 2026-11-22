from __future__ import annotations

import pytest
from pydantic import ValidationError

from plugins.apps.backend.schemas import ApplicationCreate, TenantPlanRequest


def test_public_application_input_cannot_choose_runtime_identifiers() -> None:
    value = ApplicationCreate(
        name="Demo", installation_id="i1", repository_id="r1",
        domain="demo.example", ingress_service="web", ingress_port=8080,
    )
    assert not hasattr(value, "runtime_project")
    assert not hasattr(value, "repository")
    with pytest.raises(ValidationError):
        ApplicationCreate(name="Demo", installation_id="i1", repository_id="r1", ingress_port=65536)
    with pytest.raises(ValidationError):
        ApplicationCreate(name="Demo", repository_id="r1")
    with pytest.raises(ValidationError):
        ApplicationCreate(name="Demo", installation_id="i1")


def test_application_source_requires_internal_ids_not_a_git_url() -> None:
    with pytest.raises(ValidationError):
        ApplicationCreate(name="Demo", repository="https://github.com/owner/repo")
    with pytest.raises(ValidationError):
        ApplicationCreate(
            name="Demo", installation_id="i1", repository_id="r1",
            domain="demo.example", ingress_service="web", ingress_port=65536,
        )


def test_tenant_plan_storage_is_optional_and_must_be_positive() -> None:
    assert TenantPlanRequest(
        memory_bytes=1024, cpus=1, pids=10,
    ).storage_bytes is None
    assert TenantPlanRequest(
        memory_bytes=1024, cpus=1, pids=10, storage_bytes=20 * 1024**3,
    ).storage_bytes == 20 * 1024**3
    with pytest.raises(ValidationError):
        TenantPlanRequest(memory_bytes=1024, cpus=1, pids=10, storage_bytes=0)
    with pytest.raises(ValidationError):
        TenantPlanRequest(memory_bytes=1024, cpus=1, pids=10, storage_bytes=-1)


def test_compose_path_cannot_escape_checkout() -> None:
    with pytest.raises(ValidationError):
        ApplicationCreate(
            name="Demo", installation_id="i1", repository_id="r1",
            compose_file="../compose.yml",
        )
