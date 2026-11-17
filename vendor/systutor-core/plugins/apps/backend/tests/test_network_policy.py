from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from plugins.apps.backend.hardening.contracts import HardeningPolicy
from plugins.apps.backend.runtime.audit import audit_project
from plugins.apps.backend.schemas import HardeningRequest

BASE = {
    "service_users": {"web": {"uid": 1000, "gid": 1000}},
    "writable_paths": [],
}


def test_policy_network_fields_round_trip() -> None:
    payload = {
        **BASE,
        "authorized_external_networks": ["shared"],
        "egress_networks": ["upstream"],
    }
    policy = HardeningPolicy.from_dict(payload)
    assert policy.authorized_external_networks == ("shared",)
    assert policy.egress_networks == ("upstream",)
    assert policy.as_dict() == payload
    assert HardeningPolicy.from_dict(policy.as_dict()) == policy


def test_policy_rejects_invalid_network_names() -> None:
    with pytest.raises(ValueError, match="invalid network"):
        HardeningPolicy.from_dict({
            **BASE, "egress_networks": ["-bad"],
        })


def test_request_exposes_network_policy() -> None:
    request = HardeningRequest.model_validate({
        **BASE,
        "authorized_external_networks": ["shared"],
        "egress_networks": ["upstream"],
    })
    policy = request.to_policy()
    assert policy.authorized_external_networks == ("shared",)
    assert policy.egress_networks == ("upstream",)
    with pytest.raises(ValueError):
        HardeningRequest.model_validate({**BASE, "unknown": 1})


def test_audit_allows_only_authorized_external_networks(tmp_path: Path) -> None:
    (tmp_path / "compose.yml").write_text(
        yaml.safe_dump({
            "services": {"web": {"image": "busybox"}},
            "networks": {"shared": {"external": True, "name": "tenant_shared"}},
        }),
        encoding="utf-8",
    )
    errors = audit_project(tmp_path, "compose.yml", non_root=True).errors
    assert any(getattr(item, "code", None) == "compose_external_resource" for item in errors)
    clean = audit_project(
        tmp_path,
        "compose.yml",
        non_root=True,
        authorized_external_networks=frozenset({"shared"}),
    )
    assert clean.errors == []


def test_policy_json_is_canonical() -> None:
    policy = HardeningPolicy.from_dict({
        **BASE, "authorized_external_networks": ["shared"],
    })
    encoded = json.dumps(policy.as_dict(), sort_keys=True)
    assert json.loads(encoded)["authorized_external_networks"] == ["shared"]
