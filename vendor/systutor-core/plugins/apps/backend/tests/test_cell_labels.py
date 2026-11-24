"""The cell ingress only publishes targets that carry the tenancy labels."""

from __future__ import annotations

import yaml

from plugins.apps.backend.releases.scoped_execution import _ingress_labels_missing
from plugins.apps.backend.runtime.deployment import _override

DATA = {
    "services": {
        "web": {"image": "nginx:alpine"},
        "worker": {"image": "busybox", "profiles": ["jobs"]},
    }
}


def _labels(tenant_id: str | None) -> dict[str, dict[str, str]]:
    rendered = yaml.safe_load(
        _override(DATA, "app-demo", True, None, "latest", tenant_id=tenant_id)
    )
    return {
        name: config.get("labels") or {}
        for name, config in rendered["services"].items()
    }


def test_override_labels_every_service_with_tenant_ownership() -> None:
    labels = _labels("tenant-1")

    for service_labels in labels.values():
        assert service_labels["spanel.managed"] == "true"
        assert service_labels["spanel.tenant"] == "tenant-1"
        assert service_labels["io.spanel.app.owner"] == "app-demo"


def test_override_omits_ingress_labels_without_a_tenant() -> None:
    labels = _labels(None)

    for service_labels in labels.values():
        assert "spanel.managed" not in service_labels
        assert "spanel.tenant" not in service_labels


class _Runner:
    def __init__(self, results: dict[str, tuple[int, str]]) -> None:
        self.results = results

    def run(self, argv, **_kwargs):
        container = argv[-1]
        code, stdout = self.results.get(container, (1, ""))
        return type("Completed", (), {"returncode": code, "stdout": stdout})()


def test_missing_labels_force_a_recreate_of_legacy_containers() -> None:
    runner = _Runner(
        {
            "labeled": (0, "true|tenant-1"),
            "legacy": (0, "|"),
            "gone": (1, ""),
        }
    )
    containers = {"web": "labeled", "worker": "legacy", "jobs": "gone"}

    assert _ingress_labels_missing(
        runner, containers, ["web", "worker", "jobs"], "tenant-1"
    ) == ["worker", "jobs"]


def test_all_labeled_containers_are_left_untouched() -> None:
    runner = _Runner({"web": (0, "true|tenant-1")})

    assert _ingress_labels_missing(
        runner, {"web": "web"}, ["web"], "tenant-1"
    ) == []
