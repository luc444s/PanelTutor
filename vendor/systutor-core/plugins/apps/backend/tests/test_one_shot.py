from __future__ import annotations

from types import SimpleNamespace

import pytest

from plugins.apps.backend.runtime.deployment import _verify_containers
from plugins.apps.backend.runtime.types import AppDeployError, one_shot_services


class FakeRunner:
    def __init__(self, states: dict[str, dict[str, str]], project: str = "proj") -> None:
        self.states = states
        self.project = project
        self.calls: list[list[str]] = []

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[:3] == ["docker", "container", "inspect"]:
            fmt = str(argv[4])
            container = str(argv[-1])
            if "State.ExitCode" in fmt:
                return SimpleNamespace(
                    stdout=self.states[container]["one_shot"], returncode=0, stderr="",
                )
            if "State.Health" in fmt:
                return SimpleNamespace(
                    stdout=self.states[container]["running"], returncode=0, stderr="",
                )
            if "Config.Labels" in fmt:
                return SimpleNamespace(stdout=self.project, returncode=0, stderr="")
            if "Config.User" in fmt:
                return SimpleNamespace(stdout="1000:1000", returncode=0, stderr="")
        if argv[:2] == ["docker", "top"]:
            return SimpleNamespace(stdout="PID UID\n1 1000\n", returncode=0, stderr="")
        raise AssertionError(argv)


def test_one_shot_services_detects_extension_and_completion_dependency() -> None:
    services = {
        "web": {"image": "web", "depends_on": {
            "migrate": {"condition": "service_completed_successfully"},
        }},
        "migrate": {"image": "web", "x-spanel-one-shot": True},
        "job": {"image": "job", "x-spanel-one-shot": False},
    }
    assert one_shot_services(services) == {"migrate"}


def test_verify_containers_accepts_completed_one_shot() -> None:
    runner = FakeRunner({
        "web": {"running": "running none", "one_shot": "exited 0"},
        "init": {"running": "running none", "one_shot": "exited 0"},
    })
    _verify_containers(
        runner, {"web": "web", "init": "init"}, "proj", True, 1,
        one_shot={"init"},
    )
    assert not any(
        call[:2] == ["docker", "top"] and call[2] == "init"
        for call in runner.calls
    )


def test_verify_containers_rejects_failed_one_shot() -> None:
    runner = FakeRunner({
        "web": {"running": "running none", "one_shot": "exited 0"},
        "init": {"running": "running none", "one_shot": "exited 1"},
    })
    with pytest.raises(AppDeployError, match="one-shot service init exited with code 1"):
        _verify_containers(
            runner, {"web": "web", "init": "init"}, "proj", True, 1,
            one_shot={"init"},
        )


def test_verify_containers_still_requires_regular_services() -> None:
    runner = FakeRunner({
        "web": {"running": "exited 0", "one_shot": "exited 0"},
        "init": {"running": "running none", "one_shot": "exited 0"},
    })
    with pytest.raises(AppDeployError, match="did not become running/healthy"):
        _verify_containers(
            runner, {"web": "web", "init": "init"}, "proj", True, 0,
            one_shot={"init"},
        )
