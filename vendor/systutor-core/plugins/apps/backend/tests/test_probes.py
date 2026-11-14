from __future__ import annotations

import json

import pytest

from plugins.apps.backend.runtime.probes import (
    ProbeFailed,
    check_isolation,
    run_functional_probe,
    run_probes,
)
from plugins.apps.backend.runtime.types import Completed

IMAGE = "probe@sha256:" + "d" * 64
CANARY = "do-not-store-this-output"


def container(**overrides):
    value = {
        "State": {
            "Status": "running",
            "RestartCount": 0,
            "Health": {"Status": "healthy"},
        },
        "HostConfig": {
            "Privileged": False,
            "Devices": [],
            "Binds": [],
            "PortBindings": {},
            "PidMode": "",
            "NetworkMode": "proj_default",
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "ReadonlyRootfs": True,
        },
        "Config": {"User": "10001:10002"},
        "NetworkSettings": {"Networks": {"proj_default": {}}},
    }
    for key, changes in overrides.items():
        value[key].update(changes)
    return value


class FakeRunner:
    transport = "local"

    def __init__(self, payload=None, *, healthcheck=True, restart_count=0) -> None:
        self.payload = payload or container()
        self.healthcheck = healthcheck
        self.restart_count = restart_count
        self.calls: list[list[str]] = []

    def run(self, argv, *, timeout=600, check=True, **_kwargs):
        self.calls.append(list(argv))
        if argv[:3] == ["docker", "container", "inspect"]:
            value = json.loads(json.dumps(self.payload))
            value["State"]["RestartCount"] = self.restart_count
            return Completed(0, json.dumps([value]))
        if argv[:2] == ["docker", "top"]:
            return Completed(0, "PID UID\n1 10001\n2 10001\n")
        if argv[:3] == ["docker", "network", "inspect"]:
            return Completed(0, "true")
        if argv[:2] == ["docker", "compose"] and "config" in argv:
            healthcheck = (
                {"test": ["CMD", "true"]} if self.healthcheck else None
            )
            return Completed(0, json.dumps({
                "services": {"web": {"image": "img", "healthcheck": healthcheck}}
            }))
        if argv[:2] == ["docker", "run"]:
            return Completed(0, CANARY)
        return Completed(0)


def env(**overrides):
    value = {
        "SPANEL_APPS_PROBE_IMAGE": IMAGE,
        "SPANEL_APPS_PROBE_COMMAND": '["true"]',
        "SPANEL_APPS_PROBE_CHECKS": "1",
        "SPANEL_APPS_PROBE_WINDOW_SECONDS": "0",
        "SPANEL_APPS_PROBE_TIMEOUT_SECONDS": "5",
    }
    value.update(overrides)
    return value


def test_isolation_accepts_hardened_containers_and_rejects_root_processes() -> None:
    runner = FakeRunner()
    evidence = check_isolation(runner, {"web": "cid1"})
    assert evidence["web"]["networks"] == ["proj_default"]

    def root_top(argv, **_kwargs):
        if argv[:2] == ["docker", "top"]:
            return Completed(0, "PID UID\n1 0\n")
        return FakeRunner().run(argv, **_kwargs)

    runner.run = root_top
    with pytest.raises(ProbeFailed, match="root"):
        check_isolation(runner, {"web": "cid1"})


def test_isolation_rejects_published_ports_and_writable_rootfs() -> None:
    runner = FakeRunner(container(HostConfig={"PortBindings": {"80/tcp": [{}]}}))
    with pytest.raises(ProbeFailed, match="publishes"):
        check_isolation(runner, {"web": "cid1"})
    runner = FakeRunner(container(HostConfig={"ReadonlyRootfs": False}))
    with pytest.raises(ProbeFailed, match="writable"):
        check_isolation(runner, {"web": "cid1"})


def test_functional_probe_is_bounded_and_never_returns_output() -> None:
    runner = FakeRunner()
    evidence = run_functional_probe(
        runner, network="proj_default", image=IMAGE, command=["true"], timeout=5
    )
    assert CANARY not in json.dumps(evidence)
    assert evidence["returncode"] == 0
    assert evidence["bytes"] == len(CANARY)
    argv = runner.calls[-1]
    assert argv[:2] == ["docker", "run"]
    assert "no-new-privileges:true" in argv
    assert "--pids-limit" in argv and "--memory" in argv and "--cpus" in argv
    assert "--network" in argv and argv[argv.index("--network") + 1] == "proj_default"


def test_run_probes_requires_an_effective_healthcheck(tmp_path) -> None:
    runner = FakeRunner(healthcheck=False)
    with pytest.raises(ProbeFailed, match="healthcheck"):
        run_probes(
            runner,
            release=tmp_path,
            compose_rel="compose.yml",
            project="proj",
            services=["web"],
            containers={"web": "cid1"},
            environ=env(),
            sleep=lambda _seconds: None,
        )
    assert not any(call[:2] == ["docker", "run"] for call in runner.calls)


def test_run_probes_requires_zero_restarts(tmp_path) -> None:
    runner = FakeRunner(restart_count=1)
    with pytest.raises(ProbeFailed, match="restarted"):
        run_probes(
            runner,
            release=tmp_path,
            compose_rel="compose.yml",
            project="proj",
            services=["web"],
            containers={"web": "cid1"},
            environ=env(),
            sleep=lambda _seconds: None,
        )


def test_run_probes_returns_only_digests_and_sizes(tmp_path) -> None:
    runner = FakeRunner()
    evidence = run_probes(
        runner,
        release=tmp_path,
        compose_rel="compose.yml",
        project="proj",
        services=["web"],
        containers={"web": "cid1"},
        environ=env(),
        sleep=lambda _seconds: None,
    )
    assert CANARY not in json.dumps(evidence)
    assert evidence["functional"]["checks"][0]["sha256"]
    assert evidence["stability"]["restart_counts"] == {"web": 0}
    assert "probe" in evidence["functional"]["image"]


def test_missing_probe_configuration_fails_closed(tmp_path) -> None:
    runner = FakeRunner()
    with pytest.raises(ProbeFailed, match="probe image"):
        run_probes(
            runner,
            release=tmp_path,
            compose_rel="compose.yml",
            project="proj",
            services=["web"],
            containers={"web": "cid1"},
            environ={"SPANEL_APPS_PROBE_COMMAND": '["true"]'},
            sleep=lambda _seconds: None,
        )
    with pytest.raises(ProbeFailed, match="command"):
        run_probes(
            runner,
            release=tmp_path,
            compose_rel="compose.yml",
            project="proj",
            services=["web"],
            containers={"web": "cid1"},
            environ={"SPANEL_APPS_PROBE_IMAGE": IMAGE},
            sleep=lambda _seconds: None,
        )
