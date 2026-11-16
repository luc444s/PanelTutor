from __future__ import annotations

import json

import pytest

from plugins.apps.backend.runtime.probes import (
    ProbeFailed,
    check_isolation,
    run_functional_probe,
    run_probes,
)
from plugins.apps.backend.runtime.types import AppDeployError, Completed

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
            "SecurityOpt": [
                "no-new-privileges:true",
                "apparmor=docker-default",
                "seccomp=builtin",
            ],
            "Runtime": "runc",
            "PidsLimit": 256,
            "Memory": 512 * 1024 * 1024,
            "NanoCpus": 1_000_000_000,
            "ReadonlyRootfs": False,
        },
        "AppArmorProfile": "docker-default",
        "Config": {"User": "10001:10002"},
        "Mounts": [],
        "NetworkSettings": {"Networks": {"proj_default": {}}},
    }
    for key, changes in overrides.items():
        if isinstance(value.get(key), dict) and isinstance(changes, dict):
            value[key].update(changes)
        else:
            value[key] = changes
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
    assert evidence["web"]["user"] == "10001:10002"

    def root_top(argv, **_kwargs):
        if argv[:2] == ["docker", "top"]:
            return Completed(0, "PID UID\n1 0\n")
        return FakeRunner().run(argv, **_kwargs)

    runner.run = root_top
    with pytest.raises(ProbeFailed, match="root"):
        check_isolation(runner, {"web": "cid1"})


def test_isolation_rejects_a_container_without_a_declared_user() -> None:
    from plugins.apps.backend.runtime.docker_audit import _is_definitely_non_root_user

    assert not _is_definitely_non_root_user(None)
    assert not _is_definitely_non_root_user("")
    assert _is_definitely_non_root_user("33:0")
    with pytest.raises(ProbeFailed, match="non-root user"):
        check_isolation(
            FakeRunner(container(Config={"User": ""})), {"web": "cid1"}
        )


def test_isolation_rejects_published_ports_and_read_only_rootfs() -> None:
    runner = FakeRunner(container(HostConfig={"PortBindings": {"80/tcp": [{}]}}))
    with pytest.raises(ProbeFailed, match="publishes"):
        check_isolation(runner, {"web": "cid1"})
    runner = FakeRunner(container(HostConfig={"ReadonlyRootfs": True}))
    with pytest.raises(ProbeFailed, match="not writable"):
        check_isolation(runner, {"web": "cid1"})


def test_isolation_accepts_named_volumes_and_rejects_host_binds() -> None:
    named = container(
        HostConfig={"Binds": ["project_data:/data:rw"]},
        Mounts=[{"Type": "volume", "Name": "project_data", "Destination": "/data"}],
    )
    assert check_isolation(FakeRunner(named), {"web": "cid1"})["web"]["user"]

    bound = container(
        HostConfig={"Binds": ["/host/data:/data:rw"]},
        Mounts=[{"Type": "bind", "Source": "/host/data", "Destination": "/data"}],
    )
    with pytest.raises(ProbeFailed, match="host bind"):
        check_isolation(FakeRunner(bound), {"web": "cid1"})


def test_isolation_rejects_missing_runtime_security_profiles() -> None:
    runner = FakeRunner(container(AppArmorProfile="unconfined"))
    with pytest.raises(ProbeFailed, match="AppArmor"):
        check_isolation(runner, {"web": "cid1"})

    runner = FakeRunner(container(HostConfig={"SecurityOpt": [
        "no-new-privileges:true",
        "apparmor=docker-default",
    ]}))
    with pytest.raises(ProbeFailed, match="seccomp"):
        check_isolation(runner, {"web": "cid1"})


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("Runtime", "runsc", "runc"),
        ("PidsLimit", 0, "PID"),
        ("PidsLimit", 257, "PID"),
        ("Memory", 0, "memory"),
        ("Memory", 512 * 1024 * 1024 + 1, "memory"),
        ("NanoCpus", 0, "CPU"),
        ("NanoCpus", 1_000_000_001, "CPU"),
    ],
)
def test_isolation_rejects_invalid_runtime_or_limits(field, value, message) -> None:
    runner = FakeRunner(container(HostConfig={field: value}))
    with pytest.raises(ProbeFailed, match=message):
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


def test_run_probes_accepts_image_healthcheck_by_default(tmp_path) -> None:
    runner = FakeRunner(healthcheck=False)
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
    assert evidence["stability"]["restart_counts"] == {"web": 0}
    assert any(call[:2] == ["docker", "run"] for call in runner.calls)


def test_run_probes_accepts_running_service_without_healthcheck(tmp_path) -> None:
    payload = container()
    payload["State"].pop("Health")
    evidence = run_probes(
        FakeRunner(payload, healthcheck=False),
        release=tmp_path,
        compose_rel="compose.yml",
        project="proj",
        services=["web"],
        containers={"web": "cid1"},
        environ=env(),
        sleep=lambda _seconds: None,
    )
    assert evidence["stability"]["restart_counts"] == {"web": 0}


def test_run_probes_retries_functional_probe_during_startup(tmp_path) -> None:
    class StartupRunner(FakeRunner):
        attempts = 0

        def run(self, argv, **kwargs):
            if argv[:2] == ["docker", "run"]:
                self.attempts += 1
                if self.attempts == 1:
                    self.calls.append(list(argv))
                    return Completed(1, "not ready")
            return super().run(argv, **kwargs)

    payload = container()
    payload["State"].pop("Health")
    runner = StartupRunner(payload, healthcheck=False)
    evidence = run_probes(
        runner,
        release=tmp_path,
        compose_rel="compose.yml",
        project="proj",
        services=["web"],
        containers={"web": "cid1"},
        environ=env(SPANEL_APPS_PROBE_STARTUP_SECONDS="5"),
        sleep=lambda _seconds: None,
    )
    assert runner.attempts == 2
    assert len(evidence["functional"]["checks"]) == 1


def test_run_probes_retries_functional_probe_timeout_during_startup(tmp_path) -> None:
    class TimeoutRunner(FakeRunner):
        attempts = 0

        def run(self, argv, **kwargs):
            if argv[:2] == ["docker", "run"]:
                self.attempts += 1
                if self.attempts == 1:
                    raise AppDeployError("command failed to execute: docker")
            return super().run(argv, **kwargs)

    payload = container()
    payload["State"].pop("Health")
    runner = TimeoutRunner(payload, healthcheck=False)
    evidence = run_probes(
        runner,
        release=tmp_path,
        compose_rel="compose.yml",
        project="proj",
        services=["web"],
        containers={"web": "cid1"},
        environ=env(SPANEL_APPS_PROBE_STARTUP_SECONDS="5"),
        sleep=lambda _seconds: None,
    )
    assert runner.attempts == 2
    assert len(evidence["functional"]["checks"]) == 1


def test_run_probes_rejects_declared_unhealthy_service(tmp_path) -> None:
    runner = FakeRunner(container(State={"Health": {"Status": "unhealthy"}}))
    with pytest.raises(ProbeFailed, match="not healthy"):
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
    with pytest.raises(ProbeFailed, match="command"):
        run_probes(
            runner,
            release=tmp_path,
            compose_rel="compose.yml",
            project="proj",
            services=["web"],
            containers={"web": "cid1"},
            environ={},
            sleep=lambda _seconds: None,
        )


def test_default_probe_image_and_ingress_target_need_no_environment() -> None:
    from plugins.apps.backend.runtime.probes import (
        DEFAULT_PROBE_IMAGE,
        probe_command,
        probe_image,
    )

    assert probe_image({}) == DEFAULT_PROBE_IMAGE
    assert "@sha256:" in DEFAULT_PROBE_IMAGE
    command = probe_command({}, ("web", 8080))
    assert command[0] == "curl"
    assert "%{http_code}" in command
    assert command[-1] == "http://web:8080/"
    with pytest.raises(ProbeFailed, match="service"):
        probe_command({}, ("../etc", 8080))
    with pytest.raises(ProbeFailed, match="port"):
        probe_command({}, ("web", 70000))


def test_run_probes_derives_command_from_ingress_target(tmp_path) -> None:
    from plugins.apps.backend.runtime.probes import DEFAULT_PROBE_IMAGE

    runner = FakeRunner()
    run_probes(
        runner,
        release=tmp_path,
        compose_rel="compose.yml",
        project="proj",
        services=["web"],
        containers={"web": "cid1"},
        environ={"SPANEL_APPS_PROBE_CHECKS": "1",
                 "SPANEL_APPS_PROBE_WINDOW_SECONDS": "0"},
        target=("web", 8080),
        sleep=lambda _seconds: None,
    )
    run = next(call for call in runner.calls if call[:2] == ["docker", "run"])
    assert DEFAULT_PROBE_IMAGE in run
    assert run[-1] == "http://web:8080/"


def test_run_probes_accepts_image_healthcheck_without_a_lab_flag(tmp_path) -> None:
    runner = FakeRunner(healthcheck=False)
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
    assert any(call[:2] == ["docker", "run"] for call in runner.calls)
