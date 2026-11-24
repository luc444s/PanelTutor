"""Unit tests for the doctor gate (A.SPEC 0097).

A fake HostProbe simulates every capability green/red. No test reads a real
/proc, runs a command against a host, or touches a real system.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tenant_cell import doctor as doctor_mod


class FakeProbe(doctor_mod.HostProbe):
    """Configurable read-only probe; every capability can be flipped."""

    def __init__(self, **overrides: object) -> None:
        defaults: dict[str, object] = {
            "cgroup2": True,
            "delegate": True,
            "apparmor": True,
            "parser": True,
            "skuid": True,
            "netns": True,
            "subuid": True,
            "docker": True,
        }
        defaults.update(overrides)
        self.__dict__.update(defaults)

    def cgroup2_available(self) -> bool:
        return bool(self.cgroup2)

    def systemd_delegate(self) -> bool:
        return bool(self.delegate)

    def apparmor_enabled(self) -> bool:
        return bool(self.apparmor)

    def apparmor_parser_available(self) -> bool:
        return bool(self.parser)

    def nftables_skuid_supported(self) -> bool:
        return bool(self.skuid)

    def netns_supported(self) -> bool:
        return bool(self.netns)

    def subuid_range_free(self) -> bool:
        return bool(self.subuid)

    def rootless_docker_available(self) -> bool:
        return bool(self.docker)

    def network_mode(self) -> str:
        if self.skuid:
            return "skuid"
        if self.netns:
            return "netns"
        return "none"


def test_doctor_ready_when_all_capabilities_green() -> None:
    report = doctor_mod.run_doctor(FakeProbe())

    assert report.ready is True
    assert set(report.capabilities) == set(doctor_mod.CAPABILITIES)
    assert all(cap["ok"] is True for cap in report.capabilities.values())


def test_doctor_not_ready_when_one_capability_red() -> None:
    report = doctor_mod.run_doctor(FakeProbe(apparmor=False))

    assert report.ready is False
    assert report.capabilities["apparmor_enabled"]["ok"] is False
    # Everything else stays green: the gate is precise, not all-or-nothing.
    assert report.capabilities["kernel_cgroup2"]["ok"] is True
    assert report.capabilities["rootless_docker"]["ok"] is True


def test_doctor_reports_each_red_capability() -> None:
    report = doctor_mod.run_doctor(
        FakeProbe(delegate=False, subuid=False, docker=False)
    )

    assert report.ready is False
    red = {name for name, cap in report.capabilities.items() if not cap["ok"]}
    assert red == {"systemd_delegate", "subuid_range_free", "rootless_docker"}


def test_skuid_unsupported_with_netns_fallback_is_ready() -> None:
    report = doctor_mod.run_doctor(FakeProbe(skuid=False, netns=True))

    assert report.capabilities["nftables_skuid"]["ok"] is True
    assert "netns" in str(report.capabilities["nftables_skuid"]["detail"])
    assert report.ready is True


def test_no_network_isolation_is_not_ready() -> None:
    report = doctor_mod.run_doctor(FakeProbe(skuid=False, netns=False))

    assert report.capabilities["nftables_skuid"]["ok"] is False
    assert report.ready is False


def test_report_is_json_serializable() -> None:
    report = doctor_mod.run_doctor(FakeProbe())

    payload = json.loads(json.dumps(report.to_dict()))

    assert payload["ready"] is True
    assert set(payload["capabilities"]) == set(doctor_mod.CAPABILITIES)
    assert "ok" in payload["capabilities"]["kernel_cgroup2"]
    assert "detail" in payload["capabilities"]["kernel_cgroup2"]


def test_user_service_main_pid_runs_as_cell_user(monkeypatch) -> None:
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        doctor_mod.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name="spanel-demo")
    )

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        observed["env"] = kwargs["env"]
        return SimpleNamespace(stdout="4321\n")

    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)

    assert doctor_mod.HostProbe().user_service_main_pid("demo", 60070) == 4321
    assert observed["argv"] == [
        "runuser", "-u", "spanel-demo", "--",
        "systemctl", "--user", "show", "-p", "MainPID", "--value",
        "spanel-cell-demo",
    ]
    assert observed["env"]["XDG_RUNTIME_DIR"] == "/run/user/60070"
    assert observed["env"]["DBUS_SESSION_BUS_ADDRESS"] == (
        "unix:path=/run/user/60070/bus"
    )


def test_daemon_pid_walks_through_rootlesskit_helper(monkeypatch) -> None:
    files = {
        "/proc/100/task/100/children": "200",
        "/proc/200/comm": "rootlesskit\n",
        "/proc/200/task/200/children": "300",
        "/proc/300/comm": "dockerd\n",
    }
    monkeypatch.setattr(
        doctor_mod, "_path_text", lambda path: files.get(str(path), "")
    )

    assert doctor_mod.HostProbe().daemon_pid(100) == 300


def test_daemon_pid_falls_back_to_cell_uid_when_tree_is_stale(monkeypatch) -> None:
    """Rootlesskit can reparent dockerd off the /proc children walk."""
    files = {
        "/proc/100/task/100/children": "200",
        "/proc/200/comm": "slirp4netns\n",
    }
    monkeypatch.setattr(
        doctor_mod, "_path_text", lambda path: files.get(str(path), "")
    )
    observed = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        return SimpleNamespace(stdout="4242\n")

    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)
    assert doctor_mod.HostProbe().daemon_pid(100, 60002) == 4242
    assert observed["argv"] == ["pgrep", "-u", "60002", "-x", "dockerd"]


def test_daemon_pid_without_uid_keeps_the_parent_fallback(monkeypatch) -> None:
    """Legacy callers that cannot pass a uid keep the old behaviour."""
    files = {"/proc/100/task/100/children": "200"}
    monkeypatch.setattr(
        doctor_mod, "_path_text", lambda path: files.get(str(path), "")
    )
    assert doctor_mod.HostProbe().daemon_pid(100) == 100


def test_doctor_cli_json_honors_injected_probe(monkeypatch) -> None:
    """The CLI doctor command reports the probe result as JSON."""
    from typer.testing import CliRunner

    from scripts.tenant_cell import cli

    monkeypatch.setattr(cli.doctor_mod, "HostProbe", lambda: FakeProbe())

    result = CliRunner().invoke(cli.app, ["doctor", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ready"] is True


def test_doctor_cli_json_exits_nonzero_when_not_ready(monkeypatch) -> None:
    from typer.testing import CliRunner

    from scripts.tenant_cell import cli

    monkeypatch.setattr(
        cli.doctor_mod, "HostProbe", lambda: FakeProbe(apparmor=False)
    )

    result = CliRunner().invoke(cli.app, ["doctor", "--json"])

    assert result.exit_code == 2
    assert json.loads(result.output)["ready"] is False
