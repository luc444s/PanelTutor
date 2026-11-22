"""Unit tests for provision/status/deprovision (A.SPEC 0097).

Fake HostProbe and Executor objects stand in for the host: no user is created,
no profile loaded, no nft rule installed, no remote host contacted.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tenant_cell import alloc, apparmor, audit, network
from scripts.tenant_cell.cells import (
    CellNotFound,
    CellService,
    Executor,
    MigrationVerificationFailed,
    ProvisionRefused,
)
from scripts.tenant_cell.doctor import HostProbe
from scripts.tenant_cell.executor import DELEGATE_CONTROLLERS, systemd_unit

# Real uid_map from the host: inner UID 0 maps to the cell's real UID (60000),
# NOT to the first subuid -- the mapping must be observed, never assumed.
UID_MAP = [
    {"host_id": 60000, "inner_id": 0, "count": 1},
    {"host_id": 65636, "inner_id": 1, "count": 65535},
]
GID_MAP = [dict(row) for row in UID_MAP]


class FakeProbe(HostProbe):
    def __init__(self, **overrides: object) -> None:
        defaults: dict[str, object] = {
            "cgroup2": True,
            "delegate": True,
            "apparmor": True,
            "parser": True,
            "subuid": True,
            "docker": True,
            "skuid": True,
            "netns": True,
            "effective": True,
            "uid_map": UID_MAP,
            "gid_map": GID_MAP,
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

    def service_main_pid(self, slug: str) -> int:
        return 4242

    def user_service_main_pid(self, slug: str, uid: int) -> int:
        return 4242

    def profile_effective(self, pid: int, profile: str) -> bool:
        return bool(self.effective)

    def read_uid_map(self, pid: int) -> list[dict[str, int]]:
        return list(self.uid_map)

    def read_gid_map(self, pid: int) -> list[dict[str, int]]:
        return list(self.gid_map)


class FakeExecutor(Executor):
    """Records every mutation instead of performing it."""

    def __init__(self, pid: int = 4242) -> None:
        self.pid = pid
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _rec(self, action: str, **kwargs: object) -> None:
        self.calls.append((action, dict(kwargs)))

    def ensure_user(self, name, uid, gid):
        self._rec("ensure_user", name=name, uid=uid, gid=gid)

    def ensure_subids(self, name, uid, subuid_base, subgid_base, count):
        self._rec(
            "ensure_subids", name=name, uid=uid,
            subuid_base=subuid_base, subgid_base=subgid_base, count=count,
        )

    def ensure_dirs(self, cell_dir, uid, gid):
        self._rec("ensure_dirs", cell_dir=cell_dir, uid=uid, gid=gid)

    def ensure_user_manager(self, name, uid):
        self._rec("ensure_user_manager", name=name, uid=uid)

    def write_daemon_config(self, cell_dir, uid, gid, driver="cgroupfs"):
        self._rec(
            "write_daemon_config", cell_dir=cell_dir, uid=uid, gid=gid, driver=driver
        )

    def ensure_delegation(self):
        self._rec("ensure_delegation")

    def install_profile(self, name, content):
        self._rec("install_profile", name=name, content=content)

    def apply_network(self, spec):
        self._rec("apply_network", spec=spec)

    def install_systemd_unit(self, slug, uid, cgroup_path, driver="cgroupfs"):
        self._rec(
            "install_systemd_unit", slug=slug, uid=uid, cgroup_path=cgroup_path,
            driver=driver,
        )

    def start_daemon(self, slug, uid=0, driver="cgroupfs"):
        self._rec("start_daemon", slug=slug, uid=uid, driver=driver)
        return self.pid

    def cell_dockerd_pid(self, cell_uid):
        return self.pid

    def ensure_cell_egress(self, cell_uid, subnet):
        self._rec("ensure_cell_egress", cell_uid=cell_uid, subnet=subnet)

    def remove_cell_egress(self, cell_uid, subnet):
        self._rec("remove_cell_egress", cell_uid=cell_uid, subnet=subnet)

    def cell_egress_enabled(self, cell_uid, subnet):
        return True

    def stop_daemon(self, slug, uid=0, driver="cgroupfs"):
        self._rec("stop_daemon", slug=slug, uid=uid, driver=driver)

    def install_user_unit(self, slug, uid, cgroup_path):
        self._rec("install_user_unit", slug=slug, uid=uid, cgroup_path=cgroup_path)

    def remove_user_unit(self, slug, uid):
        self._rec("remove_user_unit", slug=slug, uid=uid)

    def start_user_daemon(self, slug, uid):
        self._rec("start_user_daemon", slug=slug, uid=uid)
        return self.pid

    def stop_user_daemon(self, slug, uid):
        self._rec("stop_user_daemon", slug=slug, uid=uid)

    def user_daemon_pid(self, slug, uid):
        return self.pid

    def backup_files(self, slug, files, backup_dir):
        self._rec("backup_files", slug=slug, files=files, backup_dir=backup_dir)
        return {path: f"{backup_dir}/{path.split('/')[-1]}" for path in files}

    def restore_files(self, saved):
        self._rec("restore_files", saved=saved)

    def run_limit_probe(self, slug, uid):
        self._rec("run_limit_probe", slug=slug, uid=uid)
        return {
            "ok": True,
            "slug": slug,
            "driver": "systemd",
            "cgroup_path": "/user.slice/user-60000.slice/user@60000.service/x.scope",
            "memory_max": "134217728",
            "cpu_max": "50000 100000",
            "pids_max": "64",
            "cpu_delta_usec": 1_500_000,
            "memory_throttled": True,
            "pids_current": 63,
        }

    def remove_network(self, spec):
        self._rec("remove_network", spec=spec)

    def remove_profile(self, name):
        self._rec("remove_profile", name=name)

    def remove_systemd_unit(self, slug, uid=0, driver="cgroupfs"):
        self._rec("remove_systemd_unit", slug=slug, uid=uid, driver=driver)

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


def _service(tmp_path, probe=None, executor=None):
    probe = probe or FakeProbe()
    executor = executor or FakeExecutor()
    return CellService(probe, executor, tmp_path), probe, executor


def test_provision_refuses_with_zero_cell_changes_when_doctor_red(tmp_path) -> None:
    svc, _, executor = _service(tmp_path, probe=FakeProbe(apparmor=False))

    with pytest.raises(ProvisionRefused) as exc:
        svc.provision("acme")

    assert exc.value.report.ready is False
    # Zero side effects on the cell: no executor call, no registry, no cell dir.
    assert executor.calls == []
    assert not (tmp_path / "registry.json").exists()
    assert not (tmp_path / "cells" / "acme").exists()
    # The refusal itself is still auditable (exit_code 2).
    record = audit.read_audit(tmp_path)[0]
    assert record["tenant_slug"] == "acme"
    assert record["verb"] == "provision"
    assert record["exit_code"] == 2


def test_provision_creates_cell_with_host_observed_uid_map(tmp_path) -> None:
    svc, _, executor = _service(tmp_path)

    result = svc.provision("acme")

    assert result["state"] == "ready"
    assert result["slug"] == "acme"
    # The effective map is exactly what the probe read: inner 0 -> real uid.
    assert result["uid_map"] == UID_MAP
    assert result["uid_map"][0]["inner_id"] == 0
    assert result["uid_map"][0]["host_id"] == 60000
    assert result["socket_path"].endswith("cells/acme/docker.sock")
    assert result["apparmor"]["profile"] == "spanel-cell-acme"
    assert result["apparmor"]["hash"] == apparmor.profile_hash("acme")
    assert result["apparmor"]["effective"] is True
    # A.SPEC 0099: new cells use the systemd driver and a user-unit scope.
    assert result["cgroup_driver"] == "systemd"
    assert result["cgroup_path"] == (
        "/user.slice/user-60000.slice/user@60000.service/"
        "user.slice/spanel-cell-acme.scope"
    )
    # The socket is created by the cell user path, never the global docker.sock.
    assert "/var/run/docker.sock" not in result["socket_path"]
    assert "ensure_user" in executor.names()
    assert "ensure_user_manager" in executor.names()
    assert "write_daemon_config" in executor.names()
    assert "apply_network" in executor.names()
    assert "ensure_cell_egress" in executor.names()


def test_provision_is_idempotent(tmp_path) -> None:
    svc, _, executor = _service(tmp_path)

    first = svc.provision("acme")
    calls_after_first = list(executor.calls)
    second = svc.provision("acme")

    assert calls_after_first  # first call did the work
    assert executor.calls == calls_after_first  # second call did nothing
    assert first == second  # same returned state
    reg = alloc.load_registry(tmp_path)
    assert list(reg["allocations"]) == ["acme"]
    assert reg["next_index"] == 1
    assert [r["verb"] for r in audit.read_audit(tmp_path)].count("provision") == 2


def test_invalid_slug_rejected_before_any_change(tmp_path) -> None:
    svc, _, executor = _service(tmp_path)

    for bad in ("ACME", "acme!", "", "-acme", "a" * 63, "acme/../x", "a_b"):
        with pytest.raises(alloc.InvalidSlug):
            svc.provision(bad)
        assert executor.calls == []
        assert not (tmp_path / "registry.json").exists()
        assert not (tmp_path / "audit.jsonl").exists()


def test_deprovision_keeps_data_by_default_and_is_idempotent(tmp_path) -> None:
    svc, _, executor = _service(tmp_path)
    svc.provision("acme")
    before = alloc.load_registry(tmp_path)["allocations"]["acme"]["uid"]

    first = svc.deprovision("acme")
    calls_after_first = list(executor.calls)
    second = svc.deprovision("acme")

    assert first == second
    assert first["state"] == "deprovisioned"
    assert first["data_kept"] is True
    assert executor.calls == calls_after_first  # no repeated teardown work
    reg = alloc.load_registry(tmp_path)
    assert "acme" in reg["allocations"]  # data/allocation kept
    assert reg["allocations"]["acme"]["uid"] == before
    assert {"remove_cell_egress", "stop_daemon", "remove_systemd_unit", "remove_network", "remove_profile"} <= set(executor.names())


def test_purge_retires_uid_and_never_reuses(tmp_path) -> None:
    svc, _, executor = _service(tmp_path)
    svc.provision("acme")

    result = svc.deprovision("acme", keep_data=False)

    assert result["state"] == "retired"
    reg = alloc.load_registry(tmp_path)
    assert "acme" not in reg["allocations"]
    assert reg["tombstones"][0]["slug"] == "acme"
    calls_before = list(executor.calls)
    with pytest.raises(alloc.SlugRetired):
        svc.provision("acme")
    assert executor.calls == calls_before
    assert alloc.load_registry(tmp_path)["tombstones"][0]["slug"] == "acme"


def test_status_of_unknown_cell_raises(tmp_path) -> None:
    svc, _, _ = _service(tmp_path)
    with pytest.raises(CellNotFound):
        svc.status("ghost")


def test_audit_records_have_required_fields_and_no_secrets(tmp_path) -> None:
    svc, _, _ = _service(tmp_path)
    svc.provision("acme")
    svc.deprovision("acme")

    records = audit.read_audit(tmp_path)
    assert records
    for record in records:
        assert {"tenant_slug", "verb", "exit_code"} <= set(record)
        assert record["tenant_slug"] == "acme"
        assert record["exit_code"] in (0, 2)
    blob = json.dumps(records)
    for secret in ("password", "token", "sshpass", "api_key"):
        assert secret not in blob

    cleaned = audit._clean({"token": "abc", "note": "password=hunter2", "ok": 1})
    assert cleaned["token"] == "[redacted]"
    assert cleaned["note"] == "[redacted]"
    assert cleaned["ok"] == 1


def test_status_never_exposes_secret_fields(tmp_path) -> None:
    svc, _, _ = _service(tmp_path)
    svc.provision("acme")

    blob = json.dumps(svc.status("acme")).lower()
    for secret in ("password", "token", "secret", "credential"):
        assert secret not in blob


def test_repair_restores_daemon_config_and_unit_for_a_legacy_cell(tmp_path) -> None:
    """Repair must bring an old cell up to the current unit/profile contract."""
    svc, _, executor = _service(tmp_path)
    svc.provision("acme")
    executor.calls.clear()
    result = svc.repair("acme")
    names = [name for name, _ in executor.calls]
    assert "install_profile" in names
    assert "write_daemon_config" in names
    assert "install_systemd_unit" in names
    assert "apply_network" in names
    assert result["apparmor"]["effective"] is True


def test_apparmor_profile_uses_only_validated_slug() -> None:
    profile = apparmor.render_profile("acme")
    assert "spanel-cell-acme" in profile
    assert "spanel-cell-other" not in profile
    assert apparmor.profile_hash("acme") == apparmor.profile_hash("acme")
    assert apparmor.profile_hash("acme") != apparmor.profile_hash("other")
    # A.SPEC 0105/0109-R2: unpigz, busybox, the qemu-check helpers and the
    # per-image path lists are no longer enumerated -- the broad, image-agnostic
    # rootfs grant covers them all, unqualified by `owner` (the tenant is the
    # trust boundary, not the uid).
    assert "/** rix," in profile
    assert "/** rwklix," in profile
    assert "owner /**" not in profile
    # A.SPEC 0109-R2: the broad two-path union rule is retained, and the four
    # narrow HEAD rules it had wrongly replaced are restored (E2E FAIL: a
    # remount has no srcname and cannot match a two-path `src -> dst` rule).
    assert (
        "mount options in (ro, rw, bind, rbind, remount, nosuid, nodev, noexec) "
        "/var/lib/spanel/cells/acme/** -> /var/lib/spanel/cells/acme/**," in profile
    )
    assert (
        "remount options in (ro, rw, nosuid, nodev, noexec, bind, rbind) "
        "/var/lib/spanel/cells/acme/**,"
    ) in profile
    with pytest.raises(alloc.InvalidSlug):
        apparmor.render_profile("acme\n  deny /etc/** rw,")


def test_apparmor_profile_allows_rootless_build_and_exec() -> None:
    """E2E in cell-g found each of these denials blocking a real deploy.

    All grants stay inside this cell's own tree (or are read-only host paths),
    so cross-cell and rootful-socket denials remain intact.
    """
    profile = apparmor.render_profile("acme")
    assert "capability net_raw," in profile
    assert "network netlink raw," in profile
    # Real-image shells (busybox/dash/sh) run via the broad rootfs grant, now
    # unqualified: intra-tenant access is allowed by design (A.SPEC 0109-R2).
    assert "/** rix," in profile
    assert "/** rwklix," in profile
    assert "owner /**" not in profile
    assert "/proc/pressure/** r," in profile
    assert "/proc/self/{setgroups,uid_map,gid_map} rw," in profile
    # E2E 0109-R2 FAIL: a remount carries no srcname, so the two-path
    # consolidated rule cannot match `flags="ro, remount, rbind"`. The original
    # single-path `remount options in (...)` HEAD rule is restored verbatim.
    assert (
        "remount options in (ro, rw, nosuid, nodev, noexec, bind, rbind) "
        "/var/lib/spanel/cells/acme/**,"
    ) in profile
    assert (
        "mount options in (ro, rw, bind, rbind, remount, nosuid, nodev, noexec)"
        " /var/lib/spanel/cells/acme/** -> /var/lib/spanel/cells/acme/**" in profile
    )
    # The hard denials from the original profile are preserved.
    assert "audit deny /var/run/docker.sock rw," in profile
    assert "audit deny /run/secrets/** r," in profile
    assert "/var/lib/spanel/cells/other" not in profile


def test_network_spec_targets_dedicated_loopback_and_skuid() -> None:
    cell = {"index": 3, "uid": 60003}
    spec = network.build_network_spec("acme", cell, "skuid")

    assert spec["loopback_address"] != "127.0.0.1"
    assert spec["loopback_address"].startswith("127.")
    assert any("skuid" in rule for rule in spec["nft_rules"])
    assert any(str(cell["uid"]) in rule for rule in spec["nft_rules"])
    other = network.build_network_spec("beta", {"index": 4, "uid": 60004}, "skuid")
    assert other["loopback_address"] != spec["loopback_address"]


def test_cell_is_degraded_when_daemon_failed_to_start(tmp_path) -> None:
    class DeadUserManager(FakeProbe):
        def user_service_main_pid(self, slug: str, uid: int) -> int:
            return 0

    svc, _, _ = _service(
        tmp_path, executor=FakeExecutor(pid=0), probe=DeadUserManager()
    )

    result = svc.provision("acme")

    assert result["state"] == "degraded"
    assert result["apparmor"]["effective"] is False


def test_two_tenants_get_distinct_userspaces(tmp_path) -> None:
    """Two slugs must never share uid, subuid range, socket, cgroup or profile."""
    map_a = [{"host_id": 60000, "inner_id": 0, "count": 1}]
    map_b = [{"host_id": 60001, "inner_id": 0, "count": 1}]
    probe_a = FakeProbe(uid_map=map_a, gid_map=map_a)
    probe_b = FakeProbe(uid_map=map_b, gid_map=map_b)
    exec_a, exec_b = FakeExecutor(pid=4001), FakeExecutor(pid=4002)
    svc_a = CellService(probe_a, exec_a, tmp_path)
    svc_b = CellService(probe_b, exec_b, tmp_path)

    a = svc_a.provision("acme")
    b = svc_b.provision("beta")

    assert a["uid"] != b["uid"]
    assert a["socket_path"] != b["socket_path"]
    assert a["cgroup_path"] != b["cgroup_path"]
    assert a["apparmor"]["profile"] != b["apparmor"]["profile"]
    # The host-observed mapping is different for each cell: inner UID 0 is
    # reported as each cell's real host uid, not a shared formula.
    assert a["uid_map"][0]["host_id"] != b["uid_map"][0]["host_id"]

    reg = alloc.load_registry(tmp_path)
    cell_a, cell_b = reg["allocations"]["acme"], reg["allocations"]["beta"]
    block = int(reg["block_size"])
    assert cell_a["uid"] != cell_b["uid"]
    assert cell_a["gid"] != cell_b["gid"]
    assert cell_a["subuid_base"] + block <= cell_b["subuid_base"]
    assert cell_a["subgid_base"] + block <= cell_b["subgid_base"]

    users = {
        kw["name"]: kw["uid"]
        for name, kw in exec_a.calls + exec_b.calls
        if name == "ensure_user"
    }
    assert users == {"spanel-acme": cell_a["uid"], "spanel-beta": cell_b["uid"]}

    spec_a = next(kw["spec"] for name, kw in exec_a.calls if name == "apply_network")
    spec_b = next(kw["spec"] for name, kw in exec_b.calls if name == "apply_network")
    assert spec_a["table"] != spec_b["table"]
    assert spec_a["loopback_address"] != spec_b["loopback_address"]
    assert spec_a["publish_port"] != spec_b["publish_port"]
    assert spec_a["cell_uid"] != spec_b["cell_uid"]


def test_systemd_unit_uses_rootlesskit_netns_and_no_host_iptables() -> None:
    from scripts.tenant_cell.executor import systemd_unit

    unit = systemd_unit("acme", 60000, "/system.slice/spanel-cell-acme.scope")

    assert "DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=false" in unit
    assert "--iptables=false" in unit
    assert "--ip6tables=false" in unit
    assert "Delegate=yes" in unit
    assert "XDG_RUNTIME_DIR=/run/user/60000" in unit
    assert "AppArmorProfile=spanel-cell-acme" in unit
    assert "DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SANDBOX=false" in unit
    assert "DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=true" in unit
    assert "Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_NET=gvisor-tap-vsock" in unit
    assert "Environment=SPANEL_TENANT_CELL_DNS=10.0.2.1" in unit
    assert "--dns ${SPANEL_TENANT_CELL_DNS}" in unit
    assert "--config-file=/var/lib/spanel/cells/acme/daemon.json" in unit
    assert "ExecStartPost=" not in unit
    assert "ExecStopPost=" not in unit


def test_netns_masquerade_command_always_targets_dockerd_pid() -> None:
    argv = network.netns_masquerade_argv(4242, "172.17.0.0/16", "-C")
    assert argv[:5] == ["/usr/bin/nsenter", "-t", "4242", "-n", "iptables"]
    assert argv[-4:] == ["-s", "172.17.0.0/16", "-j", "MASQUERADE"]


def test_cell_dns_is_configurable_and_rejects_host_loopback(monkeypatch) -> None:
    monkeypatch.setenv("SPANEL_TENANT_CELL_DNS", "100.100.100.100")
    unit = systemd_unit("acme", 60000, "/some/path", "systemd")
    assert "Environment=SPANEL_TENANT_CELL_DNS=100.100.100.100" in unit
    assert "DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=true" in unit

    monkeypatch.setenv("SPANEL_TENANT_CELL_DNS", "127.0.0.53")
    with pytest.raises(ValueError, match="reachable unicast resolver"):
        systemd_unit("acme", 60000, "/some/path", "systemd")


def test_cell_dns_follows_the_rootlesskit_network_driver(monkeypatch) -> None:
    monkeypatch.delenv("SPANEL_TENANT_CELL_DNS", raising=False)

    assert network.cell_network_driver() == "gvisor-tap-vsock"
    assert network.cell_dns_resolver() == "10.0.2.1"
    unit = systemd_unit("acme", 60000, "/some/path", "systemd")
    assert "Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_NET=gvisor-tap-vsock" in unit
    assert "Environment=SPANEL_TENANT_CELL_DNS=10.0.2.1" in unit

    monkeypatch.setenv("SPANEL_TENANT_CELL_NET", "slirp4netns")
    assert network.cell_dns_resolver() == "10.0.2.3"
    unit = systemd_unit("acme", 60000, "/some/path", "systemd")
    assert "Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_NET=slirp4netns" in unit
    assert "Environment=SPANEL_TENANT_CELL_DNS=10.0.2.3" in unit

    monkeypatch.setenv("SPANEL_TENANT_CELL_NET", "pasta")
    with pytest.raises(ValueError, match="SPANEL_TENANT_CELL_NET"):
        network.cell_dns_resolver()


def test_local_executor_creates_output_chain_before_rules(monkeypatch) -> None:
    """The inet table needs an explicit output chain before any rule is added."""
    from types import SimpleNamespace

    from scripts.tenant_cell import executor

    calls: list[list[str]] = []
    monkeypatch.setenv("SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS", "1")
    monkeypatch.setattr(
        executor.subprocess,
        "run",
        lambda argv, **_kw: calls.append(list(argv)) or SimpleNamespace(returncode=0),
    )
    spec = network.build_network_spec("acme", {"index": 0, "uid": 60000}, "skuid")

    executor.LocalExecutor().apply_network(spec)

    assert calls[0][:4] == ["nft", "add", "table", "inet"]
    assert calls[1][1:4] == ["add", "chain", "inet"]
    assert calls[1][4] == spec["table"]
    assert any("skuid" in " ".join(call) for call in calls[2:])


def test_deprovision_removes_only_its_own_nft_table(tmp_path) -> None:
    exec_a, exec_b = FakeExecutor(pid=4001), FakeExecutor(pid=4002)
    svc_a = CellService(FakeProbe(), exec_a, tmp_path)
    svc_b = CellService(FakeProbe(), exec_b, tmp_path)
    svc_a.provision("acme")
    svc_b.provision("beta")

    svc_a.deprovision("acme", keep_data=False)

    removed = next(kw["spec"] for name, kw in exec_a.calls if name == "remove_network")
    assert removed["table"] == "spanel-cell-acme"
    assert removed["table"] != "spanel-cells"
    assert not any(name == "remove_network" for name, _ in exec_b.calls)


def test_apparmor_verify_uses_live_effective_profile(tmp_path) -> None:
    svc = CellService(FakeProbe(effective=True), FakeExecutor(), tmp_path)
    svc.provision("acme")

    stale = CellService(FakeProbe(effective=False), FakeExecutor(), tmp_path)
    result = stale.apparmor_verify("acme")

    assert result["hash_matches"] is True  # stored profile unchanged
    assert result["effective"] is False  # but the daemon is no longer confined
    assert result["ok"] is False  # so verification must fail


def test_netns_fallback_when_probe_reports_no_skuid(tmp_path) -> None:
    svc, _, executor = _service(tmp_path, probe=FakeProbe(skuid=False, netns=True))

    result = svc.provision("acme")

    assert result["network_mode"] == "netns"
    applied_spec = next(
        kw["spec"] for name, kw in executor.calls if name == "apply_network"
    )
    assert applied_spec["mode"] == "netns"
    assert applied_spec["netns"] == "spanel-acme"


# --- A.SPEC 0099: systemd cgroup driver -------------------------------------


def test_new_cell_defaults_to_systemd_driver_and_user_unit(tmp_path) -> None:
    svc, _, executor = _service(tmp_path)

    result = svc.provision("acme")

    assert result["cgroup_driver"] == "systemd"
    assert "ensure_delegation" in executor.names()
    config = next(
        kw for name, kw in executor.calls if name == "write_daemon_config"
    )
    assert config["driver"] == "systemd"
    unit_kw = next(
        kw for name, kw in executor.calls if name == "install_systemd_unit"
    )
    assert unit_kw["driver"] == "systemd"
    start_kw = next(kw for name, kw in executor.calls if name == "start_daemon")
    assert start_kw["driver"] == "systemd"


def test_systemd_unit_template_uses_user_bus_and_aa_exec() -> None:
    unit = systemd_unit("acme", 60000, "/some/path", "systemd")

    assert "AppArmorProfile=" not in unit  # a user manager cannot set it
    assert "User=" not in unit
    assert "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/60000/bus" in unit
    assert "XDG_RUNTIME_DIR=/run/user/60000" in unit
    assert "/usr/bin/aa-exec -p spanel-cell-acme -- /usr/bin/dockerd-rootless.sh" in unit
    assert "native.cgroupdriver" not in unit  # driver lives in daemon.json
    assert "WantedBy=default.target" in unit


def test_legacy_unit_template_is_unchanged() -> None:
    unit = systemd_unit("acme", 60000, "/some/path", "cgroupfs")

    assert "User=spanel-acme" in unit
    assert "AppArmorProfile=spanel-cell-acme" in unit
    assert "WantedBy=multi-user.target" in unit


def test_apparmor_profile_has_systemd_rules_without_format_placeholders() -> None:
    profile = apparmor.render_profile("acme")

    assert "dbus (send, receive) bus=session," in profile
    assert "dbus (send, receive) bus=system," not in profile  # no system-bus grant
    assert "deny dbus bus=system," in profile  # system bus explicitly denied
    assert "/proc/[0-9]*/sessionid r," in profile
    assert "user@[0-9]*.service/** rwkl," in profile
    assert "/proc/[0-9]*/stat r," in profile
    assert "/proc/[0-9]*/cmdline r," in profile


def test_doctor_accepts_explicit_delegate_controllers() -> None:
    from scripts.tenant_cell.doctor import delegate_controllers_ok

    assert delegate_controllers_ok("[Service]\nDelegate=yes\n") is True
    assert delegate_controllers_ok("[Service]\nDelegate=cpu cpuset io memory pids\n") is True
    assert delegate_controllers_ok("[Service]\nDelegate=pids memory cpu\n") is False
    assert delegate_controllers_ok("[Service]\nDelegate=no\n") is False


def _legacy_cell(tmp_path) -> None:
    alloc.allocate(str(tmp_path), "acme")
    alloc.update_allocation(
        str(tmp_path), "acme", cgroup_driver="cgroupfs", state="ready"
    )


def test_repair_does_not_downgrade_a_systemd_cell(tmp_path) -> None:
    svc, _, executor = _service(tmp_path)
    svc.provision("acme")
    executor.calls.clear()

    result = svc.repair("acme")

    assert result["cgroup_driver"] == "systemd"
    config = next(
        kw for name, kw in executor.calls if name == "write_daemon_config"
    )
    assert config["driver"] == "systemd"


def test_migrate_legacy_cell_verifies_limits(tmp_path) -> None:
    _legacy_cell(tmp_path)
    svc, _, executor = _service(tmp_path)

    result = svc.migrate("acme", "systemd")

    assert result["cgroup_driver"] == "systemd"
    assert result["migration"]["from"] == "cgroupfs"
    assert result["migration"]["verification"]["ok"] is True
    assert "run_limit_probe" in executor.names()
    assert "backup_files" in executor.names()
    record = audit.read_audit(tmp_path)[-1]
    assert record["verb"] == "migrate"
    assert record["exit_code"] == 0


def test_migrate_rolls_back_when_kernel_limits_are_not_applied(tmp_path) -> None:
    _legacy_cell(tmp_path)

    class FailingProbe(FakeExecutor):
        def run_limit_probe(self, slug, uid):
            self._rec("run_limit_probe", slug=slug, uid=uid)
            return {"ok": False, "error": "limits not applied"}

    svc, _, executor = _service(tmp_path, executor=FailingProbe())

    with pytest.raises(MigrationVerificationFailed):
        svc.migrate("acme", "systemd")

    assert alloc.cgroup_driver(
        alloc.load_registry(tmp_path)["allocations"]["acme"]
    ) == "cgroupfs"
    assert "restore_files" in executor.names()
    assert "start_daemon" in executor.names()
    record = audit.read_audit(tmp_path)[-1]
    assert record["exit_code"] == 1
    assert record["rolled_back"] is True


def test_verify_limits_is_refused_for_legacy_cells(tmp_path) -> None:
    _legacy_cell(tmp_path)
    svc, _, executor = _service(tmp_path)

    result = svc.verify_limits("acme")

    assert result["ok"] is False
    assert "run_limit_probe" not in executor.names()


def test_delegate_controllers_cover_the_five_required() -> None:
    assert set(DELEGATE_CONTROLLERS.split()) == {
        "cpu", "cpuset", "io", "memory", "pids"
    }


# --- A.SPEC 0100: a plan survives provision / repair -----------------------


class PlanAwareExecutor(FakeExecutor):
    """A cell executor that also records the A.SPEC 0100 plan operations."""

    def __init__(self) -> None:
        super().__init__()
        self.effective: dict[str, str] = {}

    def read_plan_state(self, uid):
        self._rec("read_plan_state", uid=uid)
        return {
            "slice": f"user-{uid}.slice",
            "properties": {},
            "effective": dict(self.effective),
            "owner_uid": str(uid),
            "cgroup_path": f"/user.slice/user-{uid}.slice/user@{uid}.service",
        }

    def apply_plan_in_place(self, uid, plan):
        from scripts.tenant_cell import plans

        self._rec("apply_plan_in_place", uid=uid, plan=plan)
        self.effective = plans.expected_probe_limits(plan)

    def reset_plan_properties(self, uid):
        self._rec("reset_plan_properties", uid=uid)
        self.effective = {}

    def cleanup_legacy_plan(self, slug, uid):
        self._rec("cleanup_legacy_plan", slug=slug, uid=uid)
        return False

    def install_tenant_slice(self, slug, plan):
        self._rec("install_tenant_slice", slug=slug, plan=plan)

    def remove_tenant_slice(self, slug):
        self._rec("remove_tenant_slice", slug=slug)

    def install_user_manager_dropin(self, slug, uid):
        self._rec("install_user_manager_dropin", slug=slug, uid=uid)

    def remove_user_manager_dropin(self, slug, uid):
        self._rec("remove_user_manager_dropin", slug=slug, uid=uid)

    def restart_user_manager(self, uid):
        self._rec("restart_user_manager", uid=uid)

    def run_plan_probe(self, slug, uid, plan):
        self._rec("run_plan_probe", slug=slug, uid=uid, plan=plan)
        return {"ok": True}


def test_repair_and_provision_preserve_an_active_tenant_plan(tmp_path, monkeypatch) -> None:
    from scripts.tenant_cell import materializer, plans

    monkeypatch.setenv("SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS", "1")
    executor = PlanAwareExecutor()
    svc = CellService(FakeProbe(), executor, tmp_path)
    svc.provision("acme")
    materializer.PlanMaterializer(executor, tmp_path).apply(
        "acme", {"memory": "512M", "cpus": 0.5, "pids": 128}
    )
    executor.calls.clear()

    svc.repair("acme")

    cell = alloc.load_registry(tmp_path)["allocations"]["acme"]
    assert alloc.cgroup_driver(cell) == "systemd"
    assert plans.active_plan(tmp_path, "acme")["plan"]["pids"] == 128
    assert "cleanup_legacy_plan" in executor.names()
    assert "install_tenant_slice" not in executor.names()
    assert "install_user_manager_dropin" not in executor.names()
    assert "apply_plan_in_place" not in executor.names()

    executor.calls.clear()
    svc.provision("acme")

    assert alloc.cgroup_driver(
        alloc.load_registry(tmp_path)["allocations"]["acme"]
    ) == "systemd"
    assert plans.active_plan(tmp_path, "acme")["plan"]["memory"] == "512M"
    assert "cleanup_legacy_plan" in executor.names()
    assert "install_tenant_slice" not in executor.names()


def test_repair_reasserts_a_drifted_plan_in_place(tmp_path, monkeypatch) -> None:
    from scripts.tenant_cell import materializer

    monkeypatch.setenv("SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS", "1")
    executor = PlanAwareExecutor()
    svc = CellService(FakeProbe(), executor, tmp_path)
    svc.provision("acme")
    materializer.PlanMaterializer(executor, tmp_path).apply(
        "acme", {"memory": "512M", "cpus": 0.5, "pids": 128}
    )
    executor.calls.clear()
    executor.effective = {}

    svc.repair("acme")

    assert "cleanup_legacy_plan" in executor.names()
    assert "apply_plan_in_place" in executor.names()
    assert "install_tenant_slice" not in executor.names()


def test_repair_of_a_cell_without_a_plan_installs_no_slice(tmp_path) -> None:
    svc, _, executor = _service(tmp_path)
    svc.provision("acme")
    executor.calls.clear()

    svc.repair("acme")

    assert "cleanup_legacy_plan" not in executor.names()
    assert "install_tenant_slice" not in executor.names()
    assert "install_user_manager_dropin" not in executor.names()


# --- A.SPEC 0103: user commands run as the cell user, not root --------------


def test_run_user_switches_identity_via_runuser(monkeypatch) -> None:
    """No ``systemctl --user`` may run as root: wrap it in runuser -u <user>."""
    from types import SimpleNamespace

    from scripts.tenant_cell import executor as exec_mod

    monkeypatch.setenv("SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS", "1")
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(exec_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(
        exec_mod.pwd,
        "getpwuid",
        lambda uid: SimpleNamespace(pw_name="spanel-acme"),
    )

    exec_mod.LocalExecutor()._run_user(
        60000, ["systemctl", "--user", "start", "spanel-cell-acme"]
    )

    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv == [
        "runuser", "-u", "spanel-acme", "--",
        "systemctl", "--user", "start", "spanel-cell-acme",
    ]
    env = kwargs["env"]
    assert env["XDG_RUNTIME_DIR"] == "/run/user/60000"
    assert env["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/user/60000/bus"


# --- A.SPEC 0109-R3: cell-netns egress + builtin rootlesskit port driver -----


def test_network_spec_carries_nat_and_port_driver_for_both_modes() -> None:
    for mode in ("skuid", "netns"):
        spec = network.build_network_spec("acme", {"index": 3, "uid": 60003}, mode)

        assert spec["egress_subnet"] == "172.17.0.0/16"
        assert spec["egress"]["subnet"] == "172.17.0.0/16"
        assert spec["egress"]["check"] == [
            "iptables", "-t", "nat", "-C", "POSTROUTING",
            "-s", "172.17.0.0/16", "-j", "MASQUERADE",
        ]
        assert spec["egress"]["add"][3] == "-A"
        assert spec["egress"]["delete"][3] == "-D"
        assert spec["egress"]["add"][4:] == spec["egress"]["delete"][4:]
        assert spec["rootlesskit_env"] == {
            "DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER": "builtin"
        }
        assert spec["loopback_address"].startswith("127.")
        assert spec["publish_port"] == 20003


def test_egress_subnet_is_validated_and_configurable(monkeypatch) -> None:
    monkeypatch.setenv("SPANEL_TENANT_CELL_EGRESS_SUBNET", "10.7.0.0/16")
    assert network.egress_subnet() == "10.7.0.0/16"

    monkeypatch.setenv("SPANEL_TENANT_CELL_EGRESS_SUBNET", "127.0.0.0/8")
    with pytest.raises(ValueError, match="unicast subnet"):
        network.egress_subnet()

    monkeypatch.setenv("SPANEL_TENANT_CELL_EGRESS_SUBNET", "0.0.0.0/0")
    with pytest.raises(ValueError, match="whole IPv4 space"):
        network.egress_subnet()

    monkeypatch.setenv("SPANEL_TENANT_CELL_EGRESS_SUBNET", "not-a-cidr")
    with pytest.raises(ValueError, match="IPv4 CIDR"):
        network.egress_subnet()

    with pytest.raises(ValueError, match="unsupported iptables action"):
        network.masquerade_argv(action="-I")


def test_user_unit_leaves_nat_to_the_privileged_host_lifecycle() -> None:
    unit = systemd_unit("acme", 60000, "/some/path", "systemd")

    assert "Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=builtin\n" in unit
    assert "ExecStartPost=" not in unit
    assert "ExecStopPost=" not in unit
    assert "nsenter" not in unit
    # The invariants stay intact: no host iptables, NAT only in the cell netns.
    assert "--iptables=false" in unit
    assert "--ip6tables=false" in unit
    assert "--dns ${SPANEL_TENANT_CELL_DNS}" in unit
    assert "DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=false" in unit


def test_legacy_unit_also_leaves_nat_to_the_privileged_host_lifecycle() -> None:
    unit = systemd_unit("acme", 60000, "/some/path", "cgroupfs")
    assert "Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=builtin\n" in unit
    assert "ExecStartPost=" not in unit
    assert "ExecStopPost=" not in unit
    assert "--iptables=false" in unit


def test_deprovision_spec_reverts_the_cell_nat(tmp_path) -> None:
    svc, _, executor = _service(tmp_path)
    svc.provision("acme")
    svc.deprovision("acme", keep_data=False)

    applied = next(kw["spec"] for name, kw in executor.calls if name == "apply_network")
    removed = next(kw["spec"] for name, kw in executor.calls if name == "remove_network")
    assert applied["egress"]["subnet"] == removed["egress"]["subnet"]
    assert removed["egress"]["delete"] == [
        "iptables", "-t", "nat", "-D", "POSTROUTING",
        "-s", "172.17.0.0/16", "-j", "MASQUERADE",
    ]


def test_dockerd_pid_is_selected_by_cell_uid_not_wrapper_pid(tmp_path) -> None:
    from scripts.tenant_cell.executor import dockerd_pid_for_uid

    for pid, uid, argv0 in (
        (7100, 60000, "/usr/bin/dockerd-rootless.sh"),
        (7101, 60001, "/usr/bin/dockerd"),
        (7331, 60000, "/usr/bin/dockerd"),
    ):
        process = tmp_path / str(pid)
        process.mkdir()
        (process / "status").write_text(
            f"Name:\ttest\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n",
            encoding="utf-8",
        )
        (process / "cmdline").write_bytes(argv0.encode() + b"\0--flag\0")

    assert dockerd_pid_for_uid(60000, tmp_path) == 7331


def test_cell_egress_rejects_host_netns_before_iptables(monkeypatch) -> None:
    from scripts.tenant_cell import executor as exec_mod

    local = exec_mod.LocalExecutor()
    monkeypatch.setenv("SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS", "1")
    monkeypatch.setattr(local, "cell_dockerd_pid", lambda _uid: 7331)
    monkeypatch.setattr(exec_mod.os, "readlink", lambda _path: "net:[4026531840]")
    calls: list[list[str]] = []
    monkeypatch.setattr(
        exec_mod.subprocess,
        "run",
        lambda argv, **_kwargs: calls.append(list(argv)),
    )

    with pytest.raises(RuntimeError, match="uses host netns"):
        local.ensure_cell_egress(60000, "172.17.0.0/16")

    assert calls == []


def test_cell_egress_apply_is_pid_correct_and_idempotent(monkeypatch) -> None:
    from types import SimpleNamespace

    from scripts.tenant_cell import executor as exec_mod

    local = exec_mod.LocalExecutor()
    installed = False
    calls: list[list[str]] = []
    monkeypatch.setenv("SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS", "1")
    monkeypatch.setattr(local, "cell_dockerd_pid", lambda _uid: 7331)
    monkeypatch.setattr(
        exec_mod.os,
        "readlink",
        lambda path: "net:[cell]" if path == "/proc/7331/ns/net" else "net:[host]",
    )

    def fake_run(argv, **_kwargs):
        nonlocal installed
        calls.append(list(argv))
        action = argv[7]
        if action == "-C":
            return SimpleNamespace(returncode=0 if installed else 1)
        if action == "-A":
            installed = True
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(exec_mod.subprocess, "run", fake_run)

    local.ensure_cell_egress(60000, "172.17.0.0/16")
    local.ensure_cell_egress(60000, "172.17.0.0/16")

    assert all(call[2:4] == ["7331", "-n"] for call in calls)
    assert [call[7] for call in calls].count("-A") == 1


def test_cell_egress_remove_reverts_only_cell_rule(monkeypatch) -> None:
    from types import SimpleNamespace

    from scripts.tenant_cell import executor as exec_mod

    local = exec_mod.LocalExecutor()
    installed = True
    calls: list[list[str]] = []
    monkeypatch.setenv("SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS", "1")
    monkeypatch.setattr(local, "cell_dockerd_pid", lambda _uid: 7331)
    monkeypatch.setattr(
        exec_mod.os,
        "readlink",
        lambda path: "net:[cell]" if path == "/proc/7331/ns/net" else "net:[host]",
    )

    def fake_run(argv, **_kwargs):
        nonlocal installed
        calls.append(list(argv))
        action = argv[7]
        if action == "-C":
            return SimpleNamespace(returncode=0 if installed else 1)
        if action == "-D":
            installed = False
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(exec_mod.subprocess, "run", fake_run)

    local.remove_cell_egress(60000, "172.17.0.0/16")

    assert installed is False
    assert [call[7] for call in calls].count("-D") == 1
    assert all(call[2:4] == ["7331", "-n"] for call in calls)
