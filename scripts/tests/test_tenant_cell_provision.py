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
    ProvisionRefused,
)
from scripts.tenant_cell.doctor import HostProbe

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

    def write_daemon_config(self, cell_dir, uid, gid):
        self._rec("write_daemon_config", cell_dir=cell_dir, uid=uid, gid=gid)

    def install_profile(self, name, content):
        self._rec("install_profile", name=name, content=content)

    def apply_network(self, spec):
        self._rec("apply_network", spec=spec)

    def install_systemd_unit(self, slug, uid, cgroup_path):
        self._rec("install_systemd_unit", slug=slug, uid=uid, cgroup_path=cgroup_path)

    def start_daemon(self, slug):
        self._rec("start_daemon", slug=slug)
        return self.pid

    def stop_daemon(self, slug):
        self._rec("stop_daemon", slug=slug)

    def remove_network(self, spec):
        self._rec("remove_network", spec=spec)

    def remove_profile(self, name):
        self._rec("remove_profile", name=name)

    def remove_systemd_unit(self, slug):
        self._rec("remove_systemd_unit", slug=slug)

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
    assert result["cgroup_path"] == "/system.slice/spanel-cell-acme.scope"
    # The socket is created by the cell user path, never the global docker.sock.
    assert "/var/run/docker.sock" not in result["socket_path"]
    assert "ensure_user" in executor.names()
    assert "ensure_user_manager" in executor.names()
    assert "write_daemon_config" in executor.names()
    assert "apply_network" in executor.names()


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
    assert {"stop_daemon", "remove_systemd_unit", "remove_network", "remove_profile"} <= set(executor.names())


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
    # containerd decompresses pulled layers through unpigz (regression: E2E in
    # cell-g found pull blocked by an AppArmor exec denial for this binary).
    assert "/usr/bin/unpigz ix," in profile
    assert "qemu-check*/** ix," in profile
    assert "options=(ro, rbind) /var/lib/spanel/cells/acme/**" in profile
    with pytest.raises(alloc.InvalidSlug):
        apparmor.render_profile("acme\n  deny /etc/** rw,")


def test_apparmor_profile_allows_rootless_build_and_exec() -> None:
    """E2E in cell-g found each of these denials blocking a real deploy.

    All grants stay inside this cell's own tree (or are read-only host paths),
    so cross-cell and rootful-socket denials remain intact.
    """
    profile = apparmor.render_profile("acme")
    assert "capability net_raw," in profile
    assert "/bin/busybox ix," in profile
    assert "/proc/pressure/** r," in profile
    assert "/proc/self/{setgroups,uid_map,gid_map} rw," in profile
    assert "remount options in (ro, rw, nosuid, nodev, noexec, bind, rbind)" in profile
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
    svc, _, _ = _service(tmp_path, executor=FakeExecutor(pid=0))

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
    assert "--config-file=/var/lib/spanel/cells/acme/daemon.json" in unit


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
