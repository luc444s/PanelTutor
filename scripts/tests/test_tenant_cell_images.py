"""A.SPEC 0119: image preloading into rootless cells (no Docker required)."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tenant_cell import alloc
from scripts.tenant_cell import images as mod
from scripts.tenant_cell.cells import CellService
from scripts.tenant_cell.doctor import HostProbe
from scripts.tenant_cell.executor import Executor, LocalExecutor

CELL = "/var/lib/spanel/cells/acme/docker.sock"
ROOTFUL = "/var/run/docker.sock"


class _FakeProcess:
    """Minimal ``Popen`` stand-in: save/load succeed and flip the image state."""

    def __init__(self, argv: list[str], **kwargs: object) -> None:
        self.argv = list(argv)
        self.kwargs = dict(kwargs)
        self.returncode = 0
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"")
        self.stdin = kwargs.get("stdin")
        self.killed = False
        processes.append(self)
        if "load" in self.argv:
            # ``docker load`` has no image argument: the stream decides it.
            for previous in reversed(processes[:-1]):
                if "save" in previous.argv:
                    state["cell"].add(previous.argv[-1])
                    break

    def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        return b"", b""

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def poll(self) -> int:
        return self.returncode

    def kill(self) -> None:
        self.killed = True


state: dict[str, set[str]] = {"cell": set(), "rootful": set()}
processes: list[_FakeProcess] = []
runs: list[list[str]] = []


def _install_fake(
    monkeypatch: pytest.MonkeyPatch,
    *,
    cell_images: tuple[str, ...] = (),
    rootful_images: tuple[str, ...] = (),
) -> list[list[str]]:
    global state, processes, runs
    state = {"cell": set(cell_images), "rootful": set(rootful_images)}
    processes = []
    runs = []

    def fake_run(argv: list[str], **kwargs: object) -> SimpleNamespace:
        assert kwargs.get("shell") in (None, False)
        runs.append(list(argv))
        socket = str(argv[2]).removeprefix("unix://")
        image = str(argv[-1])
        if "inspect" in argv:
            present = image in state["cell" if socket == CELL else "rootful"]
            return SimpleNamespace(
                returncode=0 if present else 1, stdout=b"", stderr=b""
            )
        if "pull" in argv:
            state["rootful"].add(image)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(f"unexpected docker command: {argv}")

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.subprocess, "Popen", _FakeProcess)
    return runs


def test_desired_images_uses_hosting_env_without_duplicates(monkeypatch) -> None:
    monkeypatch.delenv("SPANEL_HOSTING_WP_IMAGE", raising=False)
    monkeypatch.delenv("SPANEL_HOSTING_DB_IMAGE", raising=False)
    monkeypatch.delenv("SPANEL_HOSTING_STATIC_IMAGE", raising=False)
    assert mod.desired_images() == [
        "wordpress:latest", "mariadb:11", "nginx:alpine"
    ]

    monkeypatch.setenv("SPANEL_HOSTING_WP_IMAGE", "wordpress:6.8")
    monkeypatch.setenv("SPANEL_HOSTING_DB_IMAGE", "wordpress:6.8")
    assert mod.desired_images() == ["wordpress:6.8", "nginx:alpine"]


def test_image_exists_inspects_on_the_given_socket(monkeypatch) -> None:
    _install_fake(monkeypatch, rootful_images=("wordpress:latest",))

    assert mod.image_exists(ROOTFUL, "wordpress:latest") is True
    assert runs == [
        ["docker", "-H", f"unix://{ROOTFUL}", "image", "inspect", "wordpress:latest"]
    ]


def test_ensure_image_streams_the_rootful_copy_without_pulling(monkeypatch) -> None:
    _install_fake(monkeypatch, rootful_images=("wordpress:latest",))

    assert mod.ensure_image(CELL, "wordpress:latest") == "transferred"

    assert [process.argv[3] for process in processes] == ["save", "load"]
    assert processes[0].argv[:3] == ["docker", "-H", f"unix://{ROOTFUL}"]
    assert processes[1].argv[:3] == ["docker", "-H", f"unix://{CELL}"]
    assert all(process.kwargs.get("shell") in (None, False) for process in processes)
    assert all("pull" not in argv for argv in runs)
    assert state["cell"] == {"wordpress:latest"}


def test_ensure_image_pulls_in_rootful_when_the_host_lacks_it(monkeypatch) -> None:
    _install_fake(monkeypatch)

    assert mod.ensure_image(CELL, "mariadb:11") == "pulled"

    pulls = [argv for argv in runs if "pull" in argv]
    assert pulls == [["docker", "-H", f"unix://{ROOTFUL}", "pull", "mariadb:11"]]
    assert [process.argv[3] for process in processes] == ["save", "load"]


def test_ensure_image_is_idempotent_when_the_cell_already_has_it(monkeypatch) -> None:
    _install_fake(monkeypatch, cell_images=("wordpress:latest",))

    assert mod.ensure_image(CELL, "wordpress:latest") == "present"

    assert processes == []
    assert runs == [
        ["docker", "-H", f"unix://{CELL}", "image", "inspect", "wordpress:latest"]
    ]


def test_ensure_image_does_not_retransfer_on_a_second_call(monkeypatch) -> None:
    _install_fake(monkeypatch, rootful_images=("wordpress:latest",))

    assert mod.ensure_image(CELL, "wordpress:latest") == "transferred"
    transferred = list(processes)

    assert mod.ensure_image(CELL, "wordpress:latest") == "present"
    assert processes == transferred


def test_ensure_cell_images_skips_cells_without_a_daemon(tmp_path) -> None:
    alloc.allocate(str(tmp_path), "acme")

    assert mod.ensure_cell_images(tmp_path) == [
        {"slug": "acme", "images": "no-cell-daemon"}
    ]


def test_ensure_cell_images_reports_unchanged_when_present(tmp_path, monkeypatch) -> None:
    alloc.allocate(str(tmp_path), "acme")
    monkeypatch.setattr(Path, "is_socket", lambda _self: True)
    monkeypatch.setattr(mod, "ensure_image", lambda _socket, _image: "present")

    assert mod.ensure_cell_images(tmp_path) == [
        {
            "slug": "acme",
            "images": "unchanged",
            "detail": {
                "wordpress:latest": "present",
                "mariadb:11": "present",
                "nginx:alpine": "present",
            },
        }
    ]


def test_ensure_cell_images_reports_transfers_and_isolates_failures(
    tmp_path, monkeypatch
) -> None:
    alloc.allocate(str(tmp_path), "acme")
    alloc.allocate(str(tmp_path), "beta")
    monkeypatch.setattr(Path, "is_socket", lambda _self: True)

    def fake_ensure(socket_path: str, image: str) -> str:
        if socket_path.endswith("/beta/docker.sock") and image == "mariadb:11":
            raise RuntimeError("cell daemon is stuck")
        return "transferred" if image == "wordpress:latest" else "present"

    monkeypatch.setattr(mod, "ensure_image", fake_ensure)

    results = {row["slug"]: row for row in mod.ensure_cell_images(tmp_path)}

    assert results["acme"] == {
        "slug": "acme",
        "images": "updated",
        "detail": {
            "wordpress:latest": "transferred",
            "mariadb:11": "present",
            "nginx:alpine": "present",
        },
    }
    assert results["beta"]["images"] == "failed"
    assert "cell daemon is stuck" in results["beta"]["detail"]


def test_base_executor_ensure_cell_images_is_a_noop(monkeypatch) -> None:
    from scripts.tenant_cell import executor as exec_mod

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("base hook must not touch Docker")

    monkeypatch.setattr(exec_mod, "ensure_cell_image", forbidden)

    assert Executor().ensure_cell_images(CELL, ["wordpress:latest"]) is None


def test_local_executor_delegates_each_image_and_requires_the_gate(
    monkeypatch,
) -> None:
    from scripts.tenant_cell import executor as exec_mod

    monkeypatch.delenv("SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS", raising=False)
    with pytest.raises(RuntimeError, match="local mutations disabled"):
        LocalExecutor().ensure_cell_images(CELL, ["wordpress:latest"])

    monkeypatch.setenv("SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS", "1")
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        exec_mod,
        "ensure_cell_image",
        lambda socket_path, image: calls.append((socket_path, image)),
    )

    LocalExecutor().ensure_cell_images(CELL, ["wordpress:latest", "mariadb:11"])

    assert calls == [(CELL, "wordpress:latest"), (CELL, "mariadb:11")]


class _Probe(HostProbe):
    def cgroup2_available(self) -> bool:
        return True

    def systemd_delegate(self) -> bool:
        return True

    def apparmor_enabled(self) -> bool:
        return True

    def apparmor_parser_available(self) -> bool:
        return True

    def nftables_skuid_supported(self) -> bool:
        return True

    def subuid_range_free(self) -> bool:
        return True

    def rootless_docker_available(self) -> bool:
        return True

    def network_mode(self) -> str:
        return "skuid"

    def service_main_pid(self, slug: str) -> int:
        return 4242

    def user_service_main_pid(self, slug: str, uid: int) -> int:
        return 4242

    def daemon_pid(self, main_pid: int, uid: int | None = None) -> int:
        return max(0, main_pid)

    def profile_effective(self, pid: int, profile: str) -> bool:
        return True

    def read_uid_map(self, pid: int) -> list[dict[str, int]]:
        return [{"host_id": 60000, "inner_id": 0, "count": 1}]

    def read_gid_map(self, pid: int) -> list[dict[str, int]]:
        return [{"host_id": 60000, "inner_id": 0, "count": 1}]


class _RecordingExecutor(Executor):
    """Records provision mutations without touching the host."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.image_calls: list[tuple[str, list[str]]] = []

    def _rec(self, name: str) -> None:
        self.calls.append(name)

    def ensure_delegation(self) -> None:
        self._rec("ensure_delegation")

    def ensure_user(self, name: str, uid: int, gid: int) -> None:
        self._rec("ensure_user")

    def ensure_subids(
        self, name: str, uid: int, subuid_base: int, subgid_base: int, count: int
    ) -> None:
        self._rec("ensure_subids")

    def ensure_dirs(self, cell_dir: str, uid: int, gid: int) -> None:
        self._rec("ensure_dirs")

    def ensure_user_manager(self, name: str, uid: int) -> None:
        self._rec("ensure_user_manager")

    def write_daemon_config(
        self, cell_dir: str, uid: int, gid: int, driver: str = "cgroupfs"
    ) -> None:
        self._rec("write_daemon_config")

    def install_profile(self, name: str, content: str) -> None:
        self._rec("install_profile")

    def apply_network(self, spec: dict[str, object]) -> None:
        self._rec("apply_network")

    def install_systemd_unit(
        self, slug: str, uid: int, cgroup_path: str, driver: str = "cgroupfs"
    ) -> None:
        self._rec("install_systemd_unit")

    def start_daemon(
        self, slug: str, uid: int = 0, driver: str = "cgroupfs"
    ) -> int:
        self._rec("start_daemon")
        return 4242

    def ensure_cell_images(self, socket_path: str, images: list[str]) -> None:
        self._rec("ensure_cell_images")
        self.image_calls.append((socket_path, list(images)))

    def ensure_cell_egress(self, cell_uid: int, subnet: str) -> None:
        self._rec("ensure_cell_egress")


def test_provision_seeds_images_once_the_socket_exists(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SPANEL_HOSTING_WP_IMAGE", "wordpress:latest")
    monkeypatch.setenv("SPANEL_HOSTING_DB_IMAGE", "mariadb:11")
    monkeypatch.setenv("SPANEL_HOSTING_STATIC_IMAGE", "nginx:alpine")
    socket = tmp_path / "cells" / "acme" / "docker.sock"
    socket.parent.mkdir(parents=True)
    socket.touch()
    executor = _RecordingExecutor()
    svc = CellService(_Probe(), executor, tmp_path)

    svc.provision("acme")
    svc.provision("acme")

    assert executor.image_calls == [
        (str(socket), ["wordpress:latest", "mariadb:11", "nginx:alpine"])
    ]
    assert alloc.load_registry(tmp_path)["allocations"]["acme"]["applied"]["images"] is True


def test_provision_does_not_seed_images_without_a_socket(tmp_path) -> None:
    executor = _RecordingExecutor()

    CellService(_Probe(), executor, tmp_path).provision("acme")

    assert "ensure_cell_images" not in executor.calls


def test_reconcile_main_calls_ensure_cell_images(tmp_path, monkeypatch) -> None:
    from scripts.tenant_cell import reconcile_cells as reconcile

    alloc.allocate(str(tmp_path), "acme")
    images_calls: list[Path] = []
    monkeypatch.setattr(reconcile, "reconcile_seccomp", lambda *a, **k: [])
    monkeypatch.setattr(reconcile, "reconcile_ingress", lambda *a, **k: [])
    monkeypatch.setattr(
        reconcile,
        "ensure_cell_images",
        lambda data_root: images_calls.append(Path(data_root)) or [],
    )

    assert reconcile.main(["--data-root", str(tmp_path)]) == 0
    assert images_calls == [tmp_path]

    images_calls.clear()
    assert reconcile.main(["--data-root", str(tmp_path), "--dry-run"]) == 0
    assert images_calls == []
