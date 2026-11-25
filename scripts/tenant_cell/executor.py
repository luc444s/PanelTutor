"""Mutation gateway for cells: injectable interface + gated local adapter.

The service layer never shells out directly. ``LocalExecutor`` is the only real
adapter and requires an explicit opt-in, so tests and ``--help`` can never
change a host. Each tenant owns its own nftables table: tearing one cell down
never removes another tenant's isolation rules.
"""

from __future__ import annotations

import json
import os
import pwd
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

from .alloc import DEFAULT_CGROUP_DRIVER, LEGACY_CGROUP_DRIVER
from .network import (
    cell_dns_resolver,
    cell_network_driver,
    egress_subnets,
    netns_masquerade_argv,
    rootlesskit_port_driver_env,
)
from .plans import PlanExecutorMixin

_SYSTEMD_DIR = Path("/etc/systemd/system")
_USER_SYSTEMD_DIR = Path("/etc/systemd/user")
_DELEGATE_CONF = _SYSTEMD_DIR / "user@.service.d" / "delegate.conf"
_CELL_ROOT = "/var/lib/spanel/cells"
# A.SPEC 0105: shipped seccomp profile copied into each cell's data-root.
_CELL_SECCOMP_SRC = Path(__file__).resolve().parent / "deploy" / "cell-seccomp.json"
_CELL_SECCOMP_NAME = "cell-seccomp.json"

# A.SPEC 0099: the user manager must be able to hand these controllers to the
# cell's dockerd. systemd 255 keeps its own payload in DelegateSubgroup=init.scope
# so the user@ service cgroup stays empty (cgroup v2 no-internal-process rule).
DELEGATE_CONTROLLERS = "cpu cpuset io memory pids"
PROBE_CONTAINER = "spanel-cgroup-probe"
PROBE_MEMORY = 128 * 1024 * 1024
PROBE_NANO_CPUS = 500_000_000
PROBE_PIDS_LIMIT = 64


def rootlesskit_env_lines() -> str:
    """RootlessKit network + port-driver settings for a cell (0109-R3).

    The network driver is pinned explicitly so the resolver passed to dockerd
    always matches the driver that rootlesskit actually starts.
    """
    env = dict(rootlesskit_port_driver_env(0))
    env["DOCKERD_ROOTLESS_ROOTLESSKIT_NET"] = cell_network_driver()
    return "".join(
        f"Environment={key}={value}\n" for key, value in sorted(env.items())
    )


def dockerd_pid_for_uid(cell_uid: int, proc_root: Path = Path("/proc")) -> int:
    """Return the real dockerd owned by a cell uid, excluding wrapper parents."""
    uid = int(cell_uid)
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text(encoding="utf-8")
            real_uid = next(
                int(line.split()[1])
                for line in status.splitlines()
                if line.startswith("Uid:")
            )
            argv0 = (entry / "cmdline").read_bytes().split(b"\0", 1)[0]
        except (OSError, StopIteration, ValueError):
            continue
        if real_uid == uid and Path(os.fsdecode(argv0)).name == "dockerd":
            return int(entry.name)
    return 0


class Executor:
    """Idempotent mutation gateway. Fakes subclass this in unit tests."""

    def ensure_user(self, name: str, uid: int, gid: int) -> None:
        raise NotImplementedError

    def ensure_subids(
        self, name: str, uid: int, subuid_base: int, subgid_base: int, count: int
    ) -> None:
        raise NotImplementedError

    def ensure_dirs(self, cell_dir: str, uid: int, gid: int) -> None:
        raise NotImplementedError

    def install_profile(self, name: str, content: str) -> None:
        raise NotImplementedError

    def apply_network(self, spec: dict[str, Any]) -> None:
        raise NotImplementedError

    def install_systemd_unit(
        self,
        slug: str,
        uid: int,
        cgroup_path: str,
        driver: str = LEGACY_CGROUP_DRIVER,
    ) -> None:
        raise NotImplementedError

    def start_daemon(self, slug: str) -> int:
        raise NotImplementedError

    def stop_daemon(
        self,
        slug: str,
        uid: int = 0,
        driver: str = LEGACY_CGROUP_DRIVER,
    ) -> None:
        raise NotImplementedError

    # A.SPEC 0099 additions. Default implementations raise so an executor that
    # does not support the systemd layout fails loudly instead of silently
    # writing the wrong driver to disk.
    def ensure_delegation(self) -> None:
        raise NotImplementedError

    def install_user_unit(self, slug: str, uid: int, cgroup_path: str) -> None:
        raise NotImplementedError

    def remove_user_unit(self, slug: str, uid: int) -> None:
        raise NotImplementedError

    def start_user_daemon(self, slug: str, uid: int) -> int:
        raise NotImplementedError

    def stop_user_daemon(self, slug: str, uid: int) -> None:
        raise NotImplementedError

    def user_daemon_pid(self, slug: str, uid: int) -> int:
        raise NotImplementedError

    def backup_files(
        self, slug: str, files: list[str], backup_dir: str
    ) -> dict[str, str]:
        raise NotImplementedError

    def restore_files(self, saved: dict[str, str]) -> None:
        raise NotImplementedError

    def run_limit_probe(self, slug: str, uid: int) -> dict[str, Any]:
        raise NotImplementedError

    # A.SPEC 0100: defaults raise so unsupported executors fail loudly.
    def install_tenant_slice(self, slug: str, plan: dict[str, Any]) -> None:
        raise NotImplementedError

    def remove_tenant_slice(self, slug: str) -> None:
        raise NotImplementedError

    def install_user_manager_dropin(self, slug: str, uid: int) -> None:
        raise NotImplementedError

    def remove_user_manager_dropin(self, slug: str, uid: int) -> None:
        raise NotImplementedError

    def restart_user_manager(self, uid: int) -> None:
        raise NotImplementedError

    def run_plan_probe(
        self, slug: str, uid: int, plan: dict[str, Any]
    ) -> dict[str, Any]:
        raise NotImplementedError

    def remove_network(self, spec: dict[str, Any]) -> None:
        raise NotImplementedError

    def remove_profile(self, name: str) -> None:
        raise NotImplementedError

    def remove_systemd_unit(
        self,
        slug: str,
        uid: int = 0,
        driver: str = LEGACY_CGROUP_DRIVER,
    ) -> None:
        raise NotImplementedError

    def cell_dockerd_pid(self, cell_uid: int) -> int:
        raise NotImplementedError

    def ensure_cell_egress(self, cell_uid: int, subnet: str) -> None:
        raise NotImplementedError

    def remove_cell_egress(self, cell_uid: int, subnet: str) -> None:
        raise NotImplementedError

    def cell_egress_enabled(self, cell_uid: int, subnet: str) -> bool:
        raise NotImplementedError

    def ensure_cell_egress_all(
        self, cell_uid: int, subnets: list[str] | None = None
    ) -> None:
        """Apply every configured NAT rule; fake executors inherit this loop."""
        for subnet in subnets or egress_subnets():
            self.ensure_cell_egress(cell_uid, subnet)

    def remove_cell_egress_all(
        self, cell_uid: int, subnets: list[str] | None = None
    ) -> None:
        for subnet in subnets or egress_subnets():
            self.remove_cell_egress(cell_uid, subnet)

    def cell_egress_all_enabled(
        self, cell_uid: int, subnets: list[str] | None = None
    ) -> bool:
        selected = subnets or egress_subnets()
        return bool(selected) and all(
            self.cell_egress_enabled(cell_uid, subnet) for subnet in selected
        )


def systemd_unit(
    slug: str,
    uid: int,
    cgroup_path: str,
    driver: str = LEGACY_CGROUP_DRIVER,
) -> str:
    """Render the cell unit for the requested cgroup driver (validated slug).

    ``cgroupfs`` keeps the legacy system unit. ``systemd`` renders a user unit:
    the daemon runs inside ``user@<uid>.service`` so its cgroup has no internal
    processes and the delegated controllers can be handed to container scopes.
    """
    from .alloc import validate_slug

    slug = validate_slug(slug)
    name = f"spanel-{slug}"
    cell_dir = f"{_CELL_ROOT}/{slug}"
    socket = f"{cell_dir}/docker.sock"
    resolver = cell_dns_resolver()
    rk_env = rootlesskit_env_lines()
    if driver == DEFAULT_CGROUP_DRIVER:
        # AppArmor is attached with aa-exec: a user manager cannot use the
        # system unit's AppArmorProfile= directive. The user bus lets runc read
        # OwnerUID (rootless detection) and create scopes via systemd.
        return (
            "[Unit]\n"
            f"Description=Spanel rootless Docker cell {slug} (user unit)\n"
            "After=network.target\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            "Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            f"Environment=XDG_RUNTIME_DIR=/run/user/{uid}\n"
            f"Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus\n"
            f"Environment=DOCKER_HOST=unix://{socket}\n"
            "Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=false\n"
            "Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SANDBOX=false\n"
            "Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=true\n"
            + rk_env
            + f"Environment=SPANEL_TENANT_CELL_DNS={resolver}\n"
            + f"ExecStart=/usr/bin/aa-exec -p spanel-cell-{slug} -- "
            "/usr/bin/dockerd-rootless.sh "
            f"--data-root {cell_dir} "
            f"--host unix://{socket} --config-file={cell_dir}/daemon.json "
            "--iptables=false --ip6tables=false "
            "--dns ${SPANEL_TENANT_CELL_DNS}\n"
            "Restart=on-failure\n"
            "\n"
            "[Install]\n"
            "WantedBy=default.target\n"
        )
    return (
        "[Unit]\n"
        f"Description=Spanel rootless Docker cell {slug}\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"User={name}\n"
        f"Group={name}\n"
        f"Environment=XDG_RUNTIME_DIR=/run/user/{uid}\n"
        f"Environment=DOCKER_HOST=unix://{socket}\n"
        # Detached netns runs dockerd outside the userns net namespace, where
        # it cannot create the bridge; rootlesskit's own netns + port driver
        # provide connectivity and loopback publishing instead.
        "Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=false\n"
        # slirp4netns' own mount sandbox conflicts with AppArmor mount rules;
        # the cell profile supplies confinement instead (verified in lab).
        "Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SANDBOX=false\n"
        "Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=true\n"
        + rk_env
        + f"Environment=SPANEL_TENANT_CELL_DNS={resolver}\n"
        # Bind the cell profile at exec, not by executable path: all execs in
        # the chain inherit it via the profile's ix rules.
        + f"AppArmorProfile=spanel-cell-{slug}\n"
        "Delegate=yes\n"
        # The daemon never manages iptables. The privileged host lifecycle
        # installs egress NAT inside this cell's netns after startup.
        f"ExecStart=/usr/bin/dockerd-rootless.sh --data-root {cell_dir} "
        f"--host unix://{socket} --config-file={cell_dir}/daemon.json "
        "--iptables=false --ip6tables=false "
        "--dns ${SPANEL_TENANT_CELL_DNS}\n"
        "Restart=on-failure\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


class LocalExecutor(PlanExecutorMixin, Executor):
    """Real adapter for the lab host; mutations require an explicit opt-in.

    Plan operations are supplied by ``PlanExecutorMixin`` so their rendering,
    paths and probe interpretation stay next to the rest of the plan logic.
    """

    _GATE = "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS"

    def _ensure_gate(self) -> None:
        if os.environ.get(self._GATE) != "1":
            raise RuntimeError(
                f"local mutations disabled; set {self._GATE}=1 on the lab host"
            )

    def _run(self, argv: list[str]) -> None:
        self._ensure_gate()
        subprocess.run(argv, check=True)

    def cell_dockerd_pid(self, cell_uid: int) -> int:
        """Find the cell's dockerd, never rootlesskit's host-netns parent."""
        return dockerd_pid_for_uid(cell_uid)

    @staticmethod
    def _assert_cell_netns(dockerd_pid: int) -> None:
        """Fail closed before iptables if the target is the host netns."""
        try:
            target = os.readlink(f"/proc/{dockerd_pid}/ns/net")
            host = os.readlink("/proc/self/ns/net")
        except OSError as exc:
            raise RuntimeError(
                f"cannot verify network namespace for dockerd pid {dockerd_pid}"
            ) from exc
        if target == host:
            raise RuntimeError(
                f"refusing cell egress NAT: dockerd pid {dockerd_pid} uses host netns"
            )

    def _cell_egress_enabled_pid(self, dockerd_pid: int, subnet: str) -> bool:
        self._assert_cell_netns(dockerd_pid)
        result = subprocess.run(
            netns_masquerade_argv(dockerd_pid, subnet, "-C"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return result.returncode == 0

    def cell_egress_enabled(self, cell_uid: int, subnet: str) -> bool:
        dockerd_pid = self.cell_dockerd_pid(cell_uid)
        return dockerd_pid > 0 and self._cell_egress_enabled_pid(dockerd_pid, subnet)

    def ensure_cell_egress(self, cell_uid: int, subnet: str) -> None:
        """Install and verify MASQUERADE in the cell netns, retrying startup races."""
        self._ensure_gate()
        last_error = "cell network namespace is not ready"
        for _ in range(20):
            dockerd_pid = self.cell_dockerd_pid(cell_uid)
            if dockerd_pid <= 0:
                time.sleep(0.25)
                continue
            if self._cell_egress_enabled_pid(dockerd_pid, subnet):
                return
            self._assert_cell_netns(dockerd_pid)
            result = subprocess.run(
                netns_masquerade_argv(dockerd_pid, subnet, "-A"),
                capture_output=True,
                text=True,
                check=False,
            )
            last_error = (result.stderr or result.stdout or last_error).strip()
            if result.returncode == 0 and self._cell_egress_enabled_pid(
                dockerd_pid, subnet
            ):
                return
            time.sleep(0.25)
        raise RuntimeError(f"could not install cell egress NAT: {last_error[:300]}")

    def remove_cell_egress(self, cell_uid: int, subnet: str) -> None:
        """Delete only the cell-netns MASQUERADE rule, if it still exists."""
        self._ensure_gate()
        dockerd_pid = self.cell_dockerd_pid(cell_uid)
        if dockerd_pid <= 0:
            return
        if not self._cell_egress_enabled_pid(dockerd_pid, subnet):
            return
        self._assert_cell_netns(dockerd_pid)
        result = subprocess.run(
            netns_masquerade_argv(dockerd_pid, subnet, "-D"),
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0 or self._cell_egress_enabled_pid(
            dockerd_pid, subnet
        ):
            detail = (result.stderr or result.stdout or "rule remains installed").strip()
            raise RuntimeError(f"could not remove cell egress NAT: {detail[:300]}")

    def _write_once(self, path: Path, line: str) -> None:
        if path.exists() and line in path.read_text(encoding="utf-8").splitlines():
            return
        self._ensure_gate()
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def _write_file_once(self, path: Path, content: str) -> None:
        if path.exists() and path.read_text(encoding="utf-8") == content:
            return
        self._ensure_gate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def ensure_user(self, name: str, uid: int, gid: int) -> None:
        exists = subprocess.run(
            ["getent", "passwd", name], capture_output=True, check=False
        ).returncode == 0
        if not exists:
            self._run(["groupadd", "--gid", str(gid), name])
            self._run(
                ["useradd", "--system", "--uid", str(uid), "--gid", str(gid), name]
            )

    def ensure_subids(
        self, name: str, uid: int, subuid_base: int, subgid_base: int, count: int
    ) -> None:
        self._write_once(Path("/etc/subuid"), f"{name}:{subuid_base}:{count}")
        self._write_once(Path("/etc/subgid"), f"{name}:{subgid_base}:{count}")

    def ensure_dirs(self, cell_dir: str, uid: int, gid: int) -> None:
        base = Path(cell_dir)
        common = ["install", "-d", "-m", "0700", "-o", str(uid), "-g", str(gid)]
        # dockerd-rootless.sh requires XDG_RUNTIME_DIR and a writable HOME,
        # both owned by the cell user, before it will start.
        home = Path(pwd.getpwuid(uid).pw_dir)
        for target in (base, base / "apps", Path(f"/run/user/{uid}"), home):
            self._run([*common, str(target)])

    def ensure_user_manager(self, name: str, uid: int) -> None:
        # rootlesskit needs the delegated cgroup of the cell's uid
        # (user-<uid>.slice). Without a linger user manager that slice does
        # not exist and dockerd cannot start containers.
        self._ensure_gate()
        subprocess.run(["loginctl", "enable-linger", name], check=True)
        for _ in range(20):
            active = subprocess.run(
                ["systemctl", "is-active", "--quiet", f"user@{uid}.service"],
                check=False,
            ).returncode
            if active == 0:
                return
            time.sleep(0.5)

    def write_daemon_config(
        self,
        cell_dir: str,
        uid: int,
        gid: int,
        driver: str = LEGACY_CGROUP_DRIVER,
    ) -> None:
        # A.SPEC 0099: cgroupfs silently ignores container limits on cgroup v2
        # when the daemon lives in a cgroup that already has processes. The
        # systemd driver is used together with the user unit and the user bus.
        # A.SPEC 0105: ship the fail-closed seccomp profile into the cell's own
        # data-root and reference it from daemon.json (no extra mounts/sockets).
        seccomp_dest = Path(cell_dir) / _CELL_SECCOMP_NAME
        self._write_file_once(
            seccomp_dest, _CELL_SECCOMP_SRC.read_text(encoding="utf-8")
        )
        config = json.dumps(
            {
                "exec-opts": [f"native.cgroupdriver={driver}"],
                "seccomp-profile": str(seccomp_dest),
            }
        ) + "\n"
        self._write_file_once(Path(cell_dir) / "daemon.json", config)
        self._run(["chown", f"{uid}:{gid}", f"{cell_dir}/daemon.json"])
        self._run(["chown", f"{uid}:{gid}", str(seccomp_dest)])

    def ensure_delegation(self) -> None:
        """Host-wide, idempotent controller delegation for user managers."""
        self._write_file_once(
            _DELEGATE_CONF, f"[Service]\nDelegate={DELEGATE_CONTROLLERS}\n"
        )

    def install_user_unit(self, slug: str, uid: int, cgroup_path: str) -> None:
        path = _USER_SYSTEMD_DIR / f"spanel-cell-{slug}.service"
        self._write_file_once(
            path, systemd_unit(slug, uid, cgroup_path, DEFAULT_CGROUP_DRIVER)
        )
        # The cell's user manager must be able to read the unit. A privileged
        # caller with UMask=0077 would leave it 0600 and systemd marks it
        # "bad", so the rootless dockerd never starts and no socket appears.
        path.chmod(0o644)
        self._run_user(uid, ["systemctl", "--user", "daemon-reload"])
        self._run_user(uid, ["systemctl", "--user", "enable", f"spanel-cell-{slug}"])

    def remove_user_unit(self, slug: str, uid: int) -> None:
        unit = f"spanel-cell-{slug}"
        self._run_user(uid, ["systemctl", "--user", "disable", unit])
        self._ensure_gate()
        (_USER_SYSTEMD_DIR / f"{unit}.service").unlink(missing_ok=True)
        self._run_user(uid, ["systemctl", "--user", "daemon-reload"])

    def _user_env(self, uid: int) -> dict[str, str]:
        env = dict(os.environ)
        env["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{uid}/bus"
        return env

    def _run_user(self, uid: int, argv: list[str], **kwargs: Any) -> Any:
        """Run ``argv`` as the *cell user*, never as root.

        A.SPEC 0103: ``systemctl --user`` / ``systemd-run --user`` connect to
        the user bus from ``/run/user/<uid>``.  Running them as root used root's
        runtime dir and bus and got EPERM, leaving provision's rootless daemon
        down.  ``runuser`` switches identity to the real name resolved from the
        uid; the cell's bus environment is carried through explicitly.
        """
        self._ensure_gate()
        user = pwd.getpwuid(uid).pw_name
        return subprocess.run(
            ["runuser", "-u", user, "--", *argv],
            env=self._user_env(uid),
            text=True,
            check=False,
            **kwargs,
        )

    def start_user_daemon(self, slug: str, uid: int) -> int:
        unit = f"spanel-cell-{slug}"
        self._run_user(uid, ["systemctl", "--user", "start", unit])
        for _ in range(30):
            active = self._run_user(
                uid, ["systemctl", "--user", "is-active", "--quiet", unit]
            )
            pid = self.user_daemon_pid(slug, uid)
            if active.returncode == 0 and pid > 0:
                return pid
            time.sleep(0.5)
        return 0

    def stop_user_daemon(self, slug: str, uid: int) -> None:
        self._run_user(
            uid, ["systemctl", "--user", "stop", f"spanel-cell-{slug}"]
        )

    def user_daemon_pid(self, slug: str, uid: int) -> int:
        result = self._run_user(
            uid,
            [
                "systemctl", "--user", "show", "-p", "MainPID", "--value",
                f"spanel-cell-{slug}",
            ],
            capture_output=True,
        )
        try:
            return int(result.stdout.strip())
        except (ValueError, AttributeError):
            return 0

    def run_limit_probe(self, slug: str, uid: int) -> dict[str, Any]:
        """Run a bounded container with limits and read the *kernel* cgroup.

        This is the acceptance gate for a systemd-driver migration: ``docker
        run`` returning 0 is not enough. Everything is cleaned up in ``finally``.
        """
        socket = f"{_CELL_ROOT}/{slug}/docker.sock"
        env = dict(os.environ)
        env["DOCKER_HOST"] = f"unix://{socket}"

        def docker(argv: list[str], stdin: str | None = None) -> Any:
            return subprocess.run(
                ["docker", *argv],
                env=env,
                input=stdin,
                text=True,
                capture_output=True,
                check=False,
                timeout=90,
            )

        def cgroup_file(path: Path, name: str) -> str:
            try:
                return (path / name).read_text(encoding="utf-8").strip()
            except OSError:
                return ""

        evidence: dict[str, Any] = {"slug": slug, "driver": "systemd"}
        docker(["rm", "-f", PROBE_CONTAINER])
        try:
            started = docker([
                "run", "-d", "--name", PROBE_CONTAINER,
                "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64",
                "alpine", "sleep", "300",
            ])
            if started.returncode:
                evidence.update(ok=False, error=(started.stderr or started.stdout)[:400])
                return evidence
            pid_s = docker(["inspect", "-f", "{{.State.Pid}}", PROBE_CONTAINER]).stdout.strip()
            try:
                pid = int(pid_s)
            except ValueError:
                evidence.update(ok=False, error=f"bad container pid: {pid_s!r}")
                return evidence
            raw = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8")
            cgroup = next(
                (line.split(":", 2)[2] for line in raw.splitlines() if line.startswith("0::")),
                "",
            )
            path = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
            evidence["cgroup_path"] = cgroup
            evidence["memory_max"] = cgroup_file(path, "memory.max")
            evidence["cpu_max"] = cgroup_file(path, "cpu.max")
            evidence["pids_max"] = cgroup_file(path, "pids.max")

            def usage_usec() -> int:
                text = cgroup_file(path, "cpu.stat")
                for line in text.splitlines():
                    if line.startswith("usage_usec "):
                        try:
                            return int(line.split()[1])
                        except (ValueError, IndexError):
                            return 0
                return 0

            before = usage_usec()
            docker(["exec", PROBE_CONTAINER, "timeout", "3", "sh", "-c", "while :; do :; done"])
            evidence["cpu_delta_usec"] = usage_usec() - before

            docker([
                "exec", PROBE_CONTAINER, "sh", "-c",
                "x=a; i=0; while [ $i -lt 28 ]; do x=\"$x$x\"; i=$((i+1)); done",
            ])
            events = cgroup_file(path, "memory.events")
            evidence["memory_events"] = events
            evidence["memory_throttled"] = any(
                (line.startswith("max ") and line.split()[1] != "0")
                or (line.startswith("oom_kill ") and line.split()[1] != "0")
                for line in events.splitlines()
            )

            docker([
                "exec", PROBE_CONTAINER, "sh", "-c",
                "i=0; while [ $i -lt 100 ]; do sleep 30 2>/dev/null & i=$((i+1)); done",
            ])
            try:
                evidence["pids_current"] = int(cgroup_file(path, "pids.current") or 0)
            except ValueError:
                evidence["pids_current"] = 0

            evidence["ok"] = (
                evidence["memory_max"] == str(PROBE_MEMORY)
                and evidence["cpu_max"] == "50000 100000"
                and evidence["pids_max"] == str(PROBE_PIDS_LIMIT)
                and 0 < evidence["cpu_delta_usec"] < 2_200_000
                and evidence["memory_throttled"]
                and 0 < evidence["pids_current"] <= PROBE_PIDS_LIMIT
            )
            return evidence
        finally:
            docker(["rm", "-f", PROBE_CONTAINER])

    def backup_files(
        self, slug: str, files: list[str], backup_dir: str
    ) -> dict[str, str]:
        """Copy the pre-migration artifacts of one cell before any change."""
        import shutil

        self._ensure_gate()
        target = Path(backup_dir)
        target.mkdir(parents=True, exist_ok=True)
        saved: dict[str, str] = {}
        for source in files:
            path = Path(source)
            if not path.exists():
                continue
            dest = target / path.name
            shutil.copy2(path, dest)
            saved[source] = str(dest)
        return saved

    def restore_files(self, saved: dict[str, str]) -> None:
        """Undo a migration by copying backed-up artifacts back in place."""
        import shutil

        self._ensure_gate()
        for source, backup in saved.items():
            shutil.copy2(backup, source)

    def install_profile(self, name: str, content: str) -> None:
        self._ensure_gate()
        path = Path("/etc/apparmor.d") / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        self._run(["apparmor_parser", "-r", str(path)])

    def apply_network(self, spec: dict[str, Any]) -> None:
        if spec["mode"] == "skuid":
            table = spec["table"]
            self._run(["nft", "add", "table", "inet", table])
            # An inet table has no built-in chains: declare the output hook
            # before adding rules to it.
            self._run([
                "nft", "add", "chain", "inet", table, "output",
                "{", "type", "filter", "hook", "output", "priority", "0",
                ";", "policy", "accept", ";", "}",
            ])
            # Re-applying must not pile up duplicate rules (repair / re-run).
            self._run(["nft", "flush", "chain", "inet", table, "output"])
            for rule in spec.get("nft_rules", []):
                self._run(["nft", *shlex.split(rule)])
        else:
            self._run(["ip", "netns", "add", spec["netns"]])

    def install_systemd_unit(
        self,
        slug: str,
        uid: int,
        cgroup_path: str,
        driver: str = LEGACY_CGROUP_DRIVER,
    ) -> None:
        if driver == DEFAULT_CGROUP_DRIVER:
            self.install_user_unit(slug, uid, cgroup_path)
            return
        path = _SYSTEMD_DIR / f"spanel-cell-{slug}.service"
        self._write_file_once(path, systemd_unit(slug, uid, cgroup_path, driver))
        self._run(["systemctl", "daemon-reload"])
        self._run(["systemctl", "enable", f"spanel-cell-{slug}"])

    def start_daemon(
        self,
        slug: str,
        uid: int = 0,
        driver: str = LEGACY_CGROUP_DRIVER,
    ) -> int:
        if driver == DEFAULT_CGROUP_DRIVER:
            return self.start_user_daemon(slug, uid)
        unit = f"spanel-cell-{slug}"
        self._run(["systemctl", "start", unit])
        # `systemctl start` returns before a crashing service dies, so confirm
        # it is still active before reporting a PID (otherwise the cell would
        # be marked ready with no daemon and no observable uid map).
        for _ in range(30):
            active = subprocess.run(
                ["systemctl", "is-active", "--quiet", unit], check=False
            ).returncode
            result = subprocess.run(
                ["systemctl", "show", "-p", "MainPID", "--value", unit],
                capture_output=True,
                text=True,
                check=False,
            )
            try:
                pid = int(result.stdout.strip())
            except ValueError:
                pid = 0
            if active == 0 and pid > 0:
                return pid
            # Do not bail on a transient "activating"/pid=0 right after start:
            # systemd reports those for a moment even for healthy services.
            time.sleep(0.5)
        return 0

    def stop_daemon(
        self,
        slug: str,
        uid: int = 0,
        driver: str = LEGACY_CGROUP_DRIVER,
    ) -> None:
        if driver == DEFAULT_CGROUP_DRIVER:
            self.stop_user_daemon(slug, uid)
            return
        self._run(["systemctl", "stop", f"spanel-cell-{slug}"])

    def remove_network(self, spec: dict[str, Any]) -> None:
        if spec["mode"] == "skuid":
            # Only this cell's table; other tenants keep their rules.
            self._run(["nft", "delete", "table", "inet", spec["table"]])
        else:
            self._run(["ip", "netns", "delete", spec["netns"]])

    def remove_profile(self, name: str) -> None:
        self._run(["apparmor_parser", "-R", str(Path("/etc/apparmor.d") / name)])

    def remove_systemd_unit(
        self,
        slug: str,
        uid: int = 0,
        driver: str = LEGACY_CGROUP_DRIVER,
    ) -> None:
        if driver == DEFAULT_CGROUP_DRIVER:
            self.remove_user_unit(slug, uid)
            return
        unit = f"spanel-cell-{slug}"
        self._run(["systemctl", "disable", unit])
        path = _SYSTEMD_DIR / f"{unit}.service"
        self._ensure_gate()
        path.unlink(missing_ok=True)
        self._run(["systemctl", "daemon-reload"])
