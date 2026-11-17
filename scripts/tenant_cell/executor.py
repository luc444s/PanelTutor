"""Mutation gateway for cells: injectable interface + gated local adapter.

The service layer never shells out directly. ``LocalExecutor`` is the only real
adapter and requires an explicit opt-in, so tests and ``--help`` can never
change a host. Each tenant owns its own nftables table: tearing one cell down
never removes another tenant's isolation rules.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

_SYSTEMD_DIR = Path("/etc/systemd/system")
_CELL_ROOT = "/var/lib/spanel/cells"


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

    def install_systemd_unit(self, slug: str, uid: int, cgroup_path: str) -> None:
        raise NotImplementedError

    def start_daemon(self, slug: str) -> int:
        raise NotImplementedError

    def stop_daemon(self, slug: str) -> None:
        raise NotImplementedError

    def remove_network(self, spec: dict[str, Any]) -> None:
        raise NotImplementedError

    def remove_profile(self, name: str) -> None:
        raise NotImplementedError

    def remove_systemd_unit(self, slug: str) -> None:
        raise NotImplementedError


def systemd_unit(slug: str, uid: int, cgroup_path: str) -> str:
    """Render the systemd unit for one cell (fixed template, validated slug)."""
    from .alloc import validate_slug

    slug = validate_slug(slug)
    name = f"spanel-{slug}"
    cell_dir = f"{_CELL_ROOT}/{slug}"
    socket = f"{cell_dir}/docker.sock"
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
        "Delegate=yes\n"
        f"ExecStart=/usr/bin/dockerd-rootless.sh --data-root {cell_dir} "
        f"--host unix://{socket}\n"
        "Restart=on-failure\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


class LocalExecutor(Executor):
    """Real adapter for the lab host; mutations require an explicit opt-in."""

    _GATE = "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS"

    def _ensure_gate(self) -> None:
        if os.environ.get(self._GATE) != "1":
            raise RuntimeError(
                f"local mutations disabled; set {self._GATE}=1 on the lab host"
            )

    def _run(self, argv: list[str]) -> None:
        self._ensure_gate()
        subprocess.run(argv, check=True)

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
        # dockerd-rootless.sh requires XDG_RUNTIME_DIR to exist and be owned
        # by the cell user before it will start.
        for target in (base, base / "apps", Path(f"/run/user/{uid}")):
            self._run([*common, str(target)])

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
            for rule in spec.get("nft_rules", []):
                self._run(["nft", *shlex.split(rule)])
        else:
            self._run(["ip", "netns", "add", spec["netns"]])

    def install_systemd_unit(self, slug: str, uid: int, cgroup_path: str) -> None:
        path = _SYSTEMD_DIR / f"spanel-cell-{slug}.service"
        self._write_file_once(path, systemd_unit(slug, uid, cgroup_path))
        self._run(["systemctl", "daemon-reload"])
        self._run(["systemctl", "enable", f"spanel-cell-{slug}"])

    def start_daemon(self, slug: str) -> int:
        unit = f"spanel-cell-{slug}"
        self._run(["systemctl", "start", unit])
        result = subprocess.run(
            ["systemctl", "show", "-p", "MainPID", "--value", unit],
            capture_output=True,
            text=True,
            check=False,
        )
        try:
            return int(result.stdout.strip())
        except ValueError:
            return 0

    def stop_daemon(self, slug: str) -> None:
        self._run(["systemctl", "stop", f"spanel-cell-{slug}"])

    def remove_network(self, spec: dict[str, Any]) -> None:
        if spec["mode"] == "skuid":
            # Only this cell's table; other tenants keep their rules.
            self._run(["nft", "delete", "table", "inet", spec["table"]])
        else:
            self._run(["ip", "netns", "delete", spec["netns"]])

    def remove_profile(self, name: str) -> None:
        self._run(["apparmor_parser", "-R", str(Path("/etc/apparmor.d") / name)])

    def remove_systemd_unit(self, slug: str) -> None:
        unit = f"spanel-cell-{slug}"
        self._run(["systemctl", "disable", unit])
        path = _SYSTEMD_DIR / f"{unit}.service"
        self._ensure_gate()
        path.unlink(missing_ok=True)
        self._run(["systemctl", "daemon-reload"])
