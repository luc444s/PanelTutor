"""Tenant resource plans: validated persistence, slice rendering and enforcement.

A plan is a small, atomically written JSON record keyed by a validated slug.
Applying it materialises ``tenant-<slug>.slice`` (under the default
``tenant.slice`` hierarchy) and points the cell's user manager at that slice
with a drop-in. Removing it deletes both artifacts and restarts the manager so
it returns to ``user-<uid>.slice``.

Everything that touches the host goes through the injectable ``Executor``. This
module owns validation, rendering, persistence and orchestration; the only real
adapter (``LocalExecutor``) is gated. Fakes record calls in unit tests, so no
test ever writes to a host.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from . import alloc, audit
from .alloc import DEFAULT_CGROUP_DRIVER, validate_slug

_SYSTEMD_DIR = Path("/etc/systemd/system")
_CELL_ROOT = "/var/lib/spanel/cells"

PLANS_NAME = "plans.json"
PLAN_VERSION = 1
MUTATION_GATE = "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS"
DROPIN_NAME = "tenant-plan.conf"

_MEMORY_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([KMGT]?)B?$", re.IGNORECASE)
_UNIT_MULT = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}


class InvalidPlan(ValueError):
    """Raised when plan values are not strictly positive and well formed."""


class PlanNotFound(Exception):
    """Raised when an operation targets a slug without a stored plan."""


class PlanCellMissing(Exception):
    """Raised when the targeted slug has no cell allocation."""


class PlanDriverError(Exception):
    """Raised when a cell does not use the systemd cgroup driver."""


class MutationDisabled(Exception):
    """Raised when the host mutation gate is not enabled."""


# --- pure validation / rendering -------------------------------------------


def validate_memory(value: object) -> str | int:
    """Accept a positive byte count or a positive systemd size ('512M', '1G')."""
    if isinstance(value, bool):
        raise InvalidPlan("memory must be a positive number or size")
    if isinstance(value, int):
        if value <= 0:
            raise InvalidPlan("memory must be > 0")
        return value
    if isinstance(value, str):
        match = _MEMORY_RE.fullmatch(value.strip())
        if match is None or float(match.group(1)) <= 0:
            raise InvalidPlan(f"invalid memory size: {value!r}")
        return value.strip()
    raise InvalidPlan("memory must be a positive number or size")


def memory_bytes(value: object) -> int:
    """Return the byte count of a validated plan memory value."""
    memory = validate_memory(value)
    if isinstance(memory, int):
        return memory
    match = _MEMORY_RE.fullmatch(memory)
    assert match is not None  # validated above
    return int(float(match.group(1)) * _UNIT_MULT[match.group(2).upper()])


def cpu_quota(cpus: object) -> str:
    """Render ``CPUQuota`` percent from a positive fractional CPU count."""
    if isinstance(cpus, bool) or not isinstance(cpus, (int, float)) or float(cpus) <= 0:
        raise InvalidPlan("cpus must be > 0")
    return f"{format(round(float(cpus) * 100, 6), 'g')}%"


def validate_plan(memory: object, cpus: object, pids: object) -> dict[str, Any]:
    """Validate every plan value BEFORE any host write (INVARIANT 7)."""
    valid_memory = validate_memory(memory)
    if isinstance(cpus, bool) or not isinstance(cpus, (int, float)) or float(cpus) <= 0:
        raise InvalidPlan("cpus must be > 0")
    if isinstance(pids, bool) or not isinstance(pids, int) or pids <= 0:
        raise InvalidPlan("pids must be a positive integer")
    return {"memory": valid_memory, "cpus": float(cpus), "pids": pids}


def slice_name(slug: str) -> str:
    """The slice unit name for a validated slug."""
    return f"tenant-{validate_slug(slug)}.slice"


def slice_cgroup_path(slug: str) -> str:
    """Where systemd places the slice (automatically under tenant.slice)."""
    return f"/tenant.slice/{slice_name(slug)}"


def user_slice(uid: int) -> str:
    """The default slice a cell's user manager returns to on plan remove."""
    return f"user-{int(uid)}.slice"


def dropin_path(uid: int) -> str:
    return f"/etc/systemd/system/user@{int(uid)}.service.d/{DROPIN_NAME}"


def render_slice(slug: str, plan: dict[str, Any]) -> str:
    """Render the tenant slice with MemoryMax / CPUQuota / TasksMax."""
    checked = validate_plan(plan["memory"], plan["cpus"], plan["pids"])
    return (
        "[Unit]\n"
        f"Description=Spanel tenant {validate_slug(slug)} resource plan slice\n"
        "\n"
        "[Slice]\n"
        f"MemoryMax={checked['memory']}\n"
        f"CPUQuota={cpu_quota(checked['cpus'])}\n"
        f"TasksMax={checked['pids']}\n"
    )


def render_dropin(slug: str) -> str:
    """Render the user-manager drop-in that attaches it to the tenant slice."""
    return f"[Service]\nSlice={slice_name(slug)}\n"


def expected_probe_limits(plan: dict[str, Any]) -> dict[str, str]:
    """Kernel cgroup values expected when the plan limits are really applied."""
    return {
        "memory_max": str(memory_bytes(plan["memory"])),
        "cpu_max": f"{int(float(plan['cpus']) * 100000)} 100000",
        "pids_max": str(plan["pids"]),
    }


# --- atomic persistence ----------------------------------------------------


def plans_path(data_root: str | Path) -> Path:
    return Path(data_root) / PLANS_NAME


def default_plans() -> dict[str, Any]:
    return {"version": PLAN_VERSION, "plans": {}}


def load_plans(data_root: str | Path) -> dict[str, Any]:
    path = plans_path(data_root)
    if not path.exists():
        return default_plans()
    data = json.loads(path.read_text(encoding="utf-8"))
    data.setdefault("version", PLAN_VERSION)
    data.setdefault("plans", {})
    return data


def save_plans(data_root: str | Path, plans: dict[str, Any]) -> None:
    """Write plans.json atomically (temp file + rename), like the registry."""
    path = plans_path(data_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(plans, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    tmp.replace(path)


def active_plan(data_root: str | Path, slug: str) -> dict[str, Any] | None:
    """Return the stored entry for a slug, if a plan is active (used by cells)."""
    return load_plans(data_root)["plans"].get(validate_slug(slug))


def mutation_allowed() -> bool:
    """INVARIANT 3: no plan mutation without the explicit host opt-in."""
    return os.environ.get(MUTATION_GATE) == "1"


# --- orchestration ---------------------------------------------------------


class PlanService:
    """Doctor-agnostic, slug-keyed plan lifecycle with audit on every mutation."""

    def __init__(
        self,
        executor: Any,
        data_root: str | Path,
        probe: Any = None,
    ) -> None:
        self.executor = executor
        self.data_root = Path(data_root)
        self.probe = probe

    def _require_gate(self) -> None:
        if not mutation_allowed():
            raise MutationDisabled(
                f"local plan mutations disabled; set {MUTATION_GATE}=1"
            )

    def _cell(self, slug: str) -> dict[str, Any]:
        cell = alloc.load_registry(self.data_root)["allocations"].get(slug)
        if cell is None:
            raise PlanCellMissing(slug)
        return cell

    def _entry(self, slug: str) -> dict[str, Any]:
        entry = load_plans(self.data_root)["plans"].get(slug)
        if entry is None:
            raise PlanNotFound(slug)
        return entry

    def set(self, slug: str, memory: object, cpus: object, pids: object) -> dict[str, Any]:
        """Validate, install the slice + drop-in, restart the manager, persist."""
        slug = validate_slug(slug)
        plan = validate_plan(memory, cpus, pids)  # before ANY host write
        self._require_gate()
        cell = self._cell(slug)
        if alloc.cgroup_driver(cell) != DEFAULT_CGROUP_DRIVER:
            raise PlanDriverError("tenant plans require the systemd cgroup driver")
        uid = int(cell["uid"])

        self.executor.install_tenant_slice(slug, plan)
        self.executor.install_user_manager_dropin(slug, uid)
        self.executor.restart_user_manager(uid)

        data = load_plans(self.data_root)
        data["plans"][slug] = {"slug": slug, "uid": uid, "plan": plan}
        save_plans(self.data_root, data)
        audit.write_audit(
            self.data_root,
            tenant_slug=slug,
            verb="plan_set",
            exit_code=0,
            slice=slice_name(slug),
            restored_slice=user_slice(uid),
        )
        return self.show(slug)

    def show(self, slug: str) -> dict[str, Any]:
        """Return the saved plan and the slice it currently materialises."""
        slug = validate_slug(slug)
        entry = self._entry(slug)
        uid = int(entry.get("uid", 0)) or int(self._cell(slug)["uid"])
        return {
            "slug": slug,
            "uid": uid,
            "plan": entry["plan"],
            "slice": slice_name(slug),
            "cgroup_path": slice_cgroup_path(slug),
            "dropin": dropin_path(uid),
        }

    def remove(self, slug: str) -> dict[str, Any]:
        """Drop the artifacts, restore user-<uid>.slice and delete the entry."""
        slug = validate_slug(slug)
        self._require_gate()
        entry = self._entry(slug)
        cell = alloc.load_registry(self.data_root)["allocations"].get(slug)
        uid = int(entry.get("uid", 0)) or int(cell["uid"] if cell else 0)

        self.executor.remove_user_manager_dropin(slug, uid)
        self.executor.remove_tenant_slice(slug)
        self.executor.restart_user_manager(uid)

        data = load_plans(self.data_root)
        data["plans"].pop(slug, None)
        save_plans(self.data_root, data)
        restored = user_slice(uid)
        audit.write_audit(
            self.data_root,
            tenant_slug=slug,
            verb="plan_remove",
            exit_code=0,
            restored_slice=restored,
        )
        return {"slug": slug, "removed": True, "restored_slice": restored}

    def verify(self, slug: str) -> dict[str, Any]:
        """Return ok=true with kernel evidence from both sides, or ok=false."""
        slug = validate_slug(slug)
        self._require_gate()
        entry = self._entry(slug)
        plan = entry["plan"]
        uid = int(entry.get("uid", 0)) or int(self._cell(slug)["uid"])
        evidence = self.executor.run_plan_probe(slug, uid, plan)
        ok = bool(evidence.get("ok"))
        audit.write_audit(
            self.data_root,
            tenant_slug=slug,
            verb="plan_verify",
            exit_code=0 if ok else 1,
        )
        return {
            "slug": slug,
            "ok": ok,
            "slice": slice_name(slug),
            "cgroup_path": slice_cgroup_path(slug),
            "plan": plan,
            "evidence": evidence,
        }


# --- host adapter mixin ----------------------------------------------------


class PlanExecutorMixin:
    """Real (gated) host operations for plans, mixed into ``LocalExecutor``.

    Kept here so the plan's rendering, paths and probe interpretation live in a
    single module; the mixin only performs writes through the host executor's
    already-gated helpers and reads cgroup files read-only.
    """

    def install_tenant_slice(self, slug: str, plan: dict[str, Any]) -> None:
        self._write_file_once(  # type: ignore[attr-defined]
            _SYSTEMD_DIR / slice_name(slug), render_slice(slug, plan)
        )
        self._run(["systemctl", "daemon-reload"])  # type: ignore[attr-defined]

    def remove_tenant_slice(self, slug: str) -> None:
        self._ensure_gate()  # type: ignore[attr-defined]
        (_SYSTEMD_DIR / slice_name(slug)).unlink(missing_ok=True)
        self._run(["systemctl", "daemon-reload"])  # type: ignore[attr-defined]

    def install_user_manager_dropin(self, slug: str, uid: int) -> None:
        self._write_file_once(  # type: ignore[attr-defined]
            _SYSTEMD_DIR / f"user@{uid}.service.d" / DROPIN_NAME,
            render_dropin(slug),
        )
        self._run(["systemctl", "daemon-reload"])  # type: ignore[attr-defined]

    def remove_user_manager_dropin(self, slug: str, uid: int) -> None:
        self._ensure_gate()  # type: ignore[attr-defined]
        path = _SYSTEMD_DIR / f"user@{uid}.service.d" / DROPIN_NAME
        path.unlink(missing_ok=True)
        self._run(["systemctl", "daemon-reload"])  # type: ignore[attr-defined]

    def restart_user_manager(self, uid: int) -> None:
        # The only plan mutation that briefly interrupts the cell's containers:
        # restarting user@<uid>.service re-parents the manager to the slice.
        unit = f"user@{uid}.service"
        self._run(["systemctl", "restart", unit])  # type: ignore[attr-defined]
        for _ in range(20):
            active = subprocess.run(
                ["systemctl", "is-active", "--quiet", unit], check=False
            )
            if active.returncode == 0:
                return
            time.sleep(0.5)

    def run_plan_probe(
        self, slug: str, uid: int, plan: dict[str, Any]
    ) -> dict[str, Any]:
        """Prove the kernel enforces the slice on rootful and rootless sides."""
        self._ensure_gate()  # type: ignore[attr-defined]
        name = slice_name(slug)
        cgroup = slice_cgroup_path(slug)
        path = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
        container = f"spanel-plan-probe-{slug}"
        env = dict(os.environ)
        env["DOCKER_HOST"] = f"unix://{_CELL_ROOT}/{slug}/docker.sock"

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

        def read(filename: str) -> str:
            try:
                return (path / filename).read_text(encoding="utf-8").strip()
            except OSError:
                return ""

        def usage_usec() -> int:
            for line in read("cpu.stat").splitlines():
                if line.startswith("usage_usec "):
                    try:
                        return int(line.split()[1])
                    except (ValueError, IndexError):
                        return 0
            return 0

        def proc_cgroup(pid: int) -> str:
            try:
                raw = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8")
            except OSError:
                return ""
            return next(
                (
                    line.split(":", 2)[2]
                    for line in raw.splitlines()
                    if line.startswith("0::")
                ),
                "",
            )

        def manager_pid() -> int:
            result = subprocess.run(
                [
                    "systemctl", "show", "-p", "MainPID", "--value",
                    f"user@{uid}.service",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            try:
                return int(result.stdout.strip())
            except ValueError:
                return 0

        evidence: dict[str, Any] = {
            "slug": slug,
            "slice": name,
            "cgroup_path": cgroup,
            "expected": expected_probe_limits(plan),
            "rootful": {},
            "rootless": {},
            "ok": False,
        }
        docker(["rm", "-f", container])
        try:
            started = docker([
                "run", "-d", "--name", container, f"--cgroup-parent={name}",
                "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64",
                "alpine", "sleep", "300",
            ])
            if started.returncode:
                evidence["error"] = (started.stderr or started.stdout)[:400]
                return evidence
            pid_s = docker([
                "inspect", "-f", "{{.State.Pid}}", container,
            ]).stdout.strip()
            try:
                pid = int(pid_s)
            except ValueError:
                evidence["error"] = f"bad probe pid: {pid_s!r}"
                return evidence
            rootful_cgroup = proc_cgroup(pid)
            rootless_cgroup = proc_cgroup(manager_pid())
            evidence["rootful"] = {
                "container_pid": pid,
                "container_cgroup": rootful_cgroup,
            }
            evidence["rootless"] = {"user_manager_cgroup": rootless_cgroup}

            before = usage_usec()
            docker([
                "exec", container, "timeout", "3", "sh", "-c",
                "while :; do :; done",
            ])
            # A rootless scope under the same manager also loads the slice.
            self._run_user(  # type: ignore[attr-defined]
                uid,
                [
                    "systemd-run", "--user", "--scope", "--no-block", "--collect",
                    "sh", "-c", "timeout 3 sh -c 'while :; do :; done'",
                ],
            )
            evidence["cpu_delta_usec"] = usage_usec() - before
            evidence["memory_max"] = read("memory.max")
            evidence["cpu_max"] = read("cpu.max")
            evidence["pids_max"] = read("pids.max")
            evidence["memory_events"] = read("memory.events")
            events = evidence["memory_events"]
            evidence["memory_throttled"] = any(
                line.startswith(("max ", "oom_kill ")) and line.split()[1] != "0"
                for line in events.splitlines()
            )

            expected = evidence["expected"]
            evidence["ok"] = (
                rootful_cgroup.startswith(cgroup)
                and rootless_cgroup.startswith(cgroup)
                and evidence["memory_max"] == expected["memory_max"]
                and evidence["cpu_max"] == expected["cpu_max"]
                and evidence["pids_max"] == expected["pids_max"]
                and evidence["cpu_delta_usec"] > 0
            )
            return evidence
        finally:
            docker(["rm", "-f", container])
