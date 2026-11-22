"""Tenant resource plan vocabulary: validation, rendering and host adapter.

The DB in the Apps plugin is the source of truth. ``plans.json`` is only a
cache of the last applied state. Limits are applied to the existing user
manager; this module never reparents it or creates a tenant slice.

Everything that touches the host goes through the injectable ``Executor``. This
module owns validation, rendering, persistence and orchestration; the only real
adapter (``LocalExecutor``) is gated. Fakes record calls in unit tests, so no
test ever writes to a host.
"""

from __future__ import annotations

import json
import os
import pwd
import re
import subprocess
from pathlib import Path
from typing import Any

from .alloc import validate_slug

PLANS_NAME = "plans.json"
PLAN_VERSION = 1
MUTATION_GATE = "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS"
DROPIN_NAME = "tenant-plan.conf"
PLAN_KEYS = {"memory", "cpus", "pids", "cpuset"}
_SYSTEMD_DIR = Path("/etc/systemd/system")

_MEMORY_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([KMGT]?)B?$", re.IGNORECASE)
_CPUSET_RE = re.compile(r"^[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*$")
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
    """Return the *real* cgroup path of the tenant slice.

    A.SPEC 0103: for a hyphenated name such as ``tenant-cell-e2e-v5.slice``
    systemd inserts intermediate slices
    (``/tenant.slice/tenant-cell.slice/tenant-cell-e2e.slice/...``), so a
    literal composition does not match the paths observed by ``verify``.  Ask
    systemd for the slice's ``ControlGroup`` and fall back to the old literal
    path only when systemd cannot be queried (INVARIANT: deterministic
    fallback, never assume intermediate slices are absent).
    """
    name = slice_name(slug)
    fallback = f"/tenant.slice/{name}"
    try:
        result = subprocess.run(
            ["systemctl", "show", name, "-p", "ControlGroup", "--value"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return fallback
    if result.returncode != 0:
        return fallback
    return result.stdout.strip() or fallback


def user_slice(uid: int) -> str:
    """The default slice a cell's user manager returns to on plan remove."""
    return f"user-{int(uid)}.slice"


def dropin_path(uid: int) -> str:
    return f"/etc/systemd/system/user@{int(uid)}.service.d/{DROPIN_NAME}"


def render_slice(slug: str, plan: dict[str, Any]) -> str:
    """Render the tenant slice with MemoryMax / CPUQuota / TasksMax."""
    checked = validate_plan(plan["memory"], plan["cpus"], plan["pids"])
    rendered = (
        "[Unit]\n"
        f"Description=Spanel tenant {validate_slug(slug)} resource plan slice\n"
        "\n"
        "[Slice]\n"
        f"MemoryMax={checked['memory']}\n"
        f"CPUQuota={cpu_quota(checked['cpus'])}\n"
        f"TasksMax={checked['pids']}\n"
    )
    cpuset = plan.get("cpuset")
    if cpuset:
        value = str(cpuset).strip()
        if not _CPUSET_RE.fullmatch(value):
            raise InvalidPlan(f"invalid cpuset: {cpuset!r}")
        rendered += f"AllowedCPUs={value}\n"
    return rendered


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


def probe_mismatches(
    uid: int,
    state: dict[str, Any],
    evidence: dict[str, Any],
) -> list[str]:
    """Explain every kernel-evidence check that did not match the plan.

    ``verify`` used to return ``ok: False`` without a reason, which the backend
    stored as the opaque ``kernel evidence differs``.  Keeping the concrete
    differences here makes the plan row actionable (A.SPEC 0111 keeps the
    cgroup-only contract; this only reports the cause).
    """
    expected = evidence.get("expected", {})
    problems: list[str] = []

    expected_slice = user_slice(uid)
    observed_slice = str(state.get("slice") or "")
    if observed_slice != expected_slice:
        problems.append(
            f"slice differs: expected {expected_slice}, observed "
            f"{observed_slice or '<empty>'} (legacy reparenting?)"
        )

    observed_owner = str(state.get("owner_uid") or "")
    if observed_owner != str(uid):
        problems.append(
            f"OwnerUID differs: expected {uid}, observed "
            f"{observed_owner or '<empty>'}"
        )

    for key in ("memory_max", "cpu_max", "pids_max"):
        observed = str(evidence.get(key) or "")
        wanted = str(expected.get(key) or "")
        if observed != wanted:
            problems.append(
                f"{key} differs: expected {wanted}, observed "
                f"{observed or '<empty>'}"
            )

    if int(evidence.get("cpu_delta_usec") or 0) <= 0:
        problems.append("cpu accounting shows no usage under load")
    if evidence.get("eperm"):
        problems.append("container logs contain EPERM")
    return problems


def set_property_args(uid: int, plan: dict[str, Any]) -> list[str]:
    """Build the bounded systemd mutation for an existing user manager."""
    checked = validate_plan(plan["memory"], plan["cpus"], plan["pids"])
    return [
        "systemctl",
        "set-property",
        f"user@{int(uid)}.service",
        f"MemoryMax={checked['memory']}",
        f"CPUQuota={cpu_quota(checked['cpus'])}",
        f"TasksMax={checked['pids']}",
    ]


def reset_property_args(uid: int) -> list[str]:
    """Build rollback for all properties owned by the plan materializer."""
    return ["systemctl", "revert", f"user@{int(uid)}.service"]


def user_manager_cgroup_path(uid: int, control_group: str | None = None) -> str:
    """Map the existing manager to its cgroups-v2 directory."""
    group = (control_group or f"/user.slice/user-{int(uid)}.slice/user@{int(uid)}.service")
    return str(Path("/sys/fs/cgroup") / group.lstrip("/"))


def read_cgroup_limits(path: str | Path) -> dict[str, str]:
    """Read effective cgroups-v2 values without mutating the host."""
    root = Path(path)
    names = {"memory_max": "memory.max", "cpu_max": "cpu.max", "pids_max": "pids.max"}
    result: dict[str, str] = {}
    for key, filename in names.items():
        try:
            result[key] = (root / filename).read_text(encoding="utf-8").strip()
        except OSError:
            result[key] = ""
    return result


def parse_systemd_show(output: str) -> dict[str, str]:
    return {
        key: value
        for line in output.splitlines()
        if "=" in line
        for key, value in [line.split("=", 1)]
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
# Lifecycle (apply/remove/verify) lives in ``materializer.py``.  plans.json is
# now only a cache of the last applied state; the DB in the Apps plugin is the
# source of truth and is never read implicitly here.


# --- host adapter mixin ----------------------------------------------------


class PlanExecutorMixin:
    """Real (gated) host operations for plans, mixed into ``LocalExecutor``.

    Kept here so the plan's rendering, paths and probe interpretation live in a
    single module; the mixin only performs writes through the host executor's
    already-gated helpers and reads cgroup files read-only.
    """

    def apply_plan_in_place(self, uid: int, plan: dict[str, Any]) -> None:
        self._run(set_property_args(uid, plan))  # type: ignore[attr-defined]

    def reset_plan_properties(self, uid: int) -> None:
        self._run(reset_property_args(uid))  # type: ignore[attr-defined]

    def cleanup_legacy_plan(self, slug: str, uid: int) -> bool:
        """Remove obsolete reparenting files without restarting the manager."""
        self._ensure_gate()  # type: ignore[attr-defined]
        paths = (
            _SYSTEMD_DIR / slice_name(slug),
            _SYSTEMD_DIR / f"user@{int(uid)}.service.d" / DROPIN_NAME,
        )
        changed = any(path.exists() for path in paths)
        for path in paths:
            path.unlink(missing_ok=True)
        if changed:
            self._run(["systemctl", "daemon-reload"])  # type: ignore[attr-defined]
        return changed

    def read_plan_state(self, uid: int) -> dict[str, Any]:
        unit = f"user@{int(uid)}.service"
        result = subprocess.run(
            ["systemctl", "show", unit, "-p", "MemoryMax", "-p",
             "CPUQuotaPerSecUSec", "-p", "TasksMax", "-p", "Slice", "-p",
             "ControlGroup"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        properties = parse_systemd_show(result.stdout) if result.returncode == 0 else {}
        control_group = properties.get("ControlGroup", "")
        effective = read_cgroup_limits(user_manager_cgroup_path(uid, control_group))
        env = dict(os.environ)
        env["XDG_RUNTIME_DIR"] = f"/run/user/{int(uid)}"
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{int(uid)}/bus"
        owner = subprocess.run(
            ["runuser", "-u", pwd.getpwuid(int(uid)).pw_name, "--", "busctl",
             "--user", "--no-pager", "status"],
            env=env, capture_output=True, text=True, check=False, timeout=10,
        )
        owner_uid = ""
        for line in (owner.stdout or "").splitlines():
            if "OwnerUID=" in line:
                owner_uid = line.split("OwnerUID=", 1)[1].strip()
                break
        return {
            "unit": unit,
            "slice": properties.get("Slice", ""),
            "properties": properties,
            "control_group": control_group,
            "cgroup_path": user_manager_cgroup_path(uid, control_group),
            "effective": effective,
            "owner_uid": owner_uid,
        }

    def run_plan_probe(
        self, slug: str, uid: int, plan: dict[str, Any],
        memory_mb: int = 64, seconds: int = 3,
    ) -> dict[str, Any]:
        """Prove effective limits with load in a disposable rootless container."""
        self._ensure_gate()  # type: ignore[attr-defined]
        state = self.read_plan_state(uid)
        cgroup = state["control_group"]
        path = Path(state["cgroup_path"])
        container = f"spanel-plan-probe-{slug}"

        def docker(argv: list[str]) -> Any:
            return self._run_user(  # type: ignore[attr-defined]
                uid, ["docker", "--host", f"unix:///var/lib/spanel/cells/{slug}/docker.sock", *argv],
                capture_output=True, timeout=90,
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
            "slice": state["slice"],
            "owner_uid": state["owner_uid"],
            "cgroup_path": cgroup,
            "expected": expected_probe_limits(plan),
            "rootless": {},
            "ok": False,
        }
        docker(["rm", "-f", container])
        try:
            started = docker(["run", "-d", "--name", container, "alpine", "sleep", "300"])
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
            rootless_cgroup = proc_cgroup(manager_pid())
            evidence["rootless"] = {
                "container_pid": pid,
                "container_cgroup": proc_cgroup(pid),
                "user_manager_cgroup": rootless_cgroup,
            }

            before = usage_usec()
            docker([
                "exec", container, "sh", "-c",
                (
                    f"dd if=/dev/zero of=/tmp/probe bs=1M count={int(memory_mb)} "
                    f"2>/dev/null; timeout {int(seconds)} sh -c 'while :; do :; done'"
                ),
            ])
            logs = docker(["logs", container])
            evidence["eperm"] = "EPERM" in ((logs.stdout or "") + (logs.stderr or ""))
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

            problems = probe_mismatches(uid, state, evidence)
            evidence["ok"] = not problems
            if problems:
                evidence["error"] = "; ".join(problems)[:400]
            return evidence
        finally:
            docker(["rm", "-f", container])
