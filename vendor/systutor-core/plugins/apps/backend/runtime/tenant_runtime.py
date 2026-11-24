"""Tenant-scoped Docker runtime abstraction (A.SPEC 0096 §5.2 / 0098).

The plugin never imports the Fase 1 CLI. It reads the same persisted cell
registry and the same live host evidence, but with its own small reader so the
backend stays independent from the operator tooling.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .transport import Runner
from .types import AppDeployError

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,61}$")
DEFAULT_DATA_ROOT = "/var/lib/spanel"


def validate_slug(slug: str) -> str:
    if not isinstance(slug, str) or not SLUG_RE.fullmatch(slug):
        raise AppDeployError("invalid tenant cell slug")
    return slug


def _cell_slug(tenant_slug: str) -> str:
    """Derive the canonical cell slug from a free-form kernel tenant slug.

    Mirrors ``scripts/tenant_cell/slugs.py::cell_slug_for`` on the host.  The
    plugin cannot import operator tooling, so the small deterministic rule is
    duplicated here; both sides are covered by the same derivation tests.
    """
    if not isinstance(tenant_slug, str) or not tenant_slug.strip():
        raise AppDeployError("invalid tenant slug")
    raw = tenant_slug.strip()
    if SLUG_RE.fullmatch(raw):
        return raw
    plain = unicodedata.normalize("NFKD", raw).encode("ascii", "ignore").decode()
    candidate = re.sub(r"[^a-z0-9]+", "-", plain.lower()).strip("-")
    candidate = candidate[:62].rstrip("-")
    try:
        return validate_slug(candidate)
    except AppDeployError as exc:
        raise AppDeployError("tenant slug has no valid cell slug") from exc


def tenant_slug(session: Any, tenant_id: str) -> str:
    """Resolve the cell slug from the kernel tenant table, never from a request."""
    from systutor.kernel.tenants.models import Tenant

    tenant = session.get(Tenant, tenant_id)
    if tenant is None:
        raise AppDeployError("tenant not found")
    return _cell_slug(tenant.slug)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _main_pid(slug: str) -> int:
    try:
        result = subprocess.run(
            ["systemctl", "show", "-p", "MainPID", "--value", f"spanel-cell-{slug}"],
            capture_output=True,
            text=True,
            check=False,
        )
        return int(result.stdout.strip())
    except (ValueError, OSError):
        return 0


def _dockerd_pid(main_pid: int) -> int:
    """Find the dockerd descendant; UID 0 is not assumed to be the first subuid."""
    try:
        children = Path(f"/proc/{main_pid}/task/{main_pid}/children").read_text().split()
    except OSError:
        return main_pid
    for pid in children:
        try:
            comm = Path(f"/proc/{pid}/comm").read_text().strip()
        except OSError:
            continue
        if comm == "dockerd":
            return int(pid)
    return main_pid


def _uid_map(pid: int) -> list[dict[str, int]]:
    entries: list[dict[str, int]] = []
    for line in _read(Path(f"/proc/{pid}/uid_map")).splitlines():
        parts = line.split()
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            entries.append(
                {
                    "inner_id": int(parts[0]),
                    "host_id": int(parts[1]),
                    "count": int(parts[2]),
                }
            )
    return entries


@runtime_checkable
class TenantRuntime(Protocol):
    slug: str
    socket_path: str

    def environment(self) -> dict[str, str]: ...
    def status(self, slug: str | None = None) -> dict[str, Any]: ...
    def build(self, slug: str, release_dir: Path, tag: str) -> Any: ...
    def up(self, slug: str, compose_files: list[Path], override: Any = None) -> Any: ...
    def down(self, slug: str, project: str) -> Any: ...
    def logs(self, slug: str, project: str, service: str | None = None) -> Any: ...
    def exec_probe(self, slug: str, argv: list[str]) -> Any: ...


class DockerRootlessRuntime:
    """Runs Docker commands against one tenant's rootless socket."""

    def __init__(
        self,
        slug: str,
        data_root: str = DEFAULT_DATA_ROOT,
        runner_factory: Callable[..., Runner] = Runner,
        transport: str = "local",
    ) -> None:
        self.slug = validate_slug(slug)
        self.data_root = Path(data_root)
        self._runner_factory = runner_factory
        self.transport = transport if transport in {"local", "ssh"} else "local"

    @property
    def socket_path(self) -> str:
        return f"{self.data_root}/cells/{self.slug}/docker.sock"

    def environment(self) -> dict[str, str]:
        env = dict(os.environ)
        env["DOCKER_HOST"] = f"unix://{self.socket_path}"
        # Runtime selection and probe policy are one decision.  A global
        # hardened baseline would reject the cell's user-namespace isolation
        # and attempt AppArmor-forbidden read-only rootfs remounts.
        env["SPANEL_APPS_PROBE_BASELINE"] = "rootless"
        return env

    def runner(self) -> Runner:
        return self._runner_factory(self.transport, self.environment())

    def _check(self, slug: str | None) -> None:
        if slug is not None and validate_slug(slug) != self.slug:
            raise AppDeployError("runtime slug mismatch")

    def status(self, slug: str | None = None) -> dict[str, Any]:
        self._check(slug)
        registry_path = self.data_root / "registry.json"
        try:
            registry = json.loads(_read(registry_path) or "{}")
        except json.JSONDecodeError as exc:
            raise AppDeployError("invalid cell registry") from exc
        cell = (registry.get("allocations") or {}).get(self.slug, {})
        main_pid = _main_pid(self.slug)
        pid = _dockerd_pid(main_pid) if main_pid else 0
        profile_name = f"spanel-cell-{self.slug}"
        current = _read(Path(f"/proc/{main_pid}/attr/current")).strip() if main_pid else ""
        effective = current == f"{profile_name} (enforce)"
        profile_path = Path("/etc/apparmor.d") / profile_name
        return {
            "state": "ready" if cell and effective and pid else "degraded",
            "slug": self.slug,
            "uid": cell.get("uid"),
            "socket_path": self.socket_path,
            "cgroup_path": cell.get("cgroup_path", ""),
            "uid_map": _uid_map(pid) if pid else [],
            "apparmor": {
                "profile": profile_name,
                "effective": effective,
                "hash": hashlib.sha256(_read(profile_path).encode()).hexdigest()
                if profile_path.exists()
                else "",
            },
        }

    def build(self, slug: str, release_dir: Path, tag: str) -> Any:
        self._check(slug)
        return self.runner().run(["docker", "build", "-t", tag, str(release_dir)])

    def up(self, slug: str, compose_files: list[Path], override: Any = None) -> Any:
        self._check(slug)
        argv = ["docker", "compose"]
        for path in compose_files:
            argv.extend(["-f", str(path)])
        argv.extend(["up", "-d"])
        return self.runner().run(argv)

    def down(self, slug: str, project: str) -> Any:
        self._check(slug)
        return self.runner().run(["docker", "compose", "-p", project, "down"])

    def logs(self, slug: str, project: str, service: str | None = None) -> Any:
        self._check(slug)
        argv = ["docker", "compose", "-p", project, "logs"]
        if service:
            argv.append(service)
        return self.runner().run(argv)

    def exec_probe(self, slug: str, argv: list[str]) -> Any:
        self._check(slug)
        return self.runner().run(argv)


class FakeTenantRuntime:
    """Records calls; never executes a process or touches the filesystem."""

    def __init__(self, slug: str, status: dict[str, Any] | None = None) -> None:
        self.slug = validate_slug(slug)
        self.socket_path = f"/fake/cells/{self.slug}/docker.sock"
        self.status_result = status or {
            "state": "ready",
            "slug": self.slug,
            "socket_path": self.socket_path,
            "uid_map": [],
            "apparmor": {"profile": f"spanel-cell-{self.slug}", "effective": True, "hash": "fake"},
        }
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _record(self, verb: str, **kwargs: Any) -> None:
        self.calls.append((verb, kwargs))

    def environment(self) -> dict[str, str]:
        self._record("environment")
        return {
            "DOCKER_HOST": f"unix://{self.socket_path}",
            "SPANEL_APPS_PROBE_BASELINE": "rootless",
        }

    def status(self, slug: str | None = None) -> dict[str, Any]:
        self._record("status", slug=slug)
        return dict(self.status_result)

    def build(self, slug: str, release_dir: Path, tag: str) -> None:
        self._record("build", slug=slug, release_dir=release_dir, tag=tag)

    def up(self, slug: str, compose_files: list[Path], override: Any = None) -> None:
        self._record("up", slug=slug, compose_files=compose_files, override=override)

    def down(self, slug: str, project: str) -> None:
        self._record("down", slug=slug, project=project)

    def logs(self, slug: str, project: str, service: str | None = None) -> None:
        self._record("logs", slug=slug, project=project, service=service)

    def exec_probe(self, slug: str, argv: list[str]) -> None:
        self._record("exec_probe", slug=slug, argv=argv)


class TenantRuntimeRegistry:
    """Factory used by the worker; no production behavior changes by default."""

    def __init__(
        self,
        data_root: str = DEFAULT_DATA_ROOT,
        runner_factory: Callable[..., Runner] = Runner,
        transport: str = "local",
    ) -> None:
        self.data_root = data_root
        self.runner_factory = runner_factory
        self.transport = transport

    def for_tenant(self, tenant_id: str, slug: str) -> DockerRootlessRuntime:
        return DockerRootlessRuntime(
            slug, self.data_root, self.runner_factory, self.transport
        )
