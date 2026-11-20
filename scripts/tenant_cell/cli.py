"""Typer command definitions for the rootless tenant cell CLI (A.SPEC 0097).

Commands stay thin: they parse arguments, build a CellService and print a
serializable result. All logic and all host access live in the service layer.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click.core
import typer
from typer.core import TyperOption

from . import alloc, host_agent, materializer, network, plans, relay
from . import doctor as doctor_mod
from .cells import CellNotFound, CellService, ProvisionRefused
from .executor import LocalExecutor


def _needs_flag_value_shim() -> bool:
    """Only typer <= 0.9 forwards flag_value=None to click >= 8.2.

    Newer typer versions pass their own sentinel and reject ``flag_value`` as
    an unexpected keyword, so the shim must not be installed on those hosts.
    """
    try:
        parts = importlib.metadata.version("typer").split(".")
        return int(parts[0]) == 0 and int(parts[1]) < 10
    except (ValueError, IndexError, importlib.metadata.PackageNotFoundError):
        return False


# typer 0.4.x always forwards flag_value=None, which click >= 8.2 reads as a
# real (non-bool) flag value, breaking every option. Translate it to click's
# UNSET sentinel so flags and value options are auto-detected correctly.
if _needs_flag_value_shim() and getattr(click.core, "UNSET", None) is not None:
    _option_init = TyperOption.__init__

    def _compat_option_init(self: TyperOption, *args: object, **kwargs: object) -> None:
        if kwargs.get("flag_value") is None:
            kwargs["flag_value"] = click.core.UNSET
        _option_init(self, *args, **kwargs)

    TyperOption.__init__ = _compat_option_init  # type: ignore[method-assign]

app = typer.Typer(
    name="spanel-tenant",
    add_completion=False,
    help=(
        "Rootless per-tenant cell: doctor, provision, status, repair, "
        "migrate, verify, deprovision."
    ),
)

DEFAULT_DATA_ROOT = "/var/lib/spanel"


def _service(data_root: str) -> CellService:
    return CellService(doctor_mod.HostProbe(), LocalExecutor(), data_root)


def _emit(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        typer.echo(json.dumps(payload, sort_keys=True, default=str))
    else:
        for key, value in payload.items():
            typer.echo(f"{key}: {value}")


def _execute(
    action: Callable[[], dict[str, Any]], json_output: bool, verb: str
) -> dict[str, Any]:
    """Run an action, turning failures into printable errors (no stack traces)."""
    try:
        return action()
    except ProvisionRefused as exc:
        _emit(
            {"error": "doctor gate failed", "doctor": exc.report.to_dict()},
            json_output,
        )
        raise typer.Exit(code=2)
    except (
        alloc.InvalidSlug,
        alloc.SlugRetired,
        CellNotFound,
        plans.InvalidPlan,
        plans.PlanNotFound,
        plans.PlanCellMissing,
        plans.PlanDriverError,
        plans.MutationDisabled,
    ) as exc:
        _emit({"error": str(exc), "verb": verb}, json_output)
        raise typer.Exit(code=2)
    except Exception as exc:  # noqa: BLE001 - CLI must not leak a stack trace
        _emit({"error": str(exc), "verb": verb}, json_output)
        raise typer.Exit(code=1)


CORE_NAMES = {
    "traefik",
    "mariadb",
    "phpmyadmin",
    "powerdns",
    "docker-mailserver",
    "mailserver",
    "spanel-mail",
    "spanel-core",
}
MIGRATION_KINDS = ("static", "wordpress", "app")


class MigrationBackend:
    """Injectable bridge to the 0107 inventory/runtime and future migrators."""

    def resources(self) -> list[dict[str, Any]]:
        return []

    def runtime(self, resource: dict[str, Any]) -> str:
        return str(resource.get("runtime", "rootful"))

    def migrate(self, resource: dict[str, Any]) -> Any:
        raise RuntimeError("no resource migrator is registered")

    def verify(self, resource: dict[str, Any]) -> bool:
        return False

    def set_runtime(self, resource: dict[str, Any], runtime: str) -> None:
        raise RuntimeError("no runtime registry is registered")

    def rollback(self, resource: dict[str, Any], token: Any) -> None:
        return None


class HostingMigrationBackend(MigrationBackend):
    """Production bridge to Hosting's real shadow-copy service."""

    def __init__(self) -> None:
        from app.main import create_app
        from plugins.hosting.backend.rootless_migration import RootlessMigrationService
        from systutor.core.lifecycle import ensure_session_factory

        self.app = create_app()
        self.db = ensure_session_factory(self.app)()
        self.service = RootlessMigrationService(self.app, self.db)

    def resources(self) -> list[dict[str, Any]]:
        from plugins.hosting.backend.models import HostingSite
        from sqlalchemy import select

        return [
            {
                "kind": site.kind,
                "resource_id": site.id,
                "name": site.container_name,
                "container_name": site.container_name,
                "runtime": self.service.resolver.assigned(
                    site.tenant_id, site.kind, site.id
                )
                or "rootful",
            }
            for site in self.db.scalars(select(HostingSite))
            if site.kind in {"static", "wordpress"}
        ]

    def migrate(self, resource: dict[str, Any]) -> Any:
        result = self.service.migrate(str(resource["resource_id"]))
        if not result.get("ok"):
            raise RuntimeError(str(result.get("error") or "hosting migration failed"))
        return result.get("operation_id")

    def verify(self, resource: dict[str, Any]) -> bool:
        return (
            self.service.status(str(resource["resource_id"])).get("state") == "retained"
        )

    def set_runtime(self, resource: dict[str, Any], runtime: str) -> None:
        # RootlessMigrationService owns the transactional registry transition.
        if runtime == "rootless" and not self.verify(resource):
            raise RuntimeError("hosting migration has not reached retained state")

    def rollback(self, resource: dict[str, Any], token: Any) -> None:
        if token:
            self.service.rollback(str(resource["resource_id"]), str(token))


def _is_core_resource(resource: dict[str, Any]) -> bool:
    labels = resource.get("labels", {})
    label_values = labels.values() if isinstance(labels, dict) else labels or []
    if any(str(value).lower() == "core" for value in label_values):
        return True
    names = " ".join(
        str(resource.get(key, "")).lower()
        for key in ("resource_id", "name", "container_name")
    )
    return any(name in names for name in CORE_NAMES)


class MigrationService:
    """Sequential, fail-closed orchestration over the registered runtime."""

    def __init__(self, backend: MigrationBackend) -> None:
        self.backend = backend

    def run(
        self,
        *,
        dry_run: bool,
        only: str | None,
        exclude: set[str],
        stop_on_failure: bool,
    ) -> dict[str, Any]:
        if only is not None and only not in MIGRATION_KINDS:
            raise ValueError("--only must be static, wordpress, or app")
        if (
            not dry_run
            and os.environ.get("SPANEL_TENANTS_ROOTLESS", "false").lower() != "true"
        ):
            raise plans.MutationDisabled(
                "SPANEL_TENANTS_ROOTLESS=true is required to apply migrations"
            )
        selected = [
            row
            for row in self.backend.resources()
            if row.get("kind") in MIGRATION_KINDS
            and (only is None or row.get("kind") == only)
            and str(row.get("resource_id")) not in exclude
            and not _is_core_resource(row)
        ]
        selected.sort(
            key=lambda row: (
                MIGRATION_KINDS.index(str(row["kind"])),
                str(row.get("resource_id", "")),
            )
        )
        results: list[dict[str, Any]] = []
        for resource in selected:
            resource_id = str(resource["resource_id"])
            old_runtime = self.backend.runtime(resource)
            item = {"kind": resource["kind"], "resource_id": resource_id}
            if old_runtime == "rootless":
                results.append({**item, "status": "already_rootless"})
                continue
            if dry_run:
                results.append({**item, "status": "would_migrate", "mutation": False})
                continue
            token: Any = None
            try:
                token = self.backend.migrate(resource)
                if not self.backend.verify(resource):
                    raise RuntimeError("post-migration verification failed")
                self.backend.set_runtime(resource, "rootless")
                results.append({**item, "status": "migrated"})
            except Exception as exc:  # noqa: BLE001 - rollback is the boundary
                self.backend.rollback(resource, token)
                self.backend.set_runtime(resource, old_runtime)
                results.append({**item, "status": "failed", "error": str(exc)[:300]})
                if stop_on_failure:
                    break
        return {
            "ok": not any(row["status"] == "failed" for row in results),
            "dry_run": dry_run,
            "order": results,
            "core_excluded": True,
        }


def _migration_service(data_root: str) -> MigrationService:
    del data_root
    return MigrationService(HostingMigrationBackend())


@app.command()
def doctor(
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """Verify that the host meets every cell prerequisite (gate for provision)."""
    report = doctor_mod.run_doctor(doctor_mod.HostProbe())
    _emit(report.to_dict(), json_output)
    if not report.ready:
        raise typer.Exit(code=2)


@app.command()
def provision(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without mutation."),
) -> None:
    """Create a cell, but only after a green doctor gate; idempotent."""
    if dry_run:
        result = _execute(
            lambda: _provision_blueprint(slug, data_root), json_output, "provision"
        )
        _emit(result, json_output)
        return
    result = _execute(
        lambda: _service(data_root).provision(slug), json_output, "provision"
    )
    _emit(result, json_output)


def _provision_blueprint(slug: str, data_root: str) -> dict[str, Any]:
    """Compute allocation facts without calling ``allocate`` or writing files."""
    slug = alloc.validate_slug(slug)
    registry = alloc.load_registry(data_root)
    cell = registry["allocations"].get(slug)
    if cell is None:
        index = int(registry["next_index"])
        retired = {int(row["index"]) for row in registry["tombstones"]}
        while index in retired:
            index += 1
        block = int(registry["block_size"])
        uid = int(registry["base_uid"]) + index
        subuid = int(registry["base_uid"]) + block + index * block
        cell = {"uid": uid, "subuid_base": subuid, "subgid_base": subuid}
    uid = int(cell["uid"])
    block = int(registry["block_size"])
    active = plans.active_plan(data_root, slug)
    return {
        "slug": slug,
        "uid": uid,
        "subuid_range": [int(cell["subuid_base"]), block],
        "subgid_range": [int(cell["subgid_base"]), block],
        "slice": plans.user_slice(uid),
        "apparmor_profile": f"spanel-cell-{slug}",
        "docker_socket": f"/var/lib/spanel/cells/{slug}/docker.sock",
        "limits": active["plan"] if active else None,
        "mutation": False,
        "would_create": [
            "user",
            "subuid",
            "subgid",
            "cell_dirs",
            "apparmor",
            "docker_socket",
        ],
    }


@app.command()
def status(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """Report effective cell state, including the host-observed uid_map."""
    result = _execute(lambda: _service(data_root).status(slug), json_output, "status")
    _emit(result, json_output)


@app.command("list")
def list_cells(
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """List all known cells."""
    result = _execute(
        lambda: {"cells": _service(data_root).list_cells()}, json_output, "list"
    )
    _emit(result, json_output)


@app.command()
def repair(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """Re-install profile and network rules without touching cell data."""
    result = _execute(lambda: _service(data_root).repair(slug), json_output, "repair")
    _emit(result, json_output)


@app.command()
def migrate(
    slug: str | None = typer.Option(None, "--slug", help="Validated tenant slug."),
    driver: str | None = typer.Option(None, "--driver", help="Target cgroup driver."),
    all_resources: bool = typer.Option(False, "--all", help="Migrate all resources."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without mutation."),
    only: str | None = typer.Option(None, "--only", help="static, wordpress, or app."),
    exclude: str | None = typer.Option(None, "--exclude", help="Resource id to skip."),
    stop_on_failure: bool = typer.Option(
        True, "--stop-on-failure/--continue-on-failure"
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """Migrate a driver, or preview/run sequential per-resource migration."""
    if all_resources:
        if slug is not None or driver is not None:
            _emit(
                {"error": "--all is mutually exclusive with --slug/--driver"},
                json_output,
            )
            raise typer.Exit(code=2)
        result = _execute(
            lambda: _migration_service(data_root).run(
                dry_run=dry_run,
                only=only,
                exclude={exclude} if exclude else set(),
                stop_on_failure=stop_on_failure,
            ),
            json_output,
            "migrate_all",
        )
        _emit(result, json_output)
        if not result.get("ok"):
            raise typer.Exit(code=1)
        return
    if slug is None:
        _emit({"error": "--slug is required unless --all is used"}, json_output)
        raise typer.Exit(code=2)
    result = _execute(
        lambda: _service(data_root).migrate(
            slug, driver or alloc.DEFAULT_CGROUP_DRIVER
        ),
        json_output,
        "migrate",
    )
    _emit(result, json_output)


@app.command()
def verify(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """Prove the kernel applies memory/CPU/PID limits for a systemd cell."""
    result = _execute(
        lambda: _service(data_root).verify_limits(slug), json_output, "verify"
    )
    _emit(result, json_output)
    if not result.get("ok"):
        raise typer.Exit(code=1)


@app.command()
def deprovision(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    keep_data: bool = typer.Option(
        True, "--keep-data", help="Keep app data (default)."
    ),
    purge_data: bool = typer.Option(False, "--purge-data", help="Purge app data."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """Tear down the cell; data is conserved unless --purge-data is given."""
    result = _execute(
        lambda: _service(data_root).deprovision(
            slug, keep_data=keep_data and not purge_data
        ),
        json_output,
        "deprovision",
    )
    _emit(result, json_output)


apparmor_app = typer.Typer(
    name="apparmor", add_completion=False, help="Manage cell profiles."
)
app.add_typer(apparmor_app, name="apparmor")


@apparmor_app.command("install")
def apparmor_install(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    result = _execute(
        lambda: _service(data_root).apparmor_install(slug),
        json_output,
        "apparmor_install",
    )
    _emit(result, json_output)


@apparmor_app.command("verify")
def apparmor_verify(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    result = _execute(
        lambda: _service(data_root).apparmor_verify(slug),
        json_output,
        "apparmor_verify",
    )
    _emit(result, json_output)


@apparmor_app.command("remove")
def apparmor_remove(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    result = _execute(
        lambda: _service(data_root).apparmor_remove(slug),
        json_output,
        "apparmor_remove",
    )
    _emit(result, json_output)


# --- A.SPEC 0100: per-tenant resource plans --------------------------------

plan_app = typer.Typer(
    name="plan",
    add_completion=False,
    help="Manage a tenant's aggregate memory/CPU/PID plan (tenant slice).",
)
app.add_typer(plan_app, name="plan")


def _plan_service(data_root: str) -> materializer.PlanMaterializer:
    return materializer.PlanMaterializer(
        LocalExecutor(), data_root, probe=doctor_mod.HostProbe()
    )


def _plan_preview(
    slug: str, memory: str, cpus: float, pids: int, data_root: str
) -> dict[str, Any]:
    checked = plans.validate_plan(memory, cpus, pids)
    cell = alloc.load_registry(data_root)["allocations"].get(alloc.validate_slug(slug))
    if cell is None:
        raise plans.PlanCellMissing(slug)
    uid = int(cell["uid"])
    return {
        "slug": slug,
        "uid": uid,
        "slice": plans.user_slice(uid),
        "properties": plans.set_property_args(uid, checked)[3:],
        "mutation": False,
    }


def _plan_apply_command(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    memory: str = typer.Option(..., "--memory", help="MemoryMax (e.g. 512M)."),
    cpus: float = typer.Option(..., "--cpus", help="CPU quota in cores (e.g. 0.5)."),
    pids: int = typer.Option(..., "--pids", help="TasksMax (positive integer)."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without systemd."),
) -> None:
    """Apply limits to the existing user manager without reparenting it."""
    result = _execute(
        (lambda: _plan_preview(slug, memory, cpus, pids, data_root))
        if dry_run
        else lambda: _plan_service(data_root).apply(
            slug, {"memory": memory, "cpus": cpus, "pids": pids}
        ),
        json_output,
        "plan_apply",
    )
    _emit(result, json_output)


plan_app.command("apply")(_plan_apply_command)
plan_app.command("set")(_plan_apply_command)


@plan_app.command("show")
def plan_show(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """Return the saved plan and its effective slice."""
    result = _execute(
        lambda: _plan_service(data_root).show(slug), json_output, "plan_show"
    )
    _emit(result, json_output)


@plan_app.command("remove")
def plan_remove(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """Remove the slice and drop-in and restore user-<uid>.slice."""
    result = _execute(
        lambda: _plan_service(data_root).remove(slug), json_output, "plan_remove"
    )
    _emit(result, json_output)


@plan_app.command("verify")
def plan_verify(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """Prove the kernel enforces the plan on the rootful and rootless sides."""
    result = _execute(
        lambda: _plan_service(data_root).verify(slug), json_output, "plan_verify"
    )
    _emit(result, json_output)
    if not result.get("ok"):
        raise typer.Exit(code=1)


@plan_app.command("probe")
def plan_probe(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    memory_mb: int = typer.Option(64, "--memory-mb"),
    seconds: int = typer.Option(3, "--seconds"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    result = _execute(
        lambda: _plan_service(data_root).probe(
            slug, memory_mb=memory_mb, seconds=seconds
        ),
        json_output,
        "plan_probe",
    )
    _emit(result, json_output)
    if not result.get("ok"):
        raise typer.Exit(code=1)


def _import_plans(from_file: str, data_root: str) -> dict[str, Any]:
    """Explicit migration: materialize every entry of a legacy plans.json."""
    payload = json.loads(Path(from_file).read_text(encoding="utf-8"))
    entries = payload.get("plans", {})
    if not isinstance(entries, dict):
        raise plans.InvalidPlan("plans.json has no 'plans' object")
    service = _plan_service(data_root)
    imported = [
        service.apply(slug, entry["plan"])
        for slug, entry in sorted(entries.items())
        if isinstance(entry, dict) and isinstance(entry.get("plan"), dict)
    ]
    return {"imported": imported, "source": from_file, "cache_only": True}


@plan_app.command("import")
def plan_import(
    from_file: str = typer.Option(
        ..., "--from", help="plans.json cache to import explicitly."
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """Migrate a legacy plans.json to the materializer (no silent fallback)."""
    result = _execute(
        lambda: _import_plans(from_file, data_root), json_output, "plan_import"
    )
    _emit(result, json_output)


# --- A.SPEC 0102: privileged host agent (run only by systemd) ---------------


@app.command("plan-agent")
def plan_agent(
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """Serve the restricted plan protocol on the host Unix socket.

    This command is meant to be started by ``spanel-plan-agent.service`` only.
    The local mutation gate and the shared token live in this privileged host
    process, never in the unprivileged application container.
    """
    if not host_agent.plans.mutation_allowed():
        typer.echo(
            f"refusing to start: set {host_agent.plans.MUTATION_GATE}=1 "
            "in the host agent process only"
        )
        raise typer.Exit(code=2)
    agent = host_agent.build_agent_from_env(data_root)
    path = host_agent.socket_path_from_env()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(16)
    try:
        agent.serve_forever(server)
    finally:
        server.close()
        path.unlink(missing_ok=True)


# --- A.SPEC 0104: unprivileged edge relay -----------------------------------


@app.command("edge-relay")
def edge_relay(
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
    bind: str = typer.Option("", "--bind", help="Override the relay bind address."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Serve the unprivileged TCP relay and its restricted control socket.

    Started by ``spanel-edge-relay.service`` only. It carries the same
    host-only mutation gate as ``plan-agent`` and never touches a Docker socket
    or a certificate: the relay just forwards bytes to the cell loopback.
    """
    if not host_agent.plans.mutation_allowed():
        typer.echo(
            f"refusing to start: set {host_agent.plans.MUTATION_GATE}=1 "
            "in the host relay process only"
        )
        raise typer.Exit(code=2)
    relay_bind = bind or relay.default_bind()
    sources = relay.allowed_sources()
    endpoints = relay.endpoints_from_registry(
        data_root, bind=relay_bind, sources=sources
    )
    tcp = relay.TCPRelay(relay_bind, sources)
    try:
        tcp.reload(endpoints)
    except Exception as exc:  # noqa: BLE001 - surface a bind failure cleanly
        _emit({"error": str(exc), "verb": "edge_relay"}, json_output)
        raise typer.Exit(code=1) from None
    agent = relay.RelayControlAgent(tcp, allowed_uids={network.traefik_uid()})
    path = Path(relay.socket_path_from_env())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    control.bind(str(path))
    control.listen(16)
    try:
        agent.serve_forever(control)
    finally:
        control.close()
        tcp.close()
        path.unlink(missing_ok=True)
