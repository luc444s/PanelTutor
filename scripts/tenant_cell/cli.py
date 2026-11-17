"""Typer command definitions for the rootless tenant cell CLI (A.SPEC 0097).

Commands stay thin: they parse arguments, build a CellService and print a
serializable result. All logic and all host access live in the service layer.
"""

from __future__ import annotations

import importlib.metadata
import json
from collections.abc import Callable
from typing import Any

import click.core
import typer
from typer.core import TyperOption

from . import alloc
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
    help="Rootless per-tenant cell: doctor, provision, status, deprovision.",
)

DEFAULT_DATA_ROOT = "/var/lib/spanel/cells"


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
    except (alloc.InvalidSlug, alloc.SlugRetired, CellNotFound) as exc:
        _emit({"error": str(exc), "verb": verb}, json_output)
        raise typer.Exit(code=2)
    except Exception as exc:  # noqa: BLE001 - CLI must not leak a stack trace
        _emit({"error": str(exc), "verb": verb}, json_output)
        raise typer.Exit(code=1)


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
) -> None:
    """Create a cell, but only after a green doctor gate; idempotent."""
    result = _execute(
        lambda: _service(data_root).provision(slug), json_output, "provision"
    )
    _emit(result, json_output)


@app.command()
def status(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """Report effective cell state, including the host-observed uid_map."""
    result = _execute(
        lambda: _service(data_root).status(slug), json_output, "status"
    )
    _emit(result, json_output)


@app.command("list")
def list_cells(
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """List all known cells."""
    result = _execute(lambda: {"cells": _service(data_root).list_cells()}, json_output, "list")
    _emit(result, json_output)


@app.command()
def repair(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    """Re-install profile and network rules without touching cell data."""
    result = _execute(
        lambda: _service(data_root).repair(slug), json_output, "repair"
    )
    _emit(result, json_output)


@app.command()
def deprovision(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    keep_data: bool = typer.Option(True, "--keep-data", help="Keep app data (default)."),
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


apparmor_app = typer.Typer(name="apparmor", add_completion=False, help="Manage cell profiles.")
app.add_typer(apparmor_app, name="apparmor")


@apparmor_app.command("install")
def apparmor_install(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    result = _execute(
        lambda: _service(data_root).apparmor_install(slug), json_output, "apparmor_install"
    )
    _emit(result, json_output)


@apparmor_app.command("verify")
def apparmor_verify(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    result = _execute(
        lambda: _service(data_root).apparmor_verify(slug), json_output, "apparmor_verify"
    )
    _emit(result, json_output)


@apparmor_app.command("remove")
def apparmor_remove(
    slug: str = typer.Option(..., "--slug", help="Validated tenant slug."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    data_root: str = typer.Option(DEFAULT_DATA_ROOT, "--data-root"),
) -> None:
    result = _execute(
        lambda: _service(data_root).apparmor_remove(slug), json_output, "apparmor_remove"
    )
    _emit(result, json_output)
