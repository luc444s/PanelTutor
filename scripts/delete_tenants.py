#!/usr/bin/env python3
"""Delete tenant rows and their rootless cells, safely.

Dry-run by default: it only prints what would be destroyed. To mutate, pass
``--apply``. Cells are deprovisioned through the supported ``CellService``
path before any database row is removed; if a cell cannot be torn down the
script aborts for that tenant and leaves the database untouched.

Examples::

    # preview one or more slugs
    python3 scripts/delete_tenants.py --slug acme --slug demo

    # delete cells + rows, keep the cell directories
    sudo SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS=1 \
        python3 scripts/delete_tenants.py --apply --slug acme

    # additionally remove /var/lib/spanel/cells/<slug> once it is empty
    sudo SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS=1 \
        python3 scripts/delete_tenants.py --apply --purge-files --slug acme

    # explicit database URL
    python3 scripts/delete_tenants.py --apply --slug acme \
        --database-url postgresql+psycopg://user:pass@host/db
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from sqlalchemy import bindparam, create_engine, inspect, text
from sqlalchemy.engine import Connection

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor" / "systutor-core" / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from systutor.contracts.tenant_slugs import cell_slug_for

DEFAULT_DATA_ROOT = "/var/lib/spanel"
DEFAULT_PLAN_ENV = Path("/etc/spanel/plan-agent.env")
MUTATION_GATE = "SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS"

# Children first, parents last. Every table here is deleted by ``tenant_id``.
TENANT_TABLES = (
    "apps_operations",
    "apps_github_repositories",
    "apps_github_installations",
    "apps_github_providers",
    "apps_applications",
    "apps_tenant_plans",
    "hosting_rootless_migrations",
    "hosting_sites",
    "domains_routes",
    "domains_app_hosts",
    "domains_observed",
    "domains_cloudflare_connections",
    "domains_cloudflare_oauth_flows",
    "domains_dns_zones",
    "core_signature_evidence",
    "core_signature_sessions",
    "core_document_versions",
    "event_outbox",
    "event_logs",
    "user_context_claims",
    "audit_logs",
    "users",
    "roles",
    "branches",
    "tenant_site_settings",
    "tenant_domains",
    "tenant_resource_runtimes",
    "tenant_permissions",
)

# Tables without ``tenant_id`` that still reference tenant-scoped rows.
# (table, [(fk column, parent table)], parent primary key column)
CHILD_TABLES: tuple[tuple[str, tuple[tuple[str, str], ...], str], ...] = (
    ("apps_deployments", (("application_id", "apps_applications"),), "id"),
    (
        "user_roles",
        (("user_id", "users"), ("role_id", "roles")),
        "id",
    ),
    ("role_permissions", (("role_id", "roles"),), "id"),
)


def ids_statement(sql: str) -> Any:
    """``text()`` with an expanding list parameter named ``ids``."""
    return text(sql).bindparams(bindparam("ids", expanding=True))


def load_database_url(explicit: str | None) -> str:
    if explicit:
        return explicit
    value = os.environ.get("SYSTUTOR_DATABASE_URL", "").strip()
    if value:
        return value
    if DEFAULT_PLAN_ENV.is_file():
        for line in DEFAULT_PLAN_ENV.read_text(encoding="utf-8").splitlines():
            if line.startswith("SYSTUTOR_DATABASE_URL="):
                return line.split("=", 1)[1].strip()
    raise SystemExit(
        "no database URL: pass --database-url or set SYSTUTOR_DATABASE_URL "
        f"(also read from {DEFAULT_PLAN_ENV})"
    )


def table_names(connection: Connection) -> set[str]:
    return set(inspect(connection).get_table_names())


def columns(connection: Connection, table: str) -> set[str]:
    return {column["name"] for column in inspect(connection).get_columns(table)}


def resolve_tenants(
    connection: Connection, cell_slugs: Iterable[str]
) -> dict[str, str]:
    """Map each requested cell slug to exactly one tenant id."""
    rows = connection.execute(text("SELECT id, slug FROM tenants")).all()
    resolved: dict[str, str] = {}
    for cell_slug in cell_slugs:
        matches = [
            (tenant_id, tenant_slug)
            for tenant_id, tenant_slug in rows
            if tenant_slug == cell_slug or cell_slug_for(tenant_slug) == cell_slug
        ]
        if not matches:
            print(f"[cell] {cell_slug}: no tenant row")
            continue
        if len(matches) > 1:
            found = ", ".join(repr(slug) for _, slug in matches)
            raise SystemExit(f"{cell_slug}: ambiguous, matches {found}")
        tenant_id, tenant_slug = matches[0]
        resolved[cell_slug] = tenant_id
        if tenant_slug != cell_slug:
            print(f"[map ] {cell_slug} -> tenant {tenant_slug!r} ({tenant_id})")
        else:
            print(f"[map ] {cell_slug} -> {tenant_id}")
    return resolved


def present_tables(connection: Connection) -> set[str]:
    existing = table_names(connection)
    return {
        name
        for name in (*TENANT_TABLES, *(c[0] for c in CHILD_TABLES))
        if name in existing
    }


def count_rows(
    connection: Connection, tenant_ids: list[str], existing: set[str]
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in TENANT_TABLES:
        if table not in existing:
            continue
        here = columns(connection, table)
        if "tenant_id" not in here:
            continue
        total = connection.execute(
            ids_statement(f'SELECT count(*) FROM "{table}" WHERE tenant_id IN :ids'),
            {"ids": tenant_ids},
        ).scalar_one()
        if total:
            counts[table] = int(total)
    for table, links, parent_pk in CHILD_TABLES:
        if table not in existing:
            continue
        here = columns(connection, table)
        clauses = [
            f'"{column}" IN '
            f'(SELECT "{parent_pk}" FROM "{parent}" WHERE tenant_id IN :ids)'
            for column, parent in links
            if column in here and parent in existing
        ]
        if not clauses:
            continue
        total = connection.execute(
            ids_statement(
                f'SELECT count(*) FROM "{table}" WHERE ' + " OR ".join(clauses)
            ),
            {"ids": tenant_ids},
        ).scalar_one()
        if total:
            counts[table] = int(total)
    return counts


def uncovered_tables(
    connection: Connection, tenant_ids: list[str], existing: set[str]
) -> list[str]:
    """Tenant-scoped tables this script does not know how to delete."""
    known = set(TENANT_TABLES)
    missing: list[str] = []
    for table in existing:
        if table in known:
            continue
        here = columns(connection, table)
        if "tenant_id" not in here:
            continue
        total = connection.execute(
            ids_statement(f'SELECT count(*) FROM "{table}" WHERE tenant_id IN :ids'),
            {"ids": tenant_ids},
        ).scalar_one()
        if total:
            missing.append(f"{table} ({total} rows)")
    return missing


def delete_rows(
    connection: Connection, tenant_ids: list[str], existing: set[str]
) -> None:
    for table, links, parent_pk in CHILD_TABLES:
        if table not in existing:
            continue
        here = columns(connection, table)
        for column, parent in links:
            if column not in here or parent not in existing:
                continue
            connection.execute(
                ids_statement(
                    f'DELETE FROM "{table}" WHERE "{column}" IN '
                    f'(SELECT "{parent_pk}" FROM "{parent}" WHERE tenant_id IN :ids)'
                ),
                {"ids": tenant_ids},
            )
    for table in TENANT_TABLES:
        if table not in existing:
            continue
        if "tenant_id" not in columns(connection, table):
            continue
        connection.execute(
            ids_statement(f'DELETE FROM "{table}" WHERE tenant_id IN :ids'),
            {"ids": tenant_ids},
        )
    connection.execute(
        ids_statement("DELETE FROM tenants WHERE id IN :ids"), {"ids": tenant_ids}
    )


def cell_containers(data_root: str, slug: str) -> bool | None:
    """True if the cell daemon answers and still has containers."""
    socket = Path(data_root) / "cells" / slug / "docker.sock"
    if not socket.exists():
        return None
    env = {**os.environ, "DOCKER_HOST": f"unix://{socket}"}
    try:
        result = subprocess.run(
            ["docker", "ps", "-aq"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return bool(result.stdout.strip())


def cell_state(data_root: str, slug: str) -> str:
    """Registry state for one cell, without importing the host agent."""
    registry = Path(data_root) / "registry.json"
    if not registry.is_file():
        return "no-registry"
    import json

    data = json.loads(registry.read_text(encoding="utf-8"))
    cell = (data.get("allocations") or {}).get(slug)
    if cell is not None:
        return str(cell.get("state") or "allocated")
    if any(row.get("slug") == slug for row in data.get("tombstones") or []):
        return "retired"
    return "absent"


def deprovision_cells(slugs: list[str], data_root: str, purge_files: bool) -> list[str]:
    if os.geteuid() != 0:
        raise SystemExit("cell teardown requires root")
    if os.environ.get(MUTATION_GATE) != "1":
        raise SystemExit(
            f"set {MUTATION_GATE}=1 to allow host mutations "
            "(or rerun without --apply to preview)"
        )

    from tenant_cell.cells import CellService
    from tenant_cell.doctor import HostProbe
    from tenant_cell.executor import LocalExecutor

    service = CellService(HostProbe(), LocalExecutor(), data_root)
    removed: list[str] = []
    for slug in slugs:
        try:
            result = service.deprovision(slug, keep_data=False)
        except Exception as exc:
            raise SystemExit(f"cell {slug}: teardown failed: {exc}") from exc
        state = result.get("state")
        print(f"[cell] {slug}: {state}")
        removed.append(slug)
        if not purge_files or state not in {"deprovisioned", "retired", "absent"}:
            continue
        containers = cell_containers(data_root, slug)
        if containers:
            print(f"[cell] {slug}: containers still present, keeping {data_root}/cells/{slug}")
            continue
        directory = Path(data_root) / "cells" / slug
        if directory.exists():
            shutil.rmtree(directory)
            print(f"[cell] {slug}: removed {directory}")
    return removed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--slug",
        action="append",
        dest="slugs",
        metavar="SLUG",
        help="cell slug to delete (repeatable, at least one required)",
    )
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--data-root", default=DEFAULT_DATA_ROOT)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually deprovision cells and delete rows (default: dry-run)",
    )
    parser.add_argument(
        "--purge-files",
        action="store_true",
        help="remove /var/lib/spanel/cells/<slug> after a clean teardown",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="skip the interactive confirmation required by --apply",
    )
    args = parser.parse_args(argv)

    if not args.slugs:
        parser.error("pass at least one --slug")
    slugs = args.slugs
    url = load_database_url(args.database_url)
    engine = create_engine(url, pool_pre_ping=True)

    with engine.connect() as connection:
        existing = present_tables(connection)
        resolved = resolve_tenants(connection, slugs)
        tenant_ids = sorted(set(resolved.values()))
        counts = count_rows(connection, tenant_ids, existing) if tenant_ids else {}
        missing = (
            uncovered_tables(connection, tenant_ids, existing) if tenant_ids else []
        )
        if missing:
            print("\nrefusing: tenant-scoped tables without a delete rule:")
            for item in missing:
                print(f"  - {item}")
            print("add them to TENANT_TABLES and rerun")
            return 2

        print("\ncells to deprovision:")
        for slug in slugs:
            print(f"  {slug:38} state={cell_state(args.data_root, slug)}")

        print("\nrows to delete:")
        if not counts:
            print("  (none)")
        for table, total in counts.items():
            print(f"  {table:38} {total}")

        owned = {
            table: counts[table]
            for table in ("apps_applications", "hosting_sites")
            if counts.get(table)
        }
        if owned:
            print("\nWARNING: selected tenants own applications/sites:")
            for table, total in owned.items():
                print(f"  {table}: {total}")
            print("  delete them only if they are disposable")

        if not args.apply:
            print("\ndry-run: pass --apply to deprovision cells and delete rows")
            return 0

        if not args.yes:
            if not sys.stdin.isatty():
                parser.error("--apply requires --yes when stdin is not a terminal")
            answer = input(f"\ntype 'yes' to delete {len(slugs)} cell(s): ")
            if answer.strip().lower() != "yes":
                print("aborted")
                return 1

        deprovision_cells(slugs, args.data_root, args.purge_files)

        if tenant_ids:
            connection.commit()
            with connection.begin():
                delete_rows(connection, tenant_ids, existing)
            print(f"\ndeleted {len(tenant_ids)} tenant(s) from the database")
        else:
            print("\nno tenant rows to delete")

    engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
