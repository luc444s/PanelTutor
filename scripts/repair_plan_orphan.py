#!/usr/bin/env python3
"""Close orphaned tenant-plan operations and unblock a stuck resource plan.

A ``plan_set`` operation is created synchronously, then the host agent is
called and the DB plan row is committed. If the request dies in between (the
app restarts, the actor loses its tenant scope in ``audit()``, or the client
disconnects), the operation stays ``queued`` with no ``message_id`` and every
later save fails with ``apps.operation_active``. The host cgroup can even keep
the limits while ``apps_tenant_plans`` has no row: that is the split-brain this
tool repairs.

The tool never enqueues anything and never touches the host agent. It only
closes the exact operation an operator names, behind SQL guards, so a live
request cannot be interrupted by accident:

* ``kind = 'plan_set'`` and ``subject_type = 'tenant_plan'``;
* ``status = 'queued'``, ``message_id IS NULL``, ``finished_at IS NULL``;
* older than ``--min-age`` seconds (default 300).

After a successful repair the plan must be saved again from the UI/API so the
``apps_tenant_plans`` row is created; this tool does not fabricate plan data.

Usage (from the repository root on the host):

    python3 scripts/repair_plan_orphan.py --tenant miltonarquez
    python3 scripts/repair_plan_orphan.py --tenant miltonarquez \\
        --apply --operation-id 23351f6b-89e3-4ccf-a979-2a255cfcf5cc --confirm yes

Exit codes: 0 ok, 1 error, 2 usage, 3 guard rejected (nothing updated).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_COMPOSE = REPO_ROOT / "docker-compose.yml"
DEFAULT_ENV_FILE = REPO_ROOT / ".env.docker"
DEFAULT_MIN_AGE = 300
GUARDED_KIND = "plan_set"
GUARDED_SUBJECT = "tenant_plan"
ORPHAN_ERROR_CODE = "apps_plan_operation_orphaned"


class RepairError(RuntimeError):
    """A safe-to-print repair failure."""


@dataclass(frozen=True)
class Database:
    user: str
    name: str


def read_env_file(path: Path) -> dict[str, str]:
    """Parse ``KEY=VALUE`` lines without executing or expanding anything."""
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RepairError(f"cannot read {path}: {exc}") from exc
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def resolve_database(env_file: Path) -> Database:
    values = read_env_file(env_file)
    user = values.get("POSTGRES_USER", "").strip()
    name = values.get("POSTGRES_DB", "").strip()
    if not user or not name:
        raise RepairError(f"POSTGRES_USER and POSTGRES_DB are required in {env_file}")
    return Database(user=user, name=name)


def report_sql() -> str:
    """Every active plan operation plus whether a plan row exists."""
    return """
WITH t AS (
    SELECT id, slug FROM tenants
    WHERE id::text = :'tenant' OR slug = :'tenant'
)
SELECT t.slug || E'\\t' || t.id
       || E'\\t' || (SELECT count(*) FROM apps_tenant_plans p WHERE p.tenant_id = t.id)
       || E'\\t' || coalesce(o.id, '')
       || E'\\t' || coalesce(o.kind, '')
       || E'\\t' || coalesce(o.status, '')
       || E'\\t' || coalesce(o.phase, '')
       || E'\\t' || coalesce(o.message_id, '')
       || E'\\t' || coalesce(o.error_code, '')
       || E'\\t' || coalesce(o.created_at::text, '')
FROM t
LEFT JOIN apps_operations o
       ON o.tenant_id = t.id
      AND o.subject_type = :'subject'
      AND o.status IN ('queued', 'running')
ORDER BY o.created_at NULLS LAST;
""".strip()


def repair_sql() -> str:
    """Close exactly one orphan, only when every guard still holds."""
    return f"""
WITH t AS (
    SELECT id FROM tenants
    WHERE id::text = :'tenant' OR slug = :'tenant'
),
guard AS (
    SELECT o.id
    FROM apps_operations o
    JOIN t ON t.id = o.tenant_id
    WHERE o.id = :'operation_id'
      AND o.kind = :'kind'
      AND o.subject_type = :'subject'
      AND o.status = 'queued'
      AND o.message_id IS NULL
      AND o.finished_at IS NULL
      AND o.created_at < now() - (interval '1 second' * :'min_age'::int)
    FOR UPDATE
)
UPDATE apps_operations o
SET status = 'interrupted',
    phase = 'done',
    error_code = '{ORPHAN_ERROR_CODE}',
    public_error = coalesce(
        o.public_error,
        'Operation orphaned before dispatch; closed by operator repair.'
    ),
    finished_at = now()
FROM guard g
WHERE o.id = g.id
RETURNING o.id || E'\\t' || o.status || E'\\t' || o.phase
          || E'\\t' || o.error_code;
""".strip()


def psql_command(compose_file: Path, database: Database) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(compose_file),
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        database.user,
        "-d",
        database.name,
        "-v",
        "ON_ERROR_STOP=1",
        "-A",
        "-t",
        "-X",
        "-q",
    ]


def run_psql(
    sql: str,
    variables: dict[str, str],
    *,
    compose_file: Path,
    database: Database,
    runner: Any = subprocess.run,
) -> list[list[str]]:
    command = psql_command(compose_file, database)
    for key, value in variables.items():
        command.extend(["-v", f"{key}={value}"])
    command.extend(["-c", sql])
    try:
        result = runner(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise RepairError(f"cannot run docker compose: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()[-1:] or ["psql failed"]
        raise RepairError(f"psql failed: {detail[0]}")
    rows: list[list[str]] = []
    for line in (result.stdout or "").splitlines():
        if line.strip():
            rows.append(line.split("\t"))
    return rows


def parse_report(rows: list[list[str]]) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    for row in rows:
        if len(row) < 10:
            raise RepairError(f"unexpected report row: {row!r}")
        parsed.append(
            {
                "tenant_slug": row[0],
                "tenant_id": row[1],
                "plan_rows": int(row[2]),
                "operation_id": row[3] or None,
                "kind": row[4] or None,
                "status": row[5] or None,
                "phase": row[6] or None,
                "message_id": row[7] or None,
                "error_code": row[8] or None,
                "created_at": row[9] or None,
            }
        )
    return parsed


def _uuid(value: str) -> str:
    text = value.strip()
    parts = text.split("-")
    if len(text) != 36 or [len(part) for part in parts] != [8, 4, 4, 4, 12]:
        raise argparse.ArgumentTypeError(f"not a UUID: {value!r}")
    try:
        int(text.replace("-", ""), 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a UUID: {value!r}") from exc
    return text


def _positive(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", required=True, help="tenant slug or UUID")
    parser.add_argument("--compose-file", type=Path, default=DEFAULT_COMPOSE)
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE)
    parser.add_argument(
        "--min-age",
        type=_positive,
        default=DEFAULT_MIN_AGE,
        help=f"seconds an operation must be idle (default {DEFAULT_MIN_AGE})",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="close the operation instead of only reporting",
    )
    parser.add_argument(
        "--operation-id",
        type=_uuid,
        help="exact apps_operations.id to close (required with --apply)",
    )
    parser.add_argument(
        "--confirm", default="", help="must be exactly 'yes' to update anything"
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    return parser


def _require_apply(args: argparse.Namespace) -> None:
    if not args.apply:
        return
    if args.confirm != "yes":
        raise RepairError("--apply requires --confirm yes")
    if args.operation_id is None:
        raise RepairError("--apply requires --operation-id")


def _emit(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    rows = payload.get("operations", [])
    if not rows:
        print("tenant not found")
        return
    first = rows[0]
    print(f"tenant: {first['tenant_slug']} ({first['tenant_id']})")
    print(f"plan rows: {first['plan_rows']}")
    active = [row for row in rows if row["operation_id"]]
    if not active:
        print("active plan operations: none")
    for row in active:
        print(
            f"- {row['operation_id']} kind={row['kind']} status={row['status']} "
            f"phase={row['phase']} message_id={row['message_id'] or '-'} "
            f"created_at={row['created_at'] or '-'}"
        )
    if payload.get("repaired"):
        print(f"closed: {payload['repaired']}")
    if payload.get("error"):
        print(f"error: {payload['error']}")
    if payload.get("warning"):
        print(f"warning: {payload['warning']}")
    if payload.get("next"):
        print(f"next: {payload['next']}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        _require_apply(args)
        database = resolve_database(args.env_file)
        rows = run_psql(
            report_sql(),
            {"tenant": args.tenant, "subject": GUARDED_SUBJECT},
            compose_file=args.compose_file,
            database=database,
        )
        operations = parse_report(rows)
        if not operations:
            _emit({"operations": [], "error": "tenant not found"}, args.json)
            return 1
        payload: dict[str, Any] = {"operations": operations}
        if any(row["operation_id"] for row in operations) and not args.apply:
            payload["next"] = (
                "review the orphan, then rerun with --apply --operation-id <id> "
                "--confirm yes"
            )
        if args.apply:
            repaired = run_psql(
                repair_sql(),
                {
                    "tenant": args.tenant,
                    "subject": GUARDED_SUBJECT,
                    "kind": GUARDED_KIND,
                    "operation_id": args.operation_id or "",
                    "min_age": str(args.min_age),
                },
                compose_file=args.compose_file,
                database=database,
            )
            if not repaired:
                _emit(
                    {**payload, "error": "guard rejected: operation not updated"},
                    args.json,
                )
                return 3
            payload["repaired"] = repaired[0][0]
            payload["next"] = (
                "save the plan again from the UI/API; this creates the "
                "apps_tenant_plans row and materializes it idempotently"
            )
        if operations[0]["plan_rows"] > 0 and args.apply:
            payload["warning"] = (
                "a plan row already exists; verify it before saving again"
            )
        _emit(payload, args.json)
        return 0
    except RepairError as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
