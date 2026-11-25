#!/usr/bin/env python3
"""A.SPEC 0118: reconcile per-cell host artifacts after a deploy.

Two idempotent fixes run for every allocated cell:

* copy the repo's fail-closed seccomp profile into the cell data root (dockerd
  reads it from there when it creates containers);
* make the in-cell nginx ingress stop calling ``io_setup`` (blocked by older
  profiles), reloading only when the config actually changed.

The app container never runs this: it needs root and the cell docker sockets.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tenant_cell import alloc

PROFILE = Path(__file__).resolve().parent / "deploy" / "cell-seccomp.json"
INGRESS = "spanel-cell-ingress"
AIO_LINE = "worker_aio_requests 0;"


def _docker(socket: Path, argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "-H", f"unix://{socket}", *argv],
        capture_output=True,
        text=True,
        check=False,
    )


def reconcile_seccomp(data_root: Path, *, dry_run: bool = False) -> list[dict[str, Any]]:
    profile = PROFILE.read_bytes()
    registry = alloc.load_registry(str(data_root))
    results: list[dict[str, Any]] = []
    for slug, cell in (registry.get("allocations") or {}).items():
        if not isinstance(cell, dict) or "uid" not in cell or "gid" not in cell:
            continue
        dest = data_root / "cells" / slug / "cell-seccomp.json"
        changed = not dest.is_file() or dest.read_bytes() != profile
        if changed and not dry_run:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(profile)
            os.chown(dest, int(cell["uid"]), int(cell["gid"]))
        results.append({"slug": slug, "seccomp": "updated" if changed else "unchanged"})
    return results


def reconcile_ingress(data_root: Path, *, dry_run: bool = False) -> list[dict[str, Any]]:
    registry = alloc.load_registry(str(data_root))
    results: list[dict[str, Any]] = []
    for slug in (registry.get("allocations") or {}):
        socket = data_root / "cells" / slug / "docker.sock"
        if not socket.is_socket():
            results.append({"slug": slug, "ingress": "no-cell-daemon"})
            continue
        running = _docker(socket, ["inspect", "-f", "{{.State.Running}}", INGRESS])
        if running.returncode != 0 or running.stdout.strip() != "true":
            results.append({"slug": slug, "ingress": "not-running"})
            continue
        present = _docker(
            socket,
            [
                "exec", INGRESS, "sh", "-c",
                f"grep -q '{AIO_LINE}' /etc/nginx/nginx.conf",
            ],
        )
        if present.returncode == 0:
            results.append({"slug": slug, "ingress": "unchanged"})
            continue
        if dry_run:
            results.append({"slug": slug, "ingress": "would-disable-aio"})
            continue
        apply = _docker(
            socket,
            [
                "exec", INGRESS, "sh", "-c",
                (
                    "cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak && "
                    f"sed -i '/events {{/a\\    {AIO_LINE}' /etc/nginx/nginx.conf && "
                    "nginx -t && nginx -s reload"
                ),
            ],
        )
        state = "aio-disabled" if apply.returncode == 0 else "aio-fix-failed"
        results.append({"slug": slug, "ingress": state, "detail": apply.stderr.strip()[:200]})
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", default="/var/lib/spanel")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    data_root = Path(args.data_root)
    payload = {
        "ok": True,
        "dry_run": args.dry_run,
        "seccomp": reconcile_seccomp(data_root, dry_run=args.dry_run),
        "ingress": reconcile_ingress(data_root, dry_run=args.dry_run),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for item in payload["seccomp"]:
            print(f"seccomp {item['slug']}: {item['seccomp']}")
        for item in payload["ingress"]:
            detail = f" ({item['detail']})" if item.get("detail") else ""
            print(f"ingress {item['slug']}: {item['ingress']}{detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
