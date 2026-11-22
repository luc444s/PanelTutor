#!/usr/bin/env python3
"""E2E cruzado cell-g / cell-h: aislamiento de socket, datos y credenciales.

Se ejecuta DENTRO del lab como root (necesita sudo para change-user). Verifica
que una operacion de un tenant nunca alcanza el socket, los volumenes ni las
credenciales del otro, incluyendo una construccion fallida y una secuencia de
rollback. La garantia a nivel de codigo (ReleaseExecution resuelve el runner
por tenant_id) se cubre ademas con tests unitarios en el plugin Apps.

Uso (en el lab):
  echo <password> | sudo -S python3 scripts/e2e_cross_cell_isolation.py \
    --evidence /tmp/e2e-cross-cell.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CELLS = {"cell-g": 60008, "cell-h": 60009}
DATA_ROOT = "/var/lib/spanel"
REGISTRY = f"{DATA_ROOT}/registry.json"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Lab:
    def run(self, argv: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            argv, text=True, capture_output=True, check=False, timeout=timeout
        )

    def as_cell(self, slug: str, argv: list[str]) -> subprocess.CompletedProcess[str]:
        uid = CELLS[slug]
        return self.run([
            "sudo", "-u", f"spanel-{slug}",
            "env", f"XDG_RUNTIME_DIR=/run/user/{uid}",
            f"DOCKER_HOST=unix://{DATA_ROOT}/cells/{slug}/docker.sock",
            *argv,
        ])

    def docker(self, slug: str, *argv: str) -> subprocess.CompletedProcess[str]:
        return self.as_cell(slug, ["docker", *argv])


def step(evidence: dict[str, Any], name: str, fn: Any) -> None:
    started = now()
    try:
        evidence["steps"][name] = {"ok": True, "at": started, "detail": fn()}
    except Exception as exc:
        evidence["steps"][name] = {
            "ok": False, "at": started,
            "error": f"{type(exc).__name__}: {exc}"[:600],
        }
        raise


def expect_denied(result: subprocess.CompletedProcess[str], what: str) -> str:
    assert result.returncode, f"{what} was unexpectedly allowed"
    return (result.stderr or result.stdout).strip().splitlines()[-1][:300]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    lab = Lab()
    evidence: dict[str, Any] = {
        "started_at": now(), "cells": sorted(CELLS), "steps": {}, "ok": False,
    }
    canary_volume = "cross-canary-vol"
    canary_network = "cross-canary-net"
    old_container = "cross-rollback-old"
    new_container = "cross-rollback-new"
    build_dir = Path(tempfile.mkdtemp(prefix="cross-e2e-"))

    try:
        def do_preflight() -> dict[str, Any]:
            detail: dict[str, Any] = {}
            for slug in CELLS:
                result = lab.docker(slug, "info", "--format", "{{.Name}}")
                assert result.returncode == 0, f"{slug} socket unavailable"
                detail[slug] = result.stdout.strip()
            tables = lab.run(["nft", "list", "tables"]).stdout
            for slug in CELLS:
                assert f"spanel-cell-{slug}" in tables, f"missing nft table for {slug}"
            return {"own_sockets": detail, "nft_tables": sorted(CELLS)}

        def do_cross_socket() -> dict[str, Any]:
            detail: dict[str, Any] = {}
            for src, dst in (("cell-g", "cell-h"), ("cell-h", "cell-g")):
                socket = f"{DATA_ROOT}/cells/{dst}/docker.sock"
                result = lab.as_cell(
                    src,
                    ["docker", "-H", f"unix://{socket}", "info", "--format", "{{.Name}}"],
                )
                detail[f"{src}->{dst}"] = expect_denied(result, "cross-cell socket")
            return detail

        def do_cross_engine_id() -> dict[str, Any]:
            detail: dict[str, Any] = {}
            for src, dst in (("cell-g", "cell-h"), ("cell-h", "cell-g")):
                path = f"{DATA_ROOT}/cells/{dst}/engine-id"
                result = lab.as_cell(src, ["cat", path])
                detail[f"{src}->{dst}"] = expect_denied(result, "cross-cell engine-id")
            return detail

        def do_apparmor_cross_denied() -> dict[str, Any]:
            detail: dict[str, Any] = {}
            for slug in CELLS:
                # The registry is world-readable, so without the cell profile
                # the tenant user can read it; under the profile AppArmor must
                # deny it (no rule grants paths outside this cell's tree).
                plain = lab.as_cell(slug, ["cat", REGISTRY])
                confined = lab.as_cell(
                    slug, ["aa-exec", "-p", f"spanel-cell-{slug}", "--", "cat", REGISTRY]
                )
                assert plain.returncode == 0, "registry should be readable as cell user"
                detail[slug] = {
                    "plain_readable": True,
                    "confined_denied": bool(expect_denied(confined, "confined registry read")),
                }
            return detail

        def do_profile_rules() -> dict[str, Any]:
            detail: dict[str, Any] = {}
            for src, dst in (("cell-g", "cell-h"), ("cell-h", "cell-g")):
                profile = Path(f"/etc/apparmor.d/spanel-cell-{src}").read_text()
                assert f"/var/lib/spanel/cells/{dst}" not in profile
                # Both the current (audit deny) and legacy (deny) profile
                # variants must forbid the rootful socket and host secrets.
                assert "/var/run/docker.sock rw," in profile
                assert "/run/secrets/** r," in profile
                detail[src] = {"cross_cell_grants": 0, "hard_denials": 2}
            return detail

        def do_daemon_confinement() -> dict[str, Any]:
            """Record whether each cell's dockerd actually runs confined."""
            detail: dict[str, Any] = {}
            for slug in CELLS:
                pids = lab.run(["pgrep", "-u", f"spanel-{slug}", "dockerd"]).stdout.split()
                profiles = [
                    Path(f"/proc/{pid}/attr/current").read_text().strip()
                    for pid in pids
                ]
                detail[slug] = {
                    "dockerd_pids": pids,
                    "profiles": profiles,
                    "confined": all("(enforce)" in value for value in profiles) if profiles else False,
                }
            return detail

        def do_failure_isolation() -> dict[str, Any]:
            assert lab.docker("cell-h", "volume", "create", canary_volume).returncode == 0
            assert lab.docker(
                "cell-h", "network", "create", "--internal", canary_network
            ).returncode == 0
            (build_dir / "Dockerfile").write_text(
                "FROM alpine:3.20\nRUN false\n", encoding="utf-8"
            )
            build_dir.chmod(0o755)
            failed = lab.docker("cell-g", "build", "-t", "cross-fail:test", str(build_dir))
            expect_denied(failed, "failing build")
            h_volumes = lab.docker(
                "cell-h", "volume", "ls", "--format", "{{.Name}}"
            ).stdout
            h_networks = lab.docker(
                "cell-h", "network", "ls", "--format", "{{.Name}}"
            ).stdout
            g_volumes = lab.docker(
                "cell-g", "volume", "ls", "--format", "{{.Name}}"
            ).stdout
            g_networks = lab.docker(
                "cell-g", "network", "ls", "--format", "{{.Name}}"
            ).stdout
            assert canary_volume in h_volumes, "cell-h canary volume changed on g failure"
            assert canary_network in h_networks, "cell-h canary network changed on g failure"
            assert canary_volume not in g_volumes
            assert canary_network not in g_networks
            return {
                "failing_build_exit": failed.returncode,
                "cell_h_canary_intact": True,
                "cell_g_leaked_resources": False,
            }

        def do_rollback_isolation() -> dict[str, Any]:
            for name in (old_container, new_container):
                lab.docker("cell-g", "rm", "-f", name)
            assert lab.docker(
                "cell-g", "create", "--name", old_container, "alpine:3.20", "sleep", "300"
            ).returncode == 0
            assert lab.docker("cell-g", "start", old_container).returncode == 0
            assert lab.docker(
                "cell-g", "create", "--name", new_container, "alpine:3.20", "sleep", "300"
            ).returncode == 0
            # Simulated rollback: drop the new deployment, revive the old one.
            lab.docker("cell-g", "rm", "-f", new_container)
            assert lab.docker("cell-g", "start", old_container).returncode == 0
            h_containers = lab.docker(
                "cell-h", "ps", "-a", "--format", "{{.Names}}"
            ).stdout
            assert old_container not in h_containers and new_container not in h_containers
            g_containers = lab.docker(
                "cell-g", "ps", "-a", "--format", "{{.Names}}"
            ).stdout
            assert old_container in g_containers and new_container not in g_containers
            return {"old_running_in_g": True, "cross_cell_containers": 0}

        for name, fn in (
            ("preflight", do_preflight),
            ("cross_socket", do_cross_socket),
            ("cross_engine_id", do_cross_engine_id),
            ("apparmor_cross_denied", do_apparmor_cross_denied),
            ("profile_rules", do_profile_rules),
            ("daemon_confinement", do_daemon_confinement),
            ("failure_isolation", do_failure_isolation),
            ("rollback_isolation", do_rollback_isolation),
        ):
            step(evidence, name, fn)
        evidence["ok"] = True
    finally:
        cleanup: dict[str, Any] = {}
        for slug in CELLS:
            for argv in (
                ["docker", "rm", "-f", old_container],
                ["docker", "rm", "-f", new_container],
                ["docker", "volume", "rm", canary_volume],
                ["docker", "network", "rm", canary_network],
                ["docker", "rmi", "-f", "cross-fail:test"],
            ):
                lab.as_cell(slug, argv)
            cleanup[slug] = "cleaned"
        evidence["cleanup"] = cleanup
        shutil.rmtree(build_dir, ignore_errors=True)
        evidence["finished_at"] = now()
        Path(args.evidence).write_text(
            json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8"
        )
    return 0 if evidence["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
