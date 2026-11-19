#!/usr/bin/env python3
"""E2E real de runtime rootless por celda (Fase 2, A.SPEC 0096/0098).

Se ejecuta DENTRO del laboratorio, como el usuario dueño de la celda, y usa
EXCLUSIVAMENTE el socket rootless del tenant. No pasa por el hardener, el
pipeline de releases ni los probes: verifica build/pull, create, start,
healthcheck, logs, volúmenes, red y cleanup contra el socket aislado.

Uso (en el lab):
  sudo -u spanel-cell-g env XDG_RUNTIME_DIR=/run/user/60008 \
    python3 scripts/e2e_rootless_cell.py --slug cell-g --evidence /tmp/e2e-cell-g.json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DATA_ROOT = "/var/lib/spanel"
ROOTFUL_SOCKET = "/var/run/docker.sock"

# The build step only has to prove BuildKit can produce an image through the
# tenant socket.  A trivial Dockerfile avoids depending on writes outside the
# cell profile's allowed paths inside the container payload.
DOCKERFILE = 'FROM alpine:3.20\nCMD ["sh"]\n'

PROBE_IMAGE = (
    "curlimages/curl@sha256:"
    "d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b"
)

# The payload runs entirely under /tmp (explicitly writable in the cell
# profile), listens on a port for the network check and emits heartbeat lines
# for the logs check.  BusyBox httpd is not in Alpine's base busybox, so nc
# provides the listener instead.
APP_COMMAND = (
    "echo cell-e2e boot $(date -u +%FT%TZ) > /tmp/boot.txt; "
    "while true; do "
    "printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nOK' "
    "| nc -l -p 8080; done >/dev/null 2>&1 & "
    "i=0; while true; do i=$((i + 1)); echo heartbeat $i; sleep 2; done"
)
HEALTH_COMMAND = "test -s /tmp/boot.txt"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CellClient:
    def __init__(self, slug: str, data_root: str) -> None:
        self.slug = slug
        self.socket = f"{data_root}/cells/{slug}/docker.sock"
        self.env = dict(os.environ)
        self.env["DOCKER_HOST"] = f"unix://{self.socket}"
        self.env["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"

    def run(
        self, argv: list[str], *, check: bool = True, timeout: int = 120
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            argv,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )

    def ok(self, argv: list[str], **kwargs: Any) -> str:
        result = self.run(argv, **kwargs)
        if result.returncode:
            raise RuntimeError(
                f"{' '.join(argv[:3])} failed ({result.returncode}): "
                f"{(result.stderr or result.stdout).strip()[:400]}"
            )
        return result.stdout.strip()


def step(evidence: dict[str, Any], name: str, fn: Any) -> None:
    started = now()
    try:
        detail = fn()
        evidence["steps"][name] = {
            "ok": True, "at": started, "detail": detail,
        }
    except Exception as exc:
        evidence["steps"][name] = {
            "ok": False, "at": started,
            "error": f"{type(exc).__name__}: {exc}"[:600],
        }
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", default="cell-g")
    parser.add_argument("--data-root", default=DEFAULT_DATA_ROOT)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--keep-on-failure", action="store_true")
    args = parser.parse_args()

    client = CellClient(args.slug, args.data_root)
    suffix = f"{args.slug}-{int(time.time())}"
    image = f"cell-e2e:{suffix}"
    network = f"cell-e2e-net-{suffix}"
    volume = f"cell-e2e-vol-{suffix}"
    app = f"cell-e2e-app-{suffix}"
    helper = f"cell-e2e-helper-{suffix}"
    evidence: dict[str, Any] = {
        "slug": args.slug,
        "socket": client.socket,
        "uid": os.getuid(),
        "started_at": now(),
        "steps": {},
        "ok": False,
    }
    build_dir = Path(tempfile.mkdtemp(prefix="cell-e2e-"))
    created: dict[str, bool] = {"container": False, "helper": False,
                                "network": False, "volume": False, "image": False}

    try:
        def do_preflight() -> dict[str, Any]:
            assert client.env["DOCKER_HOST"] == f"unix://{client.socket}"
            info = client.ok(["docker", "info", "--format", "{{.SecurityOptions}}"])
            rootful = client.run(["docker", "-H", f"unix://{ROOTFUL_SOCKET}",
                                  "version", "--format", "{{.Server.Version}}"])
            assert rootful.returncode, "rootful socket must be unreachable from the cell"
            assert "rootless" in info.lower(), "dockerd is not rootless"
            daemon_id = client.ok(["docker", "info", "--format", "{{.ID}}"])
            return {
                "docker_host": client.env["DOCKER_HOST"],
                "daemon_id": daemon_id,
                "security_options": info,
                "rootful_access": "denied",
            }

        def do_pull() -> dict[str, Any]:
            out = client.ok(["docker", "pull", "alpine:3.20"])
            probe = client.ok(["docker", "pull", PROBE_IMAGE])
            return {
                "last_line": out.splitlines()[-1] if out else "",
                "probe_last_line": probe.splitlines()[-1] if probe else "",
            }

        def do_build() -> dict[str, Any]:
            (build_dir / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
            out = client.ok(
                ["docker", "build", "-t", image, str(build_dir)], timeout=300
            )
            created["image"] = True
            return {"tag": image, "tail": out.splitlines()[-3:]}

        def do_network() -> dict[str, Any]:
            out = client.ok(["docker", "network", "create", "--internal", network])
            created["network"] = True
            inspect = client.ok([
                "docker", "network", "inspect", "-f", "{{.Internal}}", network
            ])
            assert inspect == "true", "network must be internal"
            return {"network": network, "id": out, "internal": inspect}

        def do_volume() -> dict[str, Any]:
            out = client.ok(["docker", "volume", "create", volume])
            created["volume"] = True
            return {"volume": volume, "name": out}

        def do_create_start() -> dict[str, Any]:
            client.ok([
                "docker", "create", "--name", app, "--network", network,
                "-v", f"{volume}:/tmp",
                "--health-cmd", HEALTH_COMMAND,
                "--health-interval", "2s", "--health-timeout", "2s",
                "--health-retries", "15",
                "alpine:3.20", "sh", "-c", APP_COMMAND,
            ])
            created["container"] = True
            cid = client.ok(["docker", "start", app])
            return {"container": app, "id": cid[:12]}

        def do_healthcheck() -> dict[str, Any]:
            deadline = time.monotonic() + 90
            status = "starting"
            while time.monotonic() < deadline:
                status = client.ok([
                    "docker", "inspect", "-f", "{{.State.Health.Status}}", app
                ])
                if status == "healthy":
                    return {"status": status}
                if status == "unhealthy":
                    raise RuntimeError("container became unhealthy")
                time.sleep(2)
            raise RuntimeError(f"healthcheck never became healthy ({status})")

        def do_logs() -> dict[str, Any]:
            out = client.ok(["docker", "logs", "--tail", "5", app])
            assert "heartbeat" in out, "no heartbeat lines in logs"
            return {"tail": out.splitlines()[-5:]}

        def do_volume_data() -> dict[str, Any]:
            out = client.ok([
                "docker", "run", "--rm", "-v", f"{volume}:/tmp",
                "alpine:3.20", "cat", "/tmp/boot.txt",
            ])
            assert out.startswith("cell-e2e boot "), "volume marker missing"
            return {"boot_marker": out}

        def do_networked() -> dict[str, Any]:
            client.ok([
                "docker", "run", "--rm", "--network", network, "--name", helper,
                "alpine:3.20", "sh", "-c",
                f"nc -w 2 {app} 8080 </dev/null",
            ], timeout=60)
            created["helper"] = False  # --rm removes it
            return {"peer_connect": "ok", "via": f"{app}:8080"}

        def do_readiness_probe() -> dict[str, Any]:
            result = client.run([
                "docker", "run", "--rm", "--network", network,
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                "--pids-limit", "64", "--memory", "128m", "--cpus", "1",
                "--user", "65534:65534", PROBE_IMAGE,
                "curl", "-sS", "-o", "/dev/null", "--write-out", "%{http_code}",
                "--connect-timeout", "5", "--max-time", "10",
                f"http://{app}:8080/",
            ], timeout=30)
            if result.returncode:
                raise RuntimeError(
                    f"readiness probe failed ({result.returncode}): "
                    f"{(result.stderr or result.stdout).strip()[:400]}"
                )
            assert result.stdout == "200", f"unexpected HTTP status {result.stdout!r}"
            daemon_id = client.ok(["docker", "info", "--format", "{{.ID}}"])
            return {
                "http_status": result.stdout,
                "target": f"http://{app}:8080/",
                "network": network,
                "daemon_id": daemon_id,
                "docker_host": client.env["DOCKER_HOST"],
            }

        for name, fn in (
            ("preflight", do_preflight),
            ("pull", do_pull),
            ("build", do_build),
            ("network", do_network),
            ("volume", do_volume),
            ("create_start", do_create_start),
            ("healthcheck", do_healthcheck),
            ("logs", do_logs),
            ("volume_data", do_volume_data),
            ("networked", do_networked),
            ("readiness_probe", do_readiness_probe),
        ):
            step(evidence, name, fn)
        evidence["ok"] = True
    except Exception:
        if args.keep_on_failure:
            raise
    finally:
        cleanup: dict[str, Any] = {}
        for label, argv in (
            ("container", ["docker", "rm", "-f", app]),
            ("network", ["docker", "network", "rm", network]),
            ("volume", ["docker", "volume", "rm", volume]),
            ("image", ["docker", "rmi", "-f", image]),
        ):
            result = client.run(argv, check=False, timeout=60)
            cleanup[label] = {"removed": result.returncode == 0}
        evidence["cleanup"] = cleanup
        shutil.rmtree(build_dir, ignore_errors=True)
        evidence["finished_at"] = now()
        Path(args.evidence).write_text(
            json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8"
        )
    return 0 if evidence["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
