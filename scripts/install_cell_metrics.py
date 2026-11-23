#!/usr/bin/env python3
"""Install the read-only cell metrics daemon on the Spanel host.

The daemon (``spanel-cell-metrics --serve``, A.SPEC 0112/0113) is what the
Resources tab reads for live RAM/CPU/PIDs. Without it the SSE endpoint fails
closed with ``tenant.metrics_unavailable`` and the UI only shows
``No connection``.

This installer is idempotent and server-agnostic:

* builds the Rust binary unless ``--no-build`` or ``--check`` is used;
* keeps a persistent root-only token in ``/etc/spanel/cell_metrics_token``
  (never rotated);
* renders the systemd unit with the real paths and the app container uid;
* enables and starts ``spanel-cell-metrics.service``;
* verifies the socket with ``PING`` and, optionally, one ``SNAPSHOT``;
* reports whether the app container already mounts the socket and token.

Usage (as root, from the repository):

    python3 scripts/install_cell_metrics.py --check
    python3 scripts/install_cell_metrics.py --dry-run
    python3 scripts/install_cell_metrics.py
    python3 scripts/install_cell_metrics.py --slug miltonarquez

Exit codes: 0 ok, 1 error, 2 usage.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
UNIT_TEMPLATE = REPO_ROOT / "apps" / "cell-metrics" / "spanel-cell-metrics.service"
BINARY_BUILD = (
    REPO_ROOT / "apps" / "cell-metrics" / "target" / "release" / "spanel-cell-metrics"
)
BINARY_TARGET = Path("/usr/local/bin/spanel-cell-metrics")
SOCKET_PATH = Path("/run/spanel/cell-metrics.sock")
TOKEN_PATH = Path("/etc/spanel/cell_metrics_token")
UNIT_PATH = Path("/etc/systemd/system/spanel-cell-metrics.service")
UNIT_NAME = "spanel-cell-metrics.service"
APP_CONTAINER_SOCKET = Path("/run/spanel")
APP_CONTAINER_TOKEN = Path("/run/secrets/cell_metrics_token")


class InstallError(RuntimeError):
    """A safe-to-print installer failure."""


def _run(
    command: list[str], *, dry_run: bool = False
) -> subprocess.CompletedProcess[str]:
    if dry_run:
        return subprocess.CompletedProcess(command, 0, "", "")
    try:
        return subprocess.run(command, check=True, capture_output=True, text=True)
    except OSError as exc:
        raise InstallError(f"cannot run {command[0]}: {exc}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip().splitlines()
        raise InstallError(
            f"{' '.join(command[:3])} failed" + (f": {detail[-1]}" if detail else "")
        ) from exc


def _run_optional(command: list[str]) -> str:
    """Return stdout for a read-only probe; never raise."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _journal_tail(lines: int = 20) -> str:
    output = _run_optional(
        ["journalctl", "-u", UNIT_NAME, "-n", str(lines), "--no-pager"]
    )
    return " | ".join(output.splitlines()[-lines:]) or "journal unavailable"


def _wait_for_socket(path: Path, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_socket():
            return True
        time.sleep(0.25)
    return path.is_socket()


def ensure_token(path: Path, *, dry_run: bool) -> str:
    """Create the shared token once; never overwrite an existing secret."""
    if path.is_file() and path.read_text(encoding="utf-8").strip():
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            if dry_run:
                return "would tighten"
            path.chmod(0o600)
            return "tightened"
        return "existing"
    if path.exists() and not path.is_file():
        raise InstallError(f"{path} exists and is not a regular file")
    if dry_run:
        return "would create"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(secrets.token_urlsafe(32) + "\n")
    path.chmod(0o600)
    return "created"


def render_unit(
    template: str,
    *,
    binary: Path = BINARY_TARGET,
    socket_path: Path = SOCKET_PATH,
    token_path: Path = TOKEN_PATH,
    allowed_uids: str = "0",
) -> str:
    """Replace the reference paths in the unit template."""
    for value in (str(binary), str(socket_path), str(token_path)):
        if not value.startswith("/") or "\n" in value:
            raise InstallError(f"unsafe absolute path in unit: {value!r}")
    if not re.fullmatch(r"[0-9,]+", allowed_uids):
        raise InstallError(f"invalid --allowed-uids: {allowed_uids!r}")
    rendered = template
    rendered = re.sub(
        r"^ExecStart=(?:[^\n]*\\\n)*[^\n]*$",
        f"ExecStart={binary} --serve \\\n"
        f"  --socket {socket_path} \\\n"
        f"  --token-file {token_path} \\\n"
        f"  --allowed-uids {allowed_uids}",
        rendered,
        count=1,
        flags=re.MULTILINE,
    )
    rendered = re.sub(
        r"^ReadOnlyPaths=.*cell_metrics_token$",
        f"ReadOnlyPaths={token_path}",
        rendered,
        count=1,
        flags=re.MULTILINE,
    )
    if str(socket_path) not in rendered or str(token_path) not in rendered:
        raise InstallError("unit template did not accept the configured paths")
    return rendered


def detect_app_uid(repo_root: Path) -> str:
    """The app image runs as root; keep the daemon compatible by default."""
    try:
        output = _run(
            [
                "docker",
                "compose",
                "-f",
                str(repo_root / "docker-compose.yml"),
                "exec",
                "-T",
                "app",
                "id",
                "-u",
            ]
        ).stdout.strip()
    except InstallError:
        return "0"
    return output if re.fullmatch(r"[0-9]+", output) else "0"


def app_container(repo_root: Path) -> str | None:
    try:
        output = _run(
            [
                "docker",
                "compose",
                "-f",
                str(repo_root / "docker-compose.yml"),
                "ps",
                "-q",
                "app",
            ]
        ).stdout
    except InstallError:
        return None
    ids = [line.strip() for line in output.splitlines() if line.strip()]
    return ids[0] if ids else None


def app_mounts(container: str) -> list[str]:
    try:
        output = _run(
            [
                "docker",
                "inspect",
                container,
                "--format",
                "{{json .Mounts}}",
            ]
        ).stdout
    except InstallError:
        return []
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return []
    return [
        str(item.get("Destination", "")) for item in payload if isinstance(item, dict)
    ]


def missing_mounts(container: str) -> list[str]:
    mounted = app_mounts(container)
    missing: list[str] = []
    if not any(
        path == str(APP_CONTAINER_SOCKET) or path.startswith(f"{APP_CONTAINER_SOCKET}/")
        for path in mounted
    ):
        missing.append(str(APP_CONTAINER_SOCKET))
    if str(APP_CONTAINER_TOKEN) not in mounted:
        missing.append(str(APP_CONTAINER_TOKEN))
    return missing


def ping(socket_path: Path, *, timeout: float = 5.0) -> dict[str, Any]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(str(socket_path))
        client.sendall(b"PING\n")
        raw = b""
        while not raw.endswith(b"\n") and len(raw) < 65536:
            chunk = client.recv(4096)
            if not chunk:
                break
            raw += chunk
    except OSError as exc:
        raise InstallError(f"daemon PING failed: {exc}") from exc
    finally:
        client.close()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError("daemon PING returned invalid JSON") from exc
    if payload.get("ok") is not True or payload.get("pong") is not True:
        raise InstallError("daemon PING was not acknowledged")
    return payload


def snapshot(
    socket_path: Path, token: str, slug: str, *, timeout: float = 10.0
) -> dict[str, Any]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(str(socket_path))
        client.sendall(f"SNAPSHOT {slug} {token}\n".encode())
        raw = b""
        while not raw.endswith(b"\n") and len(raw) < (1 << 20):
            chunk = client.recv(4096)
            if not chunk:
                break
            raw += chunk
    except OSError as exc:
        raise InstallError(f"daemon SNAPSHOT failed: {exc}") from exc
    finally:
        client.close()
    text = raw.decode("utf-8", errors="replace").strip()
    if text.startswith("ERROR"):
        raise InstallError(f"daemon rejected SNAPSHOT: {text}")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise InstallError("daemon SNAPSHOT returned invalid JSON") from exc


def _check(repo_root: Path, args: argparse.Namespace) -> int:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool | None, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    token = Path(args.token_file)
    unit_file = Path(args.unit_dir) / UNIT_NAME
    add(
        "binary",
        BINARY_TARGET.is_file() and os.access(BINARY_TARGET, os.X_OK),
        str(BINARY_TARGET),
    )
    add("token", token.is_file(), str(token))
    add("unit", unit_file.is_file(), str(unit_file))
    enabled = _run_optional(["systemctl", "is-enabled", UNIT_NAME])
    add(
        "unit_enabled", enabled in {"enabled", "static"}, enabled or "systemctl missing"
    )
    active = _run_optional(["systemctl", "is-active", UNIT_NAME])
    add("unit_active", active == "active", active or "unknown")
    add("socket", Path(args.socket).is_socket(), args.socket)
    if Path(args.socket).is_socket() and token.is_file():
        try:
            ping(Path(args.socket))
            add("ping", True, "PING acknowledged")
        except InstallError as exc:
            add("ping", False, str(exc))
    container = app_container(repo_root)
    if container:
        missing = missing_mounts(container)
        add(
            "app_mounts",
            not missing,
            "missing: " + ", ".join(missing) if missing else "ok",
        )
    else:
        add("app_mounts", None, "app container not running")
    if args.json:
        print(json.dumps({"checks": checks}, indent=2, sort_keys=True))
    else:
        for item in checks:
            flag = "ok" if item["ok"] else ("WARN" if item["ok"] is None else "FAIL")
            print(f"[{flag}] {item['check']}: {item['detail']}")
    return 0 if all(item["ok"] is not False for item in checks) else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=REPO_ROOT)
    parser.add_argument("--socket", default=str(SOCKET_PATH))
    parser.add_argument("--token-file", default=str(TOKEN_PATH))
    parser.add_argument("--unit-dir", type=Path, default=UNIT_PATH.parent)
    parser.add_argument(
        "--allowed-uids",
        default="",
        help="comma-separated peer uids (default: the app container uid)",
    )
    parser.add_argument(
        "--slug", default="", help="optional tenant slug for one SNAPSHOT smoke test"
    )
    parser.add_argument(
        "--no-build", action="store_true", help="install the existing binary"
    )
    parser.add_argument("--dry-run", action="store_true", help="print actions only")
    parser.add_argument("--check", action="store_true", help="read-only verification")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo = args.repo.resolve()
    if args.check:
        return _check(repo, args)
    try:
        if os.geteuid() != 0 and not args.dry_run:
            raise InstallError("run as root (or use --dry-run)")
        if not args.no_build and not args.dry_run:
            _run(
                [
                    "cargo",
                    "build",
                    "--release",
                    "--manifest-path",
                    str(repo / "apps" / "cell-metrics" / "Cargo.toml"),
                ]
            )
        source = BINARY_BUILD
        if args.no_build and not source.is_file():
            raise InstallError(f"binary not found: {source}")
        token_path = Path(args.token_file)
        socket_path = Path(args.socket)
        allowed = args.allowed_uids or detect_app_uid(repo)
        template = UNIT_TEMPLATE.read_text(encoding="utf-8")
        unit = render_unit(
            template,
            binary=BINARY_TARGET,
            socket_path=socket_path,
            token_path=token_path,
            allowed_uids=allowed,
        )
        token_action = ensure_token(token_path, dry_run=args.dry_run)
        _run(
            ["install", "-D", "-m", "0750", str(source), str(BINARY_TARGET)],
            dry_run=args.dry_run,
        )
        unit_path = Path(args.unit_dir) / UNIT_NAME
        if args.dry_run:
            if not args.json:
                print(f"would write {unit_path}")
        else:
            unit_path.write_text(unit, encoding="utf-8")
            unit_path.chmod(0o644)
        if not args.dry_run:
            socket_path.parent.mkdir(parents=True, exist_ok=True)
        _run(["systemctl", "daemon-reload"], dry_run=args.dry_run)
        try:
            _run(["systemctl", "enable", "--now", UNIT_NAME], dry_run=args.dry_run)
        except InstallError as exc:
            raise InstallError(f"{exc}; journal: {_journal_tail()}") from exc
        if not args.dry_run and not _wait_for_socket(socket_path):
            raise InstallError(
                f"daemon did not create {socket_path}; journal: {_journal_tail()}"
            )
        result: dict[str, Any] = {
            "binary": str(BINARY_TARGET),
            "token": str(token_path),
            "token_action": token_action,
            "unit": str(unit_path),
            "socket": str(socket_path),
            "allowed_uids": allowed,
        }
        if not args.dry_run:
            result["ping"] = ping(socket_path)
            if args.slug:
                token = token_path.read_text(encoding="utf-8").strip()
                result["snapshot"] = snapshot(socket_path, token, args.slug)
            container = app_container(repo)
            missing = missing_mounts(container) if container else []
            result["app_mounts_missing"] = missing
            if missing:
                result["next"] = (
                    "add the missing bind mounts to docker-compose.yml, ensure the "
                    "token file exists, then recreate the app container"
                )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            for key, value in result.items():
                print(f"{key}: {value}")
        return 0
    except InstallError as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
