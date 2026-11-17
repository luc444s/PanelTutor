"""Local subprocess adapter for the transactional hardener."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..symlinks import symlink_target
from .contracts import HardenedCandidate, HardeningPolicy, HardeningRejected

MAX_STDOUT = 8 * 1024 * 1024
_SAFE_HARDENER_ERRORS = frozenset(
    {
        "skipped because static checks are blocking",
        "required executable is unavailable",
        "image build failed",
        "image was not produced",
        "image build could not execute",
        "external image pull or inspection failed",
        "external image validation could not execute",
        "build, image, or runtime validation failed",
    }
)


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if ".git" in relative.parts or ".spanel-build-backups" in relative.parts:
            continue
        digest.update(relative.as_posix().encode())
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"L" + symlink_target(path).encode())
        elif path.is_file():
            digest.update(b"F")
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
        elif path.is_dir():
            digest.update(b"D")
    return digest.hexdigest()


def _compose_name(checkout: Path, configured: str | None) -> str:
    if configured:
        return configured
    candidates = [
        name
        for name in ("compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml")
        if (checkout / name).is_file()
    ]
    if len(candidates) != 1:
        raise HardeningRejected("Hardener compose evidence is unavailable")
    return candidates[0]


class CommandHardeningEngine:
    def __init__(
        self,
        command: str | os.PathLike[str] | None = None,
        *,
        timeout: int = 3600,
        runner: Callable[..., Any] = subprocess.run,
        environ: dict[str, str] | None = None,
    ) -> None:
        value = str(
            command
            or os.environ.get("SPANEL_APPS_HARDENER_COMMAND", "dangerous-build-normalize")
        )
        if not value or any(character.isspace() for character in value) or "\x00" in value:
            raise ValueError("hardener command must name one executable")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
            raise ValueError("hardener timeout must be positive")
        self.command = value
        self.timeout = timeout
        self.runner = runner
        self.environ = environ

    def prepare(
        self,
        checkout: Path,
        compose_file: str | None,
        policy: HardeningPolicy,
        normalization: object | None = None,
    ) -> HardenedCandidate:
        checkout = Path(checkout).resolve()
        if not checkout.is_dir():
            raise HardeningRejected("Hardener checkout is unavailable")
        argv = [self.command, "harden", str(checkout), "--apply", "--format", "json"]
        if compose_file:
            argv.extend(("--compose-file", compose_file))
        for item in policy.service_users:
            argv.extend(("--service-user", f"{item.service}={item.uid}:{item.gid}"))
        for item in policy.writable_paths:
            argv.extend(("--writable-path", f"{item.service}={item.path}:{item.mode}"))
        child_env = dict(self.environ if self.environ is not None else os.environ)
        for name in tuple(child_env):
            upper = name.upper()
            if upper == "SSH_AUTH_SOCK" or upper.startswith("GH_") or "GITHUB" in upper:
                child_env.pop(name, None)
        source_hash = _tree_digest(checkout)
        try:
            completed = self.runner(
                argv,
                cwd=checkout,
                env=child_env,
                capture_output=True,
                text=False,
                timeout=self.timeout,
                shell=False,
            )
        except FileNotFoundError:
            raise HardeningRejected("Hardener executable is unavailable") from None
        except subprocess.TimeoutExpired:
            raise HardeningRejected("Hardener timed out") from None
        except OSError:
            raise HardeningRejected("Hardener could not be executed") from None
        stdout = completed.stdout
        if isinstance(stdout, str):
            stdout = stdout.encode()
        if not isinstance(stdout, bytes) or len(stdout) > MAX_STDOUT:
            raise HardeningRejected("Hardener response exceeded the size limit")
        if completed.returncode != 0:
            detail = ""
            if stdout:
                try:
                    payload = json.loads(stdout)
                except (UnicodeError, json.JSONDecodeError):
                    payload = None
                if isinstance(payload, dict):
                    gate = payload.get("gate")
                    gate = gate if isinstance(gate, dict) else {}
                    buildkit = gate.get("buildkit")
                    buildkit = buildkit if isinstance(buildkit, dict) else {}
                    candidates = [buildkit.get("error")]
                    services = buildkit.get("services")
                    for service in services if isinstance(services, list) else []:
                        scan = service.get("image_scan") if isinstance(service, dict) else None
                        if isinstance(scan, dict):
                            candidates.append(scan.get("error"))
                    candidates.append(payload.get("error"))
                    for value in candidates:
                        if isinstance(value, str) and value in _SAFE_HARDENER_ERRORS:
                            detail = value
                            break
            message = "Hardener rejected the application"
            if detail:
                message = f"{message}: {detail}"
            raise HardeningRejected(message)
        try:
            response = json.loads(stdout)
        except (UnicodeError, json.JSONDecodeError):
            raise HardeningRejected("Hardener returned invalid evidence") from None
        try:
            return HardenedCandidate.from_response(
                response,
                source_tree_sha256=source_hash,
                hardened_tree_sha256=_tree_digest(checkout),
                compose=_compose_name(checkout, compose_file),
                policy=policy,
                normalization=normalization,
            )
        except (TypeError, ValueError):
            raise HardeningRejected("Hardener returned incomplete evidence") from None
