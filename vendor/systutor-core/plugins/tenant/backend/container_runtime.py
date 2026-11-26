"""Rootless container-runtime provider backed by an existing tenant cell."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from plugins.hosting.backend.inspection import inspect_many_containers
from systutor.contracts.container_runtime import (
    ContainerRuntimeError,
    RuntimeHealth,
)
from systutor.contracts.tenant_slugs import InvalidCellSlug, cell_slug_for
from systutor.kernel.tenants.models import Tenant

REGISTRY_CACHE_TTL_SECONDS = 5.0
_registry_cache: dict[str, tuple[float, float, dict[str, Any]]] = {}


def _registry_payload(data_root: Path) -> dict[str, Any]:
    """Parsed `registry.json`, cached for a short window keyed by mtime.

    The registry is read for every tenant resolution; in a site list that is
    once per tenant instead of once per site, but the file does not change
    between requests. A five second window keeps the hot path on memory while
    a new allocation is visible almost immediately. Any read or parse failure
    drops the entry and fails closed, exactly like the uncached code.
    """
    path = data_root / "registry.json"
    key = str(data_root)
    try:
        modified = path.stat().st_mtime
    except OSError as exc:
        _registry_cache.pop(key, None)
        raise ContainerRuntimeError("tenant cell registry unavailable") from exc
    now = time.monotonic()
    cached = _registry_cache.get(key)
    if (
        cached is not None
        and now - cached[0] < REGISTRY_CACHE_TTL_SECONDS
        and cached[1] == modified
    ):
        return cached[2]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _registry_cache.pop(key, None)
        raise ContainerRuntimeError("tenant cell registry unavailable") from exc
    if not isinstance(payload, dict):
        _registry_cache.pop(key, None)
        raise ContainerRuntimeError("tenant cell registry unavailable")
    _registry_cache[key] = (now, modified, payload)
    return payload


class RootlessCellHandle:
    runtime = "rootless"

    def __init__(self, slug: str, uid: int, index: int, data_root: Path) -> None:
        self._slug = slug
        self._uid = uid
        self._publish_port = 20000 + (index % 20000)
        self._socket = data_root / "cells" / slug / "docker.sock"
        self._state = data_root / "cells" / slug / "hosting"

    def _env(self) -> dict[str, str]:
        return {**os.environ, "DOCKER_HOST": f"unix://{self._socket}"}

    def command(
        self,
        args: tuple[str, ...],
        *,
        input: bytes | None = None,
        timeout: float | None = None,
    ) -> bytes:
        try:
            result = subprocess.run(
                ["docker", *args],
                input=input,
                capture_output=True,
                env=self._env(),
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ContainerRuntimeError("cell docker command timed out") from exc
        if result.returncode:
            raise ContainerRuntimeError(
                (result.stderr or result.stdout)[:400].decode(errors="replace")
            )
        return result.stdout

    def inspect(self, kind: str, name: str) -> dict[str, Any] | None:
        try:
            payload = self.command((kind, "inspect", name))
        except ContainerRuntimeError as exc:
            message = str(exc).lower()
            if "no such" in message or "not found" in message:
                return None
            raise
        rows = json.loads(payload)
        return rows[0] if isinstance(rows, list) and rows else None

    def inspect_many(self, names: Sequence[str]) -> dict[str, dict[str, Any] | None]:
        """Bulk `docker inspect` against the cell socket, one call per batch."""

        def command(args: tuple[str, ...]) -> tuple[int, str]:
            try:
                result = subprocess.run(
                    ["docker", *args],
                    capture_output=True,
                    text=True,
                    env=self._env(),
                    check=False,
                    timeout=60,
                )
            except subprocess.TimeoutExpired:
                return 124, ""
            return result.returncode, result.stdout

        return inspect_many_containers(names, command=command)

    def export_volume(self, name: str) -> Iterator[bytes]:
        process = subprocess.Popen(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{name}:/data:ro",
                "busybox:1.36",
                "tar",
                "-C",
                "/data",
                "-cf",
                "-",
                ".",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._env(),
        )
        assert process.stdout is not None
        while chunk := process.stdout.read(1024 * 1024):
            yield chunk
        if process.wait() != 0:
            assert process.stderr is not None
            raise ContainerRuntimeError(process.stderr.read(400).decode(errors="replace"))

    def import_volume(self, name: str, chunks: Iterator[bytes]) -> None:
        process = subprocess.Popen(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "-v",
                f"{name}:/data",
                "busybox:1.36",
                "tar",
                "-C",
                "/data",
                "-xf",
                "-",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._env(),
        )
        assert process.stdin is not None
        try:
            for chunk in chunks:
                process.stdin.write(chunk)
        finally:
            process.stdin.close()
        if process.wait() != 0:
            assert process.stderr is not None
            raise ContainerRuntimeError(process.stderr.read(400).decode(errors="replace"))

    def _private_path(self, relative_path: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", relative_path):
            raise ContainerRuntimeError("invalid private state path")
        target = self._state / relative_path
        if self._state not in target.parents:
            raise ContainerRuntimeError("private state path escapes cell")
        return target

    def write_private(self, relative_path: str, content: bytes) -> str:
        target = self._private_path(relative_path)
        self._state.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = target.with_suffix(target.suffix + ".new")
        temporary.write_bytes(content)
        os.chmod(temporary, 0o600)
        try:
            os.chown(temporary, self._uid, self._uid)
            os.chown(self._state, self._uid, self._uid)
            os.chown(target.parent, self._uid, self._uid)
            os.chmod(self._state, 0o700)
            os.chmod(target.parent, 0o700)
        except PermissionError as exc:
            temporary.unlink(missing_ok=True)
            raise ContainerRuntimeError("cannot assign private state to cell uid") from exc
        os.replace(temporary, target)
        return str(target)

    def remove_private(self, relative_path: str) -> None:
        self._private_path(relative_path).unlink(missing_ok=True)

    def health(self) -> RuntimeHealth:
        state = "degraded"
        if self._socket.exists():
            try:
                self.command(("info", "--format", "{{.ID}}"))
                state = "ready"
            except ContainerRuntimeError:
                pass
        return RuntimeHealth("rootless", state, self._slug, self._uid, self._publish_port)


class RootlessCellProvider:
    def __init__(self, data_root: str | None = None) -> None:
        self.data_root = Path(data_root or os.getenv("SPANEL_TENANTS_DATA_ROOT", "/var/lib/spanel"))

    def __call__(self, db: Session, tenant_id: str) -> RootlessCellHandle:
        tenant = db.get(Tenant, tenant_id)
        if tenant is None:
            raise ContainerRuntimeError("tenant not found")
        try:
            cell_slug = cell_slug_for(tenant.slug)
        except InvalidCellSlug as exc:
            raise ContainerRuntimeError("tenant has no valid cell slug") from exc
        registry = _registry_payload(self.data_root)
        cell = (registry.get("allocations") or {}).get(cell_slug)
        if (
            not isinstance(cell, dict)
            or not isinstance(cell.get("uid"), int)
            or not isinstance(cell.get("index"), int)
        ):
            raise ContainerRuntimeError("tenant cell is not registered")
        return RootlessCellHandle(cell_slug, int(cell["uid"]), int(cell["index"]), self.data_root)
