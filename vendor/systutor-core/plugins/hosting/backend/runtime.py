"""Hosting runtime resolution and the registered rootful Docker handle."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from sqlalchemy.orm import Session

from systutor.contracts.container_runtime import (
    ContainerRuntimeError,
    ContainerRuntimeHandle,
    RuntimeHealth,
    resolve_container_runtime,
)
from systutor.contracts.resource_runtime import read_resource_runtime
from systutor.core.errors import AppError

from .settings import HostingSettings, docker_env
from .transport import (
    borrar_archivo_remoto,
    build_docker_argv,
    escribir_archivo_remoto_en,
    run,
)


class RootfulDockerHandle:
    runtime = "rootful"

    def __init__(self, settings: HostingSettings) -> None:
        self.settings = settings
        self.env = docker_env(settings)

    def command(self, args: tuple[str, ...], *, input: bytes | None = None) -> bytes:
        text = "docker " + " ".join(shlex.quote(part) for part in args)
        result = run(
            build_docker_argv(text, env=self.env),
            env=self.env,
            timeout=max(self.settings.command_timeout, self.settings.install_timeout),
            input=input.decode() if input is not None else None,
        )
        if result.returncode:
            raise ContainerRuntimeError((result.stderr or result.stdout).strip()[:400])
        return result.stdout.encode()

    def inspect(self, kind: str, name: str) -> dict[str, Any] | None:
        try:
            rows = json.loads(self.command((kind, "inspect", name)))
        except ContainerRuntimeError as exc:
            message = str(exc).lower()
            if "no such" in message or "not found" in message:
                return None
            raise
        return rows[0] if isinstance(rows, list) and rows else None

    def export_volume(self, name: str) -> Iterator[bytes]:
        return self._export_mount(f"{name}:/data:ro")

    def export_path(self, path: str) -> Iterator[bytes]:
        """Stream a host bind-mount path through the rootful daemon."""
        return self._export_mount(f"{path}:/data:ro")

    def _export_mount(self, mount: str) -> Iterator[bytes]:
        command = (
            "docker run --rm -v "
            + shlex.quote(mount)
            + " busybox:1.36 tar -C /data -cf - ."
        )
        child_env = dict(os.environ)
        child_env["SSHPASS"] = self.env.get("MAIL_SERVER_PASSWORD", "")
        process = subprocess.Popen(
            build_docker_argv(command, env=self.env),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_env,
        )
        assert process.stdout is not None
        while chunk := process.stdout.read(1024 * 1024):
            yield chunk
        if process.wait() != 0:
            assert process.stderr is not None
            raise ContainerRuntimeError(process.stderr.read(400).decode(errors="replace"))

    def import_volume(self, name: str, chunks: Iterator[bytes]) -> None:
        command = (
            "docker run --rm -i -v "
            + shlex.quote(f"{name}:/data")
            + " busybox:1.36 tar -C /data -xf -"
        )
        child_env = dict(os.environ)
        child_env["SSHPASS"] = self.env.get("MAIL_SERVER_PASSWORD", "")
        process = subprocess.Popen(
            build_docker_argv(command, env=self.env),
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_env,
        )
        assert process.stdin is not None
        for chunk in chunks:
            process.stdin.write(chunk)
        process.stdin.close()
        if process.wait() != 0:
            assert process.stderr is not None
            raise ContainerRuntimeError(process.stderr.read(400).decode(errors="replace"))

    def _private_path(self, relative_path: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", relative_path):
            raise ContainerRuntimeError("invalid private state path")
        return Path(self.settings.sites_dir) / relative_path

    def write_private(self, relative_path: str, content: bytes) -> str:
        path = self._private_path(relative_path)
        escribir_archivo_remoto_en(self.env, str(path), content.decode())
        return str(path)

    def remove_private(self, relative_path: str) -> None:
        borrar_archivo_remoto(self.env, str(self._private_path(relative_path)))

    def health(self) -> RuntimeHealth:
        try:
            self.command(("info", "--format", "{{.ID}}"))
            state = "ready"
        except ContainerRuntimeError:
            state = "degraded"
        return RuntimeHealth("rootful", state)


class HostingRuntimeResolver:
    def __init__(self, app: FastAPI, db: Session) -> None:
        self.app = app
        self.db = db

    def assigned(self, tenant_id: str, kind: str, site_id: str) -> str | None:
        return read_resource_runtime(self.app, self.db, tenant_id, kind, site_id)

    def resolve(self, tenant_id: str, kind: str, site_id: str) -> ContainerRuntimeHandle:
        assigned = self.assigned(tenant_id, kind, site_id)
        runtime = assigned or "rootful"  # unregistered rows are pre-0110 legacy sites
        try:
            handle = resolve_container_runtime(self.app, self.db, tenant_id, runtime)
        except (ContainerRuntimeError, RuntimeError) as exc:
            raise AppError(
                "The site's registered container runtime is unavailable",
                status_code=503,
                code="hosting_runtime_unavailable",
            ) from exc
        if handle.health().state != "ready":
            raise AppError(
                "The site's registered container runtime is not ready",
                status_code=503,
                code="hosting_runtime_unavailable",
            )
        return handle

    def candidate(self, tenant_id: str) -> ContainerRuntimeHandle:
        if os.getenv("SPANEL_TENANTS_ROOTLESS", "false").strip().lower() != "true":
            return resolve_container_runtime(self.app, self.db, tenant_id, "rootful")
        try:
            handle = resolve_container_runtime(self.app, self.db, tenant_id, "rootless")
        except ContainerRuntimeError as exc:
            raise AppError(
                "The tenant cell is unavailable",
                status_code=503,
                code="hosting_rootless_cell_unavailable",
            ) from exc
        if handle.health().state != "ready":
            raise AppError(
                "The tenant cell is not ready",
                status_code=503,
                code="hosting_rootless_cell_unavailable",
            )
        return handle
