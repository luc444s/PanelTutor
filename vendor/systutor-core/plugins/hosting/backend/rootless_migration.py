from __future__ import annotations

import fcntl
import hashlib
import json
import re
import time
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session

from systutor.contracts.resource_runtime import write_resource_runtime
from systutor.contracts.site_domain_publisher import get_site_domain_publisher
from systutor.core.errors import AppError

from .config import env_of
from .models import HostingSite, RootlessMigrationOperation, StaticProfile
from .provisioner import Provisioner, SiteNames
from .rootless_ingress import (
    RootlessIngress,
    RootlessRoutePublisher,
    RouteSpec,
    verify_external_route,
)
from .runtime import HostingRuntimeResolver
from .settings import HostingSettings, get_hosting_settings
from .static import StaticNames, StaticProvisioner

FINAL_STATES = {"failed", "rolled_back", "finalized"}


def _redact(error: Exception) -> str:
    text = str(error)
    text = re.sub(r"(?i)(password|passwd|pwd)=([^\s;]+)", r"\1=<hidden>", text)
    return text[:500]


class RootlessMigrationService:
    def __init__(self, app: FastAPI, db: Session, settings: HostingSettings | None = None) -> None:
        self.app = app
        self.db = db
        self.settings = settings or get_hosting_settings()
        self.resolver = HostingRuntimeResolver(app, db)
        self.state_root = Path(self.settings.backups_dir) / "rootless-migrations"

    def _site(self, site_id: str) -> HostingSite:
        site = self.db.get(HostingSite, site_id)
        if site is None:
            raise AppError("Site not found", status_code=404, code="hosting_site_not_found")
        return site

    def _operation(self, operation_id: str, site_id: str) -> RootlessMigrationOperation:
        row = self.db.get(RootlessMigrationOperation, operation_id)
        if row is None or row.site_id != site_id:
            raise AppError(
                "Migration operation not found",
                status_code=404,
                code="hosting_rootless_operation_not_found",
            )
        return row

    @contextmanager
    def _lock(self, site_id: str) -> Iterator[None]:
        directory = self.state_root / "locks"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / f"{hashlib.sha256(site_id.encode()).hexdigest()}.lock"
        with path.open("a+b") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise AppError(
                    "Another site operation is in progress",
                    status_code=409,
                    code="hosting_rootless_busy",
                ) from exc
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def _result(self, site: HostingSite, row: RootlessMigrationOperation) -> dict[str, Any]:
        return {
            "ok": row.state not in {"failed"},
            "operation_id": row.id,
            "site_id": site.id,
            "kind": site.kind,
            "from_runtime": row.from_runtime,
            "to_runtime": row.to_runtime,
            "state": row.state,
            "steps": json.loads(row.steps_json or "[]"),
            "rollback_available": row.state in {"cutover", "verified", "retained"},
            **({"error": row.error} if row.error else {}),
        }

    def plan(self, site_id: str) -> dict[str, Any]:
        site = self._site(site_id)
        assigned = self.resolver.assigned(site.tenant_id, site.kind, site.id)
        source = assigned or "rootful"
        candidate = self.resolver.candidate(site.tenant_id)
        if candidate.runtime != "rootless":
            raise AppError(
                "Rootless migrations are disabled",
                status_code=409,
                code="hosting_rootless_disabled",
            )
        info = self.resolver.resolve(site.tenant_id, site.kind, site.id).inspect(
            "container", site.container_name
        )
        if info is None:
            raise AppError(
                "Source site is unavailable", status_code=409, code="hosting_site_unavailable"
            )
        mounts = [
            mount.get("Name")
            for mount in info.get("Mounts", [])
            if mount.get("Type") == "volume" and mount.get("Name")
        ]
        return {
            "ok": source == "rootful",
            "operation_id": None,
            "site_id": site.id,
            "kind": site.kind,
            "from_runtime": source,
            "to_runtime": "rootless",
            "state": "planned",
            "steps": ["inventory", "backup", "shadow_copy", "verify", "cutover", "retain"],
            "rollback_available": False,
            "mutation": False,
            "inventory": {
                "container": site.container_name,
                "volumes": mounts,
                "domain": site.domain,
            },
        }

    def _step(self, row: RootlessMigrationOperation, state: str, step: str) -> None:
        steps = json.loads(row.steps_json or "[]")
        if step not in steps:
            steps.append(step)
        row.steps_json = json.dumps(steps)
        row.state = state
        self.db.add(row)
        self.db.flush()

    def _backup_stream(self, site: HostingSite, source, volumes: list[str]) -> tuple[str, str]:
        directory = self.state_root / site.id
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / f"{int(time.time())}.zip"
        manifest: dict[str, Any] = {"site_id": site.id, "kind": site.kind, "volumes": {}}
        temporary: list[Path] = []
        try:
            for index, volume in enumerate(volumes):
                tar_path = directory / f".{path.stem}-{index}.tar"
                temporary.append(tar_path)
                digest = hashlib.sha256()
                with tar_path.open("xb") as output:
                    for chunk in source.export_volume(volume):
                        output.write(chunk)
                        digest.update(chunk)
                manifest["volumes"][volume] = {
                    "entry": f"volumes/{index}.tar",
                    "sha256": digest.hexdigest(),
                }
            with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True))
                for index, tar_path in enumerate(temporary):
                    archive.write(tar_path, f"volumes/{index}.tar")
            with zipfile.ZipFile(path, "r") as archive:
                if archive.testzip() is not None:
                    raise RuntimeError("recovery backup verification failed")
        finally:
            for tar_path in temporary:
                tar_path.unlink(missing_ok=True)
        path.chmod(0o600)
        return str(path), hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def _database_name(site: HostingSite, source) -> str | None:
        if site.kind != "wordpress":
            return None
        info = source.inspect("container", site.container_name) or {}
        return env_of(info).get("WORDPRESS_DB_HOST", "").split(":", 1)[0] or None

    def _stop_source(self, site: HostingSite, source) -> None:
        source.command(("stop", site.container_name))
        database = self._database_name(site, source)
        if database:
            source.command(("stop", database))

    def _start_source(self, site: HostingSite, source) -> None:
        database = self._database_name(site, source)
        if database:
            source.command(("start", database))
        source.command(("start", site.container_name))

    @staticmethod
    def _volume(info: dict, destination: str) -> str:
        matches = [
            str(mount.get("Name"))
            for mount in info.get("Mounts", [])
            if mount.get("Type") == "volume" and mount.get("Destination") == destination
        ]
        if len(matches) != 1:
            raise RuntimeError(f"ambiguous managed volume for {destination}")
        return matches[0]

    def _create_volume(self, target, name: str, site: HostingSite) -> None:
        slug = site.container_name.removeprefix("spanel-")
        slug = slug.removesuffix("-web").removesuffix("-wp")
        target.command(
            (
                "volume",
                "create",
                "--label",
                "spanel.managed=true",
                "--label",
                f"spanel.tenant={site.tenant_id}",
                "--label",
                f"spanel.site={slug}",
                name,
            )
        )

    def _copy_volume(self, source, target, name: str, site: HostingSite) -> None:
        if target.inspect("volume", name) is None:
            self._create_volume(target, name, site)
        target.import_volume(name, source.export_volume(name))

    def _wait_container(self, target, name: str) -> None:
        deadline = time.monotonic() + self.settings.install_timeout
        while time.monotonic() < deadline:
            info = target.inspect("container", name)
            state = (info or {}).get("State") or {}
            if state.get("Running") is True or state.get("Status") == "running":
                return
            time.sleep(1)
        raise RuntimeError(f"candidate {name} did not become ready")

    def _static(self, site: HostingSite, source, target) -> tuple[str, int]:
        info = source.inspect("container", site.container_name)
        if info is None:
            raise RuntimeError("source static container missing")
        labels = (info.get("Config") or {}).get("Labels") or {}
        if labels.get("spanel.tenant") != site.tenant_id:
            raise RuntimeError("source static ownership mismatch")
        profile = self.db.get(StaticProfile, site.profile_id or "nginx")
        names = StaticNames.for_profile(
            site.container_name.removeprefix("spanel-").removesuffix("-web"),
            None
            if profile is None
            else __import__(
                "plugins.hosting.backend.profiles", fromlist=["spec_from_row"]
            ).spec_from_row(profile),
        )
        volume = self._volume(info, names.web_root)
        self._copy_volume(source, target, volume, site)
        source.command(("stop", site.container_name))
        self._copy_volume(source, target, volume, site)
        args = (
            "run",
            "-d",
            "--name",
            site.container_name,
            "--network",
            "spanel-hosting",
            "--restart",
            "unless-stopped",
            "--label",
            "spanel.managed=true",
            "--label",
            f"spanel.tenant={site.tenant_id}",
            "--label",
            f"spanel.site={names.slug}",
            "--label",
            "spanel.kind=static",
            "--label",
            f"spanel.profile={names.profile}",
            "-v",
            f"{volume}:{names.web_root}",
            names.image,
        ) + (("sh", "-c", names.command) if names.command else ())
        target.command(args)
        self._wait_container(target, site.container_name)
        target.command(
            (
                "exec",
                site.container_name,
                "wget",
                "-q",
                "-O",
                "-",
                f"http://127.0.0.1:{names.container_port}/",
            )
        )
        return site.container_name, names.container_port

    def _wordpress(self, site: HostingSite, source, target) -> tuple[str, int]:
        wp = source.inspect("container", site.container_name)
        if wp is None:
            raise RuntimeError("source WordPress container missing")
        wp_env = env_of(wp)
        db_name = wp_env.get("WORDPRESS_DB_HOST", "").split(":", 1)[0]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]+", db_name):
            raise RuntimeError("external or ambiguous WordPress database")
        database = source.inspect("container", db_name)
        if database is None:
            raise RuntimeError("managed WordPress database missing")
        labels = (database.get("Config") or {}).get("Labels") or {}
        if labels.get("spanel.tenant") != site.tenant_id:
            raise RuntimeError("WordPress database ownership mismatch")
        wp_volume = self._volume(wp, "/var/www/html")
        db_volume = self._volume(database, "/var/lib/mysql")
        self._copy_volume(source, target, wp_volume, site)
        source.command(("stop", site.container_name))
        self._copy_volume(source, target, wp_volume, site)
        self._copy_volume(source, target, db_volume, site)
        slug = site.container_name.removeprefix("spanel-").removesuffix("-wp")
        private = SiteNames(slug).private_network
        if target.inspect("network", private) is None:
            target.command(
                (
                    "network",
                    "create",
                    "--internal",
                    "--label",
                    "spanel.managed=true",
                    "--label",
                    f"spanel.tenant={site.tenant_id}",
                    "--label",
                    f"spanel.site={slug}",
                    private,
                )
            )
        db_file = target.write_private(
            f"{site.container_name}/db.env",
            ("\n".join((database.get("Config") or {}).get("Env") or []) + "\n").encode(),
        )
        wp_file = target.write_private(
            f"{site.container_name}/wp.env",
            ("\n".join((wp.get("Config") or {}).get("Env") or []) + "\n").encode(),
        )
        target.command(
            (
                "run",
                "-d",
                "--name",
                db_name,
                "--network",
                private,
                "--label",
                "spanel.managed=true",
                "--label",
                f"spanel.tenant={site.tenant_id}",
                "--label",
                f"spanel.site={site.container_name.removeprefix('spanel-').removesuffix('-wp')}",
                "--env-file",
                db_file,
                "-v",
                f"{db_volume}:/var/lib/mysql",
                str((database.get("Config") or {}).get("Image") or self.settings.db_image),
            )
        )
        self._wait_container(target, db_name)
        target.command(
            (
                "run",
                "-d",
                "--name",
                site.container_name,
                "--network",
                private,
                "--label",
                "spanel.managed=true",
                "--label",
                f"spanel.tenant={site.tenant_id}",
                "--label",
                f"spanel.site={site.container_name.removeprefix('spanel-').removesuffix('-wp')}",
                "--env-file",
                wp_file,
                "-v",
                f"{wp_volume}:/var/www/html",
                str((wp.get("Config") or {}).get("Image") or self.settings.wp_image),
            )
        )
        target.command(("network", "connect", "spanel-hosting", site.container_name))
        self._wait_container(target, site.container_name)
        candidate = Provisioner(self.settings, target)
        candidate._wait(
            lambda: candidate.command(
                "run",
                "--rm",
                "--network",
                private,
                "--volumes-from",
                site.container_name,
                "--env-file",
                wp_file,
                "wordpress:cli",
                "wp",
                "core",
                "is-installed",
            ),
            "migrated WordPress database",
        )
        return site.container_name, 80

    def migrate(self, site_id: str, *, dry_run: bool = False) -> dict[str, Any]:
        if dry_run:
            return self.plan(site_id)
        site = self._site(site_id)
        self.plan(site_id)
        with self._lock(site.id):
            active = self.db.scalar(
                select(RootlessMigrationOperation).where(
                    RootlessMigrationOperation.site_id == site.id,
                    RootlessMigrationOperation.state.not_in(FINAL_STATES),
                )
            )
            if active is not None:
                return self._result(site, active)
            row = RootlessMigrationOperation(
                site_id=site.id,
                tenant_id=site.tenant_id,
                kind=site.kind,
                from_runtime="rootful",
                to_runtime="rootless",
                state="planned",
                steps_json="[]",
            )
            self.db.add(row)
            self.db.flush()
            source = self.resolver.resolve(site.tenant_id, site.kind, site.id)
            target = self.resolver.candidate(site.tenant_id)
            cutover = False
            try:
                info = source.inspect("container", site.container_name) or {}
                volumes = [
                    str(m["Name"])
                    for m in info.get("Mounts", [])
                    if m.get("Type") == "volume" and m.get("Name")
                ]
                self._step(row, "copying", "inventory")
                self._stop_source(site, source)
                row.backup_path, row.backup_sha256 = self._backup_stream(site, source, volumes)
                self._step(row, "copying", "backup_verified")
                RootlessIngress(self.db, target)._network()
                target_name, port = (
                    self._static(site, source, target)
                    if site.kind == "static"
                    else self._wordpress(site, source, target)
                )
                self._step(row, "candidate_ready", "candidate_verified")
                route = RouteSpec(site.id, site.tenant_id, str(site.domain), target_name, port)
                RootlessIngress(self.db, target).upsert(route)
                rootful_publisher = get_site_domain_publisher(self.app)
                if rootful_publisher is not None and site.domain:
                    rootful_publisher.unpublish(site.domain)
                https = RootlessRoutePublisher(self.app, self.db).publish(
                    site.tenant_id, str(site.domain)
                )
                cutover = True
                self._step(row, "cutover", "route_cutover")
                verify_external_route(str(site.domain), https=https)
                write_resource_runtime(
                    self.app, self.db, site.tenant_id, site.kind, site.id, "rootless"
                )
                self._step(row, "verified", "external_http_verified")
                self._step(row, "retained", "rootful_retained")
                self.db.commit()
                return self._result(site, row)
            except Exception as exc:
                self.db.rollback()
                row = self.db.get(RootlessMigrationOperation, row.id) or row
                row.error = _redact(exc)
                row.state = "failed"
                self.db.add(row)
                self.db.flush()
                try:
                    if cutover and site.domain:
                        RootlessRoutePublisher(self.app, self.db).unpublish(site.domain)
                    RootlessIngress(self.db, target).remove(site.id, site.tenant_id)
                    self._start_source(site, source)
                    publisher = get_site_domain_publisher(self.app)
                    if publisher is not None and site.domain:
                        publisher.publish(site.container_name, site.domain)
                    write_resource_runtime(
                        self.app, self.db, site.tenant_id, site.kind, site.id, "rootful"
                    )
                except Exception as rollback_error:
                    row.error += f"; rollback: {_redact(rollback_error)}"
                failures = self._cleanup_runtime(site, target)
                if failures:
                    row.error += "; candidate cleanup: " + "; ".join(failures)
                self.db.commit()
                return self._result(site, row)

    def status(self, site_id: str) -> dict[str, Any]:
        site = self._site(site_id)
        row = self.db.scalar(
            select(RootlessMigrationOperation)
            .where(RootlessMigrationOperation.site_id == site.id)
            .order_by(RootlessMigrationOperation.created_at.desc())
        )
        return self.plan(site_id) if row is None else self._result(site, row)

    def rollback(self, site_id: str, operation_id: str) -> dict[str, Any]:
        site = self._site(site_id)
        with self._lock(site.id):
            row = self._operation(operation_id, site.id)
            if row.state == "rolled_back":
                return self._result(site, row)
            if row.state not in {"cutover", "verified", "retained", "failed"}:
                raise AppError(
                    "Operation cannot be rolled back",
                    status_code=409,
                    code="hosting_rootless_bad_state",
                )
            target = self.resolver.candidate(site.tenant_id)
            if site.domain:
                RootlessRoutePublisher(self.app, self.db).unpublish(site.domain)
            RootlessIngress(self.db, target).remove(site.id, site.tenant_id)
            source = __import__(
                "plugins.hosting.backend.runtime", fromlist=["RootfulDockerHandle"]
            ).RootfulDockerHandle(self.settings)
            self._start_source(site, source)
            publisher = get_site_domain_publisher(self.app)
            if publisher is not None and site.domain:
                publisher.publish(site.container_name, site.domain)
            write_resource_runtime(self.app, self.db, site.tenant_id, site.kind, site.id, "rootful")
            failures = self._cleanup_runtime(site, target)
            if failures:
                raise AppError(
                    "; ".join(failures),
                    status_code=409,
                    code="hosting_rootless_rollback_cleanup_failed",
                )
            self._step(row, "rolled_back", "rollback_rootful")
            self.db.commit()
            return self._result(site, row)

    def finalize(self, site_id: str, operation_id: str, confirm_domain: str) -> dict[str, Any]:
        site = self._site(site_id)
        with self._lock(site.id):
            row = self._operation(operation_id, site.id)
            if row.state == "finalized":
                return self._result(site, row)
            if row.state != "retained" or confirm_domain != site.domain:
                raise AppError(
                    "Finalize confirmation or state is invalid",
                    status_code=409,
                    code="hosting_rootless_bad_state",
                )
            if not row.backup_path or not row.backup_sha256:
                raise AppError(
                    "Verified recovery backup required",
                    status_code=409,
                    code="hosting_rootless_backup_required",
                )
            path = Path(row.backup_path)
            if (
                not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != row.backup_sha256
            ):
                raise AppError(
                    "Recovery backup verification failed",
                    status_code=409,
                    code="hosting_rootless_backup_required",
                )
            source = __import__(
                "plugins.hosting.backend.runtime", fromlist=["RootfulDockerHandle"]
            ).RootfulDockerHandle(self.settings)
            failures = self._cleanup_runtime(site, source)
            if failures:
                raise AppError(
                    "; ".join(failures), status_code=409, code="hosting_rootless_finalize_failed"
                )
            self._step(row, "finalized", "rootful_removed")
            self.db.commit()
            return self._result(site, row)

    def reconcile(self, site_id: str) -> dict[str, Any]:
        site = self._site(site_id)
        runtime = self.resolver.resolve(site.tenant_id, site.kind, site.id)
        if runtime.runtime != "rootless":
            return {**self.status(site_id), "reconciled": False}
        RootlessIngress(self.db, runtime).reconcile(site.tenant_id)
        if site.domain:
            RootlessRoutePublisher(self.app, self.db).publish(site.tenant_id, site.domain)
        return {**self.status(site_id), "reconciled": True}
    def _cleanup_runtime(self, site: HostingSite, runtime) -> list[str]:
        slug = site.container_name.removeprefix("spanel-").rsplit("-", 1)[0]
        cleaner = StaticProvisioner if site.kind == "static" else Provisioner
        names = StaticNames(slug) if site.kind == "static" else SiteNames(slug)
        return cleaner(self.settings, runtime).cleanup(names, site.tenant_id)
