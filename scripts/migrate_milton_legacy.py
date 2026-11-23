#!/usr/bin/env python3
"""Migrate the legacy ``milton`` Hosting stack into its rootless cell.

The tenant predates the SPanel labels/volumes contract:

* WordPress uses bind mounts from ``/opt/stacks/wordpress/<site>/html``;
* the database host lives in ``wp-config.php`` (``mariadb:3306``), not in the
  container environment;
* the shared MariaDB uses a bind mount from ``/opt/stacks/mariadb/data``;
* ``portafolio`` is a baked static image with no labels and no volume;
* the custom images only exist in the rootful Docker daemon.

This tool is deliberately separate from the generic Hosting migrator. It runs
**inside the ``spanel-app-1`` container**, where it can use both the rootful
socket (mounted at ``/var/run/docker.sock``) and the cell socket, and it reuses
the Hosting plugins to publish routes and record runtimes.

Phases::

    --statics      migrate the four static sites (no MariaDB window)
    --wordpress    stop the legacy WordPress + MariaDB, copy their data and
                   cut the four WordPress routes over (maintenance window)
    --all          both phases, statics first

Default is ``--statics`` and dry-run. Mutations require ``--apply`` and a
confirmation (``--yes`` to skip).

Usage inside the app container::

    docker cp scripts/migrate_milton_legacy.py spanel-app-1:/tmp/
    docker exec -it \
      -e PYTHONPATH=/app:/app/vendor/systutor-core \
      spanel-app-1 python /tmp/migrate_milton_legacy.py \
      --tenant milton --statics --dry-run

Exit codes: 0 ok, 1 failure, 2 usage/configuration.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# When copied to /tmp inside the app container, PYTHONPATH is already set by
# the caller. On a host checkout these fallbacks make the script importable.
HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
CORE = ROOT / "vendor" / "systutor-core"
for candidate in (
    str(CORE / "src"),
    str(CORE),
    str(ROOT),
    "/app/vendor/systutor-core",
    "/app",
):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

DEFAULT_DATA_ROOT = "/var/lib/spanel"
DEFAULT_TENANT = "milton"
DEFAULT_SHARED_DB = "mariadb"
DEFAULT_SHARED_NETWORK = "spanel-milton-shared-db"
DEFAULT_BUSYBOX = "busybox:1.36"
DEFAULT_WP_CLI = "wordpress:cli"
DEFAULT_NGINX = "nginx:alpine"
DEFAULT_DB_IMAGE = "mariadb:11.7"
DEFAULT_DB_VOLUME = "milton-mariadb-data"
PORTAFOLIO = "portafolio"


class LegacyError(RuntimeError):
    """A safe-to-print migration failure."""


class CommandError(LegacyError):
    """A Docker or helper command failed."""


# ---------------------------------------------------------------------------
# Command helpers
# ---------------------------------------------------------------------------


def log(message: str) -> None:
    print(f"   {message}", flush=True)


def step(message: str) -> None:
    print(f"\n== {message}", flush=True)


def run(
    argv: list[str],
    *,
    timeout: int = 120,
    check: bool = True,
    input: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            argv,
            input=input,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise CommandError(f"command not found: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"timeout after {timeout}s: {' '.join(argv[:6])}") from exc
    if check and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(errors="replace")
        raise CommandError(f"{' '.join(argv[:6])} failed: {detail.strip()[:400]}")
    return completed


def stream(source: list[str], sink: list[str], *, timeout: int = 3600) -> None:
    """Pipe stdout of one Docker command into stdin of another."""
    producer = subprocess.Popen(source, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert producer.stdout is not None
    consumer = subprocess.Popen(
        sink, stdin=producer.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    assert consumer.stdin is not None
    producer.stdout.close()
    try:
        _, sink_err = consumer.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        producer.kill()
        consumer.kill()
        raise CommandError(f"stream timed out: {' '.join(source[:6])}") from exc
    finally:
        if producer.poll() is None:
            producer.kill()
    sink_code = consumer.returncode
    producer_code = producer.wait(timeout=30)
    if producer_code != 0:
        detail = (producer.stderr.read() if producer.stderr else b"").decode(
            errors="replace"
        )
        raise CommandError(
            f"source command failed ({producer_code}): {detail.strip()[:300]}"
        )
    if sink_code != 0:
        detail = (sink_err or b"").decode(errors="replace")
        raise CommandError(f"sink command failed ({sink_code}): {detail.strip()[:300]}")


class Docker:
    def __init__(self, socket: str | None = None) -> None:
        self.socket = socket
        self.bin = os.environ.get("DOCKER_BIN", "docker")

    def argv(self, *args: str) -> list[str]:
        if self.socket:
            return [self.bin, "-H", f"unix://{self.socket}", *args]
        return [self.bin, *args]

    def run(
        self, *args: str, timeout: int = 120, check: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        return run(self.argv(*args), timeout=timeout, check=check)

    def text(self, *args: str, timeout: int = 120, check: bool = True) -> str:
        return self.run(*args, timeout=timeout, check=check).stdout.decode().strip()

    def inspect(self, name: str) -> dict[str, Any] | None:
        completed = self.run("inspect", name, check=False)
        if completed.returncode != 0:
            return None
        rows = json.loads(completed.stdout or b"[]")
        return rows[0] if isinstance(rows, list) and rows else None

    def exists(self, kind: str, name: str) -> bool:
        return self.run(kind, "inspect", name, check=False).returncode == 0

    def image_exists(self, image: str) -> bool:
        return self.exists("image", image)

    def volume_exists(self, name: str) -> bool:
        return self.exists("volume", name)

    def network_exists(self, name: str) -> bool:
        return self.exists("network", name)


# ---------------------------------------------------------------------------
# Database and site inventory
# ---------------------------------------------------------------------------


def service_context():
    from app.main import create_app
    from systutor.core.lifecycle import ensure_session_factory

    app = create_app()
    factory = ensure_session_factory(app)
    return app, factory


def tenant_sites(db: Any, slug: str) -> tuple[Any, list[Any]]:
    from plugins.hosting.backend.models import HostingSite
    from sqlalchemy import select
    from systutor.kernel.tenants.models import Tenant

    tenant = db.scalar(select(Tenant).where(Tenant.slug == slug))
    if tenant is None:
        raise LegacyError(f"tenant not found: {slug}")
    rows = list(
        db.scalars(
            select(HostingSite)
            .where(HostingSite.tenant_id == tenant.id)
            .order_by(HostingSite.kind, HostingSite.domain)
        ).all()
    )
    return tenant, rows


# ---------------------------------------------------------------------------
# Docker inspection helpers
# ---------------------------------------------------------------------------


def mount_for(info: dict[str, Any], destination: str) -> dict[str, Any]:
    matches = [
        mount
        for mount in info.get("Mounts") or []
        if mount.get("Destination") == destination
    ]
    if len(matches) != 1:
        raise LegacyError(f"expected one mount at {destination}, found {len(matches)}")
    return matches[0]


def env_lines(info: dict[str, Any]) -> list[str]:
    values = (info.get("Config") or {}).get("Env") or []
    return [str(item) for item in values]


def image_of(info: dict[str, Any], fallback: str) -> str:
    return str((info.get("Config") or {}).get("Image") or fallback)


def write_env(path: Path, info: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = env_lines(info)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    path.chmod(0o600)
    return path


def is_running(info: dict[str, Any] | None) -> bool:
    state = (info or {}).get("State") or {}
    return state.get("Running") is True or state.get("Status") == "running"


def wait_running(docker: Docker, name: str, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if is_running(docker.inspect(name)):
            return
        time.sleep(1)
    raise LegacyError(f"container {name} did not start in {int(timeout)}s")


def wait_database(docker: Docker, name: str, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    probe = (
        'p="${MARIADB_ROOT_PASSWORD:-$MYSQL_ROOT_PASSWORD}"; '
        'MYSQL_PWD="$p" mariadb-admin ping -h 127.0.0.1 -uroot --silent'
    )
    while time.monotonic() < deadline:
        completed = docker.run("exec", name, "sh", "-lc", probe, check=False)
        if completed.returncode == 0:
            return
        time.sleep(2)
    raise LegacyError(f"database {name} did not become ready in {int(timeout)}s")


def wait_wordpress(
    docker: Docker, name: str, env_file: Path, network: str, timeout: float = 120.0
) -> None:
    deadline = time.monotonic() + timeout
    argv = docker.argv(
        "run",
        "--rm",
        "--network",
        network,
        "--volumes-from",
        name,
        "--env-file",
        str(env_file),
        DEFAULT_WP_CLI,
        "wp",
        "core",
        "is-installed",
    )
    while time.monotonic() < deadline:
        completed = run(argv, timeout=120, check=False)
        if completed.returncode == 0:
            return
        time.sleep(3)
    detail = (completed.stderr or completed.stdout).decode(errors="replace")
    raise LegacyError(f"WordPress {name} is not ready: {detail.strip()[:300]}")


# ---------------------------------------------------------------------------
# Data transfer
# ---------------------------------------------------------------------------


def ensure_volume(docker: Docker, name: str) -> None:
    if not docker.volume_exists(name):
        docker.run("volume", "create", name, timeout=30)
        log(f"volumen creado: {name}")


def ensure_image(cell: Docker, rootful: Docker, image: str) -> None:
    if cell.image_exists(image):
        return
    if rootful.image_exists(image):
        log(f"transfiriendo imagen a la celda: {image}")
        stream(rootful.argv("save", image), cell.argv("load"), timeout=3600)
        return
    log(f"descargando imagen en la celda: {image}")
    cell.run("pull", image, timeout=1800)


def copy_bind(cell: Docker, rootful: Docker, source: str, volume: str) -> None:
    ensure_volume(cell, volume)
    ensure_image(cell, rootful, DEFAULT_BUSYBOX)
    log(f"copiando {source} -> volumen {volume}")
    stream(
        rootful.argv(
            "run",
            "--rm",
            "-v",
            f"{source}:/data:ro",
            DEFAULT_BUSYBOX,
            "tar",
            "-C",
            "/data",
            "-cf",
            "-",
            ".",
        ),
        cell.argv(
            "run",
            "--rm",
            "-i",
            "-v",
            f"{volume}:/data",
            DEFAULT_BUSYBOX,
            "tar",
            "-C",
            "/data",
            "-xf",
            "-",
        ),
        timeout=3600,
    )


def extract_image_dir(
    cell: Docker, rootful: Docker, image: str, container_path: str, volume: str
) -> None:
    ensure_volume(cell, volume)
    ensure_image(cell, rootful, DEFAULT_BUSYBOX)
    log(f"extrayendo {image}:{container_path} -> volumen {volume}")
    created = rootful.text("create", image, timeout=120)
    try:
        stream(
            rootful.argv("cp", f"{created}:{container_path}/.", "-"),
            cell.argv(
                "run",
                "--rm",
                "-i",
                "-v",
                f"{volume}:/data",
                DEFAULT_BUSYBOX,
                "tar",
                "-C",
                "/data",
                "-xf",
                "-",
            ),
            timeout=1800,
        )
    finally:
        rootful.run("rm", "-f", created, timeout=60, check=False)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def publish_custom_route(
    app: Any,
    db: Any,
    tenant_id: str,
    site: Any,
    target: Any,
    ingress: Any,
    container: str,
    domain: str,
    port: int = 80,
    https: bool = True,
) -> dict[str, Any]:
    from plugins.hosting.backend.rootless_ingress import (
        RootlessRoutePublisher,
        RouteSpec,
        verify_external_route,
    )
    from systutor.contracts.resource_runtime import write_resource_runtime
    from systutor.contracts.site_domain_publisher import get_site_domain_publisher

    ingress._network()
    ingress.upsert(RouteSpec(site.id, tenant_id, domain, container, port))
    publisher = get_site_domain_publisher(app)
    if publisher is not None:
        publisher.unpublish(domain)
    effective_https = RootlessRoutePublisher(app, db).publish(tenant_id, domain)
    verify_external_route(domain, https=effective_https if https else False)
    write_resource_runtime(app, db, tenant_id, site.kind, site.id, "rootless")
    db.commit()
    return {"ok": True, "domain": domain, "container": container, "port": port}


def rollback_custom_route(
    app: Any,
    db: Any,
    tenant_id: str,
    site: Any,
    target: Any,
    ingress: Any,
    cell: Docker,
    rootful: Docker,
    container: str,
    domain: str,
) -> None:
    from plugins.hosting.backend.rootless_ingress import RootlessRoutePublisher
    from systutor.contracts.resource_runtime import write_resource_runtime
    from systutor.contracts.site_domain_publisher import get_site_domain_publisher

    RootlessRoutePublisher(app, db).unpublish(domain)
    ingress.remove(site.id, tenant_id)
    cell.run("stop", container, timeout=120, check=False)
    rootful.run("start", container, timeout=120, check=False)
    publisher = get_site_domain_publisher(app)
    if publisher is not None:
        publisher.publish(container, domain)
    write_resource_runtime(app, db, tenant_id, site.kind, site.id, "rootful")
    db.commit()


# ---------------------------------------------------------------------------
# Migrator
# ---------------------------------------------------------------------------


@dataclass
class Plan:
    tenant: str
    cell: str
    shared_db: str
    shared_network: str
    statics: bool
    wordpress: bool
    apply: bool
    force: bool
    precopy: bool
    timeout: int
    data_root: str
    state_file: Path
    apps: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)


class LegacyMigrator:
    def __init__(self, plan: Plan, app: Any, db: Any) -> None:
        self.plan = plan
        self.app = app
        self.db = db
        self.tenant = None
        self.sites: list[Any] = []
        self.rootful = Docker()
        self.cell = Docker(
            str(Path(plan.data_root) / "cells" / plan.cell / "docker.sock")
        )
        self.tmp = Path(f"/tmp/spanel-milton-legacy-{os.getpid()}")
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.migrated: list[dict[str, Any]] = []

    # -- inventory ---------------------------------------------------------

    def load_sites(self) -> None:
        self.tenant, self.sites = tenant_sites(self.db, self.plan.tenant)
        self.plan.evidence["site_count"] = len(self.sites)

    def site_by_kind(self, kind: str) -> list[Any]:
        return [site for site in self.sites if site.kind == kind]

    def source_info(self, site: Any) -> dict[str, Any]:
        info = self.rootful.inspect(site.container_name)
        if info is None:
            raise LegacyError(f"source container is missing: {site.container_name}")
        return info

    # -- preflight ---------------------------------------------------------

    def preflight(self) -> None:
        step("Preflight")
        if not self.plan.apply:
            log("modo dry-run: no se muta nada")
        if not self.cell.socket or not Path(self.cell.socket).exists():
            raise LegacyError(f"cell socket is missing: {self.cell.socket}")
        self.cell.run("info", "--format", "{{.ServerVersion}}", timeout=60)
        for site in self.sites:
            self.source_info(site)
            log(f"{site.kind:9} {site.container_name:28} {site.domain}")
        db_info = self.rootful.inspect(self.plan.shared_db)
        if db_info is None:
            raise LegacyError(f"shared database is missing: {self.plan.shared_db}")
        mount = mount_for(db_info, "/var/lib/mysql")
        if mount.get("Type") != "bind":
            raise LegacyError("shared database is not a legacy bind mount")
        log(f"MYSQL bind: {mount.get('Source')} -> {mount.get('Destination')}")
        self.plan.evidence["preflight"] = {
            "sites": len(self.sites),
            "shared_db": self.plan.shared_db,
            "mysql_bind": mount.get("Source"),
        }

    # -- images ------------------------------------------------------------

    def images_for(self, statics: bool, wordpress: bool) -> list[str]:
        images: list[str] = []
        if statics:
            images.append(DEFAULT_NGINX)
        if wordpress:
            images.extend(
                image_of(self.source_info(site), DEFAULT_DB_IMAGE)
                for site in self.site_by_kind("wordpress")
            )
            images.append(DEFAULT_DB_IMAGE)
            images.append(DEFAULT_WP_CLI)
        return sorted(set(images))

    def ensure_images(self) -> None:
        step("Imágenes")
        for image in self.images_for(self.plan.statics, self.plan.wordpress):
            if self.cell.image_exists(image):
                log(f"presente: {image}")
                continue
            if self.plan.apply:
                ensure_image(self.cell, self.rootful, image)
            else:
                log(f"faltante: {image} (se transferiría/descargaría)")
        for image in (DEFAULT_BUSYBOX,):
            if self.plan.apply:
                ensure_image(self.cell, self.rootful, image)

    # -- static phase ------------------------------------------------------

    def migrate_statics(self) -> None:
        if not self.plan.statics:
            return
        from plugins.hosting.backend.rootless_migration import RootlessMigrationService

        step("Estáticos")
        service = RootlessMigrationService(self.app, self.db)
        for site in self.site_by_kind("static"):
            if site.container_name == PORTAFOLIO:
                self._migrate_portafolio(site)
                continue
            if not self.plan.apply:
                log(f"{site.container_name}: se migraría con el flujo estándar")
                continue
            log(f"migrando estático estándar: {site.container_name}")
            result = service.migrate(site.id)
            if not result.get("ok"):
                raise LegacyError(
                    f"static {site.container_name}: {result.get('error')}"
                )
            self.migrated.append(result)

    def _migrate_portafolio(self, site: Any) -> None:
        from plugins.hosting.backend.rootless_ingress import (
            RootlessIngress,
        )
        from plugins.hosting.backend.runtime import HostingRuntimeResolver

        source = self.source_info(site)
        image = image_of(source, "portafolio-lucas")
        volume = f"{PORTAFOLIO}-html"
        log(f"{PORTAFOLIO}: imagen {image}, volumen {volume}")
        if not self.plan.apply:
            log(f"{PORTAFOLIO}: se extraería {image} y se arrancaría nginx")
            return

        if self.plan.force and self.cell.inspect(PORTAFOLIO) is not None:
            self.cell.run("rm", "-f", PORTAFOLIO, timeout=60)
        resolver = HostingRuntimeResolver(self.app, self.db)
        target = resolver.candidate(self.tenant.id)
        ingress = RootlessIngress(self.db, target)
        ingress._network()
        existing = self.cell.inspect(PORTAFOLIO)
        if existing is None:
            if not self.cell.volume_exists(volume) or self.plan.force:
                extract_image_dir(
                    self.cell,
                    self.rootful,
                    image,
                    "/usr/share/nginx/html",
                    volume,
                )
            ensure_image(self.cell, self.rootful, DEFAULT_NGINX)
            self.cell.run(
                "run",
                "-d",
                "--name",
                PORTAFOLIO,
                "--network",
                "spanel-hosting",
                "--restart",
                "unless-stopped",
                "--label",
                "spanel.managed=true",
                "--label",
                f"spanel.tenant={self.tenant.id}",
                "--label",
                f"spanel.site={PORTAFOLIO}",
                "--label",
                "spanel.kind=static",
                "-v",
                f"{volume}:/usr/share/nginx/html",
                DEFAULT_NGINX,
                timeout=120,
            )
            wait_running(self.cell, PORTAFOLIO)
        try:
            publish_custom_route(
                self.app,
                self.db,
                self.tenant.id,
                site,
                target,
                ingress,
                PORTAFOLIO,
                str(site.domain),
                80,
                True,
            )
        except Exception:
            rollback_custom_route(
                self.app,
                self.db,
                self.tenant.id,
                site,
                target,
                ingress,
                self.cell,
                self.rootful,
                PORTAFOLIO,
                str(site.domain),
            )
            raise
        self.rootful.run("stop", PORTAFOLIO, timeout=120, check=False)
        self.migrated.append(
            {
                "ok": True,
                "site_id": site.id,
                "kind": "static",
                "container": PORTAFOLIO,
                "domain": str(site.domain),
            }
        )

    # -- wordpress phase ---------------------------------------------------

    def migrate_wordpress(self) -> None:
        if not self.plan.wordpress:
            return
        from plugins.hosting.backend.rootless_ingress import (
            RootlessIngress,
            RootlessRoutePublisher,
            RouteSpec,
            verify_external_route,
        )
        from plugins.hosting.backend.runtime import HostingRuntimeResolver
        from systutor.contracts.resource_runtime import write_resource_runtime
        from systutor.contracts.site_domain_publisher import get_site_domain_publisher

        step("WordPress + MariaDB")
        sites = self.site_by_kind("wordpress")
        if not sites:
            log("no hay WordPress")
            return
        db_info = self.source_info_by_name(self.plan.shared_db)
        db_bind = mount_for(db_info, "/var/lib/mysql")["Source"]
        wp_sources = {
            site.container_name: mount_for(self.source_info(site), "/var/www/html")[
                "Source"
            ]
            for site in sites
        }
        for site in sites:
            if not wp_sources[site.container_name]:
                raise LegacyError(f"no bind mount for {site.container_name}")
        if not self.plan.apply:
            for site in sites:
                log(
                    f"{site.container_name}: se copiaría {wp_sources[site.container_name]}"
                )
            log(f"{self.plan.shared_db}: se copiaría {db_bind}")
            log("después: parar rootful, arrancar celda y cutover")
            return
        resolver = HostingRuntimeResolver(self.app, self.db)
        target = resolver.candidate(self.tenant.id)
        ingress = RootlessIngress(self.db, target)
        ingress._network()
        # Optional first pass while rootful still serves.
        if self.plan.precopy:
            step("Precopia de ficheros WordPress")
            for site in sites:
                copy_bind(
                    self.cell,
                    self.rootful,
                    wp_sources[site.container_name],
                    f"{site.container_name}-html",
                )
        step("Ventana de mantenimiento")
        for site in sites:
            self.rootful.run("stop", site.container_name, timeout=180, check=False)
        self.rootful.run("stop", self.plan.shared_db, timeout=180, check=False)
        # Final consistent copy.
        for site in sites:
            copy_bind(
                self.cell,
                self.rootful,
                wp_sources[site.container_name],
                f"{site.container_name}-html",
            )
        copy_bind(self.cell, self.rootful, db_bind, DEFAULT_DB_VOLUME)
        # Start the shared database.
        self._start_shared_database(db_info)
        env_files = {}
        for site in sites:
            info = self.source_info(site)
            env_file = write_env(self.tmp / f"{site.container_name}.env", info)
            env_files[site.container_name] = env_file
            if self.plan.force and self.cell.inspect(site.container_name) is not None:
                self.cell.run("rm", "-f", site.container_name, timeout=60)
            existing = self.cell.inspect(site.container_name)
            if existing is None:
                config = info.get("Config") or {}
                command = [str(item) for item in (config.get("Cmd") or [])]
                entrypoint = config.get("Entrypoint")
                if entrypoint and entrypoint not in (
                    ["docker-entrypoint.sh"],
                    ["/usr/local/bin/docker-entrypoint.sh"],
                ):
                    log(
                        f"aviso: {site.container_name} usa entrypoint custom "
                        f"{entrypoint}; se conserva el de la imagen"
                    )
                self.cell.run(
                    "run",
                    "-d",
                    "--name",
                    site.container_name,
                    "--network",
                    self.plan.shared_network,
                    "--restart",
                    "unless-stopped",
                    "--label",
                    "spanel.managed=true",
                    "--label",
                    f"spanel.tenant={self.tenant.id}",
                    "--label",
                    f"spanel.site={site.container_name}",
                    "--label",
                    "spanel.kind=wordpress",
                    "--env-file",
                    str(env_file),
                    "-v",
                    f"{site.container_name}-html:/var/www/html",
                    image_of(info, DEFAULT_DB_IMAGE),
                    *command,
                    timeout=180,
                )
                wait_running(self.cell, site.container_name)
                self.cell.run(
                    "network",
                    "connect",
                    "spanel-hosting",
                    site.container_name,
                    timeout=60,
                    check=False,
                )
            try:
                wait_wordpress(
                    self.cell,
                    site.container_name,
                    env_file,
                    self.plan.shared_network,
                    timeout=self.plan.timeout,
                )
            except Exception:
                self._rollback_wordpress(sites, env_files)
                raise
        staged = []
        for site in sites:
            route = RouteSpec(
                site.id,
                self.tenant.id,
                str(site.domain),
                site.container_name,
                80,
            )
            ingress.upsert(route)
            staged.append(route)
        try:
            for site in sites:
                publisher = get_site_domain_publisher(self.app)
                if publisher is not None:
                    publisher.unpublish(str(site.domain))
                https = RootlessRoutePublisher(self.app, self.db).publish(
                    self.tenant.id, str(site.domain)
                )
                verify_external_route(str(site.domain), https=https)
                write_resource_runtime(
                    self.app, self.db, self.tenant.id, site.kind, site.id, "rootless"
                )
                self.db.commit()
                self.migrated.append(
                    {
                        "ok": True,
                        "site_id": site.id,
                        "kind": "wordpress",
                        "container": site.container_name,
                        "domain": str(site.domain),
                    }
                )
                log(f"{site.container_name}: ruta publicada y verificada")
        except Exception:
            self._rollback_wordpress(sites, env_files)
            raise

    def _start_shared_database(self, db_info: dict[str, Any]) -> None:
        ensure_volume(self.cell, DEFAULT_DB_VOLUME)
        if self.plan.force and self.cell.inspect(self.plan.shared_db) is not None:
            self.cell.run("rm", "-f", self.plan.shared_db, timeout=60)
        existing = self.cell.inspect(self.plan.shared_db)
        if existing is not None:
            if not is_running(existing):
                self.cell.run("start", self.plan.shared_db, timeout=120)
            wait_database(self.cell, self.plan.shared_db, timeout=self.plan.timeout)
            return
        if not self.cell.network_exists(self.plan.shared_network):
            self.cell.run(
                "network",
                "create",
                "--internal",
                "--label",
                "spanel.managed=true",
                "--label",
                f"spanel.tenant={self.tenant.id}",
                "--label",
                "spanel.role=legacy-shared-db",
                self.plan.shared_network,
                timeout=60,
            )
        env_file = write_env(self.tmp / "mariadb.env", db_info)
        self.cell.run(
            "run",
            "-d",
            "--name",
            self.plan.shared_db,
            "--network",
            self.plan.shared_network,
            "--restart",
            "unless-stopped",
            "--label",
            "spanel.managed=true",
            "--label",
            f"spanel.tenant={self.tenant.id}",
            "--label",
            "spanel.role=legacy-shared-db",
            "--env-file",
            str(env_file),
            "-v",
            f"{DEFAULT_DB_VOLUME}:/var/lib/mysql",
            DEFAULT_DB_IMAGE,
            timeout=180,
        )
        wait_database(self.cell, self.plan.shared_db, timeout=self.plan.timeout)

    def _rollback_wordpress(self, sites: list[Any], env_files: dict[str, Path]) -> None:
        del env_files
        log("rollback WordPress")
        from plugins.hosting.backend.rootless_ingress import (
            RootlessIngress,
            RootlessRoutePublisher,
        )
        from plugins.hosting.backend.runtime import HostingRuntimeResolver
        from systutor.contracts.resource_runtime import write_resource_runtime
        from systutor.contracts.site_domain_publisher import get_site_domain_publisher

        target = HostingRuntimeResolver(self.app, self.db).candidate(self.tenant.id)
        ingress = RootlessIngress(self.db, target)
        for site in sites:
            try:
                RootlessRoutePublisher(self.app, self.db).unpublish(str(site.domain))
            except Exception as exc:  # noqa: BLE001 - rollback keeps going
                log(f"rollback route {site.domain}: {exc}")
            try:
                ingress.remove(site.id, self.tenant.id)
            except Exception as exc:  # noqa: BLE001 - rollback keeps going
                log(f"rollback ingress {site.domain}: {exc}")
            self.cell.run("stop", site.container_name, timeout=120, check=False)
        self.cell.run("stop", self.plan.shared_db, timeout=120, check=False)
        self.rootful.run("start", self.plan.shared_db, timeout=120, check=False)
        time.sleep(2)
        for site in sites:
            self.rootful.run("start", site.container_name, timeout=120, check=False)
            publisher = get_site_domain_publisher(self.app)
            if publisher is not None:
                publisher.publish(site.container_name, str(site.domain))
            write_resource_runtime(
                self.app, self.db, self.tenant.id, site.kind, site.id, "rootful"
            )
        self.db.commit()

    def source_info_by_name(self, name: str) -> dict[str, Any]:
        info = self.rootful.inspect(name)
        if info is None:
            raise LegacyError(f"container is missing: {name}")
        return info

    # -- evidence ----------------------------------------------------------

    def save(self) -> None:
        self.plan.evidence.update(
            {
                "ok": True,
                "tenant": self.plan.tenant,
                "cell": self.plan.cell,
                "shared_db": self.plan.shared_db,
                "migrated": self.migrated,
                "finished_at": datetime.now(UTC).isoformat(),
            }
        )
        self.plan.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.plan.state_file.write_text(
            json.dumps(self.plan.evidence, indent=2, sort_keys=True, default=str)
            + "\n",
            encoding="utf-8",
        )
        try:
            self.tmp.rmdir()
        except OSError:
            pass
        log(f"evidencia: {self.plan.state_file}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="migrate_milton_legacy.py", description=__doc__)
    p.add_argument("--tenant", default=DEFAULT_TENANT)
    p.add_argument("--cell", default=None, help="Cell slug (default: tenant).")
    p.add_argument("--data-root", default=DEFAULT_DATA_ROOT)
    p.add_argument("--shared-db", default=DEFAULT_SHARED_DB)
    p.add_argument("--shared-network", default=DEFAULT_SHARED_NETWORK)
    p.add_argument("--statics", action="store_true", help="Migrate statics only.")
    p.add_argument(
        "--wordpress", action="store_true", help="Migrate WordPress/MariaDB only."
    )
    p.add_argument("--all", action="store_true", help="Statics then WordPress.")
    p.add_argument("--apply", action="store_true", help="Mutate; default is dry-run.")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Explicit preview (default; wins over --apply).",
    )
    p.add_argument("--yes", action="store_true", help="Skip the confirmation.")
    p.add_argument(
        "--force", action="store_true", help="Recreate target containers/volumes."
    )
    p.add_argument(
        "--no-precopy", action="store_true", help="Skip the live WordPress precopy."
    )
    p.add_argument("--timeout", type=int, default=180)
    p.add_argument("--state-file", type=Path, default=None)
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not (args.statics or args.wordpress or args.all):
        args.statics = True
    if args.all:
        args.statics = True
        args.wordpress = True
    cell = args.cell or args.tenant
    if args.dry_run:
        args.apply = False
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    state = args.state_file or Path(
        f"/var/lib/spanel/hosting-backups/milton-legacy-{stamp}.json"
    )
    plan = Plan(
        tenant=args.tenant,
        cell=cell,
        shared_db=args.shared_db,
        shared_network=args.shared_network,
        statics=args.statics,
        wordpress=args.wordpress,
        apply=args.apply,
        force=args.force,
        precopy=not args.no_precopy,
        timeout=args.timeout,
        data_root=args.data_root,
        state_file=state,
    )
    if args.apply and not args.yes:
        print(
            "Esta operación para WordPress/MariaDB abre una ventana de mantenimiento."
        )
        answer = input("¿Continuar? [y/N]: ").strip().lower()
        if answer not in {"y", "yes", "s", "si", "sí"}:
            print("cancelado")
            return 2
    try:
        app, factory = service_context()
        with factory() as db:
            migrator = LegacyMigrator(plan, app, db)
            migrator.load_sites()
            migrator.preflight()
            migrator.ensure_images()
            migrator.migrate_statics()
            migrator.migrate_wordpress()
            migrator.save()
        payload = plan.evidence
    except LegacyError as exc:
        payload = {"ok": False, "error": str(exc)[:500]}
    except Exception as exc:  # noqa: BLE001 - operator boundary
        import traceback

        detail = str(exc) or type(exc).__name__
        payload = {
            "ok": False,
            "error": f"unexpected failure: {detail}"[:500],
            "exception": type(exc).__name__,
            "traceback": traceback.format_exc()[-1500:],
        }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    elif payload.get("ok"):
        print("\nOK")
    else:
        print(f"\nERROR: {payload.get('error')}", file=sys.stderr)
        if payload.get("traceback"):
            print(payload["traceback"], file=sys.stderr)
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
