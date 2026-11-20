"""Validated backup format executed through an opaque container runtime."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

from systutor.contracts.container_runtime import ContainerRuntimeHandle

from .config import env_of
from .models import HostingSite


def _safe_extract(payload: bytes, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
        for member in archive.getmembers():
            if (
                member.islnk()
                or member.issym()
                or member.name.startswith("/")
                or ".." in Path(member.name).parts
            ):
                raise ValueError("unsafe site archive")
        archive.extractall(destination, filter="data")


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def export_archive(
    runtime: ContainerRuntimeHandle,
    site: HostingSite,
    root: str,
    destination: Path,
) -> Path:
    info = runtime.inspect("container", site.container_name)
    if info is None:
        raise RuntimeError("site container unavailable")
    work = destination / ".build"
    work.mkdir(mode=0o700)
    try:
        payload = runtime.command(("cp", f"{site.container_name}:{root}", "-"))
        _safe_extract(payload, work / "site")
        sql_path: Path | None = None
        env = env_of(info)
        if site.kind == "wordpress":
            host = env.get("WORDPRESS_DB_HOST", "").split(":", 1)[0]
            user = env.get("WORDPRESS_DB_USER", "")
            password = env.get("WORDPRESS_DB_PASSWORD", "")
            database = env.get("WORDPRESS_DB_NAME", "")
            if not all((host, user, password, database)):
                raise RuntimeError("WordPress database binding incomplete")
            script = (
                "IFS= read -r u; IFS= read -r p; "
                f'MYSQL_PWD="$p" exec mariadb-dump -u "$u" --no-tablespaces {database}'
            )
            sql = runtime.command(
                ("exec", "-i", host, "sh", "-c", script),
                input=f"{user}\n{password}\n".encode(),
            )
            if not sql.strip():
                raise RuntimeError("database dump is empty")
            sql_path = work / "database" / "backup.sql"
            sql_path.parent.mkdir()
            sql_path.write_bytes(sql)
        files = sorted(path for path in work.rglob("*") if path.is_file())
        manifest = {
            "kind": "wp" if site.kind == "wordpress" else "static",
            "container": site.container_name,
            "entries": {
                path.relative_to(work).as_posix(): {
                    "sha256": _hash(path),
                    "size": path.stat().st_size,
                }
                for path in files
            },
        }
        archive_path = destination / f"{manifest['kind']}-{site.container_name}.zip"
        with zipfile.ZipFile(archive_path, "x", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True))
            for path in files:
                archive.write(path, path.relative_to(work).as_posix())
        verify_archive(archive_path, site)
        archive_path.chmod(0o600)
        return archive_path
    finally:
        import shutil

        shutil.rmtree(work, ignore_errors=True)


def verify_archive(path: Path, site: HostingSite) -> dict:
    with zipfile.ZipFile(path, "r") as archive:
        manifest = json.loads(archive.read("manifest.json"))
        if manifest.get("container") != site.container_name:
            raise ValueError("backup belongs to another site")
        for name, facts in manifest.get("entries", {}).items():
            if hashlib.sha256(archive.read(name)).hexdigest() != facts.get("sha256"):
                raise ValueError("backup entry hash mismatch")
        return manifest


def restore_archive(
    runtime: ContainerRuntimeHandle, site: HostingSite, root: str, path: Path
) -> None:
    manifest = verify_archive(path, site)
    info = runtime.inspect("container", site.container_name) or {}
    mounts = [
        mount
        for mount in info.get("Mounts", [])
        if mount.get("Type") == "volume" and mount.get("Destination") == root
    ]
    if len(mounts) != 1:
        raise ValueError("site volume is ambiguous")
    with zipfile.ZipFile(path, "r") as archive:
        site_entries = [name for name in manifest["entries"] if name.startswith("site/")]
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as tar:
            for name in site_entries:
                data = archive.read(name)
                relative = name.removeprefix("site/")
                record = tarfile.TarInfo(relative)
                record.size = len(data)
                record.mode = 0o644
                tar.addfile(record, io.BytesIO(data))
        stream.seek(0)
        runtime.import_volume(str(mounts[0]["Name"]), iter(lambda: stream.read(65536), b""))
        if site.kind == "wordpress":
            env = env_of(info)
            host = env["WORDPRESS_DB_HOST"].split(":", 1)[0]
            user = env["WORDPRESS_DB_USER"]
            password = env["WORDPRESS_DB_PASSWORD"]
            database = env["WORDPRESS_DB_NAME"]
            script = (
                f'IFS= read -r u; IFS= read -r p; MYSQL_PWD="$p" exec mariadb -u "$u" {database}'
            )
            runtime.command(
                ("exec", "-i", host, "sh", "-c", script),
                input=f"{user}\n{password}\n".encode() + archive.read("database/backup.sql"),
            )
