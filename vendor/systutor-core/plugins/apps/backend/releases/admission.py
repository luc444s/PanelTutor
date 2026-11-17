"""Isolation-only admission for the ``tenant-rootless`` profile (A.SPEC 0096).

The Compose of the app is admitted **as signed**: no normalisation, no
hardening, no destructive rewrite.  Admission only rejects declarations that
break the tenant boundary (I1-I6, I10, I12) and records the signature plus the
image digests.  It never evaluates app content (CVEs, Dockerfile style), which
stays inherited from 0087 (I15).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from ..runtime.types import AppDeployError

FORBIDDEN_CAPABILITIES = frozenset({
    "SYS_ADMIN",
    "SYS_PTRACE",
    "NET_ADMIN",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_BOOT",
    "DAC_READ_SEARCH",
    "DAC_OVERRIDE",
    "CHOWN",
    "SETUID",
    "SETGID",
    "MKNOD",
    "NET_RAW",
})


class AdmissionRejected(AppDeployError):
    """The signed Compose violates the tenant-rootless envelope."""


def _as_mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _volumes(config: Mapping[str, Any]) -> list[object]:
    value = config.get("volumes") or []
    return list(value) if isinstance(value, list) else []


def _volume_source(entry: object) -> str:
    if isinstance(entry, Mapping):
        if str(entry.get("type", "")) != "bind":
            return ""
        source = entry.get("source")
        return source if isinstance(source, str) else ""
    if isinstance(entry, str) and ":" in entry:
        return entry.split(":", 1)[0]
    return ""


def _security_opt(config: Mapping[str, Any]) -> str:
    value = config.get("security_opt") or []
    if isinstance(value, str):
        return value.lower()
    return " ".join(str(item).lower() for item in value) if isinstance(value, list) else ""


def _reject_bind(source: str, data_root: Path, service: str) -> None:
    if source.endswith("docker.sock") or source in {"/var/run/docker.sock", "/run/docker.sock"}:
        raise AdmissionRejected(f"service {service} mounts a Docker socket")
    if not source.startswith((".", str(data_root), "~")):
        raise AdmissionRejected(
            f"service {service} binds a path outside the tenant data-root"
        )
    if source.startswith(("/", "~")):
        if not str(Path(source).expanduser().resolve()).startswith(str(data_root.resolve())):
            raise AdmissionRejected(
                f"service {service} binds a path outside the tenant data-root"
            )
    elif ".." in Path(source).parts:
        raise AdmissionRejected(f"service {service} binds a path outside the tenant")


def admit_compose(
    payload: object,
    *,
    tenant: str,
    data_root: Path,
    compose_sha256: str,
    signature: str,
    image_digests: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Validate one parsed Compose document and return admission evidence.

    Raises :class:`AdmissionRejected` on the first envelope violation so the
    deploy fails closed before any daemon is contacted.
    """
    if not isinstance(payload, Mapping):
        raise AdmissionRejected("the signed Compose is not a mapping")
    services = payload.get("services")
    if not isinstance(services, Mapping) or not services:
        raise AdmissionRejected("the signed Compose declares no services")
    if not signature.strip():
        raise AdmissionRejected("the Compose signature is required")
    if not compose_sha256.strip():
        raise AdmissionRejected("the Compose hash is required")
    digests = dict(image_digests or {})
    admitted: list[str] = []

    for raw_name, raw_config in services.items():
        service = str(raw_name)
        config = _as_mapping(raw_config)
        if config.get("privileged") is True:
            raise AdmissionRejected(f"service {service} is privileged")
        if config.get("devices"):
            raise AdmissionRejected(f"service {service} requests host devices")
        network_mode = str(config.get("network_mode", ""))
        if network_mode in {"host", "container:host"}:
            raise AdmissionRejected(f"service {service} uses host networking")
        for key in ("pid", "ipc", "uts"):
            if str(config.get(key, "")) == "host":
                raise AdmissionRejected(f"service {service} uses the host {key} namespace")
        if str(config.get("userns_mode", "")) == "host":
            raise AdmissionRejected(f"service {service} uses the host user namespace")
        caps = {
            str(item).upper()
            for item in (config.get("cap_add") or [])
            if isinstance(item, str)
        }
        if caps & FORBIDDEN_CAPABILITIES:
            raise AdmissionRejected(f"service {service} requests broad capabilities")
        sec = _security_opt(config)
        if "seccomp:unconfined" in sec or "apparmor:unconfined" in sec:
            raise AdmissionRejected(f"service {service} requests an unconfined profile")
        if "no-new-privileges" not in sec:
            raise AdmissionRejected(f"service {service} must set no-new-privileges")
        if str(config.get("runtime", "")) == "runc":
            raise AdmissionRejected(f"service {service} requests runc")
        for entry in _volumes(config):
            source = _volume_source(entry)
            if source:
                _reject_bind(source, data_root, service)
        image = config.get("image")
        if isinstance(image, str) and "@sha256:" not in image:
            if digests.get(service, "").find("sha256:") < 0:
                raise AdmissionRejected(f"service {service} image is not digest-pinned")
        admitted.append(service)

    evidence: dict[str, Any] = {
        "tenant": tenant,
        "profile": "tenant-rootless",
        "compose_sha256": compose_sha256,
        "signature": signature,
        "image_digests": dict(sorted(digests.items())),
        "services": sorted(admitted),
        "no_hardener": True,
    }
    if "hardened_tree_sha256" in evidence:
        raise AssertionError("tenant-rootless must not carry a hardened tree hash")
    return evidence


def admit_compose_file(
    path: Path,
    *,
    tenant: str,
    data_root: Path,
    signature: str,
    image_digests: Mapping[str, str] | None = None,
    hash_algorithm: str = "sha256",
) -> dict[str, Any]:
    """Hash and admit a Compose file, preserving it byte-for-byte (I7)."""
    if hash_algorithm != "sha256":
        raise AdmissionRejected("only sha256 Compose hashing is supported")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        payload = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeError, yaml.YAMLError):
        raise AdmissionRejected("the signed Compose is not valid YAML") from None
    return admit_compose(
        payload,
        tenant=tenant,
        data_root=data_root,
        compose_sha256=digest,
        signature=signature,
        image_digests=image_digests,
    )
