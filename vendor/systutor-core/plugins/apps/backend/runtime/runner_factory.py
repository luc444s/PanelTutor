"""Runner factory that binds every app operation to its tenant's socket.

The global ``Runner`` transport is intentionally *not* used for the
``tenant-rootless`` profile: each tenant resolves to a private
``DOCKER_HOST`` and the socket must exist before any command is run.  The
``hardened`` profile keeps the historical behaviour byte-for-byte (I8).
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path

from .tenant_daemon import TenantDaemonConfig, validate_tenant
from .transport import Runner
from .types import AppDeployError

RUNTIME_HARDENED = "hardened"
RUNTIME_TENANT_ROOTLESS = "tenant-rootless"
RUNTIME_VALUES = frozenset({RUNTIME_HARDENED, RUNTIME_TENANT_ROOTLESS})

_GLOBAL_SETTING = "SPANEL_APPS_RUNTIME"
_TENANT_SETTING = "SPANEL_APPS_RUNTIME_TENANT"
_ENV_KEY_RE = re.compile(r"[^A-Z0-9]+")


class TenantSocketMissing(AppDeployError):
    """The tenant socket does not exist; fail closed instead of using the global one."""


def _env_key(tenant: str) -> str:
    """Turn a tenant id into a safe env suffix (``acme-1`` -> ``ACME_1``)."""
    return _ENV_KEY_RE.sub("_", tenant.upper()).strip("_")


def resolve_runtime(
    environ: Mapping[str, str] | None = None,
    tenant: str | None = None,
) -> str:
    """Resolve the effective runtime profile for a tenant.

    Precedence: per-tenant setting (``SPANEL_APPS_RUNTIME_TENANT_<TENANT>`` or
    ``SPANEL_APPS_RUNTIME_TENANT`` as a catch-all), then the global
    ``SPANEL_APPS_RUNTIME`` and finally the default ``hardened``.  An unknown
    value is a hard error: there is no silent fallback.
    """
    env = dict(os.environ if environ is None else environ)
    value = ""
    if tenant:
        name = validate_tenant(tenant)
        value = env.get(f"{_TENANT_SETTING}_{_env_key(name)}", "").strip()
        if not value:
            value = env.get(_TENANT_SETTING, "").strip()
    if not value:
        value = env.get(_GLOBAL_SETTING, "").strip() or RUNTIME_HARDENED
    if value not in RUNTIME_VALUES:
        raise AppDeployError(f"unsupported apps runtime profile: {value}")
    return value


def tenant_environment(
    tenant: object,
    environ: Mapping[str, str] | None = None,
    *,
    proxy_ip: str = "127.0.0.1",
) -> dict[str, str]:
    """Build the environment a tenant runner must use, without touching I/O.

    Two distinct tenants always produce two distinct ``DOCKER_HOST`` values and
    neither is the inherited global ``DOCKER_HOST``.
    """
    env = dict(os.environ if environ is None else environ)
    config = TenantDaemonConfig.for_tenant(tenant, proxy_ip=proxy_ip)
    env["DOCKER_HOST"] = config.docker_host
    env["SPANEL_APPS_TENANT"] = config.tenant
    env["SPANEL_APPS_RUNTIME_EFFECTIVE"] = RUNTIME_TENANT_ROOTLESS
    return env


def build_tenant_runner(
    tenant: object,
    environ: Mapping[str, str] | None = None,
    *,
    transport: str | None = None,
    proxy_ip: str = "127.0.0.1",
    config: TenantDaemonConfig | None = None,
) -> Runner:
    """Create a fail-closed runner bound to a tenant daemon socket.

    Only valid for the ``tenant-rootless`` profile.  For ``hardened`` callers
    should use the historical ``Runner`` directly.  The socket is checked
    before the runner is returned: local``unix`` sockets are checked on disk,
    SSH sockets with a remote ``test -S``.
    """
    name = validate_tenant(tenant)
    env = dict(os.environ if environ is None else environ)
    if resolve_runtime(env, name) != RUNTIME_TENANT_ROOTLESS:
        raise AppDeployError("tenant runner requires the tenant-rootless profile")
    cfg = config or TenantDaemonConfig.for_tenant(name, proxy_ip=proxy_ip)
    chosen = transport or env.get("SPANEL_DOCKER_TRANSPORT", "local").strip() or "local"
    runner_env = tenant_environment(name, env, proxy_ip=cfg.proxy_ip)
    runner_env["DOCKER_HOST"] = cfg.docker_host
    runner = Runner(chosen, runner_env)
    runner.tenant = cfg.tenant  # type: ignore[attr-defined]
    runner.runtime_profile = RUNTIME_TENANT_ROOTLESS  # type: ignore[attr-defined]
    runner.tenant_config = cfg  # type: ignore[attr-defined]

    if chosen == "local":
        if not cfg.socket.exists():
            raise TenantSocketMissing(f"tenant daemon socket is missing: {cfg.socket}")
    else:
        checked = runner.run(["test", "-S", str(cfg.socket)], check=False)
        if checked.returncode:
            raise TenantSocketMissing(f"tenant daemon socket is missing: {cfg.socket}")
    return runner


def runner_for(
    tenant: object,
    environ: Mapping[str, str] | None = None,
    *,
    transport: str | None = None,
    legacy_factory=None,
    proxy_ip: str = "127.0.0.1",
) -> Runner:
    """Select the historical runner or a tenant-bound one by profile.

    ``legacy_factory`` defaults to :class:`Runner` and keeps the ``hardened``
    branch behaviour unchanged.
    """
    name = validate_tenant(tenant)
    env = dict(os.environ if environ is None else environ)
    if resolve_runtime(env, name) == RUNTIME_TENANT_ROOTLESS:
        return build_tenant_runner(name, env, transport=transport, proxy_ip=proxy_ip)
    factory = legacy_factory or Runner
    return factory(transport or env.get("SPANEL_DOCKER_TRANSPORT", "local").strip() or "local", env)


def socket_for_tenant(
    tenant: object, *, root: str = "/run/spanel/tenants"
) -> Path:
    """Convenience helper for the multi-socket ingress registry."""
    return TenantDaemonConfig.for_tenant(
        tenant, socket_root=root
    ).socket
