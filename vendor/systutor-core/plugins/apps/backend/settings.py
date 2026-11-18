"""Apps configuration loaded without embedding secret values in settings."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean flag from the environment, fail-safe to ``default``."""
    value = os.environ.get(name, "").strip().lower()
    if not value:
        return default
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


@dataclass(frozen=True)
class AppsSettings:
    encryption_key_file: Path
    public_url: str
    redis_url: str
    state_root: Path
    key_version: int = 1
    # A.SPEC 0102: the backend reaches the privileged host agent over a
    # Unix Domain Socket. An empty socket path means "no client configured",
    # which keeps the plans API fail-closed (503) by default.
    plan_agent_socket: Path = Path("")
    plan_agent_token_file: Path = Path("/run/secrets/plan_agent_token")
    plan_agent_timeout: float = 5.0
    plan_agent_allowed_uids: str = ""
    # A.SPEC 0106: TLS for rootless-backed routes. True is the existing
    # behaviour (PathRoute default); false is an explicit opt-out that renders
    # the plain HTTP document of the A.SPEC 0104 artifact. Never touches Traefik.
    rootless_routes_https: bool = True

    @classmethod
    def from_env(cls) -> AppsSettings:
        return cls(
            encryption_key_file=Path(
                os.environ.get("SPANEL_APPS_ENCRYPTION_KEY_FILE", "/run/secrets/apps_key")
            ),
            public_url=os.environ.get("SPANEL_APPS_PUBLIC_URL", ""),
            redis_url=os.environ.get("SYSTUTOR_REDIS_URL", "redis://redis:6379/0"),
            state_root=Path(os.environ.get("SPANEL_APPS_STATE_ROOT", "/var/lib/spanel/apps")),
            key_version=int(os.environ.get("SPANEL_APPS_KEY_VERSION", "1")),
            plan_agent_socket=Path(os.environ.get("SPANEL_PLAN_AGENT_SOCKET", "")),
            plan_agent_token_file=Path(
                os.environ.get(
                    "SPANEL_PLAN_AGENT_TOKEN_FILE", "/run/secrets/plan_agent_token"
                )
            ),
            plan_agent_timeout=float(os.environ.get("SPANEL_PLAN_AGENT_TIMEOUT", "5.0")),
            plan_agent_allowed_uids=os.environ.get("SPANEL_PLAN_AGENT_ALLOWED_UIDS", ""),
            rootless_routes_https=_env_bool(
                "SPANEL_ROOTLESS_ROUTES_HTTPS", default=True
            ),
        )

    @staticmethod
    def read_secret(path: Path) -> str:
        value = path.read_text(encoding="utf-8").strip()
        if not value:
            raise RuntimeError("apps secret file is empty")
        return value
