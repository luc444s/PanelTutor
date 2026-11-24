"""Dramatiq entrypoint for the dedicated serialized Apps worker."""

from __future__ import annotations

import logging
import os
import sys
import threading
import time

from sqlalchemy import select

from systutor.contracts.site_domain_publisher import get_site_domain_publisher
from systutor.core.config import get_settings
from systutor.core.database import build_session_factory
from systutor.kernel.tasks.broker import configure_dramatiq_broker

from .crypto import TokenCipher
from .dispatcher import DramatiqDispatcher
from .github import UrllibGithubClient
from .models import Operation
from .operations import reconcile
from .register import build_runtime_recorder, build_runtime_registry
from .settings import AppsSettings
from .worker import AppsWorker, build_actor

settings = AppsSettings.from_env()
core_settings = get_settings()
configure_dramatiq_broker(core_settings)
session_factory = build_session_factory(core_settings)


def _dispose_inherited_pools() -> None:
    """After a fork, never share psycopg prepared statements with the parent.

    Dramatiq forks its worker process after this module imported and built the
    SQLAlchemy engines.  Inherited pooled connections keep the same psycopg3
    prepared-statement names, which raises ``DuplicatePreparedStatement`` in
    the child (for example in the heartbeat thread).  Disposing without
    closing detaches the child from the parent's connections; new connections
    are created in the child as needed.
    """
    factories = [session_factory]
    app_module = sys.modules.get("app.main")
    app = getattr(app_module, "app", None)
    app_factory = getattr(getattr(app, "state", None), "session_factory", None)
    if app_factory is not None:
        factories.append(app_factory)
    for factory in factories:
        engine = getattr(factory, "kw", {}).get("bind")
        if engine is not None:
            try:
                engine.dispose(close=False)
            except Exception:  # noqa: BLE001 - fork hook must never abort boot
                pass


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_dispose_inherited_pools)
cipher = TokenCipher.from_text(
    settings.read_secret(settings.encryption_key_file), settings.key_version
)
route_cleanup = None
route_refresh = None
rootless_routes = None
app = None
try:
    from app.main import app

    from .rootless_routes import build_rootless_routes

    publisher = get_site_domain_publisher(app)
    route_cleanup = getattr(app.state, "domain_routes_cleanup", None)
    route_refresh = getattr(app.state, "domain_routes_refresh", None)
    rootless_routes = build_rootless_routes(app)
except Exception:
    publisher = None
runtime_options = {}
if settings.tenants_rootless:
    runtime_options = {
        "runtime_registry": build_runtime_registry(settings),
        "runtime_recorder": build_runtime_recorder(settings),
    }
worker = AppsWorker(
    session_factory, cipher, publisher=publisher, github=UrllibGithubClient(),
    route_cleanup=route_cleanup, route_refresh=route_refresh,
    rootless_routes=rootless_routes, app=app, **runtime_options,
)


def _stale_after() -> int:
    raw = os.environ.get("SPANEL_APPS_RECONCILE_STALE_SECONDS", "300").strip()
    try:
        value = int(raw)
    except ValueError:
        return 300
    return max(15, value)


def _recover() -> None:
    with session_factory() as db:
        reconcile(db, DramatiqDispatcher(), stale_after=_stale_after())
        active = set(db.scalars(select(Operation.id).where(
            Operation.status.in_(("queued", "running"))
        )).all())
    pending = settings.state_root / "pending"
    if pending.exists():
        for path in pending.glob("*.env"):
            if path.stem not in active:
                path.unlink(missing_ok=True)


_recover()
logger = logging.getLogger(__name__)


def _reconcile_loop() -> None:
    """Periodically expire operations whose worker died without a clean exit."""
    stale_after = _stale_after()
    interval = max(5, min(30, stale_after // 3))
    while True:
        time.sleep(interval)
        try:
            with session_factory() as db:
                reconcile(db, DramatiqDispatcher(), stale_after=stale_after)
        except Exception:  # noqa: BLE001 - recovery must not kill the worker
            logger.warning("apps_reconcile_failed", exc_info=True)


threading.Thread(
    target=_reconcile_loop, name="apps-reconcile", daemon=True,
).start()
try:
    worker.reconcile_routes()
except Exception:  # noqa: BLE001 - el worker debe arrancar aunque falle el proxy
    logger.warning("apps_route_reconcile_failed", exc_info=True)
apps_operation = build_actor(worker.run)

__all__ = ["apps_operation"]
