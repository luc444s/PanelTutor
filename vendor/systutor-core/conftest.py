"""Keep the developer checkout's `.env` out of unrelated tests.

The application copies `.env` into ``os.environ`` when the settings modules are
imported (``systutor.core.config.load_env_file`` and the plugin ``*_load_env``
helpers). That is the documented behaviour for a running app, but in a single
pytest process it leaks host configuration into every later test: importing
``tests/conftest.py`` pulls in ``app.main``, whose module-level ``create_app()``
loads ``.env`` during collection.

The suites are written to pass in a clean checkout, where no ``.env`` exists,
so tests must observe the environment the process was started with, not the
values that the import loaded. This module restores that baseline once after
collection and around every test, without touching the settings objects that
were already built from the file.
"""

from __future__ import annotations

import os
from collections.abc import Generator

import pytest

_BASELINE_ENV = dict(os.environ)
# pytest rewrites this around every test; it is not part of the user's env.
_PYTEST_OWNED = frozenset({"PYTEST_CURRENT_TEST"})


def _drop_variables_added_since(baseline: dict[str, str]) -> None:
    for key in set(os.environ) - baseline.keys() - _PYTEST_OWNED:
        os.environ.pop(key, None)


def _restore(baseline: dict[str, str]) -> None:
    _drop_variables_added_since(baseline)
    for key, value in baseline.items():
        if os.environ.get(key) != value:
            os.environ[key] = value


def pytest_collection_finish(session: pytest.Session) -> None:
    """Discard whatever importing the test modules copied from `.env`."""
    _restore(_BASELINE_ENV)


@pytest.fixture(autouse=True)
def isolate_process_environment() -> Generator[None, None, None]:
    """Give every test the environment the pytest process started with."""
    _restore(_BASELINE_ENV)
    snapshot = dict(os.environ)
    yield
    _restore(snapshot)
