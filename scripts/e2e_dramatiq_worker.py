#!/usr/bin/env python3
"""Dramatiq worker launcher for long black-box E2E deployments.

The default ``TimeLimit`` middleware aborts a deployment thread after ten
minutes, which turns a cold rootless image build into a stuck operation.  The
E2E harness raises only that bound; no product middleware is removed.
"""

from __future__ import annotations

import sys

import dramatiq
from dramatiq.middleware import TimeLimit

import plugins.apps.backend.tasks  # noqa: F401  (registers the actors)


def _raise_time_limit(milliseconds: int) -> None:
    broker = dramatiq.get_broker()
    broker.middleware = [
        TimeLimit(time_limit=milliseconds) if isinstance(item, TimeLimit) else item
        for item in broker.middleware
    ]


if __name__ == "__main__":
    _raise_time_limit(3_600_000)
    from dramatiq.cli import main, make_argument_parser

    parsed = make_argument_parser().parse_args(
        ["plugins.apps.backend.tasks", *sys.argv[1:]]
    )
    sys.exit(main(parsed))
