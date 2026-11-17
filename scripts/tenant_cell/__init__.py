"""Rootless per-tenant cell tooling (A.SPEC 0097).

This package is deliberately self-contained: it never imports backend or
kernel code. All host interaction happens through an injectable ``HostProbe``
(read-only) and an ``Executor`` (mutations), so tests run with fakes and never
touch a real system.
"""

from __future__ import annotations

__all__ = [
    "alloc",
    "apparmor",
    "audit",
    "cells",
    "cli",
    "doctor",
    "network",
]
