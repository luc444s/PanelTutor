#!/usr/bin/env python3
"""Compatibility entry point for the transactional build hardener."""
from __future__ import annotations

from dangerous_build.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
