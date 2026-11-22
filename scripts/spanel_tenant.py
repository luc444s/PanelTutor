#!/usr/bin/env python3
"""Thin typer entrypoint for rootless tenant cell management (A.SPEC 0097)."""

from __future__ import annotations

import sys
from pathlib import Path

# Allow `python scripts/spanel_tenant.py --help` from the repository root.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tenant_cell.cli import app

if __name__ == "__main__":
    app()
