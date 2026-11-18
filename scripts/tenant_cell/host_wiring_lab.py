"""LAB ONLY (A.SPEC 0102) — direct plan materializer wiring for experiments.

This module is **not production code** and is never imported by the application
container. It exists only so isolated lab tests can inject a real
``PlanMaterializer`` directly into the Apps plugin's resources (architecture
option 1) to compare it against the socket-based agent (option 2).

The production path is ``plugins.apps.backend.register`` building a
``HostPlanMaterializerClient`` and the privileged ``host_agent`` behind a Unix
socket. Do not reuse this module outside a lab.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import materializer, plans

LAB_MARKER = "LAB / NOT PRODUCTION"


def lab_plan_materializer(
    data_root: str | Path,
    executor: Any | None = None,
    *,
    enable_gate: bool = True,
) -> materializer.PlanMaterializer:
    """Return a directly-wired (gated) materializer for lab use only.

    ``enable_gate`` flips ``SPANEL_TENANT_ALLOW_LOCAL_MUTATIONS`` in *this*
    process; in production that gate exists only inside the host agent.
    """
    if enable_gate:
        os.environ[plans.MUTATION_GATE] = "1"
    if executor is None:
        from .executor import LocalExecutor

        executor = LocalExecutor()
    return materializer.PlanMaterializer(executor, data_root)
