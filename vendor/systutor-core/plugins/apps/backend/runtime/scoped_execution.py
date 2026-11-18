"""Resource-plan aware entry point for a scoped release deploy.

The releases executor stays unchanged: the plan is bound for the duration of
the deploy so that ``_override`` sees it through ``current_tenant_plan()``.
The public deploy signature here stays thin and forwards everything else.
"""

from __future__ import annotations

from typing import Any

from ..releases.scoped_execution import deploy_scoped as _deploy_scoped
from .tenant_plan import TenantPlan, bind_tenant_plan


def deploy_scoped(
    *args: Any, resource_plan: TenantPlan | None = None, **kwargs: Any
) -> Any:
    """Run a scoped deploy with ``resource_plan`` visible to the override."""
    with bind_tenant_plan(resource_plan):
        return _deploy_scoped(*args, **kwargs)
