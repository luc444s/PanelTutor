"""Immutable contracts and the fail-closed Apps hardening adapter."""

from .contracts import (
    HardenedCandidate,
    HardeningPolicy,
    HardeningRejected,
    RuntimeUserPolicy,
    WritablePathPolicy,
    automatic_hardening_policy,
)
from .engine import CommandHardeningEngine

__all__ = [
    "CommandHardeningEngine",
    "automatic_hardening_policy",
    "HardenedCandidate",
    "HardeningPolicy",
    "HardeningRejected",
    "RuntimeUserPolicy",
    "WritablePathPolicy",
]
