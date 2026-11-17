"""Admission-policy contracts retained for signed releases and validation.

The former subprocess hardener and its ``HardenedCandidate`` evidence type
were removed together with all Dockerfile/Compose rewriting.  What remains is
the small, immutable contract used to sign and re-verify the host-resource
authorization policy of a release.
"""

from .contracts import (
    HardeningPolicy,
    HardeningRejected,
    RuntimeUserPolicy,
    WritablePathPolicy,
    automatic_hardening_policy,
    resolve_hardening_policy,
)

__all__ = [
    "automatic_hardening_policy",
    "resolve_hardening_policy",
    "HardeningPolicy",
    "HardeningRejected",
    "RuntimeUserPolicy",
    "WritablePathPolicy",
]
