"""Managed probe defaults shared by runtime probes and the deploy script.

Keep this module dependency-free: ``scripts/deploy.sh`` loads it with
``runpy`` to pre-pull the probe image before building the stack.
"""

from __future__ import annotations

# Digest-pinned on purpose: probes must never execute a mutable tag.
DEFAULT_PROBE_IMAGE = (
    "curlimages/curl@sha256:"
    "d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b"
)
