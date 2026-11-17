"""Repository Compose discovery for the source picker.

The worker can only clone and validate a checkout; the UI needs to offer the
nested Compose files before an application exists.  This module reads the
repository tree through the GitHub App installation token and returns the
same kind of paths the runtime accepts, without cloning the repository.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy.orm import Session

from systutor.core.errors import AppError

from .catalog import select_source
from .crypto import EncryptedValue, TokenCipher
from .github import GithubClient, app_jwt_for

MAX_CANDIDATES = 200
_EXCLUDED_SEGMENTS = frozenset(
    {
        ".git", ".venv", "venv", "node_modules", "dist", "build", "target",
        ".next", ".nuxt", ".cache", "__pycache__", "vendor",
    }
)


def is_compose_path(path: object) -> bool:
    if not isinstance(path, str) or not path or path.startswith("/"):
        return False
    if any(char in path for char in ("\x00", "\r", "\n", "\\")):
        return False
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    if any(part.lower() in _EXCLUDED_SEGMENTS for part in parts[:-1]):
        return False
    name = parts[-1].lower()
    return name.endswith((".yml", ".yaml")) and "compose" in name


def candidates_from_tree(entries: Iterable[object]) -> list[str]:
    """Filter a GitHub tree payload; pure so it is unit-testable."""
    paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("type") != "blob":
            continue
        path = entry.get("path")
        if is_compose_path(path):
            paths.add(str(path))
    ordered = sorted(paths, key=lambda path: (path.count("/"), path.lower()))
    return ordered[:MAX_CANDIDATES]


def list_compose_files(
    db: Session,
    tenant_id: str,
    installation_id: str,
    repository_id: str,
    branch: str | None,
    github: GithubClient,
    cipher: TokenCipher,
) -> list[str]:
    installation, repository, provider = select_source(
        db, tenant_id, installation_id, repository_id
    )
    ref = (branch or repository.default_branch or "main").strip()
    if not ref or ref.startswith("-") or any(ch in ref for ch in "\x00\r\n"):
        raise AppError(
            "Branch is invalid", status_code=422, code="apps.branch_invalid"
        )
    try:
        pem = cipher.decrypt_scoped(
            "github-app-private-key", provider.tenant_id, provider.id,
            EncryptedValue(
                provider.private_key_ciphertext, provider.private_key_nonce,
                provider.key_version,
            ),
        )
        jwt = app_jwt_for(pem, provider.github_app_id)
        token = github.installation_token(
            jwt, installation.github_installation_id,
            repository_id=repository.github_repository_id,
            permissions={"contents": "read"},
        ).token
        tree: dict[str, Any] = github.repository_tree(
            token, repository.full_name, ref
        )
    except Exception:
        raise AppError(
            "Could not read repository files",
            status_code=502,
            code="apps.github_unavailable",
        ) from None
    entries = tree.get("tree")
    if not isinstance(entries, list):
        raise AppError(
            "GitHub returned an invalid repository tree",
            status_code=502,
            code="apps.github_unavailable",
        )
    return candidates_from_tree(entries)
