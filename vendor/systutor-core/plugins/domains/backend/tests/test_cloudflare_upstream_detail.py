"""Only a bounded, redacted Cloudflare validation detail may reach the UI."""

from __future__ import annotations

import json

from plugins.domains.backend.cloudflare.client import (
    CloudflareValidation,
    _safe_upstream_detail,
)
from plugins.domains.backend.cloudflare_router import _translate
from systutor.core.errors import AppError


def test_safe_upstream_detail_extracts_the_first_message() -> None:
    body = json.dumps(
        {
            "success": False,
            "errors": [
                {"code": 1003, "message": "Invalid DNS record content"},
                {"code": 1004, "message": "second message"},
            ],
        }
    ).encode()
    assert _safe_upstream_detail(body) == "Invalid DNS record content"


def test_safe_upstream_detail_redacts_credentials_and_account_ids() -> None:
    body = json.dumps(
        {
            "errors": [
                {
                    "message": (
                        "Bearer secret-token-12345678901234567890 rejected for account "
                        "8130fe55771d1075944573b85571bd7b with "
                        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                        "eyJzdWIiOiJzb21ldGhpbmctbG9uZy1lbm91Z2gifQ."
                        "abcdefghijklmnopqrstuvwxyz"
                    )
                }
            ]
        }
    ).encode()
    detail = _safe_upstream_detail(body)
    assert detail is not None
    assert "<redacted>" in detail
    assert "secret-token-12345678901234567890" not in detail
    assert "8130fe55771d1075944573b85571bd7b" not in detail
    assert "abcdefghijklmnopqrstuvwxyz" not in detail


def test_safe_upstream_detail_is_bounded_and_defensive() -> None:
    long_body = json.dumps({"errors": [{"message": "x" * 300}]}).encode()
    detail = _safe_upstream_detail(long_body)
    assert detail is not None
    assert len(detail) == 160

    assert _safe_upstream_detail(b"not json") is None
    assert _safe_upstream_detail(b'{"errors":[]}') is None
    assert _safe_upstream_detail(b'{"errors":[{"message":123}]}') is None


def test_translate_exposes_upstream_detail_with_a_dedicated_code() -> None:
    error = _translate(
        CloudflareValidation(
            "Cloudflare rejected the request", detail="Invalid DNS record content"
        )
    )
    assert isinstance(error, AppError)
    assert error.status_code == 422
    assert error.code == "domains.dns.cloudflare.upstream_validation"
    assert error.message == "Invalid DNS record content"


def test_translate_keeps_generic_messages_when_there_is_no_detail() -> None:
    error = _translate(
        CloudflareValidation("the Cloudflare OAuth client is not registered")
    )
    assert error.code == "domains.dns.cloudflare.validation"
    assert error.message == "the Cloudflare OAuth client is not registered"
