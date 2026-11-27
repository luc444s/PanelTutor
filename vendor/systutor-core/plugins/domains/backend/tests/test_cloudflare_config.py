"""A.SPEC 0124: Cloudflare mode parsing is explicit and secret-free."""

from __future__ import annotations

from pathlib import Path

import pytest

from plugins.domains.backend.cloudflare.config import (
    CloudflareConfig,
    CloudflareConfigError,
)


def _env(mode: str | None) -> dict[str, str]:
    env = {
        "SPANEL_CLOUDFLARE_PUBLIC_URL": "https://spanel.lab",
        "SPANEL_CLOUDFLARE_ENCRYPTION_KEY_FILE": "/run/secrets/apps_key",
    }
    if mode is not None:
        env["SPANEL_CLOUDFLARE_MODE"] = mode
    return env


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "tenant"),
        ("", "tenant"),
        ("tenant", "tenant"),
        ("TENANT", "tenant"),
        ("  tenant  ", "tenant"),
        ("0", "tenant"),
        ("single", "single"),
        ("SINGLE", "single"),
        ("  single  ", "single"),
        ("1", "single"),
    ],
)
def test_mode_normalization(value: str | None, expected: str) -> None:
    config = CloudflareConfig.from_env(_env(value))
    assert config.mode == expected
    assert config.describe()["mode"] == expected


@pytest.mark.parametrize("value", ["2", "true", "singles", "tenant,single", "single mode"])
def test_invalid_mode_fails_without_echoing_secrets(value: str) -> None:
    with pytest.raises(CloudflareConfigError) as exc:
        CloudflareConfig.from_env(_env(value))
    assert value not in str(exc.value)
    assert "SPANEL_CLOUDFLARE_MODE" in str(exc.value)


def test_default_constructor_mode_stays_tenant() -> None:
    config = CloudflareConfig(encryption_key_file=Path("/tmp/key"), public_url="https://spanel.lab")
    assert config.mode == "tenant"
    assert "secret" not in str(config.describe()).lower()
