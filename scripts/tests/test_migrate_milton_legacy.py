from __future__ import annotations

import pytest

from scripts import migrate_milton_legacy as mod


def test_mount_for_returns_the_bind_source() -> None:
    info = {
        "Mounts": [
            {
                "Type": "bind",
                "Source": "/opt/stacks/a/html",
                "Destination": "/var/www/html",
            },
            {"Type": "bind", "Source": "/other", "Destination": "/other"},
        ]
    }
    assert mod.mount_for(info, "/var/www/html")["Source"] == "/opt/stacks/a/html"


def test_mount_for_rejects_ambiguous_or_missing_destinations() -> None:
    with pytest.raises(mod.LegacyError):
        mod.mount_for({"Mounts": []}, "/var/www/html")
    with pytest.raises(mod.LegacyError):
        mod.mount_for(
            {
                "Mounts": [
                    {"Destination": "/var/www/html"},
                    {"Destination": "/var/www/html"},
                ]
            },
            "/var/www/html",
        )


def test_env_lines_and_image_of_read_the_inspect_shape() -> None:
    info = {
        "Config": {
            "Env": ["A=1", "B=2"],
            "Image": "ardiffx-ardiffx",
        }
    }
    assert mod.env_lines(info) == ["A=1", "B=2"]
    assert mod.image_of(info, "fallback") == "ardiffx-ardiffx"
    assert mod.image_of({"Config": {}}, "fallback") == "fallback"


def test_is_running_accepts_the_docker_inspect_shapes() -> None:
    assert mod.is_running({"State": {"Running": True}}) is True
    assert mod.is_running({"State": {"Status": "running"}}) is True
    assert mod.is_running({"State": {"Status": "exited"}}) is False
    assert mod.is_running(None) is False


def test_cell_docker_uses_an_explicit_socket() -> None:
    docker = mod.Docker("/var/lib/spanel/cells/milton/docker.sock")
    assert docker.argv("ps") == [
        "docker",
        "-H",
        "unix:///var/lib/spanel/cells/milton/docker.sock",
        "ps",
    ]
    assert mod.Docker().argv("ps") == ["docker", "ps"]
