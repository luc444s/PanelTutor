"""Command construction for the two filemanager runtimes."""

# The mandated root-level test command requires this local package bootstrap.
# ruff: noqa: E402
from __future__ import annotations

import base64
import json
import shlex
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(CORE / "src"))
sys.path.insert(0, str(CORE))

from plugins.filemanager.backend.driver import _command
from systutor.contracts.file_targets import FileTarget

LOCAL = {"SPANEL_DOCKER_TRANSPORT": "local"}


def _shell(command: list[str]) -> str:
    assert command[:2] == ["sh", "-c"]
    return command[2]


def test_php_runtime_execs_inside_the_target_container() -> None:
    target = FileTarget("spanel-demo-wp", "/var/www/html", "site-1")
    command = _shell(_command(target, "list", LOCAL, path=""))
    assert "docker exec -i -u www-data spanel-demo-wp php -r" in command
    assert "docker run" not in command


def test_volume_runtime_mounts_the_site_in_the_helper_image() -> None:
    target = FileTarget("spanel-demo-web", "/usr/share/nginx/html", "site-2", runtime="volume")
    command = _shell(_command(target, "list", LOCAL, path=""))
    assert (
        "docker run --rm -i --network none --user 0 "
        "--volumes-from spanel-demo-web --entrypoint php wordpress:cli -r"
    ) in command


def test_volume_runtime_accepts_a_configured_helper_and_quotes_it() -> None:
    target = FileTarget("spanel-demo-web", "/usr/share/nginx/html", "site-2", runtime="volume")
    command = _shell(
        _command(
            target,
            "list",
            {**LOCAL, "SPANEL_FILEMANAGER_HELPER_IMAGE": "registry/php:8; id"},
            path="",
        )
    )
    assert "--entrypoint php 'registry/php:8; id' -r" in command


def test_delete_many_passes_every_path_in_one_container_command() -> None:
    target = FileTarget("spanel-demo-wp", "/var/www/html", "site-1")
    command = _shell(
        _command(
            target,
            "delete_many",
            LOCAL,
            paths=["folder/a.txt", "folder/b.txt"],
        )
    )
    arguments = shlex.split(command)
    payload = json.loads(base64.b64decode(arguments[-1]))

    assert command.count("docker exec") == 1
    assert payload["op"] == "delete_many"
    assert payload["paths"] == ["folder/a.txt", "folder/b.txt"]


def test_universal_volume_uses_one_rootful_helper(tmp_path) -> None:
    source = tmp_path / "vol"
    target = FileTarget(
        "spanel-demo-web",
        "/data",
        "site-2",
        runtime="volume",
        execution_runtime="rootless",
        volume_source=str(source),
        owner_uid=60000,
        owner_gid=60000,
    )
    command = _shell(_command(target, "upload", {"SPANEL_DOCKER_TRANSPORT": "ssh"}, path="a.txt"))

    assert "--volumes-from" not in command
    assert "--user 0:0" in command
    assert f"-v {shlex.quote(str(source) + ':/data')}" in command
    payload = json.loads(base64.b64decode(shlex.split(command)[-1]))
    assert payload["root"] == "/data"
    assert payload["owner_uid"] == 60000
    assert payload["owner_gid"] == 60000
