from __future__ import annotations

import subprocess
from pathlib import Path

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


def test_dry_run_is_an_accepted_explicit_flag() -> None:
    args = mod.parser().parse_args(["--statics", "--dry-run"])
    assert args.dry_run is True
    assert args.apply is False
    assert args.skip_external_verify is False


def test_skip_external_verify_is_explicit() -> None:
    args = mod.parser().parse_args(["--statics", "--skip-external-verify"])
    assert args.skip_external_verify is True


def test_verify_timeout_is_parsed() -> None:
    args = mod.parser().parse_args(["--statics", "--verify-timeout", "180"])
    assert args.verify_timeout == 180.0


def test_verify_local_is_parsed() -> None:
    args = mod.parser().parse_args(["--statics", "--verify-local"])
    assert args.verify_local is True


def test_single_wordpress_image_is_opt_in() -> None:
    default = mod.parser().parse_args(["--wordpress"])
    assert default.wordpress_image == ""
    latest = mod.parser().parse_args(["--wordpress", "--wordpress-image"])
    assert latest.wordpress_image == "wordpress:latest"
    pinned = mod.parser().parse_args(
        ["--wordpress", "--wordpress-image", "wordpress:php8.3-apache"]
    )
    assert pinned.wordpress_image == "wordpress:php8.3-apache"


def test_images_for_uses_one_wordpress_image_when_requested() -> None:
    plan = mod.Plan(
        tenant="milton",
        cell="milton",
        shared_db="mariadb",
        shared_network="milton-shared",
        statics=False,
        wordpress=True,
        apply=False,
        force=False,
        precopy=False,
        timeout=180,
        data_root="/var/lib/spanel",
        state_file=Path("/tmp/state.json"),
        wordpress_image="wordpress:latest",
    )
    migrator = object.__new__(mod.LegacyMigrator)
    migrator.plan = plan
    assert migrator.images_for(False, True) == [
        "mariadb:11.7",
        "wordpress:cli",
        "wordpress:latest",
    ]


def test_stream_pipes_the_source_into_the_sink(tmp_path) -> None:
    target = tmp_path / "out"
    mod.stream(
        ["sh", "-c", "printf legacy-bytes"],
        ["sh", "-c", f"cat > {target}"],
        timeout=30,
    )
    assert target.read_text() == "legacy-bytes"


class _FakeDocker:
    def __init__(self, stdout: bytes) -> None:
        self.stdout = stdout
        self.calls: list[tuple] = []

    def run(self, *args, **kwargs):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, self.stdout, b"")


def test_https_proxy_helper_updates_only_the_cell_copy() -> None:
    docker = _FakeDocker(b"")
    mod.ensure_wordpress_https_proxy(docker, "infra-html")
    args = docker.calls[0]
    assert "infra-html:/var/www/html" in args
    assert args[-2] == "-r"
    assert "SPANEL_HTTPS_PROXY" in args[-1]
    assert "HTTP_X_FORWARDED_PROTO" in args[-1]
    assert "empty($_SERVER['HTTPS'])" in args[-1]


def test_wordpress_web_ids_parses_the_target_image() -> None:
    docker = _FakeDocker(b"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n")
    assert mod.wordpress_web_ids(docker, "wordpress:latest") == (33, 33)
    assert mod.wordpress_web_ids(_FakeDocker(b""), "wordpress:latest") == (33, 33)
