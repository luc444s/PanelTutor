"""A.SPEC 0119: hosting images inside every rootless cell (eager, opt-in).

Cells do have egress (the per-cell MASQUERADE rule), so since A.SPEC 0119-R1
the default is lazy: the first ``docker run`` of a site pulls the image from
inside the cell. This module is the eager path, used only when
``SPANEL_CELL_IMAGE_PRELOAD=1`` is set, or by an explicit
``reconcile_cells.py`` run, to pull on the host and stream the image into the
cell with ``docker save | docker load``.

``subprocess.Popen`` with explicit pipes is used for the transfer (never
``shell=True``), and every call has a bounded timeout so a wedged daemon cannot
hang a deploy.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from . import alloc

DEFAULT_WP_IMAGE = "wordpress:latest"
DEFAULT_DB_IMAGE = "mariadb:11"
DEFAULT_STATIC_IMAGE = "nginx:alpine"
DEFAULT_ROOTFUL_SOCKET = "/var/run/docker.sock"

# A.SPEC 0119-R1: cells have egress (MASQUERADE in their netns), so a missing
# image is pulled on demand by ``docker run`` instead of copied during tenant
# provisioning. Opt back into eager copy with SPANEL_CELL_IMAGE_PRELOAD=1.
PRELOAD_ENV = "SPANEL_CELL_IMAGE_PRELOAD"
_EAGER_VALUES = {"1", "true", "yes", "on", "eager"}

INSPECT_TIMEOUT = 30
PULL_TIMEOUT = 1800
TRANSFER_TIMEOUT = 3600
PRODUCER_WAIT_TIMEOUT = 30


def preload_enabled(env: dict[str, str] | None = None) -> bool:
    """True only when the operator explicitly opts into eager image copies."""
    source = os.environ if env is None else env
    return str(source.get(PRELOAD_ENV, "0")).strip().lower() in _EAGER_VALUES


def desired_images() -> list[str]:
    """Images hosting needs in a cell, from the same env as the hosting plugin."""
    candidates = [
        os.environ.get("SPANEL_HOSTING_WP_IMAGE", DEFAULT_WP_IMAGE),
        os.environ.get("SPANEL_HOSTING_DB_IMAGE", DEFAULT_DB_IMAGE),
        os.environ.get("SPANEL_HOSTING_STATIC_IMAGE", DEFAULT_STATIC_IMAGE),
    ]
    wanted: list[str] = []
    for image in candidates:
        image = image.strip()
        if image and image not in wanted:
            wanted.append(image)
    return wanted


def _docker_argv(socket_path: str, *args: str) -> list[str]:
    return ["docker", "-H", f"unix://{socket_path}", *args]


def image_exists(socket_path: str, image: str) -> bool:
    """True when ``image`` is already present in the daemon at ``socket_path``."""
    completed = subprocess.run(
        _docker_argv(socket_path, "image", "inspect", image),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=INSPECT_TIMEOUT,
    )
    return completed.returncode == 0


def _pull(socket_path: str, image: str) -> None:
    """Pull into the *rootful* daemon, the only one with egress."""
    completed = subprocess.run(
        _docker_argv(socket_path, "pull", image),
        capture_output=True,
        text=True,
        check=False,
        timeout=PULL_TIMEOUT,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(f"docker pull failed for {image}: {detail[:300]}")


def _transfer(source_socket: str, target_socket: str, image: str) -> None:
    """Pipe ``docker save`` from the rootful daemon into the cell's load."""
    producer = subprocess.Popen(
        _docker_argv(source_socket, "save", image),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if producer.stdout is None:
        producer.kill()
        raise RuntimeError(f"docker save exposed no stdout for {image}")
    try:
        consumer = subprocess.Popen(
            _docker_argv(target_socket, "load"),
            stdin=producer.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception:
        producer.kill()
        producer.stdout.close()
        raise
    # The child owns the read end now; the parent must close its copy or the
    # cell's ``docker load`` never sees EOF.
    producer.stdout.close()
    try:
        _, sink_err = consumer.communicate(timeout=TRANSFER_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        producer.kill()
        consumer.kill()
        raise RuntimeError(f"image transfer timed out for {image}") from exc
    finally:
        if producer.poll() is None:
            producer.kill()
    producer_code = producer.wait(timeout=PRODUCER_WAIT_TIMEOUT)
    if producer_code != 0:
        detail = producer.stderr.read() if producer.stderr else b""
        raise RuntimeError(
            f"docker save failed ({producer_code}) for {image}: "
            f"{detail.decode(errors='replace').strip()[:300]}"
        )
    if consumer.returncode != 0:
        detail = (sink_err or b"").decode(errors="replace").strip()
        raise RuntimeError(
            f"docker load failed ({consumer.returncode}) for {image}: {detail[:300]}"
        )


def ensure_image(
    socket_path: str,
    image: str,
    *,
    rootful_socket: str = DEFAULT_ROOTFUL_SOCKET,
) -> str:
    """Make ``image`` available in the cell; return the action taken.

    ``present`` means no work was needed, ``transferred`` means the image was
    streamed from the rootful daemon and ``pulled`` means the host had to fetch
    it first. Every path is idempotent: a second call returns ``present``.
    """
    if image_exists(socket_path, image):
        return "present"
    if not image_exists(rootful_socket, image):
        _pull(rootful_socket, image)
        action = "pulled"
    else:
        action = "transferred"
    _transfer(rootful_socket, socket_path, image)
    return action


def ensure_cell_images(data_root: str | Path) -> list[dict[str, Any]]:
    """Reconcile the hosting images of every allocated cell with a live daemon.

    Cells without ``docker.sock`` are reported and skipped: the daemon may be
    stopped, deprovisioned or not yet started. A failure in one cell never
    prevents the remaining cells from being repaired.
    """
    data_root = Path(data_root)
    wanted = desired_images()
    results: list[dict[str, Any]] = []
    for slug in alloc.load_registry(data_root).get("allocations") or {}:
        socket = alloc.cell_dir(data_root, slug) / "docker.sock"
        if not socket.is_socket():
            results.append({"slug": slug, "images": "no-cell-daemon"})
            continue
        states: dict[str, str] = {}
        try:
            for image in wanted:
                states[image] = ensure_image(str(socket), image)
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            results.append(
                {"slug": slug, "images": "failed", "detail": str(exc)[:300]}
            )
            continue
        changed = any(state != "present" for state in states.values())
        results.append(
            {
                "slug": slug,
                "images": "updated" if changed else "unchanged",
                "detail": states,
            }
        )
    return results
