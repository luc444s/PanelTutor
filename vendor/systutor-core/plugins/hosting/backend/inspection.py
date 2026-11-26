"""The narrow Docker operations the hosting API needs.

Only `inspect` is used here. Listing sites reads the ownership rows first and
then inspects exactly those containers: a container that is not in the tenant's
list is never touched.

The WordPress verdict itself is NOT reimplemented: it is the extracted
`discovery.detectar_capa2` from A.SPEC 0007/0012.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Callable, Iterator, Sequence

from .discovery import Candidato, detectar_capa2
from .transport import Fallo, build_docker_argv, run

INSPECT_BATCH_SIZE = 50
InspectRunner = Callable[[tuple[str, ...]], tuple[int, str]]


def inspect_container(
    env: dict[str, str], container_name: str, *, timeout: int = 60
) -> dict | None:
    """`docker inspect` as data, or None when the container does not exist.

    A missing container is a normal state for the site list, not an exception.
    Any other failure is still reported through the same None: the caller
    decides whether that means "missing" (list) or 409 (users/reset).
    """
    command = f"docker inspect --format '{{{{json .}}}}' {shlex.quote(container_name)}"
    result = run(build_docker_argv(command, env=env), env=env, timeout=timeout)
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, list):
        payload = payload[0] if payload else None
    return payload if isinstance(payload, dict) else None


def _payloads(stdout: str) -> Iterator[dict]:
    """One inspect payload per line, as printed by `--format '{{json .}}'`."""
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        rows = parsed if isinstance(parsed, list) else [parsed]
        for row in rows:
            if isinstance(row, dict):
                yield row


def inspect_many_containers(
    names: Sequence[str],
    *,
    env: dict[str, str] | None = None,
    command: InspectRunner | None = None,
    timeout: int = 60,
) -> dict[str, dict | None]:
    """Inspect many containers with one Docker call per batch of 50 names.

    `env` is the rootful transport (the argv is built by `build_docker_argv`).
    `command` lets a handle run the same arguments over its own daemon without
    going through the SSH transport. `docker inspect` exits 1 when any name is
    missing but still prints the containers that do exist, so a non-zero exit
    is not an error here: stdout decides which names are present. Every name
    that is absent maps to `None`.
    """
    result: dict[str, dict | None] = {name: None for name in names}
    if not names:
        return result
    if command is None and env is None:
        raise ValueError("inspect_many_containers requires env or command")
    for start in range(0, len(names), INSPECT_BATCH_SIZE):
        batch = tuple(names[start : start + INSPECT_BATCH_SIZE])
        args = ("inspect", "--format", "{{json .}}", *batch)
        if command is not None:
            _, stdout = command(args)
        else:
            assert env is not None
            line = "docker " + " ".join(shlex.quote(part) for part in args)
            completed = run(build_docker_argv(line, env=env), env=env, timeout=timeout)
            stdout = completed.stdout
        for payload in _payloads(stdout):
            name = payload.get("Name")
            if not isinstance(name, str) or not name:
                continue
            key = name.removeprefix("/")
            if key in result:
                result[key] = payload
    return result


def candidato_de(info: dict) -> Candidato:
    """Run the extracted detector against an inspect payload.

    `discovery` expects the short `docker ps` shape (`Image`, `Labels` as a
    string). The labels are rebuilt from inspect's dictionary without changing
    the detector: `es_operable` still reads `spanel.managed` from them.
    """
    config = info.get("Config")
    config = config if isinstance(config, dict) else {}
    labels = config.get("Labels")
    labels = labels if isinstance(labels, dict) else {}
    labels_text = ",".join(f"{key}={value}" for key, value in labels.items())
    container = {
        "Image": config.get("Image") or info.get("Image") or "",
        "Labels": labels_text,
    }
    return detectar_capa2(container, info)


def database_container(info: dict) -> str:
    """The database container named by WORDPRESS_DB_HOST.

    The official WordPress image declares `db:3306` or just `db`. The host part
    is the container name used by `docker exec`; a bare IP or `localhost` is not
    a container we can exec into.
    """
    variables: dict[str, str] = {}
    config = info.get("Config")
    config = config if isinstance(config, dict) else {}
    for pair in config.get("Env") or []:
        if not isinstance(pair, str):
            continue
        key, _, value = pair.partition("=")
        if key:
            variables[key.strip()] = value.strip()

    host = variables.get("WORDPRESS_DB_HOST", "").strip()
    if not host:
        raise Fallo("the WordPress container does not declare WORDPRESS_DB_HOST")
    name = host.split(":", 1)[0].strip()
    if not name or name in {"localhost", "127.0.0.1", "::1"}:
        raise Fallo(
            "WORDPRESS_DB_HOST does not point to a Docker container "
            f"({host!r}); SQL cannot be run there"
        )
    return name
