"""Conservative Dockerfile transformations for isolation-first runtimes."""
from __future__ import annotations

import re
from dataclasses import dataclass


class DockerfileHardeningError(ValueError):
    """The requested runtime policy cannot be applied without guessing."""


@dataclass(frozen=True)
class WritablePath:
    path: str
    mode: str = "0750"


def _command(line: str) -> str | None:
    match = re.match(r"^\s*([A-Za-z]+)(?:\s|$)", line)
    return match.group(1).upper() if match else None


def _final_stage_start(lines: list[str]) -> int:
    starts = [index for index, line in enumerate(lines) if _command(line) == "FROM"]
    if not starts:
        raise DockerfileHardeningError("Dockerfile has no FROM instruction")
    return starts[-1]


def _logical_instruction_starts(lines: list[str], start: int) -> list[int]:
    starts: list[int] = []
    continued = False
    for index in range(start, len(lines)):
        stripped = lines[index].strip()
        if not continued and stripped and not stripped.startswith("#") and _command(lines[index]):
            starts.append(index)
        continued = bool(lines[index].rstrip().endswith("\\"))
    return starts


def _runtime_insertion(lines: list[str], start: int) -> int:
    for index in _logical_instruction_starts(lines, start):
        if _command(lines[index]) in {"CMD", "ENTRYPOINT"}:
            return index
    return len(lines)


def _last_user(lines: list[str], start: int, before: int) -> str | None:
    value: str | None = None
    for index in _logical_instruction_starts(lines, start):
        if index >= before:
            break
        if _command(lines[index]) == "USER":
            parts = lines[index].strip().split(maxsplit=1)
            value = parts[1].split()[0] if len(parts) == 2 else ""
    return value


def harden_dockerfile(
    text: str,
    *,
    uid: int,
    gid: int,
    writable_paths: tuple[WritablePath, ...] = (),
) -> str:
    """Add an explicit final runtime user without altering build-time users."""
    if uid <= 0 or gid <= 0:
        raise DockerfileHardeningError("runtime uid/gid must be positive")
    for item in writable_paths:
        if not re.fullmatch(r"/[A-Za-z0-9._/+:-]+", item.path):
            raise DockerfileHardeningError(f"invalid writable path: {item.path}")
        if not re.fullmatch(r"0?[0-7]{3}", item.mode):
            raise DockerfileHardeningError(f"invalid writable mode: {item.mode}")

    ending = "\n" if text.endswith("\n") else ""
    lines = text.splitlines()
    stage = _final_stage_start(lines)
    insertion = _runtime_insertion(lines, stage)
    final_user = _last_user(lines, stage, insertion)
    requested = f"{uid}:{gid}"
    if final_user == requested and not writable_paths:
        return text

    additions = [
        f"RUN install -d -o {uid} -g {gid} -m {item.mode.lstrip('0') or '0'} {item.path}"
        for item in writable_paths
    ]
    if final_user != requested:
        additions.append(f"USER {requested}")
    if not additions:
        return text
    if insertion and lines[insertion - 1].strip():
        additions.insert(0, "")
    additions.append("")
    lines[insertion:insertion] = additions
    return "\n".join(lines).rstrip("\n") + ending
