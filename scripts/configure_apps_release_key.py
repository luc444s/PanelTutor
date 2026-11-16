#!/usr/bin/env python3
"""Provision, audit or rotate the SPanel Apps release signing keys.

The command is deliberately narrow: it only manages
``SPANEL_APPS_RELEASE_SIGNING_KEY`` and ``SPANEL_APPS_RELEASE_VERIFY_KEYS`` in
the host environment file, recreates the consumers, and never prints key
material unless ``--print-key`` is requested. ``apply`` is idempotent and never
replaces an existing valid key; use ``rotate`` for that.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

ACTIVE_VAR = "SPANEL_APPS_RELEASE_SIGNING_KEY"
VERIFY_VAR = "SPANEL_APPS_RELEASE_VERIFY_KEYS"
RELEASE_VARS = (ACTIVE_VAR, VERIFY_VAR, "SPANEL_APPS_RELEASE_TTL_SECONDS")
DEFAULT_SERVICES = ("app", "apps-worker")
MIN_KEY_BYTES = 32
MAX_VERIFY_KEYS = 64
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
KEY_ID = re.compile(r"^[0-9a-f]{8}$")
KEY_CHARS = re.compile(r"^[A-Za-z0-9._+/=-]+$")


class ReleaseKeyError(RuntimeError):
    """Safe operator-facing configuration failure."""


def _clean_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    comment = re.search(r"\s+#", value)
    if comment:
        value = value[: comment.start()].rstrip()
    return value


def parse_env(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = ENV_LINE.match(line)
        if not match:
            continue
        result[match.group(1)] = _clean_value(line[match.end():])
    return result


def key_id_for(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]


def validate_key(key: str, *, label: str = "signing key") -> None:
    if not key:
        raise ReleaseKeyError(f"The release {label} is empty")
    if any(character.isspace() for character in key):
        raise ReleaseKeyError(f"The release {label} must not contain whitespace")
    if '"' in key or "'" in key:
        raise ReleaseKeyError(f"The release {label} must not contain quotes")
    if not KEY_CHARS.fullmatch(key):
        raise ReleaseKeyError(f"The release {label} contains unsupported characters")
    size = len(key.encode("utf-8"))
    if size < MIN_KEY_BYTES:
        raise ReleaseKeyError(
            f"The release {label} is too short ({size} bytes; minimum {MIN_KEY_BYTES})"
        )


def load_key_file(path: Path) -> str:
    path = Path(os.path.abspath(path.expanduser()))
    if not path.is_file() or path.is_symlink():
        raise ReleaseKeyError(f"Key file must be a regular non-symlink file: {path}")
    if path.stat().st_mode & 0o077:
        raise ReleaseKeyError(f"Key file must not be readable by group/others: {path}")
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        raise ReleaseKeyError(f"Key file must contain exactly one line: {path}")
    return _clean_value(lines[0])


def generate_key() -> str:
    return secrets.token_hex(MIN_KEY_BYTES)


def parse_verify_keys(raw: str) -> dict[str, str]:
    raw = raw.strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReleaseKeyError(f"{VERIFY_VAR} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ReleaseKeyError(f"{VERIFY_VAR} must be a JSON object")
    if len(data) > MAX_VERIFY_KEYS:
        raise ReleaseKeyError(f"{VERIFY_VAR} has more than {MAX_VERIFY_KEYS} keys")
    result: dict[str, str] = {}
    for item_id, item_key in data.items():
        if not isinstance(item_id, str) or not KEY_ID.fullmatch(item_id):
            raise ReleaseKeyError(f"{VERIFY_VAR} contains an invalid key id")
        if not isinstance(item_key, str):
            raise ReleaseKeyError(f"{VERIFY_VAR} contains a non-string key")
        validate_key(item_key, label=f"verification key {item_id}")
        if key_id_for(item_key) != item_id:
            raise ReleaseKeyError(
                f"{VERIFY_VAR} entry {item_id} does not match its key material"
            )
        result[item_id] = item_key
    return result


def render_env(text: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        if key not in RELEASE_VARS:
            raise ReleaseKeyError(f"Refusing to update non-release variable: {key}")
        if any(character in value for character in "\r\n\0"):
            raise ReleaseKeyError(f"Invalid value for {key}")

    output: list[str] = []
    emitted: set[str] = set()
    for line in text.splitlines():
        match = ENV_LINE.match(line)
        key = match.group(1) if match else None
        if key in values:
            if key not in emitted:
                output.append(f"{key}={values[key]}")
                emitted.add(key)
            continue
        output.append(line)
    missing = [key for key in values if key not in emitted]
    if missing:
        if output and output[-1] != "":
            output.append("")
        marker = "# APPS release signing — managed by scripts/configure_apps_release_key.py"
        if marker not in output:
            output.append(marker)
        output.extend(f"{key}={values[key]}" for key in missing)
    return "\n".join(output).rstrip() + "\n"


def write_env(path: Path, content: str, *, dry_run: bool = False) -> Path | None:
    original = path.read_text(encoding="utf-8") if path.exists() else ""
    if original == content or dry_run:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    backup: Path | None = None
    if path.exists():
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup = path.with_name(f"{path.name}.release-backup-{stamp}")
        counter = 1
        while backup.exists():
            backup = path.with_name(f"{path.name}.release-backup-{stamp}-{counter}")
            counter += 1
        shutil.copy2(path, backup)
        backup.chmod(0o600)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return backup


CommandRunner = Callable[[list[str]], None]


def run_command(command: list[str]) -> None:
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError as exc:
        raise ReleaseKeyError(f"Required executable not found: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise ReleaseKeyError(f"Command failed with exit code {exc.returncode}") from exc


def compose_base(env_file: Path, compose_file: Path) -> list[str]:
    return [
        "docker",
        "compose",
        "--project-directory",
        str(env_file.parent),
        "--env-file",
        str(env_file),
        "--file",
        str(compose_file),
    ]


def running_services(env_file: Path, compose_file: Path) -> set[str] | None:
    command = compose_base(env_file, compose_file) + ["ps", "--services", "--status", "running"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def service_key(
    service: str,
    env_file: Path,
    compose_file: Path,
    running: set[str] | None,
) -> str | None:
    """Return the key visible inside a service, or None when it is missing."""
    if running is not None and service not in running:
        raise ReleaseKeyError(f"Service {service} is not running")
    command = compose_base(env_file, compose_file) + [
        "exec", "-T", service, "printenv", ACTIVE_VAR,
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise ReleaseKeyError("Required executable not found: docker") from exc
    if result.returncode != 0:
        stderr = result.stderr.lower()
        if "not running" in stderr or "no such service" in stderr:
            raise ReleaseKeyError(f"Service {service} is not running")
        return None
    value = result.stdout.rstrip("\r\n")
    return value or None


def release_count(env_file: Path, compose_file: Path) -> int | None:
    command = compose_base(env_file, compose_file) + [
        "exec", "-T", "apps-worker", "sh", "-c",
        'find /var/lib/spanel/apps -name release.json -type f 2>/dev/null | wc -l',
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


def recreate_services(
    services: Sequence[str],
    env_file: Path,
    compose_file: Path,
    *,
    runner: CommandRunner = run_command,
) -> None:
    base = compose_base(env_file, compose_file)
    runner(base + ["config", "--quiet"])
    runner(base + ["up", "-d", "--force-recreate", "--no-deps", *services])


def service_states(
    services: Sequence[str],
    env_file: Path,
    compose_file: Path,
    expected: str | None,
) -> list[tuple[str, str]]:
    running = running_services(env_file, compose_file)
    if running is None:
        return [(service, "docker compose unavailable") for service in services]
    states: list[tuple[str, str]] = []
    for service in services:
        try:
            key = service_key(service, env_file, compose_file, running)
        except ReleaseKeyError as exc:
            states.append((service, str(exc)))
            continue
        if key is None:
            states.append((service, "signing key MISSING"))
        elif expected is None:
            states.append((service, f"follows key_id={key_id_for(key)}"))
        elif key_id_for(key) == expected:
            states.append((service, f"in sync (key_id={expected})"))
        else:
            states.append((service, f"OUT OF SYNC (key_id={key_id_for(key)}; expected {expected})"))
    return states


def report_service_states(
    services: Sequence[str],
    env_file: Path,
    compose_file: Path,
    expected: str | None,
) -> bool:
    ok = True
    for service, state in service_states(services, env_file, compose_file, expected):
        print(f"Service {service}: {state}")
        if (
            "MISSING" in state
            or "OUT OF SYNC" in state
            or "not running" in state
            or "unavailable" in state
        ):
            ok = False
    return ok


def verify_services(
    services: Sequence[str],
    key: str,
    env_file: Path,
    compose_file: Path,
    *,
    timeout: int = 90,
) -> None:
    expected = key_id_for(key)
    deadline = time.monotonic() + timeout
    pending = list(services)
    last_error: ReleaseKeyError | None = None
    while pending and time.monotonic() < deadline:
        remaining: list[str] = []
        running = running_services(env_file, compose_file)
        for service in pending:
            try:
                found = service_key(service, env_file, compose_file, running)
            except ReleaseKeyError as exc:
                last_error = exc
                remaining.append(service)
                continue
            if found is None:
                last_error = ReleaseKeyError(f"Service {service} does not expose {ACTIVE_VAR}")
                remaining.append(service)
                continue
            if key_id_for(found) != expected:
                last_error = ReleaseKeyError(
                    f"Service {service} uses key_id={key_id_for(found)}; expected {expected}"
                )
                remaining.append(service)
        pending = remaining
        if pending:
            time.sleep(2)
    if pending:
        raise last_error or ReleaseKeyError(
            f"Services {', '.join(pending)} did not expose key_id={expected}"
        )


def describe_env(
    env_file: Path,
    *,
    expected: str | None = None,
    allow_missing: bool = False,
) -> tuple[str, dict[str, str]]:
    if not env_file.exists():
        if allow_missing:
            print(f"Environment file: {env_file} (will be created)")
            return "", {}
        raise ReleaseKeyError(f"Environment file not found: {env_file}")
    try:
        text = env_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseKeyError(f"Cannot read environment file: {env_file}") from exc
    values = parse_env(text)
    active = values.get(ACTIVE_VAR, "").strip()
    print(f"Environment file: {env_file}")
    if active:
        try:
            validate_key(active)
        except ReleaseKeyError as exc:
            print(f"Active key:       INVALID ({exc})")
        else:
            print(
                f"Active key:       key_id={key_id_for(active)} "
                f"({len(active.encode('utf-8'))} bytes)"
            )
    else:
        print(f"Active key:       MISSING ({ACTIVE_VAR})")
    verify: dict[str, str] = {}
    try:
        verify = parse_verify_keys(values.get(VERIFY_VAR, ""))
    except ReleaseKeyError as exc:
        print(f"Verify keys:      INVALID ({exc})")
    else:
        print(f"Verify keys:      {', '.join(sorted(verify)) if verify else 'none'}")
    mode = stat.S_IMODE(env_file.stat().st_mode)
    if mode & 0o077:
        print(f"Warning:          {env_file} is readable by group/others (mode {mode:o})")
    if expected is not None and active and key_id_for(active) != expected:
        print("Warning:          the expected key id does not match the environment file")
    return active, {**values, VERIFY_VAR: json.dumps(verify, sort_keys=True) if verify else ""}


def apply_plan(
    env_file: Path,
    compose_file: Path,
    services: Sequence[str],
) -> None:
    active, _ = describe_env(env_file)
    print(f"Services:         {', '.join(services)}")
    if not active:
        print("Plan:             create a new 32-byte active key and recreate the services")
    else:
        validate_key(active)
        expected = key_id_for(active)
        states = service_states(services, env_file, compose_file, expected)
        if all("in sync" in state for _, state in states):
            print(f"Plan:             keep key_id={expected}; services are already in sync")
        else:
            print(f"Plan:             keep key_id={expected}; recreate out-of-sync services")


def apply(
    *,
    env_file: Path,
    compose_file: Path,
    services: Sequence[str],
    key_file: Path | None,
    restart: bool,
    print_key: bool,
    dry_run: bool,
    runner: CommandRunner = run_command,
) -> str:
    active, _ = describe_env(env_file, allow_missing=True)
    if active:
        validate_key(active)
        expected = key_id_for(active)
        if dry_run:
            validate_compose(env_file, compose_file, runner)
            print(f"Dry-run: key_id={expected} already configured; no file changes")
            report_service_states(services, env_file, compose_file, expected)
            return active
        if restart and not report_service_states(services, env_file, compose_file, expected):
            recreate_services(services, env_file, compose_file, runner=runner)
            verify_services(services, active, env_file, compose_file)
        print(f"Active key already configured (key_id={expected}); file left unchanged")
        return active

    key = load_key_file(key_file) if key_file is not None else generate_key()
    validate_key(key)
    expected = key_id_for(key)
    text = env_file.read_text(encoding="utf-8") if env_file.exists() else ""
    rendered = render_env(text, {ACTIVE_VAR: key})
    backup = write_env(env_file, rendered, dry_run=dry_run)
    print(f"Active key:       {'would create' if dry_run else 'created'} key_id={expected}")
    if backup is not None:
        print(f"Environment backup: {backup}")
    if dry_run:
        validate_compose(env_file, compose_file, runner)
        print("Dry-run: no files or services changed")
        return key
    if print_key:
        print(f"Key: {key}")
    else:
        print(f"Key stored in {env_file}; use --print-key only on a trusted terminal")
    if not restart:
        print(f"Restart skipped; run: docker compose up -d --no-deps {' '.join(services)}")
        return key
    recreate_services(services, env_file, compose_file, runner=runner)
    verify_services(services, key, env_file, compose_file)
    print(f"OK: active key_id={expected} is visible in {', '.join(services)}")
    return key


def validate_compose(env_file: Path, compose_file: Path, runner: CommandRunner) -> None:
    if not env_file.exists():
        print("Compose validation skipped: the environment file does not exist yet")
        return
    runner(compose_base(env_file, compose_file) + ["config", "--quiet"])


def rotate(
    *,
    env_file: Path,
    compose_file: Path,
    services: Sequence[str],
    key_file: Path | None,
    restart: bool,
    print_key: bool,
    dry_run: bool,
    runner: CommandRunner = run_command,
) -> str:
    active, values = describe_env(env_file)
    if not active:
        print("No active key to rotate; creating the first one")
        return apply(
            env_file=env_file, compose_file=compose_file, services=services,
            key_file=key_file, restart=restart, print_key=print_key,
            dry_run=dry_run, runner=runner,
        )
    validate_key(active)
    old_id = key_id_for(active)
    new_key = load_key_file(key_file) if key_file is not None else generate_key()
    validate_key(new_key)
    if key_id_for(new_key) == old_id:
        raise ReleaseKeyError("The new key is identical to the active key")
    new_id = key_id_for(new_key)

    verify = parse_verify_keys(values.get(VERIFY_VAR, ""))
    verify[old_id] = active
    if len(verify) > MAX_VERIFY_KEYS:
        raise ReleaseKeyError(
            f"Rotating would exceed {MAX_VERIFY_KEYS} verification keys; remove old entries first"
        )
    encoded = json.dumps(verify, sort_keys=True, separators=(",", ":"))

    text = env_file.read_text(encoding="utf-8")
    rendered = render_env(text, {ACTIVE_VAR: new_key, VERIFY_VAR: encoded})
    backup = write_env(env_file, rendered, dry_run=dry_run)
    print(f"Rotation:         {old_id} -> {new_id}")
    print(f"Previous key:     retained for verification as {old_id}")
    if backup is not None:
        print(f"Environment backup: {backup}")
    if dry_run:
        validate_compose(env_file, compose_file, runner)
        print("Dry-run: no files or services changed")
        return new_key
    if print_key:
        print(f"Key: {new_key}")
    else:
        print(f"Key stored in {env_file}; use --print-key only on a trusted terminal")
    if not restart:
        print(f"Restart skipped; run: docker compose up -d --no-deps {' '.join(services)}")
        return new_key
    recreate_services(services, env_file, compose_file, runner=runner)
    verify_services(services, new_key, env_file, compose_file)
    print(f"OK: active key_id={new_id} is visible in {', '.join(services)}")
    return new_key


def status(
    env_file: Path,
    compose_file: Path,
    services: Sequence[str],
) -> None:
    active, _ = describe_env(env_file)
    expected: str | None = None
    if active:
        try:
            validate_key(active)
        except ReleaseKeyError:
            expected = None
        else:
            expected = key_id_for(active)
    report_service_states(services, env_file, compose_file, expected)
    count = release_count(env_file, compose_file)
    if count is None:
        print("Signed releases:  unavailable (apps-worker is not running)")
    else:
        print(f"Signed releases:  {count}")


def verify(
    env_file: Path,
    compose_file: Path,
    services: Sequence[str],
) -> None:
    active, _ = describe_env(env_file)
    if not active:
        raise ReleaseKeyError(f"No {ACTIVE_VAR} in {env_file}; run 'apply' first")
    validate_key(active)
    verify_services(services, active, env_file, compose_file)
    print(f"OK: key_id={key_id_for(active)} is visible in {', '.join(services)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--env-file", type=Path, default=Path(".env.docker"))
    common.add_argument("--compose-file", type=Path, default=Path("docker-compose.yml"))
    common.add_argument(
        "--service", action="append", dest="services", metavar="NAME",
        help="Service to recreate/verify; repeatable (default: app and apps-worker)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "status", parents=[common],
        help="Show keys and running services (read-only)",
    ).set_defaults(handler="status")

    subparsers.add_parser(
        "plan", parents=[common],
        help="Show what apply would change (read-only)",
    ).set_defaults(handler="plan")

    apply_parser = subparsers.add_parser(
        "apply", parents=[common], help="Create the active key when missing",
    )
    apply_parser.add_argument("--key-file", type=Path)
    apply_parser.add_argument("--no-restart", action="store_true")
    apply_parser.add_argument("--print-key", action="store_true")
    apply_parser.add_argument("--dry-run", action="store_true")
    apply_parser.set_defaults(handler="apply")

    rotate_parser = subparsers.add_parser(
        "rotate", parents=[common],
        help="Generate a new key and retain the previous one for verification",
    )
    rotate_parser.add_argument("--key-file", type=Path)
    rotate_parser.add_argument("--no-restart", action="store_true")
    rotate_parser.add_argument("--print-key", action="store_true")
    rotate_parser.add_argument("--dry-run", action="store_true")
    rotate_parser.set_defaults(handler="rotate")

    subparsers.add_parser(
        "verify", parents=[common],
        help="Check that services see the active key",
    ).set_defaults(handler="verify")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    env_file = args.env_file.resolve()
    compose_file = args.compose_file.resolve()
    services = tuple(args.services or DEFAULT_SERVICES)
    try:
        if args.handler == "status":
            status(env_file, compose_file, services)
        elif args.handler == "plan":
            apply_plan(env_file, compose_file, services)
        elif args.handler == "apply":
            apply(
                env_file=env_file, compose_file=compose_file, services=services,
                key_file=args.key_file, restart=not args.no_restart,
                print_key=args.print_key, dry_run=args.dry_run,
            )
        elif args.handler == "rotate":
            rotate(
                env_file=env_file, compose_file=compose_file, services=services,
                key_file=args.key_file, restart=not args.no_restart,
                print_key=args.print_key, dry_run=args.dry_run,
            )
        elif args.handler == "verify":
            verify(env_file, compose_file, services)
    except ReleaseKeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
