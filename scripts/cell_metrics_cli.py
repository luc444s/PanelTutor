#!/usr/bin/env python3
"""Muestra métricas vivas de una celda Spanel (A.SPEC 0112).

Resuelve el uid del tenant desde ``<data-root>/registry.json``, localiza el
binario Rust ``spanel-cell-metrics`` y lo invoca. El binario es de solo lectura
sobre cgroups v2; este script solo dibuja la tabla o reenvía su JSON.

Uso:
    python3 scripts/cell_metrics_cli.py --slug demo --once
    python3 scripts/cell_metrics_cli.py --slug demo --watch --interval-ms 1000
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,61}$")
DEFAULT_DATA_ROOT = "/var/lib/spanel"
DEFAULT_INTERVAL_MS = 1000
MIN_INTERVAL_MS = 250
MAX_INTERVAL_MS = 60000
BUILD_HINT = "cd apps/cell-metrics && cargo build --release"
CLEAR_SCREEN = "\x1b[2J\x1b[H"
REPO_ROOT = Path(__file__).resolve().parents[1]


class CliError(RuntimeError):
    """Error operativo con un mensaje apto para stderr."""


def validate_slug(slug: str) -> str:
    if not isinstance(slug, str) or not SLUG_RE.fullmatch(slug):
        raise CliError(f"slug inválido: {slug!r}")
    return slug


def resolve_uid(data_root: str | Path, slug: str) -> int:
    """Read ``allocations[slug]["uid"]`` from the local registry."""
    slug = validate_slug(slug)
    path = Path(data_root) / "registry.json"
    if not path.is_file():
        raise CliError(f"no se encontró el registro de celdas: {path}")
    try:
        registry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError(f"no se pudo leer {path}: {exc}") from exc
    allocations = registry.get("allocations") if isinstance(registry, dict) else None
    if not isinstance(allocations, dict) or slug not in allocations:
        raise CliError(f"el slug {slug!r} no existe en {path}")
    allocation = allocations[slug]
    uid = allocation.get("uid") if isinstance(allocation, dict) else None
    if not isinstance(uid, int) or isinstance(uid, bool):
        raise CliError(f"el slug {slug!r} no tiene un uid válido en {path}")
    return uid


def locate_binary(explicit: str | None = None) -> Path:
    """Resolve the binary from --bin, the env var, release, then debug."""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    else:
        env_bin = os.environ.get("SPANEL_CELL_METRICS_BIN")
        if env_bin:
            candidates.append(Path(env_bin))
        candidates.append(REPO_ROOT / "apps/cell-metrics/target/release/spanel-cell-metrics")
        candidates.append(REPO_ROOT / "apps/cell-metrics/target/debug/spanel-cell-metrics")

    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate

    if explicit:
        raise CliError(
            f"binario no encontrado: {explicit}\nCompílalo con: {BUILD_HINT}"
        )
    raise CliError(
        "binario spanel-cell-metrics no encontrado.\n"
        f"Compílalo con: {BUILD_HINT}"
    )


def _es(value: float, digits: int) -> str:
    return f"{value:.{digits}f}".replace(".", ",")


def human_bytes(value: Any) -> str:
    if value is None:
        return "—"
    number = float(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    index = 0
    while number >= 1024 and index < len(units) - 1:
        number /= 1024
        index += 1
    if index == 0:
        return f"{int(round(number))} B"
    return f"{_es(number, 2)} {units[index]}"


def human_rate(value: Any) -> str:
    if value is None:
        return "—"
    number = float(value)
    units = ("B/s", "kB/s", "MB/s", "GB/s")
    index = 0
    while number >= 1000 and index < len(units) - 1:
        number /= 1000
        index += 1
    if index == 0:
        return f"{int(round(number))} B/s"
    return f"{_es(number, 1)} {units[index]}"


def _format_ts(ts_ms: Any) -> str:
    try:
        moment = datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return "?"
    return moment.strftime("%Y-%m-%d %H:%M:%SZ")


def _as_float(value: Any) -> float:
    return float(value) if isinstance(value, (int, float)) else 0.0


def render_snapshot(sample: dict[str, Any], interval_ms: int | None = None) -> str:
    """Render one parsed JSON snapshot as the Spanish table."""
    memory = sample.get("memory") or {}
    cpu = sample.get("cpu") or {}
    pids = sample.get("pids") or {}
    pressure = sample.get("pressure") or {}
    io = sample.get("io") or {}

    interval = interval_ms or sample.get("interval_ms") or DEFAULT_INTERVAL_MS
    lines = [
        f"Cell {sample.get('slug', '?')} · uid {sample.get('uid', '?')} · "
        f"{_format_ts(sample.get('ts_ms'))} · intervalo {int(interval) / 1000:.1f}s",
        "",
    ]

    current = memory.get("current_bytes") or 0
    maximum = memory.get("max_bytes")
    ram = f"  {'RAM':<10} {human_bytes(current)} / "
    if maximum is None:
        ram += "sin límite"
    else:
        ram += human_bytes(maximum)
        ram += f"    {round(int(current) * 100 / int(maximum))} %"
    if memory.get("peak_bytes") is not None:
        ram += f"   pico {human_bytes(memory['peak_bytes'])}"
    lines.append(ram)

    cores = _as_float(cpu.get("cores"))
    quota = cpu.get("quota_usec")
    period = cpu.get("period_usec")
    limit = float(quota) / float(period) if quota and period else None
    cpu_line = f"  {'CPU':<10} {_es(cores, 2)} cores"
    if limit:
        cpu_line += f" / {_es(limit, 2)}    {round(cores * 100 / limit)} %"
    cpu_line += f"   throttled {cpu.get('nr_throttled') or 0}"
    lines.append(cpu_line)

    current_pids = pids.get("current") or 0
    max_pids = pids.get("max")
    lines.append(
        f"  {'PIDs':<10} {current_pids} / "
        + ("sin límite" if max_pids is None else str(max_pids))
    )

    def avg10(name: str) -> str:
        value = (pressure.get(name) or {}).get("some_avg10")
        return _es(_as_float(value), 1)

    lines.append(
        f"  {'Presión':<10} CPU {avg10('cpu')} % · RAM {avg10('memory')} %"
        f" · IO {avg10('io')} %"
    )

    lines.append(
        f"  {'I/O':<10} lectura {human_rate(io.get('read_bytes_per_s'))}"
        f" · escritura {human_rate(io.get('write_bytes_per_s'))}"
    )
    lines.extend(["", "  Ctrl-C para salir."])
    return "\n".join(lines) + "\n"


def _parse_sample(line: str) -> dict[str, Any]:
    try:
        sample = json.loads(line)
    except json.JSONDecodeError as exc:
        raise CliError(f"el binario emitió JSON inválido: {exc}: {line!r}") from exc
    if not isinstance(sample, dict):
        raise CliError(f"el binario emitió un snapshot inesperado: {line!r}")
    return sample


def run_once(binary: Path, slug: str, uid: int, json_mode: bool) -> int:
    try:
        result = subprocess.run(
            [
                str(binary),
                "--slug",
                slug,
                "--uid",
                str(uid),
                "--once",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise CliError(f"no se pudo ejecutar {binary}: {exc}") from exc

    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return result.returncode

    output = result.stdout.strip()
    if json_mode:
        print(output)
        return 0
    if not output:
        raise CliError("el binario no emitió ningún snapshot")
    print(render_snapshot(_parse_sample(output.splitlines()[0])), end="")
    return 0


def run_watch(
    binary: Path,
    slug: str,
    uid: int,
    interval_ms: int,
    json_mode: bool,
    clear: bool,
) -> int:
    command = [
        str(binary),
        "--slug",
        slug,
        "--uid",
        str(uid),
        "--watch",
        "--json",
        "--interval-ms",
        str(interval_ms),
    ]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        raise CliError(f"no se pudo ejecutar {binary}: {exc}") from exc

    assert process.stdout is not None
    try:
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            if json_mode:
                print(line, flush=True)
                continue
            sample = _parse_sample(line)
            if clear:
                sys.stdout.write(CLEAR_SCREEN)
            print(render_snapshot(sample, interval_ms), end="", flush=True)
        return process.wait()
    except KeyboardInterrupt:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return 0
    finally:
        if process.poll() is None:
            process.terminate()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Muestra métricas reales de una celda leyendo cgroups v2 a través de "
            "spanel-cell-metrics."
        )
    )
    parser.add_argument("--slug", required=True, help="slug de la celda")
    parser.add_argument(
        "--data-root",
        default=DEFAULT_DATA_ROOT,
        help=f"raíz de datos con registry.json (defecto {DEFAULT_DATA_ROOT})",
    )
    parser.add_argument(
        "--bin",
        default=None,
        help="ruta al binario spanel-cell-metrics",
    )
    parser.add_argument(
        "--interval-ms",
        type=int,
        default=DEFAULT_INTERVAL_MS,
        help=f"intervalo de muestreo ({MIN_INTERVAL_MS}-{MAX_INTERVAL_MS} ms)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="un snapshot y termina")
    mode.add_argument(
        "--watch",
        action="store_true",
        help="redibuja en vivo cada intervalo (modo por defecto)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="imprime las líneas JSON crudas, sin tabla",
    )
    parser.add_argument(
        "--no-clear",
        action="store_true",
        help="no usa secuencias ANSI de limpieza (tests/logs)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not MIN_INTERVAL_MS <= args.interval_ms <= MAX_INTERVAL_MS:
        parser.error(
            f"--interval-ms debe estar entre {MIN_INTERVAL_MS} y {MAX_INTERVAL_MS}"
        )

    try:
        slug = validate_slug(args.slug)
        uid = resolve_uid(args.data_root, slug)
        binary = locate_binary(args.bin)
        if args.once:
            return run_once(binary, slug, uid, args.json)
        return run_watch(
            binary,
            slug,
            uid,
            args.interval_ms,
            args.json,
            clear=not args.no_clear,
        )
    except CliError as exc:
        print(f"cell_metrics_cli: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
