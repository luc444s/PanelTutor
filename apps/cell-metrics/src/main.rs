//! CLI for the read-only cell metrics sampler (A.SPEC 0112).
//!
//! Always emits one JSON object per line on stdout. Errors go to stderr.
//! There is no daemon, socket or service here: `--once` prints one sample and
//! `--watch` prints one sample per interval until SIGINT.

use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use spanel_cell_metrics::{Sampler, Snapshot, MAX_INTERVAL_MS, MIN_INTERVAL_MS};

const USAGE: &str = "\
Uso: spanel-cell-metrics --slug <slug> --uid <uid> [opciones]

Muestrea una celda desde cgroups v2 (solo lectura) y emite JSON por línea.

Opciones:
  --slug <slug>          Slug de la celda (minúsculas, dígitos y guiones)
  --uid <uid>            Uid del tenant
  --cgroup-root <path>   Raíz de cgroups v2 (solo tests; defecto /sys/fs/cgroup)
  --interval-ms <ms>     Intervalo entre muestras (250-60000; defecto 1000)
  --once                 Emite un snapshot y termina (modo por defecto)
  --watch                Emite una línea por intervalo hasta SIGINT
  --json                 Salida JSON (siempre activa en v1)
  -h, --help             Muestra esta ayuda
";

struct Args {
    slug: String,
    uid: u64,
    cgroup_root: PathBuf,
    interval_ms: u64,
    once: bool,
}

fn next_value(
    iter: &mut impl Iterator<Item = String>,
    flag: &str,
) -> std::result::Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("falta el valor de {flag}"))
}

fn parse_args() -> std::result::Result<Args, String> {
    let mut slug = None;
    let mut uid = None;
    let mut cgroup_root = PathBuf::from("/sys/fs/cgroup");
    let mut interval_ms = 1000u64;
    let mut once = false;
    let mut watch = false;

    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--slug" => slug = Some(next_value(&mut iter, "--slug")?),
            "--uid" => {
                let raw = next_value(&mut iter, "--uid")?;
                let value = raw
                    .parse::<u64>()
                    .map_err(|_| format!("--uid inválido: {raw}"))?;
                uid = Some(value);
            }
            "--cgroup-root" => cgroup_root = PathBuf::from(next_value(&mut iter, "--cgroup-root")?),
            "--interval-ms" => {
                let raw = next_value(&mut iter, "--interval-ms")?;
                let value = raw
                    .parse::<u64>()
                    .map_err(|_| format!("--interval-ms inválido: {raw}"))?;
                if !(MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&value) {
                    return Err(format!(
                        "--interval-ms debe estar entre {MIN_INTERVAL_MS} y {MAX_INTERVAL_MS}: {value}"
                    ));
                }
                interval_ms = value;
            }
            "--once" => once = true,
            "--watch" => watch = true,
            // v1 always emits JSON; the flag is accepted for clarity.
            "--json" => {}
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("argumento desconocido: {other}")),
        }
    }

    if once && watch {
        return Err("--once y --watch son mutuamente excluyentes".to_string());
    }
    Ok(Args {
        slug: slug.ok_or_else(|| "falta --slug".to_string())?,
        uid: uid.ok_or_else(|| "falta --uid".to_string())?,
        cgroup_root,
        interval_ms,
        // Without an explicit mode, a single snapshot is the safe default.
        once: once || !watch,
    })
}

fn write_snapshot(out: &mut impl Write, snapshot: &Snapshot) -> std::result::Result<bool, String> {
    let result = writeln!(out, "{}", snapshot.to_json()).and_then(|()| out.flush());
    match result {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(error) => Err(format!("no se pudo escribir en stdout: {error}")),
    }
}

fn run(args: Args) -> std::result::Result<(), String> {
    let mut sampler = Sampler::new(&args.cgroup_root, &args.slug, args.uid, args.interval_ms)
        .map_err(|error| error.to_string())?;

    // A single snapshot needs two samples to report real CPU and I/O rates.
    // Take a short warmup sample and discard it; `--watch` keeps its first
    // emitted line as warmup so the terminal shows something immediately.
    if args.once {
        sampler.sample().map_err(|error| error.to_string())?;
        thread::sleep(Duration::from_millis(250));
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();
    loop {
        let snapshot = sampler.sample().map_err(|error| error.to_string())?;
        if !write_snapshot(&mut out, &snapshot)? || args.once {
            break;
        }
        thread::sleep(Duration::from_millis(args.interval_ms));
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("spanel-cell-metrics: {message}");
            eprintln!();
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("spanel-cell-metrics: {message}");
            ExitCode::FAILURE
        }
    }
}
