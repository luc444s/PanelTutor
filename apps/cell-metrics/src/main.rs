//! CLI and daemon entrypoint for the read-only cell metrics sampler.
//!
//! A.SPEC 0112 modes (`--once`, `--watch`) keep emitting one JSON object per
//! line on stdout. A.SPEC 0113 adds `--serve`: an AF_UNIX socket daemon that
//! authenticates peers with SO_PEERCRED plus a shared token and speaks the
//! newline protocol `SUBSCRIBE` / `SNAPSHOT` / `PING`. Errors go to stderr.

use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use spanel_cell_metrics::{
    parse_allowed_uids, run_daemon, DaemonConfig, Sampler, Snapshot, DEFAULT_PASSWD_PATH,
    DEFAULT_SOCKET_PATH, DEFAULT_TOKEN_FILE, MAX_INTERVAL_MS, MIN_INTERVAL_MS,
};

const USAGE: &str = "\
Uso (CLI):    spanel-cell-metrics --slug <slug> --uid <uid> [opciones]
Uso (daemon): spanel-cell-metrics --serve --socket <path> --token-file <path> \
--allowed-uids <uids> [opciones]

Muestrea una celda desde cgroups v2 (solo lectura) y emite JSON por línea.

Opciones CLI:
  --slug <slug>          Slug de la celda (minúsculas, dígitos y guiones)
  --uid <uid>            Uid del tenant
  --cgroup-root <path>   Raíz de cgroups v2 (solo tests; defecto /sys/fs/cgroup)
  --interval-ms <ms>     Intervalo entre muestras (250-60000; defecto 1000)
  --once                 Emite un snapshot y termina (modo por defecto)
  --watch                Emite una línea por intervalo hasta SIGINT
  --json                 Salida JSON (siempre activa en v1)

Opciones daemon:
  --serve                Escucha en un socket Unix (solo AF_UNIX, nunca TCP)
  --socket <path>        Socket Unix (defecto /run/spanel/cell-metrics.sock)
  --token-file <path>    Fichero 0600 con el token compartido
                         (defecto /run/secrets/cell_metrics_token)
  --allowed-uids <uids>  Uids de peer permitidos, separados por comas (defecto 0)
  --passwd <path>        Fichero passwd para resolver spanel-<slug>
                         (defecto /etc/passwd)
  --cgroup-root <path>   Raíz de cgroups v2 (defecto /sys/fs/cgroup)

  -h, --help             Muestra esta ayuda
";

struct Args {
    serve: bool,
    slug: Option<String>,
    uid: Option<u64>,
    cgroup_root: PathBuf,
    interval_ms: u64,
    once: bool,
    socket: PathBuf,
    token_file: PathBuf,
    allowed_uids: Vec<u64>,
    passwd: PathBuf,
}

fn next_value(
    iter: &mut impl Iterator<Item = String>,
    flag: &str,
) -> std::result::Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("falta el valor de {flag}"))
}

fn parse_args() -> std::result::Result<Args, String> {
    let mut serve = false;
    let mut slug = None;
    let mut uid = None;
    let mut cgroup_root = PathBuf::from("/sys/fs/cgroup");
    let mut interval_ms = 1000u64;
    let mut once = false;
    let mut watch = false;
    let mut socket = PathBuf::from(DEFAULT_SOCKET_PATH);
    let mut token_file = PathBuf::from(DEFAULT_TOKEN_FILE);
    let mut allowed_uids = vec![0u64];
    let mut passwd = PathBuf::from(DEFAULT_PASSWD_PATH);

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
            "--serve" => serve = true,
            "--socket" => socket = PathBuf::from(next_value(&mut iter, "--socket")?),
            "--token-file" => token_file = PathBuf::from(next_value(&mut iter, "--token-file")?),
            "--allowed-uids" => {
                let raw = next_value(&mut iter, "--allowed-uids")?;
                allowed_uids = parse_allowed_uids(&raw).map_err(|error| error.to_string())?;
            }
            "--passwd" => passwd = PathBuf::from(next_value(&mut iter, "--passwd")?),
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
    if serve {
        return Ok(Args {
            serve,
            slug,
            uid,
            cgroup_root,
            interval_ms,
            once,
            socket,
            token_file,
            allowed_uids,
            passwd,
        });
    }
    Ok(Args {
        serve,
        slug: Some(slug.ok_or_else(|| "falta --slug".to_string())?),
        uid: Some(uid.ok_or_else(|| "falta --uid".to_string())?),
        cgroup_root,
        interval_ms,
        // Without an explicit mode, a single snapshot is the safe default.
        once: once || !watch,
        socket,
        token_file,
        allowed_uids,
        passwd,
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

fn run_cli(args: &Args) -> std::result::Result<(), String> {
    let slug = args
        .slug
        .as_deref()
        .ok_or_else(|| "falta --slug".to_string())?;
    let uid = args.uid.ok_or_else(|| "falta --uid".to_string())?;
    let mut sampler = Sampler::new(&args.cgroup_root, slug, uid, args.interval_ms)
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

fn run(args: &Args) -> std::result::Result<(), String> {
    if args.serve {
        let config = DaemonConfig::new(
            args.socket.clone(),
            args.token_file.clone(),
            args.allowed_uids.clone(),
            args.cgroup_root.clone(),
            args.passwd.clone(),
        );
        return run_daemon(&config).map_err(|error| error.to_string());
    }
    run_cli(args)
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
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("spanel-cell-metrics: {message}");
            ExitCode::FAILURE
        }
    }
}
