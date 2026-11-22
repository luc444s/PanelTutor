//! Read-only cgroups v2 sampler for a Spanel cell (A.SPEC 0112).
//!
//! The sampler never writes cgroups, never opens the network and never runs
//! external commands. It only reads the two cgroup trees of a rootless cell:
//!
//! - `<root>/system.slice/spanel-cell-<slug>.service`
//! - `<root>/user.slice/user-<uid>.slice/user@<uid>.service`
//!
//! Counters are accumulated; CPU cores and I/O rates are derived from deltas
//! against the previous sample using a monotonic clock.

use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_SLUG_LEN: usize = 63;

pub const MIN_INTERVAL_MS: u64 = 250;
pub const MAX_INTERVAL_MS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsError(String);

impl MetricsError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for MetricsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MetricsError {}

pub type Result<T> = std::result::Result<T, MetricsError>;

fn invalid(message: impl Into<String>) -> MetricsError {
    MetricsError::new(message)
}

/// A slug is interpolated into a filesystem path, so it is validated first.
pub fn validate_slug(slug: &str) -> Result<()> {
    if slug.is_empty() || slug.len() > MAX_SLUG_LEN {
        return Err(invalid(format!("slug inválido: {slug:?}")));
    }
    let Some(first) = slug.chars().next() else {
        return Err(invalid("slug vacío"));
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(invalid(format!("slug inválido: {slug:?}")));
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(invalid(format!("slug inválido: {slug:?}")));
    }
    Ok(())
}

pub fn validate_interval_ms(interval_ms: u64) -> Result<()> {
    if !(MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&interval_ms) {
        return Err(invalid(format!(
            "--interval-ms debe estar entre {MIN_INTERVAL_MS} y {MAX_INTERVAL_MS}: {interval_ms}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

pub fn parse_u64(text: &str) -> Result<u64> {
    let value = text.trim();
    value
        .parse::<u64>()
        .map_err(|_| invalid(format!("valor entero inválido: {value:?}")))
}

pub fn parse_f64(text: &str) -> Result<f64> {
    let value = text.trim();
    value
        .parse::<f64>()
        .map_err(|_| invalid(format!("valor decimal inválido: {value:?}")))
}

/// `memory.max` / `pids.max` use the literal `max` for "no limit".
pub fn parse_limit(text: &str) -> Result<Option<u64>> {
    let value = text.trim();
    if value == "max" {
        Ok(None)
    } else {
        parse_u64(value).map(Some)
    }
}

/// Read a `key value` line from a flat-keyed file such as `cpu.stat`.
pub fn parse_keyed_u64(text: &str, key: &str) -> Result<Option<u64>> {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some(key) {
            if let Some(value) = parts.next() {
                return parse_u64(value).map(Some);
            }
        }
    }
    Ok(None)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuStat {
    pub usage_usec: u64,
    pub nr_throttled: u64,
}

pub fn parse_cpu_stat(text: &str) -> Result<CpuStat> {
    Ok(CpuStat {
        usage_usec: parse_keyed_u64(text, "usage_usec")?.unwrap_or(0),
        nr_throttled: parse_keyed_u64(text, "nr_throttled")?.unwrap_or(0),
    })
}

pub fn parse_memory_events(text: &str) -> Result<u64> {
    Ok(parse_keyed_u64(text, "oom_kill")?.unwrap_or(0))
}

/// Breakdown from `memory.stat`. `anon + kernel` is the non-reclaimable
/// footprint; `file` is page cache (including shared binary text) and is
/// reclaimed by the kernel under pressure. `slab` is a subset of `kernel`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryStat {
    pub anon_bytes: u64,
    pub file_bytes: u64,
    pub kernel_bytes: u64,
    pub slab_bytes: u64,
}

pub fn parse_memory_stat(text: &str) -> Result<MemoryStat> {
    Ok(MemoryStat {
        anon_bytes: parse_keyed_u64(text, "anon")?.unwrap_or(0),
        file_bytes: parse_keyed_u64(text, "file")?.unwrap_or(0),
        kernel_bytes: parse_keyed_u64(text, "kernel")?.unwrap_or(0),
        slab_bytes: parse_keyed_u64(text, "slab")?.unwrap_or(0),
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuMax {
    pub quota_usec: Option<u64>,
    pub period_usec: Option<u64>,
}

pub fn parse_cpu_max(text: &str) -> Result<CpuMax> {
    let mut parts = text.split_whitespace();
    let quota = parts.next().ok_or_else(|| invalid("cpu.max vacío"))?;
    let period = parts.next().ok_or_else(|| invalid("cpu.max sin periodo"))?;
    Ok(CpuMax {
        quota_usec: if quota == "max" {
            None
        } else {
            Some(parse_u64(quota)?)
        },
        period_usec: if period == "max" {
            None
        } else {
            Some(parse_u64(period)?)
        },
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PressureValue {
    pub some_avg10: f64,
    pub full_avg10: f64,
}

pub fn parse_pressure(text: &str) -> Result<PressureValue> {
    let mut value = PressureValue::default();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(kind) = parts.next() else {
            continue;
        };
        let mut avg10 = None;
        for token in parts {
            if let Some(raw) = token.strip_prefix("avg10=") {
                avg10 = Some(parse_f64(raw)?);
            }
        }
        let Some(avg10) = avg10 else {
            continue;
        };
        match kind {
            "some" => value.some_avg10 = avg10,
            "full" => value.full_avg10 = avg10,
            _ => {}
        }
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IoCounters {
    pub read_bytes: u64,
    pub write_bytes: u64,
}

pub fn parse_io_stat(text: &str) -> Result<IoCounters> {
    let mut counters = IoCounters::default();
    for line in text.lines() {
        for token in line.split_whitespace() {
            if let Some(raw) = token.strip_prefix("rbytes=") {
                counters.read_bytes = counters.read_bytes.saturating_add(parse_u64(raw)?);
            } else if let Some(raw) = token.strip_prefix("wbytes=") {
                counters.write_bytes = counters.write_bytes.saturating_add(parse_u64(raw)?);
            }
        }
    }
    Ok(counters)
}

// ---------------------------------------------------------------------------
// Cgroup path resolution
// ---------------------------------------------------------------------------

/// Remove any path nested inside another one so a parent tree is counted once.
pub fn dedupe_prefixes(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.sort_by_key(|path| path.components().count());
    let mut kept: Vec<PathBuf> = Vec::new();
    for path in paths {
        if kept.iter().any(|parent| path.starts_with(parent)) {
            continue;
        }
        kept.push(path);
    }
    kept
}

/// Resolve the existing cgroup trees of a cell, never escaping `cgroup_root`.
pub fn cgroup_paths(cgroup_root: &Path, slug: &str, uid: u64) -> Result<Vec<PathBuf>> {
    validate_slug(slug)?;

    let root = fs::canonicalize(cgroup_root).map_err(|error| {
        invalid(format!(
            "no se pudo resolver el cgroup root {}: {error}",
            cgroup_root.display()
        ))
    })?;

    let candidates = [
        cgroup_root
            .join("system.slice")
            .join(format!("spanel-cell-{slug}.service")),
        cgroup_root
            .join("user.slice")
            .join(format!("user-{uid}.slice"))
            .join(format!("user@{uid}.service")),
    ];

    let mut resolved = Vec::new();
    for candidate in candidates {
        if !candidate.is_dir() {
            continue;
        }
        let canonical = fs::canonicalize(&candidate).map_err(|error| {
            invalid(format!(
                "no se pudo resolver el cgroup {}: {error}",
                candidate.display()
            ))
        })?;
        // A symlink pointing outside the cgroup root is ignored.
        if !canonical.is_dir() || !canonical.starts_with(&root) {
            continue;
        }
        if !resolved.contains(&canonical) {
            resolved.push(canonical);
        }
    }

    if resolved.is_empty() {
        return Err(invalid(format!(
            "no existe ningún cgroup para la celda {slug:?} (uid {uid}); buscados en {}",
            cgroup_root.display()
        )));
    }

    Ok(dedupe_prefixes(resolved))
}

// ---------------------------------------------------------------------------
// Sampling
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub usage_usec: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Memory {
    pub current_bytes: u64,
    pub peak_bytes: Option<u64>,
    pub max_bytes: Option<u64>,
    pub oom_kill: u64,
    pub anon_bytes: u64,
    pub file_bytes: u64,
    pub kernel_bytes: u64,
    pub slab_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Cpu {
    pub usage_usec: u64,
    pub cores: f64,
    pub quota_usec: Option<u64>,
    pub period_usec: Option<u64>,
    pub nr_throttled: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pids {
    pub current: u64,
    pub max: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Pressure {
    pub cpu: PressureValue,
    pub memory: PressureValue,
    pub io: PressureValue,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Io {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_bytes_per_s: Option<f64>,
    pub write_bytes_per_s: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub ts_ms: u64,
    pub slug: String,
    pub uid: u64,
    pub interval_ms: u64,
    pub warmup: bool,
    pub memory: Memory,
    pub cpu: Cpu,
    pub pids: Pids,
    pub pressure: Pressure,
    pub io: Io,
}

fn read_optional(tree: &Path, file: &str) -> Option<String> {
    fs::read_to_string(tree.join(file)).ok()
}

fn sum_u64(roots: &[PathBuf], file: &str) -> Result<u64> {
    let mut total = 0u64;
    for root in roots {
        if let Some(text) = read_optional(root, file) {
            total = total.saturating_add(parse_u64(&text)?);
        }
    }
    Ok(total)
}

fn sum_memory_stat(roots: &[PathBuf]) -> Result<MemoryStat> {
    let mut total = MemoryStat::default();
    for root in roots {
        if let Some(text) = read_optional(root, "memory.stat") {
            let stat = parse_memory_stat(&text)?;
            total.anon_bytes = total.anon_bytes.saturating_add(stat.anon_bytes);
            total.file_bytes = total.file_bytes.saturating_add(stat.file_bytes);
            total.kernel_bytes = total.kernel_bytes.saturating_add(stat.kernel_bytes);
            total.slab_bytes = total.slab_bytes.saturating_add(stat.slab_bytes);
        }
    }
    Ok(total)
}

/// Most restrictive integer limit across the cell trees.
///
/// Usage counters are additive, but limits are not: the plan lives in the
/// user-manager tree while the cell's system slice is usually unlimited. The
/// visible limit is the smallest non-`max` value.
fn min_limit(roots: &[PathBuf], file: &str) -> Result<Option<u64>> {
    let mut best: Option<u64> = None;
    for root in roots {
        if let Some(text) = read_optional(root, file) {
            if let Some(value) = parse_limit(&text)? {
                best = Some(best.map_or(value, |current| current.min(value)));
            }
        }
    }
    Ok(best)
}

/// Highest value across the cell trees (used only for `memory.peak`).
fn max_limit(roots: &[PathBuf], file: &str) -> Result<Option<u64>> {
    let mut best: Option<u64> = None;
    for root in roots {
        if let Some(text) = read_optional(root, file) {
            if let Some(value) = parse_limit(&text)? {
                best = Some(best.map_or(value, |current| current.max(value)));
            }
        }
    }
    Ok(best)
}

fn sum_cpu_stat(roots: &[PathBuf]) -> Result<CpuStat> {
    let mut total = CpuStat::default();
    for root in roots {
        if let Some(text) = read_optional(root, "cpu.stat") {
            let stat = parse_cpu_stat(&text)?;
            total.usage_usec = total.usage_usec.saturating_add(stat.usage_usec);
            total.nr_throttled = total.nr_throttled.saturating_add(stat.nr_throttled);
        }
    }
    Ok(total)
}

fn most_restrictive_cpu_max(roots: &[PathBuf]) -> Result<CpuMax> {
    let mut best: Option<(f64, u64, u64)> = None;
    for root in roots {
        if let Some(text) = read_optional(root, "cpu.max") {
            let cpu_max = parse_cpu_max(&text)?;
            if let (Some(quota), Some(period)) = (cpu_max.quota_usec, cpu_max.period_usec) {
                if period == 0 {
                    continue;
                }
                let ratio = quota as f64 / period as f64;
                let better = match best {
                    Some((current, _, _)) => ratio < current,
                    None => true,
                };
                if better {
                    best = Some((ratio, quota, period));
                }
            }
        }
    }
    Ok(match best {
        Some((_, quota, period)) => CpuMax {
            quota_usec: Some(quota),
            period_usec: Some(period),
        },
        None => CpuMax::default(),
    })
}

fn sum_memory_events(roots: &[PathBuf]) -> Result<u64> {
    let mut total = 0u64;
    for root in roots {
        if let Some(text) = read_optional(root, "memory.events") {
            total = total.saturating_add(parse_memory_events(&text)?);
        }
    }
    Ok(total)
}

fn max_pressure(roots: &[PathBuf], file: &str) -> Result<PressureValue> {
    let mut best = PressureValue::default();
    for root in roots {
        if let Some(text) = read_optional(root, file) {
            let value = parse_pressure(&text)?;
            best.some_avg10 = best.some_avg10.max(value.some_avg10);
            best.full_avg10 = best.full_avg10.max(value.full_avg10);
        }
    }
    Ok(best)
}

fn sum_io_stat(roots: &[PathBuf]) -> Result<IoCounters> {
    let mut total = IoCounters::default();
    for root in roots {
        if let Some(text) = read_optional(root, "io.stat") {
            let io = parse_io_stat(&text)?;
            total.read_bytes = total.read_bytes.saturating_add(io.read_bytes);
            total.write_bytes = total.write_bytes.saturating_add(io.write_bytes);
        }
    }
    Ok(total)
}

/// Cores consumed between two cumulative `usage_usec` values.
pub fn compute_cores(previous_usage_usec: u64, current_usage_usec: u64, elapsed_secs: f64) -> f64 {
    if elapsed_secs <= 0.0 {
        return 0.0;
    }
    let delta = current_usage_usec.saturating_sub(previous_usage_usec);
    delta as f64 / 1_000_000.0 / elapsed_secs
}

/// Per-second rate between two cumulative byte counters.
pub fn compute_rate(previous: u64, current: u64, elapsed_secs: f64) -> f64 {
    if elapsed_secs <= 0.0 {
        return 0.0;
    }
    let delta = current.saturating_sub(previous);
    delta as f64 / elapsed_secs
}

fn now_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| invalid(format!("reloj del sistema inválido: {error}")))?;
    u64::try_from(elapsed.as_millis()).map_err(|_| invalid("timestamp fuera de rango para u64"))
}

/// Stateful sampler: keeps only the previous counters and its monotonic time.
#[derive(Debug)]
pub struct Sampler {
    slug: String,
    uid: u64,
    interval_ms: u64,
    roots: Vec<PathBuf>,
    previous: Option<(Counters, Instant)>,
}

impl Sampler {
    pub fn new(cgroup_root: &Path, slug: &str, uid: u64, interval_ms: u64) -> Result<Self> {
        validate_interval_ms(interval_ms)?;
        let roots = cgroup_paths(cgroup_root, slug, uid)?;
        Ok(Self {
            slug: slug.to_string(),
            uid,
            interval_ms,
            roots,
            previous: None,
        })
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    pub fn sample(&mut self) -> Result<Snapshot> {
        let now = Instant::now();
        let ts_ms = now_ms()?;

        let cpu_stat = sum_cpu_stat(&self.roots)?;
        let cpu_max = most_restrictive_cpu_max(&self.roots)?;
        let io = sum_io_stat(&self.roots)?;
        let memory_stat = sum_memory_stat(&self.roots)?;
        let counters = Counters {
            usage_usec: cpu_stat.usage_usec,
            read_bytes: io.read_bytes,
            write_bytes: io.write_bytes,
        };

        let (warmup, cores, read_rate, write_rate) = match self.previous {
            None => (true, 0.0, None, None),
            Some((previous, previous_at)) => {
                let elapsed = now.saturating_duration_since(previous_at).as_secs_f64();
                (
                    false,
                    compute_cores(previous.usage_usec, counters.usage_usec, elapsed),
                    Some(compute_rate(
                        previous.read_bytes,
                        counters.read_bytes,
                        elapsed,
                    )),
                    Some(compute_rate(
                        previous.write_bytes,
                        counters.write_bytes,
                        elapsed,
                    )),
                )
            }
        };

        let snapshot = Snapshot {
            ts_ms,
            slug: self.slug.clone(),
            uid: self.uid,
            interval_ms: self.interval_ms,
            warmup,
            memory: Memory {
                current_bytes: sum_u64(&self.roots, "memory.current")?,
                peak_bytes: max_limit(&self.roots, "memory.peak")?,
                max_bytes: min_limit(&self.roots, "memory.max")?,
                oom_kill: sum_memory_events(&self.roots)?,
                anon_bytes: memory_stat.anon_bytes,
                file_bytes: memory_stat.file_bytes,
                kernel_bytes: memory_stat.kernel_bytes,
                slab_bytes: memory_stat.slab_bytes,
            },
            cpu: Cpu {
                usage_usec: cpu_stat.usage_usec,
                cores,
                quota_usec: cpu_max.quota_usec,
                period_usec: cpu_max.period_usec,
                nr_throttled: cpu_stat.nr_throttled,
            },
            pids: Pids {
                current: sum_u64(&self.roots, "pids.current")?,
                max: min_limit(&self.roots, "pids.max")?,
            },
            pressure: Pressure {
                cpu: max_pressure(&self.roots, "cpu.pressure")?,
                memory: max_pressure(&self.roots, "memory.pressure")?,
                io: max_pressure(&self.roots, "io.pressure")?,
            },
            io: Io {
                read_bytes: io.read_bytes,
                write_bytes: io.write_bytes,
                read_bytes_per_s: read_rate,
                write_bytes_per_s: write_rate,
            },
        };

        self.previous = Some((counters, now));
        Ok(snapshot)
    }
}

// ---------------------------------------------------------------------------
// JSON (manual formatting, no external crates)
// ---------------------------------------------------------------------------

fn json_u64(value: Option<u64>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => "null".to_string(),
    }
}

fn json_f64(value: f64) -> String {
    if !value.is_finite() {
        return "null".to_string();
    }
    let mut text = format!("{value:.6}");
    while text.ends_with('0') {
        text.pop();
    }
    if text.ends_with('.') {
        text.pop();
    }
    if text == "-0" {
        text = "0".to_string();
    }
    text
}

fn json_opt_f64(value: Option<f64>) -> String {
    match value {
        Some(value) => json_f64(value),
        None => "null".to_string(),
    }
}

fn json_pressure(value: &PressureValue) -> String {
    format!(
        "{{\"some_avg10\":{},\"full_avg10\":{}}}",
        json_f64(value.some_avg10),
        json_f64(value.full_avg10)
    )
}

impl Snapshot {
    /// One-line JSON object with the field order documented in the A.SPEC.
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(512);
        let _ = write!(
            out,
            "{{\"ts_ms\":{},\"slug\":\"{}\",\"uid\":{},\"interval_ms\":{},\"warmup\":{},",
            self.ts_ms, self.slug, self.uid, self.interval_ms, self.warmup
        );
        let _ = write!(
            out,
            "\"memory\":{{\"current_bytes\":{},\"peak_bytes\":{},\"max_bytes\":{},\"oom_kill\":{},\"anon_bytes\":{},\"file_bytes\":{},\"kernel_bytes\":{},\"slab_bytes\":{}}},",
            self.memory.current_bytes,
            json_u64(self.memory.peak_bytes),
            json_u64(self.memory.max_bytes),
            self.memory.oom_kill,
            self.memory.anon_bytes,
            self.memory.file_bytes,
            self.memory.kernel_bytes,
            self.memory.slab_bytes
        );
        let _ = write!(
            out,
            "\"cpu\":{{\"usage_usec\":{},\"cores\":{},\"quota_usec\":{},\"period_usec\":{},\"nr_throttled\":{}}},",
            self.cpu.usage_usec,
            json_f64(self.cpu.cores),
            json_u64(self.cpu.quota_usec),
            json_u64(self.cpu.period_usec),
            self.cpu.nr_throttled
        );
        let _ = write!(
            out,
            "\"pids\":{{\"current\":{},\"max\":{}}},",
            self.pids.current,
            json_u64(self.pids.max)
        );
        let _ = write!(
            out,
            "\"pressure\":{{\"cpu\":{},\"memory\":{},\"io\":{}}},",
            json_pressure(&self.pressure.cpu),
            json_pressure(&self.pressure.memory),
            json_pressure(&self.pressure.io)
        );
        let _ = write!(
            out,
            "\"io\":{{\"read_bytes\":{},\"write_bytes\":{},\"read_bytes_per_s\":{},\"write_bytes_per_s\":{}}}",
            self.io.read_bytes,
            self.io.write_bytes,
            json_opt_f64(self.io.read_bytes_per_s),
            json_opt_f64(self.io.write_bytes_per_s)
        );
        out.push('}');
        out
    }
}

// ---------------------------------------------------------------------------
// Daemon (A.SPEC 0113): AF_UNIX socket, token + SO_PEERCRED, line protocol
// ---------------------------------------------------------------------------

pub const DEFAULT_SOCKET_PATH: &str = "/run/spanel/cell-metrics.sock";
pub const DEFAULT_TOKEN_FILE: &str = "/run/secrets/cell_metrics_token";
pub const DEFAULT_PASSWD_PATH: &str = "/etc/passwd";
pub const DEFAULT_READ_TIMEOUT_SECS: u64 = 5;
const MAX_COMMAND_BYTES: usize = 4096;
const ACCEPT_POLL_INTERVAL_MS: u64 = 20;

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub token_file: PathBuf,
    pub allowed_uids: Vec<u64>,
    pub cgroup_root: PathBuf,
    pub passwd_path: PathBuf,
}

impl DaemonConfig {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        token_file: impl Into<PathBuf>,
        allowed_uids: Vec<u64>,
        cgroup_root: impl Into<PathBuf>,
        passwd_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            token_file: token_file.into(),
            allowed_uids,
            cgroup_root: cgroup_root.into(),
            passwd_path: passwd_path.into(),
        }
    }
}

/// Parse a comma-separated `--allowed-uids` value (`0`, `0,1000`).
pub fn parse_allowed_uids(text: &str) -> Result<Vec<u64>> {
    let mut uids = Vec::new();
    for part in text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(invalid("--allowed-uids contiene un valor vacío"));
        }
        let uid = part
            .parse::<u64>()
            .map_err(|_| invalid(format!("uid inválido en --allowed-uids: {part:?}")))?;
        if !uids.contains(&uid) {
            uids.push(uid);
        }
    }
    if uids.is_empty() {
        return Err(invalid("--allowed-uids no puede estar vacío"));
    }
    Ok(uids)
}

/// Read the shared token once at startup. It must be non-empty and one word,
/// because the line protocol separates fields with whitespace.
pub fn read_token(path: &Path) -> Result<String> {
    let raw = fs::read_to_string(path).map_err(|error| {
        invalid(format!(
            "no se pudo leer el token {}: {error}",
            path.display()
        ))
    })?;
    let token = raw.trim_end_matches(['\n', '\r']).to_string();
    if token.is_empty() {
        return Err(invalid(format!("el token {} está vacío", path.display())));
    }
    if token.chars().any(char::is_whitespace) {
        return Err(invalid(format!(
            "el token {} contiene espacios",
            path.display()
        )));
    }
    Ok(token)
}

/// Constant-time comparison: never short-circuits on the first difference.
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(a ^ b);
    }
    difference == 0
}

/// Resolve the cell uid from `<passwd>` (`spanel-<slug>`), never from the registry.
pub fn resolve_uid_from_passwd(passwd: &Path, slug: &str) -> Result<u64> {
    validate_slug(slug)?;
    let wanted = format!("spanel-{slug}");
    let text = fs::read_to_string(passwd)
        .map_err(|error| invalid(format!("no se pudo leer {}: {error}", passwd.display())))?;
    for line in text.lines() {
        let mut fields = line.split(':');
        if fields.next() != Some(wanted.as_str()) {
            continue;
        }
        let _password = fields.next();
        let raw_uid = fields
            .next()
            .ok_or_else(|| invalid(format!("el usuario {wanted} no tiene uid")))?;
        return raw_uid
            .parse::<u64>()
            .map_err(|_| invalid(format!("uid inválido para {wanted}: {raw_uid:?}")));
    }
    Err(invalid(format!(
        "no existe el usuario {wanted} en {}",
        passwd.display()
    )))
}

/// Line protocol commands. Syntax only: slug and interval are validated by the
/// connection handler so it can answer with a precise `ERROR <code>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolCommand {
    Subscribe {
        slug: String,
        interval_ms: u64,
        token: String,
    },
    Snapshot {
        slug: String,
        token: String,
    },
    Ping,
}

pub fn parse_protocol_line(line: &str) -> Result<ProtocolCommand> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.as_slice() {
        ["PING"] => Ok(ProtocolCommand::Ping),
        ["SUBSCRIBE", slug, interval_ms, token] => {
            let interval_ms = parse_u64(interval_ms)?;
            Ok(ProtocolCommand::Subscribe {
                slug: (*slug).to_string(),
                interval_ms,
                token: (*token).to_string(),
            })
        }
        ["SNAPSHOT", slug, token] => Ok(ProtocolCommand::Snapshot {
            slug: (*slug).to_string(),
            token: (*token).to_string(),
        }),
        [] => Err(invalid("comando vacío")),
        _ => Err(invalid("comando desconocido o con argumentos incorrectos")),
    }
}

#[repr(C)]
struct PeerCredentials {
    pid: i32,
    uid: u32,
    gid: u32,
}

const SOL_SOCKET: i32 = 1;
const SO_PEERCRED: i32 = 17;

extern "C" {
    fn getsockopt(
        socket: i32,
        level: i32,
        option_name: i32,
        option_value: *mut std::ffi::c_void,
        option_len: *mut u32,
    ) -> i32;
}

/// Peer uid from `SO_PEERCRED` (Linux/Android). std has no stable wrapper, so
/// this declares the libc symbol that std already links; no Cargo dependency.
pub fn peer_uid(stream: &UnixStream) -> Result<u64> {
    use std::os::unix::io::AsRawFd;

    let mut credentials = PeerCredentials {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<PeerCredentials>() as u32;
    // SAFETY: `credentials` is a valid writable `ucred` buffer and `length`
    // describes its size; the fd belongs to a live `UnixStream`.
    let result = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut credentials as *mut PeerCredentials).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(invalid(format!(
            "no se pudo leer SO_PEERCRED: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(u64::from(credentials.uid))
}

fn write_protocol_error(mut stream: &UnixStream, code: &str, message: &str) {
    let message = message.replace(['\n', '\r'], " ");
    let _ = writeln!(stream, "ERROR {code} {message}");
    let _ = stream.flush();
}

fn write_json_line(stream: &mut UnixStream, json: &str) -> bool {
    writeln!(stream, "{json}")
        .and_then(|()| stream.flush())
        .is_ok()
}

fn sample_once(sampler: &mut Sampler) -> Result<Snapshot> {
    // A single snapshot needs two reads to report real CPU and I/O rates, like
    // the 0112 `--once` mode.
    sampler.sample()?;
    thread::sleep(Duration::from_millis(250));
    sampler.sample()
}

fn handle_subscribe(
    mut stream: UnixStream,
    config: &DaemonConfig,
    token: &str,
    slug: &str,
    interval_ms: u64,
    received_token: &str,
) -> Result<()> {
    if !constant_time_eq(token, received_token) {
        write_protocol_error(&stream, "unauthorized", "token inválido");
        return Ok(());
    }
    if let Err(error) = validate_slug(slug) {
        write_protocol_error(&stream, "invalid_slug", &error.to_string());
        return Ok(());
    }
    if let Err(error) = validate_interval_ms(interval_ms) {
        write_protocol_error(&stream, "invalid_interval", &error.to_string());
        return Ok(());
    }
    let uid = match resolve_uid_from_passwd(&config.passwd_path, slug) {
        Ok(uid) => uid,
        Err(error) => {
            write_protocol_error(&stream, "unknown_user", &error.to_string());
            return Ok(());
        }
    };
    let mut sampler = match Sampler::new(&config.cgroup_root, slug, uid, interval_ms) {
        Ok(sampler) => sampler,
        Err(error) => {
            write_protocol_error(&stream, "unavailable", &error.to_string());
            return Ok(());
        }
    };

    loop {
        let snapshot = match sampler.sample() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                write_protocol_error(&stream, "sampling_failed", &error.to_string());
                return Ok(());
            }
        };
        if !write_json_line(&mut stream, &snapshot.to_json()) {
            // The client closed: end this connection and its sampler.
            return Ok(());
        }
        thread::sleep(Duration::from_millis(interval_ms));
    }
}

fn handle_snapshot(
    mut stream: UnixStream,
    config: &DaemonConfig,
    token: &str,
    slug: &str,
    received_token: &str,
) -> Result<()> {
    if !constant_time_eq(token, received_token) {
        write_protocol_error(&stream, "unauthorized", "token inválido");
        return Ok(());
    }
    if let Err(error) = validate_slug(slug) {
        write_protocol_error(&stream, "invalid_slug", &error.to_string());
        return Ok(());
    }
    let uid = match resolve_uid_from_passwd(&config.passwd_path, slug) {
        Ok(uid) => uid,
        Err(error) => {
            write_protocol_error(&stream, "unknown_user", &error.to_string());
            return Ok(());
        }
    };
    let mut sampler = match Sampler::new(&config.cgroup_root, slug, uid, 1000) {
        Ok(sampler) => sampler,
        Err(error) => {
            write_protocol_error(&stream, "unavailable", &error.to_string());
            return Ok(());
        }
    };
    match sample_once(&mut sampler) {
        Ok(snapshot) => {
            write_json_line(&mut stream, &snapshot.to_json());
        }
        Err(error) => write_protocol_error(&stream, "sampling_failed", &error.to_string()),
    }
    Ok(())
}

/// Handle one accepted connection. Every connection owns its `Sampler`; there
/// is no shared state between clients. Validation happens before any cgroup
/// is opened.
pub fn handle_connection(mut stream: UnixStream, config: &DaemonConfig, token: &str) -> Result<()> {
    let uid = peer_uid(&stream)?;
    if !config.allowed_uids.contains(&uid) {
        write_protocol_error(&stream, "peer_denied", "uid de peer no permitido");
        return Ok(());
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS)))
        .map_err(|error| invalid(format!("no se pudo fijar el timeout: {error}")))?;

    let mut line = String::new();
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|error| invalid(format!("no se pudo clonar el socket: {error}")))?,
    );
    match reader.read_line(&mut line) {
        Ok(0) => return Ok(()),
        Ok(_) => {}
        Err(error) => return Err(invalid(format!("no se pudo leer el comando: {error}"))),
    }
    if line.len() > MAX_COMMAND_BYTES {
        write_protocol_error(&stream, "invalid_request", "comando demasiado largo");
        return Ok(());
    }

    let command = match parse_protocol_line(&line) {
        Ok(command) => command,
        Err(error) => {
            write_protocol_error(&stream, "invalid_request", &error.to_string());
            return Ok(());
        }
    };

    match command {
        ProtocolCommand::Ping => {
            write_json_line(&mut stream, "{\"ok\":true,\"pong\":true}");
            Ok(())
        }
        ProtocolCommand::Subscribe {
            slug,
            interval_ms,
            token: received_token,
        } => handle_subscribe(stream, config, token, &slug, interval_ms, &received_token),
        ProtocolCommand::Snapshot {
            slug,
            token: received_token,
        } => handle_snapshot(stream, config, token, &slug, &received_token),
    }
}

/// Bind the AF_UNIX socket, removing only a stale socket at that path, and set
/// it to `0600`. A non-socket file is never deleted.
pub fn bind_unix_socket(path: &Path) -> Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            use std::os::unix::fs::FileTypeExt;
            if !metadata.file_type().is_socket() {
                return Err(invalid(format!(
                    "{} existe y no es un socket; no se elimina",
                    path.display()
                )));
            }
            fs::remove_file(path).map_err(|error| {
                invalid(format!(
                    "no se pudo eliminar el socket huérfano {}: {error}",
                    path.display()
                ))
            })?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(invalid(format!(
                "no se pudo inspeccionar {}: {error}",
                path.display()
            )));
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| invalid(format!("no se pudo crear {}: {error}", parent.display())))?;
    }
    let listener = UnixListener::bind(path).map_err(|error| {
        invalid(format!(
            "no se pudo escuchar en {}: {error}",
            path.display()
        ))
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
        invalid(format!(
            "no se pudieron fijar los permisos de {}: {error}",
            path.display()
        ))
    })?;
    Ok(listener)
}

/// Accept loop. Non-blocking accept plus a stop flag keeps tests deterministic;
/// every connection runs in its own thread.
pub fn serve_listener(
    listener: UnixListener,
    config: &DaemonConfig,
    token: &str,
    stop: &Arc<AtomicBool>,
) -> Result<()> {
    listener
        .set_nonblocking(true)
        .map_err(|error| invalid(format!("no se pudo configurar el listener: {error}")))?;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _address)) => {
                stream.set_nonblocking(false).map_err(|error| {
                    invalid(format!("no se pudo configurar el socket: {error}"))
                })?;
                let config = config.clone();
                let token = token.to_string();
                thread::spawn(move || {
                    let _ = handle_connection(stream, &config, &token);
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(ACCEPT_POLL_INTERVAL_MS));
            }
            Err(error) => return Err(invalid(format!("fallo al aceptar conexiones: {error}"))),
        }
    }
    Ok(())
}

pub fn run_daemon(config: &DaemonConfig) -> Result<()> {
    if config.allowed_uids.is_empty() {
        return Err(invalid("--allowed-uids no puede estar vacío"));
    }
    let token = read_token(&config.token_file)?;
    let listener = bind_unix_socket(&config.socket_path)?;
    let stop = Arc::new(AtomicBool::new(false));
    let result = serve_listener(listener, config, &token, &stop);
    let _ = fs::remove_file(&config.socket_path);
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "cell-metrics-test-{}-{nanos}-{id}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, relative: &str, contents: &str) {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().expect("parent")).expect("parents");
            fs::write(path, contents).expect("write fixture");
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const SYSTEM_TREE: &str = "system.slice/spanel-cell-demo.service";
    const USER_TREE: &str = "user.slice/user-60070.slice/user@60070.service";

    fn populate(root: &TempDir) {
        root.write(&format!("{SYSTEM_TREE}/memory.current"), "1000\n");
        root.write(&format!("{SYSTEM_TREE}/memory.peak"), "1500\n");
        root.write(&format!("{SYSTEM_TREE}/memory.max"), "4096\n");
        root.write(
            &format!("{SYSTEM_TREE}/memory.stat"),
            "anon 300\nfile 400\nkernel 50\nslab 20\n",
        );
        root.write(
            &format!("{SYSTEM_TREE}/memory.events"),
            "low 0\nhigh 0\nmax 0\noom 0\noom_kill 2\n",
        );
        root.write(
            &format!("{SYSTEM_TREE}/cpu.stat"),
            "usage_usec 1000\nuser_usec 500\nsystem_usec 500\nnr_periods 10\nnr_throttled 3\nthrottled_usec 100\n",
        );
        root.write(&format!("{SYSTEM_TREE}/cpu.max"), "50000 100000\n");
        root.write(&format!("{SYSTEM_TREE}/pids.current"), "10\n");
        root.write(&format!("{SYSTEM_TREE}/pids.max"), "20\n");
        root.write(
            &format!("{SYSTEM_TREE}/cpu.pressure"),
            "some avg10=1.00 avg60=0.50 avg300=0.10 total=123\nfull avg10=0.50 avg60=0.25 avg300=0.05 total=45\n",
        );
        root.write(
            &format!("{SYSTEM_TREE}/memory.pressure"),
            "some avg10=0.40 avg60=0.20 avg300=0.10 total=12\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        );
        root.write(
            &format!("{SYSTEM_TREE}/io.pressure"),
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        );
        root.write(
            &format!("{SYSTEM_TREE}/io.stat"),
            "8:0 rbytes=100 wbytes=200 rios=1 wios=2\n8:16 rbytes=50 wbytes=60 rios=3 wios=4\n",
        );

        root.write(&format!("{USER_TREE}/memory.current"), "500\n");
        root.write(&format!("{USER_TREE}/memory.max"), "2048\n");
        root.write(
            &format!("{USER_TREE}/memory.stat"),
            "anon 200\nfile 100\nkernel 30\nslab 10\n",
        );
        root.write(
            &format!("{USER_TREE}/cpu.stat"),
            "usage_usec 2000\nnr_throttled 1\n",
        );
        root.write(&format!("{USER_TREE}/pids.current"), "5\n");
        root.write(&format!("{USER_TREE}/pids.max"), "100\n");
        root.write(
            &format!("{USER_TREE}/cpu.pressure"),
            "some avg10=0.50 avg60=0.20 avg300=0.10 total=10\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        );
        root.write(
            &format!("{USER_TREE}/io.stat"),
            "8:0 rbytes=10 wbytes=20 rios=0 wios=0\n",
        );
    }

    #[test]
    fn parses_cgroup_files() {
        assert_eq!(parse_u64("123\n").unwrap(), 123);
        assert_eq!(parse_limit("max\n").unwrap(), None);
        assert_eq!(parse_limit("4096\n").unwrap(), Some(4096));

        let cpu_stat = parse_cpu_stat("usage_usec 42\nnr_throttled 7\n").unwrap();
        assert_eq!(cpu_stat.usage_usec, 42);
        assert_eq!(cpu_stat.nr_throttled, 7);

        let memory_stat =
            parse_memory_stat("anon 100\nfile 200\nkernel 30\nslab 10\nsock 1\nshmem 2\n").unwrap();
        assert_eq!(memory_stat.anon_bytes, 100);
        assert_eq!(memory_stat.file_bytes, 200);
        assert_eq!(memory_stat.kernel_bytes, 30);
        assert_eq!(memory_stat.slab_bytes, 10);
        assert_eq!(parse_memory_stat("").unwrap(), MemoryStat::default());

        let cpu_max = parse_cpu_max("max 100000\n").unwrap();
        assert_eq!(cpu_max.quota_usec, None);
        assert_eq!(cpu_max.period_usec, Some(100_000));

        let cpu_max = parse_cpu_max("50000 100000\n").unwrap();
        assert_eq!(cpu_max.quota_usec, Some(50_000));
        assert_eq!(cpu_max.period_usec, Some(100_000));

        assert_eq!(parse_memory_events("oom 0\noom_kill 3\n").unwrap(), 3);

        let pressure = parse_pressure(
            "some avg10=3.10 avg60=1.00 avg300=0.50 total=9\nfull avg10=1.20 avg60=0.10 avg300=0.05 total=2\n",
        )
        .unwrap();
        assert!((pressure.some_avg10 - 3.10).abs() < f64::EPSILON);
        assert!((pressure.full_avg10 - 1.20).abs() < f64::EPSILON);

        let io = parse_io_stat("8:0 rbytes=10 wbytes=20 rios=1 wios=2\n8:16 rbytes=5 wbytes=6\n")
            .unwrap();
        assert_eq!(io.read_bytes, 15);
        assert_eq!(io.write_bytes, 26);
    }

    #[test]
    fn rejects_invalid_slugs() {
        for slug in ["", "Demo", "demo/x", "-demo", "demo space", "demo_1"] {
            assert!(validate_slug(slug).is_err(), "slug should fail: {slug:?}");
        }
        assert!(validate_slug("demo").is_ok());
        assert!(validate_slug("demo-2").is_ok());
    }

    #[test]
    fn rejects_interval_out_of_range() {
        assert!(validate_interval_ms(249).is_err());
        assert!(validate_interval_ms(250).is_ok());
        assert!(validate_interval_ms(60_000).is_ok());
        assert!(validate_interval_ms(60_001).is_err());
    }

    #[test]
    fn dedupes_nested_prefixes() {
        let parent = PathBuf::from("/sys/fs/cgroup/system.slice/spanel-cell-demo.service");
        let nested = parent.join("user.slice/user-60070.slice/user@60070.service");
        let other = PathBuf::from("/sys/fs/cgroup/user.slice/user-60070.slice/user@60070.service");
        let kept = dedupe_prefixes(vec![nested.clone(), other.clone(), parent.clone()]);
        assert_eq!(kept.len(), 2);
        assert!(kept.contains(&parent));
        assert!(kept.contains(&other));
        assert!(!kept.contains(&nested));
    }

    #[test]
    fn computes_cores_and_rates() {
        assert!((compute_cores(0, 2_000_000, 2.0) - 1.0).abs() < 1e-9);
        assert!((compute_cores(1_000_000, 1_000_000, 1.0)).abs() < 1e-9);
        assert!((compute_cores(5_000_000, 1_000_000, 1.0)).abs() < 1e-9);
        assert!((compute_rate(100, 300, 2.0) - 100.0).abs() < 1e-9);
        assert!((compute_rate(0, 0, 0.0)).abs() < 1e-9);
    }

    #[test]
    fn samples_both_trees_and_first_sample_is_warmup() {
        let root = TempDir::new();
        populate(&root);
        let mut sampler = Sampler::new(root.path(), "demo", 60070, 1000).expect("sampler");
        assert_eq!(sampler.roots().len(), 2);

        let snapshot = sampler.sample().expect("sample");
        assert!(snapshot.warmup);
        assert_eq!(snapshot.memory.current_bytes, 1500);
        assert_eq!(snapshot.memory.peak_bytes, Some(1500));
        assert_eq!(snapshot.memory.max_bytes, Some(2048));
        assert_eq!(snapshot.memory.oom_kill, 2);
        assert_eq!(snapshot.memory.anon_bytes, 500);
        assert_eq!(snapshot.memory.file_bytes, 500);
        assert_eq!(snapshot.memory.kernel_bytes, 80);
        assert_eq!(snapshot.memory.slab_bytes, 30);
        assert_eq!(snapshot.cpu.usage_usec, 3000);
        assert_eq!(snapshot.cpu.cores, 0.0);
        assert_eq!(snapshot.cpu.quota_usec, Some(50_000));
        assert_eq!(snapshot.cpu.period_usec, Some(100_000));
        assert_eq!(snapshot.cpu.nr_throttled, 4);
        assert_eq!(snapshot.pids.current, 15);
        assert_eq!(snapshot.pids.max, Some(20));
        assert!((snapshot.pressure.cpu.some_avg10 - 1.00).abs() < 1e-9);
        assert!((snapshot.pressure.memory.some_avg10 - 0.40).abs() < 1e-9);
        assert_eq!(snapshot.io.read_bytes, 160);
        assert_eq!(snapshot.io.write_bytes, 280);
        assert_eq!(snapshot.io.read_bytes_per_s, None);
        assert_eq!(snapshot.io.write_bytes_per_s, None);
    }

    #[test]
    fn limits_use_the_most_restrictive_tree_not_a_sum() {
        let root = TempDir::new();
        root.write(&format!("{SYSTEM_TREE}/memory.current"), "100\n");
        root.write(&format!("{SYSTEM_TREE}/memory.max"), "max\n");
        root.write(&format!("{SYSTEM_TREE}/memory.peak"), "150\n");
        root.write(&format!("{SYSTEM_TREE}/cpu.stat"), "usage_usec 10\n");
        root.write(&format!("{SYSTEM_TREE}/cpu.max"), "max 100000\n");
        root.write(&format!("{SYSTEM_TREE}/pids.current"), "5\n");
        root.write(&format!("{SYSTEM_TREE}/pids.max"), "12299\n");
        root.write(
            &format!("{SYSTEM_TREE}/cpu.pressure"),
            "some avg10=0.00\nfull avg10=0.00\n",
        );

        root.write(&format!("{USER_TREE}/memory.current"), "50\n");
        root.write(&format!("{USER_TREE}/memory.max"), "2048\n");
        root.write(&format!("{USER_TREE}/memory.peak"), "80\n");
        root.write(&format!("{USER_TREE}/cpu.stat"), "usage_usec 20\n");
        root.write(&format!("{USER_TREE}/cpu.max"), "100000 100000\n");
        root.write(&format!("{USER_TREE}/pids.current"), "3\n");
        root.write(&format!("{USER_TREE}/pids.max"), "256\n");
        root.write(
            &format!("{USER_TREE}/cpu.pressure"),
            "some avg10=2.50\nfull avg10=0.50\n",
        );

        let mut sampler = Sampler::new(root.path(), "demo", 60070, 1000).expect("sampler");
        let snapshot = sampler.sample().expect("sample");
        assert_eq!(snapshot.memory.current_bytes, 150);
        assert_eq!(snapshot.memory.max_bytes, Some(2048));
        assert_eq!(snapshot.memory.peak_bytes, Some(150));
        assert_eq!(snapshot.cpu.quota_usec, Some(100_000));
        assert_eq!(snapshot.cpu.period_usec, Some(100_000));
        assert_eq!(snapshot.pids.max, Some(256));
        assert!((snapshot.pressure.cpu.some_avg10 - 2.50).abs() < 1e-9);
    }

    #[test]
    fn treats_a_missing_tree_as_zero() {
        let root = TempDir::new();
        root.write(&format!("{SYSTEM_TREE}/memory.current"), "10\n");
        root.write(&format!("{SYSTEM_TREE}/cpu.stat"), "usage_usec 5\n");
        let mut sampler = Sampler::new(root.path(), "demo", 60070, 1000).expect("sampler");
        assert_eq!(sampler.roots().len(), 1);
        let snapshot = sampler.sample().expect("sample");
        assert_eq!(snapshot.memory.current_bytes, 10);
        assert_eq!(snapshot.pids.current, 0);
        assert_eq!(snapshot.io.read_bytes, 0);
    }

    #[test]
    fn fails_when_no_cgroup_exists() {
        let root = TempDir::new();
        let error = Sampler::new(root.path(), "demo", 60070, 1000).expect_err("missing cgroups");
        assert!(error.to_string().contains("no existe ningún cgroup"));
    }

    #[test]
    fn fails_on_invalid_slug_even_without_root() {
        let root = TempDir::new();
        let missing = root.path().join("does-not-exist");
        let error = cgroup_paths(&missing, "Demo", 60070).expect_err("invalid slug");
        assert!(error.to_string().contains("slug inválido"));
    }

    #[cfg(unix)]
    #[test]
    fn ignores_symlinks_outside_the_cgroup_root() {
        let root = TempDir::new();
        let outside = TempDir::new();
        outside.write("memory.current", "999\n");
        fs::create_dir_all(root.path().join("system.slice")).expect("parent");
        std::os::unix::fs::symlink(outside.path(), root.path().join(SYSTEM_TREE)).expect("symlink");
        let error = cgroup_paths(root.path(), "demo", 60070).expect_err("outside symlink");
        assert!(error.to_string().contains("no existe ningún cgroup"));
    }

    #[test]
    fn emits_documented_json_shape() {
        let root = TempDir::new();
        populate(&root);
        let mut sampler = Sampler::new(root.path(), "demo", 60070, 1000).expect("sampler");
        let snapshot = sampler.sample().expect("sample");
        let json = snapshot.to_json();
        assert!(json.starts_with("{\"ts_ms\":"));
        assert!(json.contains("\"slug\":\"demo\""));
        assert!(json.contains("\"uid\":60070"));
        assert!(json.contains("\"interval_ms\":1000"));
        assert!(json.contains("\"warmup\":true"));
        assert!(json.contains("\"memory\":{\"current_bytes\":1500"));
        assert!(json.contains("\"peak_bytes\":1500"));
        assert!(json.contains("\"max_bytes\":2048"));
        assert!(json.contains("\"anon_bytes\":500"));
        assert!(json.contains("\"file_bytes\":500"));
        assert!(json.contains("\"kernel_bytes\":80"));
        assert!(json.contains("\"slab_bytes\":30"));
        assert!(json.contains("\"cores\":0,"));
        assert!(json.contains("\"some_avg10\":1"));
        assert!(json.contains("\"read_bytes_per_s\":null"));
        assert!(json.ends_with('}'));
    }
}

#[cfg(test)]
mod daemon_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::fs::MetadataExt;

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            use std::sync::atomic::AtomicU64;
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "cell-metrics-daemon-{}-{nanos}-{id}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("temp root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.0.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("parents");
            }
            fs::write(&path, contents).expect("fixture");
            path
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn current_uid() -> u64 {
        fs::metadata("/proc/self")
            .map(|metadata| u64::from(metadata.uid()))
            .unwrap_or(0)
    }

    fn populate_cgroups(root: &TempRoot, slug: &str) {
        let tree = format!("cgroup/system.slice/spanel-cell-{slug}.service");
        root.write(&format!("{tree}/memory.current"), "1024\n");
        root.write(&format!("{tree}/memory.max"), "4096\n");
        root.write(
            &format!("{tree}/cpu.stat"),
            "usage_usec 1000\nnr_throttled 1\n",
        );
        root.write(&format!("{tree}/cpu.max"), "50000 100000\n");
        root.write(&format!("{tree}/pids.current"), "4\n");
        root.write(&format!("{tree}/pids.max"), "64\n");
        root.write(
            &format!("{tree}/cpu.pressure"),
            "some avg10=1.00 avg60=0.00 avg300=0.00 total=1\nfull avg10=0.00\n",
        );
        root.write(
            &format!("{tree}/io.stat"),
            "8:0 rbytes=10 wbytes=20 rios=1 wios=1\n",
        );
    }

    struct Harness {
        root: TempRoot,
        config: DaemonConfig,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
        token: String,
    }

    impl Harness {
        fn new(allowed_uids: Vec<u64>) -> Self {
            Self::with_croups(allowed_uids, true)
        }

        fn with_croups(allowed_uids: Vec<u64>, populate: bool) -> Self {
            let root = TempRoot::new();
            if populate {
                populate_cgroups(&root, "demo");
            }
            let passwd = root.write(
                "passwd",
                "root:x:0:0:root:/root:/bin/sh\nspanel-demo:x:60070:60070::/home/spanel-demo:/bin/sh\n",
            );
            let token = "secret-token".to_string();
            let token_file = root.write("token", "secret-token\n");
            let socket_path = root.path().join("run/cell-metrics.sock");
            let config = DaemonConfig::new(
                &socket_path,
                &token_file,
                allowed_uids,
                root.path().join("cgroup"),
                &passwd,
            );
            let listener = bind_unix_socket(&config.socket_path).expect("bind");
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let thread_config = config.clone();
            let thread_token = token.clone();
            let handle = thread::spawn(move || {
                serve_listener(listener, &thread_config, &thread_token, &thread_stop)
                    .expect("serve");
            });
            Self {
                root,
                config,
                stop,
                handle: Some(handle),
                token,
            }
        }

        fn socket(&self) -> &Path {
            &self.config.socket_path
        }

        fn connect(&self) -> UnixStream {
            let stream = UnixStream::connect(self.socket()).expect("connect");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            stream
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn read_all(stream: UnixStream) -> String {
        let mut text = String::new();
        BufReader::new(stream)
            .read_to_string(&mut text)
            .expect("read all");
        text
    }

    fn first_line(mut stream: UnixStream) -> String {
        let mut line = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut line)
            .expect("read line");
        line.trim_end().to_string()
    }

    #[test]
    fn parses_protocol_lines() {
        assert_eq!(
            parse_protocol_line("PING\n").unwrap(),
            ProtocolCommand::Ping
        );
        assert_eq!(
            parse_protocol_line("SNAPSHOT demo abc").unwrap(),
            ProtocolCommand::Snapshot {
                slug: "demo".to_string(),
                token: "abc".to_string(),
            }
        );
        assert_eq!(
            parse_protocol_line("SUBSCRIBE demo 1000 abc").unwrap(),
            ProtocolCommand::Subscribe {
                slug: "demo".to_string(),
                interval_ms: 1000,
                token: "abc".to_string(),
            }
        );
        assert!(parse_protocol_line("").is_err());
        assert!(parse_protocol_line("SUBSCRIBE demo 1000").is_err());
        assert!(parse_protocol_line("SUBSCRIBE demo nope abc").is_err());
        assert!(parse_protocol_line("DROP demo").is_err());
    }

    #[test]
    fn compares_tokens_in_constant_time_shape() {
        assert!(constant_time_eq("abcdef", "abcdef"));
        assert!(!constant_time_eq("abcdef", "abcdeg"));
        assert!(!constant_time_eq("abc", "abcdef"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn parses_allowed_uids() {
        assert_eq!(parse_allowed_uids("0").unwrap(), vec![0]);
        assert_eq!(parse_allowed_uids("0, 1000,0").unwrap(), vec![0, 1000]);
        assert!(parse_allowed_uids("").is_err());
        assert!(parse_allowed_uids("0,,1").is_err());
        assert!(parse_allowed_uids("root").is_err());
    }

    #[test]
    fn reads_token_and_rejects_empty_or_missing_files() {
        let root = TempRoot::new();
        let good = root.write("token", "secret\n");
        assert_eq!(read_token(&good).unwrap(), "secret");
        let empty = root.write("empty", "\n\n");
        assert!(read_token(&empty).is_err());
        let spaced = root.write("spaced", "two words\n");
        assert!(read_token(&spaced).is_err());
        assert!(read_token(&root.path().join("missing")).is_err());
    }

    #[test]
    fn resolves_uid_from_passwd_and_rejects_unknown_users() {
        let root = TempRoot::new();
        let passwd = root.write(
            "passwd",
            "root:x:0:0:root:/root:/bin/sh\nspanel-demo:x:60070:60070::/home/demo:/bin/sh\n",
        );
        assert_eq!(resolve_uid_from_passwd(&passwd, "demo").unwrap(), 60070);
        assert!(resolve_uid_from_passwd(&passwd, "otra").is_err());
        assert!(resolve_uid_from_passwd(&passwd, "Demo").is_err());
    }

    #[test]
    fn answers_ping() {
        let harness = Harness::new(vec![current_uid()]);
        let mut stream = harness.connect();
        stream.write_all(b"PING\n").unwrap();
        let response = first_line(stream);
        assert_eq!(response, "{\"ok\":true,\"pong\":true}");
    }

    #[test]
    fn snapshot_returns_one_0112_json_line_and_closes() {
        let harness = Harness::new(vec![current_uid()]);
        let mut stream = harness.connect();
        writeln!(stream, "SNAPSHOT demo {}", harness.token).unwrap();
        let body = read_all(stream);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 1, "snapshot must close after one line: {body}");
        assert!(lines[0].starts_with("{\"ts_ms\":"));
        assert!(lines[0].contains("\"slug\":\"demo\""));
        assert!(lines[0].contains("\"warmup\":false"));
        assert!(lines[0].contains("\"max_bytes\":4096"));
    }

    #[test]
    fn subscribe_streams_one_line_per_sample_until_client_closes() {
        let harness = Harness::new(vec![current_uid()]);
        let mut stream = harness.connect();
        writeln!(stream, "SUBSCRIBE demo 250 {}", harness.token).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut first = String::new();
        reader.read_line(&mut first).unwrap();
        let mut second = String::new();
        reader.read_line(&mut second).unwrap();
        assert!(first.contains("\"warmup\":true"), "{first}");
        assert!(second.contains("\"warmup\":false"), "{second}");
        assert!(second.contains("\"cores\":"));
        drop(reader);
        drop(stream);
    }

    #[test]
    fn rejects_a_bad_token_before_touching_cgroups() {
        let harness = Harness::new(vec![current_uid()]);
        let mut stream = harness.connect();
        writeln!(stream, "SUBSCRIBE demo 1000 wrong").unwrap();
        assert_eq!(first_line(stream), "ERROR unauthorized token inválido");
    }

    #[test]
    fn rejects_a_peer_outside_the_allowlist() {
        let uid = current_uid();
        let other = if uid == 0 { 1 } else { 0 };
        let harness = Harness::new(vec![other]);
        let mut stream = harness.connect();
        writeln!(stream, "SNAPSHOT demo {}", harness.token).unwrap();
        assert_eq!(
            first_line(stream),
            "ERROR peer_denied uid de peer no permitido"
        );
    }

    #[test]
    fn rejects_invalid_slugs_and_intervals() {
        let harness = Harness::new(vec![current_uid()]);

        let mut stream = harness.connect();
        writeln!(stream, "SUBSCRIBE Demo 1000 {}", harness.token).unwrap();
        assert!(first_line(stream).starts_with("ERROR invalid_slug"));

        let mut stream = harness.connect();
        writeln!(stream, "SUBSCRIBE demo 100 {}", harness.token).unwrap();
        assert!(first_line(stream).starts_with("ERROR invalid_interval"));
    }

    #[test]
    fn reports_a_missing_spanel_user() {
        let harness = Harness::new(vec![current_uid()]);
        let mut stream = harness.connect();
        writeln!(stream, "SNAPSHOT otra {}", harness.token).unwrap();
        assert!(first_line(stream).starts_with("ERROR unknown_user"));
    }

    #[test]
    fn reports_unavailable_when_no_cgroup_exists() {
        let harness = Harness::with_croups(vec![current_uid()], false);
        let mut stream = harness.connect();
        writeln!(stream, "SNAPSHOT demo {}", harness.token).unwrap();
        assert!(first_line(stream).starts_with("ERROR unavailable"));
    }

    #[test]
    fn sampling_never_writes_cgroup_files() {
        let harness = Harness::new(vec![current_uid()]);
        let tree = harness
            .root
            .path()
            .join("cgroup/system.slice/spanel-cell-demo.service");
        let before: Vec<(PathBuf, Vec<u8>)> = ["memory.current", "cpu.stat", "io.stat"]
            .iter()
            .map(|name| {
                let path = tree.join(name);
                (path.clone(), fs::read(&path).expect("read fixture"))
            })
            .collect();

        let mut stream = harness.connect();
        writeln!(stream, "SNAPSHOT demo {}", harness.token).unwrap();
        let _ = read_all(stream);

        for (path, contents) in before {
            assert_eq!(fs::read(&path).expect("read fixture"), contents);
        }
    }

    #[test]
    fn socket_is_private_and_stale_sockets_are_replaced() {
        let root = TempRoot::new();
        let path = root.path().join("run/metrics.sock");
        let first = bind_unix_socket(&path).expect("first bind");
        drop(first);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Rebinding the same path removes the stale socket.
        let second = bind_unix_socket(&path).expect("rebind");
        drop(second);
        // A regular file is never deleted.
        let regular = root.write("run/not-a-socket", "data");
        assert!(bind_unix_socket(&regular).is_err());
        assert_eq!(fs::read_to_string(&regular).unwrap(), "data");
    }
}
