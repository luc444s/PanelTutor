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
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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

/// Sum integer limits; if any tree is unlimited (`max`) the aggregate is null.
fn sum_limit(roots: &[PathBuf], file: &str) -> Result<Option<u64>> {
    let mut total = 0u64;
    let mut present = false;
    for root in roots {
        if let Some(text) = read_optional(root, file) {
            present = true;
            match parse_limit(&text)? {
                Some(value) => total = total.saturating_add(value),
                None => return Ok(None),
            }
        }
    }
    Ok(if present { Some(total) } else { None })
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

fn sum_cpu_max(roots: &[PathBuf]) -> Result<CpuMax> {
    let mut quota_total = 0u64;
    let mut unlimited = false;
    let mut has_quota = false;
    let mut period = 0u64;
    let mut present = false;
    for root in roots {
        if let Some(text) = read_optional(root, "cpu.max") {
            present = true;
            let cpu_max = parse_cpu_max(&text)?;
            match cpu_max.quota_usec {
                Some(quota) => {
                    quota_total = quota_total.saturating_add(quota);
                    has_quota = true;
                }
                None => unlimited = true,
            }
            if let Some(value) = cpu_max.period_usec {
                period = period.max(value);
            }
        }
    }
    if !present {
        return Ok(CpuMax::default());
    }
    Ok(CpuMax {
        quota_usec: if unlimited || !has_quota {
            None
        } else {
            Some(quota_total)
        },
        period_usec: if period == 0 { None } else { Some(period) },
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

fn sum_pressure(roots: &[PathBuf], file: &str) -> Result<PressureValue> {
    let mut total = PressureValue::default();
    for root in roots {
        if let Some(text) = read_optional(root, file) {
            let value = parse_pressure(&text)?;
            total.some_avg10 += value.some_avg10;
            total.full_avg10 += value.full_avg10;
        }
    }
    Ok(total)
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
        let cpu_max = sum_cpu_max(&self.roots)?;
        let io = sum_io_stat(&self.roots)?;
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
                peak_bytes: sum_limit(&self.roots, "memory.peak")?,
                max_bytes: sum_limit(&self.roots, "memory.max")?,
                oom_kill: sum_memory_events(&self.roots)?,
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
                max: sum_limit(&self.roots, "pids.max")?,
            },
            pressure: Pressure {
                cpu: sum_pressure(&self.roots, "cpu.pressure")?,
                memory: sum_pressure(&self.roots, "memory.pressure")?,
                io: sum_pressure(&self.roots, "io.pressure")?,
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
            "\"memory\":{{\"current_bytes\":{},\"peak_bytes\":{},\"max_bytes\":{},\"oom_kill\":{}}},",
            self.memory.current_bytes,
            json_u64(self.memory.peak_bytes),
            json_u64(self.memory.max_bytes),
            self.memory.oom_kill
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
        assert_eq!(snapshot.memory.max_bytes, Some(6144));
        assert_eq!(snapshot.memory.oom_kill, 2);
        assert_eq!(snapshot.cpu.usage_usec, 3000);
        assert_eq!(snapshot.cpu.cores, 0.0);
        assert_eq!(snapshot.cpu.quota_usec, Some(50_000));
        assert_eq!(snapshot.cpu.period_usec, Some(100_000));
        assert_eq!(snapshot.cpu.nr_throttled, 4);
        assert_eq!(snapshot.pids.current, 15);
        assert_eq!(snapshot.pids.max, Some(120));
        assert!((snapshot.pressure.cpu.some_avg10 - 1.50).abs() < 1e-9);
        assert!((snapshot.pressure.memory.some_avg10 - 0.40).abs() < 1e-9);
        assert_eq!(snapshot.io.read_bytes, 160);
        assert_eq!(snapshot.io.write_bytes, 280);
        assert_eq!(snapshot.io.read_bytes_per_s, None);
        assert_eq!(snapshot.io.write_bytes_per_s, None);
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
        assert!(json.contains("\"max_bytes\":6144"));
        assert!(json.contains("\"cores\":0,"));
        assert!(json.contains("\"some_avg10\":1.5"));
        assert!(json.contains("\"read_bytes_per_s\":null"));
        assert!(json.ends_with('}'));
    }
}
