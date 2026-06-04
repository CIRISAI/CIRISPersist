//! Per-Engine-open migration-apply timing log (CIRISPersist#156).
//!
//! Always-compiled diagnostic. When the env var
//! `CIRIS_PERSIST_MIGRATION_TIMING_LOG` is set, every call to
//! [`crate::store::Backend::run_migrations`] (postgres + sqlite)
//! appends one structured entry to the named file (with `.{pid}`
//! appended) recording:
//!
//! - **`unix_ms`** — wall-clock anchor for log correlation
//! - **`backend`** — `"postgres"` / `"sqlite"`
//! - **`total_wall_us`** — microseconds spent inside the refinery
//!   `runner().run()` call (does NOT include connection acquisition
//!   or the post-migration trust-graph bootstrap; just the schema
//!   apply step itself)
//! - **`applied_count`** — number of migrations refinery reported as
//!   newly applied this call (0 on a no-op idempotent reopen)
//! - **`applied_versions`** — comma-joined list of version numbers
//!   that refinery applied (e.g. `"58,59"` after a v3.11.0 → v3.12.1
//!   upgrade; empty string on a no-op reopen)
//!
//! # Why this is persist-specific (vs the sibling debug panic-hook)
//!
//! The CIRISPersist#156 cohabitation regression diagnosis (Eric's
//! triage) implicated added migrations (V058 + V059) shifting the
//! Engine-construction timing enough to make a Leviculum-side race
//! deterministic. The panic-hook in `crate::debug` captures the
//! downstream symptom (the panic site that fires when the race
//! loses); this log captures the upstream cause (how many ms of
//! schema-apply delta the new migrations actually add). Together
//! they let `tools/race_repro.py` correlate "applied migrations" ×
//! "panic-or-hang count" across N rounds.
//!
//! # Why always-compiled (vs the `debug-tools` panic-hook)
//!
//! The cost of the always-compiled path is one [`std::env::var`]
//! lookup per Engine open — cheap enough that gating behind
//! `debug-tools` is pure ceremony. The log content is mundane
//! per-migration timing (no panic backtraces, no symbol resolution);
//! release wheels can write this log without exposing diagnostic
//! surface that needs guarding. Operators can also use this in
//! production to monitor migration-apply latency growth across
//! releases.
//!
//! # Format
//!
//! One JSON object per line (JSON-Lines), so the harness can stream
//! it via `jq`. Same one-line-per-row discipline as the existing
//! audit/transparency log shapes the substrate writes.
//!
//! ```json
//! {"unix_ms":1717445000123,"backend":"sqlite","total_wall_us":4521,"applied_count":2,"applied_versions":"58,59"}
//! ```

use std::io::Write;
use std::sync::Mutex;
use std::time::Instant;

static WRITE_GUARD: Mutex<()> = Mutex::new(());

/// Resolve the log path from `CIRIS_PERSIST_MIGRATION_TIMING_LOG`
/// (with `.{pid}` appended or `{pid}` expanded). Returns `None` if
/// the env var is unset.
fn resolve_log_path() -> Option<std::path::PathBuf> {
    let raw = std::env::var("CIRIS_PERSIST_MIGRATION_TIMING_LOG").ok()?;
    let path = if raw.contains("{pid}") {
        raw.replace("{pid}", &std::process::id().to_string())
    } else {
        format!("{raw}.{}", std::process::id())
    };
    Some(std::path::PathBuf::from(path))
}

/// Result of a migration-apply timing measurement — emitted as one
/// JSON-Lines entry per call. Backends construct this and pass it to
/// [`append`].
#[derive(Debug, Clone)]
pub struct MigrationTiming {
    /// `"postgres"` or `"sqlite"`.
    pub backend: &'static str,
    /// Wall time inside `refinery::Runner::run(...)` (not the wider
    /// `run_migrations` wrapper).
    pub elapsed: std::time::Duration,
    /// Number of migrations refinery applied this call.
    pub applied_count: usize,
    /// Comma-joined refinery version numbers (e.g. `"58,59"`).
    pub applied_versions: String,
}

impl MigrationTiming {
    /// Convenience: time a block returning a refinery `Report` and
    /// build a `MigrationTiming` from it. Doesn't write — caller
    /// passes the result to [`append`] when the env var path
    /// resolves.
    pub fn from_run<F, E>(backend: &'static str, run: F) -> Result<Self, E>
    where
        F: FnOnce() -> Result<refinery::Report, E>,
    {
        let started = Instant::now();
        let report = run()?;
        let elapsed = started.elapsed();
        let applied = report.applied_migrations();
        let applied_versions = applied
            .iter()
            .map(|m| m.version().to_string())
            .collect::<Vec<_>>()
            .join(",");
        Ok(MigrationTiming {
            backend,
            elapsed,
            applied_count: applied.len(),
            applied_versions,
        })
    }
}

/// Append a JSON-Lines entry to the migration-timing log if the
/// env var is set. Silent on all failure paths — the diagnostic
/// MUST NOT impact a successful migration-apply call.
pub fn append(timing: &MigrationTiming) {
    let Some(path) = resolve_log_path() else {
        return;
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let total_wall_us = timing.elapsed.as_micros();
    // Manual JSON construction — avoids serde_json::Value heap +
    // keeps the diagnostic minimal in the always-compiled path.
    // `applied_versions` is comma-joined integers so it's
    // JSON-string-safe without escaping. Backend names are static.
    let entry = format!(
        "{{\"unix_ms\":{},\"backend\":\"{}\",\"total_wall_us\":{},\
         \"applied_count\":{},\"applied_versions\":\"{}\"}}\n",
        now_ms, timing.backend, total_wall_us, timing.applied_count, timing.applied_versions,
    );
    if let Ok(_guard) = WRITE_GUARD.lock() {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = file.write_all(entry.as_bytes());
            let _ = file.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_silently_noops_without_env_var() {
        // No env var → no panic, no file created.
        std::env::remove_var("CIRIS_PERSIST_MIGRATION_TIMING_LOG");
        let timing = MigrationTiming {
            backend: "sqlite",
            elapsed: std::time::Duration::from_micros(1234),
            applied_count: 2,
            applied_versions: "58,59".into(),
        };
        append(&timing); // must not panic
    }

    #[test]
    fn json_format_is_one_line() {
        // Sanity: format produces one JSON object per line with the
        // documented keys. We can't easily exercise the file write
        // without env-var pollution affecting other tests, so check
        // the format string shape directly.
        let timing = MigrationTiming {
            backend: "postgres",
            elapsed: std::time::Duration::from_micros(4521),
            applied_count: 2,
            applied_versions: "58,59".into(),
        };
        // Build the same shape `append` writes (sans file I/O).
        let now_ms = 1717445000123u128;
        let total_wall_us = timing.elapsed.as_micros();
        let entry = format!(
            "{{\"unix_ms\":{},\"backend\":\"{}\",\"total_wall_us\":{},\
             \"applied_count\":{},\"applied_versions\":\"{}\"}}\n",
            now_ms, timing.backend, total_wall_us, timing.applied_count, timing.applied_versions,
        );
        assert_eq!(entry.matches('\n').count(), 1);
        // Parseable as JSON.
        let v: serde_json::Value = serde_json::from_str(entry.trim_end()).unwrap();
        assert_eq!(v["unix_ms"], 1717445000123u64);
        assert_eq!(v["backend"], "postgres");
        assert_eq!(v["total_wall_us"], 4521u64);
        assert_eq!(v["applied_count"], 2);
        assert_eq!(v["applied_versions"], "58,59");
    }
}
