//! CIRIS Scrubbing v2 — JSON-walker + regex PII redaction
//! (multilingual NER lift deferred to v0.6.0-α4).
//!
//! Lifted from CIRISLens `cirislens-core/src/scrubber/` (the source-
//! of-truth implementation, ~2,700 LOC across walker/regex/fields/ner).
//! v0.6.0-α2 brings over the regex + walker + fields catalog + a stub
//! NER backend; v0.6.0-α4 adds the real NER backends (XLM-R / DistilBERT
//! via Candle, ORT INT8 fast path) behind the `scrub-ner` / `scrub-ort`
//! Cargo features.
//!
//! # Invariants (preserved verbatim from lens-core)
//!
//! - No unscrubbed text reaches the storage layer. Callers must
//!   consume the returned [`ScrubbedTrace`] and never reference the
//!   input after passing it to [`scrub_trace`].
//! - Any error path returns `Err`, never a partially-scrubbed `Ok`.
//!   Mission category §4: a scrubber that fails MUST fail ingest;
//!   partial scrubbing is worse than none.
//! - The historical-year regex (1700-2023) catches any year that
//!   slipped past the walker scope. `FullTraces` traces with NER
//!   off are rejected with [`ScrubError::NerNotConfigured`] — fail
//!   loud rather than silently drop multilingual coverage.
//!
//! # Surface
//!
//! - [`scrub_trace`] — one trace, one error.
//! - [`scrub_traces_batch`] — many traces, one batched NER call,
//!   one error (the whole batch is rejected if any single trace
//!   fails).
//! - [`ScrubbedTrace`] — owned output with per-trace [`ScrubStats`].
//!
//! # Integration with the v0.5.x `Scrubber` trait
//!
//! Persist's existing `crate::scrub::Scrubber` trait (the v0.1.x slot
//! for the lens FastAPI callback) is unaffected by α2. A
//! `DefaultScrubber` impl that wraps `scrub_traces_batch` lands in
//! v0.6.0-α5 alongside the Engine API additions; until then the
//! Scrubber trait stays the per-batch hook and the new
//! `scrub_traces_batch` is invoked by edge-side callers per FSD §4.

pub mod fields;
pub mod ner;
pub mod regex;
pub mod walker;

// v0.6.0-α4 — feature-gated NER model loaders.
#[cfg(feature = "scrub-ner")]
pub mod distilbert_loader;
#[cfg(feature = "scrub-ner")]
pub mod xlm_r_loader;

#[cfg(feature = "scrub-ort")]
pub mod ort_loader;

pub use fields::scrub_fields;

use serde_json::Value;

use crate::schema::TraceLevel;

/// Counts of redactions made. Per-trace metric for observability.
#[derive(Debug, Default, Clone)]
pub struct ScrubStats {
    /// NER entity replacements, by tag. Always 0 in v0.6.0-α2 (NER
    /// is stubbed); populates real values when α4 lands the backends.
    pub entities_redacted: usize,
    /// Regex replacements summed across all patterns.
    pub regex_redactions: usize,
    /// Number of distinct string fields modified.
    pub fields_modified: usize,
    /// Maximum depth reached in the JSON walker.
    pub walker_max_depth: usize,
    /// True if the NER pass actually ran. v0.6.0-α2: always false.
    pub ner_ran: bool,
    /// Number of NER inputs served from the content cache (no model
    /// call). v0.6.0-α2: always 0.
    pub ner_cache_hits: usize,
    /// Number of NER inputs that missed the cache and went to the
    /// model. v0.6.0-α2: always 0.
    pub ner_cache_misses: usize,
}

/// Output of a successful scrub. Holds owned JSON; the input is
/// consumed.
#[derive(Debug)]
pub struct ScrubbedTrace {
    /// The redacted JSON value.
    pub value: Value,
    /// Per-trace stats.
    pub stats: ScrubStats,
    /// Trace-level the scrub ran at.
    pub level: TraceLevel,
}

/// Errors that prevent scrubbing from completing.
///
/// Contract: any error here means the trace MUST be rejected —
/// never persisted partially scrubbed.
#[derive(Debug, thiserror::Error)]
pub enum ScrubError {
    /// Unrecognized trace-level token at parse time.
    #[error("invalid trace level: {0}")]
    InvalidLevel(String),
    /// NER inference raised. v0.6.0-α2 stub always returns
    /// `NerNotConfigured` instead.
    #[error("NER inference failed: {0}")]
    NerFailed(String),
    /// Walker recursion exceeded its hard depth limit.
    #[error("walker recursion exceeded depth limit ({0})")]
    WalkerDepthExceeded(usize),
    /// Post-scrub residue check: redacted output still contains
    /// historical-year matches — the regex pass missed something.
    /// Caller rejects the trace.
    #[error(
        "year-residue check failed: redacted output still contains {0} historical-year matches"
    )]
    YearResidue(usize),
    /// Operator-supplied leak probe matched the scrubbed output.
    /// Set via `CIRISLENS_LEAK_PROBES` env (newline-separated).
    #[error("operator probe matched in scrubbed output (CIRISLENS_LEAK_PROBES)")]
    ProbeMatch,
    /// `FullTraces` traces require NER. Without it the multilingual
    /// PII coverage is lost — fail loud.
    #[error("NER model not configured — full_traces cannot be scrubbed without it")]
    NerNotConfigured,
}

impl ScrubError {
    /// Stable string-token for telemetry / structured logging.
    /// THREAT_MODEL.md AV-15: HTTP / PyO3 sanitization.
    pub fn kind(&self) -> &'static str {
        match self {
            ScrubError::InvalidLevel(_) => "scrub_invalid_level",
            ScrubError::NerFailed(_) => "scrub_ner_failed",
            ScrubError::WalkerDepthExceeded(_) => "scrub_walker_depth",
            ScrubError::YearResidue(_) => "scrub_year_residue",
            ScrubError::ProbeMatch => "scrub_probe_match",
            ScrubError::NerNotConfigured => "scrub_ner_not_configured",
        }
    }
}

/// Scrub a trace. The input is consumed; only the returned
/// [`ScrubbedTrace`] may be passed to persistence.
///
/// Per the FSD invariant: any error path returns `Err`, never a
/// partially-scrubbed `Ok`. The caller must propagate the error;
/// downstream storage code must not have a path from `Err` to a
/// write.
pub fn scrub_trace(trace: Value, level: TraceLevel) -> Result<ScrubbedTrace, ScrubError> {
    let mut stats = ScrubStats::default();

    let scrubbed_value = match level {
        TraceLevel::Generic => {
            // No-op: generic traces have no text to scrub.
            trace
        }
        TraceLevel::Detailed => {
            // Regex pass only.
            walker::walk(
                trace,
                scrub_fields(),
                &mut stats,
                /* run_ner = */ false,
            )?
        }
        TraceLevel::FullTraces => {
            // NER + regex on every string in matched subtrees.
            stats.ner_ran = ner::is_configured();
            if !stats.ner_ran {
                // Fail-loud: full_traces without NER would silently
                // drop multilingual entity coverage.
                return Err(ScrubError::NerNotConfigured);
            }
            walker::walk(trace, scrub_fields(), &mut stats, /* run_ner = */ true)?
        }
    };

    // Invariant check: no historical-year residue in redacted
    // output.
    if let TraceLevel::Detailed | TraceLevel::FullTraces = level {
        let residue = regex::count_year_residue(&scrubbed_value);
        if residue > 0 {
            return Err(ScrubError::YearResidue(residue));
        }
        if regex::probe_match(&scrubbed_value) {
            return Err(ScrubError::ProbeMatch);
        }
    }

    Ok(ScrubbedTrace {
        value: scrubbed_value,
        stats,
        level,
    })
}

/// Scrub a batch of traces with one NER forward pass shared across
/// the whole batch. Significantly higher throughput than calling
/// [`scrub_trace`] in a loop when level=`FullTraces`; for other
/// levels it's just a per-trace regex pass.
pub fn scrub_traces_batch(
    traces: Vec<Value>,
    level: TraceLevel,
) -> Result<Vec<ScrubbedTrace>, ScrubError> {
    if traces.is_empty() {
        return Ok(Vec::new());
    }
    let mut stats = ScrubStats::default();

    let scrubbed_values: Vec<Value> = match level {
        TraceLevel::Generic => traces, // pass-through
        TraceLevel::Detailed => {
            walker::walk_batch(
                traces,
                scrub_fields(),
                &mut stats,
                /* run_ner = */ false,
            )?
        }
        TraceLevel::FullTraces => {
            stats.ner_ran = ner::is_configured();
            if !stats.ner_ran {
                return Err(ScrubError::NerNotConfigured);
            }
            walker::walk_batch(
                traces,
                scrub_fields(),
                &mut stats,
                /* run_ner = */ true,
            )?
        }
    };

    // Per-trace invariant check: residue / probe match. Reject the
    // whole batch if any single trace fails.
    if let TraceLevel::Detailed | TraceLevel::FullTraces = level {
        for v in &scrubbed_values {
            let residue = regex::count_year_residue(v);
            if residue > 0 {
                return Err(ScrubError::YearResidue(residue));
            }
            if regex::probe_match(v) {
                return Err(ScrubError::ProbeMatch);
            }
        }
    }

    Ok(scrubbed_values
        .into_iter()
        .map(|v| ScrubbedTrace {
            value: v,
            stats: stats.clone(),
            level,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn generic_passes_through() {
        let trace = json!({"csdma": 0.95, "coh": 1.0});
        let out = scrub_trace(trace.clone(), TraceLevel::Generic).unwrap();
        assert_eq!(out.value, trace);
        assert!(!out.stats.ner_ran);
    }

    /// When `scrub-ner` is off, the NER backend is unconfigured and
    /// `FullTraces` MUST reject (fail-loud, no silent coverage loss).
    /// When `scrub-ner` is on, the backend may legitimately be ready
    /// (e.g. `CIRISLENS_NER_MODEL_DIR` set or an HF cache exists), so
    /// this test only asserts the off-feature invariant.
    #[cfg(not(feature = "scrub-ner"))]
    #[test]
    fn full_traces_without_ner_rejects() {
        let trace = json!({"task_description": "anything"});
        let result = scrub_trace(trace, TraceLevel::FullTraces);
        assert!(matches!(result, Err(ScrubError::NerNotConfigured)));
    }

    #[test]
    fn detailed_runs_regex_only() {
        let trace = json!({
            "task_description": "User email is alice@example.com from 1989"
        });
        let out = scrub_trace(trace, TraceLevel::Detailed).unwrap();
        let text = out.value["task_description"].as_str().unwrap();
        assert!(text.contains("[EMAIL]"));
        // Year regex should have caught 1989
        assert!(!text.contains("1989"));
    }

    #[test]
    fn batch_round_trip() {
        let v1 = json!({"task_description": "Event in 1989"});
        let v2 = json!({"task_description": "Email: bob@example.com"});
        let out = scrub_traces_batch(vec![v1, v2], TraceLevel::Detailed).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out[0].value["task_description"]
            .as_str()
            .unwrap()
            .contains("[YEAR]"));
        assert!(out[1].value["task_description"]
            .as_str()
            .unwrap()
            .contains("[EMAIL]"));
    }

    #[test]
    fn scrub_error_kinds_stable() {
        assert_eq!(
            ScrubError::InvalidLevel("x".into()).kind(),
            "scrub_invalid_level"
        );
        assert_eq!(ScrubError::NerFailed("x".into()).kind(), "scrub_ner_failed");
        assert_eq!(
            ScrubError::WalkerDepthExceeded(99).kind(),
            "scrub_walker_depth"
        );
        assert_eq!(ScrubError::YearResidue(1).kind(), "scrub_year_residue");
        assert_eq!(ScrubError::ProbeMatch.kind(), "scrub_probe_match");
        assert_eq!(
            ScrubError::NerNotConfigured.kind(),
            "scrub_ner_not_configured"
        );
    }
}
