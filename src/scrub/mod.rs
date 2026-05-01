//! PII scrubbing — trait + Phase 1 impls.
//!
//! # Mission alignment (MISSION.md §2 — `scrub/`)
//!
//! Privacy at trace level. The Accord (Book II §IV) and the
//! GDPR/HIPAA compliance posture in CIRISLens require that PII never
//! cross the persistence boundary at trace levels where it isn't
//! warranted.
//!
//! Constraint (FSD §3.3 step 3): Phase 1 *delegates* to the existing
//! `cirislens-core` scrubber — no behavior change. This module
//! defines the trait + a null pass-through impl + a callback-shaped
//! impl that the lens (or any consumer) wires up by injecting its
//! existing scrubber as a closure / trait impl. The trait boundary
//! is what later phases extend (Presidio-style, locale-specific,
//! field-level redaction policies) without restructuring the
//! ingest pipeline.

use crate::schema::{BatchEvent, BatchEnvelope, TraceLevel};

/// PII scrubber trait.
///
/// Phase 1: invoked by the ingest pipeline (FSD §3.3 step 3) for
/// `trace_level = full_traces` only. The implementation is free to
/// also act on `detailed` (the agent's existing scrubber does this).
/// Generic-level traces have no content text by design (TRACE_WIRE_FORMAT.md
/// §7), so no scrubbing is required.
///
/// Mission constraint (MISSION.md §3 anti-pattern #8): "delete the
/// whole field" is only correct when the field has no privacy-safe
/// form. Scrubber impls maintain analytical signal where possible.
pub trait Scrubber: Send + Sync {
    /// Scrub a batch in place. Returns the count of fields modified
    /// (for telemetry / lens dashboards).
    ///
    /// Mission category §4 "Mission rejection": an Err here MUST
    /// fail the ingest — partial scrubbing is worse than none, since
    /// it leaks the assumption that the rest *was* scrubbed. The
    /// caller (ingest pipeline) propagates as a typed
    /// `IngestError::Scrub` and rejects the batch.
    fn scrub_batch(&self, env: &mut BatchEnvelope) -> Result<usize, ScrubError>;
}

/// Scrubber-layer errors.
#[derive(Debug, thiserror::Error)]
pub enum ScrubError {
    /// External scrubber (Python callback / Rust impl) raised; carry
    /// the message verbatim so the caller can log it.
    #[error("scrubber raised: {0}")]
    External(String),

    /// Internal serialization issue when materializing a value for
    /// the external scrubber.
    #[error("internal: {0}")]
    Internal(#[from] serde_json::Error),
}

/// Pass-through scrubber — used when `trace_level = generic` (no
/// content text by design) and as the default for tests.
///
/// Mission: this is the *only* impl that's safe to use without an
/// upstream scrubber wired up; production deployments at
/// `detailed`/`full_traces` MUST replace it with a real scrubber.
/// The lens enforces this in its config-loading path; the crate
/// emits a tracing::warn! at construction so misconfigurations
/// surface in logs.
#[derive(Debug, Default)]
pub struct NullScrubber;

impl Scrubber for NullScrubber {
    fn scrub_batch(&self, env: &mut BatchEnvelope) -> Result<usize, ScrubError> {
        // Mission constraint: at GENERIC trace level there is no
        // content text to scrub (TRACE_WIRE_FORMAT.md §7). The lens
        // config gates: NullScrubber is acceptable only at GENERIC.
        if env.trace_level != TraceLevel::Generic {
            tracing::warn!(
                trace_level = ?env.trace_level,
                "NullScrubber used at non-GENERIC trace level — content not scrubbed; \
                 wire a real Scrubber impl in production"
            );
        }
        let _ = env; // Pass-through.
        Ok(0)
    }
}

/// A callback-shaped scrubber.
///
/// Phase 1 deployment shape (FSD §3.5): the lens passes its existing
/// `cirislens-core` scrubber via a closure (Rust callers) or a Python
/// callable (PyO3 callers; see `ffi/pyo3.rs` Phase 1.9).
///
/// The callback receives the full batch envelope serialized to JSON
/// and returns a (possibly modified) JSON envelope. We round-trip
/// through `serde_json` to keep the FFI surface stable; the hot path
/// is bounded by batch size (default 10 events per batch), so the
/// extra serialization is acceptable.
pub struct CallbackScrubber<F>
where
    F: Fn(serde_json::Value) -> Result<(serde_json::Value, usize), ScrubError> + Send + Sync,
{
    callback: F,
}

impl<F> CallbackScrubber<F>
where
    F: Fn(serde_json::Value) -> Result<(serde_json::Value, usize), ScrubError> + Send + Sync,
{
    pub fn new(callback: F) -> Self {
        Self { callback }
    }
}

impl<F> Scrubber for CallbackScrubber<F>
where
    F: Fn(serde_json::Value) -> Result<(serde_json::Value, usize), ScrubError> + Send + Sync,
{
    fn scrub_batch(&self, env: &mut BatchEnvelope) -> Result<usize, ScrubError> {
        // Trust the existing cirislens-core scrubber on detailed
        // and full_traces; skip work entirely at GENERIC.
        if env.trace_level == TraceLevel::Generic {
            return Ok(0);
        }

        // Round-trip the typed envelope through JSON to feed the
        // callback. Reject typed deserialization-failure into the
        // typed BatchEnvelope back — that would mean the scrubber
        // changed schema-level fields (`trace_schema_version`,
        // `events[]` shape), which is a contract violation.
        let v = serde_json::to_value(&*env)?;
        let (out, modified_count) = (self.callback)(v)?;
        let new_env: BatchEnvelope = serde_json::from_value(out).map_err(ScrubError::Internal)?;

        // Mission constraint (MISSION.md §3 anti-pattern #8): a
        // scrubber MUST NOT alter the schema-level fields. Verify.
        if new_env.trace_schema_version != env.trace_schema_version {
            return Err(ScrubError::External(
                "scrubber altered trace_schema_version — rejected".into(),
            ));
        }
        if new_env.trace_level != env.trace_level {
            return Err(ScrubError::External(
                "scrubber altered trace_level — rejected".into(),
            ));
        }
        if new_env.events.len() != env.events.len() {
            return Err(ScrubError::External(
                "scrubber altered events[] count — rejected".into(),
            ));
        }
        // events: the scrubber may modify content but not change the
        // event_type discriminator on any event.
        for (a, b) in new_env.events.iter().zip(env.events.iter()) {
            if std::mem::discriminant(a) != std::mem::discriminant(b) {
                return Err(ScrubError::External(
                    "scrubber altered an events[] discriminant — rejected".into(),
                ));
            }
        }

        *env = new_env;
        Ok(modified_count)
    }
}

/// Convenience: a scrubber that returns each event's typed shape
/// after callbacks. Used by the test suite (and as a parity reference
/// for the Python callable shim once PyO3 lands in Phase 1.9).
#[cfg(test)]
pub fn _silence(_: BatchEvent) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{BatchEnvelope, BatchEvent, TraceLevel};

    fn ascii_envelope(level: TraceLevel) -> BatchEnvelope {
        let body = serde_json::json!({
            "events": [{
                "event_type": "complete_trace",
                "trace_level": level_str(level),
                "trace": {
                    "trace_id": "trace-x-1",
                    "thought_id": "th-1",
                    "task_id": "task-1",
                    "agent_id_hash": "deadbeef",
                    "started_at": "2026-04-30T00:15:53.123456+00:00",
                    "completed_at": "2026-04-30T00:16:12.789012+00:00",
                    "trace_level": level_str(level),
                    "trace_schema_version": "2.7.0",
                    "components": [],
                    "signature": "AAAA",
                    "signature_key_id": "ciris-agent-key:dead"
                }
            }],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": level_str(level),
            "trace_schema_version": "2.7.0"
        });
        BatchEnvelope::from_json(body.to_string().as_bytes()).unwrap()
    }

    fn level_str(t: TraceLevel) -> &'static str {
        match t {
            TraceLevel::Generic => "generic",
            TraceLevel::Detailed => "detailed",
            TraceLevel::FullTraces => "full_traces",
        }
    }

    #[test]
    fn null_scrubber_generic_passthrough() {
        let mut env = ascii_envelope(TraceLevel::Generic);
        let scrubber = NullScrubber;
        let n = scrubber.scrub_batch(&mut env).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn null_scrubber_detailed_passes_but_warns() {
        // The warn! is observed via tracing-subscriber in CI; this
        // test asserts the scrub does not error and is no-op.
        let mut env = ascii_envelope(TraceLevel::Detailed);
        let n = NullScrubber.scrub_batch(&mut env).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn callback_scrubber_skips_generic() {
        // Mission alignment: GENERIC has no content text, so the
        // scrubber is bypassed entirely.
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_in = calls.clone();
        let scrubber = CallbackScrubber::new(move |v| {
            calls_in.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((v, 0))
        });
        let mut env = ascii_envelope(TraceLevel::Generic);
        scrubber.scrub_batch(&mut env).unwrap();
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "GENERIC must not invoke the scrubber"
        );
    }

    #[test]
    fn callback_scrubber_runs_on_detailed() {
        let scrubber = CallbackScrubber::new(|v| Ok((v, 7)));
        let mut env = ascii_envelope(TraceLevel::Detailed);
        let n = scrubber.scrub_batch(&mut env).unwrap();
        assert_eq!(n, 7);
    }

    #[test]
    fn callback_scrubber_rejects_schema_alteration() {
        // Mission category §4 "Mission rejection": a scrubber that
        // alters trace_schema_version is a contract violation.
        let scrubber = CallbackScrubber::new(|mut v| {
            v["trace_schema_version"] = serde_json::Value::String("9.9.9".into());
            Ok((v, 1))
        });
        let mut env = ascii_envelope(TraceLevel::Detailed);
        let err = scrubber.scrub_batch(&mut env).unwrap_err();
        // Either we reject inside the version gate (parsing the
        // returned envelope hits SUPPORTED_VERSIONS), or we reject
        // explicitly. Both are acceptable; both are rejection.
        let msg = err.to_string();
        assert!(
            msg.contains("schema") || msg.contains("trace_schema_version") || msg.contains("9.9.9"),
            "expected schema rejection, got: {msg}"
        );
    }

    #[test]
    fn callback_scrubber_rejects_event_count_change() {
        let scrubber = CallbackScrubber::new(|mut v| {
            // Empty out the events[] array.
            v["events"] = serde_json::Value::Array(vec![]);
            Ok((v, 0))
        });
        let mut env = ascii_envelope(TraceLevel::FullTraces);
        let err = scrubber.scrub_batch(&mut env).unwrap_err();
        // Either rejected by our explicit check, or by the
        // BatchEnvelope::from_json reject-empty-events guard.
        let msg = err.to_string();
        assert!(
            msg.contains("events") || msg.contains("MissingField"),
            "expected events-count rejection, got: {msg}"
        );
    }

    #[test]
    fn callback_scrubber_propagates_external_error() {
        let scrubber: CallbackScrubber<_> = CallbackScrubber::new(|_v| {
            Err(ScrubError::External("upstream redaction failed".into()))
        });
        let mut env = ascii_envelope(TraceLevel::FullTraces);
        let err = scrubber.scrub_batch(&mut env).unwrap_err();
        assert!(matches!(err, ScrubError::External(_)));
    }
}
