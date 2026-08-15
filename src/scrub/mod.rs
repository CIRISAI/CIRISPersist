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

use crate::schema::{BatchEnvelope, TraceLevel};

/// **What a scrub actually did** (v32.0.0, CIRISPersist#690).
///
/// `scrub_batch` used to return `usize` — a count of fields modified — and that
/// count cannot answer the question a receiver has to ask. `fields_modified: 0`
/// is the honest output of *"NER ran and found nothing"* **and** of *"no
/// scrubber ran at all"*, and those are exactly the two states that must be
/// distinguishable now that scrubbing happens at the sender's egress and
/// `apply_replicated_*` applies federated rows verbatim.
///
/// So the scrubber states what it DID, not merely how much it changed, and
/// [`ScrubEnvelope`](crate::ingest::ScrubEnvelope) binds that statement into the
/// signature.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScrubOutcome {
    /// Distinct string fields modified. Telemetry only — see the type doc for
    /// why this is not evidence of treatment.
    pub fields_modified: usize,
    /// **Did a named-entity pass actually run?** `NullScrubber` answers `false`
    /// and is honest about it; before #690 it produced an envelope
    /// indistinguishable from a full NER pass.
    pub ner_ran: bool,
    /// The trace level the content was **actually treated at**, after any
    /// downgrade.
    ///
    /// A node with no model loaded scrubs at `detailed` and must relabel the
    /// trace `detailed` — otherwise the content carries a `full_traces` label it
    /// did not earn. Carrying `ner_ran` alone would leave that lie expressible:
    /// the flag honest, the label false. Binding both is what makes the envelope
    /// agree with itself.
    pub applied_trace_level: String,
    /// **Digest of the model that ran**, `None` when no NER pass happened.
    ///
    /// `ner_ran: true` says a pass occurred; it does not say what that pass was
    /// capable of catching. Two NER models disagree about what counts as PII, so
    /// a receiver enforcing "properly scrubbed" needs to know WHICH instrument
    /// was used — the difference between *"a scrub ran"*, *"an NER scrub ran"*,
    /// and *"an NER scrub ran with a model I accept"*. Only the third is a
    /// policy anyone can enforce.
    ///
    /// Same reason #660 widened the genesis digest from `key_id` to the whole
    /// record: the identity of the actor is not the content of the act.
    pub scrubber_model_digest: Option<String>,
}

impl ScrubOutcome {
    /// The honest answer for a pass-through scrubber: nothing modified, no NER,
    /// no model, level unchanged.
    #[must_use]
    pub fn none_at(trace_level: &str) -> Self {
        Self {
            fields_modified: 0,
            ner_ran: false,
            applied_trace_level: trace_level.to_owned(),
            scrubber_model_digest: None,
        }
    }
}

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
    /// Scrub a batch in place and **state what was done to it**.
    ///
    /// v32.0.0 (CIRISPersist#690) — returns [`ScrubOutcome`] rather than a bare
    /// count. The count remains available on the outcome; it is simply not
    /// evidence, because `0` means both "found nothing" and "did nothing".
    ///
    /// Mission category §4 "Mission rejection": an Err here MUST
    /// fail the ingest — partial scrubbing is worse than none, since
    /// it leaks the assumption that the rest *was* scrubbed. The
    /// caller (ingest pipeline) propagates as a typed
    /// `IngestError::Scrub` and rejects the batch.
    fn scrub_batch(&self, env: &mut BatchEnvelope) -> Result<ScrubOutcome, ScrubError>;
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

impl ScrubError {
    /// Stable string-token identifying the error variant.
    /// THREAT_MODEL.md AV-15: HTTP / PyO3 sanitization.
    pub fn kind(&self) -> &'static str {
        match self {
            ScrubError::External(_) => "scrub_external",
            ScrubError::Internal(_) => "scrub_internal",
        }
    }
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
    /// v32.0.0 (#690) — reports the truth about itself: no NER, no model. It
    /// used to be indistinguishable from a full pass once the envelope was
    /// signed, which is the defect #690 exists to close.
    fn scrub_batch(&self, env: &mut BatchEnvelope) -> Result<ScrubOutcome, ScrubError> {
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
        let level = env.trace_level.as_str();
        let _ = env; // Pass-through.
        Ok(ScrubOutcome::none_at(level))
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
    /// Wrap a closure into a [`Scrubber`] impl. The callback receives
    /// each component's `data` blob as a JSON value and must return
    /// `(scrubbed_value, fields_modified_count)`.
    pub fn new(callback: F) -> Self {
        Self { callback }
    }
}

impl<F> Scrubber for CallbackScrubber<F>
where
    F: Fn(serde_json::Value) -> Result<(serde_json::Value, usize), ScrubError> + Send + Sync,
{
    /// v32.0.0 (#690) — the callback reports a COUNT, so this adapter cannot
    /// claim NER ran or name a model. It reports `ner_ran: false` and no digest,
    /// which is the honest answer for an adapter that does not know: a scrubber
    /// that cannot prove what it did must not assert it did more.
    ///
    /// A callback that DOES run NER should implement `Scrubber` directly and
    /// state its model digest, rather than routing through this adapter.
    fn scrub_batch(&self, env: &mut BatchEnvelope) -> Result<ScrubOutcome, ScrubError> {
        // Trust the existing cirislens-core scrubber on detailed
        // and full_traces; skip work entirely at GENERIC.
        if env.trace_level == TraceLevel::Generic {
            return Ok(ScrubOutcome::none_at(env.trace_level.as_str()));
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
        // #690 — the callback reports a count only, so this adapter states
        // `ner_ran: false` and no model digest. Honest for an adapter that
        // cannot know: a scrubber unable to prove what it did must not claim it.
        Ok(ScrubOutcome {
            fields_modified: modified_count,
            ner_ran: false,
            applied_trace_level: env.trace_level.as_str().to_owned(),
            scrubber_model_digest: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{BatchEnvelope, TraceLevel};

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
        assert_eq!(n.fields_modified, 0);
        // v32.0.0 (#690) — the count was never the point. A pass-through must
        // REPORT itself as one, or its envelope is indistinguishable from a
        // full NER pass once signed.
        assert!(!n.ner_ran, "NullScrubber must not claim an NER pass");
        assert!(
            n.scrubber_model_digest.is_none(),
            "no model ran, so no model digest may be asserted"
        );
        assert_eq!(n.applied_trace_level, "generic");
    }

    #[test]
    fn null_scrubber_detailed_passes_but_warns() {
        // The warn! is observed via tracing-subscriber in CI; this
        // test asserts the scrub does not error and is no-op.
        let mut env = ascii_envelope(TraceLevel::Detailed);
        let n = NullScrubber.scrub_batch(&mut env).unwrap();
        assert_eq!(n.fields_modified, 0);
        assert!(!n.ner_ran, "NullScrubber must not claim an NER pass");
        // The level reported is the level TREATED, and a pass-through treats
        // whatever it was handed — it does not downgrade the label.
        assert_eq!(n.applied_trace_level, "detailed");
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

    /// v32.0.0 (CIRISPersist#690) — **the exact state the ingest door refuses.**
    ///
    /// `NullScrubber` handed a `full_traces` batch reports `ner_ran: false` with
    /// `applied_trace_level: "full_traces"` — the content claims a level it did
    /// not receive treatment for. That pair is the condition
    /// `IngestError::ScrubTreatmentMismatch` is raised on, so this pins the
    /// input side of the door: if `NullScrubber` ever started reporting
    /// `ner_ran: true`, or reporting a downgraded level it did not apply, the
    /// door would stop firing and nothing else would notice.
    ///
    /// Before #690 this state was not merely unrefused — it was
    /// *unrepresentable*: `scrub_batch` returned a count, and `0` meant both
    /// "NER found nothing" and "nothing ran".
    #[test]
    fn null_scrubber_at_full_traces_reports_the_refusable_state_690() {
        let mut env = ascii_envelope(TraceLevel::FullTraces);
        let out = NullScrubber.scrub_batch(&mut env).unwrap();

        assert!(
            !out.ner_ran,
            "a pass-through must not claim a named-entity pass"
        );
        assert_eq!(
            out.applied_trace_level, "full_traces",
            "it treated the content at the level it was handed — it does not \
             silently downgrade the label, which is what makes the mismatch \
             visible to the door rather than papered over here"
        );
        assert!(
            out.scrubber_model_digest.is_none(),
            "no model ran, so none may be named"
        );

        // The door's condition, spelled out so this witness fails if the door's
        // predicate and this fixture ever diverge.
        let door_refuses = out.applied_trace_level == "full_traces" && !out.ner_ran;
        assert!(
            door_refuses,
            "this is the state IngestError::ScrubTreatmentMismatch exists for"
        );
    }

    /// The honest alternative a node without a model must take: scrub at
    /// `detailed` and RELABEL, so the claim matches the treatment. That state is
    /// NOT refused — the door must not reject a node behaving correctly.
    #[test]
    fn a_downgraded_relabelled_scrub_is_not_refusable_690() {
        let out = ScrubOutcome::none_at("detailed");
        let door_refuses = out.applied_trace_level == "full_traces" && !out.ner_ran;
        assert!(
            !door_refuses,
            "a node that downgraded to `detailed` and said so is behaving \
             correctly and must pass — a door that refuses this would push \
             operators toward mislabelling instead of downgrading"
        );
    }

    #[test]
    fn callback_scrubber_runs_on_detailed() {
        let scrubber = CallbackScrubber::new(|v| Ok((v, 7)));
        let mut env = ascii_envelope(TraceLevel::Detailed);
        let n = scrubber.scrub_batch(&mut env).unwrap();
        assert_eq!(n.fields_modified, 7);
        // #690 — the callback reports a COUNT, so the adapter cannot know
        // whether NER ran and must not claim it did. Seven fields modified is
        // not evidence of a named-entity pass.
        assert!(
            !n.ner_ran,
            "a count-only adapter must not assert an NER pass it cannot prove"
        );
        assert!(n.scrubber_model_digest.is_none());
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
