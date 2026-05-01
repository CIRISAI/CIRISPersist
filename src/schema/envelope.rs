//! Outer batch envelope (TRACE_WIRE_FORMAT.md §1).
//!
//! Mission (MISSION.md §2 — `schema/`): the outer envelope is the
//! agent's first testimony per HTTP request. Strict typing here is
//! what makes downstream invariants (`consent_timestamp` required,
//! `trace_level` baked into signature input) checkable.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::trace::CompleteTrace;
use super::version::SchemaVersion;

/// Privacy / bandwidth tier (TRACE_WIRE_FORMAT.md §7).
///
/// `trace_level` is constant within a single batch envelope — an agent
/// at `generic` cannot mix `full_traces` events. The signature input
/// includes `trace_level` (TRACE_WIRE_FORMAT.md §8), so re-signing at
/// a different level produces a different signature; verification
/// cannot be confused across levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceLevel {
    /// All numeric scores, booleans, identifiers, attempt_index, sizes,
    /// durations, cost. **No content text.**
    Generic,
    /// Generic + reasoning text fields, override reasons, identified
    /// sources, sanitized stakeholder lists, prompt hashes.
    Detailed,
    /// Detailed + every prompt + every completion verbatim.
    FullTraces,
}

/// Optional correlation metadata
/// (TRACE_WIRE_FORMAT.md §1, agent's `correlation_metadata` field).
///
/// Only fields the agent has explicit user consent to share are
/// populated; `_strip_empty` removes anything `None` / empty before
/// signing. Mission (MISSION.md §2 — `scrub/`): consent gating is
/// upstream; the lens trusts what the agent shipped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_latitude: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_longitude: Option<String>,
}

/// One element of `events[]` in the batch
/// (TRACE_WIRE_FORMAT.md §2).
///
/// In production today the agent only ships `complete_trace` envelopes;
/// the per-event types in §5 of the wire-format spec are the
/// *components inside* a CompleteTrace. The forward-compat seam for
/// loose events is preserved as the `Loose` variant — when the agent
/// grows live streaming, we add component variants here without
/// breaking the existing path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum BatchEvent {
    /// A full sealed CompleteTrace + signature (TRACE_WIRE_FORMAT.md §3).
    CompleteTrace {
        trace: CompleteTrace,
        /// Same value as the batch's `trace_level`. Carried on the
        /// envelope element for §7 gating consistency checks.
        trace_level: TraceLevel,
    },
    // NOTE: when loose events arrive (TRACE_WIRE_FORMAT.md §13 forward
    // compat), add new variants here. Today this enum is effectively
    // single-variant.
}

/// Outer per-request batch envelope (TRACE_WIRE_FORMAT.md §1).
///
/// Required fields per spec:
/// - `consent_timestamp` — lens MUST 422 if missing or empty.
/// - `trace_level` — one of `generic`/`detailed`/`full_traces`.
/// - `trace_schema_version` — gated by [`SUPPORTED_VERSIONS`].
/// - `events` — non-empty; each item per [`BatchEvent`].
///
/// Mission constraint (MISSION.md §3 anti-pattern #1): no
/// `serde_json::Value` here. `correlation_metadata` is a typed
/// optional struct; future fields land as new optional fields, not as
/// a free-form blob.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchEnvelope {
    pub events: Vec<BatchEvent>,

    pub batch_timestamp: DateTime<Utc>,
    pub consent_timestamp: DateTime<Utc>,

    pub trace_level: TraceLevel,
    pub trace_schema_version: SchemaVersion,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_metadata: Option<CorrelationMetadata>,
}

impl BatchEnvelope {
    /// Parse a batch envelope from raw JSON bytes.
    ///
    /// All schema-version / trace-level / required-field gates fire
    /// here; the result is either a fully validated typed value or a
    /// structured error. Mission constraint (MISSION.md §2 —
    /// `verify/`): downstream verify path runs against typed values
    /// only.
    pub fn from_json(bytes: &[u8]) -> Result<Self, super::Error> {
        let env: Self = serde_json::from_slice(bytes)?;
        if env.events.is_empty() {
            return Err(super::Error::MissingField("events"));
        }
        Ok(env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mission category (MISSION.md §4): "Schema parity — does the
    /// parser preserve the agent's testimony byte-for-byte?"
    ///
    /// Recorded-batch JSON deserializes to a typed BatchEnvelope. Any
    /// field rename, type drift, or required-field flip surfaces here.
    #[test]
    fn parse_minimal_complete_trace_batch() {
        // Stripped minimal example from TRACE_WIRE_FORMAT.md §11
        // (one wakeup thought, one CompleteTrace event).
        let body = serde_json::json!({
          "events": [{
            "event_type": "complete_trace",
            "trace_level": "generic",
            "trace": {
              "trace_id": "trace-th_std_abc-20260430001553",
              "thought_id": "th_std_abc",
              "task_id": "ACCEPT_INCOMPLETENESS_xyz",
              "agent_id_hash": "deadbeef",
              "started_at": "2026-04-30T00:15:53.123456+00:00",
              "completed_at": "2026-04-30T00:16:12.789012+00:00",
              "trace_level": "generic",
              "trace_schema_version": "2.7.0",
              "components": [],
              "signature": "AAAA",
              "signature_key_id": "ciris-agent-key:dead"
            }
          }],
          "batch_timestamp": "2026-04-30T15:00:00+00:00",
          "consent_timestamp": "2025-01-01T00:00:00Z",
          "trace_level": "generic",
          "trace_schema_version": "2.7.0"
        });
        let env = BatchEnvelope::from_json(body.to_string().as_bytes())
            .expect("recorded minimal batch must parse");

        assert_eq!(env.trace_level, TraceLevel::Generic);
        assert_eq!(env.trace_schema_version.as_str(), "2.7.0");
        assert_eq!(env.events.len(), 1);
        match &env.events[0] {
            BatchEvent::CompleteTrace { trace, trace_level } => {
                assert_eq!(*trace_level, TraceLevel::Generic);
                assert_eq!(trace.thought_id, "th_std_abc");
            }
        }
    }

    /// Mission category §4 "Verify rejection": schema-version gate
    /// rejects unknown values with a structured error, not silent
    /// acceptance. (FSD §3.4 robustness primitive #3.)
    #[test]
    fn reject_unsupported_schema_version() {
        let body = serde_json::json!({
          "events": [],
          "batch_timestamp": "2026-04-30T15:00:00+00:00",
          "consent_timestamp": "2025-01-01T00:00:00Z",
          "trace_level": "generic",
          "trace_schema_version": "9.9.9"
        });
        let err = BatchEnvelope::from_json(body.to_string().as_bytes())
            .expect_err("9.9.9 must be rejected");
        assert!(
            err.to_string().contains("unsupported trace_schema_version"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_empty_events() {
        // FSD §3.3 step 1: events array is required. The lens cannot
        // 200-OK an empty batch — that would be silent acceptance of
        // nothing, which the mission (MISSION.md §3 anti-pattern #7)
        // rejects.
        let body = serde_json::json!({
          "events": [],
          "batch_timestamp": "2026-04-30T15:00:00+00:00",
          "consent_timestamp": "2025-01-01T00:00:00Z",
          "trace_level": "generic",
          "trace_schema_version": "2.7.0"
        });
        let err = BatchEnvelope::from_json(body.to_string().as_bytes()).unwrap_err();
        assert!(matches!(err, super::super::Error::MissingField("events")));
    }

    #[test]
    fn reject_unknown_trace_level() {
        let body = serde_json::json!({
          "events": [],
          "batch_timestamp": "2026-04-30T15:00:00+00:00",
          "consent_timestamp": "2025-01-01T00:00:00Z",
          "trace_level": "verbose",
          "trace_schema_version": "2.7.0"
        });
        assert!(BatchEnvelope::from_json(body.to_string().as_bytes()).is_err());
    }

    #[test]
    fn trace_level_serde_round_trip() {
        for &level in &[
            TraceLevel::Generic,
            TraceLevel::Detailed,
            TraceLevel::FullTraces,
        ] {
            let s = serde_json::to_string(&level).unwrap();
            let back: TraceLevel = serde_json::from_str(&s).unwrap();
            assert_eq!(back, level);
        }
        // Spelling matches TRACE_WIRE_FORMAT.md §1 verbatim.
        assert_eq!(serde_json::to_string(&TraceLevel::Generic).unwrap(), r#""generic""#);
        assert_eq!(serde_json::to_string(&TraceLevel::Detailed).unwrap(), r#""detailed""#);
        assert_eq!(
            serde_json::to_string(&TraceLevel::FullTraces).unwrap(),
            r#""full_traces""#
        );
    }
}
