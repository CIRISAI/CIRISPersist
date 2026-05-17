//! Incident records wire types (v0.8.3, CIRISPersist#37).

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// State-machine ladder (AV-55, extended in v1.5.5 / CIRISPersist#56).
///
/// Strict forward progress: every transition advances along this
/// order, no backflow accepted. The original V016 ladder was
/// `Open(0) → Investigating(1) → Resolved(2) → Closed(3)`.
///
/// v1.5.5 adds [`IncidentState::Recurring`] at rank 0 — parallel
/// to [`IncidentState::Open`], representing "open incident with
/// identified recurrence pattern". Because Recurring and Open
/// share rank 0, [`Self::can_transition_to`] rejects Open ↔
/// Recurring as a state transition; callers signal "this is the
/// recurring form of an open issue" by recording a new
/// Recurring-state incident referencing the same `problem_id`
/// via `correlation_keys` (the SQL layer accepts either state
/// at INSERT time, but does not let the state machine cross the
/// rank-0 plateau).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    Open,
    Investigating,
    Resolved,
    Closed,
    /// v1.5.5 — "open with identified recurrence pattern". Parallel
    /// to [`IncidentState::Open`] in the AV-55 ladder (same rank 0).
    Recurring,
}

impl IncidentState {
    /// Stable SQL CHECK value.
    pub fn as_sql_str(&self) -> &'static str {
        match self {
            IncidentState::Open => "open",
            IncidentState::Investigating => "investigating",
            IncidentState::Resolved => "resolved",
            IncidentState::Closed => "closed",
            IncidentState::Recurring => "recurring",
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "open" => Some(IncidentState::Open),
            "investigating" => Some(IncidentState::Investigating),
            "resolved" => Some(IncidentState::Resolved),
            "closed" => Some(IncidentState::Closed),
            "recurring" => Some(IncidentState::Recurring),
            _ => None,
        }
    }

    /// Ladder rank for monotonicity check. Higher means later.
    ///
    /// v1.5.5 — [`IncidentState::Recurring`] sits at rank 0
    /// alongside [`IncidentState::Open`]. Two rank-0 states means
    /// neither is reachable from the other through the state
    /// machine — see [`Self::can_transition_to`] for the strict
    /// semantics.
    pub fn rank(&self) -> u8 {
        match self {
            IncidentState::Open => 0,
            IncidentState::Recurring => 0,
            IncidentState::Investigating => 1,
            IncidentState::Resolved => 2,
            IncidentState::Closed => 3,
        }
    }

    /// AV-55: legal transitions advance forward only.
    ///
    /// v1.5.5: rank comparison is strict `>`, so same-rank
    /// transitions are rejected. This preserves the AV-55
    /// monotonicity invariant for the new rank-0 plateau — Open
    /// and Recurring cannot transition into each other; the
    /// recurrence relationship is encoded out-of-band via
    /// `correlation_keys` at record time, not via a transition.
    pub fn can_transition_to(&self, next: IncidentState) -> bool {
        next.rank() > self.rank()
    }
}

/// Severity ladder.
///
/// Two vocabularies are accepted, both round-trip lossless:
///
/// - **Syslog set** (V016, used by Persist's own internal
///   classification): `Info` < `Warning` < `Error` < `Critical`.
/// - **ITIL set** (v1.5.5, used by CIRISAgent's IncidentNode shape):
///   `Low` < `Medium` < `High` < `Critical`. The agent emits these
///   alongside `Critical` for operator-facing classification.
///
/// The SQL CHECK constraint (V022) accepts the union of both
/// vocabularies. The Rust enum carries them as distinct variants
/// so round-trip is lossless — callers that want a unified ladder
/// must translate at the type layer, not at the storage layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Info,
    Warning,
    Error,
    Critical,
    /// v1.5.5 — ITIL low.
    Low,
    /// v1.5.5 — ITIL medium.
    Medium,
    /// v1.5.5 — ITIL high.
    High,
}

impl IncidentSeverity {
    pub fn as_sql_str(&self) -> &'static str {
        match self {
            IncidentSeverity::Info => "info",
            IncidentSeverity::Warning => "warning",
            IncidentSeverity::Error => "error",
            IncidentSeverity::Critical => "critical",
            IncidentSeverity::Low => "low",
            IncidentSeverity::Medium => "medium",
            IncidentSeverity::High => "high",
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "info" => Some(IncidentSeverity::Info),
            "warning" => Some(IncidentSeverity::Warning),
            "error" => Some(IncidentSeverity::Error),
            "critical" => Some(IncidentSeverity::Critical),
            "low" => Some(IncidentSeverity::Low),
            "medium" => Some(IncidentSeverity::Medium),
            "high" => Some(IncidentSeverity::High),
            _ => None,
        }
    }
}

/// One incident record. Mirrors `cirislens.incident_records` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub incident_id: String,
    pub tenant_id: String,
    pub severity: IncidentSeverity,
    pub category: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// AV-56: capped at [`super::MAX_CORRELATION_KEYS`] entries of
    /// at most [`super::MAX_CORRELATION_KEY_BYTES`] each.
    pub correlation_keys: Vec<String>,
    pub state: IncidentState,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_notes: Option<String>,
    pub occurrences: i32,

    // ── v1.5.5 / CIRISPersist#56 — D1-full forensic fields ───────
    // All nullable; pre-V022 rows and non-EXCEPTION incidents
    // leave these `None`. Serde defaults keep wire-format compat
    // for v1.5.4 callers that don't emit them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_component: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_number: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urgency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection_method: Option<String>,
}

/// Filter for [`super::IncidentService::list_incidents`]. `tenant_id`
/// required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentFilter {
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<IncidentState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<IncidentSeverity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Filter to incidents with all of these keys in their
    /// correlation_keys (JSONB `@>` containment with array
    /// semantics).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub has_correlation_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen_before: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentCursor {
    pub version: String,
    pub last_ts: DateTime<Utc>,
    pub last_id: String,
}

impl IncidentCursor {
    pub fn from_trailing(last_ts: DateTime<Utc>, last_id: String) -> Self {
        Self {
            version: "v1".to_owned(),
            last_ts,
            last_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentListPage {
    pub items: Vec<Incident>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<IncidentCursor>,
}

/// Args for [`super::IncidentService::transition_state`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentTransition {
    pub incident_id: String,
    pub new_state: IncidentState,
    /// Required when `new_state ∈ {Resolved, Closed}`. Persist
    /// rejects with `InvalidArgument` if missing on those arms;
    /// optional for `Investigating`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_notes: Option<String>,
}

/// Lightweight reference returned from `correlate` — caller pulls
/// the full Incident via `list_incidents` if needed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentRef {
    pub incident_id: String,
    pub severity: IncidentSeverity,
    pub category: String,
    pub state: IncidentState,
    pub last_seen_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_ladder_monotonic() {
        // AV-55 — forward-only progression locked.
        assert!(IncidentState::Open.can_transition_to(IncidentState::Investigating));
        assert!(IncidentState::Investigating.can_transition_to(IncidentState::Resolved));
        assert!(IncidentState::Resolved.can_transition_to(IncidentState::Closed));
        assert!(IncidentState::Open.can_transition_to(IncidentState::Closed));

        // Backflow rejected.
        assert!(!IncidentState::Investigating.can_transition_to(IncidentState::Open));
        assert!(!IncidentState::Resolved.can_transition_to(IncidentState::Investigating));
        assert!(!IncidentState::Closed.can_transition_to(IncidentState::Open));

        // Same-state no-op also rejected (no idempotent transitions
        // — caller must check current state first if that's the
        // intent).
        assert!(!IncidentState::Open.can_transition_to(IncidentState::Open));
    }

    #[test]
    fn state_sql_round_trip() {
        for s in [
            IncidentState::Open,
            IncidentState::Investigating,
            IncidentState::Resolved,
            IncidentState::Closed,
            // v1.5.5 — extend the round-trip to cover Recurring.
            IncidentState::Recurring,
        ] {
            assert_eq!(IncidentState::from_sql_str(s.as_sql_str()), Some(s));
        }
        assert_eq!(IncidentState::from_sql_str("UNKNOWN"), None);
    }

    #[test]
    fn severity_sql_round_trip() {
        for sev in [
            IncidentSeverity::Info,
            IncidentSeverity::Warning,
            IncidentSeverity::Error,
            IncidentSeverity::Critical,
            // v1.5.5 — extend to cover the ITIL alias set.
            IncidentSeverity::Low,
            IncidentSeverity::Medium,
            IncidentSeverity::High,
        ] {
            assert_eq!(IncidentSeverity::from_sql_str(sev.as_sql_str()), Some(sev));
        }
    }

    /// v1.5.5 (CIRISPersist#56) — Recurring lives at rank 0 next
    /// to Open. Two states at rank 0 means neither is reachable
    /// from the other via the state machine (see
    /// [`recurring_not_a_transition_from_open`]); the recurrence
    /// relationship is recorded out-of-band via correlation_keys.
    #[test]
    fn recurring_parallel_to_open_in_rank() {
        assert_eq!(IncidentState::Recurring.rank(), 0);
        assert_eq!(IncidentState::Open.rank(), 0);
        assert_eq!(IncidentState::Recurring.rank(), IncidentState::Open.rank());
        // Other ladder ranks unchanged.
        assert_eq!(IncidentState::Investigating.rank(), 1);
        assert_eq!(IncidentState::Resolved.rank(), 2);
        assert_eq!(IncidentState::Closed.rank(), 3);
    }

    /// v1.5.5 — Recurring is NOT reachable from Open as a state
    /// transition (same-rank). Callers record a separate
    /// Recurring-state incident referencing the original problem
    /// via correlation_keys; they do not transition into it.
    #[test]
    fn recurring_not_a_transition_from_open() {
        assert!(!IncidentState::Open.can_transition_to(IncidentState::Recurring));
        assert!(!IncidentState::Recurring.can_transition_to(IncidentState::Open));
        // But Recurring is still a real lifecycle starting state —
        // it can progress forward exactly like Open does.
        assert!(IncidentState::Recurring.can_transition_to(IncidentState::Investigating));
        assert!(IncidentState::Recurring.can_transition_to(IncidentState::Resolved));
        assert!(IncidentState::Recurring.can_transition_to(IncidentState::Closed));
        // And backflow from a later state into Recurring stays
        // rejected.
        assert!(!IncidentState::Investigating.can_transition_to(IncidentState::Recurring));
        assert!(!IncidentState::Resolved.can_transition_to(IncidentState::Recurring));
        assert!(!IncidentState::Closed.can_transition_to(IncidentState::Recurring));
    }

    #[test]
    fn state_serde_snake_case() {
        let s = serde_json::to_string(&IncidentState::Investigating).unwrap();
        assert_eq!(s, "\"investigating\"");
    }

    #[test]
    fn incident_serde_round_trip() {
        let inc = Incident {
            incident_id: "abc".into(),
            tenant_id: "tnt-x".into(),
            severity: IncidentSeverity::Error,
            category: "service_failure".into(),
            title: "LLM call timeout".into(),
            description: Some("3 consecutive timeouts".into()),
            correlation_keys: vec!["service:llm".into(), "model:opus".into()],
            state: IncidentState::Open,
            first_seen_at: Utc::now(),
            last_seen_at: Utc::now(),
            resolved_at: None,
            resolution_notes: None,
            occurrences: 3,
            incident_type: None,
            source_component: None,
            handler_name: None,
            exception_type: None,
            stack_trace: None,
            filename: None,
            line_number: None,
            function_name: None,
            impact: None,
            urgency: None,
            detection_method: None,
        };
        let s = serde_json::to_string(&inc).unwrap();
        let back: Incident = serde_json::from_str(&s).unwrap();
        assert_eq!(inc, back);
    }

    /// v1.5.5 (CIRISPersist#56) — populate all 11 forensic fields
    /// and assert lossless serde round-trip.
    #[test]
    fn incident_serde_round_trip_with_forensic_fields() {
        let inc = Incident {
            incident_id: "abc".into(),
            tenant_id: "tnt-x".into(),
            severity: IncidentSeverity::High,
            category: "exception".into(),
            title: "ValueError in dispatch".into(),
            description: Some("dispatch raised ValueError".into()),
            correlation_keys: vec!["component:dispatch".into()],
            state: IncidentState::Recurring,
            first_seen_at: Utc::now(),
            last_seen_at: Utc::now(),
            resolved_at: None,
            resolution_notes: None,
            occurrences: 5,
            incident_type: Some("EXCEPTION".into()),
            source_component: Some("dispatch_handler".into()),
            handler_name: Some("on_message".into()),
            exception_type: Some("ValueError".into()),
            stack_trace: Some("Traceback (most recent call last):\n  …".into()),
            filename: Some("ciris_agent/dispatch.py".into()),
            line_number: Some(142),
            function_name: Some("on_message".into()),
            impact: Some("medium".into()),
            urgency: Some("high".into()),
            detection_method: Some("exception_hook".into()),
        };
        let s = serde_json::to_string(&inc).unwrap();
        let back: Incident = serde_json::from_str(&s).unwrap();
        assert_eq!(inc, back);

        // Per-field spot-check (catches accidental rename in
        // serde attrs).
        assert_eq!(back.incident_type.as_deref(), Some("EXCEPTION"));
        assert_eq!(back.source_component.as_deref(), Some("dispatch_handler"));
        assert_eq!(back.handler_name.as_deref(), Some("on_message"));
        assert_eq!(back.exception_type.as_deref(), Some("ValueError"));
        assert!(back.stack_trace.is_some());
        assert_eq!(back.filename.as_deref(), Some("ciris_agent/dispatch.py"));
        assert_eq!(back.line_number, Some(142));
        assert_eq!(back.function_name.as_deref(), Some("on_message"));
        assert_eq!(back.impact.as_deref(), Some("medium"));
        assert_eq!(back.urgency.as_deref(), Some("high"));
        assert_eq!(back.detection_method.as_deref(), Some("exception_hook"));
    }

    /// v1.5.5 — back-compat: a v1.5.4-shape JSON (no forensic
    /// fields) must deserialize cleanly with all forensic fields
    /// defaulted to None.
    #[test]
    fn incident_serde_back_compat_pre_v155_shape() {
        let json = serde_json::json!({
            "incident_id": "abc",
            "tenant_id": "tnt-x",
            "severity": "error",
            "category": "service_failure",
            "title": "LLM call timeout",
            "correlation_keys": ["service:llm"],
            "state": "open",
            "first_seen_at": "2024-01-01T00:00:00Z",
            "last_seen_at": "2024-01-01T00:00:00Z",
            "occurrences": 1
        });
        let inc: Incident = serde_json::from_value(json).unwrap();
        assert_eq!(inc.incident_type, None);
        assert_eq!(inc.source_component, None);
        assert_eq!(inc.line_number, None);
        assert_eq!(inc.stack_trace, None);
    }
}
