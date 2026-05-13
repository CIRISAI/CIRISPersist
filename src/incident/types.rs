//! Incident records wire types (v0.8.3, CIRISPersist#37).

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// State-machine ladder (AV-55). Strict forward progress: every
/// transition advances along this order, no backflow accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    Open,
    Investigating,
    Resolved,
    Closed,
}

impl IncidentState {
    /// Stable SQL CHECK value.
    pub fn as_sql_str(&self) -> &'static str {
        match self {
            IncidentState::Open => "open",
            IncidentState::Investigating => "investigating",
            IncidentState::Resolved => "resolved",
            IncidentState::Closed => "closed",
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "open" => Some(IncidentState::Open),
            "investigating" => Some(IncidentState::Investigating),
            "resolved" => Some(IncidentState::Resolved),
            "closed" => Some(IncidentState::Closed),
            _ => None,
        }
    }

    /// Ladder rank for monotonicity check. Higher means later.
    pub fn rank(&self) -> u8 {
        match self {
            IncidentState::Open => 0,
            IncidentState::Investigating => 1,
            IncidentState::Resolved => 2,
            IncidentState::Closed => 3,
        }
    }

    /// AV-55: legal transitions advance forward only.
    pub fn can_transition_to(&self, next: IncidentState) -> bool {
        next.rank() > self.rank()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl IncidentSeverity {
    pub fn as_sql_str(&self) -> &'static str {
        match self {
            IncidentSeverity::Info => "info",
            IncidentSeverity::Warning => "warning",
            IncidentSeverity::Error => "error",
            IncidentSeverity::Critical => "critical",
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "info" => Some(IncidentSeverity::Info),
            "warning" => Some(IncidentSeverity::Warning),
            "error" => Some(IncidentSeverity::Error),
            "critical" => Some(IncidentSeverity::Critical),
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
        ] {
            assert_eq!(IncidentSeverity::from_sql_str(sev.as_sql_str()), Some(sev));
        }
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
        };
        let s = serde_json::to_string(&inc).unwrap();
        let back: Incident = serde_json::from_str(&s).unwrap();
        assert_eq!(inc, back);
    }
}
