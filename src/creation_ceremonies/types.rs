//! Creation-ceremonies substrate wire types (v1.5.16,
//! CIRISPersist#59 #8).
//!
//! Mirrors the row shape of `cirislens.creation_ceremonies`
//! (Postgres) / `cirislens_creation_ceremonies` (SQLite). 14
//! columns matching CIRISAgent v2.8.13's `creation_ceremonies`
//! verbatim — identity-creation history. No FKs (agent_id
//! references are free-form pointers).

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Ceremony lifecycle status. **LOWERCASE snake_case on the wire
/// and in SQL.** 5-value vocabulary matching the agent's column.
///
/// Wire format (JSON via serde) is `rename_all = "snake_case"` so
/// `InProgress` serializes to `"in_progress"` — matching the SQL
/// string directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyStatus {
    /// Ceremony queued, not yet started.
    #[default]
    Pending,
    /// Ceremony in progress — creator agent is preparing the new
    /// agent's substrate (template hash, capability list, etc.).
    InProgress,
    /// Ceremony completed — new agent is alive in the federation.
    Completed,
    /// Ceremony failed mid-flight — new agent did NOT come into
    /// being.
    Failed,
    /// Ceremony's outcome was retroactively revoked (e.g. WA
    /// invalidates the creation after the fact). The new agent
    /// may have existed for some interval but is no longer
    /// considered a legitimate federation member.
    Revoked,
}

impl CeremonyStatus {
    /// Stable SQL CHECK value (lowercase + snake_case for
    /// `in_progress`).
    pub fn as_sql_str(self) -> &'static str {
        match self {
            CeremonyStatus::Pending => "pending",
            CeremonyStatus::InProgress => "in_progress",
            CeremonyStatus::Completed => "completed",
            CeremonyStatus::Failed => "failed",
            CeremonyStatus::Revoked => "revoked",
        }
    }

    /// Inverse of [`Self::as_sql_str`]. Accepts only the lowercase
    /// SQL vocabulary.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "in_progress" => Some(Self::InProgress),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// One row of the `creation_ceremonies` substrate.
///
/// 14 columns. Matches the agent's column-for-column. No FKs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreationCeremony {
    /// Caller-supplied ceremony identifier. NOT NULL, PK.
    pub ceremony_id: String,
    /// Wall-clock time at which the ceremony was recorded.
    pub timestamp: DateTime<Utc>,
    /// Identity of the agent performing the creation.
    pub creator_agent_id: String,
    /// Identity of the human witness / sponsor.
    pub creator_human_id: String,
    /// Identity of the WA who signed off on the ceremony.
    pub wise_authority_id: String,
    /// Identity of the new agent being brought into being.
    pub new_agent_id: String,
    /// Human-readable name for the new agent.
    pub new_agent_name: String,
    /// Stated purpose / role of the new agent.
    pub new_agent_purpose: String,
    /// Optional longer-form description of the new agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_agent_description: Option<String>,
    /// Free-form text justifying why this agent is being created.
    /// NOT NULL — the ceremony is supposed to carry a reason.
    pub creation_justification: String,
    /// Optional free-form capability descriptor. Agent stores it as
    /// a JSON-encoded array of strings; persist preserves the wire
    /// shape (TEXT, not JSONB) so callers can ride the same payload
    /// literally across the absorb boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_capabilities: Option<String>,
    /// Free-form ethical considerations recorded at ceremony time.
    /// NOT NULL — the ceremony is supposed to carry the ethical
    /// reasoning that made the WA sign off.
    pub ethical_considerations: String,
    /// Optional hash of the template profile used to instantiate
    /// the new agent's substrate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_profile_hash: Option<String>,
    /// Lifecycle status.
    pub ceremony_status: CeremonyStatus,
}

/// Filter for [`super::CreationCeremonyService::list_ceremonies`].
///
/// All fields optional. Hot-path index dispatch:
///
/// - `new_agent_id` → `creation_ceremonies_new_agent`
/// - `creator_agent_id` (+ timestamp window) →
///   `creation_ceremonies_creator`
/// - `wise_authority_id` (+ timestamp window) →
///   `creation_ceremonies_wa`
/// - (none / timestamp-only) → `creation_ceremonies_timeline`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CeremonyFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_human_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wise_authority_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceremony_status: Option<CeremonyStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_before: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_sql_round_trip() {
        for s in [
            CeremonyStatus::Pending,
            CeremonyStatus::InProgress,
            CeremonyStatus::Completed,
            CeremonyStatus::Failed,
            CeremonyStatus::Revoked,
        ] {
            assert_eq!(CeremonyStatus::parse_str(s.as_sql_str()), Some(s));
        }
        assert_eq!(CeremonyStatus::parse_str("PENDING"), None);
        assert_eq!(CeremonyStatus::parse_str("inProgress"), None);
        assert_eq!(CeremonyStatus::parse_str("UNKNOWN"), None);
    }

    #[test]
    fn status_sql_strings_are_lowercase_snake_case() {
        assert_eq!(CeremonyStatus::Pending.as_sql_str(), "pending");
        assert_eq!(CeremonyStatus::InProgress.as_sql_str(), "in_progress");
        assert_eq!(CeremonyStatus::Completed.as_sql_str(), "completed");
        assert_eq!(CeremonyStatus::Failed.as_sql_str(), "failed");
        assert_eq!(CeremonyStatus::Revoked.as_sql_str(), "revoked");
    }

    #[test]
    fn status_serde_snake_case_wire_format() {
        assert_eq!(
            serde_json::to_string(&CeremonyStatus::InProgress).unwrap(),
            "\"in_progress\""
        );
        assert_eq!(
            serde_json::to_string(&CeremonyStatus::Revoked).unwrap(),
            "\"revoked\""
        );
        let s: CeremonyStatus = serde_json::from_str("\"in_progress\"").unwrap();
        assert_eq!(s, CeremonyStatus::InProgress);
    }

    #[test]
    fn status_default_is_pending() {
        assert_eq!(CeremonyStatus::default(), CeremonyStatus::Pending);
    }

    #[test]
    fn ceremony_serde_round_trip_all_14_columns() {
        let now = Utc::now();
        let c = CreationCeremony {
            ceremony_id: "ceremony-abc".into(),
            timestamp: now,
            creator_agent_id: "creator-a".into(),
            creator_human_id: "human-h".into(),
            wise_authority_id: "wa-w".into(),
            new_agent_id: "new-n".into(),
            new_agent_name: "Newton".into(),
            new_agent_purpose: "scientific reasoning".into(),
            new_agent_description: Some("a thoughtful agent".into()),
            creation_justification: "operator demand".into(),
            expected_capabilities: Some(r#"["a", "b", "c"]"#.into()),
            ethical_considerations: "alignment confirmed".into(),
            template_profile_hash: Some("sha256:deadbeef".into()),
            ceremony_status: CeremonyStatus::Completed,
        };
        let s = serde_json::to_string(&c).unwrap();
        let back: CreationCeremony = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn ceremony_serde_minimal_required_columns() {
        let now = Utc::now();
        let json = serde_json::json!({
            "ceremony_id": "ceremony-min",
            "timestamp": now.to_rfc3339(),
            "creator_agent_id": "a",
            "creator_human_id": "h",
            "wise_authority_id": "w",
            "new_agent_id": "n",
            "new_agent_name": "name",
            "new_agent_purpose": "purpose",
            "creation_justification": "why",
            "ethical_considerations": "considered",
            "ceremony_status": "pending",
        });
        let c: CreationCeremony = serde_json::from_value(json).unwrap();
        assert!(c.new_agent_description.is_none());
        assert!(c.expected_capabilities.is_none());
        assert!(c.template_profile_hash.is_none());
        assert_eq!(c.ceremony_status, CeremonyStatus::Pending);
    }

    #[test]
    fn ceremony_filter_default_is_empty() {
        let f = CeremonyFilter::default();
        assert!(f.creator_agent_id.is_none());
        assert!(f.creator_human_id.is_none());
        assert!(f.wise_authority_id.is_none());
        assert!(f.new_agent_id.is_none());
        assert!(f.ceremony_status.is_none());
        assert!(f.timestamp_after.is_none());
        assert!(f.timestamp_before.is_none());
    }
}
