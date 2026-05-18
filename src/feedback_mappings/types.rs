//! Feedback-mappings substrate wire types (v1.5.18, CIRISPersist#59 #10).
//!
//! Mirrors the row shape of `cirislens.feedback_mappings` (Postgres)
//! / `cirislens_feedback_mappings` (SQLite). 5 columns matching
//! CIRISAgent v2.8.13's `feedback_mappings` verbatim — the link
//! between an inbound feedback Discord-message (or analogous wire-
//! message id) and the agent thought that resolved against it.
//!
//! `feedback_type` is free-form text — the agent uses values like
//! `"approval"`, `"correction"`, `"clarification"` but doesn't
//! constrain them at the schema layer.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One row of the `feedback_mappings` substrate.
///
/// 5 columns. Matches the agent's column-for-column.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedbackMapping {
    /// Caller-supplied feedback identifier. NOT NULL, PK. The agent
    /// generates these as wire-id-shaped strings.
    pub feedback_id: String,
    /// Optional wire-message id (typically the Discord message id
    /// that delivered the feedback). Nullable in the agent's schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_message_id: Option<String>,
    /// Optional FK to `cirislens.thoughts(thought_id)` (PG) /
    /// `cirislens_thoughts(thought_id)` (SQLite). When `Some(_)`,
    /// the referenced thought MUST exist; when `None`, the feedback
    /// is recorded without a resolution target yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_thought_id: Option<String>,
    /// Free-form feedback-type discriminator. Agent uses values like
    /// `"approval"`, `"correction"`, `"clarification"` — no DB-level
    /// CHECK constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback_type: Option<String>,
    /// Wall-clock time the feedback was recorded. NOT NULL with a
    /// `NOW()` / `datetime('now', 'subsec')` default so callers
    /// can omit it and get a server-side timestamp.
    pub created_at: DateTime<Utc>,
}

/// Filter for [`super::FeedbackMappingService::list_feedback`].
///
/// All fields optional. The trait surface orders newest-first by
/// `created_at`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedbackFilter {
    /// Narrow to feedback originating from a specific wire-message
    /// id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_message_id: Option<String>,
    /// Narrow to feedback of a specific type (free-form string —
    /// agent uses values like `"approval"`, `"correction"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback_type: Option<String>,
    /// Inclusive lower bound on `created_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_after: Option<DateTime<Utc>>,
    /// Inclusive upper bound on `created_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_before: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_full() -> FeedbackMapping {
        FeedbackMapping {
            feedback_id: "fb-abc".into(),
            source_message_id: Some("msg-xyz".into()),
            target_thought_id: Some("th-1".into()),
            feedback_type: Some("approval".into()),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn feedback_serde_round_trip_all_5_columns() {
        let f = mk_full();
        let s = serde_json::to_string(&f).unwrap();
        let back: FeedbackMapping = serde_json::from_str(&s).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn feedback_serde_minimal_required_columns() {
        // Only feedback_id + created_at are required at the type
        // layer (the SQL columns themselves are nullable on the
        // optional 3).
        let now = Utc::now();
        let json = serde_json::json!({
            "feedback_id": "fb-min",
            "created_at": now.to_rfc3339(),
        });
        let f: FeedbackMapping = serde_json::from_value(json).unwrap();
        assert!(f.source_message_id.is_none());
        assert!(f.target_thought_id.is_none());
        assert!(f.feedback_type.is_none());
    }

    #[test]
    fn feedback_filter_default_is_empty() {
        let f = FeedbackFilter::default();
        assert!(f.source_message_id.is_none());
        assert!(f.feedback_type.is_none());
        assert!(f.created_after.is_none());
        assert!(f.created_before.is_none());
    }
}
