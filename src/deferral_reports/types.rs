//! Deferral-reports substrate wire types (v1.5.14,
//! CIRISPersist#59 #6).
//!
//! Mirrors the row shape of `cirislens.deferral_reports` (Postgres)
//! / `cirislens_deferral_reports` (SQLite). JSON column `package`
//! lifts to `serde_json::Value` (Postgres maps it as JSONB; SQLite
//! stores it as TEXT). Both `resolved_at` and `resolution_notes`
//! are persist-only nullable columns supporting the
//! `list_active_deferrals` hot path; they default to `None` so
//! deserialization of agent-shape (5-column) JSON stays valid.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One row of the agent's `deferral_reports` substrate.
///
/// 7 columns. Agent ships 5: `message_id` (PK), `task_id`,
/// `thought_id`, `package` (renamed from `package_json` —
/// idiomatic JSONB column name on PG, SQLite drops the suffix for
/// cross-backend consistency), and `created_at`. Persist adds 2:
/// `resolved_at` + `resolution_notes`, both nullable, supporting
/// the WA `list_active_deferrals` hot path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeferralReport {
    pub message_id: String,
    /// FK → `cirislens.tasks(task_id)`. NOT NULL.
    pub task_id: String,
    /// FK → `cirislens.thoughts(thought_id)`. NOT NULL.
    pub thought_id: String,
    /// WA deferral payload — free-form JSON (the agent serializes
    /// the `DeferralPackage` schema here). Nullable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    /// Persist-only — when `Some(_)`, the deferral has been
    /// resolved by a WA and won't appear in
    /// [`super::DeferralReportService::list_active_deferrals`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,
    /// Persist-only — free-form WA resolution notes. Paired with
    /// `resolved_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_notes: Option<String>,
}

/// Filter for [`super::DeferralReportService::list_active_deferrals`].
///
/// All fields optional. The trait surface filters on
/// `resolved_at IS NULL` unconditionally — the partial index
/// `deferral_reports_active` covers that predicate. Additional
/// fields narrow further:
///
/// - `task_id` / `thought_id` — direct FK filter.
/// - `created_after` / `created_before` — time-window scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeferralFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thought_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_before: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferral_serde_round_trip_full_columns() {
        let now = Utc::now();
        let r = DeferralReport {
            message_id: "msg-abc".into(),
            task_id: "task-1".into(),
            thought_id: "thought-1".into(),
            package: Some(serde_json::json!({"reason": "out_of_scope"})),
            created_at: now,
            resolved_at: Some(now + chrono::Duration::hours(1)),
            resolution_notes: Some("approved".into()),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: DeferralReport = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn deferral_serde_minimal_agent_shape_back_compat() {
        // Agent's 5-column shape — no package / no resolved_at /
        // no resolution_notes. Should deserialize cleanly with
        // defaults.
        let now = Utc::now();
        let json = serde_json::json!({
            "message_id": "msg-min",
            "task_id": "t-1",
            "thought_id": "th-1",
            "created_at": now.to_rfc3339(),
        });
        let r: DeferralReport = serde_json::from_value(json).unwrap();
        assert!(r.package.is_none());
        assert!(r.resolved_at.is_none());
        assert!(r.resolution_notes.is_none());
    }

    #[test]
    fn deferral_filter_default_is_empty() {
        let f = DeferralFilter::default();
        assert!(f.task_id.is_none());
        assert!(f.thought_id.is_none());
        assert!(f.created_after.is_none());
        assert!(f.created_before.is_none());
    }
}
