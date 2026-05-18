//! Scheduled tasks substrate wire types (v1.5.12, CIRISPersist#59 #4).
//!
//! Mirrors the row shape of `cirislens.scheduled_tasks` (Postgres) /
//! `cirislens_scheduled_tasks` (SQLite). JSON column
//! `deferral_history` lifts to `serde_json::Value`; Postgres maps it
//! as `JSONB`, SQLite stores it as TEXT.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Scheduled-task lifecycle status. **UPPERCASE on the wire to SQL**
/// — distinct from `tasks` / `thoughts` lowercase vocabularies. The
/// agent's `scheduled_tasks.status` column declares
/// `PENDING | ACTIVE | COMPLETE | FAILED`. The Rust enum variant
/// names stay TitleCase; SQL emit is uppercase via `as_sql_str`.
/// Serde format is snake_case (so JSON wire format is `pending` /
/// `active` / `complete` / `failed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledTaskStatus {
    #[default]
    Pending,
    Active,
    Complete,
    Failed,
}

impl ScheduledTaskStatus {
    /// Stable SQL CHECK value. UPPERCASE per the agent's vocabulary.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            ScheduledTaskStatus::Pending => "PENDING",
            ScheduledTaskStatus::Active => "ACTIVE",
            ScheduledTaskStatus::Complete => "COMPLETE",
            ScheduledTaskStatus::Failed => "FAILED",
        }
    }

    /// Inverse of [`Self::as_sql_str`]. Accepts only the UPPERCASE
    /// SQL vocabulary.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "PENDING" => Some(Self::Pending),
            "ACTIVE" => Some(Self::Active),
            "COMPLETE" => Some(Self::Complete),
            "FAILED" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// One row of the agent's `scheduled_tasks` substrate.
///
/// 15 columns. `deferral_history` (JSONB on PG, TEXT JSON on SQLite)
/// lifts to `serde_json::Value` so callers carry decoded values
/// across the trait boundary. `origin_thought_id` references
/// `cirislens.thoughts(thought_id)` via a DEFERRABLE FK on PG /
/// immediate FK on SQLite.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScheduledTask {
    pub id: String,
    pub name: String,
    pub goal_description: String,
    #[serde(default)]
    pub status: ScheduledTaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defer_until: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_cron: Option<String>,
    pub trigger_prompt: String,
    /// FK to `cirislens.thoughts(thought_id)` (PG: DEFERRABLE
    /// INITIALLY DEFERRED; SQLite: immediate).
    pub origin_thought_id: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_triggered_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_trigger_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub deferral_count: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferral_history: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by_agent: Option<String>,
    /// Multi-occurrence scoping. Default `"default"` for single-
    /// occurrence callers — matches the SQL column DEFAULT.
    #[serde(default = "default_occurrence")]
    pub agent_occurrence_id: String,
}

fn default_occurrence() -> String {
    "default".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_sql_round_trip() {
        for s in [
            ScheduledTaskStatus::Pending,
            ScheduledTaskStatus::Active,
            ScheduledTaskStatus::Complete,
            ScheduledTaskStatus::Failed,
        ] {
            assert_eq!(ScheduledTaskStatus::parse_str(s.as_sql_str()), Some(s));
        }
        assert_eq!(ScheduledTaskStatus::parse_str("pending"), None);
        assert_eq!(ScheduledTaskStatus::parse_str("UNKNOWN"), None);
    }

    #[test]
    fn status_sql_strings_are_uppercase() {
        // The whole point of this substrate's vocabulary — uppercase
        // on the agent's table, distinct from tasks/thoughts.
        assert_eq!(ScheduledTaskStatus::Pending.as_sql_str(), "PENDING");
        assert_eq!(ScheduledTaskStatus::Active.as_sql_str(), "ACTIVE");
        assert_eq!(ScheduledTaskStatus::Complete.as_sql_str(), "COMPLETE");
        assert_eq!(ScheduledTaskStatus::Failed.as_sql_str(), "FAILED");
    }

    #[test]
    fn status_serde_snake_case() {
        // Wire format (JSON) stays lowercase per project convention;
        // only the SQL CHECK string is uppercase.
        assert_eq!(
            serde_json::to_string(&ScheduledTaskStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&ScheduledTaskStatus::Complete).unwrap(),
            "\"complete\""
        );
        let s: ScheduledTaskStatus = serde_json::from_str("\"failed\"").unwrap();
        assert_eq!(s, ScheduledTaskStatus::Failed);
    }

    #[test]
    fn status_default_is_pending() {
        assert_eq!(ScheduledTaskStatus::default(), ScheduledTaskStatus::Pending);
    }

    #[test]
    fn scheduled_task_serde_round_trip_full_columns() {
        let now = Utc::now();
        let t = ScheduledTask {
            id: "task-abc".into(),
            name: "weekly-rollup".into(),
            goal_description: "compute weekly rollup".into(),
            status: ScheduledTaskStatus::Active,
            defer_until: Some(now),
            schedule_cron: Some("0 0 * * 0".into()),
            trigger_prompt: "Run weekly rollup".into(),
            origin_thought_id: "thought-1".into(),
            created_at: now,
            last_triggered_at: Some(now),
            next_trigger_at: Some(now),
            deferral_count: 3,
            deferral_history: Some(serde_json::json!([
                {"at": "2026-01-01T00:00:00Z", "reason": "user-cancelled"}
            ])),
            created_by_agent: Some("agent-x".into()),
            agent_occurrence_id: "occ-1".into(),
        };
        let s = serde_json::to_string(&t).unwrap();
        let back: ScheduledTask = serde_json::from_str(&s).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn scheduled_task_serde_minimal_columns_back_compat() {
        let now = Utc::now();
        let json = serde_json::json!({
            "id": "task-min",
            "name": "x",
            "goal_description": "y",
            "trigger_prompt": "go",
            "origin_thought_id": "thought-1",
            "created_at": now.to_rfc3339(),
        });
        let t: ScheduledTask = serde_json::from_value(json).unwrap();
        assert_eq!(t.status, ScheduledTaskStatus::Pending);
        assert_eq!(t.deferral_count, 0);
        assert_eq!(t.agent_occurrence_id, "default");
        assert!(t.defer_until.is_none());
        assert!(t.schedule_cron.is_none());
        assert!(t.last_triggered_at.is_none());
        assert!(t.next_trigger_at.is_none());
        assert!(t.deferral_history.is_none());
        assert!(t.created_by_agent.is_none());
    }
}
