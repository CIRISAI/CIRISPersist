//! Agent tasks substrate wire types (v1.5.9, CIRISPersist#59 #1).
//!
//! Mirrors the row shape of `cirislens.tasks` (Postgres) /
//! `cirislens_tasks` (SQLite). JSON-string columns (`context_json`,
//! `outcome_json`, `images_json`) lift to `serde_json::Value` so
//! callers don't have to round-trip through string on every put/get;
//! Postgres maps them as `JSONB`, SQLite stores them as TEXT.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Task lifecycle status. Vocabulary mirrors the CIRISAgent 2.8.13
/// task state machine: `pending → active → (completed | failed |
/// cancelled | deferred)`. Persist does not enforce transition
/// monotonicity at the trait surface — the agent owns the state
/// machine and persist accepts whatever the agent asserts. The
/// CHECK constraint at the schema layer keeps the vocabulary
/// closed-set so a bad caller can't write an unknown status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Active,
    Completed,
    Failed,
    Cancelled,
    Deferred,
}

impl TaskStatus {
    /// Stable SQL CHECK value.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            TaskStatus::Pending => "pending",
            TaskStatus::Active => "active",
            TaskStatus::Completed => "completed",
            TaskStatus::Failed => "failed",
            TaskStatus::Cancelled => "cancelled",
            TaskStatus::Deferred => "deferred",
        }
    }

    /// Inverse of [`Self::as_sql_str`].
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(TaskStatus::Pending),
            "active" => Some(TaskStatus::Active),
            "completed" => Some(TaskStatus::Completed),
            "failed" => Some(TaskStatus::Failed),
            "cancelled" => Some(TaskStatus::Cancelled),
            "deferred" => Some(TaskStatus::Deferred),
            _ => None,
        }
    }
}

/// One row of the agent's `tasks` substrate.
///
/// `context`, `outcome`, `images` lift to `serde_json::Value` so
/// callers carry decoded JSON values across the trait boundary.
/// Postgres stores them as JSONB; SQLite stores them as raw JSON
/// TEXT (the backend handles the encoding both ways).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    pub task_id: String,
    pub channel_id: String,
    pub description: String,
    pub status: TaskStatus,
    #[serde(default)]
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<String>,
    /// Maps to the SQL `context_json` column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
    /// Maps to the SQL `outcome_json` column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<serde_json::Value>,
    #[serde(default)]
    pub retry_count: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub updated_info_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_info_content: Option<String>,
    /// Multi-occurrence scoping. Default `"default"` for
    /// single-occurrence callers — matches the SQL column DEFAULT.
    pub agent_occurrence_id: String,
    /// Maps to the SQL `images_json` column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<serde_json::Value>,
}

/// Filter for [`super::TaskService::list_tasks`].
///
/// All fields optional. The PG happy path hits the
/// `tasks_status_occurrence` index when `agent_occurrence_id` +
/// `status` are both set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_occurrence_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TaskStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_before: Option<DateTime<Utc>>,
}

/// Cursor for list-tasks pagination. Captures the trailing
/// `(updated_at, task_id)` tuple of the previous page so the next
/// page's WHERE-clause is `(updated_at, task_id) < (last_ts,
/// last_id)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskCursor {
    pub version: String,
    pub last_ts: DateTime<Utc>,
    pub last_id: String,
}

impl TaskCursor {
    /// Build a v1 cursor from a trailing row.
    pub fn from_trailing(last_ts: DateTime<Utc>, last_id: String) -> Self {
        Self {
            version: "v1".to_owned(),
            last_ts,
            last_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskListPage {
    pub items: Vec<Task>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<TaskCursor>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_sql_round_trip() {
        for s in [
            TaskStatus::Pending,
            TaskStatus::Active,
            TaskStatus::Completed,
            TaskStatus::Failed,
            TaskStatus::Cancelled,
            TaskStatus::Deferred,
        ] {
            assert_eq!(TaskStatus::parse_str(s.as_sql_str()), Some(s));
        }
        assert_eq!(TaskStatus::parse_str("UNKNOWN"), None);
    }

    #[test]
    fn status_serde_snake_case() {
        let s = serde_json::to_string(&TaskStatus::Cancelled).unwrap();
        assert_eq!(s, "\"cancelled\"");
    }

    #[test]
    fn task_serde_round_trip_full_columns() {
        let now = Utc::now();
        let t = Task {
            task_id: "task-abc".into(),
            channel_id: "chan-1".into(),
            description: "do the thing".into(),
            status: TaskStatus::Active,
            priority: 7,
            created_at: now,
            updated_at: now,
            parent_task_id: Some("task-parent".into()),
            context: Some(serde_json::json!({"k": "v", "n": 42})),
            outcome: Some(serde_json::json!({"ok": true})),
            retry_count: 2,
            signed_by: Some("agent-sig-id".into()),
            signature: Some("base64sig==".into()),
            signed_at: Some(now),
            updated_info_available: true,
            updated_info_content: Some("there is news".into()),
            agent_occurrence_id: "occ-1".into(),
            images: Some(serde_json::json!(["sha:aaa", "sha:bbb"])),
        };
        let s = serde_json::to_string(&t).unwrap();
        let back: Task = serde_json::from_str(&s).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn task_serde_minimal_columns_back_compat() {
        // Only the required columns present — every Optional /
        // defaulted field defaults cleanly.
        let now = Utc::now();
        let json = serde_json::json!({
            "task_id": "task-min",
            "channel_id": "chan-min",
            "description": "minimal",
            "status": "pending",
            "created_at": now.to_rfc3339(),
            "updated_at": now.to_rfc3339(),
            "agent_occurrence_id": "default"
        });
        let t: Task = serde_json::from_value(json).unwrap();
        assert_eq!(t.priority, 0);
        assert_eq!(t.retry_count, 0);
        assert!(!t.updated_info_available);
        assert!(t.parent_task_id.is_none());
        assert!(t.context.is_none());
        assert!(t.outcome.is_none());
        assert!(t.images.is_none());
    }

    #[test]
    fn cursor_from_trailing_sets_version_v1() {
        let now = Utc::now();
        let c = TaskCursor::from_trailing(now, "id-x".into());
        assert_eq!(c.version, "v1");
        assert_eq!(c.last_id, "id-x");
        assert_eq!(c.last_ts, now);
    }
}
