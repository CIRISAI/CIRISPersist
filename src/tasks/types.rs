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

/// Task lifecycle status: `pending → active → (completed | failed |
/// rejected | cancelled | deferred)`. Persist does not enforce
/// transition monotonicity at the trait surface — the agent owns the
/// state machine and persist accepts whatever the agent asserts. The
/// CHECK constraint at the schema layer keeps the vocabulary
/// closed-set so a bad caller can't write an unknown status.
///
/// **This set is a SUPERSET of the consumer enum it serves**, and that
/// direction is load-bearing. The consumer is
/// `ciris_engine.schemas.runtime.enums.TaskStatus` in CIRISAgent, which
/// declares `pending / active / completed / failed / deferred /
/// rejected`. A value persist is missing is not a refusal the caller can
/// route around: the agent logs the `ValueError` and continues, the write
/// never lands, and the task stays `active` forever with nothing to
/// retry it — the CIRISAgent#1077 wedge, which persist shipped for the
/// whole life of the six-member set. A value persist has that the agent
/// does not (`cancelled`, here) is inert.
///
/// So: when the consumer enum grows, this one grows with it, in a MINOR,
/// with a CHECK-widening migration on both backends. It never shrinks.
/// `every_status_the_agent_can_write_round_trips` pins the consumer set
/// as literals so an addition here that misses the migration — or a
/// migration that misses this — is a red, not a production wedge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Active,
    Completed,
    Failed,
    Cancelled,
    Deferred,
    /// v41.2.0 (CIRISPersist#810, CIRISAgent#1077) — the agent's
    /// `TaskStatus.REJECTED`. Distinct from `Failed` (the task ran and
    /// did not succeed) and from `Deferred` (the task is waiting on a
    /// wise authority): the work was declined, and the agent's
    /// `reject` handler is the only writer of it.
    Rejected,
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
            TaskStatus::Rejected => "rejected",
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
            "rejected" => Some(TaskStatus::Rejected),
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
    /// v1.5.21 (CIRISPersist#62) — push agent's `get_tasks_older_than`
    /// cutoff into a SQL `created_at < ?` predicate instead of
    /// paginating the whole occurrence and filtering in Python.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_before: Option<DateTime<Utc>>,
    /// v1.5.21 (CIRISPersist#62) — symmetric `created_at >= ?` for
    /// archive sweep upper-bound queries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_after: Option<DateTime<Utc>>,
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

/// Outcome of [`super::TaskService::upsert_task`] (v1.5.22,
/// CIRISPersist#61). Carries the canonical row the caller should
/// treat as authoritative.
///
/// - [`Self::Stored`] — INSERT (or ON CONFLICT(task_id) DO UPDATE
///   resolving to the caller's row). The caller's `task_id` won.
/// - [`Self::AlreadyExists`] — V036 unique index on
///   `(agent_occurrence_id, context_json->>'correlation_id')`
///   tripped: a different task with the same correlation_id is
///   already present under this occurrence. The returned `Task` is
///   the **existing** row, with the existing `task_id` (NOT the
///   caller's). Mirrors the
///   [`crate::ClaimResult::AlreadyClaimed`] shape on
///   `try_claim_shared_task` — callers reconcile to the canonical
///   id.
///
/// The outcome only fires when `context.correlation_id` is non-null;
/// without a correlation_id the V036 partial index doesn't apply and
/// the row inserts normally as `Stored`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", content = "task", rename_all = "snake_case")]
pub enum TaskUpsertOutcome {
    /// INSERT (clean) or ON CONFLICT(task_id) UPSERT — caller's row.
    Stored(Task),
    /// Unique-index violation on the V036 (agent_occurrence_id,
    /// correlation_id) constraint. Carries the existing row.
    AlreadyExists(Task),
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
            TaskStatus::Rejected,
        ] {
            assert_eq!(TaskStatus::parse_str(s.as_sql_str()), Some(s));
        }
        assert_eq!(TaskStatus::parse_str("UNKNOWN"), None);
    }

    /// v41.2.0 (CIRISPersist#810, CIRISAgent#1077) — the consumer set,
    /// spelled as LITERALS.
    ///
    /// `status_sql_round_trip` above iterates `TaskStatus`'s own members,
    /// so it is structurally incapable of failing when the defect is a
    /// MISSING member: delete `Rejected` and that test still passes on
    /// five values. This one asserts against the six strings CIRISAgent's
    /// `ciris_engine.schemas.runtime.enums.TaskStatus` can hand us, copied
    /// by hand and deliberately not derived from anything in this crate.
    /// It is the only test here that goes red when persist's vocabulary
    /// falls behind its consumer's again.
    #[test]
    fn every_status_the_agent_can_write_round_trips() {
        for wire in [
            "pending",
            "active",
            "completed",
            "failed",
            "deferred",
            "rejected",
        ] {
            let parsed = TaskStatus::parse_str(wire).unwrap_or_else(|| {
                panic!(
                    "persist refuses `{wire}`, which CIRISAgent's TaskStatus can write. \
                     A refused status write is not a refusal the agent can route around \
                     (CIRISAgent#1077): it logs and continues, and the task stays active \
                     forever. Add the member here AND widen the CHECK on both backends."
                )
            });
            assert_eq!(parsed.as_sql_str(), wire);
        }
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
