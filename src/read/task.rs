//! Section C — Task-grouped listing primitives.
//!
//! A *task* is the unit of work the agent was prompted with; each task
//! contains 1..N *traces* (one trace per thought). Lens needs to
//! surface tasks rather than raw traces in the visible-page driver
//! because the qa-eval / discord / wakeup-ritual / real-user pages are
//! task-axis views, not trace-axis views.
//!
//! Derivation of [`TaskClass`] and `initial_observation` lives in
//! persist (not in lens) so federation peers see uniform task identity:
//! the same `task_id` resolves to the same class across every consumer.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{TimeWindow, TraceSummary};

/// Task classification — derived from the `task_id` prefix by
/// [`TaskClass::from_task_id`]. The match table is the canonical
/// persist derivation; lens / agent / bridge MUST agree on this
/// mapping so the federation has one task taxonomy.
///
/// The list mirrors the cohorts that CIRISLens's `corpus_shape.py`
/// already cares about plus the agent's wakeup-ritual lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClass {
    /// QA evaluation harness task (`qa_*` / `qa-eval-*` prefix).
    QaEval,
    /// Discord adapter task (`discord_*` prefix) — bot-loop and
    /// scripted operator interactions.
    Discord,
    /// Real-user Discord interaction (`real_user_discord_*` prefix) —
    /// the cohort RATCHET treats as ground truth for human-in-loop.
    RealUserDiscord,
    /// Real-user CLI interaction (`real_user_cli_*` prefix) — operator
    /// shell / `ciris chat` style.
    RealUserCli,
    /// Real-user API interaction (`real_user_api_*` prefix) — HTTP
    /// integration partners.
    RealUserApi,
    /// Wakeup ritual / cognitive-state transition (`wakeup_*` prefix
    /// or `wakeup` substring) — the agent's startup self-check.
    WakeupRitual,
    /// Anything else. Tasks should rarely fall here in mature
    /// deployments; the bucket exists so the listing surface never
    /// silently drops a `task_id`.
    Other,
}

impl TaskClass {
    /// Canonical derivation. Substring `"wakeup"` is checked broadly
    /// because the agent's `wakeup_ritual` cohort sometimes appears
    /// inside a longer task_id (e.g. `wakeup_2026_03_01T...`).
    pub fn from_task_id(task_id: &str) -> Self {
        if task_id.starts_with("qa_") || task_id.starts_with("qa-eval") {
            TaskClass::QaEval
        } else if task_id.starts_with("real_user_discord_") {
            TaskClass::RealUserDiscord
        } else if task_id.starts_with("real_user_cli_") {
            TaskClass::RealUserCli
        } else if task_id.starts_with("real_user_api_") {
            TaskClass::RealUserApi
        } else if task_id.contains("wakeup") {
            TaskClass::WakeupRitual
        } else if task_id.starts_with("discord_") {
            TaskClass::Discord
        } else {
            TaskClass::Other
        }
    }

    /// Stable wire-side token for filter SQL + serialization.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            TaskClass::QaEval => "qa_eval",
            TaskClass::Discord => "discord",
            TaskClass::RealUserDiscord => "real_user_discord",
            TaskClass::RealUserCli => "real_user_cli",
            TaskClass::RealUserApi => "real_user_api",
            TaskClass::WakeupRitual => "wakeup_ritual",
            TaskClass::Other => "other",
        }
    }
}

/// Filter for [`super::ReadEngine::list_tasks`]. Composes AND-style;
/// every field is optional. Filter semantics match [`super::TraceFilter`]
/// (filters the underlying trace rows; tasks are then grouped from
/// the surviving traces).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskFilter {
    /// Window on the task's earliest trace `ts`.
    pub time_window: Option<TimeWindow>,

    /// Filter by `agent_id_hash`. **AV-9** authorization gate applies.
    pub agent_id_hash: Option<String>,

    /// Filter by human-readable agent name.
    pub agent_name: Option<String>,

    /// Filter by `deployment_domain`.
    pub deployment_domain: Option<String>,

    /// Filter by [`TaskClass`]. Server-side filter via task_id prefix
    /// match (the same derivation as [`TaskClass::from_task_id`]).
    pub task_class: Option<TaskClass>,
}

/// Opaque cursor for [`super::ReadEngine::list_tasks`].
///
/// Built around the `(earliest_at, task_id)` tuple — pages are ordered
/// newest-first (`earliest_at DESC, task_id DESC`). The cursor encodes
/// the trailing edge so the next page picks up at the next-older task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCursor {
    /// Cursor format version. v0.5.5 ships `"v1"`.
    pub version: String,

    /// `earliest_at` of the last task on the previous page.
    pub last_earliest_at: DateTime<Utc>,

    /// `task_id` of the last task — tiebreaker for equal `earliest_at`.
    pub last_task_id: String,
}

impl TaskCursor {
    /// Construct a v1 cursor from the trailing edge of a result page.
    pub fn from_trailing(last_earliest_at: DateTime<Utc>, last_task_id: String) -> Self {
        TaskCursor {
            version: "v1".to_owned(),
            last_earliest_at,
            last_task_id,
        }
    }
}

/// One task with its component traces.
///
/// `initial_observation` is derived from the task's earliest
/// `THOUGHT_START` event's `task_description` payload field. Missing
/// when no THOUGHT_START row has a `task_description` (legacy / pre-v2.7
/// shapes).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskGroup {
    /// `task_id` — the federation-stable task identifier.
    pub task_id: String,

    /// Derived from the earliest THOUGHT_START's `task_description`
    /// payload field, when present.
    pub initial_observation: Option<String>,

    /// Canonical task class (see [`TaskClass::from_task_id`]).
    pub task_class: TaskClass,

    /// Earliest trace `started_at` in the task. The cursor sort key.
    pub earliest_at: DateTime<Utc>,

    /// Latest trace `completed_at` in the task.
    pub latest_at: DateTime<Utc>,

    /// Trace summaries belonging to this task, ordered by
    /// `thought_depth ASC` (so depth-0 first; reasoning chain
    /// reads top-to-bottom). When `thought_depth` is unset, fallback
    /// is `started_at ASC`.
    pub traces: Vec<TraceSummary>,
}

/// One page of task groups, newest-first by `earliest_at`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskListPage {
    /// Task groups in `earliest_at DESC, task_id DESC` order.
    pub items: Vec<TaskGroup>,
    /// Cursor for the next page; `None` when there are no more tasks.
    pub next_cursor: Option<TaskCursor>,
}
