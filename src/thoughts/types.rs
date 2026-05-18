//! Agent thoughts substrate wire types (v1.5.10, CIRISPersist#59 #2).
//!
//! Mirrors the row shape of `cirislens.thoughts` (Postgres) /
//! `cirislens_thoughts` (SQLite). JSON-string columns (`context_json`,
//! `ponder_notes_json`, `final_action_json`) lift to
//! `serde_json::Value` so callers don't have to round-trip through
//! string on every put/get; Postgres maps them as `JSONB`, SQLite
//! stores them as TEXT.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Thought lifecycle status. Vocabulary mirrors the CIRISAgent 2.8.13
/// thought state machine (`ciris_engine/schemas/runtime/enums.py
/// ::ThoughtStatus`):
/// `pending → processing → (completed | failed | deferred)`.
/// Persist does not enforce transition monotonicity at the trait
/// surface — the agent owns the state machine and persist accepts
/// whatever the agent asserts. The CHECK constraint at the schema
/// layer keeps the vocabulary closed-set so a bad caller can't write
/// an unknown status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThoughtStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    Deferred,
}

impl ThoughtStatus {
    /// Stable SQL CHECK value.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            ThoughtStatus::Pending => "pending",
            ThoughtStatus::Processing => "processing",
            ThoughtStatus::Completed => "completed",
            ThoughtStatus::Failed => "failed",
            ThoughtStatus::Deferred => "deferred",
        }
    }

    /// Inverse of [`Self::as_sql_str`].
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(ThoughtStatus::Pending),
            "processing" => Some(ThoughtStatus::Processing),
            "completed" => Some(ThoughtStatus::Completed),
            "failed" => Some(ThoughtStatus::Failed),
            "deferred" => Some(ThoughtStatus::Deferred),
            _ => None,
        }
    }
}

/// Thought type tag. The agent's `ThoughtType` enum
/// (`ciris_engine/schemas/runtime/enums.py`) currently lists 20+
/// values across processing categories (core / feedback /
/// decision-making / system / communication / tool / urgency /
/// learning). Persist treats this as an open vocabulary — the
/// schema column is `TEXT NOT NULL DEFAULT 'standard'` with no
/// CHECK constraint, so new agent-side variants flow through
/// without a persist schema change.
///
/// `ThoughtType` carries the wire string verbatim. Convenience
/// associated functions provide constants for the named variants
/// in the agent's current vocabulary; callers are free to
/// construct `ThoughtType("custom_variant".into())` for forward-
/// compat. `Default` lines up with `ThoughtType::STANDARD =
/// "standard"` from the agent enum.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ThoughtType(pub String);

impl ThoughtType {
    /// `"standard"` — agent default. Matches `ThoughtType.STANDARD`.
    pub fn standard() -> Self {
        Self("standard".into())
    }
    /// `"follow_up"` — agent reasoning chain continuation.
    pub fn follow_up() -> Self {
        Self("follow_up".into())
    }
    /// `"observation"` — agent observation thought.
    pub fn observation() -> Self {
        Self("observation".into())
    }
    /// `"reflection"` — system/meta reflection.
    pub fn reflection() -> Self {
        Self("reflection".into())
    }
    /// `"ponder"` — agent ponder action.
    pub fn ponder() -> Self {
        Self("ponder".into())
    }
    /// `"memory"` — memory thought.
    pub fn memory() -> Self {
        Self("memory".into())
    }
    /// `"error"` — error thought.
    pub fn error() -> Self {
        Self("error".into())
    }
    /// `"deferred"` — deferred thought.
    pub fn deferred() -> Self {
        Self("deferred".into())
    }
    /// `"guidance"` — wise-authority guidance thought.
    pub fn guidance() -> Self {
        Self("guidance".into())
    }
    /// `"scheduled"` — scheduled thought.
    pub fn scheduled() -> Self {
        Self("scheduled".into())
    }

    /// Borrow as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ThoughtType {
    fn default() -> Self {
        Self::standard()
    }
}

impl From<String> for ThoughtType {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ThoughtType {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// One row of the agent's `thoughts` substrate.
///
/// `context`, `ponder_notes`, `final_action` lift to
/// `serde_json::Value` so callers carry decoded JSON values across
/// the trait boundary. Postgres stores them as JSONB; SQLite stores
/// them as raw JSON TEXT (the backend handles the encoding both
/// ways).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Thought {
    pub thought_id: String,
    pub source_task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(default)]
    pub thought_type: ThoughtType,
    pub status: ThoughtStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub round_number: i32,
    pub content: String,
    /// Maps to the SQL `context_json` column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
    #[serde(default)]
    pub thought_depth: i32,
    /// Maps to the SQL `ponder_notes_json` column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ponder_notes: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_thought_id: Option<String>,
    /// Maps to the SQL `final_action_json` column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_action: Option<serde_json::Value>,
    /// Multi-occurrence scoping. Default `"default"` for
    /// single-occurrence callers — matches the SQL column DEFAULT.
    pub agent_occurrence_id: String,
}

/// Filter for [`super::ThoughtService::list_thoughts`].
///
/// All fields optional. The PG happy paths:
/// - `agent_occurrence_id` + `status` → `thoughts_status_occurrence`
/// - `source_task_id` alone → `thoughts_task_recency`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThoughtFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ThoughtStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_occurrence_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_thought_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_before: Option<DateTime<Utc>>,
}

/// Cursor for list-thoughts pagination. Captures the trailing
/// `(updated_at, thought_id)` tuple of the previous page so the
/// next page's WHERE-clause is `(updated_at, thought_id) <
/// (last_ts, last_id)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThoughtCursor {
    pub version: String,
    pub last_ts: DateTime<Utc>,
    pub last_id: String,
}

impl ThoughtCursor {
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
pub struct ThoughtListPage {
    pub items: Vec<Thought>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<ThoughtCursor>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_sql_round_trip() {
        for s in [
            ThoughtStatus::Pending,
            ThoughtStatus::Processing,
            ThoughtStatus::Completed,
            ThoughtStatus::Failed,
            ThoughtStatus::Deferred,
        ] {
            assert_eq!(ThoughtStatus::parse_str(s.as_sql_str()), Some(s));
        }
        assert_eq!(ThoughtStatus::parse_str("UNKNOWN"), None);
    }

    #[test]
    fn status_serde_snake_case() {
        let s = serde_json::to_string(&ThoughtStatus::Processing).unwrap();
        assert_eq!(s, "\"processing\"");
    }

    #[test]
    fn thought_type_default_is_standard() {
        assert_eq!(ThoughtType::default(), ThoughtType("standard".into()));
        assert_eq!(ThoughtType::standard().as_str(), "standard");
    }

    #[test]
    fn thought_type_serde_transparent() {
        let s = serde_json::to_string(&ThoughtType::observation()).unwrap();
        assert_eq!(s, "\"observation\"");
        let back: ThoughtType = serde_json::from_str("\"custom_variant\"").unwrap();
        assert_eq!(back.as_str(), "custom_variant");
    }

    #[test]
    fn thought_serde_round_trip_full_columns() {
        let now = Utc::now();
        let t = Thought {
            thought_id: "th-abc".into(),
            source_task_id: "task-abc".into(),
            channel_id: Some("chan-1".into()),
            thought_type: ThoughtType::reflection(),
            status: ThoughtStatus::Processing,
            created_at: now,
            updated_at: now,
            round_number: 3,
            content: "let me reason about this".into(),
            context: Some(serde_json::json!({"k": "v", "n": 42})),
            thought_depth: 2,
            ponder_notes: Some(serde_json::json!(["note1", "note2"])),
            parent_thought_id: Some("th-parent".into()),
            final_action: Some(serde_json::json!({"action": "speak"})),
            agent_occurrence_id: "occ-1".into(),
        };
        let s = serde_json::to_string(&t).unwrap();
        let back: Thought = serde_json::from_str(&s).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn thought_serde_minimal_columns_back_compat() {
        // Only the required columns present — every Optional /
        // defaulted field defaults cleanly.
        let now = Utc::now();
        let json = serde_json::json!({
            "thought_id": "th-min",
            "source_task_id": "task-min",
            "status": "pending",
            "created_at": now.to_rfc3339(),
            "updated_at": now.to_rfc3339(),
            "content": "minimal",
            "agent_occurrence_id": "default"
        });
        let t: Thought = serde_json::from_value(json).unwrap();
        assert_eq!(t.round_number, 0);
        assert_eq!(t.thought_depth, 0);
        assert_eq!(t.thought_type, ThoughtType::standard());
        assert!(t.channel_id.is_none());
        assert!(t.context.is_none());
        assert!(t.ponder_notes.is_none());
        assert!(t.parent_thought_id.is_none());
        assert!(t.final_action.is_none());
    }

    #[test]
    fn cursor_from_trailing_sets_version_v1() {
        let now = Utc::now();
        let c = ThoughtCursor::from_trailing(now, "id-x".into());
        assert_eq!(c.version, "v1");
        assert_eq!(c.last_id, "id-x");
        assert_eq!(c.last_ts, now);
    }
}
