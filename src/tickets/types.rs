//! Tickets substrate wire types (v1.5.13, CIRISPersist#59 #5).
//!
//! Mirrors the row shape of `cirislens.tickets` (Postgres) /
//! `cirislens_tickets` (SQLite). JSON column `metadata` lifts to
//! `serde_json::Value`; Postgres maps it as `JSONB`, SQLite stores
//! it as TEXT. Boolean `automated` rides as native `bool`; SQLite
//! stores it as INTEGER 0/1.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Ticket lifecycle status. **LOWERCASE 9-value on the wire and in
/// SQL.** Distinct from `scheduled_tasks` (UPPERCASE 4-value); the
/// `tasks` substrate uses a 6-value lowercase set that overlaps
/// partially. The agent's `tickets.status` column declares the
/// lowercase set verbatim; persist follows it. Note the
/// mixed snake_case form `in_progress`.
///
/// Wire format (JSON via serde) is `rename_all = "snake_case"` so
/// `InProgress` serializes to `"in_progress"` — matching the SQL
/// string directly.
///
/// # v24.1.0 (CIRISPersist#560) — `proposed`
///
/// The set was 8-value and had no way to say "an agent asked for this
/// and no human has authorized it yet". CIRISAgent shipped
/// `status = "blocked"` plus a `__proposal__` metadata marker as a
/// workaround; it works, but `blocked` means *work that is stuck* and
/// this means *work that is not authorized*. Those are different
/// operational states, and an operator reading a blocked-ticket queue
/// could not tell them apart.
///
/// The substrate models the state rather than widening the vocabulary
/// to an open string (the alternative the consumer offered): a closed
/// enum is what makes an unknown status a REFUSAL instead of a silently
/// stored typo, and authorization is exactly the kind of state that
/// must not be expressible by accident.
///
/// `proposed` is **not** terminal and is **not** executable. Approval is
/// therefore an ordinary status transition (`proposed → pending`) through
/// `update_ticket_status`, not a metadata edit — which is the property
/// the consumer needs: a proposal cannot become work without a human act,
/// and that act is one auditable status write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    /// v24.1.0 (CIRISPersist#560) — an agent has PROPOSED this work and
    /// no human has approved it. Not executable; see the type-level doc.
    Proposed,
    #[default]
    Pending,
    Assigned,
    InProgress,
    Blocked,
    Deferred,
    Completed,
    Cancelled,
    Failed,
}

impl TicketStatus {
    /// Stable SQL CHECK value (lowercase + snake_case for
    /// `in_progress`).
    pub fn as_sql_str(self) -> &'static str {
        match self {
            TicketStatus::Proposed => "proposed",
            TicketStatus::Pending => "pending",
            TicketStatus::Assigned => "assigned",
            TicketStatus::InProgress => "in_progress",
            TicketStatus::Blocked => "blocked",
            TicketStatus::Deferred => "deferred",
            TicketStatus::Completed => "completed",
            TicketStatus::Cancelled => "cancelled",
            TicketStatus::Failed => "failed",
        }
    }

    /// Inverse of [`Self::as_sql_str`]. Accepts only the lowercase
    /// SQL vocabulary.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "proposed" => Some(Self::Proposed),
            "pending" => Some(Self::Pending),
            "assigned" => Some(Self::Assigned),
            "in_progress" => Some(Self::InProgress),
            "blocked" => Some(Self::Blocked),
            "deferred" => Some(Self::Deferred),
            "completed" => Some(Self::Completed),
            "cancelled" => Some(Self::Cancelled),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// `true` for terminal states (`completed`, `cancelled`,
    /// `failed`). Helper for callers driving the state machine.
    ///
    /// `proposed` is deliberately NOT terminal: an unapproved proposal is
    /// the state a ticket is in BEFORE the lifecycle starts, not after it
    /// ends, and calling it terminal would tell a caller the work is
    /// settled when nobody has decided anything (CIRISPersist#560).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TicketStatus::Completed | TicketStatus::Cancelled | TicketStatus::Failed
        )
    }

    /// v24.1.0 (CIRISPersist#560) — is this ticket AUTHORIZED to be worked?
    ///
    /// False for exactly one status today, `proposed`, and it is the whole
    /// point of that status: a work-discovery query must exclude it by
    /// default the way it already excludes `blocked`, and a consumer should
    /// not have to know WHICH statuses those are. Naming the predicate here
    /// means the substrate answers "may this be picked up" in one place
    /// instead of every caller re-deriving a status list.
    ///
    /// This is about AUTHORIZATION, not readiness — `blocked` and
    /// `deferred` are authorized work that is currently stuck or shelved,
    /// which is precisely the distinction the `__proposal__` metadata
    /// workaround could not draw.
    pub fn is_authorized(self) -> bool {
        !matches!(self, TicketStatus::Proposed)
    }
}

/// One row of the agent's `tickets` substrate.
///
/// 17 columns. JSON column `metadata` (JSONB on PG, TEXT JSON on
/// SQLite) lifts to `serde_json::Value` with default `{}`.
/// `automated` is a native `bool`. No FKs on this table —
/// `correlation_id` is a free-form pointer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ticket {
    pub ticket_id: String,
    /// Operating procedure identifier — the SOP the ticket is
    /// routed against.
    pub sop: String,
    /// Free-form ticket type (NOT CHECKed at the schema layer; the
    /// agent owns the vocabulary).
    pub ticket_type: String,
    #[serde(default)]
    pub status: TicketStatus,
    /// Priority 1-10 (default 5). CHECKed at the schema layer.
    #[serde(default = "default_priority")]
    pub priority: i32,
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_identifier: Option<String>,
    pub submitted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline: Option<DateTime<Utc>>,
    pub last_updated: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    /// Free-form per-ticket metadata. Default `{}` matches the SQL
    /// column DEFAULT.
    #[serde(default = "default_metadata")]
    pub metadata: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub automated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Multi-occurrence scoping. Default `"__shared__"` for cross-
    /// occurrence tickets — matches the SQL column DEFAULT.
    /// Distinct from the `'default'` sentinel other substrates use
    /// for single-occurrence callers.
    #[serde(default = "default_occurrence")]
    pub agent_occurrence_id: String,
    pub created_at: DateTime<Utc>,
}

fn default_priority() -> i32 {
    5
}

fn default_metadata() -> serde_json::Value {
    serde_json::json!({})
}

fn default_occurrence() -> String {
    "__shared__".to_owned()
}

/// Filter for [`super::TicketService::list_tickets`].
///
/// All fields optional. Hot-path index dispatch:
///
/// - `agent_occurrence_id` + `sop` + `status` →
///   `tickets_sop_status_recency`
/// - `email` → `tickets_email_recency`
/// - `status` + `deadline_before` →
///   `tickets_due_deadline` (partial)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TicketFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sop: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TicketStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_occurrence_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automated: Option<bool>,
    /// Due-deadline scan: tickets where `deadline <= deadline_before`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_updated_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_updated_before: Option<DateTime<Utc>>,
}

/// Cursor for list-tickets pagination. Captures the trailing
/// `(last_updated, ticket_id)` tuple of the previous page so the
/// next page's WHERE-clause is
/// `(last_updated, ticket_id) < (last_ts, last_id)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketCursor {
    pub version: String,
    pub last_ts: DateTime<Utc>,
    pub last_id: String,
}

impl TicketCursor {
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
pub struct TicketListPage {
    pub items: Vec<Ticket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<TicketCursor>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_sql_round_trip() {
        for s in [
            TicketStatus::Proposed,
            TicketStatus::Pending,
            TicketStatus::Assigned,
            TicketStatus::InProgress,
            TicketStatus::Blocked,
            TicketStatus::Deferred,
            TicketStatus::Completed,
            TicketStatus::Cancelled,
            TicketStatus::Failed,
        ] {
            assert_eq!(TicketStatus::parse_str(s.as_sql_str()), Some(s));
        }
        assert_eq!(TicketStatus::parse_str("PENDING"), None);
        assert_eq!(TicketStatus::parse_str("inProgress"), None);
        assert_eq!(TicketStatus::parse_str("UNKNOWN"), None);
    }

    #[test]
    fn status_sql_strings_are_lowercase_snake_case() {
        assert_eq!(TicketStatus::Proposed.as_sql_str(), "proposed");
        assert_eq!(TicketStatus::Pending.as_sql_str(), "pending");
        assert_eq!(TicketStatus::Assigned.as_sql_str(), "assigned");
        assert_eq!(TicketStatus::InProgress.as_sql_str(), "in_progress");
        assert_eq!(TicketStatus::Blocked.as_sql_str(), "blocked");
        assert_eq!(TicketStatus::Deferred.as_sql_str(), "deferred");
        assert_eq!(TicketStatus::Completed.as_sql_str(), "completed");
        assert_eq!(TicketStatus::Cancelled.as_sql_str(), "cancelled");
        assert_eq!(TicketStatus::Failed.as_sql_str(), "failed");
    }

    /// v24.1.0 (CIRISPersist#560) — `proposed` deserializes from the wire and
    /// round-trips as the snake_case token the SQL CHECK admits. Before this
    /// cut `ticket_upsert` refused it with `unknown variant`, which is why the
    /// consumer had to overload `blocked`.
    #[test]
    fn proposed_is_on_the_wire_560() {
        let parsed: TicketStatus =
            serde_json::from_str("\"proposed\"").expect("`proposed` is a known variant");
        assert_eq!(parsed, TicketStatus::Proposed);
        assert_eq!(serde_json::to_string(&parsed).unwrap(), "\"proposed\"");
        assert_eq!(TicketStatus::Proposed.as_sql_str(), "proposed");
    }

    /// v24.1.0 (CIRISPersist#560) — the two properties the consumer asked for,
    /// stated as assertions rather than prose.
    #[test]
    fn proposed_is_unauthorized_but_not_terminal_560() {
        // (1) excluded from work discovery by default…
        assert!(
            !TicketStatus::Proposed.is_authorized(),
            "an unapproved proposal is not work a discovery query may hand out"
        );
        // …and it is the ONLY status that is, because `blocked`/`deferred` are
        // authorized work that is merely stuck — the distinction the
        // `__proposal__` metadata workaround could not draw.
        for s in [
            TicketStatus::Pending,
            TicketStatus::Assigned,
            TicketStatus::InProgress,
            TicketStatus::Blocked,
            TicketStatus::Deferred,
            TicketStatus::Completed,
            TicketStatus::Cancelled,
            TicketStatus::Failed,
        ] {
            assert!(s.is_authorized(), "{s:?} is authorized work");
        }
        // (2) approval is a STATUS transition, so `proposed` must not read as
        // settled — a terminal proposal could never be approved.
        assert!(!TicketStatus::Proposed.is_terminal());
    }

    #[test]
    fn status_serde_snake_case_wire_format() {
        // JSON wire format = SQL string for tickets (both are
        // lowercase snake_case). Verifies the rename_all does the
        // expected thing for InProgress.
        assert_eq!(
            serde_json::to_string(&TicketStatus::InProgress).unwrap(),
            "\"in_progress\""
        );
        assert_eq!(
            serde_json::to_string(&TicketStatus::Cancelled).unwrap(),
            "\"cancelled\""
        );
        let s: TicketStatus = serde_json::from_str("\"in_progress\"").unwrap();
        assert_eq!(s, TicketStatus::InProgress);
    }

    #[test]
    fn status_default_is_pending() {
        assert_eq!(TicketStatus::default(), TicketStatus::Pending);
    }

    #[test]
    fn status_is_terminal() {
        for s in [
            TicketStatus::Completed,
            TicketStatus::Cancelled,
            TicketStatus::Failed,
        ] {
            assert!(s.is_terminal(), "{s:?} should be terminal");
        }
        for s in [
            TicketStatus::Pending,
            TicketStatus::Assigned,
            TicketStatus::InProgress,
            TicketStatus::Blocked,
            TicketStatus::Deferred,
        ] {
            assert!(!s.is_terminal(), "{s:?} should NOT be terminal");
        }
    }

    #[test]
    fn ticket_serde_round_trip_full_columns() {
        let now = Utc::now();
        let t = Ticket {
            ticket_id: "ticket-abc".into(),
            sop: "SOP-104".into(),
            ticket_type: "user_request".into(),
            status: TicketStatus::InProgress,
            priority: 3,
            email: "user@example.com".into(),
            user_identifier: Some("agent-x".into()),
            submitted_at: now,
            deadline: Some(now + chrono::Duration::days(1)),
            last_updated: now,
            completed_at: Some(now),
            metadata: serde_json::json!({"k": "v", "n": 42}),
            notes: Some("worked on it".into()),
            automated: true,
            correlation_id: Some("corr-1".into()),
            agent_occurrence_id: "occ-1".into(),
            created_at: now,
        };
        let s = serde_json::to_string(&t).unwrap();
        let back: Ticket = serde_json::from_str(&s).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn ticket_serde_minimal_columns_back_compat() {
        // Only required columns present — every Optional / defaulted
        // field defaults cleanly. `agent_occurrence_id` should
        // default to `"__shared__"`, NOT `"default"`.
        let now = Utc::now();
        let json = serde_json::json!({
            "ticket_id": "ticket-min",
            "sop": "SOP-1",
            "ticket_type": "support",
            "email": "u@x.com",
            "submitted_at": now.to_rfc3339(),
            "last_updated": now.to_rfc3339(),
            "created_at": now.to_rfc3339(),
        });
        let t: Ticket = serde_json::from_value(json).unwrap();
        assert_eq!(t.status, TicketStatus::Pending);
        assert_eq!(t.priority, 5, "priority defaults to 5");
        assert_eq!(t.agent_occurrence_id, "__shared__");
        assert_eq!(t.metadata, serde_json::json!({}));
        assert!(!t.automated);
        assert!(t.user_identifier.is_none());
        assert!(t.deadline.is_none());
        assert!(t.completed_at.is_none());
        assert!(t.notes.is_none());
        assert!(t.correlation_id.is_none());
    }

    #[test]
    fn cursor_from_trailing_sets_version_v1() {
        let now = Utc::now();
        let c = TicketCursor::from_trailing(now, "id-x".into());
        assert_eq!(c.version, "v1");
        assert_eq!(c.last_id, "id-x");
        assert_eq!(c.last_ts, now);
    }
}
