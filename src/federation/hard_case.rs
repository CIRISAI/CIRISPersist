//! `hard_case:*` emission surface (CIRISPersist#146 Ask 3; CEG §8.1.11.3
//! / §10.1.3).
//!
//! CEG draws a hard line between **substrate observability** —
//! `hard_case:*`, emitted by persist when it *observes* a
//! policy-relevant condition — and **LensCore-composed derived
//! detection** (`detection:*`). Until now persist only ever *gated*
//! (refused an ineligible write); it had no surface to *emit* an
//! observability primitive. This module is that surface.
//!
//! The consent-SLA watcher records [`kind::CONSENT_SLA_BREACH`]
//! / [`kind::CONSENT_REVOCATION_PROMOTION_OVERDUE`] rows here;
//! LensCore composes `detection:consent:*` over them. It is a **general**
//! primitive — any future substrate-side `hard_case:*` emitter (e.g. the
//! §7.8 location-proof-resolution violation) records through the same
//! `record_hard_case` / `list_hard_case_events`
//! ([`FederationDirectory`](crate::federation::FederationDirectory))
//! surface.
//!
//! Emission is **idempotent on `event_id`**: the emitter derives a
//! deterministic id from `(kind, target, window)` so a re-scan of the
//! same condition never double-emits.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Canonical `hard_case:{kind}` suffixes persist emits. Open vocabulary
/// (the column is free TEXT); these are the named-here canonical kinds.
pub mod kind {
    /// §8.1.11.3 — a producer committed `consent:deletion_sla:{days}` at
    /// publication, the subject revoked, and the deadline passed without
    /// a `consent:deletion_complete` from the producer.
    pub const CONSENT_SLA_BREACH: &str = "consent_sla_breach";
    /// §10.1.3 — a subject-side revocation stayed local-tier (unpromoted
    /// to federation tier) past the operator-configured window.
    pub const CONSENT_REVOCATION_PROMOTION_OVERDUE: &str = "consent_revocation_promotion_overdue";
}

/// A recorded `hard_case:*` observability event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardCaseEvent {
    /// Deterministic id — derived by the emitter from `(kind, target,
    /// window)` so re-recording the same observed condition is a no-op
    /// (idempotent insert).
    pub event_id: String,
    /// The `hard_case:{kind}` suffix (see [`kind`]). Open vocabulary.
    pub kind: String,
    /// The Contribution / row the case is against. `None` for
    /// substrate-wide cases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_key_id: Option<String>,
    /// The subject the case concerns, where one applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key_id: Option<String>,
    /// Structured context (e.g. `sla_days`, `revocation_at`, `deadline`).
    /// Defaults to `{}`.
    #[serde(default)]
    pub detail: serde_json::Value,
    /// When persist observed the condition.
    pub emitted_at: DateTime<Utc>,
}

/// Filter for [`list_hard_case_events`](crate::federation::FederationDirectory::list_hard_case_events)
/// — LensCore consumes by kind + recency.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardCaseFilter {
    /// Restrict to one `kind`. `None` = all kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Only events with `emitted_at >= since`. `None` = from the start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<DateTime<Utc>>,
}

/// Effective consent stance of a subject over a target Contribution
/// (CEG §8.1.11.1 resolution). Returned by
/// [`resolve_consent_state`](crate::federation::FederationDirectory::resolve_consent_state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    /// Latest `consent:state:granted` — processing may proceed in scope.
    Granted,
    /// Latest `consent:state:revoked` — subject withdrew; SLA clock runs.
    Revoked,
    /// Latest is `consent:state:expired`, or a `valid_until` passed.
    Expired,
    /// Subject named in `subject_key_ids` but never declared a stance.
    Unspecified,
}

/// Outcome of one
/// [`run_consent_sla_watch`](crate::federation::FederationDirectory::run_consent_sla_watch)
/// pass (CEG §8.1.11.3 + §10.1.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentWatchReport {
    /// Subject-side revocations scanned this pass.
    pub revocations_scanned: usize,
    /// `consent_sla_breach` **conditions detected** this pass (deadline
    /// passed, no `consent:deletion_complete`). Recording is idempotent
    /// on `event_id`, so a re-scan detects the same active condition again
    /// (count stays > 0) but writes no duplicate row; the count drops to 0
    /// once the producer's `consent:deletion_complete` lands.
    pub sla_breaches: usize,
    /// `consent_revocation_promotion_overdue` conditions detected. See the
    /// §10.1.3 caveat on
    /// [`run_consent_sla_watch`](crate::federation::FederationDirectory::run_consent_sla_watch).
    pub promotion_overdue: usize,
}

/// Parse the SLA window (days) from a `consent:deletion_sla:{days}`
/// dimension (§5.6.8.6). Tolerates a trailing `:vN` version segment —
/// takes the first integer-valued segment after the prefix. `None` if the
/// dimension isn't a deletion-SLA or carries no integer.
#[must_use]
pub fn parse_deletion_sla_days(dimension: &str) -> Option<u32> {
    dimension
        .strip_prefix("consent:deletion_sla:")?
        .split(':')
        .find_map(|seg| seg.parse::<u32>().ok())
}

/// Deterministic `event_id` for a hard_case against `(kind, target,
/// revocation)` — the idempotency key so a watcher re-scan of the same
/// observed condition is a no-op rather than a duplicate row.
#[must_use]
pub fn watch_event_id(kind: &str, target_key_id: &str, revocation_at: DateTime<Utc>) -> String {
    format!("{kind}:{target_key_id}:{}", revocation_at.timestamp())
}
