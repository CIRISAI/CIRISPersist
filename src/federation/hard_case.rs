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
