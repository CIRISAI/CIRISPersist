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
    /// §11.7.1 / §10.1.4 (CIRISPersist#161 Ask 2/4, v6.1.0) — a family
    /// roster delta was observed and the at-rest re-key walk ran: a member
    /// was admitted (newcomer joins the cohort-visibility set) or removed
    /// (future cascade writes drop them; forward secrecy is automatic via
    /// the per-write fresh DEK). The observability primitive over a
    /// membership ceremony, NOT the ceremony itself. `target_key_id` =
    /// `family_key_id`; `detail` carries the granted / excluded split.
    pub const FAMILY_MEMBERSHIP_CHANGE: &str = "family_membership_change";
    /// §7.8 (CIRISPersist#161 Ask 5, v6.7.0 / CEG 1.0-RC5) — the community
    /// analog of [`FAMILY_MEMBERSHIP_CHANGE`]: a community roster delta
    /// (`change_kind: "added"` on a member-add, `"removed"` on a
    /// membership-revocation). Same payload shape as the family prefix
    /// (`change_kind` / `subject_key_id` / `cohort_key_id` / `effective_at`);
    /// `target_key_id` = `community_key_id`. Substrate-emitted only (§7.8
    /// emitter rule: `identity_type="substrate_persist"`).
    pub const COMMUNITY_MEMBERSHIP_CHANGE: &str = "community_membership_change";
    /// §10.1.4 (CIRISPersist#161 Ask 4, v6.1.0) — during a membership-change
    /// re-key, a newcomer was **fail-secure excluded** from a blob's grant
    /// set because their occurrence carried no valid `encryption_pubkeys`.
    /// They receive NO grant (never a plaintext fallback) and stay
    /// unreachable until they register keys + the walk re-runs.
    /// `subject_key_id` = the excluded occurrence; `detail` carries the
    /// scope + the count of blobs they were excluded from.
    pub const RECIPIENT_EXCLUDED: &str = "recipient_excluded";
    /// GDPR Art. 17 / DSAR (CIRISPersist#222, v6.9.0) — persist erased an
    /// agent's full trace corpus via
    /// [`Engine::delete_traces_for_agent_id_hash`](crate::Engine::delete_traces_for_agent_id_hash):
    /// hard-deleted `trace_events` + `trace_llm_calls`, tombstoned the
    /// derived `detection_events`. `target_key_id` carries the erased
    /// `agent_id_hash`; `detail` carries the per-table counts
    /// (`trace_events`, `trace_llm_calls`, `detection_events_tombstoned`).
    /// Recorded INSIDE the erasure transaction so the audit row commits
    /// atomically with the deletes (no audit-without-erasure, no
    /// erasure-without-audit).
    pub const TRACE_ERASURE: &str = "trace_erasure";
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

/// Deterministic `event_id` for a [`kind::FAMILY_MEMBERSHIP_CHANGE`]
/// emission (CIRISPersist#161 Ask 2/4, v6.1.0) — keyed on `(family,
/// roster-delta member, observed-at)` so a re-run of the re-key walk over
/// the *same* observed delta is idempotent. `observed_at` is the walk's
/// `now`, truncated to whole seconds (matching [`watch_event_id`]) so a
/// re-scan at the same logical instant collides; a genuinely later
/// re-observation (a new ceremony second) is a distinct event.
#[must_use]
pub fn membership_change_event_id(
    family_key_id: &str,
    member_identity_key_id: &str,
    observed_at: DateTime<Utc>,
) -> String {
    format!(
        "{}:{family_key_id}:{member_identity_key_id}:{}",
        kind::FAMILY_MEMBERSHIP_CHANGE,
        observed_at.timestamp()
    )
}

/// CEG §7.7 `change_kind` payload values for the membership-change
/// prefixes ([`kind::FAMILY_MEMBERSHIP_CHANGE`] /
/// [`kind::COMMUNITY_MEMBERSHIP_CHANGE`]). RC5 normalizes the prefix to
/// cover **both** directions in one event class — there is NO separate
/// `member_removed` kind; the direction lives in this payload field.
pub mod change_kind {
    /// A member was admitted to the roster (the add / re-key-newcomer
    /// path). `effective_at` = the join instant.
    pub const ADDED: &str = "added";
    /// A member was removed from the roster (the membership-revocation
    /// path; CIRISPersist#161 Ask 5). `effective_at` = the re-key epoch
    /// boundary after which the removed member receives no new wrapped
    /// content (§8.1.12.5 / §8.1.13.4 Option-A) — the forward-secrecy
    /// re-key keys on it.
    pub const REMOVED: &str = "removed";
}

/// Deterministic `event_id` for the **removal** arm of a membership-change
/// emission (CIRISPersist#161 Ask 5, CEG §7.7 / §7.8) — keyed on
/// `(prefix-kind, cohort, removed-member, effective_at)`. Per §7.7 the
/// forward-secrecy re-key keys on `effective_at`, so the idempotency key
/// does too: re-recording the *same* removal (same effective epoch) is a
/// no-op, while a distinct removal ceremony (a later `effective_at`) is a
/// distinct event. `kind` is [`kind::FAMILY_MEMBERSHIP_CHANGE`] or
/// [`kind::COMMUNITY_MEMBERSHIP_CHANGE`].
#[must_use]
pub fn membership_removed_event_id(
    kind: &str,
    cohort_key_id: &str,
    removed_identity_key_id: &str,
    effective_at: DateTime<Utc>,
) -> String {
    format!(
        "{kind}:removed:{cohort_key_id}:{removed_identity_key_id}:{}",
        effective_at.timestamp()
    )
}

/// Build the `change_kind: "removed"` membership-change event a backend's
/// `put_family_membership_revocation` / `put_community_membership_revocation`
/// path emits (CIRISPersist#161 Ask 5, CEG §7.7 / §7.8). One source of
/// truth so all three backends produce a byte-identical event. `kind` is
/// [`kind::FAMILY_MEMBERSHIP_CHANGE`] (family) or
/// [`kind::COMMUNITY_MEMBERSHIP_CHANGE`] (community); `cohort_key_id` is the
/// family/community key, `effective_at` the §7.7 re-key epoch boundary.
/// `emitted_at` is set to `effective_at` so the row's recorded instant
/// matches the idempotency window.
#[must_use]
pub fn membership_removed_event(
    kind: &str,
    cohort_key_id: &str,
    removed_identity_key_id: &str,
    effective_at: DateTime<Utc>,
) -> HardCaseEvent {
    HardCaseEvent {
        event_id: membership_removed_event_id(
            kind,
            cohort_key_id,
            removed_identity_key_id,
            effective_at,
        ),
        kind: kind.to_string(),
        target_key_id: Some(cohort_key_id.to_string()),
        subject_key_id: Some(removed_identity_key_id.to_string()),
        detail: serde_json::json!({
            "change_kind": change_kind::REMOVED,
            "subject_key_id": removed_identity_key_id,
            "cohort_key_id": cohort_key_id,
            "effective_at": effective_at.to_rfc3339(),
        }),
        emitted_at: effective_at,
    }
}

/// Deterministic `event_id` for a [`kind::RECIPIENT_EXCLUDED`] emission
/// (CIRISPersist#161 Ask 4, v6.1.0) — keyed on `(cohort_scope, excluded
/// occurrence, observed-at)`. Idempotent on the same walk-instant so a
/// re-run that re-excludes the same keyless newcomer writes no duplicate
/// row; once the newcomer registers keys (and the next walk grants them)
/// the condition stops firing.
#[must_use]
pub fn recipient_excluded_event_id(
    cohort_scope: &str,
    excluded_key_id: &str,
    observed_at: DateTime<Utc>,
) -> String {
    format!(
        "{}:{cohort_scope}:{excluded_key_id}:{}",
        kind::RECIPIENT_EXCLUDED,
        observed_at.timestamp()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_change_event_id_is_deterministic_and_sub_second_idempotent() {
        let t0: DateTime<Utc> = "2026-06-12T10:00:00.100Z".parse().unwrap();
        let t0b: DateTime<Utc> = "2026-06-12T10:00:00.900Z".parse().unwrap();
        let t1: DateTime<Utc> = "2026-06-12T10:00:01.000Z".parse().unwrap();
        let a = membership_change_event_id("fam", "carol", t0);
        // Same whole-second instant ⇒ same id (sub-second re-scan = no-op).
        assert_eq!(a, membership_change_event_id("fam", "carol", t0b));
        // A later whole second ⇒ distinct id.
        assert_ne!(a, membership_change_event_id("fam", "carol", t1));
        // Member/target are part of the key.
        assert_ne!(a, membership_change_event_id("fam", "dave", t0));
        assert_ne!(a, membership_change_event_id("other", "carol", t0));
        assert!(a.starts_with(kind::FAMILY_MEMBERSHIP_CHANGE));
    }

    #[test]
    fn membership_removed_event_id_keys_on_effective_at_and_cohort() {
        let e0: DateTime<Utc> = "2026-06-12T10:00:00.100Z".parse().unwrap();
        let e0b: DateTime<Utc> = "2026-06-12T10:00:00.900Z".parse().unwrap();
        let e1: DateTime<Utc> = "2026-06-12T10:00:01.000Z".parse().unwrap();
        let a = membership_removed_event_id(kind::FAMILY_MEMBERSHIP_CHANGE, "fam", "carol", e0);
        // Same re-key epoch second ⇒ same id (re-recording the same removal
        // is a no-op; the forward-secrecy re-key keys on effective_at).
        assert_eq!(
            a,
            membership_removed_event_id(kind::FAMILY_MEMBERSHIP_CHANGE, "fam", "carol", e0b)
        );
        // A later effective_at second ⇒ distinct removal event.
        assert_ne!(
            a,
            membership_removed_event_id(kind::FAMILY_MEMBERSHIP_CHANGE, "fam", "carol", e1)
        );
        // Cohort + removed member are part of the key.
        assert_ne!(
            a,
            membership_removed_event_id(kind::FAMILY_MEMBERSHIP_CHANGE, "fam", "dave", e0)
        );
        assert_ne!(
            a,
            membership_removed_event_id(kind::FAMILY_MEMBERSHIP_CHANGE, "other", "carol", e0)
        );
        // The community analog carries its own prefix.
        assert_ne!(
            a,
            membership_removed_event_id(kind::COMMUNITY_MEMBERSHIP_CHANGE, "fam", "carol", e0)
        );
        assert!(a.starts_with(kind::FAMILY_MEMBERSHIP_CHANGE));
        assert!(a.contains(":removed:"));
    }

    #[test]
    fn recipient_excluded_event_id_scopes_and_idempotent() {
        let t0: DateTime<Utc> = "2026-06-12T10:00:00Z".parse().unwrap();
        let a = recipient_excluded_event_id("self", "occ-bare", t0);
        assert_eq!(a, recipient_excluded_event_id("self", "occ-bare", t0));
        // Scope separates a self-add exclusion from a family-add exclusion.
        assert_ne!(a, recipient_excluded_event_id("family", "occ-bare", t0));
        assert!(a.starts_with(kind::RECIPIENT_EXCLUDED));
    }
}
