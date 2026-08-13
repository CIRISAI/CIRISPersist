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
    /// GDPR Art. 17 / DSAR (CIRISPersist#222, v7.0.0) — persist erased an
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

    /// v25.1.0 (CIRISPersist#570 ask 3; CIRISServer `FSD/ADMIN_OPS_TAXONOMY.md`)
    /// — **an authority DID something.**
    ///
    /// Every other kind in this module names an *observed condition*: an SLA
    /// lapsed, a roster changed, a recipient had no keys. This one names an
    /// *act*, and it is the only kind whose `detail` is **required** to carry
    /// the authority the act was performed under — see
    /// [`check_admin_action_attribution`](super::check_admin_action_attribution).
    ///
    /// Downstream's reasoning is the requirement, verbatim: *an admin action
    /// that does not carry its own authority is indistinguishable from an
    /// unauthorized one once the actor is gone.* The value of the attribution
    /// is not that it proves the act was legitimate — it is that a
    /// **compromised** authority becomes survivable, because every act taken
    /// under it can be enumerated by
    /// [`list_hard_case_events`](crate::federation::FederationDirectory::list_hard_case_events)
    /// and re-adjudicated. Without it, "which of these did the real holder
    /// do?" has no answer at all.
    ///
    /// **Open suffix vocabulary**, exactly like the rest of this module: the
    /// bare token is admissible and so is any `admin_action:{op}` refinement
    /// (see [`ADMIN_ACTION_PREFIX`] and
    /// [`admin_op`](super::admin_op) for the named-here canonical ops).
    /// Persist observes; it does not sentence. Recording that an authority
    /// quarantined a key says nothing about whether it should have.
    pub const ADMIN_ACTION: &str = "admin_action";

    /// The open-suffix form of [`ADMIN_ACTION`] — `admin_action:{op}`. A kind
    /// bearing this prefix carries the SAME attribution requirement as the
    /// bare token; the suffix only tells a reader *which* op without forcing
    /// them to parse `detail`.
    pub const ADMIN_ACTION_PREFIX: &str = "admin_action:";
}

/// Named-here canonical `admin_action:{op}` suffixes (CIRISPersist#570). Open
/// vocabulary — a substrate op that needs an attributed record uses one of
/// these or mints its own; the attribution gate does not consult this list.
pub mod admin_op {
    /// An authority withheld a key's rows from serving
    /// ([`quarantine`](crate::federation::quarantine), #570 ask 5). Tier 2 of
    /// the graded response set.
    pub const QUARANTINE: &str = "quarantine";
    /// An authority RELEASED a quarantine — the reversal. Recorded as its own
    /// act because "who lifted it, under what authority" is the question that
    /// matters when a release turns out to have been the hostile step.
    pub const QUARANTINE_RELEASE: &str = "quarantine_release";
    /// An authority de-admitted a key, optionally time-bounded
    /// ([`Revocation::revoked_after`](crate::federation::Revocation::revoked_after),
    /// #570 ask 4).
    pub const DE_ADMISSION: &str = "de_admission";
}

/// The `detail` keys an [`kind::ADMIN_ACTION`] row MUST carry. Named here so
/// the emitter and the gate cannot disagree about where the attribution lives.
pub mod admin_field {
    /// The `delegates_to` attestation id the acting authority acted UNDER —
    /// the chain that conferred the duty (for #570 ask 5 / ask 4, a
    /// [`slash`](crate::federation::admission::DELEGATION_SCOPE_SLASH)-bearing
    /// one).
    ///
    /// Recorded, not resolved — see
    /// [`check_admin_action_attribution`](super::check_admin_action_attribution)
    /// on why admission does not require the named delegation to be *held*
    /// here.
    pub const DELEGATION_ID: &str = "delegation_id";
    /// Free text: WHY. Recorded, never interpreted — persist does not
    /// adjudicate an admin's reasons, it only refuses to let them go
    /// unrecorded.
    pub const REASON: &str = "reason";
    /// WHICH op (see [`admin_op`](super::admin_op)). Optional: the kind
    /// suffix already carries it when one is used.
    pub const OP: &str = "op";
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

// ─────────────────────────────────────────────────────────────────────────
//  #570 ask 3 — the attribution gate
// ─────────────────────────────────────────────────────────────────────────

/// v25.1.0 (CIRISPersist#570 ask 3) — **WHICH branch refused** an
/// [`kind::ADMIN_ACTION`] record.
///
/// Closed, snake_case serde tokens, [`Self::as_str`] returning the SAME token,
/// and deliberately no `Other`/`Unspecified` catch-all — the
/// [`KeyRefusalReason`](crate::federation::register::KeyRefusalReason)
/// discipline #565 shipped and [`PeerQuotaRefusal`](crate::federation::PeerQuotaRefusal)
/// repeated. "The attribution was bad" is not an answer an operator can act
/// on; "`reason_absent`" is.
///
/// **The token set is the downstream contract and this mapping is
/// APPEND-ONLY.** Add variants; never re-spell one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminActionRefusal {
    /// `detail` is not a JSON object, so it cannot carry the attribution at
    /// all. Distinguished from the two `*_absent` branches because the fix is
    /// different: the emitter is building the wrong shape, not omitting a key.
    DetailNotAnObject,
    /// [`admin_field::DELEGATION_ID`] is missing (or JSON `null`). The act
    /// names no authority — the exact condition #570 ask 3 exists to refuse.
    DelegationIdAbsent,
    /// [`admin_field::DELEGATION_ID`] is present but is not a non-empty
    /// string. `""` and `0` are absence wearing a key; admitting them would
    /// make the requirement satisfiable by anything.
    DelegationIdMalformed,
    /// [`admin_field::REASON`] is missing (or JSON `null`).
    ReasonAbsent,
    /// [`admin_field::REASON`] is present but is not a non-empty string.
    ReasonMalformed,
}

impl AdminActionRefusal {
    /// The **stable program token** — identical to the serde token, so a
    /// consumer reading the wire and a consumer holding the typed value key on
    /// the same constant.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DetailNotAnObject => "detail_not_an_object",
            Self::DelegationIdAbsent => "delegation_id_absent",
            Self::DelegationIdMalformed => "delegation_id_malformed",
            Self::ReasonAbsent => "reason_absent",
            Self::ReasonMalformed => "reason_malformed",
        }
    }

    /// Which `detail` key the refusal is about, or `None` for
    /// [`Self::DetailNotAnObject`] (which is about `detail` itself).
    #[must_use]
    pub const fn field(&self) -> Option<&'static str> {
        match self {
            Self::DetailNotAnObject => None,
            Self::DelegationIdAbsent | Self::DelegationIdMalformed => {
                Some(admin_field::DELEGATION_ID)
            }
            Self::ReasonAbsent | Self::ReasonMalformed => Some(admin_field::REASON),
        }
    }

    /// Every variant, in declaration order — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::DetailNotAnObject,
        Self::DelegationIdAbsent,
        Self::DelegationIdMalformed,
        Self::ReasonAbsent,
        Self::ReasonMalformed,
    ];
}

impl std::fmt::Display for AdminActionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<AdminActionRefusal> for crate::federation::Error {
    fn from(reason: AdminActionRefusal) -> Self {
        crate::federation::Error::AdminActionUnattributed { reason }
    }
}

/// Is `kind` an attributed admin-action kind? True for the bare
/// [`kind::ADMIN_ACTION`] and for any [`kind::ADMIN_ACTION_PREFIX`] refinement
/// — the open suffix vocabulary this module uses everywhere else.
#[must_use]
pub fn is_admin_action(kind: &str) -> bool {
    kind == kind::ADMIN_ACTION || kind.starts_with(kind::ADMIN_ACTION_PREFIX)
}

/// v25.1.0 (CIRISPersist#570 ask 3) — **the attribution gate.** A no-op for
/// every kind that is not an admin action; for an admin action, both
/// [`admin_field::DELEGATION_ID`] and [`admin_field::REASON`] MUST be present
/// as non-empty strings or the record is refused naming WHICH.
///
/// Called at the top of every backend's
/// [`record_hard_case`](crate::federation::FederationDirectory::record_hard_case)
/// — verify-before-mutation (AV-9), so a refused record leaves no row.
///
/// # Why the gate is structural, and not a resolution of `delegation_id`
///
/// It would be easy to also require that the named `delegates_to` row is one
/// this node **holds**, and tempting to call that stronger. It is not: an
/// admin-action record is *evidence*, and a node that has not yet received the
/// delegation row would then destroy the evidence of an act it did observe —
/// the same mistake
/// [`record_objection`](crate::federation::reverse_quorum::record_objection)
/// deliberately does not make with a late objection. Store everything, adjudicate
/// carefully.
///
/// The authority question is answered where it belongs and where it can be
/// re-derived from this node's own verified state (#377): at the **write door
/// of the op itself**. A quarantine marker cannot be admitted without a live
/// [`slash`](crate::federation::admission::DELEGATION_SCOPE_SLASH)-scoped chain
/// (`check_delegated_duty_scores_admission`); the `hard_case` row beside it
/// says which chain that was. This gate's job is only to guarantee the
/// question is *askable later*.
pub fn check_admin_action_attribution(event: &HardCaseEvent) -> Result<(), AdminActionRefusal> {
    if !is_admin_action(&event.kind) {
        return Ok(());
    }
    let Some(detail) = event.detail.as_object() else {
        return Err(AdminActionRefusal::DetailNotAnObject);
    };
    for (key, absent, malformed) in [
        (
            admin_field::DELEGATION_ID,
            AdminActionRefusal::DelegationIdAbsent,
            AdminActionRefusal::DelegationIdMalformed,
        ),
        (
            admin_field::REASON,
            AdminActionRefusal::ReasonAbsent,
            AdminActionRefusal::ReasonMalformed,
        ),
    ] {
        match detail.get(key) {
            None | Some(serde_json::Value::Null) => return Err(absent),
            Some(v) => {
                if !v.as_str().is_some_and(|s| !s.trim().is_empty()) {
                    return Err(malformed);
                }
            }
        }
    }
    Ok(())
}

/// The `admin_action:{op}` kind for `op` (see [`admin_op`]).
#[must_use]
pub fn admin_action_kind(op: &str) -> String {
    format!("{}{op}", kind::ADMIN_ACTION_PREFIX)
}

/// Deterministic `event_id` for an [`kind::ADMIN_ACTION`] emission — keyed on
/// `(op, target, whole-second instant)`, matching [`watch_event_id`]'s
/// idempotency window. Re-recording the same act at the same logical instant
/// is a no-op; a genuinely later act is a distinct event.
#[must_use]
pub fn admin_action_event_id(op: &str, target_key_id: &str, at: DateTime<Utc>) -> String {
    format!(
        "{}{op}:{target_key_id}:{}",
        kind::ADMIN_ACTION_PREFIX,
        at.timestamp()
    )
}

/// Build the attributed admin-action event a substrate op records beside its
/// write (CIRISPersist#570 ask 3). One source of truth so all three backends
/// produce a byte-identical row, exactly as
/// [`membership_removed_event`] does for the roster planes.
///
/// The returned event always clears [`check_admin_action_attribution`] when
/// `delegation_id` and `reason` are non-empty — the builder cannot *stop* a
/// caller passing empties, and deliberately does not try: the gate at the
/// write door is the one that has to hold, because a replicated or
/// hand-assembled event never passes through here.
#[must_use]
pub fn admin_action_event(
    op: &str,
    target_key_id: &str,
    subject_key_id: Option<&str>,
    delegation_id: &str,
    reason: &str,
    at: DateTime<Utc>,
) -> HardCaseEvent {
    HardCaseEvent {
        event_id: admin_action_event_id(op, target_key_id, at),
        kind: admin_action_kind(op),
        target_key_id: Some(target_key_id.to_owned()),
        subject_key_id: subject_key_id.map(str::to_owned),
        detail: serde_json::json!({
            admin_field::OP: op,
            admin_field::DELEGATION_ID: delegation_id,
            admin_field::REASON: reason,
        }),
        emitted_at: at,
    }
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

/// One overdue subject-side revocation surfaced by
/// [`list_consent_revocation_promotion_overdue`](crate::federation::FederationDirectory::list_consent_revocation_promotion_overdue)
/// (CIRISPersist#434, CC 5.3.2.2's never-rest-local tripwire): a
/// `consent:state:revoked` still at local tier (unpromoted) with
/// `now - asserted_at > sla`. Serializable — the PyO3
/// `list_consent_revocation_promotion_overdue_json` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentPromotionOverdueRow {
    /// The overdue attestation row's id (the `attestation_promote`
    /// handle that clears the condition).
    pub attestation_id: String,
    /// The target Contribution `T` the revocation is against.
    pub target_key_id: String,
    /// The revoking subject `s`.
    pub subject_key_id: String,
    /// When the subject revoked (the SLA clock's start).
    pub asserted_at: DateTime<Utc>,
    /// How long the revocation has rested local-tier, whole seconds
    /// (`now - asserted_at`).
    pub age_seconds: u64,
    /// The row's current (non-federation) tier — always `local` today;
    /// carried so the reader stays honest if tiers ever grow.
    pub tier: String,
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

    // ── #570 ask 3 — the attribution gate ────────────────────────────

    fn ev(kind: &str, detail: serde_json::Value) -> HardCaseEvent {
        HardCaseEvent {
            event_id: "e1".into(),
            kind: kind.into(),
            target_key_id: Some("k-target".into()),
            subject_key_id: None,
            detail,
            emitted_at: "2026-08-02T10:00:00Z".parse().unwrap(),
        }
    }

    #[test]
    fn admin_action_refusal_tokens_match_serde_and_are_unique() {
        let mut tokens: Vec<&str> = AdminActionRefusal::ALL.iter().map(|r| r.as_str()).collect();
        for reason in AdminActionRefusal::ALL {
            let json = serde_json::to_string(reason).expect("serialize");
            assert_eq!(
                json,
                format!("\"{}\"", reason.as_str()),
                "serde token and as_str MUST be the same spelling — the whole \
                 point of #565's discipline is that a consumer keys on one \
                 constant"
            );
            let back: AdminActionRefusal = serde_json::from_str(&json).expect("round-trip");
            assert_eq!(&back, reason);
        }
        let n = tokens.len();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(tokens.len(), n, "tokens must be distinct");
    }

    #[test]
    fn a_non_admin_kind_is_not_touched_by_the_attribution_gate() {
        // Every pre-existing kind carries whatever detail its emitter chose;
        // #570 ask 3 must not retroactively require attribution of an
        // OBSERVED CONDITION. That distinction is the whole taxonomy.
        for k in [
            kind::CONSENT_SLA_BREACH,
            kind::FAMILY_MEMBERSHIP_CHANGE,
            kind::RECIPIENT_EXCLUDED,
            kind::TRACE_ERASURE,
        ] {
            assert!(!is_admin_action(k));
            check_admin_action_attribution(&ev(k, serde_json::json!({})))
                .expect("an observed condition needs no delegation");
        }
        // …and a kind that merely CONTAINS the token is not one either.
        assert!(!is_admin_action("not_an_admin_action"));
    }

    #[test]
    fn the_bare_kind_and_every_suffix_carry_the_same_requirement() {
        for k in [
            kind::ADMIN_ACTION.to_owned(),
            admin_action_kind(admin_op::QUARANTINE),
            admin_action_kind(admin_op::QUARANTINE_RELEASE),
            admin_action_kind(admin_op::DE_ADMISSION),
            admin_action_kind("some_future_op"),
        ] {
            assert!(is_admin_action(&k), "{k} must be an admin action");
            assert_eq!(
                check_admin_action_attribution(&ev(&k, serde_json::json!({}))),
                Err(AdminActionRefusal::DelegationIdAbsent),
                "the open suffix vocabulary must not open an attribution hole"
            );
        }
    }

    #[test]
    fn the_refusal_names_which_field_is_missing() {
        let k = admin_action_kind(admin_op::QUARANTINE);
        let cases: &[(serde_json::Value, AdminActionRefusal)] = &[
            (
                serde_json::json!({}),
                AdminActionRefusal::DelegationIdAbsent,
            ),
            (
                serde_json::json!({ "delegation_id": serde_json::Value::Null, "reason": "r" }),
                AdminActionRefusal::DelegationIdAbsent,
            ),
            (
                serde_json::json!({ "delegation_id": "att-1" }),
                AdminActionRefusal::ReasonAbsent,
            ),
            (
                serde_json::json!({ "delegation_id": "att-1", "reason": serde_json::Value::Null }),
                AdminActionRefusal::ReasonAbsent,
            ),
            // `""` and a non-string are absence wearing a key.
            (
                serde_json::json!({ "delegation_id": "", "reason": "r" }),
                AdminActionRefusal::DelegationIdMalformed,
            ),
            (
                serde_json::json!({ "delegation_id": "   ", "reason": "r" }),
                AdminActionRefusal::DelegationIdMalformed,
            ),
            (
                serde_json::json!({ "delegation_id": 7, "reason": "r" }),
                AdminActionRefusal::DelegationIdMalformed,
            ),
            (
                serde_json::json!({ "delegation_id": "att-1", "reason": "" }),
                AdminActionRefusal::ReasonMalformed,
            ),
            (
                serde_json::json!({ "delegation_id": "att-1", "reason": ["r"] }),
                AdminActionRefusal::ReasonMalformed,
            ),
            (
                serde_json::json!("not an object"),
                AdminActionRefusal::DetailNotAnObject,
            ),
        ];
        for (detail, expect) in cases {
            assert_eq!(
                check_admin_action_attribution(&ev(&k, detail.clone())),
                Err(*expect),
                "detail {detail} must refuse with {expect}"
            );
        }
        // And the happy path.
        check_admin_action_attribution(&ev(
            &k,
            serde_json::json!({ "delegation_id": "att-1", "reason": "spam flood" }),
        ))
        .expect("a fully attributed admin action admits");
    }

    #[test]
    fn refusal_field_points_at_the_key_the_operator_must_fix() {
        assert_eq!(
            AdminActionRefusal::DelegationIdAbsent.field(),
            Some(admin_field::DELEGATION_ID)
        );
        assert_eq!(
            AdminActionRefusal::ReasonMalformed.field(),
            Some(admin_field::REASON)
        );
        assert_eq!(AdminActionRefusal::DetailNotAnObject.field(), None);
    }

    #[test]
    fn the_builder_produces_an_event_that_clears_its_own_gate() {
        let at: DateTime<Utc> = "2026-08-02T10:00:00Z".parse().unwrap();
        let e = admin_action_event(
            admin_op::QUARANTINE,
            "k-bad",
            Some("k-admin"),
            "att-delegation-1",
            "sustained spam",
            at,
        );
        check_admin_action_attribution(&e).expect("the builder's own shape admits");
        assert_eq!(e.kind, "admin_action:quarantine");
        assert_eq!(e.target_key_id.as_deref(), Some("k-bad"));
        assert_eq!(e.subject_key_id.as_deref(), Some("k-admin"));
        assert_eq!(
            e.detail[admin_field::DELEGATION_ID].as_str(),
            Some("att-delegation-1")
        );
        // Idempotent on the whole-second instant; distinct per op + target.
        assert_eq!(
            e.event_id,
            admin_action_event_id(admin_op::QUARANTINE, "k-bad", at)
        );
        assert_ne!(
            e.event_id,
            admin_action_event_id(admin_op::DE_ADMISSION, "k-bad", at)
        );
        assert_ne!(
            e.event_id,
            admin_action_event_id(admin_op::QUARANTINE, "k-other", at)
        );
        assert_ne!(
            e.event_id,
            admin_action_event_id(
                admin_op::QUARANTINE,
                "k-bad",
                at + chrono::Duration::seconds(1)
            )
        );
    }
}
