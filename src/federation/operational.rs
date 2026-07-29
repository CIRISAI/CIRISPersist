//! Operational-data admit + merge surface (CEG 1.0-RC2 §5.6.8.13 /
//! §10.1.6; CIRISRegistry#70, CIRISPersist#65, v5.1.0).
//!
//! # What this module is
//!
//! The three operational subject_kinds — `organization`,
//! `org_membership`, `partner_record` — federate as signed CEG envelopes
//! carried by the same anti-entropy carrier as trust data (CIRISEdge#65
//! v2 wire). This module is the substrate's **admission + merge** half;
//! the *signature verification* it depends on is Verify's
//! ([`ciris_verify_core::operational_admit`]) — RC2 §5.6.8.13 pins the
//! two-quorums split: "the substrate's merge logic never counts steward
//! signatures."
//!
//! This module holds the backend-agnostic pieces:
//!
//! - The three row shapes ([`Organization`] / [`OrgMembership`] /
//!   [`PartnerRecord`]) + their `Signed*` write wrappers.
//! - The **four admission checks** ([`check_skew_bound`],
//!   [`reject_payment_processor_identifiers`], plus the authority + set-
//!   semantics checks the backends compose from `ciris_verify_core`).
//! - The **two CEG-declared merge dispatchers** ([`resolve_lww`] for
//!   `organization` / `org_membership`; [`resolve_monotonic_quorum`] for
//!   `partner_record`), dispatched on the §10.1.6 policy declared **per
//!   subject_kind** — declared, never inferred.
//! - **Stable-id current-state resolution** ([`resolve_lww`]): group by
//!   business id, `withdraws` forward-only, latest `asserted_at`
//!   (skew-bounded), tie-break smallest `attestation_id`. Partition-
//!   tolerant: it MUST NOT require supersedes-chain completeness
//!   (supersedes is audit-only).
//!
//! # The four admission checks (RC2 §5.6.8.13 / §10.1.6)
//!
//! Every `put_*` runs, in order:
//!
//! 1. **Skew-bound** ([`check_skew_bound`]) — `asserted_at <= now +
//!    §0.7 tolerance` (±5 min) or [`Error::ClockSkewViolation`]. The LWW
//!    front-running fix: unbounded LWW on `org_membership.role:OrgAdmin`
//!    is a role-escalation surface.
//! 2. **No-payment-processor-identifier**
//!    ([`reject_payment_processor_identifiers`]) — defense-in-depth: an
//!    operational envelope MUST NOT carry Stripe-shaped ids anywhere,
//!    including open-vocabulary fields.
//! 3. **Authority** — `organization` / `org_membership` →
//!    [`ciris_verify_core::operational_admit::resolve_role_authority`]
//!    (persist resolves the current membership set + key_directory +
//!    root_stewards; fail-closed). `partner_record` →
//!    [`ciris_verify_core::operational_admit::verify_partner_record_quorum`].
//! 4. **Set-semantics** — `partner_record` capability/restriction arrays
//!    sorted ([`ciris_verify_core::operational_admit::check_set_semantics_sorted`]).
//!
//! # Merge intents are declared, not inferred (§10.1.6)
//!
//! | subject_kind(s) | Merge intent |
//! |---|---|
//! | `organization`, `org_membership` | `lww_skew_bounded` + `withdrawal_forward_only` |
//! | `partner_record` | `monotonic_quorum` (revision anti-rollback at admit, then the V058 `MergeBallot` comparator) |
//!
//! [`SubjectKind::merge_intent`] is the single source of the dispatch;
//! the substrate reads the declaration, it does not invent policy.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Error;

/// §0.7 clock-skew tolerance (±5 minutes by default). An operational
/// envelope merging under `lww_skew_bounded` is rejected at admission if
/// `asserted_at` is more than this far in the future — the LWW
/// front-running bound (RC2 §10.1.6 Persist concern B).
pub const CLOCK_SKEW_TOLERANCE: Duration = Duration::minutes(5);

/// The three operational subject_kinds (RC2 §5.6.8.13). The replication
/// wire tokens are the snake_case [`SubjectKind::as_str`] forms — the
/// Edge v2 `EnvelopeKind` additions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// `organization` — an org record (LWW + withdrawal-forward-only).
    Organization,
    /// `org_membership` — a (user, org, role) grant (LWW + withdrawal-
    /// forward-only).
    OrgMembership,
    /// `partner_record` — a license/partner grant (monotonic_quorum).
    PartnerRecord,
}

/// The §10.1.6 CEG-declared cross-region merge intent for a subject_kind.
/// Declared, never inferred — the substrate dispatches on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeIntent {
    /// `lww_skew_bounded` + `withdrawal_forward_only` — stable-id
    /// grouping, an admitted `withdraws` is forward-only (no resurrect),
    /// else latest `asserted_at` wins, tie-break smallest
    /// `attestation_id`.
    LwwSkewBounded,
    /// `monotonic_quorum` — admission anti-rollback on `revision` first
    /// (a decrease never enters the merge), then the V058 `MergeBallot`
    /// comparator (`quorum_weight` → signed timestamp → content hash);
    /// more-restrictive state wins (`revoked` > `suspended` > `active`).
    MonotonicQuorum,
}

impl SubjectKind {
    /// The snake_case replication wire token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SubjectKind::Organization => "organization",
            SubjectKind::OrgMembership => "org_membership",
            SubjectKind::PartnerRecord => "partner_record",
        }
    }

    /// The §10.1.6 CEG-declared merge intent for this subject_kind.
    /// Declared property of the kind — the substrate reads it, it does
    /// not infer policy per record type.
    #[must_use]
    pub fn merge_intent(self) -> MergeIntent {
        match self {
            SubjectKind::Organization | SubjectKind::OrgMembership => MergeIntent::LwwSkewBounded,
            SubjectKind::PartnerRecord => MergeIntent::MonotonicQuorum,
        }
    }
}

// ── Row shapes ──────────────────────────────────────────────────────

/// An `organization` row (RC2 §5.6.8.13). The trust/authz-minimal
/// projection — PII / business detail (tax_id, emails, oauth_*, metadata,
/// created_by) NEVER federates and is not stored here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    /// Server-assigned envelope identity; the §6.1 tie-break key.
    pub attestation_id: String,
    /// FIRST-CLASS business id — the stable-id grouping key.
    pub org_id: String,
    /// Org display name (projection field).
    pub name: String,
    /// `internal` | `partner` | `licensee` | `community`.
    pub org_type: String,
    /// Parent org for a licensee under a partner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_org_id: Option<String>,
    /// Link to a `partner_record`'s `partner_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner_id: Option<String>,
    /// `active` | `suspended` | `deactivated`.
    pub status: String,
    /// §0.5 RFC-3339; the LWW ordering field.
    pub asserted_at: DateTime<Utc>,
    /// When the projection expires. `None` = indefinite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// The key that signed the envelope (the role-gated admit actor).
    pub attesting_key_id: String,
    /// The signed envelope (JCS basis for signature re-verification).
    pub signed_envelope: Value,
    /// Ed25519 signature over `JCS(signed_envelope)`, base64 standard.
    pub ed25519_signature_base64: String,
    /// ML-DSA-65 signature over `JCS(signed_envelope) ‖ ed25519_sig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mldsa65_signature_base64: Option<String>,
    /// `None` = currently in force; set = withdrawn (forward-only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<DateTime<Utc>>,
    /// **Server-computed** row-integrity hash.
    #[serde(default)]
    pub persist_row_hash: String,
}

/// An `org_membership` row (RC2 §5.6.8.13). The entire User PII record
/// (email, name, oauth_*, last_login_at, mfa_*, invited_by) NEVER
/// federates — role-based authz works federation-wide; login resolution
/// is home-region-local.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgMembership {
    /// Server-assigned envelope identity; the §6.1 tie-break key.
    pub attestation_id: String,
    /// FIRST-CLASS (with `org_id`) — the stable-id grouping key.
    pub user_id: String,
    /// FIRST-CLASS (with `user_id`).
    pub org_id: String,
    /// `org_admin` | `key_manager` | `operator` | `viewer`.
    pub role: String,
    /// `active` | `deactivated`.
    pub status: String,
    /// §0.5 RFC-3339; the LWW ordering field.
    pub asserted_at: DateTime<Utc>,
    /// When the grant expires. `None` = indefinite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// The granter key that signed the envelope.
    pub attesting_key_id: String,
    /// The signed envelope (JCS basis + the
    /// [`ciris_verify_core::operational_admit::MembershipGrant`] source).
    pub signed_envelope: Value,
    /// Ed25519 signature over `JCS(signed_envelope)`, base64 standard.
    pub ed25519_signature_base64: String,
    /// ML-DSA-65 signature over `JCS(signed_envelope) ‖ ed25519_sig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mldsa65_signature_base64: Option<String>,
    /// `None` = currently in force; set = withdrawn (forward-only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<DateTime<Utc>>,
    /// **Server-computed** row-integrity hash.
    #[serde(default)]
    pub persist_row_hash: String,
}

/// A `partner_record` row (RC2 §5.6.8.13). No PII split — the record IS
/// the world-verifiable grant; it federates whole. Admitted by M-of-N
/// steward quorum, merged by `monotonic_quorum` on `revision`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartnerRecord {
    /// Server-assigned envelope identity; the §6.1 tie-break key.
    pub attestation_id: String,
    /// FIRST-CLASS business id — the stable-id grouping key.
    pub license_id: String,
    /// The partner this license belongs to.
    pub partner_id: String,
    /// The org this license is scoped to.
    pub org_id: String,
    /// `community` | `community_plus` | `professional_*` |
    /// `professional_full`.
    pub license_type: String,
    /// `A0`..`A4`.
    pub max_autonomy_tier: String,
    /// Whether deployment requires a supervisor.
    pub requires_supervisor: bool,
    /// Max concurrent deployments.
    pub deployment_limit: u32,
    /// Offline grace window, hours.
    pub offline_grace_hours: u32,
    /// `active` | `suspended` | `revoked`.
    pub status: String,
    /// MONOTONIC per `license_id` — admission REJECTS any decrease
    /// (F-AV-ROLLBACK; the `monotonic_quorum` merge orders on this).
    pub revision: u64,
    /// §0.5 RFC-3339.
    pub issued_at: DateTime<Utc>,
    /// §0.5 RFC-3339.
    pub expires_at: DateTime<Utc>,
    /// §0.5 RFC-3339.
    pub asserted_at: DateTime<Utc>,
    /// The full signed envelope (it federates whole; carries the set-
    /// semantics `capabilities_granted` / `capabilities_denied` /
    /// `geographic_restrictions` / `allowed_identity_templates` arrays).
    /// The M-of-N steward quorum verifies against the JCS bytes of this.
    pub signed_envelope: Value,
    /// `None` = currently in force; set = withdrawn (forward-only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<DateTime<Utc>>,
    /// **Server-computed** row-integrity hash.
    #[serde(default)]
    pub persist_row_hash: String,
}

/// The set-semantics array fields of a `partner_record` (RC2 §5.6.8.13).
/// Each MUST be lexicographically sorted so M stewards sign byte-
/// identical JCS bytes — fed to
/// [`ciris_verify_core::operational_admit::check_set_semantics_sorted`].
pub const PARTNER_RECORD_SET_FIELDS: &[&str] = &[
    "allowed_identity_templates",
    "capabilities_denied",
    "capabilities_granted",
    "geographic_restrictions",
];

/// Wraps an [`Organization`] for write submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOrganization {
    /// The organization being submitted.
    pub organization: Organization,
}

/// Wraps an [`OrgMembership`] for write submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOrgMembership {
    /// The membership being submitted.
    pub org_membership: OrgMembership,
}

/// Wraps a [`PartnerRecord`] for write submission, with the steward
/// M-of-N quorum signatures over its JCS bytes and the threshold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPartnerRecord {
    /// The partner record being submitted.
    pub partner_record: PartnerRecord,
    /// The M steward signatures over `JCS(partner_record.signed_envelope)`.
    pub steward_signatures: Vec<ciris_verify_core::threshold::ThresholdSignature>,
    /// The M-of-N threshold required (the N is the roster length).
    pub threshold: usize,
}

// ── Admission check 1: skew-bound (§0.7 / §10.1.6) ──────────────────

/// Reject an envelope whose `asserted_at` is more than
/// [`CLOCK_SKEW_TOLERANCE`] (±5 min) in the future relative to `now`
/// (RC2 §10.1.6 Persist concern B). The LWW front-running fix: without
/// it a forward-skewed clock future-dates `asserted_at` and wins LWW
/// indefinitely.
///
/// # Errors
/// [`Error::ClockSkewViolation`] when `asserted_at > now + tolerance`.
pub fn check_skew_bound(asserted_at: DateTime<Utc>, now: DateTime<Utc>) -> Result<(), Error> {
    if asserted_at > now + CLOCK_SKEW_TOLERANCE {
        return Err(Error::ClockSkewViolation {
            asserted_at: asserted_at.to_rfc3339(),
            now: now.to_rfc3339(),
        });
    }
    Ok(())
}

// ── Admission check 2: no payment-processor identifiers ─────────────

/// Stripe / payment-processor identifier prefixes that an operational
/// envelope MUST NOT carry (RC2 §5.6.8.13, fail-secure). Defense-in-depth
/// behind the Registry's emit-side minimization. These are the canonical
/// Stripe object-id prefixes (customer / subscription / charge / payment-
/// intent / card / invoice / payment-method / setup-intent / price /
/// product / bank account / source / token).
pub const PAYMENT_PROCESSOR_PREFIXES: &[&str] = &[
    "cus_", "sub_", "ch_", "pi_", "card_", "in_", "pm_", "seti_", "price_", "prod_", "ba_", "src_",
    "tok_", "re_", "py_", "txn_", "ii_",
];

/// Recursively scan a JSON value for any string that begins with a
/// recognizable payment-processor identifier prefix
/// ([`PAYMENT_PROCESSOR_PREFIXES`]) — anywhere, including open-vocabulary
/// fields, object keys, and array elements (RC2 §5.6.8.13).
///
/// # Errors
/// [`Error::PaymentProcessorIdentifier`] on the first offending token,
/// naming the matched prefix.
pub fn reject_payment_processor_identifiers(value: &Value) -> Result<(), Error> {
    fn matches_prefix(s: &str) -> Option<&'static str> {
        PAYMENT_PROCESSOR_PREFIXES
            .iter()
            .copied()
            .find(|p| s.starts_with(p) && s.len() > p.len())
    }
    match value {
        Value::String(s) => {
            if let Some(prefix) = matches_prefix(s) {
                return Err(Error::PaymentProcessorIdentifier {
                    matched_prefix: prefix,
                });
            }
        }
        Value::Array(arr) => {
            for v in arr {
                reject_payment_processor_identifiers(v)?;
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                // Keys are open-vocab too — a forged key like `cus_x` is
                // just as much a leak vector as a value.
                if let Some(prefix) = matches_prefix(k) {
                    return Err(Error::PaymentProcessorIdentifier {
                        matched_prefix: prefix,
                    });
                }
                reject_payment_processor_identifiers(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// ── Admission orchestration (shared across backends) ────────────────

/// Build a [`ciris_verify_core::operational_admit::MembershipGrant`] from
/// a stored [`OrgMembership`] row — the role-authority resolver input.
/// Carries the signed envelope (JCS basis) + the bound signature halves.
#[must_use]
pub fn membership_grant_of(
    m: &OrgMembership,
) -> ciris_verify_core::operational_admit::MembershipGrant {
    ciris_verify_core::operational_admit::MembershipGrant {
        signed_envelope: m.signed_envelope.clone(),
        ed25519_signature_base64: m.ed25519_signature_base64.clone(),
        mldsa65_signature_base64: m.mldsa65_signature_base64.clone(),
    }
}

/// Run admission checks 1+2 (skew-bound + no-payment-processor) shared by
/// all three operational admits. `asserted_at` is the row's ordering
/// field; `envelope` is the full signed envelope scanned for
/// payment-processor identifiers.
///
/// # Errors
/// [`Error::ClockSkewViolation`] or [`Error::PaymentProcessorIdentifier`].
pub fn check_skew_and_payment(
    asserted_at: DateTime<Utc>,
    now: DateTime<Utc>,
    envelope: &Value,
) -> Result<(), Error> {
    check_skew_bound(asserted_at, now)?;
    reject_payment_processor_identifiers(envelope)?;
    Ok(())
}

/// v21.0.0 (CIRISPersist#502 E9) — resolve the operational steward roster
/// from persist's OWN registered directory, NEVER a caller-passed slice.
/// Before this, `check_role_authority` / `check_partner_set_and_quorum`
/// trusted a `key_directory` / `root_stewards` / `steward_roster` handed in
/// by the caller — genuine hybrid crypto verified against the WRONG root of
/// trust (the gate collapses if any caller derives the roster from
/// untrusted input). The stewards are the registered `identity_type =
/// steward` keys; their `ThresholdMember`s carry their REGISTERED pubkeys.
pub async fn resolve_steward_roster<F>(
    directory: &F,
) -> Result<
    (
        Vec<ciris_verify_core::threshold::ThresholdMember>,
        Vec<String>,
    ),
    Error,
>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    let stewards = directory
        .list_keys_by_identity_type(crate::federation::types::identity_type::STEWARD)
        .await
        .map_err(|e| Error::OperationalAuthority(format!("steward roster resolve: {e}")))?;
    let members: Vec<ciris_verify_core::threshold::ThresholdMember> = stewards
        .iter()
        .map(|k| ciris_verify_core::threshold::ThresholdMember {
            member_id: k.key_id.clone(),
            ed25519_public_key_base64: k.pubkey_ed25519_base64.clone(),
            mldsa65_public_key_base64: k.pubkey_ml_dsa_65_base64.clone(),
            role: Some(ciris_verify_core::threshold::Role::Founder),
        })
        .collect();
    let root_stewards: Vec<String> = stewards.iter().map(|k| k.key_id.clone()).collect();
    Ok((members, root_stewards))
}

/// Run the `organization` / `org_membership` **authority** check
/// (admission check 3): the operation's actor (`actor_key_id`) must hold
/// `OrgAdmin` in `org_id`, established by a root-anchored grant in the
/// caller-resolved `current_memberships` set. Fail-closed.
///
/// # Errors
/// [`Error::OperationalAuthority`] if
/// [`ciris_verify_core::operational_admit::resolve_role_authority`]
/// returns anything but a positive verdict.
pub fn check_role_authority(
    actor_key_id: &str,
    org_id: &str,
    current_memberships: &[OrgMembership],
    key_directory: &[ciris_verify_core::threshold::ThresholdMember],
    root_stewards: &[String],
) -> Result<(), Error> {
    // Bootstrap anchor: a recognized root steward / system authority is
    // the org-creation root (RC2 §5.6.8.13 "rooted at org creation by a
    // steward/system authority"). It needs no prior membership grant —
    // it IS the anchor the role-chain resolves to. Without this, the
    // first `org_membership` (a steward granting the initial OrgAdmin)
    // could never admit, because the resolver looks for a grant naming
    // the actor.
    if root_stewards.iter().any(|s| s == actor_key_id) {
        return Ok(());
    }
    let grants: Vec<_> = current_memberships
        .iter()
        .map(membership_grant_of)
        .collect();
    let verdict = ciris_verify_core::operational_admit::resolve_role_authority(
        actor_key_id,
        org_id,
        ciris_verify_core::operational_admit::OrgRole::OrgAdmin,
        &grants,
        key_directory,
        root_stewards,
    );
    if verdict.authorized {
        Ok(())
    } else {
        Err(Error::OperationalAuthority(format!(
            "actor {actor_key_id:?} lacks OrgAdmin in org {org_id:?} \
             (reason: {:?})",
            verdict.reason
        )))
    }
}

/// Run the `partner_record` **set-semantics** (check 3) + **quorum**
/// (check 4) admission steps. The set-semantics guard runs first so a
/// mis-ordered array is caught loudly *before* the quorum would silently
/// collapse on divergent JCS bytes.
///
/// # Errors
/// [`Error::SetSemanticsUnsorted`] or [`Error::OperationalAuthority`].
pub fn check_partner_set_and_quorum(
    signed: &SignedPartnerRecord,
    steward_roster: &[ciris_verify_core::threshold::ThresholdMember],
) -> Result<(), Error> {
    ciris_verify_core::operational_admit::check_set_semantics_sorted(
        &signed.partner_record.signed_envelope,
        PARTNER_RECORD_SET_FIELDS,
    )
    .map_err(|e| Error::SetSemanticsUnsorted(e.to_string()))?;
    ciris_verify_core::operational_admit::verify_partner_record_quorum(
        &signed.partner_record.signed_envelope,
        steward_roster,
        &signed.steward_signatures,
        signed.threshold,
    )
    .map_err(|e| Error::OperationalAuthority(format!("partner_record quorum: {e}")))?;
    Ok(())
}

/// Anti-rollback guard (partner_record admission check 5): the submitted
/// `revision` MUST strictly exceed `existing_max` (the most-recent
/// admitted revision for the same `license_id`, or `None` for a first
/// write).
///
/// # Errors
/// [`Error::PartnerRecordRollback`] when the revision does not advance.
pub fn check_partner_revision_monotonic(
    license_id: &str,
    submitted: u64,
    existing_max: Option<u64>,
) -> Result<(), Error> {
    if let Some(existing) = existing_max {
        if submitted <= existing {
            return Err(Error::PartnerRecordRollback {
                license_id: license_id.to_string(),
                submitted,
                existing,
            });
        }
    }
    Ok(())
}

// ── Merge: lww_skew_bounded + withdrawal_forward_only ───────────────

/// Resolve current state for a stable-id-grouped set of LWW rows
/// (`organization` / `org_membership`) per RC2 §5.6.8.13 + §10.1.6.
///
/// **All `rows` MUST share the same business id** — the caller groups by
/// `org_id` (organization) or `(user_id, org_id)` (org_membership) before
/// calling. The returned [`LwwRow`] is the current effective row for that
/// id, or `None` if the group resolves to *withdrawn* (forward-only) or
/// is empty.
///
/// Resolution:
/// 1. **`withdrawal_forward_only`** — if ANY row in the group is
///    withdrawn (`withdrawn_at.is_some()` or `status` is the kind's
///    deactivated state), the id is withdrawn and a later non-withdrawn
///    write does NOT resurrect it.
/// 2. Otherwise the **latest `asserted_at`** wins.
/// 3. Tie-break: **smallest `attestation_id`** (§6.1).
///
/// **Partition tolerance (the key correctness property):** this consults
/// only the supplied set; it never walks a `supersedes` chain and never
/// requires chain completeness. A region that never observed envelope
/// N−1 still converges — out-of-order arrival is irrelevant because the
/// winner is a deterministic function of the *set*, not its arrival
/// order.
pub fn resolve_lww<R: LwwRow>(rows: &[R]) -> Option<&R> {
    if rows.is_empty() {
        return None;
    }
    // withdrawal_forward_only: a withdraw anywhere in the group is final.
    if rows.iter().any(LwwRow::is_withdrawn) {
        return None;
    }
    let mut best = &rows[0];
    for candidate in &rows[1..] {
        if lww_wins(candidate, best) {
            best = candidate;
        }
    }
    Some(best)
}

/// True iff `a` beats `b` under LWW: later `asserted_at`, tie-break
/// smaller `attestation_id` (§6.1).
fn lww_wins<R: LwwRow>(a: &R, b: &R) -> bool {
    match a.asserted_at().cmp(&b.asserted_at()) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        // Same asserted_at: smallest attestation_id wins (§6.1).
        std::cmp::Ordering::Equal => a.attestation_id() < b.attestation_id(),
    }
}

/// The fields [`resolve_lww`] needs from a stable-id-grouped row, so
/// `organization` and `org_membership` share one resolver.
pub trait LwwRow {
    /// §6.1 tie-break key.
    fn attestation_id(&self) -> &str;
    /// LWW ordering field.
    fn asserted_at(&self) -> DateTime<Utc>;
    /// Whether this row withdraws the id (withdrawn_at set OR the kind's
    /// deactivated status). A `true` anywhere in a group makes the id
    /// forward-only withdrawn.
    fn is_withdrawn(&self) -> bool;
}

impl LwwRow for Organization {
    fn attestation_id(&self) -> &str {
        &self.attestation_id
    }
    fn asserted_at(&self) -> DateTime<Utc> {
        self.asserted_at
    }
    fn is_withdrawn(&self) -> bool {
        self.withdrawn_at.is_some() || self.status == "deactivated"
    }
}

impl LwwRow for OrgMembership {
    fn attestation_id(&self) -> &str {
        &self.attestation_id
    }
    fn asserted_at(&self) -> DateTime<Utc> {
        self.asserted_at
    }
    fn is_withdrawn(&self) -> bool {
        self.withdrawn_at.is_some() || self.status == "deactivated"
    }
}

// ── Merge: monotonic_quorum (partner_record) ────────────────────────

/// More-restrictive-state rank for `partner_record` conflict resolution
/// (RC2 §10.1.6): `revoked` (2) > `suspended` (1) > `active` (0). Higher
/// wins on conflict. Unknown statuses rank below `active` (0) so a
/// malformed status never silently wins over a real revoke.
#[must_use]
pub fn partner_status_rank(status: &str) -> u8 {
    match status {
        "revoked" => 2,
        "suspended" => 1,
        _ => 0,
    }
}

/// Resolve current state for a `license_id`-grouped set of
/// `partner_record` rows under `monotonic_quorum` (RC2 §10.1.6).
///
/// **All `rows` MUST share the same `license_id`.** Admission anti-
/// rollback on `revision` already happened at `put_partner_record` (a
/// `revision` decrease never entered the store), so this resolves the
/// merge winner among admitted rows:
///
/// 1. Highest `revision` wins (the monotonic counter).
/// 2. Tie: more-restrictive `status` wins (`revoked` > `suspended` >
///    `active`) — a stale `active` can never overwrite a revoke.
/// 3. Tie: latest `asserted_at` wins.
/// 4. Tie: smallest `attestation_id` wins (§6.1).
///
/// Partition-tolerant: consults only the supplied set; no supersedes
/// chain walk.
///
/// (The §10.1.6 `MergeBallot` `quorum_weight` tier-1 lives in
/// [`super::verify_coord`]; in single-region resolution every admitted
/// row carries equal weight, so the ordering reduces to revision →
/// status → time → id. A cross-region merge layers `quorum_weight` on
/// top via `verify_coord::compare_for_merge`.)
#[must_use]
pub fn resolve_monotonic_quorum(rows: &[PartnerRecord]) -> Option<&PartnerRecord> {
    if rows.is_empty() {
        return None;
    }
    let mut best = &rows[0];
    for candidate in &rows[1..] {
        if partner_wins(candidate, best) {
            best = candidate;
        }
    }
    Some(best)
}

/// True iff `a` beats `b` under monotonic_quorum.
fn partner_wins(a: &PartnerRecord, b: &PartnerRecord) -> bool {
    match a.revision.cmp(&b.revision) {
        std::cmp::Ordering::Greater => return true,
        std::cmp::Ordering::Less => return false,
        std::cmp::Ordering::Equal => {}
    }
    let (ra, rb) = (
        partner_status_rank(&a.status),
        partner_status_rank(&b.status),
    );
    if ra != rb {
        return ra > rb;
    }
    match a.asserted_at.cmp(&b.asserted_at) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => a.attestation_id < b.attestation_id,
    }
}

/// Test-support builders shared by the backend test modules
/// (`store::sqlite` / `store::postgres`) so the operational-data
/// round-trip / merge / admission tests don't duplicate hybrid-signing
/// scaffolding. Crate-internal, test-only.
///
/// `#[allow(dead_code)]`: the signed-envelope builders are consumed by the
/// `sqlite`/`postgres` backend test modules. Under a backend-less test
/// build (`cargo test --features server`, no backend feature — the
/// `darwin-aarch64 (no postgres)` CI job) those modules don't compile, so
/// the builders are legitimately unused there; without this, `-D warnings`
/// fails the job on dead_code. The operational unit tests in this file
/// exercise the pure resolvers and don't need the signed-envelope helpers.
// v18.3.0 (CIRISPersist#484) — the gate widened from `#[cfg(test)]` to
// `#[cfg(any(test, feature = "test-anchor"))]` so DOWNSTREAM test builds can
// mint a genuinely accord-co-scrubbed record and test the `has_effective_role`
// ALLOW path. Under `#[cfg(test)]` alone these were unreachable to a consumer
// (a dependency's test items never compile into the dependent), so consumers
// gating real planes on `has_effective_role` (edge trace-serve) could only
// test the DENY path — the exact blindness that shipped CIRISEdge#379's gate
// fail-closed-dead in the field. `test-anchor` is persist's established
// "test-only, NEVER in a published wheel" fence (see Cargo.toml), so the
// signing helpers stay out of release builds.
#[cfg(any(test, feature = "test-anchor"))]
#[allow(dead_code)]
pub mod test_support {
    use super::*;
    use base64::Engine as _;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};
    use serde_json::json;

    fn b64() -> base64::engine::general_purpose::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }

    /// A signing identity: a key_id plus its hybrid keypair.
    pub struct Identity {
        /// The identity's `key_id`.
        pub key_id: String,
        ed: Ed25519Signer,
        mldsa: MlDsa65Signer,
    }

    impl Identity {
        /// v21.0.0 (#502 E9 test-isolation fix) — a DETERMINISTIC hybrid
        /// identity seeded from `id` (the same `[0x11;32]`-overlay seed
        /// `tier_ingest::test_support` uses), NOT a random keypair.
        ///
        /// The old random constructor meant a fixed key_id like `"s1"` had
        /// DIFFERENT pubkeys on every construction — harmless while rosters
        /// were passed in-memory per test, but once E9 resolves the roster
        /// from the shared directory, two serial tests reusing `"s1"` on one
        /// pg DB got mismatched pubkeys-vs-signatures (roster from run A,
        /// signatures from run B → 0 valid). Deterministic seeding makes
        /// `"s1"` stable across tests/runs AND byte-identical to
        /// `hybrid_pubkeys("s1")`, so registration is idempotent and the
        /// resolved roster always verifies the signatures.
        pub fn new(id: &str) -> Self {
            let mut seed = [0x11u8; 32];
            for (i, b) in id.bytes().take(32).enumerate() {
                seed[i] = b;
            }
            Self {
                key_id: id.to_string(),
                ed: Ed25519Signer::from_seed(&seed).expect("ed seed"),
                mldsa: MlDsa65Signer::from_seed(&seed).expect("mldsa seed"),
            }
        }

        /// v21.0.0 (#502 E9) — this identity as a REGISTERED `steward`
        /// `KeyRecord` (identity_type = steward, carrying this identity's
        /// pubkeys) so `resolve_steward_roster` finds it in the directory.
        /// The E9 model: stewards are registered steward keys, not a
        /// caller-passed roster.
        pub fn steward_key_record(&self) -> crate::federation::types::KeyRecord {
            let m = self.member();
            crate::federation::types::KeyRecord {
                key_id: self.key_id.clone(),
                pubkey_ed25519_base64: m.ed25519_public_key_base64,
                pubkey_ml_dsa_65_base64: m.mldsa65_public_key_base64,
                algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
                identity_type: crate::federation::types::identity_type::STEWARD.to_owned(),
                identity_ref: self.key_id.clone(),
                // Fixed timestamp — deterministic content so the same key_id
                // registers idempotently across serial tests on a shared DB.
                valid_from: "2020-01-01T00:00:00Z".parse().unwrap(),
                valid_until: None,
                registration_envelope: json!({ "key_id": self.key_id }),
                original_content_hash: {
                    use sha2::Digest as _;
                    let env = json!({ "key_id": self.key_id });
                    let canonical =
                        crate::verify::canonical::ceg_produce_canonicalize(&env).unwrap();
                    hex::encode(sha2::Sha256::digest(&canonical))
                },
                scrub_signature_classical: "AA".to_owned(),
                scrub_signature_pqc: None,
                scrub_key_id: self.key_id.clone(),
                scrub_timestamp: "2020-01-01T00:00:00Z".parse().unwrap(),
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            }
        }

        /// This identity as a plain (non-founder) directory member.
        pub fn member(&self) -> ciris_verify_core::threshold::ThresholdMember {
            ciris_verify_core::threshold::ThresholdMember {
                member_id: self.key_id.clone(),
                ed25519_public_key_base64: b64().encode(self.ed.public_key().unwrap()),
                mldsa65_public_key_base64: Some(b64().encode(self.mldsa.public_key().unwrap())),
                role: None,
            }
        }

        /// This identity as a `Founder`-role roster member (partner_record
        /// quorum counts only Founders).
        pub fn founder_member(&self) -> ciris_verify_core::threshold::ThresholdMember {
            let mut m = self.member();
            m.role = Some(ciris_verify_core::threshold::Role::Founder);
            m
        }

        /// Hybrid-sign `bytes` → (ed_sig_b64, mldsa_sig_b64) bound payload.
        pub fn sign_bytes(&self, bytes: &[u8]) -> (String, String) {
            let ed_sig = self.ed.sign(bytes).unwrap();
            let mut bound = bytes.to_vec();
            bound.extend_from_slice(&ed_sig);
            let pqc_sig = self.mldsa.sign(&bound).unwrap();
            (b64().encode(&ed_sig), b64().encode(&pqc_sig))
        }

        /// A threshold signature over `bytes` for the partner quorum.
        pub fn threshold_sig(
            &self,
            bytes: &[u8],
        ) -> ciris_verify_core::threshold::ThresholdSignature {
            let (ed, mldsa) = self.sign_bytes(bytes);
            ciris_verify_core::threshold::ThresholdSignature {
                member_id: self.key_id.clone(),
                ed25519_signature_base64: ed,
                mldsa65_signature_base64: Some(mldsa),
            }
        }
    }

    /// Build a signed `org_membership` row: `granter` asserts `user_id`
    /// holds `role` in `org_id` with `status`. `attestation_id`,
    /// `asserted_at`, and the bound signature are filled. The signed
    /// envelope shape matches what the verify role-resolver parses
    /// (`user_id` / `org_id` / `role` / `status` / `attesting_key_id`).
    pub fn signed_membership(
        attestation_id: &str,
        granter: &Identity,
        user_id: &str,
        org_id: &str,
        role: &str,
        status: &str,
        asserted_at: DateTime<Utc>,
    ) -> SignedOrgMembership {
        let envelope = json!({
            "user_id": user_id,
            "org_id": org_id,
            "role": role,
            "status": status,
            "attesting_key_id": granter.key_id,
        });
        let bytes = ciris_verify_core::jcs::canonicalize(&envelope).unwrap();
        let (ed, mldsa) = granter.sign_bytes(&bytes);
        SignedOrgMembership {
            org_membership: OrgMembership {
                attestation_id: attestation_id.into(),
                user_id: user_id.into(),
                org_id: org_id.into(),
                role: role.into(),
                status: status.into(),
                asserted_at,
                valid_until: None,
                attesting_key_id: granter.key_id.clone(),
                signed_envelope: envelope,
                ed25519_signature_base64: ed,
                mldsa65_signature_base64: Some(mldsa),
                withdrawn_at: None,
                persist_row_hash: String::new(),
            },
        }
    }

    /// Build a signed `organization` row whose envelope is signed by
    /// `actor` (the operation's `attesting_key_id`).
    pub fn signed_organization(
        attestation_id: &str,
        org_id: &str,
        actor: &Identity,
        status: &str,
        asserted_at: DateTime<Utc>,
    ) -> SignedOrganization {
        let envelope = json!({
            "org_id": org_id,
            "name": "Acme",
            "org_type": "partner",
            "status": status,
            "attesting_key_id": actor.key_id,
        });
        let bytes = ciris_verify_core::jcs::canonicalize(&envelope).unwrap();
        let (ed, mldsa) = actor.sign_bytes(&bytes);
        SignedOrganization {
            organization: Organization {
                attestation_id: attestation_id.into(),
                org_id: org_id.into(),
                name: "Acme".into(),
                org_type: "partner".into(),
                parent_org_id: None,
                partner_id: None,
                status: status.into(),
                asserted_at,
                valid_until: None,
                attesting_key_id: actor.key_id.clone(),
                signed_envelope: envelope,
                ed25519_signature_base64: ed,
                mldsa65_signature_base64: Some(mldsa),
                withdrawn_at: None,
                persist_row_hash: String::new(),
            },
        }
    }

    /// Build a signed `partner_record` with `threshold`-of-N stewards
    /// signing the identical JCS bytes. Set-semantics arrays are sorted.
    /// `unsorted` injects a deliberately out-of-order capability array to
    /// exercise the set-semantics guard.
    #[allow(clippy::too_many_arguments)]
    pub fn signed_partner_record(
        attestation_id: &str,
        license_id: &str,
        revision: u64,
        status: &str,
        asserted_at: DateTime<Utc>,
        stewards: &[&Identity],
        threshold: usize,
        unsorted: bool,
    ) -> SignedPartnerRecord {
        let caps = if unsorted {
            json!(["identity.read", "billing.read"]) // out of order
        } else {
            json!(["billing.read", "identity.read"])
        };
        let envelope = json!({
            "license_id": license_id,
            "partner_id": "p1",
            "org_id": "org-x",
            "license_type": "professional_full",
            "capabilities_granted": caps,
            "capabilities_denied": ["admin.super"],
            "max_autonomy_tier": "A2",
            "requires_supervisor": false,
            "geographic_restrictions": ["US"],
            "allowed_identity_templates": ["agent.default"],
            "deployment_limit": 10,
            "offline_grace_hours": 24,
            "status": status,
            "revision": revision,
        });
        let bytes = ciris_verify_core::jcs::canonicalize(&envelope).unwrap();
        let sigs: Vec<_> = stewards.iter().map(|s| s.threshold_sig(&bytes)).collect();
        SignedPartnerRecord {
            partner_record: PartnerRecord {
                attestation_id: attestation_id.into(),
                license_id: license_id.into(),
                partner_id: "p1".into(),
                org_id: "org-x".into(),
                license_type: "professional_full".into(),
                max_autonomy_tier: "A2".into(),
                requires_supervisor: false,
                deployment_limit: 10,
                offline_grace_hours: 24,
                status: status.into(),
                revision,
                issued_at: asserted_at,
                expires_at: asserted_at,
                asserted_at,
                signed_envelope: envelope,
                withdrawn_at: None,
                persist_row_hash: String::new(),
            },
            steward_signatures: sigs,
            threshold,
        }
    }

    /// v13.2.0 (CIRISPersist#383) — build a **multi-scrub canonical**
    /// `KeyRecord` for `key_id` carrying `identity_type`, scrubbed by each of
    /// `scrubbers` over the SAME canonical `registration_envelope` (JCS via
    /// `ceg_produce_canonicalize` — the IDENTICAL bytes
    /// [`check_canonical_role_admission`](crate::federation::admission::check_canonical_role_admission)
    /// verifies). Scrub #1 fills the base `scrub_key_id`/`scrub_signature_*`
    /// fields; scrubs #2..N ride `additional_scrubs`. Each scrub is a REAL
    /// hybrid signature by the scrubber's keypair, so the 2-of-3 add gate
    /// (`verify_quorum_policy`) counts it. Pass the accord-holder `Identity`s as
    /// `scrubbers` (2 distinct for a 2-of-3 admit). `envelope` lets a test embed
    /// e.g. a `transport_hints` array (the bootstrap-dial-set surface).
    pub fn signed_canonical_record(
        key_id: &str,
        identity_type: &str,
        envelope: serde_json::Value,
        scrubbers: &[&Identity],
    ) -> crate::federation::types::KeyRecord {
        use crate::federation::types::ScrubSig;
        use sha2::{Digest, Sha256};
        let bytes = crate::verify::canonical::ceg_produce_canonicalize(&envelope)
            .expect("canonicalize envelope");
        let now = chrono::Utc::now();
        let scrub_sigs: Vec<ScrubSig> = scrubbers
            .iter()
            .map(|s| {
                let (ed, pqc) = s.sign_bytes(&bytes);
                ScrubSig {
                    scrub_key_id: s.key_id.clone(),
                    scrub_signature_classical: ed,
                    scrub_signature_pqc: Some(pqc),
                }
            })
            .collect();
        assert!(!scrub_sigs.is_empty(), "at least one scrubber required");
        let first = scrub_sigs[0].clone();
        crate::federation::types::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: b64().encode([7u8; 32]),
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(Sha256::digest(&bytes)),
            scrub_signature_classical: first.scrub_signature_classical,
            scrub_signature_pqc: first.scrub_signature_pqc,
            scrub_key_id: first.scrub_key_id,
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: scrub_sigs[1..].to_vec(),
        }
    }

    /// v18.3.0 (CIRISPersist#484) — a co-scrubbed record that carries
    /// `roles`, so a consumer can test the `has_effective_role` **ALLOW**
    /// path (not just the deny path).
    ///
    /// Identical to [`signed_canonical_record`] but stamps `roles` onto the
    /// row. The co-scrub is over `JCS(registration_envelope)` (the roles
    /// column is not part of the signed bytes — matching the production
    /// admission model: role CLAIM is the column, role CONFERRAL is the
    /// re-verified co-scrub against the accord roster). Pass 2 distinct
    /// accord-holder `Identity`s (a 2-of-3 admit) as `scrubbers`, register
    /// them with [`register_accord_holder`], then read back with
    /// [`crate::federation::admission::has_effective_role_over_roster`] over
    /// their key_ids.
    pub fn signed_canonical_record_with_roles(
        key_id: &str,
        identity_type: &str,
        roles: Vec<String>,
        envelope: serde_json::Value,
        scrubbers: &[&Identity],
    ) -> crate::federation::types::KeyRecord {
        let mut rec = signed_canonical_record(key_id, identity_type, envelope, scrubbers);
        rec.roles = roles;
        rec
    }

    /// v18.3.0 (CIRISPersist#484) — register `holder`'s PINNED hybrid
    /// pubkeys as a directory row so the accord roster resolves to keys the
    /// co-scrub can be verified against. `node` identity_type (not
    /// `accord_holder`) so it skips the hardware-signer gate — the roster
    /// resolution in `verify_accord_family_coscrub` only needs the pubkeys,
    /// not the HW attestation. The exported analogue of admission's
    /// previously-private `register_founder`.
    pub async fn register_accord_holder(
        directory: &dyn crate::federation::FederationDirectory,
        holder: &Identity,
    ) -> Result<(), crate::federation::Error> {
        use sha2::{Digest, Sha256};
        let m = holder.member();
        let registration_envelope = json!({ "key_id": holder.key_id });
        // v21.14.0 (CIRISPersist#534) — self-scrub the holder registration for
        // real: canonicalize the envelope, hash it to a VALID-HEX
        // `original_content_hash`, and sign those exact bytes with the holder's
        // own hybrid key. The pre-#534 placeholders (`original_content_hash =
        // "test-anchor"`, `scrub_signature_classical = "AA"`) are NON-HEX /
        // NON-BASE64 and the SQLite backend hex/base64-decodes both columns on
        // `put_public_key` — so the holder never landed on sqlite (blocker 1),
        // which then starved roster resolution to 0 valid co-scrubs (blocker 2).
        // MemoryBackend tolerated the placeholders, which is why this crate's
        // own helper test only ever ran on memory (the #518 "tested on one
        // backend, used on the other" shape). A real self-scrub round-trips on
        // every backend.
        let bytes = crate::verify::canonical::ceg_produce_canonicalize(&registration_envelope)
            .expect("canonicalize holder registration envelope");
        let (ed, pqc) = holder.sign_bytes(&bytes);
        let rec = crate::federation::types::KeyRecord {
            key_id: holder.key_id.clone(),
            pubkey_ed25519_base64: m.ed25519_public_key_base64,
            pubkey_ml_dsa_65_base64: m.mldsa65_public_key_base64,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: crate::federation::types::identity_type::NODE.to_owned(),
            identity_ref: holder.key_id.clone(),
            valid_from: chrono::Utc::now(),
            valid_until: None,
            registration_envelope,
            original_content_hash: hex::encode(Sha256::digest(&bytes)),
            scrub_signature_classical: ed,
            scrub_signature_pqc: Some(pqc),
            scrub_key_id: holder.key_id.clone(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        // persist_row_hash is (re)computed by the backend on write (parity
        // with admission's private `register_founder`, which left it empty).
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record: rec })
            .await
    }

    /// v21.14.0 (CIRISPersist#534) — the ONE backend-agnostic conferral
    /// primitive: stand up a fresh 2-of-3 accord family, register its pinned
    /// pubkeys, and write a `key_id` canonical record whose `roles` are
    /// genuinely co-scrubbed by two distinct holders — so
    /// [`crate::federation::admission::has_effective_role_over_roster`] (over
    /// the returned roster) reads the conferred roles TRUE on any backend
    /// (sqlite / postgres / memory).
    ///
    /// This is the honest path the `InfraAttestRoleNotAccordConferred` gate
    /// demands — it does the real m-of-n dance, it does NOT bypass conferral.
    /// Consumers building an in-process round test (agent-shaped → canonical-
    /// shaped, real engines/bridges, no docker) call this instead of
    /// reassembling an accord family by hand (which every consumer got subtly
    /// wrong — CIRISPersist#534). Returns the holder roster (their `key_id`s)
    /// to pass to `has_effective_role_over_roster` / admission.
    ///
    /// The `family_tag` scopes the generated holder ids so repeated calls (and
    /// a shared postgres test DB) do not collide.
    ///
    /// # `infra:attest` vs `infra:serve` — the FIPS-custody caveat (CIRISPersist#536)
    ///
    /// This helper confers via the roster-co-scrub core, which is exactly what
    /// `infra:attest` needs. **`infra:serve` is stricter**: its admission runs
    /// the m-of-n with `require_fips_custody = true` (CIRISPersist#513), and the
    /// roster resolves from
    /// [`accord_holder_roster_key_ids`](crate::federation::admission) —
    /// the GENESIS holders — **never from the holders this helper mints**. So a
    /// software-signed `infra:serve` conferral only verifies under test-anchor
    /// **Mode A** (`CIRIS_TESTING_MODE=true` + `CIRIS_TEST_TRUST_ROOT*`
    /// publishing the genesis holders' pubkeys). Without that, the co-scrub is
    /// checked against genesis pubkeys the minted holders do not hold and the
    /// failure surfaces as an opaque `insufficient distinct valid signatures:
    /// 0 < threshold 2`. If you are standing up a TRUST ROOT (the `infra:serve`
    /// SCOPE in a `delegates_to` charter, a different plane from the key ROLE),
    /// use [`establish_trust_root`] instead — it needs none of this.
    pub async fn confer_roles(
        directory: &dyn crate::federation::FederationDirectory,
        key_id: &str,
        roles: &[&str],
        family_tag: &str,
    ) -> Result<Vec<String>, crate::federation::Error> {
        let holders = [
            Identity::new(&format!("{family_tag}-h0")),
            Identity::new(&format!("{family_tag}-h1")),
            Identity::new(&format!("{family_tag}-h2")),
        ];
        for h in &holders {
            register_accord_holder(directory, h).await?;
        }
        let roster: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();
        let record = signed_canonical_record_with_roles(
            key_id,
            crate::federation::types::identity_type::NODE,
            roles.iter().map(|r| (*r).to_owned()).collect(),
            json!({ "key_id": key_id, "conferred_by": family_tag }),
            &[&holders[0], &holders[1]],
        );
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record })
            .await?;
        Ok(roster)
    }

    /// v21.15.0 (CIRISPersist#536) — register `key_id` with a chosen
    /// `identity_type` and its deterministic hybrid pubkeys (the pair
    /// [`crate::federation::tier_ingest::test_support::sign_envelope`] signs
    /// with), so a federation-tier row this identity attests hybrid-verifies at
    /// the ingest gate on every backend. The placeholder scrub columns are
    /// valid-hex / valid-base64 (unlike the pre-#534 `test-anchor`), so the
    /// KeyRecord itself round-trips through sqlite/postgres column decoding.
    async fn register_typed_key(
        directory: &dyn crate::federation::FederationDirectory,
        key_id: &str,
        identity_type: &str,
    ) -> Result<(), crate::federation::Error> {
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        let now = chrono::Utc::now();
        // An `accord_holder` registration hits the #513 hardware-attestation
        // gate on sqlite/postgres (MemoryBackend skips it — the #534/#536 trap
        // again). Supply the established mock Android-StrongBox evidence with a
        // FRESH nonce: the gate validates shape + freshness (≤24h), not a real
        // cert chain, so this is the accepted test path for standing up an
        // accord_holder on every backend.
        let attestation_evidence = (identity_type
            == crate::federation::types::identity_type::ACCORD_HOLDER)
            .then(|| strongbox_evidence(now));
        let rec = crate::federation::types::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: json!({ "id": key_id }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record: rec })
            .await
    }

    /// The established mock Android-StrongBox `attestation_evidence` value the
    /// #513 hardware-attestation gate accepts in test builds (shape + a fresh
    /// `nonce_captured_at`; the cert chain is not cryptographically walked
    /// here). Mirrors the sqlite backend's own `android_strongbox_evidence_value`
    /// test fixture — the ONE shape that lets an `accord_holder` register
    /// without real hardware.
    fn strongbox_evidence(captured_at: chrono::DateTime<chrono::Utc>) -> serde_json::Value {
        json!({
            "platform_attestation": {
                "Android": {
                    "key_attestation_chain": [
                        vec![0x30u8, 0x82, 0x01, 0x00],
                        vec![0x30u8, 0x82, 0x02, 0x00],
                    ],
                    "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                    "strongbox_backed": true,
                }
            },
            "nonce_captured_at": captured_at.to_rfc3339(),
        })
    }

    /// v21.15.0 (CIRISPersist#536) — a federation-tier [`Attestation`] REALLY
    /// signed by `attester`'s deterministic hybrid key (via `sign_envelope`),
    /// so it passes the federation-tier ingest hybrid-verify on sqlite/postgres
    /// (not just MemoryBackend). The graph-shaped counterpart to
    /// [`signed_canonical_record`] (which builds a `KeyRecord`); the trust-root
    /// legs are `delegates_to` / `scores` rows, not key records.
    fn signed_trust_attestation(
        id: &str,
        attester: &str,
        attested: &str,
        attestation_type: &str,
        envelope: serde_json::Value,
    ) -> crate::federation::Attestation {
        // Signed by the attester's OWN deterministic key (the synthetic case).
        signed_trust_attestation_signed_by(
            id,
            attester,
            attested,
            attestation_type,
            envelope,
            attester,
        )
    }

    /// v21.16.0 (CIRISPersist#536 follow-up) — like [`signed_trust_attestation`]
    /// but signs with `signing_key_id`'s key while stamping `attester` as the
    /// `attesting_key_id` / `scrub_key_id`. Models a REAL engine-backed user
    /// whose registered pubkey is `hybrid_pubkeys(signing_key_id)`, NOT the
    /// deterministic `hybrid_pubkeys(attester)` — so its OWN signer produces an
    /// edge that hybrid-verifies while `sign_envelope(attester)` would not.
    fn signed_trust_attestation_signed_by(
        id: &str,
        attester: &str,
        attested: &str,
        attestation_type: &str,
        envelope: serde_json::Value,
        signing_key_id: &str,
    ) -> crate::federation::Attestation {
        let (och, sc, sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(signing_key_id, &envelope);
        let now = chrono::Utc::now();
        crate::federation::Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: attester.to_owned(),
            attested_key_id: attested.to_owned(),
            attestation_type: attestation_type.to_owned(),
            weight: Some(1.0),
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: sc,
            scrub_signature_pqc: sp,
            scrub_key_id: attester.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
        }
    }

    /// v21.15.0 (CIRISPersist#536) — the ONE scope-granting edge: a live
    /// `delegates_to(root → subject)` carrying `scope` (e.g. `infra:serve`),
    /// really signed by `root`. The capability half the
    /// [`crate::federation::trust_root::capability_roots_to_trusted_root`] walk
    /// resolves. Split out (per the issue) so a consumer can grant additional
    /// scopes off an already-established root without re-standing the four legs.
    /// `root` must already be registered (by [`establish_trust_root`] or the
    /// caller); `subject` must already be registered (the caller's recipient).
    pub async fn grant_scope(
        directory: &dyn crate::federation::FederationDirectory,
        root_key_id: &str,
        subject_key_id: &str,
        scope: &str,
    ) -> Result<(), crate::federation::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let edge = signed_trust_attestation(
            &id,
            root_key_id,
            subject_key_id,
            crate::federation::types::attestation_type::DELEGATES_TO,
            json!({ "references_attestation_id": id, "scope": [scope] }),
        );
        directory
            .put_attestation(crate::federation::SignedAttestation { attestation: edge })
            .await
    }

    /// v21.15.0 (CIRISPersist#536) — the leg-B counterpart to [`confer_roles`]:
    /// stand up a genuinely VALID trust root that
    /// [`crate::federation::trust_root::trust_root_valid`] accepts, with real
    /// signatures verified by the same walk production uses, on ANY backend.
    ///
    /// It writes the ROOT-SIDE legs plus the scope edge — everything signable
    /// by the helper's own synthetic actors — and best-effort the user edge:
    /// 2. `delegates_to(root → root)` carrying BOTH `infra:attest` AND
    ///    `infra:serve` AND a well-formed `pre_rotation_commitment` — the root's
    ///    self-declaration + the recovery leg (#488);
    /// 3. a fresh `accord:lifecycle:v1` `scores` row ABOUT `root`, emitted by a
    ///    helper-created `accord_holder` — **the leg a consumer cannot stand up
    ///    itself**: `accord:*` is reserved to `accord_holder` (CC 3.4.1) and a
    ///    test engine signs as itself, so the ordinary emit path cannot produce
    ///    it (CIRISPersist#536);
    /// 4. no accord halt latched for `root` (the default state — nothing to do);
    ///    plus `delegates_to(root → subject)` carrying `scope` (via [`grant_scope`]);
    /// 1. `delegates_to(user → root)` — the user's live trust edge — is
    ///    **best-effort** (see below).
    ///
    /// # SELF-ENFORCING postcondition (CIRISPersist#536 follow-up, v21.17.0)
    ///
    /// The contract of this helper is "after `Ok`, the trust walk succeeds." So
    /// it **asserts that before returning**: after standing up the legs it runs
    /// [`crate::federation::trust_root::capability_roots_to_trusted_root`]
    /// `(user, subject, scope)` and returns **`Err` if that does not succeed** —
    /// a helper whose contract is "the walk holds" must not be able to report
    /// success when it doesn't (the v21.16.0 best-effort version could, which was
    /// a fixture-contract bug).
    ///
    /// # Real vs synthetic user
    ///
    /// The root and its accord witness stay synthetic — nobody needs their
    /// private halves. The USER is the node whose serve gate you are exercising.
    /// The user's trust edge must be signed BY the user, and this helper can only
    /// sign it with the deterministic `sign_envelope(user_key_id)` derivation —
    /// correct for a **synthetic** user (whose registered pubkey IS that
    /// derivation), **wrong for a REAL engine-backed** user (whose registered
    /// pubkey is its own signing key → the edge fails federation-tier ingest).
    /// The synthetic user edge is therefore **best-effort** (skipped+logged when
    /// it won't verify). Consequently:
    /// - **synthetic user** → the synthetic edge admits, the walk succeeds, `Ok`.
    /// - **real user** → emit `delegates_to(user → root)` with the user's OWN
    ///   signer **before** calling this; the walk then succeeds and it returns
    ///   `Ok`. If you have NOT emitted it, this returns `Err` (honest — the walk
    ///   is not satisfied). Prefer [`establish_trust_root_side`] for the
    ///   real-user flow: it stands up only the root side (and asserts ITS
    ///   postcondition), leaving leg 1 to your engine, then you assert the walk.
    ///
    /// `subject_key_id` (and, for the synthetic path, `user_key_id`) must already
    /// be registered. `root_key_id` is a NEW id this helper registers. Does the
    /// whole honest dance — it does NOT bypass any gate.
    pub async fn establish_trust_root(
        directory: &dyn crate::federation::FederationDirectory,
        user_key_id: &str,
        root_key_id: &str,
        subject_key_id: &str,
        scope: &str,
    ) -> Result<(), crate::federation::Error> {
        establish_trust_root_side(directory, root_key_id, subject_key_id, scope).await?;
        // Best-effort synthetic user edge (see the type-level doc): admits for a
        // synthetic user, skipped+logged for a real one.
        try_emit_synthetic_trust_edge(directory, user_key_id, root_key_id).await;

        // POSTCONDITION — the reason this helper exists. Never return Ok unless
        // the walk it is meant to satisfy actually succeeds (CIRISPersist#536).
        let grant = crate::federation::trust_root::capability_roots_to_trusted_root(
            directory,
            user_key_id,
            subject_key_id,
            scope,
        )
        .await?;
        if grant.is_none() {
            return Err(crate::federation::Error::Backend(format!(
                "establish_trust_root postcondition NOT met: \
                 capability_roots_to_trusted_root(user={user_key_id}, subject={subject_key_id}, \
                 scope={scope}) does not succeed — leg 1 delegates_to({user_key_id} → \
                 {root_key_id}) is absent. For a REAL engine-backed user, emit that trust edge \
                 with the user's OWN signer BEFORE this call, or use establish_trust_root_side \
                 (which stands up only the root side) and assert the walk yourself."
            )));
        }
        Ok(())
    }

    /// v21.16.0 (CIRISPersist#536 follow-up) — the ROOT-SIDE legs of a valid
    /// trust root, all signable by the helper's own synthetic actors (nobody
    /// needs the root's or the accord-holder's private halves): the root
    /// self-declaration charter, the reserved `accord:lifecycle` witness, and
    /// the `delegates_to(root → subject)` scope edge. This is the part
    /// [`establish_trust_root`] does that a consumer genuinely cannot do itself
    /// (the `accord:*` reservation). The user→root TRUST edge is deliberately
    /// NOT here — for a real engine-backed user it must be emitted by the
    /// user's OWN signer (its registered pubkey is its signing key, not the
    /// deterministic `sign_envelope` derivation). Call this, then have the real
    /// user emit `delegates_to(user → root)` itself.
    pub async fn establish_trust_root_side(
        directory: &dyn crate::federation::FederationDirectory,
        root_key_id: &str,
        subject_key_id: &str,
        scope: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::trust_root::{INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE};
        use crate::federation::types::{attestation_type, identity_type};

        // The helper-controlled synthetic actors: the root and its accord witness.
        register_typed_key(directory, root_key_id, identity_type::NODE).await?;
        let la = format!("{root_key_id}-la");
        register_typed_key(directory, &la, identity_type::ACCORD_HOLDER).await?;

        // Leg 2 — the root's self-declaration charter: infra:attest AND
        // infra:serve AND a well-formed pre-rotation commitment (recovery leg).
        let charter_id = uuid::Uuid::new_v4().to_string();
        let successors = vec![
            format!("{root_key_id}-succ-a"),
            format!("{root_key_id}-succ-b"),
        ];
        let commitment = crate::federation::trust_root::pre_rotation_commitment(&successors)
            .map_err(|e| {
                crate::federation::Error::Backend(format!(
                    "establish_trust_root pre_rotation_commitment: {e}"
                ))
            })?;
        let charter = signed_trust_attestation(
            &charter_id,
            root_key_id,
            root_key_id,
            attestation_type::DELEGATES_TO,
            json!({
                "references_attestation_id": charter_id,
                "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
                "pre_rotation_commitment": commitment,
            }),
        );
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: charter,
            })
            .await?;

        // Leg 3 — the fresh accord:lifecycle row ABOUT the root, from the
        // accord_holder (the reserved-family leg a consumer cannot produce).
        let lc_id = uuid::Uuid::new_v4().to_string();
        let lifecycle = signed_trust_attestation(
            &lc_id,
            &la,
            root_key_id,
            attestation_type::SCORES,
            json!({
                "id": lc_id,
                "dimension": crate::federation::trust_root::ACCORD_LIFECYCLE_DIMENSION,
                "score": 1.0,
                "confidence": 0.9,
            }),
        );
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: lifecycle,
            })
            .await?;

        // Leg 4 — no halt latched (default). Plus the scope-carrying edge.
        grant_scope(directory, root_key_id, subject_key_id, scope).await?;

        // POSTCONDITION (CIRISPersist#536) — the root side is GENUINELY up: the
        // root self-declares AND its accord:lifecycle is live/fresh. (edge_exists
        // is legitimately false here — leg 1 is the caller's to emit — so we
        // probe the root-only legs with a throwaway user id.) A helper that
        // returns Ok must have actually done what it claims.
        let probe = crate::federation::trust_root::trust_root_valid(
            directory,
            "__side_probe__",
            root_key_id,
        )
        .await?;
        if !(probe.root_self_declares && probe.lifecycle_active) {
            return Err(crate::federation::Error::Backend(format!(
                "establish_trust_root_side postcondition NOT met for root={root_key_id}: \
                 root_self_declares={} lifecycle_active={} — the charter or accord:lifecycle did \
                 not admit",
                probe.root_self_declares, probe.lifecycle_active
            )));
        }
        Ok(())
    }

    /// v21.16.0 (CIRISPersist#536 follow-up) — emit `delegates_to(user → root)`
    /// signed with the user's DETERMINISTIC `sign_envelope` key. Correct ONLY
    /// for a synthetic user (whose registered pubkey IS that derivation); for a
    /// real engine-backed user the federation-tier ingest hybrid-verify fails
    /// (`FederationTierUnverified` — the derived key ≠ the node's real signing
    /// key). Best-effort by design: on that failure it logs and returns, and
    /// the real user's own signer is expected to emit the honest edge.
    async fn try_emit_synthetic_trust_edge(
        directory: &dyn crate::federation::FederationDirectory,
        user_key_id: &str,
        root_key_id: &str,
    ) {
        use crate::federation::trust_root::{INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE};
        use crate::federation::types::attestation_type;
        let edge_id = uuid::Uuid::new_v4().to_string();
        let edge = signed_trust_attestation(
            &edge_id,
            user_key_id,
            root_key_id,
            attestation_type::DELEGATES_TO,
            json!({
                "references_attestation_id": edge_id,
                "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            }),
        );
        if let Err(e) = directory
            .put_attestation(crate::federation::SignedAttestation { attestation: edge })
            .await
        {
            tracing::info!(
                user = %user_key_id, root = %root_key_id, error = %e,
                "establish_trust_root: synthetic user→root trust edge not admitted (expected for a \
                 REAL engine-backed user whose registered pubkey is its own signing key). The \
                 caller must emit delegates_to(user → root) with the user's OWN signer — see \
                 establish_trust_root_side (CIRISPersist#536)."
            );
        }
    }

    /// v21.14.0 (CIRISPersist#534) — the BACKEND-AGNOSTIC conferral parity
    /// body: prove [`confer_roles`] confers `infra:serve` for real, and that a
    /// self-scrubbed (out-of-roster) claim does NOT confer, over an arbitrary
    /// [`crate::federation::FederationDirectory`]. Called from the memory,
    /// sqlite AND postgres backend tests so the "tested on one backend, used on
    /// the other" gap (CIRISPersist#534, the #518 shape) cannot reopen: the
    /// holder registration + co-scrub now round-trip through whatever column
    /// encoding each backend applies (the `test-anchor` placeholder that only
    /// MemoryBackend tolerated is gone). `tag` scopes the generated ids so a
    /// shared postgres DB does not collide across runs.
    pub async fn exercise_role_conferral(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::admission::has_effective_role_over_roster;

        let canon = format!("{tag}-canon");
        // ALLOW: the honest 2-of-3 dance confers infra:serve.
        let roster = confer_roles(directory, &canon, &["infra:serve"], tag)
            .await
            .expect("confer_roles admits the co-scrubbed canonical");
        assert!(
            has_effective_role_over_roster(directory, &canon, "infra:serve", &roster)
                .await
                .expect("has_effective_role read"),
            "({tag}) genuinely accord-conferred infra:serve reads TRUE on this backend"
        );

        // DENY: same role CLAIM, but scrubbed only by an out-of-roster
        // identity → not conferred (the never-self-claimed monotonic property).
        // The scrubber is REGISTERED (so its `scrub_key_id` FK resolves — sqlite
        // enforces that constraint, MemoryBackend does not; leaning on the FK-
        // free backend is the same #518/#534 one-backend-tested trap this whole
        // fix closes), but it is deliberately NOT in `roster`, so its scrub
        // counts toward nothing.
        let self_id = format!("{tag}-canon-self");
        let self_scrubber = Identity::new(&format!("{tag}-selfscrub"));
        register_accord_holder(directory, &self_scrubber)
            .await
            .expect("register the out-of-roster scrubber (FK satisfied, roster excluded)");
        let self_only = signed_canonical_record_with_roles(
            &self_id,
            crate::federation::types::identity_type::NODE,
            vec!["infra:serve".to_owned()],
            json!({ "key_id": self_id }),
            &[&self_scrubber],
        );
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record: self_only })
            .await
            .expect("self-scrubbed record still stores");
        assert!(
            !has_effective_role_over_roster(directory, &self_id, "infra:serve", &roster)
                .await
                .expect("has_effective_role read"),
            "({tag}) self-asserted infra:serve with no accord co-scrub reads FALSE"
        );
    }

    /// v21.15.0 (CIRISPersist#536) — the backend-agnostic TRUST-ROOT parity
    /// body: prove [`establish_trust_root`] stands up a root that
    /// [`crate::federation::trust_root::trust_root_valid`] accepts (all four
    /// legs) AND that the subject's `infra:serve` roots to it via
    /// [`crate::federation::trust_root::capability_roots_to_trusted_root`] (leg
    /// B). Run from the memory, sqlite AND postgres backend tests — the leg 3
    /// (`accord:lifecycle`) reserved-family emission and the federation-tier
    /// hybrid-verify of every leg must round-trip on each backend, not just the
    /// tolerant one (the #534/#536 discipline).
    pub async fn exercise_trust_root(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::trust_root::{
            capability_roots_to_trusted_root, trust_root_valid, INFRA_SERVE_SCOPE,
        };
        use crate::federation::types::identity_type;

        let user = format!("{tag}-user");
        let root = format!("{tag}-root");
        let subject = format!("{tag}-subject");

        // The caller's own actors — registered with the deterministic test key
        // so the edges they attest hybrid-verify (the round-test engines do
        // this via register_self; here we do it explicitly).
        register_typed_key(directory, &user, identity_type::NODE)
            .await
            .expect("register user");
        register_typed_key(directory, &subject, identity_type::NODE)
            .await
            .expect("register subject");

        establish_trust_root(directory, &user, &root, &subject, INFRA_SERVE_SCOPE)
            .await
            .expect("establish_trust_root stands up all four legs + the scope edge");

        let v = trust_root_valid(directory, &user, &root)
            .await
            .expect("trust_root_valid walk");
        assert!(
            v.valid,
            "({tag}) establish_trust_root ⇒ trust_root_valid: {v:?}"
        );

        // Leg B: the subject's infra:serve roots to a root THIS user trusts.
        let grant = capability_roots_to_trusted_root(directory, &user, &subject, INFRA_SERVE_SCOPE)
            .await
            .expect("capability walk")
            .unwrap_or_else(|| {
                panic!("({tag}) subject's infra:serve must root to the trusted root")
            });
        assert_eq!(
            grant.root_key_id, root,
            "({tag}) the winning root is the one we established"
        );
    }

    /// v21.17.0 (CIRISPersist#536 follow-up) — the REAL engine-backed user path,
    /// and the HONEST CONTRACT. `user` is registered with its OWN signing key
    /// (NOT the deterministic `sign_envelope(user)` derivation), as a real node
    /// is. Proves two things:
    /// - **(A) no lying**: the full [`establish_trust_root`] returns `Err` for a
    ///   real user with no pre-emitted edge — its synthetic edge is skipped (not
    ///   forged), the walk it promises is NOT satisfied, so it does NOT return
    ///   `Ok`. The root side WAS stood up (the legs run before the postcondition).
    /// - **(B) the real-user flow works**: [`establish_trust_root_side`] stands up
    ///   the root side (asserting its own postcondition), the user's OWN signer
    ///   emits the honest `delegates_to(user → root)`, and then `trust_root_valid`
    ///   + the capability walk go green.
    /// Backend-agnostic (memory/sqlite/postgres).
    pub async fn exercise_trust_root_real_user(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::trust_root::{
            capability_roots_to_trusted_root, trust_root_valid, INFRA_ATTEST_SCOPE,
            INFRA_SERVE_SCOPE,
        };
        use crate::federation::types::{attestation_type, identity_type};

        let user = format!("{tag}-user");
        let user_real_key = format!("{tag}-userREAL"); // the user's true signing key
        let subject = format!("{tag}-subject");

        // `user` registered carrying the pubkeys of `user_real_key` — its
        // registered pubkey IS its own signing key, NOT hybrid_pubkeys(user).
        crate::federation::tier_ingest::test_support::register_hybrid_key_aliased(
            directory,
            &user,
            &user_real_key,
        )
        .await;
        register_typed_key(directory, &subject, identity_type::NODE)
            .await
            .expect("register subject");

        // ── (A) HONEST FAILURE — the full helper does NOT claim success. ──
        let root_a = format!("{tag}-rootA");
        let err = establish_trust_root(directory, &user, &root_a, &subject, INFRA_SERVE_SCOPE)
            .await
            .expect_err("({tag}) full helper must Err for a real user with no pre-emitted edge");
        assert!(
            err.to_string().contains("postcondition NOT met"),
            "({tag}) the Err names the unmet postcondition: {err}"
        );
        // …yet the root side WAS stood up (legs precede the postcondition check),
        // and the synthetic edge was skipped (not forged).
        let va = trust_root_valid(directory, &user, &root_a)
            .await
            .expect("walk A");
        assert!(
            !va.edge_exists && va.root_self_declares && va.lifecycle_active,
            "({tag}) root side up + synthetic edge skipped (not forged): {va:?}"
        );

        // ── (B) THE REAL-USER FLOW — root side, then the user's own edge. ──
        let root_b = format!("{tag}-rootB");
        establish_trust_root_side(directory, &root_b, &subject, INFRA_SERVE_SCOPE)
            .await
            .expect("({tag}) establish_trust_root_side stands up + asserts the root side");
        let vb0 = trust_root_valid(directory, &user, &root_b)
            .await
            .expect("walk B0");
        assert!(
            !vb0.valid && vb0.root_self_declares && vb0.lifecycle_active && !vb0.edge_exists,
            "({tag}) root side up, not yet valid without the user's edge: {vb0:?}"
        );

        // The real user emits its OWN honest trust edge, signed by its real key.
        let edge_id = uuid::Uuid::new_v4().to_string();
        let honest_edge = signed_trust_attestation_signed_by(
            &edge_id,
            &user,
            &root_b,
            attestation_type::DELEGATES_TO,
            json!({
                "references_attestation_id": edge_id,
                "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            }),
            &user_real_key,
        );
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: honest_edge,
            })
            .await
            .expect("({tag}) the real user's own-signed trust edge hybrid-verifies + admits");

        let vb1 = trust_root_valid(directory, &user, &root_b)
            .await
            .expect("walk B1");
        assert!(
            vb1.valid,
            "({tag}) valid once the real user emits its own edge: {vb1:?}"
        );
        let grant = capability_roots_to_trusted_root(directory, &user, &subject, INFRA_SERVE_SCOPE)
            .await
            .expect("cap walk")
            .unwrap_or_else(|| {
                panic!("({tag}) subject infra:serve roots to the real-user-trusted root")
            });
        assert_eq!(grant.root_key_id, root_b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn t(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    fn org(id: &str, asserted: i64, status: &str, withdrawn: bool) -> Organization {
        Organization {
            attestation_id: id.into(),
            org_id: "org-x".into(),
            name: "Acme".into(),
            org_type: "partner".into(),
            parent_org_id: None,
            partner_id: None,
            status: status.into(),
            asserted_at: t(asserted),
            valid_until: None,
            attesting_key_id: "k".into(),
            signed_envelope: json!({}),
            ed25519_signature_base64: "x".into(),
            mldsa65_signature_base64: None,
            withdrawn_at: withdrawn.then(|| t(asserted)),
            persist_row_hash: String::new(),
        }
    }

    fn partner(id: &str, rev: u64, status: &str, asserted: i64) -> PartnerRecord {
        PartnerRecord {
            attestation_id: id.into(),
            license_id: "lic-1".into(),
            partner_id: "p1".into(),
            org_id: "org-x".into(),
            license_type: "professional_full".into(),
            max_autonomy_tier: "A2".into(),
            requires_supervisor: false,
            deployment_limit: 10,
            offline_grace_hours: 24,
            status: status.into(),
            revision: rev,
            issued_at: t(0),
            expires_at: t(1_000_000),
            asserted_at: t(asserted),
            signed_envelope: json!({}),
            withdrawn_at: None,
            persist_row_hash: String::new(),
        }
    }

    // ── subject_kind / merge intent declaration ─────────────────────

    #[test]
    fn merge_intents_are_declared_per_subject_kind() {
        assert_eq!(
            SubjectKind::Organization.merge_intent(),
            MergeIntent::LwwSkewBounded
        );
        assert_eq!(
            SubjectKind::OrgMembership.merge_intent(),
            MergeIntent::LwwSkewBounded
        );
        assert_eq!(
            SubjectKind::PartnerRecord.merge_intent(),
            MergeIntent::MonotonicQuorum
        );
        assert_eq!(SubjectKind::Organization.as_str(), "organization");
        assert_eq!(SubjectKind::OrgMembership.as_str(), "org_membership");
        assert_eq!(SubjectKind::PartnerRecord.as_str(), "partner_record");
    }

    // ── skew bound ──────────────────────────────────────────────────

    #[test]
    fn skew_bound_accepts_within_tolerance() {
        let now = t(0);
        // exactly at the edge (now + 5min) is accepted (> is the reject).
        assert!(check_skew_bound(now + Duration::minutes(5), now).is_ok());
        assert!(check_skew_bound(now - Duration::hours(1), now).is_ok());
    }

    #[test]
    fn skew_bound_rejects_future_dated() {
        let now = t(0);
        let err = check_skew_bound(now + Duration::minutes(6), now).unwrap_err();
        assert_eq!(err.kind(), "federation_clock_skew_violation");
    }

    // ── payment-processor reject ────────────────────────────────────

    #[test]
    fn payment_processor_ids_rejected_anywhere() {
        // top-level value
        assert!(reject_payment_processor_identifiers(&json!({
            "billing_ref": "cus_ABC123"
        }))
        .is_err());
        // nested in an open-vocab object
        assert!(reject_payment_processor_identifiers(&json!({
            "metadata": {"note": "sub_9xKpQ"}
        }))
        .is_err());
        // inside an array
        assert!(reject_payment_processor_identifiers(&json!({
            "refs": ["ok", "ch_1ABC"]
        }))
        .is_err());
        // as an object KEY
        assert!(reject_payment_processor_identifiers(&json!({
            "pi_3xyz": "value"
        }))
        .is_err());
    }

    #[test]
    fn clean_envelope_passes_payment_check() {
        assert!(reject_payment_processor_identifiers(&json!({
            "org_id": "org-x",
            "name": "Acme",
            "capabilities_granted": ["billing.read", "identity.read"],
        }))
        .is_ok());
        // bare prefix with no suffix is not a real id (e.g. the word
        // "card_" alone) — len > prefix.len() guards this.
        assert!(reject_payment_processor_identifiers(&json!({"x": "cus_"})).is_ok());
    }

    // ── LWW + withdrawal-forward-only ───────────────────────────────

    #[test]
    fn lww_latest_asserted_at_wins() {
        let rows = vec![org("a", 0, "active", false), org("b", 60, "active", false)];
        assert_eq!(resolve_lww(&rows).unwrap().attestation_id, "b");
    }

    #[test]
    fn lww_tie_break_smallest_attestation_id() {
        let rows = vec![
            org("zzz", 0, "active", false),
            org("aaa", 0, "active", false),
            org("mmm", 0, "active", false),
        ];
        assert_eq!(resolve_lww(&rows).unwrap().attestation_id, "aaa");
    }

    #[test]
    fn withdrawal_is_forward_only_no_resurrect() {
        // A withdrawn row exists; a LATER non-withdrawn write must NOT
        // resurrect the id.
        let rows = vec![
            org("a", 0, "active", false),
            org("b", 60, "active", true),   // withdrawn
            org("c", 120, "active", false), // later, but cannot resurrect
        ];
        assert!(resolve_lww(&rows).is_none());
    }

    #[test]
    fn deactivated_status_is_a_withdrawal() {
        let rows = vec![
            org("a", 0, "active", false),
            org("b", 60, "deactivated", false),
        ];
        assert!(resolve_lww(&rows).is_none());
    }

    #[test]
    fn lww_converges_under_out_of_order_arrival() {
        // The winner is a function of the SET, not arrival order — the
        // partition-tolerance property. Two orderings, same answer.
        let forward = vec![
            org("a", 0, "active", false),
            org("b", 60, "active", false),
            org("c", 120, "active", false),
        ];
        let reversed = vec![
            org("c", 120, "active", false),
            org("b", 60, "active", false),
            org("a", 0, "active", false),
        ];
        assert_eq!(
            resolve_lww(&forward).unwrap().attestation_id,
            resolve_lww(&reversed).unwrap().attestation_id
        );
        assert_eq!(resolve_lww(&forward).unwrap().attestation_id, "c");
    }

    #[test]
    fn lww_empty_group_is_none() {
        let rows: Vec<Organization> = vec![];
        assert!(resolve_lww(&rows).is_none());
    }

    // ── monotonic_quorum ────────────────────────────────────────────

    #[test]
    fn monotonic_highest_revision_wins() {
        let rows = vec![
            partner("a", 1, "active", 100),
            partner("b", 3, "active", 0),
            partner("c", 2, "active", 200),
        ];
        assert_eq!(resolve_monotonic_quorum(&rows).unwrap().attestation_id, "b");
    }

    #[test]
    fn monotonic_revoked_beats_active_at_same_revision() {
        let rows = vec![
            partner("a", 5, "active", 100),
            partner("b", 5, "revoked", 0),
        ];
        // revoked > active on conflict, even though active is later.
        assert_eq!(resolve_monotonic_quorum(&rows).unwrap().attestation_id, "b");
    }

    #[test]
    fn monotonic_status_rank_order() {
        assert!(partner_status_rank("revoked") > partner_status_rank("suspended"));
        assert!(partner_status_rank("suspended") > partner_status_rank("active"));
        assert_eq!(partner_status_rank("garbage"), 0);
    }

    #[test]
    fn monotonic_converges_under_out_of_order_arrival() {
        let forward = vec![
            partner("a", 1, "active", 0),
            partner("b", 2, "suspended", 60),
            partner("c", 3, "revoked", 120),
        ];
        let reversed = vec![
            partner("c", 3, "revoked", 120),
            partner("a", 1, "active", 0),
            partner("b", 2, "suspended", 60),
        ];
        assert_eq!(
            resolve_monotonic_quorum(&forward).unwrap().attestation_id,
            resolve_monotonic_quorum(&reversed).unwrap().attestation_id
        );
        assert_eq!(
            resolve_monotonic_quorum(&forward).unwrap().attestation_id,
            "c"
        );
    }

    #[test]
    fn partner_record_set_fields_are_sorted() {
        // The constant itself must be sorted (it's the canonical field
        // list fed to check_set_semantics_sorted).
        let mut sorted = PARTNER_RECORD_SET_FIELDS.to_vec();
        sorted.sort_unstable();
        assert_eq!(PARTNER_RECORD_SET_FIELDS, sorted.as_slice());
    }
}
