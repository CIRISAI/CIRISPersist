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
//! # The admission checks (RC2 §5.6.8.13 / §10.1.6)
//!
//! Every `put_*` runs, in order:
//!
//! 0. **Authorship + envelope binding** (v31.0.0, CIRISPersist#644) —
//!    [`verify_organization_admission`] /
//!    [`verify_org_membership_admission`] hybrid-Strict verify the row's
//!    OWN signature against `attesting_key_id`'s REGISTERED pubkeys, and
//!    [`check_organization_binding`] /
//!    [`check_org_membership_binding`] /
//!    [`check_partner_record_binding`] refuse any typed column that
//!    disagrees with the envelope the signature (or the M-of-N steward
//!    quorum) actually covers.
//!
//!    These planes are **producer envelope + typed projection**: unlike
//!    [`super::types::Family`], whose `signing_envelope()` synthesizes the
//!    signed bytes from the struct so divergence cannot be represented,
//!    the producer here hands persist an envelope AND a projection of it.
//!    Everything below decides on the projection — so without check 0 the
//!    `withdrawn_at` tombstone, `status`, `role`, the `asserted_at` LWW
//!    key and the `partner_record` `revision` counter were authored by
//!    whoever wrote the row rather than by whoever signed it.
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
    let all = directory
        .list_keys_by_identity_type(crate::federation::types::identity_type::STEWARD)
        .await
        .map_err(|e| Error::OperationalAuthority(format!("steward roster resolve: {e}")))?;
    // v38.0.0 (CIRISPersist#709) — **the roster is the SEATED stewards, not
    // every steward-shaped row ever accumulated.** The quorum denominator
    // (`founder_n` in `check_partner_set_and_quorum`) is computed over this
    // list while M is signed into the envelope and frozen at mint — so a
    // roster that only ever grows makes the same signed bytes admit on a
    // fresh node and refuse on a synced one, with no repair short of a new
    // ceremony. Two liveness facts fold here, both from persist's own
    // verified state: the validity window on the registered row, and the
    // revocation plane (a revoked steward is not seated; revocations are
    // admitted through their own anti-rollback door and never leave).
    //
    // NOT folded here — recorded, not hidden: `identity_type = "steward"` is
    // itself a self-asserted string (its ConferralMode row's "every use site
    // re-derives from verified state" is TRUE of the custody steward-BINDING
    // walk and FALSE of this org-authority roster — two axes under one word).
    // Bounding the roster to conferral-seated stewards needs the seating
    // ceremony DESIGNATED (registration co-scrub à la #607's WITNESS move,
    // or a steward-body family per `ownership_reclaim::wa_quorum_over_body`)
    // — tracked on #709, which stays open for exactly that decision.
    let now = chrono::Utc::now();
    let mut stewards = Vec::with_capacity(all.len());
    for k in all {
        if k.valid_from > now {
            continue;
        }
        if k.valid_until.is_some_and(|u| u <= now) {
            continue;
        }
        let revocations = directory
            .revocations_for(&k.key_id)
            .await
            .map_err(|e| Error::OperationalAuthority(format!("steward revocation fold: {e}")))?;
        if !revocations.is_empty() {
            continue;
        }
        stewards.push(k);
    }
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
/// # v31.0.0 (CIRISPersist#659) — `threshold` HAS A FLOOR, AND IS SIGNED
///
/// `threshold` is the M of the M-of-N, and it arrived **caller-supplied and
/// outside the signature**. Two independent holes:
///
/// 1. **No floor.** [`ciris_verify_core::threshold::verify_founder_quorum`],
///    which this path routes through, rejects only `M == 0` and `M > N`.
///    [`verify_quorum_policy`](ciris_verify_core::threshold::verify_quorum_policy)
///    — the function that enforces the federation's one quorum rule, a strict
///    majority `2M > N` — is NOT on this path. So `threshold: 1` admitted a
///    licence grant carrying `capabilities_granted` and `max_autonomy_tier` on
///    ONE steward signature, contradicting this repo's own recorded invariant
///    (see [`crate::federation::reverse_quorum`]: *m-of-n OR reverse quorum,
///    never 1-of-N capability-grant*). Every sibling m-of-n door in this crate
///    already floors M at a strict majority; this one did not.
/// 2. **Unsigned.** `threshold` lives on the WRAPPER, not on the record, so it
///    was not covered by the quorum's own bytes and not covered by
///    [`check_partner_record_binding`] either. A relay could therefore rewrite
///    a `3` into a `1` in transit and the three stewards' signatures stayed
///    valid — a floor alone would not have closed that, because the number the
///    floor is applied to was the attacker's.
///
/// Both halves are fixed together and in this cut. Enforcing the floor is a
/// pure tightening for a conformant producer; BINDING it is a preimage change,
/// and v31.0.0 already forces the mesh-wide re-mint that pays for it. One
/// release later this would mean re-collecting M steward signatures across
/// organizations in a second ceremony against a live federation.
///
/// The floor is `QuorumPolicy::validate` itself — the SAME rule
/// `verify_quorum_policy` applies — rather than `2 * m > n` re-spelled here,
/// so persist never grows a second copy of the majority arithmetic. `N` is the
/// **founder subset** of the roster, because that is the set
/// `verify_founder_quorum` actually counts against.
///
/// # Errors
/// [`Error::SetSemanticsUnsorted`] or [`Error::OperationalAuthority`].
pub fn check_partner_set_and_quorum(
    signed: &SignedPartnerRecord,
    steward_roster: &[ciris_verify_core::threshold::ThresholdMember],
) -> Result<(), Error> {
    // v31.0.0 (CIRISPersist#644) — bind the typed projection FIRST. The
    // quorum below proves M stewards signed `signed_envelope`; it proves
    // nothing about the columns beside it, and `revision` — the anti-
    // rollback counter and the first key of the `monotonic_quorum`
    // comparator — is one of those columns. Binding lives here rather than
    // at the three put doors so no backend can be added without it.
    //
    // v31.0.0 (CIRISPersist#659) — that now includes `threshold`, which lives
    // on the WRAPPER: the number the floor below is applied to has to be a
    // number the stewards attested to, or the floor is applied to whatever the
    // relay chose.
    check_partner_record_binding(signed)?;
    ciris_verify_core::operational_admit::check_set_semantics_sorted(
        &signed.partner_record.signed_envelope,
        PARTNER_RECORD_SET_FIELDS,
    )
    .map_err(|e| Error::SetSemanticsUnsorted(e.to_string()))?;
    // v31.0.0 (CIRISPersist#659) — THE STRICT-MAJORITY FLOOR, before a single
    // signature is counted (fail-closed, "no action"). N is the founder subset
    // because that is the set `verify_founder_quorum` counts against.
    let founder_n = steward_roster
        .iter()
        .filter(|m| matches!(m.role, Some(ciris_verify_core::threshold::Role::Founder)))
        .count();
    ciris_verify_core::threshold::QuorumPolicy::new(signed.threshold, founder_n)
        .validate()
        .map_err(|e| {
            Error::OperationalAuthority(format!(
                "partner_record quorum policy {}/{founder_n} refused: {e}. A licence grant \
                 carries `capabilities_granted` and `max_autonomy_tier`, so it takes a STRICT \
                 MAJORITY of the steward roster (2M > N) — the same rule every other m-of-n door \
                 in this substrate applies, and the one this plane was missing \
                 (CIRISPersist#659)",
                signed.threshold,
            ))
        })?;
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

// ── Admission check 0: authorship + envelope binding (#644) ─────────
//
// v31.0.0 (CIRISPersist#644). Two holes, one root cause: the signature
// covers `signed_envelope` and NOTHING ELSE, but every decision the
// substrate makes reads a TYPED COLUMN beside it.
//
// (a) AUTHORSHIP. `Organization` / `OrgMembership` carried
//     `ed25519_signature_base64` / `mldsa65_signature_base64` that no code
//     path in this crate ever verified. The row's own signature was
//     STORED, never checked. `check_role_authority` verifies the
//     signatures of the *already-stored grants* it walks — that is a
//     different question (may this actor act?) from the one nobody asked
//     (did the claimed signer author THIS row?). And its steward
//     bootstrap anchor returns `Ok(())` on a bare `attesting_key_id`
//     string match, so naming a registered steward was sufficient to
//     write any org row on any of the three backends.
//
// (b) BINDING. Even a genuinely signed envelope does not defend a typed
//     column that is not derived from it. The producer hands persist an
//     envelope AND a projection; the projection is what
//     `resolve_lww` / `resolve_monotonic_quorum` / the read surface use.
//     So `withdrawn_at` (the tombstone), `status`, `role`, `asserted_at`
//     (the LWW key) and `revision` (the anti-rollback counter) were all
//     authored by whoever wrote the row, not by whoever signed it.
//
// These planes are **producer envelope + typed projection**, NOT
// row-is-the-envelope. `Family`/`Community` synthesize their signed bytes
// from the struct (`Family::signing_envelope`), so divergence there is
// unrepresentable. That shape is unavailable here for three independent
// reasons: the envelope's meaning is fixed by an EXTERNAL contract
// (`ciris_verify_core::operational_admit::MembershipGrant` parses
// `user_id`/`org_id`/`role`/`status`/`attesting_key_id` out of it);
// `PartnerRecord`'s bytes were signed by M stewards before persist ever
// saw the row, so persist cannot re-synthesize them; and RC2 §5.6.8.13
// makes the typed row a deliberately *lossy* projection of a larger
// producer record (PII is dropped), so struct and envelope are not the
// same object by design. The correct shape for that architecture is the
// other one: verify the producer's signature, then REFUSE any row whose
// projection disagrees with the bytes that were signed.
//
// Shaped on `check_instant_binding` (#598), which refuses
// exactly this divergence one plane over, in this same release.

/// v31.0.0 (CIRISPersist#644) — build the typed refusal for a projection
/// column that disagrees with the signed envelope it claims to project.
fn unbound(plane: &'static str, id: &str, field: &'static str, detail: String) -> Error {
    Error::OperationalEnvelopeUnbound {
        plane,
        attestation_id: id.to_string(),
        field,
        detail,
    }
}

/// Bind a REQUIRED string column to its signed counterpart.
fn bind_str(
    env: &Value,
    plane: &'static str,
    id: &str,
    field: &'static str,
    actual: &str,
) -> Result<(), Error> {
    match env.get(field) {
        Some(Value::String(signed)) if signed == actual => Ok(()),
        Some(Value::String(signed)) => Err(unbound(
            plane,
            id,
            field,
            format!("column is {actual:?}, the signed envelope says {signed:?}"),
        )),
        Some(_) => Err(unbound(
            plane,
            id,
            field,
            "signed envelope carries a non-string value for this field".to_string(),
        )),
        None => Err(unbound(
            plane,
            id,
            field,
            format!(
                "signed envelope carries no `{field}`, so the column is authored by \
                 whoever wrote the row rather than by whoever signed it"
            ),
        )),
    }
}

/// Bind an OPTIONAL string column: absent/null in the envelope ⇔ `None`.
fn bind_opt_str(
    env: &Value,
    plane: &'static str,
    id: &str,
    field: &'static str,
    actual: Option<&str>,
) -> Result<(), Error> {
    let signed = match env.get(field) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => {
            return Err(unbound(
                plane,
                id,
                field,
                "signed envelope carries a non-string value for this field".to_string(),
            ))
        }
    };
    if signed == actual {
        return Ok(());
    }
    Err(unbound(
        plane,
        id,
        field,
        format!("column is {actual:?}, the signed envelope says {signed:?}"),
    ))
}

/// Bind a REQUIRED unsigned-integer column to its signed counterpart.
fn bind_u64(
    env: &Value,
    plane: &'static str,
    id: &str,
    field: &'static str,
    actual: u64,
) -> Result<(), Error> {
    match env.get(field).and_then(Value::as_u64) {
        Some(signed) if signed == actual => Ok(()),
        Some(signed) => Err(unbound(
            plane,
            id,
            field,
            format!("column is {actual}, the signed envelope says {signed}"),
        )),
        None => Err(unbound(
            plane,
            id,
            field,
            format!(
                "signed envelope carries no unsigned-integer `{field}`, so the column is \
                 authored by whoever wrote the row rather than by whoever signed it"
            ),
        )),
    }
}

/// Bind a REQUIRED boolean column to its signed counterpart.
fn bind_bool(
    env: &Value,
    plane: &'static str,
    id: &str,
    field: &'static str,
    actual: bool,
) -> Result<(), Error> {
    match env.get(field).and_then(Value::as_bool) {
        Some(signed) if signed == actual => Ok(()),
        Some(signed) => Err(unbound(
            plane,
            id,
            field,
            format!("column is {actual}, the signed envelope says {signed}"),
        )),
        None => Err(unbound(
            plane,
            id,
            field,
            format!("signed envelope carries no boolean `{field}`"),
        )),
    }
}

/// Parse + resolution-guard a signed instant. The microsecond floor is
/// [`crate::federation::admission::CONSENT_INSTANT_RESOLUTION_NANOS`] and it
/// is REFUSED rather than truncated for the #598 reason: postgres
/// `TIMESTAMPTZ` cannot hold finer, so a nanosecond-precision row would be
/// admitted here, stored truncated, and then FAIL this very binding when a
/// replicating peer read it back and re-submitted it. Refusing keeps the
/// property total across all three backends.
fn bind_instant_value(
    plane: &'static str,
    id: &str,
    field: &'static str,
    signed: &str,
) -> Result<DateTime<Utc>, Error> {
    use chrono::Timelike as _;
    let parsed = DateTime::parse_from_rfc3339(signed)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| {
            unbound(
                plane,
                id,
                field,
                format!("signed envelope value {signed:?} is not RFC-3339: {e}"),
            )
        })?;
    if parsed.nanosecond() % crate::federation::admission::CONSENT_INSTANT_RESOLUTION_NANOS != 0 {
        return Err(unbound(
            plane,
            id,
            field,
            format!(
                "signed instant {} carries sub-microsecond precision, which postgres \
                 TIMESTAMPTZ cannot store — the row would fail its own binding after a \
                 round-trip. Truncate to microseconds at the producer",
                parsed.to_rfc3339()
            ),
        ));
    }
    Ok(parsed)
}

/// Bind a REQUIRED instant column to its signed counterpart.
fn bind_instant(
    env: &Value,
    plane: &'static str,
    id: &str,
    field: &'static str,
    actual: DateTime<Utc>,
) -> Result<(), Error> {
    let Some(Value::String(signed)) = env.get(field) else {
        return Err(unbound(
            plane,
            id,
            field,
            format!(
                "signed envelope carries no RFC-3339 `{field}` string. This column orders \
                 the merge, and an unbound ordering key is a replay waiting to happen"
            ),
        ));
    };
    let signed = bind_instant_value(plane, id, field, signed)?;
    if signed != actual {
        return Err(unbound(
            plane,
            id,
            field,
            format!(
                "column is {}, the signed envelope says {}",
                actual.to_rfc3339(),
                signed.to_rfc3339()
            ),
        ));
    }
    Ok(())
}

/// Bind an OPTIONAL instant column: absent/null in the envelope ⇔ `None`.
/// This is the gate the `withdrawn_at` tombstone needs — a withdrawal is an
/// AUTHORED act, so setting one requires a freshly signed envelope that
/// says so, not a column edit on a replay of a still-valid grant.
fn bind_opt_instant(
    env: &Value,
    plane: &'static str,
    id: &str,
    field: &'static str,
    actual: Option<DateTime<Utc>>,
) -> Result<(), Error> {
    let signed = match env.get(field) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(bind_instant_value(plane, id, field, s)?),
        Some(_) => {
            return Err(unbound(
                plane,
                id,
                field,
                "signed envelope must carry an RFC-3339 string or nothing at all".to_string(),
            ))
        }
    };
    if signed == actual {
        return Ok(());
    }
    Err(unbound(
        plane,
        id,
        field,
        format!(
            "column is {:?}, the signed envelope says {:?}",
            actual.map(|t| t.to_rfc3339()),
            signed.map(|t| t.to_rfc3339())
        ),
    ))
}

/// v31.0.0 (CIRISPersist#644) — refuse an [`Organization`] whose typed
/// projection disagrees with the envelope its signature covers.
///
/// # `attestation_id` binds FIRST (v31.0.0, CIRISPersist#658)
///
/// The attestation plane has bound the row's own identity since #643, and
/// [`crate::federation::envelope::row_paths::ATTESTATION_ID`] states the
/// reason: *same bytes ⇒ same id*, so re-submitting a still-valid signed
/// envelope collides with itself on the primary key and the dedup absorbs it
/// as an idempotent no-op. Replay stops being *refused* and starts being
/// *impossible to express*.
///
/// These three planes did not have it. Every other security-relevant column
/// was bound, and the one column that says WHICH ROW THIS IS was authored by
/// whoever wrote the row. The structural consequence is certain and does not
/// depend on any exploitation story: **one signed envelope could be installed
/// at unboundedly many primary keys**, each a fully valid row by every gate in
/// the file, each carrying an attacker-chosen §6.1 tie-break key
/// ([`lww_wins`] / [`partner_wins`] break ties on smallest `attestation_id`)
/// and each minting its own `signed_wire_index` entry. Escalation past that —
/// actually winning the merge — additionally needs an `asserted_at` tie, so it
/// is narrower than "replay wins"; the unbounded fan-out of a single signed
/// envelope is not narrow, and it is what the binding closes.
///
/// Costed as free rather than cheap: this changes the SIGNING PREIMAGE of all
/// three planes, so every producer must re-mint — and v31.0.0 forces exactly
/// that re-mint anyway. `PartnerRecord`'s envelope is signed by an M-of-N
/// steward quorum, so the same change one release later would mean
/// re-collecting M steward signatures across organizations in a second
/// ceremony against a live federation.
///
/// # Errors
/// [`Error::OperationalEnvelopeUnbound`] on the first divergent column.
pub fn check_organization_binding(row: &Organization) -> Result<(), Error> {
    const PLANE: &str = "organization";
    let (env, id) = (&row.signed_envelope, row.attestation_id.as_str());
    bind_str(env, PLANE, id, "attestation_id", &row.attestation_id)?;
    bind_str(env, PLANE, id, "org_id", &row.org_id)?;
    bind_str(env, PLANE, id, "name", &row.name)?;
    bind_str(env, PLANE, id, "org_type", &row.org_type)?;
    bind_str(env, PLANE, id, "status", &row.status)?;
    bind_str(env, PLANE, id, "attesting_key_id", &row.attesting_key_id)?;
    bind_opt_str(
        env,
        PLANE,
        id,
        "parent_org_id",
        row.parent_org_id.as_deref(),
    )?;
    bind_opt_str(env, PLANE, id, "partner_id", row.partner_id.as_deref())?;
    bind_instant(env, PLANE, id, "asserted_at", row.asserted_at)?;
    bind_opt_instant(env, PLANE, id, "valid_until", row.valid_until)?;
    bind_opt_instant(env, PLANE, id, "withdrawn_at", row.withdrawn_at)?;
    Ok(())
}

/// v31.0.0 (CIRISPersist#644) — refuse an [`OrgMembership`] whose typed
/// projection disagrees with the envelope its signature covers.
///
/// `role` and `status` are the two the role-chain resolver reads out of the
/// ENVELOPE while the read surface returns the COLUMN; unbound, the two
/// could disagree, and a `viewer` on the wire could be an `org_admin` to
/// every consumer of `list_org_memberships_since`.
///
/// # Errors
/// [`Error::OperationalEnvelopeUnbound`] on the first divergent column.
pub fn check_org_membership_binding(row: &OrgMembership) -> Result<(), Error> {
    const PLANE: &str = "org_membership";
    let (env, id) = (&row.signed_envelope, row.attestation_id.as_str());
    bind_str(env, PLANE, id, "attestation_id", &row.attestation_id)?;
    bind_str(env, PLANE, id, "user_id", &row.user_id)?;
    bind_str(env, PLANE, id, "org_id", &row.org_id)?;
    bind_str(env, PLANE, id, "role", &row.role)?;
    bind_str(env, PLANE, id, "status", &row.status)?;
    bind_str(env, PLANE, id, "attesting_key_id", &row.attesting_key_id)?;
    bind_instant(env, PLANE, id, "asserted_at", row.asserted_at)?;
    bind_opt_instant(env, PLANE, id, "valid_until", row.valid_until)?;
    bind_opt_instant(env, PLANE, id, "withdrawn_at", row.withdrawn_at)?;
    Ok(())
}

/// v31.0.0 (CIRISPersist#644) — refuse a [`PartnerRecord`] whose typed
/// projection disagrees with the envelope the M-of-N steward quorum signed.
///
/// **This is what binds `revision`.** The counter is the anti-rollback
/// gate AND the first key of the `monotonic_quorum` comparator, and it was
/// a plain caller-supplied column. It is bound INTO THE SIGNED BYTES rather
/// than derived from the quorum, because the quorum is not a source of
/// ordering: `verify_partner_record_quorum` returns *how many* stewards
/// signed, which says nothing about which of two validly-signed records is
/// later, and M stewards could sign any number of records for one
/// `license_id`. The number that decides precedence must be a number the
/// stewards actually attested to. The quorum already verifies
/// `JCS(signed_envelope)`, so requiring `revision` to live there makes the
/// counter quorum-attested at zero additional cryptographic cost.
///
/// # v31.0.0 (CIRISPersist#659) — it takes the WRAPPER, because `threshold` is
/// on the wrapper
///
/// `SignedPartnerRecord::threshold` is the M of the M-of-N and it sat OUTSIDE
/// the signed bytes, so a relay could rewrite a `3` into a `1` in transit with
/// every steward signature still valid. It is the only security-relevant field
/// of the submission that is not a column of [`PartnerRecord`], which is why
/// this function's argument changed rather than a fourth binding helper being
/// minted for one field. See [`check_partner_set_and_quorum`] for the floor
/// that is applied to it once it is honest.
///
/// # Errors
/// [`Error::OperationalEnvelopeUnbound`] on the first divergent column.
pub fn check_partner_record_binding(signed: &SignedPartnerRecord) -> Result<(), Error> {
    const PLANE: &str = "partner_record";
    let row = &signed.partner_record;
    let (env, id) = (&row.signed_envelope, row.attestation_id.as_str());
    bind_str(env, PLANE, id, "attestation_id", &row.attestation_id)?;
    bind_str(env, PLANE, id, "license_id", &row.license_id)?;
    bind_str(env, PLANE, id, "partner_id", &row.partner_id)?;
    bind_str(env, PLANE, id, "org_id", &row.org_id)?;
    bind_str(env, PLANE, id, "license_type", &row.license_type)?;
    bind_str(env, PLANE, id, "max_autonomy_tier", &row.max_autonomy_tier)?;
    bind_str(env, PLANE, id, "status", &row.status)?;
    bind_bool(
        env,
        PLANE,
        id,
        "requires_supervisor",
        row.requires_supervisor,
    )?;
    bind_u64(
        env,
        PLANE,
        id,
        "deployment_limit",
        u64::from(row.deployment_limit),
    )?;
    bind_u64(
        env,
        PLANE,
        id,
        "offline_grace_hours",
        u64::from(row.offline_grace_hours),
    )?;
    bind_u64(env, PLANE, id, "revision", row.revision)?;
    // v31.0.0 (CIRISPersist#659) — the M of the M-of-N, bound LAST because it
    // is the one member that is not a column of the record. `usize` → `u64` is
    // lossless on every target this crate builds for.
    bind_u64(
        env,
        PLANE,
        id,
        PARTNER_THRESHOLD_ENVELOPE_FIELD,
        signed.threshold as u64,
    )?;
    bind_instant(env, PLANE, id, "issued_at", row.issued_at)?;
    bind_instant(env, PLANE, id, "expires_at", row.expires_at)?;
    bind_instant(env, PLANE, id, "asserted_at", row.asserted_at)?;
    bind_opt_instant(env, PLANE, id, "withdrawn_at", row.withdrawn_at)?;
    Ok(())
}

/// v31.0.0 (CIRISPersist#659) — the `signed_envelope` key carrying the M-of-N
/// threshold. [`SignedPartnerRecord::threshold`] must mirror it exactly, and
/// [`check_partner_set_and_quorum`] floors the result at a strict majority of
/// the founder roster.
pub const PARTNER_THRESHOLD_ENVELOPE_FIELD: &str = "threshold";

/// v31.0.0 (CIRISPersist#644) — the `organization` admission gate nobody
/// was running: bind the projection, then hybrid-Strict verify the row's
/// OWN signature over `JCS(signed_envelope)` against `attesting_key_id`'s
/// **REGISTERED** pubkeys, resolved from persist's own directory.
///
/// Same verify contract as [`super::verify_family_admission`] /
/// [`super::verify_revocation_admission`] — the established shape for
/// "prove the claimed author actually authored this" — so a hybrid-pending
/// (classical-only) signature is refused, PQC-mandatory per CC 5.3.2.4.3.1.
/// Run BEFORE any DB work and before any lock the directory needs.
///
/// # Errors
/// [`Error::OperationalEnvelopeUnbound`] if the projection diverges;
/// [`Error::FederationTierUnverified`] if the signature does not verify or
/// the attester is not registered.
pub async fn verify_organization_admission<F>(
    directory: &F,
    row: &Organization,
) -> Result<(), Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    check_organization_binding(row)?;
    super::tier_ingest::verify_envelope_hybrid_signature(
        directory,
        &row.attesting_key_id,
        &row.signed_envelope,
        &row.ed25519_signature_base64,
        row.mldsa65_signature_base64.as_deref(),
    )
    .await
    .map(|_| ())
}

/// v31.0.0 (CIRISPersist#644) — the `org_membership` counterpart of
/// [`verify_organization_admission`]. See there for the contract.
///
/// # Errors
/// [`Error::OperationalEnvelopeUnbound`] or
/// [`Error::FederationTierUnverified`].
pub async fn verify_org_membership_admission<F>(
    directory: &F,
    row: &OrgMembership,
) -> Result<(), Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    check_org_membership_binding(row)?;
    super::tier_ingest::verify_envelope_hybrid_signature(
        directory,
        &row.attesting_key_id,
        &row.signed_envelope,
        &row.ed25519_signature_base64,
        row.mldsa65_signature_base64.as_deref(),
    )
    .await
    .map(|_| ())
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
// mint a genuinely accord-co-scrubbed record and test the `has_accord_conferred_role`
// ALLOW path. Under `#[cfg(test)]` alone these were unreachable to a consumer
// (a dependency's test items never compile into the dependent), so consumers
// gating real planes on `has_accord_conferred_role` (edge trace-serve) could only
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
                capability_roles: Vec::new(),
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
        // v31.0.0 (#644) — the envelope now carries EVERY column the
        // binding gate checks, and the instant is truncated to the
        // substrate resolution before it is signed so the row cannot fail
        // its own binding after a postgres round-trip.
        let asserted_at =
            crate::federation::admission::truncate_to_substrate_resolution(asserted_at);
        // v31.0.0 (#658) — the row's own IDENTITY is signed material now, so
        // a caller that wants a second row must mint a second envelope.
        let envelope = json!({
            "attestation_id": attestation_id,
            "user_id": user_id,
            "org_id": org_id,
            "role": role,
            "status": status,
            "attesting_key_id": granter.key_id,
            "asserted_at": asserted_at.to_rfc3339(),
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
        // v31.0.0 (#644) — see `signed_membership`.
        let asserted_at =
            crate::federation::admission::truncate_to_substrate_resolution(asserted_at);
        // v31.0.0 (#658) — see `signed_membership`.
        let envelope = json!({
            "attestation_id": attestation_id,
            "org_id": org_id,
            "name": "Acme",
            "org_type": "partner",
            "status": status,
            "attesting_key_id": actor.key_id,
            "asserted_at": asserted_at.to_rfc3339(),
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
        // v31.0.0 (#644) — `revision` was already in the envelope and the
        // COLUMN was still the one the anti-rollback gate read; the three
        // instants join it so every column the comparator touches is
        // quorum-attested. Truncated before signing (see
        // `signed_membership`).
        let asserted_at =
            crate::federation::admission::truncate_to_substrate_resolution(asserted_at);
        // v31.0.0 (#658) — the identity joins the quorum-signed bytes: a
        // second primary key now requires a second M-of-N ceremony.
        let envelope = json!({
            "attestation_id": attestation_id,
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
            // v31.0.0 (#659) — the M of the M-of-N joins the quorum-signed
            // bytes: a relay can no longer talk a 3-of-5 licence down to a
            // 1-of-5 while the stewards' own signatures stay valid.
            super::PARTNER_THRESHOLD_ENVELOPE_FIELD: threshold,
            "issued_at": asserted_at.to_rfc3339(),
            "expires_at": asserted_at.to_rfc3339(),
            "asserted_at": asserted_at.to_rfc3339(),
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
    ///
    /// # v31.0.0 (CIRISPersist#659) — BREAKING: the subject is now BOUND
    ///
    /// The helper stamps the subject's `key_id`, `identity_type` and BOTH
    /// pubkeys into
    /// `envelope` before canonicalizing and signing it, through the one shared
    /// [`crate::federation::admission::bind_subject_into_envelope`] — the same
    /// projection the co-scrub gate checks with, so a record this helper builds
    /// is conformant by construction and a caller cannot write the binding
    /// wrong. Every other field of `envelope` survives untouched.
    ///
    /// Two changes, both deliberate:
    ///
    /// - a **preimage change** for any caller whose envelope did not already
    ///   carry every [`crate::federation::admission::subject_binding`] member
    ///   (the in-repo `{"key_id": k}` fixtures did not) — the signed bytes now
    ///   differ, so records must be re-minted, not re-used;
    /// - a **signature change**: the subject's pubkeys are explicit parameters.
    ///   #659's second half is precisely that the accord signs for the
    ///   subject's KEYS and not merely its name, and a helper that hardcoded
    ///   ONE placeholder pubkey for every record could not express two records
    ///   whose keys differ — i.e. could not express the attack, and so could
    ///   not witness the fix.
    ///
    /// Mechanical update for downstream mesh simulations: insert
    /// `PLACEHOLDER_SUBJECT_ED25519_BASE64, None,` after `identity_type` to
    /// keep exactly the pre-#659 columns. A caller that used to OVERWRITE
    /// `record.pubkey_ed25519_base64` after the call must pass the key here
    /// instead — post-hoc mutation now (correctly) breaks the binding.
    pub fn signed_canonical_record(
        key_id: &str,
        identity_type: &str,
        pubkey_ed25519_base64: &str,
        pubkey_ml_dsa_65_base64: Option<&str>,
        envelope: serde_json::Value,
        scrubbers: &[&Identity],
    ) -> crate::federation::types::KeyRecord {
        use crate::federation::types::ScrubSig;
        use sha2::{Digest, Sha256};
        // #659 — bind the subject BEFORE the bytes are formed: the accord
        // family must sign a preimage that names the key it confers on.
        let mut envelope = envelope;
        crate::federation::admission::bind_subject_into_envelope(
            &mut envelope,
            key_id,
            identity_type,
            pubkey_ed25519_base64,
            pubkey_ml_dsa_65_base64,
        )
        .expect("bind the #659 subject into the registration envelope");
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
            pubkey_ed25519_base64: pubkey_ed25519_base64.to_owned(),
            pubkey_ml_dsa_65_base64: pubkey_ml_dsa_65_base64.map(str::to_owned),
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
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: scrub_sigs[1..].to_vec(),
        }
    }

    /// v18.3.0 (CIRISPersist#484) — a co-scrubbed record that carries
    /// `roles`, so a consumer can test the `has_accord_conferred_role` **ALLOW**
    /// path (not just the deny path).
    ///
    /// Identical to [`signed_canonical_record`] but stamps `roles` onto the
    /// row. The co-scrub is over `JCS(registration_envelope)` (the roles
    /// column is not part of the signed bytes — matching the production
    /// admission model: role CLAIM is the column, role CONFERRAL is the
    /// re-verified co-scrub against the accord roster). Pass 2 distinct
    /// accord-holder `Identity`s (a 2-of-3 admit) as `scrubbers`, register
    /// them with [`register_accord_holder`], then read back with
    /// [`crate::federation::admission::has_accord_conferred_role_over_roster`] over
    /// their key_ids.
    ///
    /// v31.0.0 (CIRISPersist#659) — takes the subject's pubkeys for the same
    /// reason [`signed_canonical_record`] does, and in the same position; see
    /// that helper's BREAKING note.
    pub fn signed_canonical_record_with_roles(
        key_id: &str,
        identity_type: &str,
        pubkey_ed25519_base64: &str,
        pubkey_ml_dsa_65_base64: Option<&str>,
        roles: Vec<String>,
        envelope: serde_json::Value,
        scrubbers: &[&Identity],
    ) -> crate::federation::types::KeyRecord {
        let mut rec = signed_canonical_record(
            key_id,
            identity_type,
            pubkey_ed25519_base64,
            pubkey_ml_dsa_65_base64,
            envelope,
            scrubbers,
        );
        rec.capability_roles = roles;
        rec
    }

    /// v31.0.0 (CIRISPersist#659) — the subject Ed25519 pubkey
    /// [`signed_canonical_record`] hardcoded for EVERY record it minted before
    /// the subject binding landed (32 bytes of `0x07`, base64).
    ///
    /// Exported so a downstream mesh simulation's update is a two-token
    /// insertion that preserves its records' columns byte-for-byte. It is a
    /// PLACEHOLDER, not a key: no private half exists, so a record carrying it
    /// can never sign anything, and two records carrying it are the SAME
    /// identity as far as the #659 binding is concerned. A simulation that
    /// needs distinct canonicals must now pass distinct keys — which is the
    /// point of binding the pubkeys at all, and the reason this could not stay
    /// a hidden constant.
    pub const PLACEHOLDER_SUBJECT_ED25519_BASE64: &str =
        "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

    /// v18.3.0 (CIRISPersist#484) — register `holder`'s PINNED hybrid
    /// pubkeys as a directory row so the accord roster resolves to keys the
    /// co-scrub can be verified against. `node` identity_type (not
    /// `accord_holder`) so it skips the hardware-signer gate — the roster
    /// resolution in `verify_accord_family_coscrub` only needs the pubkeys,
    /// not the HW attestation. The exported analogue of admission's
    /// previously-private `register_founder`.
    ///
    /// v22.0.0 (CIRISPersist#543) — **fully deterministic**: `valid_from` /
    /// `scrub_timestamp` are the same FIXED instant `Identity::steward_key_record`
    /// pins, not `Utc::now()`. Combined with `Identity::new`'s deterministic
    /// seeding (#502 E9) and the timestamp-free `registration_envelope`, a given
    /// `holder` now produces a BYTE-IDENTICAL record on every call — so
    /// re-registering the same holder against a shared postgres test DB is a
    /// true no-op instead of a differing-content write under a fixed `key_id`.
    /// That matters as of [`register_genesis_accord_roster`], which registers
    /// the FIXED genesis ids (`A1`/`B1`/`C1`) rather than per-test unique ones,
    /// and is called once per conferred key.
    pub async fn register_accord_holder(
        directory: &dyn crate::federation::FederationDirectory,
        holder: &Identity,
    ) -> Result<(), crate::federation::Error> {
        use sha2::{Digest, Sha256};
        let m = holder.member();
        let registration_envelope = json!({ "key_id": holder.key_id });
        // The pinned instant — see the determinism note above. Well in the past,
        // so the row is live for every gate that reads `valid_from`.
        let pinned: chrono::DateTime<chrono::Utc> = "2020-01-01T00:00:00Z"
            .parse()
            .expect("pinned holder timestamp is valid RFC-3339");
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
            valid_from: pinned,
            valid_until: None,
            registration_envelope,
            original_content_hash: hex::encode(Sha256::digest(&bytes)),
            scrub_signature_classical: ed,
            scrub_signature_pqc: Some(pqc),
            scrub_key_id: holder.key_id.clone(),
            scrub_timestamp: pinned,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
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
    /// [`crate::federation::admission::has_accord_conferred_role_over_roster`] (over
    /// the returned roster) reads the conferred roles TRUE on any backend
    /// (sqlite / postgres / memory).
    ///
    /// This is the honest path the `InfraAttestRoleNotAccordConferred` gate
    /// demands — it does the real m-of-n dance, it does NOT bypass conferral.
    /// Consumers building an in-process round test (agent-shaped → canonical-
    /// shaped, real engines/bridges, no docker) call this instead of
    /// reassembling an accord family by hand (which every consumer got subtly
    /// wrong — CIRISPersist#534). Returns the holder roster (their `key_id`s)
    /// to pass to `has_accord_conferred_role_over_roster` / admission.
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
            register_accord_holder(directory, h).await.map_err(|e| {
                crate::federation::Error::Backend(format!("#548 step holder-reg {}: {e}", h.key_id))
            })?;
        }
        let roster: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();
        let record = signed_canonical_record_with_roles(
            key_id,
            crate::federation::types::identity_type::NODE,
            PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            roles.iter().map(|r| (*r).to_owned()).collect(),
            json!({ "key_id": key_id, "conferred_by": family_tag }),
            &[&holders[0], &holders[1]],
        );
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record })
            .await?;
        Ok(roster)
    }

    /// v22.0.0 (CIRISPersist#543) — register the **GENESIS accord roster**
    /// (`A1`/`B1`/`C1`, or the synthesized test-anchor holders when that mode
    /// is armed) as directory rows carrying DETERMINISTIC test keypairs, and
    /// return those identities so a fixture can co-scrub with them.
    ///
    /// # Why this exists alongside [`confer_roles`]
    ///
    /// `confer_roles` mints its OWN `{family_tag}-h*` holders and hands the
    /// caller their roster, which is exactly right for the READ side
    /// ([`has_accord_conferred_role_over_roster`](crate::federation::admission)) — the
    /// caller passes the roster back in. The WRITE-side gates that run inside
    /// `put_public_key` take no roster argument: `check_canonical_role_admission`
    /// / `check_infra_attest_role_admission` /
    /// `check_privileged_identity_type_admission` all resolve the roster from
    /// `accord_holder_roster_key_ids()`, i.e. the GENESIS holder `key_id`s. So a
    /// record that must survive a chokepoint gate has to be co-scrubbed by keys
    /// sitting at *those* `key_id`s, and a bare test backend has none — the
    /// quorum resolves to 0 members and every conferral fails
    /// "accord quorum unreachable".
    ///
    /// This helper stands the trust root up in the test directory: the roster
    /// ids are the real genesis ones, and the KEY MATERIAL under them is
    /// test-held (nobody has the #268 ceremony's private halves). That is the
    /// only injectable seam, and it is fixture setup — the gate itself is
    /// untouched and runs for real: roster resolution, per-scrub hybrid
    /// signature verification, and the m-of-n quorum policy all execute against
    /// these rows exactly as they do in production. Same shape as the
    /// long-standing `adopt_scrub_upgrade_gate_sqlite` fixture, which seeds
    /// `A1`/`B1` directly "mirrors the real seed where A1/B1 are genesis rows".
    ///
    /// Holders register as `node` (not `accord_holder`) — the quorum core only
    /// needs their PINNED directory pubkeys, and `node` skips the #513
    /// hardware-attestation gate on sqlite/postgres. Deterministic and
    /// idempotent (see [`register_accord_holder`]'s pinned timestamps), so a
    /// fixture conferring several keys may call it once per key.
    ///
    /// # HARD LIMIT: only works on a directory with NO genesis seed
    ///
    /// This writes the genesis `key_id`s with TEST key material, so it requires
    /// that those rows do not already exist. On a **genesis-seeded** directory
    /// they do — carrying the REAL #268 ceremony pubkeys — and `put_public_key`
    /// correctly refuses to replace them
    /// (`Conflict("key_id A1 already exists with different content")`). That is
    /// the substrate protecting its trust root and MUST NOT be worked around:
    /// on such a directory nobody can produce the co-scrub, because the genesis
    /// private halves live in hardware.
    ///
    /// So this helper serves fixtures on a **bare** backend
    /// (`SqliteBackend::open_in_memory` + `run_migrations`, `MemoryBackend::new`,
    /// a fresh unseeded pg schema) — NOT `Engine::with_signer`, which seeds
    /// genesis, and NOT a shared pg test database that any engine test has
    /// touched. A fixture needing an accord-conferred `identity_type` against a
    /// genesis-seeded directory has to move the whole roster instead, via the
    /// `test-anchor` seam (CIRISPersist#449/#451): with that feature compiled
    /// and `CIRIS_TESTING_MODE` + `CIRIS_TEST_TRUST_ROOT*` armed,
    /// `effective_accord_holder_records` returns `test-accord-holder-{i}` and
    /// this helper follows it automatically — no code change here.
    pub async fn register_genesis_accord_roster(
        directory: &dyn crate::federation::FederationDirectory,
    ) -> Result<Vec<Identity>, crate::federation::Error> {
        let mut holders = Vec::new();
        for rec in crate::federation::genesis::effective_accord_holder_records().iter() {
            let holder = Identity::new(&rec.record.key_id);
            register_accord_holder(directory, &holder).await?;
            holders.push(holder);
        }
        Ok(holders)
    }

    /// v22.0.0 (CIRISPersist#543) — turn a self-scrubbed fixture `KeyRecord`
    /// into an accord-**CONFERRED** one: replace the placeholder scrub columns
    /// with REAL hybrid signatures by each of `scrubbers` over
    /// `JCS(registration_envelope)` — the identical bytes
    /// `verify_accord_family_coscrub` re-canonicalizes and verifies. Scrub #1
    /// fills the base `scrub_key_id`/`scrub_signature_*` fields, #2..N ride
    /// `additional_scrubs`, and `original_content_hash` is recomputed over the
    /// same bytes.
    ///
    /// Everything else on the record is preserved — notably its `key_id`,
    /// `identity_type` and (deterministic) pubkeys — so a fixture keeps
    /// testing what it always tested and only the CONFERRAL changes: the key
    /// stops asserting its own privileged type and starts being granted it.
    /// Pass 2 distinct [`register_genesis_accord_roster`] holders for a
    /// 2-of-3 admit.
    pub fn accord_conferred(
        mut record: crate::federation::types::KeyRecord,
        scrubbers: &[&Identity],
    ) -> crate::federation::types::KeyRecord {
        use crate::federation::types::ScrubSig;
        use sha2::{Digest, Sha256};
        assert!(!scrubbers.is_empty(), "at least one scrubber required");
        // v31.0.0 (CIRISPersist#659) — the SECOND producer of co-scrubbed
        // records, and therefore the second place the subject has to be bound.
        // It runs through the same `bind_subject_into_envelope` the gate checks
        // with, off the record's OWN key_id, identity_type and pubkeys, so a
        // fixture cannot hand the accord family a preimage that names somebody
        // else — nor, since 13.1.0, one that names a DIFFERENT STANDING for the
        // same key, which is the conferral this helper exists to simulate.
        crate::federation::admission::bind_subject_into_envelope(
            &mut record.registration_envelope,
            &record.key_id,
            &record.identity_type,
            &record.pubkey_ed25519_base64,
            record.pubkey_ml_dsa_65_base64.as_deref(),
        )
        .expect("bind the #659 subject into the registration envelope");
        let bytes =
            crate::verify::canonical::ceg_produce_canonicalize(&record.registration_envelope)
                .expect("canonicalize registration_envelope");
        let scrubs: Vec<ScrubSig> = scrubbers
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
        record.original_content_hash = hex::encode(Sha256::digest(&bytes));
        record.scrub_key_id = scrubs[0].scrub_key_id.clone();
        record.scrub_signature_classical = scrubs[0].scrub_signature_classical.clone();
        record.scrub_signature_pqc = scrubs[0].scrub_signature_pqc.clone();
        record.additional_scrubs = scrubs[1..].to_vec();
        record
    }

    /// v22.0.0 (CIRISPersist#543) — the one-call fixture path for "this key
    /// legitimately holds a privileged `identity_type`": stand up the genesis
    /// accord roster ([`register_genesis_accord_roster`]), co-scrub `record`
    /// to the family m-of-n ([`accord_conferred`]), and write it.
    ///
    /// Use wherever a fixture previously SELF-ASSERTED a member of
    /// `identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES` whose
    /// `ConferralMode` is `AccordCoScrubbed` (`trusted_publisher` /
    /// `lenscore_detector`) — types that assert about a THIRD PARTY and so are
    /// refused fail-closed at every `federation_keys` write chokepoint when
    /// self-declared (`Error::RoleNotAccordConferred`).
    pub async fn put_accord_conferred_key(
        directory: &dyn crate::federation::FederationDirectory,
        record: crate::federation::types::KeyRecord,
    ) -> Result<(), crate::federation::Error> {
        let holders = register_genesis_accord_roster(directory).await?;
        assert!(
            holders.len() >= 2,
            "the genesis accord roster must have at least 2 holders to reach a 2-of-3 quorum"
        );
        let record = accord_conferred(record, &[&holders[0], &holders[1]]);
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record })
            .await
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
            capability_roles: Vec::new(),
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
        crate::federation::tier_ingest::test_support::seal_row(
            signing_key_id,
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
                additional_scrubs: Vec::new(),
            },
        )
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
            // v23.0.0 (CIRISPersist#551 item 2) — R → subject: this is the
            // CONFERRAL, the one that points the opposite way from the trust
            // edge it is otherwise indistinguishable from.
            json!({
                "references_attestation_id": id,
                "dimension": crate::federation::trust_root::TRUST_CONFERS_DIMENSION,
                "scope": [scope],
            }),
        );
        directory
            .put_attestation(crate::federation::SignedAttestation { attestation: edge })
            .await
    }

    /// **v31.0.0 (CIRISPersist#659) — THE UNREPLICATED-NODE RACE, at the real
    /// write chokepoint, on every backend.**
    ///
    /// The admission-module witness
    /// (`canonical_gate_tests::coscrub_confers_only_on_the_key_it_names_659`)
    /// drives the strict canonical gate directly with fabricated hardware
    /// custody. This one drives `put_public_key` — the door every conferral
    /// actually arrives through — so the binding is proved where the mesh
    /// meets it, and proved identically on memory, sqlite and postgres. Backend
    /// asymmetry in a write gate is this repo's oldest recurring defect
    /// (#518/#543); a gate witnessed on one backend is a gate shipped on one
    /// backend.
    ///
    /// **The scenario is the residual a NAME-only binding leaves.** The victim
    /// `V` is deliberately NEVER stored: this is a node that has not yet
    /// replicated `V`'s row, which is the whole point. There is no collision
    /// for `put_public_key` to refuse, `V`'s name is exactly what the accord
    /// signed, and the ONLY thing standing between the attacker and
    /// `infra:attest` is whether the ceremony bound `V`'s KEYS as well as `V`'s
    /// name. Replication ordering across the mesh is arbitrary and the same
    /// gate runs in anti-entropy, so a hostile peer can enter this race
    /// deliberately.
    ///
    /// Legs: (a) the honestly-bound subject ADMITS — without it a gate that
    /// refused everything would pass; (b) the name lift; (c) the classical-leg
    /// substitution; (d) the PQC-leg substitution, because binding one leg of a
    /// hybrid identity leaves the other substitutable; (e) each bound field
    /// removed in turn, because an optional check is skippable by omission.
    ///
    /// # v31.0.0 (CIRISVerify 13.1.0) — the fourth member and the one carve-out
    ///
    /// (f) THE RELABEL: a record whose `identity_type` COLUMN disagrees with
    /// its signed envelope is refused, naming the field. This is verify's third
    /// 13.1.0 finding — privilege transfer — and it is reachable here rather
    /// than theoretical, because `apply_replicated_key_record`'s Insert branch
    /// skips `verify_key_registration` for exactly the role-gated records,
    /// leaving the co-scrub as their only cryptographic proof.
    ///
    /// (g) CEG §0.9 OMIT-VS-MATERIALIZE, as a three-row table: (g1) envelope
    /// omits the PQC member AND the row claims none ⇒ ADMITTED; (g2) envelope
    /// omits but the row CLAIMS a key ⇒ REFUSED; (g3) envelope declares a leg
    /// the row does not ⇒ REFUSED. The table IS the property — verify tolerates
    /// exactly one absence and it is the "both say nothing" case, so (g1) alone
    /// would read as "an omitted member is unchecked" and (g2)/(g3) are what
    /// make it agreement rather than tolerance.
    pub async fn exercise_coscrub_subject_binding(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::types::{roles, SignedKeyRecord};

        let holders = register_genesis_accord_roster(directory).await?;
        let scrubbers = [&holders[0], &holders[1]];

        // Two REAL, DISTINCT hybrid identities. Distinct keys are the point:
        // the pre-#659 helper minted one placeholder pubkey for every record,
        // which could not express two subjects at all.
        //
        // The distinguishing part goes FIRST. `hybrid_pubkeys` seeds from the
        // key_id TRUNCATED TO 32 BYTES, and the postgres tag is a 38-char
        // uuid-suffixed string — so `{tag}-victim` and `{tag}-attacker` seed
        // IDENTICALLY and this whole witness would have been vacuous on the one
        // backend production runs. Caught by the assertion below, which is why
        // it is there.
        let victim = format!("v659-{tag}");
        let attacker = format!("a659-{tag}");
        let (v_ed, v_pqc) = crate::federation::tier_ingest::test_support::hybrid_pubkeys(&victim);
        let (a_ed, a_pqc) = crate::federation::tier_ingest::test_support::hybrid_pubkeys(&attacker);
        assert_ne!(v_ed, a_ed, "({tag}) #659: the two subjects must differ");
        assert_ne!(v_pqc, a_pqc, "({tag}) #659: …on BOTH hybrid legs");

        let conferral = |key_id: &str, ed: &str, pqc: Option<&str>| {
            signed_canonical_record_with_roles(
                key_id,
                crate::federation::types::identity_type::NODE,
                ed,
                pqc,
                vec![roles::INFRA_ATTEST.to_owned()],
                json!({ "purpose": "the #659 conferral ceremony" }),
                &scrubbers,
            )
        };

        // (a) THE CONTROL — an honestly co-scrubbed, honestly bound subject
        //     takes `infra:attest` through the real door.
        let admitted = format!("ok659-{tag}");
        let (ok_ed, ok_pqc) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(&admitted);
        directory
            .put_public_key(SignedKeyRecord {
                record: conferral(&admitted, &ok_ed, ok_pqc.as_deref()),
            })
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "({tag}) #659(a): a conferral whose envelope binds its own subject must still \
                     admit — a gate that refuses everything proves nothing: {e}"
                )
            });

        // The ceremony the accord actually performed, for the victim. Never
        // stored — the node has not replicated it.
        let ceremony = conferral(&victim, &v_ed, v_pqc.as_deref());

        // Replay it verbatim onto `rec`. The attacker forges nothing: these are
        // the holders' real signatures over the holders' real preimage.
        let lift = |mut rec: crate::federation::types::KeyRecord| {
            rec.registration_envelope = ceremony.registration_envelope.clone();
            rec.original_content_hash
                .clone_from(&ceremony.original_content_hash);
            rec.scrub_key_id.clone_from(&ceremony.scrub_key_id);
            rec.scrub_signature_classical
                .clone_from(&ceremony.scrub_signature_classical);
            rec.scrub_signature_pqc
                .clone_from(&ceremony.scrub_signature_pqc);
            rec.additional_scrubs
                .clone_from(&ceremony.additional_scrubs);
            rec
        };

        let refused =
            |rec: crate::federation::types::KeyRecord, leg: &'static str, needle: String| {
                let tag = tag.to_owned();
                async move {
                    let err = directory
                        .put_public_key(SignedKeyRecord { record: rec })
                        .await
                        .err()
                        .unwrap_or_else(|| {
                            panic!(
                            "({tag}) #659{leg}: the accord co-scrub must confer on the SUBJECT it \
                             named, not on whatever record its signatures are pasted onto"
                        )
                        });
                    let msg = format!("{err}");
                    assert!(
                    msg.contains(&needle) && msg.contains("CIRISPersist#659"),
                    "({tag}) #659{leg}: the refusal must name the disagreeing binding {needle:?} \
                     and the gate: {msg}"
                );
                }
            };

        // (b) THE NAME LIFT — a different key_id entirely.
        refused(
            lift(conferral(&attacker, &a_ed, a_pqc.as_deref())),
            "(b)",
            victim.clone(),
        )
        .await;

        // (c) THE RACE, CLASSICAL LEG — the victim's NAME, the attacker's
        //     Ed25519 key. The name binding waves this through; only the pubkey
        //     binding stops it.
        refused(
            lift(conferral(&victim, &a_ed, v_pqc.as_deref())),
            "(c)",
            "pubkey_ed25519_base64".to_owned(),
        )
        .await;

        // (d) THE RACE, PQC LEG — name and classical key both the victim's,
        //     ONLY the ML-DSA-65 half swapped.
        refused(
            lift(conferral(&victim, &v_ed, a_pqc.as_deref())),
            "(d)",
            "pubkey_ml_dsa_65_base64".to_owned(),
        )
        .await;

        // (e) ABSENCE IS A REFUSAL, per bound field.
        //
        // The member list is READ OFF `subject_binding` rather than restated,
        // so a fifth member is witnessed here the moment it is added — the
        // whole point of one-projection-one-spelling is that adding a member is
        // ONE edit, and a hardcoded list here would quietly make it two. This
        // subject carries BOTH hybrid legs, so every member is non-null and
        // every absence is a refusal; the one tolerated absence needs a null
        // expectation and gets its own table in (g).
        let all_members: Vec<String> = crate::federation::admission::subject_binding(
            &victim,
            crate::federation::types::identity_type::NODE,
            &v_ed,
            v_pqc.as_deref(),
        )
        .keys()
        .cloned()
        .collect();
        assert!(
            all_members.iter().any(|m| m == "identity_type"),
            "({tag}) 13.1.0: `identity_type` must be one of the bound members, or leg (f) below \
             is witnessing a field nothing binds"
        );
        for missing in all_members {
            let mut partial = conferral(&victim, &v_ed, v_pqc.as_deref());
            partial
                .registration_envelope
                .as_object_mut()
                .expect("the conferral envelope is an object")
                .remove(&missing);
            refused(partial, "(e)", format!("does not bind {missing}")).await;
        }

        // (f) THE RELABEL — CIRISVerify 13.1.0's third finding (privilege
        //     transfer), at our write door. The envelope, the signatures and
        //     BOTH pubkeys are the accord's real work for this very subject;
        //     only the `identity_type` COLUMN is rewritten, on the outside.
        //     `is_canonical` reads standing off that column and
        //     `AUTHORITY_CONFERRING_IDENTITY_TYPES` gates on it, so before the
        //     fourth member this relabel was free.
        //
        //     The relabel is NODE → AGENT and not NODE → CANONICAL on purpose.
        //     Both are the same defect, but `canonical` also wakes the #513
        //     hardware-custody floor, which could legitimately refuse FIRST —
        //     and an assertion pinned on #659 that is actually being satisfied
        //     by a neighbouring gate is a witness that passes for the wrong
        //     reason. `agent` confers no authority, so nothing but the subject
        //     binding is left to refuse it, and the `infra:attest` role in the
        //     envelope still drives the co-scrub gate either way.
        let mut relabelled = conferral(&victim, &v_ed, v_pqc.as_deref());
        relabelled.identity_type = crate::federation::types::identity_type::AGENT.to_owned();
        refused(relabelled, "(f)", "identity_type".to_owned()).await;

        // (g) CEG §0.9 OMIT-VS-MATERIALIZE — the three-case table. Verify
        //     tolerates exactly ONE absence and it is the "both say nothing"
        //     case; the other two rows are what keeps that from being a hole.
        //     Re-scrubbing is required (not just editing the envelope) because
        //     case 1 has to ADMIT, which means its signatures must be real over
        //     the edited bytes — an unsigned edit would be refused by the
        //     quorum and prove nothing about the carve-out.
        let rescrub = |mut rec: crate::federation::types::KeyRecord| {
            use crate::federation::types::ScrubSig;
            use sha2::{Digest, Sha256};
            let bytes =
                crate::verify::canonical::ceg_produce_canonicalize(&rec.registration_envelope)
                    .expect("canonicalize the edited envelope");
            let sigs: Vec<ScrubSig> = scrubbers
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
            rec.original_content_hash = hex::encode(Sha256::digest(&bytes));
            rec.scrub_key_id.clone_from(&sigs[0].scrub_key_id);
            rec.scrub_signature_classical
                .clone_from(&sigs[0].scrub_signature_classical);
            rec.scrub_signature_pqc
                .clone_from(&sigs[0].scrub_signature_pqc);
            rec.additional_scrubs = sigs[1..].to_vec();
            rec
        };
        let omit_pqc = |rec: &mut crate::federation::types::KeyRecord| {
            rec.registration_envelope
                .as_object_mut()
                .expect("the conferral envelope is an object")
                .remove("pubkey_ml_dsa_65_base64");
        };

        // (g1) BOTH SAY NOTHING ⇒ ADMITTED. The envelope omits the member and
        //      the row claims no PQC leg. This is the row the carve-out exists
        //      for, and it is the ONLY one that admits.
        let g1 = format!("g1659-{tag}");
        let (g1_ed, _) = crate::federation::tier_ingest::test_support::hybrid_pubkeys(&g1);
        let mut both_silent = conferral(&g1, &g1_ed, None);
        omit_pqc(&mut both_silent);
        directory
            .put_public_key(SignedKeyRecord {
                record: rescrub(both_silent),
            })
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "({tag}) CEG §0.9(g1): an envelope that OMITS the PQC leg and a row that \
                     claims none say the SAME thing — a JCS producer legitimately omits rather \
                     than materializes a null, and refusing this would diverge from \
                     CIRISVerify 13.1.0's `require_optional`: {e}"
                )
            });

        // (g2) ENVELOPE SILENT, ROW CLAIMS A KEY ⇒ REFUSED. The carve-out keys
        //      on the EXPECTATION being null, and here it is not — so this
        //      lands on the plain absence arm. Without this row, the carve-out
        //      would be "an omitted member is never checked", which is the
        //      whole PQC-substitution attack back again.
        let mut row_claims = conferral(&victim, &v_ed, v_pqc.as_deref());
        omit_pqc(&mut row_claims);
        refused(
            rescrub(row_claims),
            "(g2)",
            "does not bind pubkey_ml_dsa_65_base64".to_owned(),
        )
        .await;

        // (g3) ENVELOPE DECLARES A LEG THE ROW DOES NOT ⇒ REFUSED, on the
        //      mismatch arm. A row asserting ABSENCE cannot inherit a co-scrub
        //      that named a key.
        let g3 = format!("g3659-{tag}");
        let (g3_ed, g3_pqc) = crate::federation::tier_ingest::test_support::hybrid_pubkeys(&g3);
        let mut envelope_claims = conferral(&g3, &g3_ed, g3_pqc.as_deref());
        envelope_claims.pubkey_ml_dsa_65_base64 = None;
        refused(
            envelope_claims,
            "(g3)",
            "pubkey_ml_dsa_65_base64".to_owned(),
        )
        .await;

        Ok(())
    }

    /// **CIRISPersist#548 — the baked-seed shape: an accord co-scrub IS a
    /// conferral the capability walk must see.** The genesis seed carries the
    /// canonical's `infra:serve` as roles INSIDE its 2-of-3 co-scrubbed
    /// `registration_envelope`, with ZERO `delegates_to` rows — the ceremony
    /// encoding. The `ConferralPlane::AccordCoScrub` read
    /// (`has_accord_conferred_role`) sees it; the
    /// `ConferralPlane::Delegation` walk
    /// (`capability_roots_to_trusted_root`) read only the delegation plane,
    /// so a fully accord-blessed canonical could not receive traces:
    /// `trace attestation withheld — recipient's infra:serve roots to no
    /// root this node trusts`, observed live by CIRISServer.
    ///
    /// Exercises the corrected #548 ask: the co-scrub yields a CANDIDATE
    /// (half 1), while the asking node's own trust chain — edge, charter,
    /// heartbeat, halt — is still required in full (half 2, untouched).
    /// Then the property the correction exists to protect: **delete the one
    /// `delegates_to(user → root)` edge and trust collapses** — the
    /// operator's un-trust lever, emergent, nothing special-cased.
    pub async fn exercise_ceremony_plane_capability_walk(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::trust_root::{
            capability_roots_to_trusted_root_over_roster, ConferralPlane, INFRA_ATTEST_SCOPE,
            INFRA_SERVE_SCOPE,
        };
        use crate::federation::types::attestation_type;

        let user = format!("{tag}-user");
        let canonical = format!("{tag}-baked-canonical");
        register_typed_key(
            directory,
            &user,
            crate::federation::types::identity_type::NODE,
        )
        .await?;

        // THE SEED SHAPE — the conferral in the accord's own encoding: a
        // 2-of-3 co-scrubbed key record with the role inside the signed
        // envelope, and NO delegates_to grant anywhere. Built like
        // `confer_roles` but carrying the canonical's REAL deterministic
        // hybrid pubkeys (as the production seed does) — the canonical must
        // be able to SIGN its own post-boot charter, and the synthetic
        // `[7u8;32]` pubkey in `signed_canonical_record` cannot verify
        // anything (the #545 derivation-mismatch trap, avoided by
        // construction).
        let holders = [
            Identity::new(&format!("{tag}-ch0")),
            Identity::new(&format!("{tag}-ch1")),
            Identity::new(&format!("{tag}-ch2")),
        ];
        for h in &holders {
            register_accord_holder(directory, h).await?;
        }
        let roster: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();
        // v31.0.0 (CIRISPersist#659) — the canonical's REAL pubkeys go THROUGH
        // the helper, not onto the record afterwards. Post-hoc mutation used to
        // be invisible; now it would leave the co-scrubbed envelope binding a
        // subject the row is not, and the gate would (correctly) refuse. The
        // production seed has always carried the real keys inside the signed
        // envelope — this fixture now says so in the same order.
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(&canonical);
        let record = signed_canonical_record_with_roles(
            &canonical,
            crate::federation::types::identity_type::NODE,
            &ed_pk,
            mldsa_pk.as_deref(),
            vec![INFRA_SERVE_SCOPE.to_owned()],
            json!({ "key_id": canonical, "conferred_by": tag }),
            &[&holders[0], &holders[1]],
        );
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record })
            .await?;

        // What the seed structurally CANNOT carry, written post-boot exactly
        // as the live actors would write it:
        // — the canonical's own charter (it holds its key at boot)...
        let charter_id = uuid::Uuid::new_v4().to_string();
        let successors = vec![format!("{canonical}-succ-a"), format!("{canonical}-succ-b")];
        let commitment = crate::federation::trust_root::pre_rotation_commitment(&successors)
            .map_err(|e| crate::federation::Error::Backend(format!("#548 pre_rotation: {e}")))?;
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: signed_trust_attestation(
                    &charter_id,
                    &canonical,
                    &canonical,
                    attestation_type::DELEGATES_TO,
                    json!({
                        "references_attestation_id": charter_id,
                        // v23.0.0 (CIRISPersist#551 item 2) — NAME the job:
                        // this delegates_to is a charter (R → R), not the
                        // conferral or the trust edge it is shaped like.
                        "dimension": crate::federation::trust_root::TRUST_CHARTER_DIMENSION,
                        "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
                        "pre_rotation_commitment": commitment,
                    }),
                ),
            })
            .await?;
        // — a fresh heartbeat / liveness witness (the reserved-family leg). The
        //   attester must be a REGISTERED accord_holder identity — the
        //   reserved-prefix gate refuses the dimension from anyone else —
        //   mirroring establish_trust_root_side's `-la` witness exactly.
        let la = format!("{canonical}-la");
        register_typed_key(
            directory,
            &la,
            crate::federation::types::identity_type::ACCORD_HOLDER,
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("#548 step la-reg: {e}")))?;
        let lc_id = uuid::Uuid::new_v4().to_string();
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: signed_trust_attestation(
                    &lc_id,
                    &la,
                    &canonical,
                    attestation_type::SCORES,
                    json!({
                        "id": lc_id,
                        "dimension": crate::federation::trust_root::ACCORD_HEARTBEAT_DIMENSION,
                        "score": 1.0,
                        "confidence": 0.9,
                    }),
                ),
            })
            .await?;
        // — and the USER'S OWN trust edge, the deletable lever (leg 1).
        let edge_id = uuid::Uuid::new_v4().to_string();
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: signed_trust_attestation(
                    &edge_id,
                    &user,
                    &canonical,
                    attestation_type::DELEGATES_TO,
                    json!({
                        "id": edge_id,
                        // v23.0.0 (CIRISPersist#551 item 2) — the deletable
                        // un-trust lever, named so an operator can find it.
                        "dimension": crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
                        "scope": [INFRA_SERVE_SCOPE],
                    }),
                ),
            })
            .await?;

        // THE #548 ASSERTION — the walk sees the ceremony conferral.
        let grant = capability_roots_to_trusted_root_over_roster(
            directory,
            &user,
            &canonical,
            INFRA_SERVE_SCOPE,
            &roster,
        )
        .await?
        .unwrap_or_else(|| {
            panic!(
                "({tag}) #548: a 2-of-3 accord co-scrub conferring {INFRA_SERVE_SCOPE} inside \
                 the registration_envelope, plus the user's own live trust chain, must satisfy \
                 the capability walk — the baked genesis seed is exactly this shape and today \
                 it roots to nothing"
            )
        });
        assert_eq!(
            grant.root_key_id, canonical,
            "({tag}) #548: the ceremony makes the subject ITSELF the root"
        );
        assert_eq!(
            grant.conferral_plane,
            ConferralPlane::AccordCoScrub,
            "({tag}) #548: the plane is named, not fused into the grant id"
        );

        // THE DRILL IS A SIGNAL, NOT A GATE (v23.0.0, CIRISPersist#551 item
        // 4) — pinned BOTH ways on every backend this parity body runs on.
        //
        // With the fresh drill this helper minted: valid, and the signal
        // reads Green.
        let drilled =
            crate::federation::trust_root::trust_root_valid(directory, &user, &canonical).await?;
        assert!(
            drilled.valid
                && drilled.drill_freshness == crate::federation::trust_root::DrillFreshness::Green,
            "({tag}) #551: a freshly-drilled root is valid and reads Green: {drilled:?}"
        );

        // Now REMOVE the drill (tombstone it — a withdrawn drill is not a
        // drill) and walk again. Before v23 this made `valid` go false and
        // took the whole mesh dark 90 days after any mint. It must now leave
        // service completely untouched and move only the SIGNAL.
        let drill_wd = uuid::Uuid::new_v4().to_string();
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: signed_trust_attestation(
                    &drill_wd,
                    &la,
                    &canonical,
                    attestation_type::WITHDRAWS,
                    json!({
                        "references_attestation_id": lc_id,
                        "withdrawal_reason": "#551 item 4: prove the drill does not gate",
                    }),
                ),
            })
            .await?;
        let undrilled =
            crate::federation::trust_root::trust_root_valid(directory, &user, &canonical).await?;
        assert!(
            undrilled.valid,
            "({tag}) #551 item 4: an UNDRILLED root must still serve — a root is valid until \
             revoked, halted, or un-trusted, and the deadman is gone: {undrilled:?}"
        );
        assert_eq!(
            undrilled.drill_freshness,
            crate::federation::trust_root::DrillFreshness::Red,
            "({tag}) #551 item 4: …and the signal says so — Red: {undrilled:?}"
        );
        assert_eq!(
            undrilled.last_drill_at, None,
            "({tag}) #551 item 4: never/no-longer drilled is carried by last_drill_at, which is \
             why Red needs no fourth variant: {undrilled:?}"
        );
        // The capability walk agrees: an undrilled root still confers.
        assert!(
            capability_roots_to_trusted_root_over_roster(
                directory,
                &user,
                &canonical,
                INFRA_SERVE_SCOPE,
                &roster,
            )
            .await?
            .is_some(),
            "({tag}) #551 item 4: the serve gate must not consult the drill"
        );

        // THE LEVER — withdraw the user's one edge; trust must collapse,
        // emergent, with the co-scrub still fully valid. This is what a real
        // gate looks like, and it is the contrast the drill assertions above
        // exist to draw.
        let wd_id = uuid::Uuid::new_v4().to_string();
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: signed_trust_attestation(
                    &wd_id,
                    &user,
                    &canonical,
                    attestation_type::WITHDRAWS,
                    json!({
                        "references_attestation_id": edge_id,
                        "withdrawal_reason": "operator un-trust: the one-row lever (#548)",
                    }),
                ),
            })
            .await?;
        let after = capability_roots_to_trusted_root_over_roster(
            directory,
            &user,
            &canonical,
            INFRA_SERVE_SCOPE,
            &roster,
        )
        .await?;
        assert!(
            after.is_none(),
            "({tag}) #548: deleting the user's ONE delegates_to edge must collapse trust — \
             the un-trust lever is the property the corrected ask exists to protect: {after:?}"
        );

        // NEGATIVES — candidacy is EARNED:
        // (a) a 1-of-3 scrub is not a quorum, so no candidate…
        let weak = format!("{tag}-one-scrub");
        // Scrubbed by a REGISTERED holder (ch0, from the roster above): the
        // point of this negative is the missing QUORUM, and sqlite's
        // scrub_key_id FK would otherwise refuse the row for the wrong
        // reason — an unregistered scrubber (the #534 DENY-FK trap; memory
        // tolerates it, which is exactly the parity gap that class named).
        let record = signed_canonical_record_with_roles(
            &weak,
            crate::federation::types::identity_type::NODE,
            PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            vec![INFRA_SERVE_SCOPE.to_owned()],
            json!({ "key_id": weak, "conferred_by": tag }),
            &[&holders[0]],
        );
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record })
            .await?;
        assert!(
            capability_roots_to_trusted_root_over_roster(
                directory,
                &user,
                &weak,
                INFRA_SERVE_SCOPE,
                &roster
            )
            .await?
            .is_none(),
            "({tag}) #548: ONE scrub is not an accord quorum — no candidate"
        );
        // (b) …and a quorum conferring a DIFFERENT scope confers nothing here.
        let other = format!("{tag}-other-scope");
        confer_roles(directory, &other, &["infra:store"], &format!("{tag}-os")).await?;
        assert!(
            capability_roots_to_trusted_root_over_roster(
                directory,
                &user,
                &other,
                INFRA_SERVE_SCOPE,
                &roster
            )
            .await?
            .is_none(),
            "({tag}) #548: the co-scrub confers the roles it NAMES, nothing more"
        );
        Ok(())
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
    /// 3. a fresh heartbeat (`accord:lifecycle:v1`) `scores` row ABOUT `root`, emitted by a
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
    /// self-declaration charter, the reserved heartbeat witness, and
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
                // v23.0.0 (CIRISPersist#551 item 2) — R → R: the charter.
                "dimension": crate::federation::trust_root::TRUST_CHARTER_DIMENSION,
                "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
                "pre_rotation_commitment": commitment,
            }),
        );
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: charter,
            })
            .await?;

        // Leg 3 — the fresh heartbeat row ABOUT the root, from the
        // accord_holder (the reserved-family leg a consumer cannot produce).
        let lc_id = uuid::Uuid::new_v4().to_string();
        let lifecycle = signed_trust_attestation(
            &lc_id,
            &la,
            root_key_id,
            attestation_type::SCORES,
            json!({
                "id": lc_id,
                "dimension": crate::federation::trust_root::ACCORD_HEARTBEAT_DIMENSION,
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
        // root self-declares AND the drill it just minted landed GREEN.
        // (edge_exists is legitimately false here — leg 1 is the caller's to
        // emit — so we probe the root-only legs with a throwaway user id.) A
        // helper that returns Ok must have actually done what it claims.
        //
        // v23.0.0 (CIRISPersist#551 item 4) — the drill check here is now an
        // assertion about THIS HELPER's emission, not about the root's
        // validity: a red-drilled root is perfectly valid (the deadman is
        // gone), but a helper that promised to mint a fresh drill and did
        // not has failed its contract, and that must still surface.
        let probe = crate::federation::trust_root::trust_root_valid(
            directory,
            "__side_probe__",
            root_key_id,
        )
        .await?;
        let drilled = probe.drill_freshness == crate::federation::trust_root::DrillFreshness::Green;
        if !(probe.root_self_declares && drilled) {
            return Err(crate::federation::Error::Backend(format!(
                "establish_trust_root_side postcondition NOT met for root={root_key_id}: \
                 root_self_declares={} drill_freshness={:?} — the charter or the drill this \
                 helper mints did not admit",
                probe.root_self_declares, probe.drill_freshness
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
                // v23.0.0 (CIRISPersist#551 item 2) — node → R: the trust
                // edge, named.
                "dimension": crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
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
        use crate::federation::admission::has_accord_conferred_role_over_roster;

        let canon = format!("{tag}-canon");
        // ALLOW: the honest 2-of-3 dance confers infra:serve.
        let roster = confer_roles(directory, &canon, &["infra:serve"], tag)
            .await
            .expect("confer_roles admits the co-scrubbed canonical");
        assert!(
            has_accord_conferred_role_over_roster(directory, &canon, "infra:serve", &roster)
                .await
                .expect("has_accord_conferred_role read"),
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
            PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            vec!["infra:serve".to_owned()],
            json!({ "key_id": self_id }),
            &[&self_scrubber],
        );
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record: self_only })
            .await
            .expect("self-scrubbed record still stores");
        assert!(
            !has_accord_conferred_role_over_roster(directory, &self_id, "infra:serve", &roster)
                .await
                .expect("has_accord_conferred_role read"),
            "({tag}) self-asserted infra:serve with no accord co-scrub reads FALSE"
        );
    }

    /// v21.15.0 (CIRISPersist#536) — the backend-agnostic TRUST-ROOT parity
    /// body: prove [`establish_trust_root`] stands up a root that
    /// [`crate::federation::trust_root::trust_root_valid`] accepts (all four
    /// legs) AND that the subject's `infra:serve` roots to it via
    /// [`crate::federation::trust_root::capability_roots_to_trusted_root`] (leg
    /// B). Run from the memory, sqlite AND postgres backend tests — the leg 3
    /// (the `accord:lifecycle:v1` heartbeat) reserved-family emission and the federation-tier
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

        // `ConferralPlane::Delegation`: the subject's infra:serve roots to a
        // root THIS user trusts.
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

    /// v24.0.0 (CIRISPersist#556) — a federation-tier attestation really signed
    /// by `attester` AND co-signed by each of `cosigners` over the **same**
    /// canonical envelope bytes.
    ///
    /// Scrub #1 fills the base `scrub_key_id`/`scrub_signature_*` fields; scrubs
    /// #2..N ride `additional_scrubs`. Every co-signer must be registered with
    /// its deterministic `sign_envelope` pubkeys ([`register_typed_key`]), since
    /// both federation-tier ingest and the family-quorum count resolve each
    /// scrub key from the DIRECTORY.
    fn co_signed_trust_attestation(
        id: &str,
        attester: &str,
        attested: &str,
        attestation_type: &str,
        envelope: serde_json::Value,
        cosigners: &[&str],
    ) -> crate::federation::Attestation {
        let mut row =
            signed_trust_attestation(id, attester, attested, attestation_type, envelope.clone());
        // v31.0.0 (CIRISPersist#643) — the co-signers sign the SEALED envelope,
        // i.e. the one `signed_trust_attestation` just stamped the typed-column
        // mirror into. Every scrub is over the SAME preimage (#556), and the
        // mirror is part of that preimage now.
        let envelope = row.attestation_envelope.clone();
        row.additional_scrubs = cosigners
            .iter()
            .map(|k| {
                let (_, classical, pqc) =
                    crate::federation::tier_ingest::test_support::sign_envelope(k, &envelope);
                crate::federation::types::ScrubSig {
                    scrub_key_id: (*k).to_owned(),
                    scrub_signature_classical: classical,
                    scrub_signature_pqc: pqc,
                }
            })
            .collect();
        row
    }

    /// v24.0.0 (CIRISPersist#557) — seed a KEYLESS constitutional family with
    /// `holders` seated as founders under `consensus_protocol`, on any backend.
    ///
    /// Written through `put_family_local` because a family has no key and
    /// therefore cannot sign its own declaration — the same door
    /// [`crate::federation::genesis::seed_accord_family`] uses for
    /// `humanity-accord`. The holders must already be registered.
    pub async fn seed_test_family(
        directory: &dyn crate::federation::FederationDirectory,
        family_key_id: &str,
        holders: &[String],
        consensus_protocol: &str,
    ) -> Result<(), crate::federation::Error> {
        let founded_at: chrono::DateTime<chrono::Utc> = "2020-01-01T00:00:00Z"
            .parse()
            .expect("pinned family founding instant is valid RFC-3339");
        let family = crate::federation::types::Family {
            family_key_id: family_key_id.to_owned(),
            family_name: family_key_id.to_owned(),
            members: holders
                .iter()
                .map(|k| crate::federation::types::FamilyMember {
                    key_id: k.clone(),
                    joined_at: founded_at,
                    role: Some("founder".to_owned()),
                })
                .collect(),
            founded_at,
            consensus_protocol: consensus_protocol.to_owned(),
            consensus_protocol_entrenched: true,
            persist_row_hash: String::new(),
        };
        directory.put_family_local(family).await
    }

    /// v36.2.0 (CIRISPersist#713) — **relay eligibility for an `accord:*`
    /// object: seated signer AND a live edge from THIS node.**
    ///
    /// Four legs, because each is a different way to be wrong:
    ///
    /// - **A** seated signer + live edge → relay.
    /// - **B** seated signer, NO edge → refuse. CC 4.2.1: *"a node that never
    ///   trusted the accord … is simply not reached."* A node that never
    ///   granted the root has no business carrying its traffic — this is the
    ///   leg a `Global` projection would have run over.
    /// - **C** live edge, signer NOT seated → refuse. Trusting a root does not
    ///   make every key that names it authoritative.
    /// - **D** a root this node holds no family for → `roster_resolvable:
    ///   false`, refuse. *"I cannot judge"* is distinct from *"not seated"*,
    ///   and both refuse — but an operator must be able to tell them apart.
    ///
    /// v36.3.0 (CIRISPersist#731) adds **E**, the object's root beating a
    /// caller's nomination; v37.0.0 (CIRISPersist#733) adds **F** (the
    /// ATTESTATION plane — the row names its own accord) and **G** (the write
    /// door that makes it required). Each F/G leg builds its trap and asserts
    /// the trap is REACHABLE before disproving it, because a leg whose
    /// permissive alternative already refused proves nothing.
    pub async fn exercise_accord_relay_eligibility(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::trust_root::{
            active_roster_of, may_relay_accord_attestation, may_relay_accord_object,
            may_relay_accord_participation, ACCORD_HEARTBEAT_DIMENSION,
        };
        use crate::federation::types::{attestation_type, identity_type};

        let accord = format!("{tag}-relay-accord");
        let relayer = format!("{tag}-relay-node");
        let stranger = format!("{tag}-relay-stranger");
        let outsider = format!("{tag}-relay-outsider");
        let holders: Vec<String> = (0..3).map(|i| format!("{tag}-relay-h{i}")).collect();

        for who in holders.iter().chain([&relayer, &stranger, &outsider]) {
            register_typed_key(directory, who, identity_type::NODE).await?;
        }
        seed_test_family(directory, &accord, &holders, "quorum:2/3").await?;

        // The roster resolves, revocation-folded, WITHOUT a caller supplying it.
        let roster = active_roster_of(directory, &accord)
            .await?
            .expect("a seeded family must resolve its own roster");
        assert_eq!(roster.len(), holders.len(), "({tag}) roster size");
        for h in &holders {
            assert!(roster.contains(h), "({tag}) {h} must be seated");
        }

        // (B) seated signer, but this node has NOT granted the root.
        let before = may_relay_accord_object(directory, &relayer, &holders[0], &accord).await?;
        assert!(before.signer_seated, "({tag}) B: signer is seated");
        assert!(!before.edge_exists, "({tag}) B: no edge yet");
        assert!(
            !before.may_relay(),
            "({tag}) B: a node that never granted the root must NOT relay its traffic \
             (CC 4.2.1 — simply not reached)"
        );

        emit_trust_edge(directory, &relayer, &accord, None).await?;

        // (A) seated signer + live edge.
        let ok = may_relay_accord_object(directory, &relayer, &holders[0], &accord).await?;
        assert!(
            ok.may_relay(),
            "({tag}) A: seated signer + live edge relays"
        );

        // (C) live edge, unseated signer.
        let unseated = may_relay_accord_object(directory, &relayer, &stranger, &accord).await?;
        assert!(unseated.edge_exists, "({tag}) C: edge still live");
        assert!(!unseated.signer_seated, "({tag}) C: stranger is not seated");
        assert!(
            !unseated.may_relay(),
            "({tag}) C: trusting a root does not make every key naming it authoritative"
        );

        // (D) a root this node holds no family for — unjudgeable, and DISTINCT
        // from an empty roster.
        let unknown = format!("{tag}-relay-unknown-root");
        assert!(
            active_roster_of(directory, &unknown).await?.is_none(),
            "({tag}) D: an unheld root resolves None, never Some(vec![])"
        );
        let cannot_judge =
            may_relay_accord_object(directory, &relayer, &outsider, &unknown).await?;
        assert!(
            !cannot_judge.roster_resolvable,
            "({tag}) D: roster_resolvable must say I-cannot-judge"
        );
        assert!(!cannot_judge.may_relay(), "({tag}) D: fail closed");

        // (E) v36.3.0 (#731) — THE OBJECT'S ROOT WINS, not a caller's.
        //
        // Build the permissive trap deliberately: a SECOND accord this node
        // also trusts, whose roster ALSO seats the signer. Under the
        // caller-supplied form, nominating that second root returns
        // may_relay() == true for a participation that belongs to the first —
        // a confidently wrong answer in the permissive direction, which the
        // predicate cannot detect because it never sees the object.
        let other_accord = format!("{tag}-relay-accord-b");
        seed_test_family(directory, &other_accord, &holders, "quorum:2/3").await?;
        emit_trust_edge(directory, &relayer, &other_accord, None).await?;
        let nominated =
            may_relay_accord_object(directory, &relayer, &holders[0], &other_accord).await?;
        assert!(
            nominated.may_relay(),
            "({tag}) E: the trap must actually be reachable — if nominating the \
             wrong root already refused, this leg would prove nothing"
        );

        // The object names accord A and a signer seated on it: relayable, and
        // the verdict is reached WITHOUT the caller naming any root.
        let part = ciris_verify_core::accord_live_quorum::AccordParticipation {
            family_key_id: accord.clone(),
            proposal_digest: "0".repeat(64),
            member_id: holders[0].clone(),
            vote: ciris_verify_core::accord_live_quorum::Vote::Yes,
            window_until: "2030-01-01T00:00:00Z".to_owned(),
            signed_at: "2026-01-01T00:00:00Z".to_owned(),
            signature: ciris_verify_core::threshold::ThresholdSignature {
                member_id: holders[0].clone(),
                ed25519_signature_base64: String::new(),
                mldsa65_signature_base64: None,
            },
        };
        let from_object = may_relay_accord_participation(directory, &relayer, &part).await?;
        assert!(
            from_object.may_relay(),
            "({tag}) E: an object naming a root this node granted, signed by a \
             seated member, relays"
        );

        // And an object naming a root this node holds NO family for is
        // unjudgeable — even though the caller could have nominated one of the
        // two roots that would have passed.
        let mut foreign = part.clone();
        foreign.family_key_id = format!("{tag}-relay-unknown-root");
        let unjudgeable = may_relay_accord_participation(directory, &relayer, &foreign).await?;
        assert!(
            !unjudgeable.roster_resolvable,
            "({tag}) E: the OBJECT's root decides judgeability, not the caller's"
        );
        assert!(!unjudgeable.may_relay(), "({tag}) E: fail closed");

        // ── (F) v37.0.0 (#733) — THE ATTESTATION PLANE ──────────────────
        //
        // The plane edge's relay gate actually serves. An `accord:*` row did
        // not name its own accord and `attested_key_id` cannot be made to (it
        // holds the scored agent, the self-attesting holder, or the accord,
        // depending on dimension), so the root now rides the SIGNED envelope
        // under `accord_root`, with the drill dimension's standing rule as the
        // one documented fallback.
        let accord_scores_dimension = "accord:human_dignity:v1";
        let drill_envelope = |id: &str, root: Option<&str>| {
            let mut env = json!({
                "id": id,
                "dimension": ACCORD_HEARTBEAT_DIMENSION,
                "score": 1.0,
                "confidence": 0.9,
            });
            if let Some(r) = root {
                env["accord_root"] = json!(r);
            }
            env
        };

        // (F1) THE SIGNED KEY DECIDES, not `attested_key_id`.
        //
        // The trap: a NON-drill row whose `attested_key_id` names the second
        // accord — which this node trusts and whose roster seats the signer —
        // while its signed envelope names a root this node holds no family for.
        // A resolver that reached for the column on a non-drill dimension would
        // answer `may_relay() == true`, which is #731's confidently-wrong
        // permissive answer wearing the attestation plane's clothes.
        assert!(
            may_relay_accord_object(directory, &relayer, &holders[0], &other_accord)
                .await?
                .may_relay(),
            "({tag}) F1: the trap must be reachable — if the column's root already \
             refused, this leg would prove nothing"
        );
        let f1_id = uuid::Uuid::new_v4().to_string();
        let mislabelled = signed_trust_attestation(
            &f1_id,
            &holders[0],
            &other_accord,
            attestation_type::SCORES,
            json!({
                "id": f1_id,
                "dimension": accord_scores_dimension,
                "score": 1.0,
                "confidence": 0.9,
                "accord_root": unknown,
            }),
        );
        let f1 = may_relay_accord_attestation(directory, &relayer, &mislabelled).await?;
        assert!(
            !f1.roster_resolvable && !f1.may_relay(),
            "({tag}) F1: the SIGNED `accord_root` decides, never `attested_key_id` \
             (got {f1:?})"
        );

        // (F2) THE CARRIAGE #733 BUYS: a non-drill `accord:*` row that names
        // its accord relays. Before this cut the resolver had no answer for any
        // dimension but the drill, so an enforcing node carried none of these.
        let f2_id = uuid::Uuid::new_v4().to_string();
        let scored = signed_trust_attestation(
            &f2_id,
            &holders[0],
            &stranger,
            attestation_type::SCORES,
            json!({
                "id": f2_id,
                "dimension": accord_scores_dimension,
                "score": 1.0,
                "confidence": 0.9,
                "accord_root": accord,
            }),
        );
        assert!(
            may_relay_accord_attestation(directory, &relayer, &scored)
                .await?
                .may_relay(),
            "({tag}) F2: a non-drill accord row naming its own accord, signed by a \
             seated holder, RELAYS"
        );

        // (F3) The drill rule remains the documented fallback: no key, and the
        // row still carries.
        let f3_id = uuid::Uuid::new_v4().to_string();
        let drill = signed_trust_attestation(
            &f3_id,
            &holders[0],
            &accord,
            attestation_type::SCORES,
            drill_envelope(&f3_id, None),
        );
        assert!(
            may_relay_accord_attestation(directory, &relayer, &drill)
                .await?
                .may_relay(),
            "({tag}) F3: an `accord:lifecycle:v1` row about X is a drill about accord \
             X by persist's OWN fold — the fallback still carries it"
        );

        // (F4) THE DUAL-SIGNAL RULE. A drill carrying BOTH signals, disagreeing.
        //
        // Both named roots are trusted here and both rosters seat the signer,
        // so preferring EITHER signal silently would answer `may_relay() ==
        // true`. Both preferences are asserted reachable, so the refusal below
        // can only come from the disagreement itself.
        assert!(
            may_relay_accord_object(directory, &relayer, &holders[0], &accord)
                .await?
                .may_relay(),
            "({tag}) F4: preferring the COLUMN's root would have admitted"
        );
        assert!(
            may_relay_accord_object(directory, &relayer, &holders[0], &other_accord)
                .await?
                .may_relay(),
            "({tag}) F4: preferring the KEY's root would have admitted"
        );
        let f4_id = uuid::Uuid::new_v4().to_string();
        let two_roots = signed_trust_attestation(
            &f4_id,
            &holders[0],
            &accord,
            attestation_type::SCORES,
            drill_envelope(&f4_id, Some(&other_accord)),
        );
        let f4 = may_relay_accord_attestation(directory, &relayer, &two_roots).await?;
        assert!(
            !f4.roster_resolvable && !f4.may_relay(),
            "({tag}) F4: ONE ARTIFACT ASSERTING TWO roots is refused, not resolved \
             toward whichever signal a reader prefers (got {f4:?})"
        );

        // (F5) …and AGREEMENT admits, or F4's refusal could be firing for any
        // other reason the fixture happens to carry.
        let f5_id = uuid::Uuid::new_v4().to_string();
        let agreeing = signed_trust_attestation(
            &f5_id,
            &holders[0],
            &accord,
            attestation_type::SCORES,
            drill_envelope(&f5_id, Some(&accord)),
        );
        assert!(
            may_relay_accord_attestation(directory, &relayer, &agreeing)
                .await?
                .may_relay(),
            "({tag}) F5: the two signals AGREEING admits — the drill rule became a \
             CHECK, not something the new field obsoletes"
        );

        // (F6) AN ATTACKER DOES NOT PICK THE SIGNER either. `attesting_key_id`
        // is an unsigned column; relaying is exactly when a node handles a row
        // it never admitted, so the verb runs `check_row_column_binding` first
        // and reads the signer only once it is proven equal to the signed
        // mirror. #731 was "an attacker picks the root"; this is its sibling.
        let f6_id = uuid::Uuid::new_v4().to_string();
        let unseated_signer = signed_trust_attestation(
            &f6_id,
            &stranger,
            &accord,
            attestation_type::SCORES,
            drill_envelope(&f6_id, Some(&accord)),
        );
        let f6_base = may_relay_accord_attestation(directory, &relayer, &unseated_signer).await?;
        assert!(
            f6_base.roster_resolvable && !f6_base.signer_seated && !f6_base.may_relay(),
            "({tag}) F6: baseline — the stranger's own row is JUDGEABLE and refused \
             for the right reason (got {f6_base:?})"
        );
        let mut relabelled = unseated_signer.clone();
        relabelled.attesting_key_id = holders[0].clone();
        let f6 = may_relay_accord_attestation(directory, &relayer, &relabelled).await?;
        assert!(
            !f6.roster_resolvable && !f6.may_relay(),
            "({tag}) F6: relabelling the UNSIGNED `attesting_key_id` to a seated \
             holder must not buy carriage — the mirror binds the signer (got {f6:?})"
        );

        // ── (G) v37.0.0 (#733) — THE WRITE DOOR ─────────────────────────
        //
        // `check_accord_root_binding` runs inside
        // `check_reserved_prefix_admission`, which every backend's
        // `put_attestation` and the promote door call — so these legs exercise
        // the real door on memory, sqlite AND postgres, not the pure function.
        //
        // The door protects NEW rows only; the stored corpus is covered by the
        // CONSUMER's enforcement flag. Complementary, never redundant.
        let la = format!("{tag}-relay-la");
        register_typed_key(directory, &la, identity_type::ACCORD_HOLDER).await?;
        let subject = format!("{tag}-relay-subject");
        register_typed_key(directory, &subject, identity_type::NODE).await?;

        // (G1) REQUIRED: a non-drill `accord:*` row that names no accord is
        // refused, and no row leaks through.
        let g1_id = uuid::Uuid::new_v4().to_string();
        let g1 = signed_trust_attestation(
            &g1_id,
            &la,
            &subject,
            attestation_type::SCORES,
            json!({
                "id": g1_id,
                "dimension": accord_scores_dimension,
                "score": 1.0,
                "confidence": 0.9,
            }),
        );
        let err = directory
            .put_attestation(crate::federation::SignedAttestation { attestation: g1 })
            .await
            .expect_err("({tag}) G1: an accord:* row naming no accord must be REFUSED");
        assert_eq!(
            err.kind(),
            "federation_accord_root_unnamed",
            "({tag}) G1: {err}"
        );
        assert!(
            directory.list_attestations_for(&subject).await?.is_empty(),
            "({tag}) G1: the refused row must not have landed"
        );

        // (G2) …and the SAME row carrying the key admits, so G1's refusal is
        // about the key and about nothing else in the fixture.
        let g2_id = uuid::Uuid::new_v4().to_string();
        let g2 = signed_trust_attestation(
            &g2_id,
            &la,
            &subject,
            attestation_type::SCORES,
            json!({
                "id": g2_id,
                "dimension": accord_scores_dimension,
                "score": 1.0,
                "confidence": 0.9,
                "accord_root": accord,
            }),
        );
        directory
            .put_attestation(crate::federation::SignedAttestation { attestation: g2 })
            .await?;
        assert_eq!(
            directory.list_attestations_for(&subject).await?.len(),
            1,
            "({tag}) G2: the same row NAMING its accord admits"
        );

        // (G3) The drill fallback admits with no key at all.
        let g3_id = uuid::Uuid::new_v4().to_string();
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: signed_trust_attestation(
                    &g3_id,
                    &la,
                    &accord,
                    attestation_type::SCORES,
                    drill_envelope(&g3_id, None),
                ),
            })
            .await?;

        // (G4) THE DUAL-SIGNAL REFUSAL at the door: a drill naming two accords.
        let g4_id = uuid::Uuid::new_v4().to_string();
        let err = directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: signed_trust_attestation(
                    &g4_id,
                    &la,
                    &accord,
                    attestation_type::SCORES,
                    drill_envelope(&g4_id, Some(&other_accord)),
                ),
            })
            .await
            .expect_err("({tag}) G4: a drill naming TWO accords must be REFUSED");
        assert_eq!(
            err.kind(),
            "federation_accord_root_disagrees",
            "({tag}) G4: {err}"
        );

        // (G5) …and an AGREEING drill admits, so G4 is not firing for some
        // other property of the fixture.
        let g5_id = uuid::Uuid::new_v4().to_string();
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: signed_trust_attestation(
                    &g5_id,
                    &la,
                    &accord,
                    attestation_type::SCORES,
                    drill_envelope(&g5_id, Some(&accord)),
                ),
            })
            .await?;

        Ok(())
    }

    /// v24.0.0 (CIRISPersist#557) — **the family trust root, end to end, on any
    /// backend.** The mesh's root authority is a THRESHOLD, and this body is the
    /// proof.
    ///
    /// The scenario is the accord's own shape: three seated holders under
    /// `quorum:2/3`, a family that holds no key, and a node that trusts the
    /// FAMILY rather than whichever holder happened to sign.
    ///
    /// | # | witness | what it pins |
    /// |---|---|---|
    /// | a | a 1-of-3-signed charter is REFUSED, naming "1 of 2 required distinct holders" | the shortfall is loud and countable, not a silent downgrade |
    /// | d | 2-of-3 charter + 2-of-3 grant + the node's edge ⇒ the walk returns the FAMILY as root | the family root actually confers |
    /// | b | one seat alone cannot re-root, cannot re-grant, and cannot hold the charter leg once its co-signer leaves the roster | the A1-compromise scenario, which is the whole issue |
    /// | e | the family's drill reports, and the family's HALT LATCH gates | kill switch and root are finally the same object |
    ///
    /// Witness (c) — a solo 1-of-1 key root still valid end to end — is
    /// [`exercise_trust_root`], deliberately left untouched: it passing
    /// unchanged IS the portability witness.
    pub async fn exercise_family_trust_root(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::trust_root::{
            capability_roots_to_trusted_root, trust_root_valid, ConferralPlane, DrillFreshness,
            RootKind, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE, TRUST_ACCEPTS_DIMENSION,
            TRUST_CHARTER_DIMENSION, TRUST_CONFERS_DIMENSION,
        };
        use crate::federation::types::{attestation_type, identity_type};

        let accord = format!("{tag}-accord");
        let user = format!("{tag}-user");
        let subject = format!("{tag}-subject");
        let holders: Vec<String> = (0..3).map(|i| format!("{tag}-h{i}")).collect();

        // The cast, registered with their deterministic `sign_envelope` pubkeys
        // so every signature below resolves at the ingest gate on EVERY backend.
        for who in holders.iter().chain([&user, &subject]) {
            register_typed_key(directory, who, identity_type::NODE).await?;
        }
        seed_test_family(directory, &accord, &holders, "quorum:2/3").await?;

        let successors = vec![format!("{accord}-succ-a"), format!("{accord}-succ-b")];
        let commitment = crate::federation::trust_root::pre_rotation_commitment(&successors)
            .map_err(|e| {
                crate::federation::Error::Backend(format!("#557 pre_rotation_commitment: {e}"))
            })?;
        let charter_envelope = |id: &str| {
            json!({
                "references_attestation_id": id,
                "dimension": TRUST_CHARTER_DIMENSION,
                "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
                "pre_rotation_commitment": commitment,
            })
        };

        // ── (a) RED — one seat cannot charter the accord ─────────────────
        // The row is well-formed, really signed, and names the family. It is
        // refused for the ONE reason that matters: it is a seat pretending to be
        // a threshold.
        let lone_id = uuid::Uuid::new_v4().to_string();
        let lone = co_signed_trust_attestation(
            &lone_id,
            &holders[0],
            &accord,
            attestation_type::DELEGATES_TO,
            charter_envelope(&lone_id),
            &[],
        );
        let refusal = directory
            .put_attestation(crate::federation::SignedAttestation { attestation: lone })
            .await
            .expect_err("(a) a 1-of-3-signed family charter must be REFUSED");
        assert_eq!(
            refusal.kind(),
            "federation_charter_invalid",
            "({tag}) (a) the refusal is TYPED, naming the failing leg: {refusal}"
        );
        assert!(
            refusal
                .to_string()
                .contains("1 of 2 required distinct holders"),
            "({tag}) (a) the refusal must NAME the shortfall — a ceremony operator has to \
             know whether they are one signature short or looking at the wrong family. Got: \
             {refusal}"
        );

        // ── (a2) a CO-SIGNATURE THE VERIFIER DOES NOT CHECK IS A CO-SIGNATURE
        // A WRITER MAY FORGE (CIRISPersist#556, the #541 class). A charter
        // carrying a corrupt second scrub must be refused at the SAME admission
        // boundary a corrupt BASE scrub is — otherwise `additional_scrubs` would
        // be stored-but-unverified and the quorum evidence would be free to
        // invent.
        let forged_id = uuid::Uuid::new_v4().to_string();
        let mut forged = co_signed_trust_attestation(
            &forged_id,
            &holders[0],
            &accord,
            attestation_type::DELEGATES_TO,
            charter_envelope(&forged_id),
            &[&holders[1]],
        );
        forged.additional_scrubs[0].scrub_signature_classical = {
            use base64::Engine as _;
            let mut raw = b64()
                .decode(&forged.additional_scrubs[0].scrub_signature_classical)
                .expect("our own co-signature is base64");
            raw[0] ^= 0xff;
            b64().encode(&raw)
        };
        let forged_err = directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: forged,
            })
            .await
            .expect_err("(a2) a corrupt co-signature must be REFUSED at ingest");
        assert_eq!(
            forged_err.kind(),
            "federation_federation_tier_unverified",
            "({tag}) (a2) every scrub is verified, not just the first: {forged_err}"
        );

        // …and on an ORDINARY row, where no charter gate stands behind the
        // verifier. This is the one that goes green-but-wrong if the ingest gate
        // ever stops walking the whole scrub set: the row would be STORED,
        // carrying a co-signature nobody checked, and every later reader that
        // counted scrubs would count a forgery.
        let plain_id = uuid::Uuid::new_v4().to_string();
        let mut plain = co_signed_trust_attestation(
            &plain_id,
            &holders[0],
            &subject,
            attestation_type::SCORES,
            json!({
                "id": plain_id,
                "dimension": "reputation:general:v1",
                "score": 0.5,
                "confidence": 0.9,
            }),
            &[&holders[1]],
        );
        plain.additional_scrubs[0].scrub_signature_classical = {
            use base64::Engine as _;
            let mut raw = b64()
                .decode(&plain.additional_scrubs[0].scrub_signature_classical)
                .expect("our own co-signature is base64");
            raw[0] ^= 0xff;
            b64().encode(&raw)
        };
        let plain_err = directory
            .put_attestation(crate::federation::SignedAttestation { attestation: plain })
            .await
            .expect_err("(a2) a corrupt co-signature is refused on ANY federation-tier row");
        assert_eq!(
            plain_err.kind(),
            "federation_federation_tier_unverified",
            "({tag}) (a2) the ingest verifier — not some downstream gate — is what covers \
             additional_scrubs: {plain_err}"
        );

        // ── (d) GREEN — the accord charters itself at 2-of-3 ─────────────
        let charter_id = uuid::Uuid::new_v4().to_string();
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: co_signed_trust_attestation(
                    &charter_id,
                    &holders[0],
                    &accord,
                    attestation_type::DELEGATES_TO,
                    charter_envelope(&charter_id),
                    &[&holders[1]],
                ),
            })
            .await?;

        // #556 STORAGE ROUND-TRIP, on whatever column encoding this backend
        // applies: the co-signature must come BACK, or the row proves 1-of-n
        // again the moment it is re-read (and every re-hashing write path would
        // then stamp a hash that disagrees with the stored row).
        let stored = directory
            .get_attestation(&charter_id)
            .await?
            .expect("(#556) the charter is readable");
        assert_eq!(
            stored.additional_scrubs.len(),
            1,
            "({tag}) #556: the 2nd scrub round-trips through this backend's storage"
        );
        assert_eq!(
            stored.additional_scrubs[0].scrub_key_id, holders[1],
            "({tag}) #556: …and it is the holder who actually co-signed"
        );
        assert_eq!(
            stored.distinct_scrub_count(),
            2,
            "({tag}) #556: the stored row proves its own 2-of-n"
        );

        // The conferral, ALSO at 2-of-3: a grant one seat could sign alone would
        // hand that seat the accord's granting pen, which is the asymmetry #557
        // exists to remove.
        let grant_id = uuid::Uuid::new_v4().to_string();
        let grant_envelope = json!({
            "references_attestation_id": grant_id,
            "dimension": TRUST_CONFERS_DIMENSION,
            "scope": [INFRA_SERVE_SCOPE],
        });
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: co_signed_trust_attestation(
                    &grant_id,
                    &holders[0],
                    &subject,
                    attestation_type::DELEGATES_TO,
                    grant_envelope,
                    &[&holders[1]],
                ),
            })
            .await?;

        // The node's own trust edge — naming the ACCORD, not a holder. This is
        // the row #557 is about, and the one an operator deletes to un-trust.
        let edge_id = uuid::Uuid::new_v4().to_string();
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: signed_trust_attestation(
                    &edge_id,
                    &user,
                    &accord,
                    attestation_type::DELEGATES_TO,
                    json!({
                        "references_attestation_id": edge_id,
                        "dimension": TRUST_ACCEPTS_DIMENSION,
                        "scope": [INFRA_SERVE_SCOPE],
                    }),
                ),
            })
            .await?;

        let verdict = trust_root_valid(directory, &user, &accord).await?;
        assert!(
            verdict.valid && verdict.root_kind == RootKind::Family,
            "({tag}) (d) a quorum-chartered family the node has accepted IS a valid trust \
             root: {verdict:?}"
        );
        let q = verdict
            .charter_quorum
            .expect("(d) a family verdict carries its quorum accounting");
        assert!(
            q.met() && q.distinct_holders == 2 && q.required == 2 && q.roster_size == 3,
            "({tag}) (d) the accounting is open, not a bare bool: {}",
            q.describe()
        );

        let grant = capability_roots_to_trusted_root(directory, &user, &subject, INFRA_SERVE_SCOPE)
            .await?
            .unwrap_or_else(|| {
                panic!(
                    "({tag}) (d) the subject's {INFRA_SERVE_SCOPE} must root to the ACCORD — a \
                     2-of-3 grant from a seated holder is a grant by the family"
                )
            });
        assert_eq!(
            grant.root_key_id, accord,
            "({tag}) (d) the winning root is the FAMILY, not the holder who signed"
        );
        assert_eq!(
            grant.conferral_plane,
            ConferralPlane::FamilyQuorum,
            "({tag}) (d) the plane is NAMED — one field with two silent value spaces is the \
             class this substrate keeps re-learning"
        );

        // ── (e) the drill reports; the family HALT LATCH gates ───────────
        let la = format!("{tag}-la");
        register_typed_key(directory, &la, identity_type::ACCORD_HOLDER).await?;
        let drill_id = uuid::Uuid::new_v4().to_string();
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: signed_trust_attestation(
                    &drill_id,
                    &la,
                    &accord,
                    attestation_type::SCORES,
                    json!({
                        "id": drill_id,
                        "dimension": crate::federation::trust_root::ACCORD_HEARTBEAT_DIMENSION,
                        "score": 1.0,
                        "confidence": 0.9,
                    }),
                ),
            })
            .await?;
        let drilled = trust_root_valid(directory, &user, &accord).await?;
        assert!(
            drilled.last_drill_at.is_some()
                && drilled.drill_freshness == DrillFreshness::Green
                && drilled.valid,
            "({tag}) (e) a drill ABOUT the family reports on the family root, and — v23.0.0 — \
             still does not gate: {drilled:?}"
        );

        // The kill switch and the root are finally the same object: before this
        // cut `get_active_halt` was handed a KEY id while the table is keyed by
        // FAMILY, so the accord's 2-of-3 brake could never reach the root it was
        // built to stop.
        let halt_id = format!("{tag}-halt-1");
        directory.set_active_halt(&accord, &halt_id).await?;
        let halted = trust_root_valid(directory, &user, &accord).await?;
        assert!(
            halted.halt_latched == Some(true) && !halted.valid,
            "({tag}) (e) the FAMILY halt latch stops the FAMILY root: {halted:?}"
        );
        assert!(
            capability_roots_to_trusted_root(directory, &user, &subject, INFRA_SERVE_SCOPE)
                .await?
                .is_none(),
            "({tag}) (e) …and the capability walk agrees — a halted root confers nothing"
        );
        directory.clear_active_halt(&accord, &halt_id).await?;
        assert!(
            trust_root_valid(directory, &user, &accord).await?.valid,
            "({tag}) (e) a resume un-fires the halt — the brake is a lever, not a door"
        );

        // ── (b) THE A1-COMPROMISE SCENARIO ───────────────────────────────
        // Assume holders[0]'s seat is fully owned by an attacker. It holds a real
        // key, it is genuinely seated, and it can sign anything it likes.
        //
        // (b1) it cannot RE-ROOT: a charter for a second "accord" it controls is
        // refused by the same quorum rule.
        let rogue = format!("{tag}-rogue-accord");
        seed_test_family(directory, &rogue, &holders, "quorum:2/3").await?;
        let rogue_charter_id = uuid::Uuid::new_v4().to_string();
        let rogue_err = directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: co_signed_trust_attestation(
                    &rogue_charter_id,
                    &holders[0],
                    &rogue,
                    attestation_type::DELEGATES_TO,
                    charter_envelope(&rogue_charter_id),
                    &[],
                ),
            })
            .await
            .expect_err("(b1) one compromised seat must not be able to charter a root");
        assert_eq!(rogue_err.kind(), "federation_charter_invalid");

        // (b2) it cannot RE-GRANT under the accord's name: a lone-signed
        // conferral onto a fresh subject yields no family candidate at all.
        let victim = format!("{tag}-victim");
        register_typed_key(directory, &victim, identity_type::NODE).await?;
        let lone_grant_id = uuid::Uuid::new_v4().to_string();
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: co_signed_trust_attestation(
                    &lone_grant_id,
                    &holders[0],
                    &victim,
                    attestation_type::DELEGATES_TO,
                    json!({
                        "references_attestation_id": lone_grant_id,
                        "dimension": TRUST_CONFERS_DIMENSION,
                        "scope": [INFRA_SERVE_SCOPE],
                    }),
                    &[],
                ),
            })
            .await?;
        assert!(
            capability_roots_to_trusted_root(directory, &user, &victim, INFRA_SERVE_SCOPE)
                .await?
                .is_none(),
            "({tag}) (b2) a conferral carrying ONE seat's signature roots to nothing — the \
             grant is stored, and it grants nothing"
        );

        // (b3) it cannot buy a quorum with signatures from OUTSIDE the roster.
        // A co-signature by a registered non-seat is a real signature over the
        // real bytes; it simply is not a HOLDER, so it counts toward nothing.
        let outsider = format!("{tag}-outsider");
        register_typed_key(directory, &outsider, identity_type::NODE).await?;
        let bought = format!("{tag}-bought-accord");
        seed_test_family(directory, &bought, &holders, "quorum:2/3").await?;
        let bought_id = uuid::Uuid::new_v4().to_string();
        let bought_err = directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: co_signed_trust_attestation(
                    &bought_id,
                    &holders[0],
                    &bought,
                    attestation_type::DELEGATES_TO,
                    charter_envelope(&bought_id),
                    &[&outsider],
                ),
            })
            .await
            .expect_err("(b3) a co-signature from outside the roster must not make a quorum");
        assert!(
            bought_err
                .to_string()
                .contains("1 of 2 required distinct holders"),
            "({tag}) (b3) the outsider's signature verifies and still counts for nothing: \
             {bought_err}"
        );

        // (b4) THE THRESHOLD IS RE-DERIVED AT READ TIME, FROM THIS NODE'S OWN
        // STATE — and it cannot be talked down. Grow the accord to five seats.
        // The family row still SAYS `quorum:2/3`; the node floors that at a
        // strict majority of the roster it actually holds, so the charter that
        // was quorate a moment ago stops being quorate — with no write to the
        // charter row, and nothing revoked.
        for i in 3..5 {
            let extra = format!("{tag}-h{i}");
            register_typed_key(directory, &extra, identity_type::NODE).await?;
            // v31.0.0 (CIRISPersist#654) — the roster grow carries an authority
            // signature over the GROWN envelope; the newcomer signs its own
            // admission here purely because it is the key this fixture just
            // registered.
            let member = crate::federation::types::FamilyMember {
                key_id: extra.clone(),
                joined_at: chrono::Utc::now(),
                role: Some("founder".to_owned()),
            };
            let spec = crate::federation::cohort::test_support::admit_family_via(
                directory, &extra, &accord, &member,
            )
            .await;
            directory.add_family_member(&accord, member, &spec).await?;
        }

        let after = trust_root_valid(directory, &user, &accord).await?;
        let aq = after
            .charter_quorum
            .expect("(b4) the family verdict still accounts for its quorum");
        assert!(
            !after.valid && !after.root_self_declares && !aq.met(),
            "({tag}) (b4) two of five seats is not a majority of the accord, so the root is \
             not chartered — re-derived, not frozen at admission: {after:?}"
        );
        assert!(
            aq.distinct_holders == 2 && aq.required == 3 && aq.roster_size == 5,
            "({tag}) (b4) the carried consensus_protocol still says quorum:2/3 and the node \
             requires 3 anyway — a tampered policy string cannot talk the threshold down: {}",
            aq.describe()
        );
        assert!(
            capability_roots_to_trusted_root(directory, &user, &subject, INFRA_SERVE_SCOPE)
                .await?
                .is_none(),
            "({tag}) (b4) …and the capability walk agrees — an un-chartered family confers \
             nothing"
        );
        Ok(())
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
    ///
    /// Backend-agnostic (memory/sqlite/postgres).
    pub async fn exercise_trust_root_real_user(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::trust_root::{
            capability_roots_to_trusted_root, trust_root_valid, DrillFreshness, INFRA_ATTEST_SCOPE,
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
            !va.edge_exists && va.root_self_declares && va.drill_freshness == DrillFreshness::Green,
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
            !vb0.valid
                && vb0.root_self_declares
                && vb0.drill_freshness == DrillFreshness::Green
                && !vb0.edge_exists,
            "({tag}) root side up, not yet valid without the user's edge — the missing leg is \
             the EDGE, a hard gate; the drill is green and would not have gated either way: \
             {vb0:?}"
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
                // v23.0.0 (CIRISPersist#551 item 2) — node → R.
                "dimension": crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
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

    /// v24.1.0 (CIRISPersist#561) — register `key_id` as a NODE that
    /// self-offers `infra:transport`, on any backend.
    ///
    /// The self-claim conjuncts (B) and (C) of the transit gate, and NOTHING
    /// else — which is the point of the AV-75 witness below: this alone must
    /// buy a peer nothing.
    async fn register_transport_node(
        directory: &dyn crate::federation::FederationDirectory,
        key_id: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::types::{delegation_scope, identity_type};
        let mut record = crate::federation::tier_ingest::test_support::replicated_key_record(
            key_id,
            identity_type::NODE,
            key_id,
            key_id,
            "transit",
        );
        record.capability_roles = vec![delegation_scope::INFRA_TRANSPORT.to_owned()];
        directory
            .put_public_key(crate::federation::SignedKeyRecord { record })
            .await
    }

    /// v24.1.0 (CIRISPersist#561) — emit a live `delegates_to(from → root)`
    /// `trust:accepts:v1` edge, really signed by `from`, optionally expiring.
    ///
    /// The un-trust lever and the TTL contributor in one row: this is the edge
    /// a withdrawal tombstones and the edge whose `expires_at` bounds the
    /// cached verdict.
    async fn emit_trust_edge(
        directory: &dyn crate::federation::FederationDirectory,
        from: &str,
        root: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<String, crate::federation::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut edge = signed_trust_attestation(
            &id,
            from,
            root,
            crate::federation::types::attestation_type::DELEGATES_TO,
            json!({
                "references_attestation_id": id,
                "dimension": crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
                "scope": [crate::federation::trust_root::INFRA_SERVE_SCOPE],
            }),
        );
        edge.expires_at = expires_at;
        // v31.0.0 (CIRISPersist#598) — `expires_at` is bound in BOTH
        // directions, so setting the COLUMN after the seal is exactly the
        // divergence the gate refuses. Re-seal: this helper's whole subject is
        // the TTL min-fold, and an edge whose expiry the signature does not
        // cover is an unsigned mute button on the bound it is testing.
        crate::federation::tier_ingest::test_support::reseal(&mut edge);
        directory
            .put_attestation(crate::federation::SignedAttestation { attestation: edge })
            .await?;
        Ok(id)
    }

    /// v24.1.0 (CIRISPersist#561) — tombstone `attestation_id` with a
    /// `withdraws` composer authored by `attester` (the CEG un-trust act).
    async fn withdraw_attestation(
        directory: &dyn crate::federation::FederationDirectory,
        attester: &str,
        subject: &str,
        attestation_id: &str,
    ) -> Result<(), crate::federation::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let row = signed_trust_attestation(
            &id,
            attester,
            subject,
            crate::federation::types::attestation_type::WITHDRAWS,
            json!({
                "id": id,
                "references_attestation_id": attestation_id,
            }),
        );
        directory
            .put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
    }

    /// **CIRISPersist#561 — transport-hop eligibility, end to end, on any
    /// backend.**
    ///
    /// The scenario is CIRISEdge#430's: a selecting node, a candidate relay,
    /// and a shared trust root neither of them owns. Each witness pins one
    /// clause of the rule.
    ///
    /// | # | witness | what it pins |
    /// |---|---|---|
    /// | a | unregistered user ⇒ `false` | fail-closed on the ASKING side, not just the peer's |
    /// | b | self-claimed `infra:transport`, no shared root ⇒ `false` | the AV-75 property: registering the string buys nothing |
    /// | c | all four legs ⇒ `true`, `via_root` names the root, TTL min-folds | the gate, and its authoritative cache bound |
    /// | d | each leg removed individually ⇒ `false` | every conjunct is load-bearing |
    /// | e | a hostile peer's 50 `delegates_to` rows change neither the verdict NOR the candidate set | the anti-inflation property |
    /// | f | withdraw the user's edge ⇒ `false` on the very next call | the event-driven invalidation contract's substrate half |
    /// | g | the `_over_roster` arm agrees with the default arm | the ceremony-parity entry point |
    pub async fn exercise_transit_eligibility(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::trust_root::{
            resolve_transit_eligibility, resolve_transit_eligibility_over_roster, INFRA_SERVE_SCOPE,
        };
        use crate::federation::types::identity_type;

        let user = format!("{tag}-user");
        let peer = format!("{tag}-peer");
        let root = format!("{tag}-root");
        let sink = format!("{tag}-sink");

        // ── (a) RED — an unregistered USER cannot be eligible for anything.
        // The peer does not exist yet either; what is pinned is that the walk
        // DENIES rather than erroring out of the caller's hands.
        let unknown = resolve_transit_eligibility(directory, &user, &peer).await?;
        assert!(
            !unknown.eligible && unknown.via_root.is_none() && unknown.valid_until.is_none(),
            "({tag}) (a) an unresolvable walk DENIES — a transport gate never fails open: \
             {unknown:?}"
        );

        register_transport_node(directory, &user).await?;
        register_transport_node(directory, &peer).await?;
        register_transport_node(directory, &sink).await?;

        // ── (b) THE AV-75 PROPERTY. Both sides now register the string
        // `infra:transport` and both are `node`s — conjuncts (A)(B)(C) all
        // hold — and there is still no shared root. Eligibility must be false,
        // or the gate is a self-declaration.
        let self_claimed = resolve_transit_eligibility(directory, &user, &peer).await?;
        assert!(
            !self_claimed.eligible,
            "({tag}) (b) self-claimed infra:transport with NO shared root buys NOTHING \
             (AV-75): {self_claimed:?}"
        );

        // The shared root: a real charter + drill, plus each side's own
        // `trust:accepts` edge. `establish_trust_root_side` stands up the root
        // half (the accord-reserved drill a consumer cannot mint itself).
        establish_trust_root_side(directory, &root, &sink, INFRA_SERVE_SCOPE).await?;
        let user_edge = emit_trust_edge(directory, &user, &root, None).await?;
        let peer_edge = emit_trust_edge(directory, &peer, &root, None).await?;

        // ── (c) GREEN — all four legs.
        let ok = resolve_transit_eligibility(directory, &user, &peer).await?;
        assert!(
            ok.eligible,
            "({tag}) (c) node + infra:transport + a shared valid root ⇒ eligible: {ok:?}"
        );
        assert_eq!(
            ok.via_root.as_deref(),
            Some(root.as_str()),
            "({tag}) (c) via_root NAMES the shared root — the caller's cache key"
        );
        assert!(
            ok.valid_until.is_none(),
            "({tag}) (c) nothing walked is time-bounded here, so the TTL is None (cache \
             until a withdrawal event) — NOT a fabricated finite value: {ok:?}"
        );

        // ── (g) the `_over_roster` arm. Driven with a roster the test HOLDS,
        // and it must agree with the default arm exactly — the entry point is
        // parity, not a second policy.
        let holders: Vec<String> = (0..3).map(|i| format!("{tag}-rh{i}")).collect();
        let over =
            resolve_transit_eligibility_over_roster(directory, &user, &peer, &holders).await?;
        assert_eq!(
            over, ok,
            "({tag}) (g) the _over_roster arm returns the SAME verdict — none of the four \
             conjuncts reads the ceremony plane, and the entry point must not invent one"
        );

        // ── (c2) TTL MIN-FOLD, from BOTH sides.
        //
        // Both edges must be finite for this to say anything: with one side
        // unbounded, min and max agree and a fold written the wrong way round
        // passes. (The first draft left the peer's original unbounded edge in
        // place and stayed green under a deliberate `min`→`max` swap.) So the
        // unbounded edges are withdrawn first, and the earliest bound is then
        // moved from one side to the other — a fold that always returned "our"
        // side, or "the first" side, fails the second half.
        let near = chrono::Utc::now() + chrono::Duration::hours(2);
        let far = chrono::Utc::now() + chrono::Duration::hours(9);
        withdraw_attestation(directory, &peer, &root, &peer_edge).await?;
        withdraw_attestation(directory, &user, &root, &user_edge).await?;
        let peer_far = emit_trust_edge(directory, &peer, &root, Some(far)).await?;
        let mut bounded_user_edge = emit_trust_edge(directory, &user, &root, Some(near)).await?;

        // OUR side is the earlier one.
        let bounded = resolve_transit_eligibility(directory, &user, &peer).await?;
        assert!(bounded.eligible, "({tag}) (c2) still eligible: {bounded:?}");
        let ttl = bounded
            .valid_until
            .unwrap_or_else(|| panic!("({tag}) (c2) a bounded edge MUST produce a bounded TTL"));
        assert!(
            (ttl - near).num_seconds().abs() <= 1,
            "({tag}) (c2) the EARLIEST bound wins: expected ~{near}, got {ttl}. The peer's \
             own edge expires at {far} and must not be what the caller caches to."
        );

        // THEIR side is the earlier one — same rule, other direction.
        withdraw_attestation(directory, &peer, &root, &peer_far).await?;
        withdraw_attestation(directory, &user, &root, &bounded_user_edge).await?;
        emit_trust_edge(directory, &peer, &root, Some(near)).await?;
        bounded_user_edge = emit_trust_edge(directory, &user, &root, Some(far)).await?;
        let flipped = resolve_transit_eligibility(directory, &user, &peer).await?;
        let flipped_ttl = flipped
            .valid_until
            .unwrap_or_else(|| panic!("({tag}) (c2) the flipped case is bounded too"));
        assert!(
            (flipped_ttl - near).num_seconds().abs() <= 1,
            "({tag}) (c2) the earliest bound wins whichever SIDE carries it: expected \
             ~{near} (the peer's), got {flipped_ttl}"
        );

        // ── (e) ANTI-INFLATION. A hostile peer authors fifty `trust:accepts`
        // edges to fifty roots we have never heard of, and neither the verdict
        // nor the WORK may grow.
        //
        // Three deliberate choices, each of which the first draft got wrong and
        // stayed green for:
        //
        // 1. The work is read from the REAL walk's own count of candidate roots
        //    evaluated. Re-deriving `transit_candidate_roots` in the test
        //    asserts the boundary's DEFINITION and says nothing about whether
        //    the walk honours it — that draft stayed green under a walk
        //    deliberately rewritten to enumerate the peer's edges too.
        // 2. The probe peer is INELIGIBLE, so the candidate loop runs to
        //    exhaustion. Against an eligible peer the walk short-circuits on
        //    the first matching root and the count is 1 no matter how inflated
        //    the set is — which is exactly the case an attacker would not
        //    bother with. The DoS shape is a candidate that never matches.
        // 3. The flood is authored by the peer being MEASURED. Inflation is
        //    peer-specific; flooding one peer and measuring another proves
        //    nothing.
        let flooded = format!("{tag}-flooded");
        register_transport_node(directory, &flooded).await?;
        let (before_verdict, walked_before) =
            crate::federation::trust_root::resolve_transit_eligibility_counting_roots(
                directory, &user, &flooded,
            )
            .await?;
        assert!(
            !before_verdict.eligible,
            "({tag}) (e) the probe peer shares no root, so the loop EXHAUSTS the candidate \
             set rather than short-circuiting: {before_verdict:?}"
        );
        assert_eq!(
            walked_before, 1,
            "({tag}) (e) the user trusts exactly one root, so exactly one candidate is walked"
        );
        for i in 0..50 {
            let bogus = format!("{tag}-bogus{i}");
            register_transport_node(directory, &bogus).await?;
            emit_trust_edge(directory, &flooded, &bogus, None).await?;
        }
        let (after_verdict, walked_after) =
            crate::federation::trust_root::resolve_transit_eligibility_counting_roots(
                directory, &user, &flooded,
            )
            .await?;
        assert_eq!(
            walked_after, walked_before,
            "({tag}) (e) 50 peer-authored edges did not add ONE unit of work (still \
             {walked_before}, not 51). The candidate set is bounded by the ASKING node's \
             own records; enumerating from the peer would let any peer set the cost of \
             evaluating it — on a per-substream hot path — for free."
        );
        assert!(
            !after_verdict.eligible,
            "({tag}) (e) …and fifty self-authored roots still buy the peer nothing: \
             {after_verdict:?}"
        );
        // The eligible peer's verdict is untouched by a sibling's flood.
        let after_flood = resolve_transit_eligibility(directory, &user, &peer).await?;
        assert_eq!(
            after_flood.via_root.as_deref(),
            Some(root.as_str()),
            "({tag}) (e) the real peer still roots through OUR root, not one of theirs"
        );

        // ── (d) EVERY CONJUNCT IS LOAD-BEARING.
        //
        // (d/A) a peer that is not in the directory at all.
        let absent = resolve_transit_eligibility(directory, &user, &format!("{tag}-ghost")).await?;
        assert!(
            !absent.eligible,
            "({tag}) (d/A) directory presence is required: {absent:?}"
        );

        // (d/B) a peer that is NOT a node — same trust root, same transport
        // claim, wrong identity_type.
        let agent = format!("{tag}-agent");
        let mut agent_rec = crate::federation::tier_ingest::test_support::replicated_key_record(
            &agent,
            identity_type::AGENT,
            &agent,
            &agent,
            "transit",
        );
        agent_rec.capability_roles =
            vec![crate::federation::types::delegation_scope::INFRA_TRANSPORT.to_owned()];
        directory
            .put_public_key(crate::federation::SignedKeyRecord { record: agent_rec })
            .await?;
        emit_trust_edge(directory, &agent, &root, None).await?;
        let not_a_node = resolve_transit_eligibility(directory, &user, &agent).await?;
        assert!(
            !not_a_node.eligible,
            "({tag}) (d/B) a non-`node` identity is not a hop, however it is rooted — node \
             mode is the verifiable recast of proxy/server mode: {not_a_node:?}"
        );

        // (d/C) a NODE, validly sharing our root, that never offered transport.
        let quiet = format!("{tag}-quiet");
        crate::federation::tier_ingest::test_support::register_identity_key(
            directory,
            &quiet,
            identity_type::NODE,
        )
        .await;
        emit_trust_edge(directory, &quiet, &root, None).await?;
        let no_offer = resolve_transit_eligibility(directory, &user, &quiet).await?;
        assert!(
            !no_offer.eligible,
            "({tag}) (d/C) a node that does not offer infra:transport is not a hop: \
             {no_offer:?}"
        );

        // (d/D) a peer with NO trust root of its own: its side of the overlap
        // is missing and eligibility goes with it, with no write on our side.
        let solo = format!("{tag}-solo");
        register_transport_node(directory, &solo).await?;
        let solo_ineligible = resolve_transit_eligibility(directory, &user, &solo).await?;
        assert!(
            !solo_ineligible.eligible,
            "({tag}) (d/D) a rooted-to-nothing peer shares no root with us: \
             {solo_ineligible:?}"
        );

        // ── (f) WITHDRAWAL — the invalidation contract's substrate half.
        // Delete the ONE `delegates_to(user → root)` edge and the very next
        // resolution reads false. Nothing is special-cased: (D) re-derives from
        // live graph state on every call, so the tombstone IS the mechanism.
        withdraw_attestation(directory, &user, &root, &bounded_user_edge).await?;
        let after_withdrawal = resolve_transit_eligibility(directory, &user, &peer).await?;
        assert!(
            !after_withdrawal.eligible,
            "({tag}) (f) withdrawing our own trust edge un-elects the peer on the NEXT \
             call — the operator's un-trust lever reaches the transport plane too: \
             {after_withdrawal:?}"
        );
        assert!(
            after_withdrawal.via_root.is_none() && after_withdrawal.valid_until.is_none(),
            "({tag}) (f) a denied verdict carries no root and no TTL — there is nothing for \
             a caller to cache: {after_withdrawal:?}"
        );

        // ── (e2) EXPIRY IS HONORED without any tombstone: an edge whose
        // `expires_at` has PASSED is as dead to the walk as a withdrawn one
        // (#488 delta 3), so a peer cannot ride a stale grant.
        let stale_root = format!("{tag}-stale-root");
        establish_trust_root_side(directory, &stale_root, &sink, INFRA_SERVE_SCOPE).await?;
        let past = chrono::Utc::now() - chrono::Duration::minutes(5);
        emit_trust_edge(directory, &user, &stale_root, Some(past)).await?;
        emit_trust_edge(directory, &peer, &stale_root, None).await?;
        let expired = resolve_transit_eligibility(directory, &user, &peer).await?;
        assert!(
            !expired.eligible,
            "({tag}) (e2) an EXPIRED shared-root edge is not a shared root — stale grants \
             die of age, no tombstone required: {expired:?}"
        );
        Ok(())
    }

    /// **CIRISPersist#561 — a shared FAMILY root satisfies (D) too.**
    ///
    /// The v24.0.0 finding was that the mesh's root authority is a THRESHOLD,
    /// not a seat, and the transport gate inherits that for free: conjunct (D)
    /// is `trust_root_valid` on both sides, and that predicate already chooses
    /// its own arm from the node's stored state. A relay hop can therefore be
    /// anchored on the ACCORD rather than on whichever holder happened to sign
    /// — which is the shape a production mesh actually has.
    ///
    /// Kept as its own body rather than a ninth witness inside
    /// **CIRISPersist#686 — a foreign, unentitled `withdraws` against a FAMILY
    /// CHARTER candidate.** Lifted verbatim from the #686 evidence thread
    /// (comment 5312289784), written to PASS once the consolidated fold
    /// carries an entitlement gate.
    ///
    /// The sibling witness
    /// (`ungated_doors_test_support::exercise_foreign_retraction_cannot_sever_conferral`)
    /// drives the conferral walk. This one drives `about_dead`, which filters
    /// the family-root CHARTER candidates **upstream of the quorum tally** —
    /// a retraction landing there does not merely unroot one edge: it thins
    /// the candidate set a quorum decision is computed over, before
    /// `family_quorum_over` ever counts a seat, and the operator-facing
    /// shortfall (#557's `distinct_holders: 0 of required`) then reads as a
    /// roster problem rather than an attack.
    ///
    /// The family arm reads the ABOUT set by construction — a family is
    /// keyless and cannot sign its own charter — so a foreign row is in
    /// scope by design, and no slice tightening can close this: only the
    /// fold's entitlement gate can. Cast and shape mirror
    /// [`exercise_transit_eligibility_family_root`] exactly, so any
    /// divergence is the retraction and not the fixture.
    ///
    /// Three legs, matching the conferral witness: CONTROL (chartered family,
    /// valid), LEG A (in-order foreign withdraws → write-door refusal, root
    /// stays valid — load-bearing), LEG B (out-of-order deferred window, then
    /// the charter lands — the root must still be valid).
    pub async fn exercise_foreign_retraction_cannot_sever_charter(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::trust_root::{
            trust_root_valid, RootKind, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE,
            TRUST_CHARTER_DIMENSION,
        };
        use crate::federation::types::{attestation_type, identity_type};

        let user = format!("{tag}-user");
        let foreign = format!("{tag}-foreign");
        let holders: Vec<String> = (0..3).map(|i| format!("{tag}-h{i}")).collect();

        for who in &holders {
            register_typed_key(directory, who, identity_type::NODE).await?;
        }
        register_typed_key(directory, &user, identity_type::NODE).await?;
        // The attacker is a registered, well-formed NODE holding no seat in
        // either family and no authority over either charter. Nothing about it
        // is malformed — only unentitled.
        register_typed_key(directory, &foreign, identity_type::NODE).await?;

        let build_charter = |accord: &str,
                             charter_id: &str|
         -> Result<
            crate::federation::Attestation,
            crate::federation::Error,
        > {
            let successors = vec![format!("{accord}-succ-a"), format!("{accord}-succ-b")];
            let commitment = crate::federation::trust_root::pre_rotation_commitment(&successors)
                .map_err(|e| {
                    crate::federation::Error::Backend(format!("#686 pre_rotation_commitment: {e}"))
                })?;
            Ok(co_signed_trust_attestation(
                charter_id,
                &holders[0],
                accord,
                attestation_type::DELEGATES_TO,
                json!({
                    "references_attestation_id": charter_id,
                    "dimension": TRUST_CHARTER_DIMENSION,
                    "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
                    "pre_rotation_commitment": commitment,
                }),
                &[&holders[1]],
            ))
        };
        let foreign_withdraws = |id: &str, target_id: &str, accord: &str| {
            signed_trust_attestation(
                id,
                &foreign,
                accord,
                attestation_type::WITHDRAWS,
                json!({
                    "references_attestation_id": target_id,
                    "dimension": "cw:charter-retract:v1",
                }),
            )
        };

        // ── CONTROL — a chartered family root, untouched. ────────────────────
        let accord_ctl = format!("{tag}-accord-ctl");
        seed_test_family(directory, &accord_ctl, &holders, "quorum:2/3").await?;
        let ctl_charter_id = format!("{tag}-charter-ctl");
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: build_charter(&accord_ctl, &ctl_charter_id)?,
            })
            .await?;
        emit_trust_edge(directory, &user, &accord_ctl, None).await?;

        let v = trust_root_valid(directory, &user, &accord_ctl).await?;
        assert_eq!(
            v.root_kind,
            RootKind::Family,
            "({tag}) CONTROL: this must be the keyless FAMILY arm — the key arm reads a \
             different slice and would not exercise `about_dead`: {v:?}"
        );
        assert!(
            v.valid,
            "({tag}) CONTROL: the chartered family root must be valid before any attack, or \
             the legs below prove nothing: {v:?}"
        );

        // ── LEG A — IN ORDER. The charter is already stored, so the write door
        //    can resolve authority and must REFUSE. This guard is the only
        //    thing making the read-side fold unreachable in the ordinary case.
        let inorder_id = format!("{tag}-inorder-withdraws");
        let err = directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: foreign_withdraws(&inorder_id, &ctl_charter_id, &accord_ctl),
            })
            .await
            .expect_err(
                "LEG A: with the charter PRESENT, an unentitled foreign `withdraws` must be \
                 refused at the write door",
            );
        assert!(
            matches!(err, crate::federation::Error::WithdrawsNotAdmitted { .. }),
            "({tag}) LEG A: expected WithdrawsNotAdmitted, got {err:?}"
        );
        let after_a = trust_root_valid(directory, &user, &accord_ctl).await?;
        assert!(
            after_a.valid,
            "({tag}) LEG A: a refused withdraws must leave the charter standing: {after_a:?}"
        );

        // ── LEG B — OUT OF ORDER, the deferred window. ────────────────────────
        //
        // `check_withdraws_admission` returns `Ok(None)` — admit, no rule —
        // when the target is "not locally present … defer authority to read
        // side". The read side is `tombstoned_ids`, which (pre-#686) never
        // re-checked it.
        let accord_atk = format!("{tag}-accord-atk");
        seed_test_family(directory, &accord_atk, &holders, "quorum:2/3").await?;
        let atk_charter_id = format!("{tag}-charter-atk");
        let early_id = format!("{tag}-early-withdraws");

        // The retraction lands FIRST, naming a charter that does not exist yet.
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: foreign_withdraws(&early_id, &atk_charter_id, &accord_atk),
            })
            .await?;
        let stored = directory
            .get_attestation(&early_id)
            .await?
            .expect("the early withdraws is stored");
        assert!(
            stored.withdraws_admission_rule.is_none(),
            "({tag}) LEG B measures the DEFERRED path — a stamped rule means the write door \
             resolved authority and this witness proves something else. Got {:?}",
            stored.withdraws_admission_rule
        );

        // NOW the charter arrives, and the family is chartered exactly as the
        // control is.
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: build_charter(&accord_atk, &atk_charter_id)?,
            })
            .await?;
        emit_trust_edge(directory, &user, &accord_atk, None).await?;

        let after_b = trust_root_valid(directory, &user, &accord_atk).await?;
        assert!(
            after_b.valid,
            "({tag}) #686 HOLE IS LIVE ON THE CHARTER PLANE: a `withdraws` from `{foreign}` — \
             holding no seat in the family, not the charter's attester, not one of its \
             subject_key_ids, carrying no admission rule, admitted only because it arrived \
             BEFORE its target — removed the family's ONLY charter candidate from \
             `charter_shaped` via trust_root::tombstoned_ids (`about_dead`), \
             so `family_quorum_over` never counted a seat. The quorum did not fail; it was \
             never reached. Verdict: {after_b:?}"
        );
        Ok(())
    }

    /// [`exercise_transit_eligibility`]: the cast is different (three seated
    /// holders and a keyless family instead of one key root), and the point is
    /// precisely that NOTHING in the transit walk is arm-aware. If this needed
    /// special-casing to pass, that would be the finding.
    pub async fn exercise_transit_eligibility_family_root(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::trust_root::{
            resolve_transit_eligibility, trust_root_valid, RootKind, INFRA_ATTEST_SCOPE,
            INFRA_SERVE_SCOPE, TRUST_CHARTER_DIMENSION,
        };
        use crate::federation::types::{attestation_type, identity_type};

        let accord = format!("{tag}-accord");
        let user = format!("{tag}-user");
        let peer = format!("{tag}-peer");
        let holders: Vec<String> = (0..3).map(|i| format!("{tag}-h{i}")).collect();

        for who in &holders {
            register_typed_key(directory, who, identity_type::NODE).await?;
        }
        register_transport_node(directory, &user).await?;
        register_transport_node(directory, &peer).await?;
        seed_test_family(directory, &accord, &holders, "quorum:2/3").await?;

        // The accord charters ITSELF at 2-of-3 — no seat can do it alone.
        let successors = vec![format!("{accord}-succ-a"), format!("{accord}-succ-b")];
        let commitment = crate::federation::trust_root::pre_rotation_commitment(&successors)
            .map_err(|e| {
                crate::federation::Error::Backend(format!("#561 pre_rotation_commitment: {e}"))
            })?;
        let charter_id = uuid::Uuid::new_v4().to_string();
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: co_signed_trust_attestation(
                    &charter_id,
                    &holders[0],
                    &accord,
                    attestation_type::DELEGATES_TO,
                    json!({
                        "references_attestation_id": charter_id,
                        "dimension": TRUST_CHARTER_DIMENSION,
                        "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
                        "pre_rotation_commitment": commitment,
                    }),
                    &[&holders[1]],
                ),
            })
            .await?;

        // Each side names THE ACCORD, not a holder.
        emit_trust_edge(directory, &user, &accord, None).await?;
        emit_trust_edge(directory, &peer, &accord, None).await?;

        let verdict = trust_root_valid(directory, &user, &accord).await?;
        assert_eq!(
            verdict.root_kind,
            RootKind::Family,
            "({tag}) the shared root really is the keyless family arm: {verdict:?}"
        );
        assert!(verdict.valid, "({tag}) …and it is valid: {verdict:?}");

        let eligible = resolve_transit_eligibility(directory, &user, &peer).await?;
        assert!(
            eligible.eligible,
            "({tag}) a shared FAMILY root satisfies (D) exactly as a key root does — the \
             transit walk is not arm-aware, and must not need to be: {eligible:?}"
        );
        assert_eq!(
            eligible.via_root.as_deref(),
            Some(accord.as_str()),
            "({tag}) via_root names the FAMILY — the cache key an accord-wide revocation \
             would invalidate"
        );

        // The THRESHOLD is still the gate underneath, and it is re-derived on
        // every call. Grow the accord to five seats: the family row still says
        // `quorum:2/3`, but the node floors that at a strict majority of the
        // roster it actually holds, so the 2-of-3 charter stops being quorate —
        // with no write to the charter, nothing revoked, and nothing at all
        // written on the transit plane. The hop goes ineligible because (D)
        // re-derives, which is the same mechanism as the withdrawal contract.
        for i in 3..5 {
            let extra = format!("{tag}-h{i}");
            register_typed_key(directory, &extra, identity_type::NODE).await?;
            // v31.0.0 (CIRISPersist#654) — signed roster grow; see the twin
            // fixture above.
            let member = crate::federation::types::FamilyMember {
                key_id: extra.clone(),
                joined_at: chrono::Utc::now(),
                role: Some("founder".to_owned()),
            };
            let spec = crate::federation::cohort::test_support::admit_family_via(
                directory, &extra, &accord, &member,
            )
            .await;
            directory.add_family_member(&accord, member, &spec).await?;
        }
        let after_growth = resolve_transit_eligibility(directory, &user, &peer).await?;
        assert!(
            !after_growth.eligible,
            "({tag}) two of five seats is not a majority, so the family root is no longer \
             chartered — and the hop it anchored goes with it. The threshold reaches the \
             transport plane, with nothing written there: {after_growth:?}"
        );
        Ok(())
    }

    /// v24.1.0 (CIRISPersist#547) — **whatever this node ADVERTISES, it can
    /// SERVE.**
    ///
    /// The advertised ref is `sha256` over the bytes
    /// `list_signed_key_records_since` returns for the CURRENT row, and the peer
    /// fetches it with `lookup_signed_record_by_content_hash("Key", <that
    /// hash>)`. Those two facts are maintained by different code — the read
    /// surface re-serializes, `signed_wire_index` is written at each put path —
    /// so they are free to disagree, which is exactly the #541
    /// preserve-set ≢ verified-set class. #547 is the Key plane's instance:
    /// `put_public_key` maintained the index and every `UPDATE
    /// federation_keys` path did not, so a node scrub-upgraded while running
    /// advertised a ref it could not serve, and the miss was SILENT (edge's
    /// fetch is a `let … else { continue }`).
    ///
    /// This asserts the round trip after EVERY mutator the backend exposes, so
    /// the property does not care how many write paths get added later. Backends
    /// that do not implement a mutator (memory has no `adopt_scrub_upgrade`) skip
    /// that leg and still run the rest.
    pub async fn exercise_key_wire_index_follows_every_mutator(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type;

        let anchor = format!("{tag}-anchor");
        let node = format!("{tag}-node");
        ts::register_hybrid_key(directory, &anchor).await;

        // (0) the self-signed boot row — `put_public_key`, the one writer that
        // always maintained the index. The GREEN control: if this leg fails the
        // harness itself is wrong, not the mutators.
        directory
            .put_public_key(crate::federation::SignedKeyRecord {
                record: ts::replicated_key_record(&node, identity_type::NODE, &node, &node, "boot"),
            })
            .await?;
        assert_advertised_key_ref_is_servable(directory, &node, tag, "put_public_key").await?;

        // (1) adopt_scrub_upgrade — the mutator CIRISServer measured. Live
        // production code (the admit-node / rooting loop), and the row it
        // rewrites is the node's OWN, advertised the instant it lands.
        match directory
            .adopt_scrub_upgrade(crate::federation::SignedKeyRecord {
                record: ts::replicated_key_record(
                    &node,
                    identity_type::NODE,
                    &anchor,
                    &anchor,
                    "boot",
                ),
            })
            .await
        {
            Ok(_) => {
                assert_advertised_key_ref_is_servable(directory, &node, tag, "adopt_scrub_upgrade")
                    .await?;
            }
            // The trait default — this backend does not implement the upgrade
            // (memory). Reported, not silently passed.
            Err(crate::federation::Error::InvalidArgument(detail))
                if detail.contains("not supported on this backend") => {}
            Err(e) => return Err(e),
        }

        // (2) set_consent_role — NOT one of the three the issue names, and the
        // reason it is here: `consent_role` is excluded from `persist_row_hash`
        // (so its own doc said it "does not touch the signed row") but it IS in
        // the bytes the read surface returns. Two hashes, one of them moved.
        directory.set_consent_role(&node, Some("peer")).await?;
        assert_advertised_key_ref_is_servable(directory, &node, tag, "set_consent_role").await?;

        // (3) attach_key_pqc_signature — four serialized columns at once.
        // A fresh hybrid-pending row, since the one above is already complete.
        let pending = format!("{tag}-pending");
        // v31.0.0 (CIRISPersist#657) — the pending row is minted in the shape a
        // legitimate cold-path fill-in has: self-scrubbed, with the ML-DSA
        // pubkey bound into the signed `registration_envelope` (#659). Stripping
        // the PQC leg off a `replicated_key_record` no longer produces a row the
        // attach door will accept, and that is the point of #657 — an attached
        // PUBLIC KEY has to be one the envelope's signer named.
        //
        // v31.0.0 (CIRISVerify 13.1.0) — the standing is passed IN rather than
        // assigned onto the row afterwards. The fourth bound member makes a
        // post-hoc `rec.identity_type = …` a relabel: the envelope would name
        // one standing and the row carry another, and the attach door would
        // (correctly) refuse a row this exerciser only meant to be a `node`.
        let (rec, pqc_pubkey, pqc_sig) =
            crate::federation::admission::pqc_attach_test_support::hybrid_pending_self_scrubbed(
                &pending,
                identity_type::NODE,
            );
        directory
            .put_public_key(crate::federation::SignedKeyRecord { record: rec })
            .await?;
        assert_advertised_key_ref_is_servable(directory, &pending, tag, "put_public_key (pending)")
            .await?;
        directory
            .attach_key_pqc_signature(&pending, &pqc_pubkey, &pqc_sig)
            .await?;
        assert_advertised_key_ref_is_servable(directory, &pending, tag, "attach_key_pqc_signature")
            .await?;
        Ok(())
    }

    /// v36.0.0 (CIRISPersist#707) — **a consumer-visible key mutation MOVES
    /// THE SERVE POSITION.**
    ///
    /// #682 fixed the row that ARRIVES late; this witnesses the row that
    /// MUTATES after arrival. Wire-index coverage (#547, the sibling exercise
    /// above) only proves a peer that already knows the new content hash can
    /// fetch it — the CURSOR is how a peer learns a hash exists, and before
    /// #707 the five mutating doors left every consumer's cursor past the
    /// row, permanently unaware.
    ///
    /// Per door: a consumer reads the key stream to the end and keeps the
    /// PAIR cursor; the door rewrites the row; resuming from the old cursor
    /// MUST re-serve the row, carrying the NEW bytes, at a position strictly
    /// above the old cursor — while `admitted_at` (first admission, V126)
    /// stays put, because the mutation position is `mutated_at` (V131), not a
    /// re-stamp of history.
    ///
    /// Doors driven here: `adopt_scrub_upgrade` (skipped where the backend
    /// does not implement it — memory), `set_consent_role`,
    /// `attach_key_pqc_signature`, plus the NEGATIVE leg: `grant_trust` /
    /// `revoke_trust` write only `trust_*` columns — bytes no consumer ever
    /// received — and must NOT move the position, or every trust flip churns
    /// the stream for changes no peer can observe.
    /// (`supersede_canonical_record` and `adopt_genesis_reanchor` re-stamp
    /// through the identical allocator call in the same statement; their
    /// fixtures need an m-of-n quorum / genesis bundle and are not driven
    /// here — stated rather than implied.)
    pub async fn exercise_key_mutation_moves_serve_position(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type;

        let anchor = format!("{tag}-707-anchor");
        let node = format!("{tag}-707-node");
        ts::register_hybrid_key(directory, &anchor).await;
        directory
            .put_public_key(crate::federation::SignedKeyRecord {
                record: ts::replicated_key_record(&node, identity_type::NODE, &node, &node, "boot"),
            })
            .await?;

        // One consumer read-to-end + resume, shared by every door leg.
        let cursor_at_end = |rows: &[crate::federation::ServedKeyRecord]| {
            rows.last()
                .map(crate::federation::ServedKeyRecord::resume_pair)
                .expect("the stream cannot be empty after a put")
        };
        let all = directory
            .list_signed_key_records_since(None, u32::MAX)
            .await?;
        let first_admitted = all
            .iter()
            .find(|r| r.record.key_id == node)
            .expect("the boot row is served")
            .admitted_at;
        let mut cursor = cursor_at_end(&all);

        // ── door: adopt_scrub_upgrade (where implemented) ──────────────────
        match directory
            .adopt_scrub_upgrade(crate::federation::SignedKeyRecord {
                record: ts::replicated_key_record(
                    &node,
                    identity_type::NODE,
                    &anchor,
                    &anchor,
                    "boot",
                ),
            })
            .await
        {
            Ok(_) => {
                let resumed = directory
                    .list_signed_key_records_since(Some(cursor.clone()), u32::MAX)
                    .await?;
                let served = resumed.iter().find(|r| r.record.key_id == node).expect(
                    "#707 adopt_scrub_upgrade: the re-rooted row must be re-served past the \
                         consumer's cursor — its whole purpose is to re-root the key, and a \
                         consumer past the cursor kept the pre-anchor row forever",
                );
                assert_eq!(
                    served.record.scrub_key_id, anchor,
                    "({tag}) and the re-served bytes are the NEW (anchored) bytes"
                );
                cursor = cursor_at_end(
                    &directory
                        .list_signed_key_records_since(None, u32::MAX)
                        .await?,
                );
            }
            Err(crate::federation::Error::InvalidArgument(detail))
                if detail.contains("not supported on this backend") => {}
            Err(e) => return Err(e),
        }

        // ── door: set_consent_role ─────────────────────────────────────────
        directory.set_consent_role(&node, Some("peer")).await?;
        let resumed = directory
            .list_signed_key_records_since(Some(cursor.clone()), u32::MAX)
            .await?;
        let served = resumed.iter().find(|r| r.record.key_id == node).expect(
            "#707 set_consent_role: `consent_role` IS in the served bytes, so the row must \
                 be re-served past the consumer's cursor",
        );
        assert_eq!(
            served.record.consent_role.as_deref(),
            Some("peer"),
            "({tag}) the re-served bytes carry the NEW role"
        );
        assert!(
            served.admitted_at > cursor.0,
            "({tag}) the serve position moved strictly forward"
        );
        // First admission is NOT rewritten: the position that moved is
        // `mutated_at` (V131); `admitted_at` keeps its V126 meaning. Observable
        // here because `ServedKeyRecord::admitted_at` reports the SERVE
        // position (the max), which must exceed the original first-admission
        // instant rather than replace it in place — the row's own history
        // question ("how long held?") stays answerable from the column.
        assert!(
            served.admitted_at > first_admitted,
            "({tag}) the serve position is above first admission, not a rewrite of it"
        );
        cursor = cursor_at_end(
            &directory
                .list_signed_key_records_since(None, u32::MAX)
                .await?,
        );

        // ── NEGATIVE leg: grant_trust / revoke_trust must NOT move it ──────
        // v38.0.0 (#721): the doors take PROVEN grants now — register a
        // hybrid granter and sign through the test-support twin of the
        // production signing shape.
        let granter = format!("trust-granter-707-{tag}");
        crate::federation::tier_ingest::test_support::register_hybrid_key(directory, &granter)
            .await;
        directory
            .grant_trust(
                crate::federation::tier_ingest::test_support::signed_trust_grant(
                    crate::federation::TrustGrant {
                        key: node.clone(),
                        trust_type: crate::federation::TrustType::Temporary,
                        trust_relationship: crate::federation::TrustRelationship::Direct,
                        trust_domains: None,
                        trusted_by: granter.clone(),
                        expires_at: None,
                    },
                ),
            )
            .await?;
        directory
            .revoke_trust(
                crate::federation::tier_ingest::test_support::signed_trust_revocation(
                    &node, &granter,
                ),
            )
            .await?;
        let after_trust = directory
            .list_signed_key_records_since(Some(cursor.clone()), u32::MAX)
            .await?;
        assert!(
            !after_trust.iter().any(|r| r.record.key_id == node),
            "({tag}) #707 negative leg: grant_trust/revoke_trust write only `trust_*` columns — \
             bytes no consumer ever received — and must NOT re-serve the row. Re-stamping on \
             every UPDATE would churn the stream for changes no peer can observe."
        );

        // ── door: attach_key_pqc_signature ─────────────────────────────────
        let pending = format!("{tag}-707-pending");
        let (rec, pqc_pubkey, pqc_sig) =
            crate::federation::admission::pqc_attach_test_support::hybrid_pending_self_scrubbed(
                &pending,
                identity_type::NODE,
            );
        directory
            .put_public_key(crate::federation::SignedKeyRecord { record: rec })
            .await?;
        let cursor = cursor_at_end(
            &directory
                .list_signed_key_records_since(None, u32::MAX)
                .await?,
        );
        directory
            .attach_key_pqc_signature(&pending, &pqc_pubkey, &pqc_sig)
            .await?;
        let resumed = directory
            .list_signed_key_records_since(Some(cursor.clone()), u32::MAX)
            .await?;
        let served = resumed.iter().find(|r| r.record.key_id == pending).expect(
            "#707 attach_key_pqc_signature: the hybrid-completion rewrites FOUR served \
                 columns and must re-serve the row past the consumer's cursor",
        );
        assert!(
            served.record.pqc_completed_at.is_some(),
            "({tag}) the re-served bytes are the completed (post-attach) bytes"
        );
        Ok(())
    }

    /// v31.0.0 (CIRISPersist#657) — **THE ATTESTATION PLANE'S INSTANCE OF THE
    /// SAME ROUND TRIP.**
    ///
    /// #547 fixed the Key plane and #640 made the remedy a shared helper, but
    /// `attach_attestation_pqc_signature` was never redirected through it: it
    /// moves `scrub_signature_pqc`, `pqc_completed_at` and `persist_row_hash`
    /// — three serialized columns — and left `signed_wire_index` describing the
    /// pre-completion row. A federation-tier attestation that completed its PQC
    /// leg therefore advertised a ref it could not serve, silently, exactly as
    /// the Key plane did before #547.
    ///
    /// Driven from memory, sqlite AND postgres: the defect was in each
    /// backend's own method, so a single-backend witness would have been the
    /// test shape that let it live.
    pub async fn exercise_attestation_wire_index_follows_pqc_attach(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::tier_ingest::test_support as ts;

        let owner = format!("owner-{tag}");
        let node = format!("node-{tag}");
        let att_id = format!("att-{tag}");
        ts::register_identity_key(
            directory,
            &owner,
            crate::federation::types::identity_type::USER,
        )
        .await;
        ts::register_hybrid_key(directory, &node).await;

        // A federation-tier row whose `pqc_completed_at` is still NULL — the
        // shape `list_hybrid_pending_attestations` hands the cold-path sweep.
        let mut row = ts::owner_binding_attestation(&att_id, &owner, &node);
        let pqc_sig = row
            .scrub_signature_pqc
            .clone()
            .expect("the deterministic row carries a PQC signature");
        row.pqc_completed_at = None;
        directory
            .put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await?;
        assert_advertised_attestation_ref_is_servable(directory, &att_id, tag, "put_attestation")
            .await?;

        directory
            .attach_attestation_pqc_signature(&att_id, &pqc_sig)
            .await?;
        assert_advertised_attestation_ref_is_servable(
            directory,
            &att_id,
            tag,
            "attach_attestation_pqc_signature",
        )
        .await?;
        Ok(())
    }

    /// v31.0.0 (CIRISPersist#657) — the attestation twin of
    /// [`assert_advertised_key_ref_is_servable`]: hash what this node
    /// ADVERTISES for `attestation_id` and demand the point-read serve it,
    /// byte-exact.
    async fn assert_advertised_attestation_ref_is_servable(
        directory: &dyn crate::federation::FederationDirectory,
        attestation_id: &str,
        tag: &str,
        after: &str,
    ) -> Result<(), crate::federation::Error> {
        let advertised = directory
            .list_attestations_since(None, 10_000)
            .await?
            .into_iter()
            .find(|a| a.attestation.attestation_id == attestation_id)
            .unwrap_or_else(|| panic!("({tag}) {attestation_id} is advertised after {after}"))
            .attestation;
        let hash = crate::federation::wire_index::content_hash_of(&advertised)?;
        let served = directory
            .lookup_signed_record_by_content_hash("Attestation", &hash)
            .await?;
        let served = served.unwrap_or_else(|| {
            panic!(
                "({tag}) after {after}: {attestation_id} advertises (Attestation, {hash}) and \
                 CANNOT SERVE IT. Three serialized columns moved and `signed_wire_index` did not \
                 follow, so the peer asks for exactly the ref we published and gets None — \
                 silently (CIRISPersist#657, the #547/#640 class at its unfixed site)."
            )
        });
        assert_eq!(
            served,
            serde_json::to_vec(&advertised).expect("advertised attestation re-serializes"),
            "({tag}) after {after}: the served bytes must be the advertised bytes"
        );
        Ok(())
    }

    /// v24.1.0 (CIRISPersist#547) — the round trip itself: hash what this node
    /// ADVERTISES for `key_id` and demand the point-read serve it, byte-exact.
    ///
    /// Deliberately reads the ADVERTISE surface
    /// ([`FederationDirectory::list_signed_key_records_since`](crate::federation::FederationDirectory::list_signed_key_records_since))
    /// rather than `lookup_public_key`, because the advertised row is what a
    /// peer actually asks for — the measured symptom was `ADVERTISED hash ⇒
    /// POINT-READ None`.
    ///
    /// v31.4.0 (CIRISPersist#682) — the hash is taken over the
    /// [`SignedKeyRecord`](crate::federation::SignedKeyRecord) wrapper, NOT over
    /// the [`ServedKeyRecord`](crate::federation::ServedKeyRecord) that surface
    /// now returns. The cursor carries this node's `admitted_at` BESIDE the
    /// record; the content-addressed bytes are the record's own, or one key
    /// record would hash differently on every node and no ref would resolve
    /// anywhere but where it was minted. Reading the served wrapper and hashing
    /// the record's is the whole point of the split.
    async fn assert_advertised_key_ref_is_servable(
        directory: &dyn crate::federation::FederationDirectory,
        key_id: &str,
        tag: &str,
        after: &str,
    ) -> Result<(), crate::federation::Error> {
        let served_row = directory
            .list_signed_key_records_since(None, 10_000)
            .await?
            .into_iter()
            .find(|r| r.record.key_id == key_id)
            .unwrap_or_else(|| panic!("({tag}) {key_id} is advertised after {after}"));
        let advertised = crate::federation::SignedKeyRecord {
            record: served_row.record,
        };
        let hash = crate::federation::wire_index::content_hash_of(&advertised)?;
        let served = directory
            .lookup_signed_record_by_content_hash("Key", &hash)
            .await?;
        let served = served.unwrap_or_else(|| {
            panic!(
                "({tag}) after {after}: {key_id} advertises (Key, {hash}) and CANNOT SERVE IT. \
                 The row moved and `signed_wire_index` did not follow, so the peer asks for \
                 exactly the ref we published and gets None — silently (CIRISPersist#547)."
            )
        });
        assert_eq!(
            served,
            serde_json::to_vec(&advertised).expect("advertised record re-serializes"),
            "({tag}) after {after}: the served bytes must be the advertised bytes"
        );
        Ok(())
    }

    // ── #644 witnesses — authorship + envelope binding ──────────────
    //
    // One body, driven from memory + sqlite + postgres. The defect was
    // uniform across all three backends because the gate was missing from
    // the SHARED admission code, so a single-backend witness would have
    // been the same test shape that let this live.

    /// The instants these witnesses use, substrate-truncated so a
    /// postgres round-trip cannot make a row fail its own binding.
    fn w644_now() -> DateTime<Utc> {
        crate::federation::admission::truncate_to_substrate_resolution(Utc::now())
    }

    /// Register `id` as a directory STEWARD carrying its own real hybrid
    /// pubkeys, so `resolve_steward_roster` finds it AND
    /// `lookup_public_key` can verify what it signs.
    async fn w644_register_steward(
        dir: &dyn crate::federation::FederationDirectory,
        id: &Identity,
    ) {
        dir.put_public_key(crate::federation::SignedKeyRecord {
            record: id.steward_key_record(),
        })
        .await
        .ok();
    }

    /// **#644-a — AN ORG ROW WITH A BOGUS SIGNATURE IS REFUSED.**
    ///
    /// The reported defect at its simplest. `Organization` and
    /// `OrgMembership` carry `ed25519_signature_base64` /
    /// `mldsa65_signature_base64`, and before this cut NOTHING in the crate
    /// ever verified them — the row's own signature was stored, indexed,
    /// re-served on the wire, and never once checked. So the forgery needs
    /// no key material: name a registered steward as `attesting_key_id`,
    /// put any bytes at all in the signature column, and the write lands.
    ///
    /// Proves both directions: the pristine row admits, the corrupted one
    /// does not, and the corruption is ONLY in the signature half.
    pub async fn exercise_org_bogus_signature_refused(
        dir: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) {
        let steward = Identity::new(&format!("{tag}-stw"));
        w644_register_steward(dir, &steward).await;
        let org_id = format!("{tag}-org");
        let now = w644_now();

        // (a) The genuine row admits — the gate is not simply refusing
        //     everything, which is the failure mode a one-sided witness
        //     cannot tell apart from a working one.
        let good = signed_organization(&format!("{tag}-o-ok"), &org_id, &steward, "active", now);
        dir.put_organization(good.clone())
            .await
            .unwrap_or_else(|e| panic!("({tag}) #644-a: the genuinely signed org row admits: {e}"));

        // (b) The SAME row with only the Ed25519 half replaced. Everything
        //     else — envelope, attesting_key_id, every typed column — is
        //     byte-identical to the row that just admitted.
        //
        //     v31.0.0 (#658): the `attestation_id` is deliberately NOT moved
        //     any more. It is signed material now, so a forger cannot pick a
        //     fresh primary key without minting a fresh envelope — and the
        //     write is refused at the pre-DB gate, before the PK is ever
        //     consulted. (Were the signature check to disappear, this write
        //     would return Ok on sqlite's `ON CONFLICT DO NOTHING` and the
        //     `expect_err` below would fail LOUDLY rather than pass.)
        let mut forged = good.clone();
        forged.organization.ed25519_signature_base64 =
            base64::engine::general_purpose::STANDARD.encode([0x41u8; 64]);
        assert_eq!(
            forged.organization.signed_envelope, good.organization.signed_envelope,
            "({tag}) #644-a: the forgery must differ ONLY in the signature — otherwise the \
             witness could pass for the wrong reason"
        );
        let err = dir
            .put_organization(forged)
            .await
            .expect_err("({tag}) #644-a: an org row whose signature does not verify is REFUSED");
        assert_eq!(
            err.kind(),
            "federation_federation_tier_unverified",
            "({tag}) #644-a: and it is refused as an unverified signature, not incidentally \
             by some other gate: {err:?}"
        );

        // (c) The same hole one plane over: org_membership.
        let mut forged_m = signed_membership(
            &format!("{tag}-m-forged"),
            &steward,
            &format!("{tag}-user"),
            &org_id,
            "org_admin",
            "active",
            now,
        );
        forged_m.org_membership.ed25519_signature_base64 =
            base64::engine::general_purpose::STANDARD.encode([0x42u8; 64]);
        let err = dir.put_org_membership(forged_m).await.expect_err(
            "({tag}) #644-a: an org_membership row whose signature does not verify is REFUSED",
        );
        assert_eq!(
            err.kind(),
            "federation_federation_tier_unverified",
            "({tag}) #644-a: org_membership refuses for the same reason: {err:?}"
        );
    }

    /// **#644-b — A TOMBSTONE SET BY A KEY THAT DID NOT SIGN IT IS REFUSED.**
    ///
    /// Verifying the signature is necessary and NOT sufficient. The
    /// signature covers `signed_envelope`; `withdrawn_at` is a column
    /// beside it, and `LwwRow::is_withdrawn` — the whole
    /// `withdrawal_forward_only` rule — reads the column. So an attacker
    /// who never forges anything can take a still-validly-signed grant,
    /// stamp a tombstone into the projection, and retire an org or revoke
    /// somebody's membership using the victim's own signature.
    ///
    /// Also drives `status` and `role`: the role-chain resolver parses
    /// those out of the ENVELOPE while `list_org_memberships_since` returns
    /// the COLUMN, so an unbound projection lets one row be a `viewer` to
    /// the resolver and an `org_admin` to every consumer.
    pub async fn exercise_unsigned_tombstone_refused(
        dir: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) {
        let steward = Identity::new(&format!("{tag}-stw"));
        w644_register_steward(dir, &steward).await;
        let org_id = format!("{tag}-org");
        let now = w644_now();

        let good = signed_organization(&format!("{tag}-o-live"), &org_id, &steward, "active", now);
        dir.put_organization(good.clone())
            .await
            .unwrap_or_else(|e| panic!("({tag}) #644-b: the in-force org row admits: {e}"));

        // (a) The tombstone. Signature untouched and still valid; only the
        //     unsigned column moves.
        // v31.0.0 (#658) — the id stays put; see `exercise_org_bogus_signature_refused`.
        let mut tombstoned = good.clone();
        tombstoned.organization.withdrawn_at = Some(now + Duration::seconds(60));
        assert_eq!(
            tombstoned.organization.ed25519_signature_base64,
            good.organization.ed25519_signature_base64,
            "({tag}) #644-b: the attacker forges NOTHING — that is the point of the witness"
        );
        let err = dir.put_organization(tombstoned).await.expect_err(
            "({tag}) #644-b: a withdrawn_at tombstone the signature does not cover is REFUSED",
        );
        assert_eq!(
            err.kind(),
            "federation_operational_envelope_unbound",
            "({tag}) #644-b: refused as an unbound column: {err:?}"
        );
        assert!(
            format!("{err}").contains("withdrawn_at"),
            "({tag}) #644-b: the refusal must name the column it is about: {err}"
        );

        // (b) The org is still in force — the failed write changed nothing.
        let rows = dir
            .list_organizations_for(&org_id)
            .await
            .expect("list organizations");
        assert!(
            rows.iter().all(|r| r.withdrawn_at.is_none()),
            "({tag}) #644-b: the refused tombstone must not have landed"
        );

        // (c) `status` is bound too — the other half of the same column.
        let mut restatused = good.clone();
        restatused.organization.status = "deactivated".into();
        let err = dir
            .put_organization(restatused)
            .await
            .expect_err("({tag}) #644-b: an unsigned `status` flip is REFUSED");
        assert_eq!(err.kind(), "federation_operational_envelope_unbound");

        // (d) …and `role` on the membership plane — the escalation surface.
        let mut escalated = signed_membership(
            &format!("{tag}-m-esc"),
            &steward,
            &format!("{tag}-user"),
            &org_id,
            "viewer",
            "active",
            now,
        );
        escalated.org_membership.role = "org_admin".into();
        let err = dir.put_org_membership(escalated).await.expect_err(
            "({tag}) #644-b: a membership signed as `viewer` may not be stored as `org_admin`",
        );
        assert_eq!(
            err.kind(),
            "federation_operational_envelope_unbound",
            "({tag}) #644-b: role divergence is an unbound column: {err:?}"
        );
        assert!(
            format!("{err}").contains("role"),
            "({tag}) #644-b: the refusal names `role`: {err}"
        );
    }

    /// **#644-c — AN INFLATED `revision` IS REFUSED, AND THE LOCKOUT IS GONE.**
    ///
    /// `PartnerRecord` is the plane that was PARTIALLY clean: it really
    /// does verify an M-of-N steward quorum. But the quorum verifies
    /// `JCS(signed_envelope)`, and `revision` — the anti-rollback counter
    /// and the first key of the `monotonic_quorum` comparator — was read
    /// off the typed column.
    ///
    /// That made a permanent denial-of-service reachable WITHOUT ANY KEY:
    /// replay a legitimately quorum-signed record with the column set to
    /// `u64::MAX`. The quorum still verifies (the envelope is untouched),
    /// `check_partner_revision_monotonic` accepts it (MAX exceeds
    /// everything), and from then on EVERY legitimate revision is refused
    /// as a rollback, forever, with no recovery path — the counter only
    /// goes up.
    ///
    /// The last leg is the one that matters: it is not enough that the
    /// attack write fails. A later legitimate write must still succeed, or
    /// the fix merely relocated the lockout.
    pub async fn exercise_revision_inflation_refused(
        dir: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) {
        let s1 = Identity::new(&format!("{tag}-s1"));
        let s2 = Identity::new(&format!("{tag}-s2"));
        for s in [&s1, &s2] {
            w644_register_steward(dir, s).await;
        }
        let license = format!("{tag}-lic");
        let now = w644_now();
        let stewards: Vec<&Identity> = vec![&s1, &s2];

        // (a) A legitimate 2-of-2 record at revision 1.
        let r1 = signed_partner_record(
            &format!("{tag}-p1"),
            &license,
            1,
            "active",
            now,
            &stewards,
            2,
            false,
        );
        dir.put_partner_record(r1.clone())
            .await
            .unwrap_or_else(|e| panic!("({tag}) #644-c: the quorum-signed revision 1 admits: {e}"));

        // (b) THE LOCKOUT ATTEMPT. The attacker holds no steward key. They
        //     take the record above — whose quorum signatures remain
        //     entirely valid — and raise only the unsigned column.
        // v31.0.0 (#658) — the id stays put. It is quorum-signed material
        // now, so the attacker cannot even give the lockout row a primary key
        // of its own without a second M-of-N ceremony.
        let mut inflated = r1.clone();
        inflated.partner_record.revision = u64::MAX;
        assert_eq!(
            inflated.steward_signatures, r1.steward_signatures,
            "({tag}) #644-c: the steward quorum is REPLAYED VERBATIM — no forgery anywhere"
        );
        let err = dir.put_partner_record(inflated).await.expect_err(
            "({tag}) #644-c: an inflated `revision` the quorum never signed is REFUSED",
        );
        assert_eq!(
            err.kind(),
            "federation_operational_envelope_unbound",
            "({tag}) #644-c: refused as an unbound column, NOT as a rollback: {err:?}"
        );
        assert!(
            format!("{err}").contains("revision"),
            "({tag}) #644-c: the refusal names `revision`: {err}"
        );

        // (c) THE LOCKOUT IS GONE. A legitimate revision 2 still admits.
        //     Had the inflated row landed, this write — and every write
        //     after it, forever — would fail PartnerRecordRollback.
        let r2 = signed_partner_record(
            &format!("{tag}-p2"),
            &license,
            2,
            "active",
            now + Duration::seconds(1),
            &stewards,
            2,
            false,
        );
        dir.put_partner_record(r2).await.unwrap_or_else(|e| {
            panic!(
                "({tag}) #644-c: THE LOCKOUT SURVIVED. A legitimate revision 2 was refused \
                 after the inflation attempt, which means the attack still denies service \
                 even though its own write failed: {e}"
            )
        });

        // (d) …and the merge resolves to it, on a counter every steward
        //     actually attested to.
        let rows = dir
            .list_partner_records_for(&license)
            .await
            .expect("list partner records");
        let winner = resolve_monotonic_quorum(&rows).expect("a winner exists");
        assert_eq!(
            winner.revision, 2,
            "({tag}) #644-c: the monotonic_quorum winner is the legitimate revision 2"
        );
        assert!(
            rows.iter().all(|r| r.revision <= 2),
            "({tag}) #644-c: no inflated revision was ever stored"
        );
    }

    /// **#658 — ONE SIGNED ENVELOPE, ONE PRIMARY KEY.**
    ///
    /// #644 bound every security-relevant column on these three planes
    /// EXCEPT the one that says which row this is. The attestation plane had
    /// bound its identity since #643 for a stated reason (see
    /// [`crate::federation::envelope::row_paths::ATTESTATION_ID`]): same bytes
    /// ⇒ same id ⇒ the PK dedup absorbs a resubmission as an idempotent no-op,
    /// which makes replay *impossible to express* rather than merely refused.
    ///
    /// **The witness is written against the STRUCTURAL fact, not an
    /// escalation story.** Whether the attacker goes on to WIN a merge is
    /// narrower than replay — [`lww_wins`] / [`partner_wins`] reach the
    /// `attestation_id` tie-break only on an `asserted_at` (and, for partner,
    /// `revision` + status-rank) tie. What is certain and unconditional is
    /// this: one still-valid signed envelope could be installed at unboundedly
    /// many primary keys, each a fully valid row by every other gate, each
    /// with an attacker-chosen §6.1 tie-break key, and each minting its own
    /// `signed_wire_index` entry. That is what the legs below pin.
    ///
    /// The last leg is the one that keeps this honest: a row genuinely
    /// RE-MINTED at a new id — fresh envelope, freshly signed — must still
    /// admit. Otherwise the fix would read as "second rows are impossible"
    /// rather than "second rows must be authored".
    pub async fn exercise_operational_id_replay_refused(
        dir: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) {
        let s1 = Identity::new(&format!("{tag}-s1"));
        let s2 = Identity::new(&format!("{tag}-s2"));
        for s in [&s1, &s2] {
            w644_register_steward(dir, s).await;
        }
        let org_id = format!("{tag}-org");
        let user_id = format!("{tag}-user");
        let license = format!("{tag}-lic");
        let now = w644_now();

        // The replayed ids are chosen to sort BEFORE the originals, so each
        // one is the row §6.1 hands the tie-break to. Nothing below depends
        // on that — it is pinned so the stake is legible.
        let (o_id, o_replay) = (format!("{tag}-o-1"), format!("{tag}-o-0"));
        let (m_id, m_replay) = (format!("{tag}-m-1"), format!("{tag}-m-0"));
        let (p_id, p_replay) = (format!("{tag}-p-1"), format!("{tag}-p-0"));
        for (orig, replay) in [(&o_id, &o_replay), (&m_id, &m_replay), (&p_id, &p_replay)] {
            assert!(
                replay < orig,
                "({tag}) #658: the replay id must sort first — it is the §6.1 tie-break winner"
            );
        }

        // ── (a) organization ────────────────────────────────────────
        let org = signed_organization(&o_id, &org_id, &s1, "active", now);
        dir.put_organization(org.clone())
            .await
            .unwrap_or_else(|e| panic!("({tag}) #658: the genuinely signed org row admits: {e}"));

        let mut org_replay = org.clone();
        org_replay.organization.attestation_id.clone_from(&o_replay);
        assert_eq!(
            org_replay.organization.signed_envelope, org.organization.signed_envelope,
            "({tag}) #658: the attacker forges NOTHING — the envelope and its signature are \
             the producer's own, replayed verbatim"
        );
        assert_eq!(
            org_replay.organization.ed25519_signature_base64,
            org.organization.ed25519_signature_base64
        );
        let err = dir.put_organization(org_replay).await.expect_err(
            "({tag}) #658: one signed org envelope may not be installed at a second primary key",
        );
        assert_eq!(
            err.kind(),
            "federation_operational_envelope_unbound",
            "({tag}) #658: refused as an unbound column, not incidentally: {err:?}"
        );
        assert!(
            format!("{err}").contains("attestation_id"),
            "({tag}) #658: the refusal names the column it is about: {err}"
        );

        // ── (b) org_membership ──────────────────────────────────────
        let mem = signed_membership(&m_id, &s1, &user_id, &org_id, "org_admin", "active", now);
        dir.put_org_membership(mem.clone())
            .await
            .unwrap_or_else(|e| {
                panic!("({tag}) #658: the genuinely signed membership admits: {e}")
            });

        let mut mem_replay = mem.clone();
        mem_replay
            .org_membership
            .attestation_id
            .clone_from(&m_replay);
        assert_eq!(
            mem_replay.org_membership.signed_envelope, mem.org_membership.signed_envelope,
            "({tag}) #658: nothing is forged on the membership plane either"
        );
        let err = dir
            .put_org_membership(mem_replay)
            .await
            .expect_err("({tag}) #658: a membership envelope binds to ONE attestation_id");
        assert_eq!(err.kind(), "federation_operational_envelope_unbound");
        assert!(format!("{err}").contains("attestation_id"), "{err}");

        // ── (c) partner_record — the M-of-N plane ───────────────────
        let stewards: Vec<&Identity> = vec![&s1, &s2];
        let pr = signed_partner_record(&p_id, &license, 1, "active", now, &stewards, 2, false);
        dir.put_partner_record(pr.clone())
            .await
            .unwrap_or_else(|e| panic!("({tag}) #658: the quorum-signed record admits: {e}"));

        let mut pr_replay = pr.clone();
        pr_replay
            .partner_record
            .attestation_id
            .clone_from(&p_replay);
        assert_eq!(
            pr_replay.steward_signatures, pr.steward_signatures,
            "({tag}) #658: the M-of-N steward quorum is REPLAYED VERBATIM — the attacker holds \
             no steward key, which is exactly why binding the id here is the expensive one to \
             defer: a second primary key now costs a second ceremony"
        );
        let err = dir
            .put_partner_record(pr_replay)
            .await
            .expect_err("({tag}) #658: a quorum-signed envelope binds to ONE attestation_id");
        assert_eq!(err.kind(), "federation_operational_envelope_unbound");
        assert!(format!("{err}").contains("attestation_id"), "{err}");

        // ── (d) NO FAN-OUT: one envelope, one row, one wire-index entry ──
        let orgs = dir.list_organizations_for(&org_id).await.expect("orgs");
        assert_eq!(
            orgs.len(),
            1,
            "({tag}) #658: the refused replay must not have landed a second organization row"
        );
        let mems = dir
            .list_org_memberships_for(&org_id)
            .await
            .expect("memberships");
        assert_eq!(mems.len(), 1, "({tag}) #658: no second membership row");
        let prs = dir
            .list_partner_records_for(&license)
            .await
            .expect("partner records");
        assert_eq!(prs.len(), 1, "({tag}) #658: no second partner_record row");

        // The wire index is the half that makes the fan-out REACHABLE: every
        // distinct `attestation_id` mints its own `record_key`, so an
        // unbounded id fan-out is an unbounded set of addresses a peer can
        // pull the same signed bytes from. Counted through this node's own
        // index derivation, tag-scoped (postgres shares one DB across tests).
        let indexed = crate::federation::wire_index::all_kind_hash_keys(dir)
            .await
            .expect("wire index derivation");
        for kind in ["Organization", "OrgMembership", "PartnerRecord"] {
            let n = indexed
                .iter()
                .filter(|(k, _, rk)| *k == kind && rk.contains(tag))
                .count();
            assert_eq!(
                n, 1,
                "({tag}) #658: `{kind}` must have exactly ONE wire-index address for one signed \
                 envelope — found {n}"
            );
        }

        // ── (e) THE FIX DID NOT BRICK THE PLANE ─────────────────────
        // A row genuinely re-minted at the new id — a NEW envelope, signed
        // afresh — still admits on all three planes. Without this leg, a gate
        // that simply refused every `attestation_id` would pass everything
        // above.
        let later = now + Duration::seconds(1);
        dir.put_organization(signed_organization(
            &o_replay, &org_id, &s1, "active", later,
        ))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "({tag}) #658: a genuinely RE-MINTED organization at the same id the replay \
                     tried to use must admit — the binding requires authorship, it does not ban \
                     second rows: {e}"
            )
        });
        dir.put_org_membership(signed_membership(
            &m_replay,
            &s1,
            &user_id,
            &org_id,
            "org_admin",
            "active",
            later,
        ))
        .await
        .unwrap_or_else(|e| panic!("({tag}) #658: a re-minted membership must admit: {e}"));
        dir.put_partner_record(signed_partner_record(
            &p_replay, &license, 2, "active", later, &stewards, 2, false,
        ))
        .await
        .unwrap_or_else(|e| panic!("({tag}) #658: a re-minted partner_record must admit: {e}"));

        assert_eq!(
            dir.list_organizations_for(&org_id)
                .await
                .expect("orgs")
                .len(),
            2,
            "({tag}) #658: the authored second row DID land"
        );
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

    /// v31.0.0 (CIRISPersist#659) — the exported migration constant IS the
    /// pubkey `signed_canonical_record` used to hardcode. The CHANGELOG tells a
    /// downstream mesh sim that passing it keeps a record's columns
    /// byte-for-byte; that claim is CHECKED here rather than believed, because
    /// a wrong constant would silently change every downstream preimage while
    /// still compiling.
    #[test]
    fn placeholder_subject_pubkey_is_the_pre_659_literal_659() {
        use base64::Engine as _;
        assert_eq!(
            test_support::PLACEHOLDER_SUBJECT_ED25519_BASE64,
            base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            "#659: the exported placeholder must be the `[7u8; 32]` key the helper hardcoded, or \
             the documented mechanical update is not byte-preserving"
        );
    }

    /// v31.0.0 (CIRISPersist#659) — the ONE spelling, checked in both
    /// directions: what the producer stamps is exactly what the checker
    /// demands. A drift here is the #643/#598/#652 defect shape, and it would
    /// be invisible to every gate test (both sides would simply agree on the
    /// wrong thing).
    ///
    /// # One literal, and it is the CROSS-REPO pin (v31.0.0, CIRISVerify 13.1.0)
    ///
    /// The literal list below is deliberately the ONLY restatement of the
    /// member set in the repo, and it is not here to describe persist — it is
    /// here to pin persist against `ciris_verify_core`'s
    /// `KeyRecord::check_subject_binding`, which binds `key_id`,
    /// `identity_type`, `pubkey_ed25519_base64` and `pubkey_ml_dsa_65_base64`
    /// (the last via `require_optional`). Persist keeps its own spelling only
    /// because its `KeyRecord` is a distinct type with a declaration-order
    /// contract against CIRISRegistry; the SEMANTICS are verify's, so silent
    /// drift away from those four is the failure this literal exists to make
    /// loud.
    ///
    /// The pin is on the SET, spelled in the order persist iterates it. Verify
    /// carries its members in an insertion-ordered `Vec` while persist builds a
    /// `serde_json::Map` (BTreeMap-backed — this crate does not enable
    /// `preserve_order`), so the two orders are not comparable and only the set
    /// is the contract. Lexicographic is the right spelling here regardless: it
    /// is the order JCS emits, which is the order the co-scrubbers actually
    /// signed over.
    ///
    /// Everything else derives from [`subject_binding`] itself — in particular
    /// the per-member load-bearing loop, which witnesses a FIFTH member
    /// automatically the day one is added. Adding a member should be one edit
    /// in `subject_binding` plus this one deliberate cross-repo line.
    #[test]
    fn subject_binding_has_one_spelling_659() {
        use crate::federation::admission::{
            bind_subject_into_envelope, subject_binding, verify_envelope_binds_subject,
        };
        let bound = subject_binding("k1", "node", "ED", Some("PQC"));
        assert_eq!(
            bound.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "identity_type",
                "key_id",
                "pubkey_ed25519_base64",
                "pubkey_ml_dsa_65_base64"
            ],
            "13.1.0: persist's projection must be the same four members \
             `ciris_verify_core::federation_self_record::KeyRecord::check_subject_binding` binds — \
             two implementations of one projection may not drift"
        );
        assert!(
            subject_binding("k1", "node", "ED", None)["pubkey_ml_dsa_65_base64"].is_null(),
            "#659: an absent PQC leg binds `null` — an assertion of ABSENCE, not a missing field"
        );
        // …and it is the ONLY member that may ever be null, which is what makes
        // the CEG §0.9 carve-out narrow. Read off the projection, not restated.
        for (member, value) in subject_binding("k1", "node", "ED", None) {
            assert_eq!(
                value.is_null(),
                member == "pubkey_ml_dsa_65_base64",
                "13.1.0: only the PQC leg may bind `null`, because `verify_envelope_binds_subject` \
                 tolerates an OMITTED member exactly when the expectation is null — a second \
                 nullable member would silently widen that carve-out to a second field"
            );
        }

        // Producer → checker, round trip, for a row with and without a PQC leg.
        for pqc in [Some("PQC".to_owned()), None] {
            let mut rec = crate::federation::types::KeyRecord {
                pubkey_ml_dsa_65_base64: pqc.clone(),
                ..test_support::signed_canonical_record(
                    "k1",
                    "node",
                    "ED",
                    pqc.as_deref(),
                    json!({ "purpose": "round trip" }),
                    &[&test_support::Identity::new("s1")],
                )
            };
            verify_envelope_binds_subject(&rec)
                .expect("#659: what the producer stamps, the checker accepts");
            // …and the caller's own fields survive the stamping.
            assert_eq!(rec.registration_envelope["purpose"], json!("round trip"));

            // EVERY bound member is load-bearing, and the list comes off the
            // projection rather than a literal — so a fifth member is witnessed
            // the day it is added instead of the day someone remembers. The
            // envelope side is the one tampered with (not the row) because that
            // is generic over members whose row-side spellings differ.
            for member in subject_binding("k1", "node", "ED", pqc.as_deref()).keys() {
                let mut tampered = rec.clone();
                tampered.registration_envelope[member] = json!("a-value-nobody-signed-for");
                let Err(why) = verify_envelope_binds_subject(&tampered) else {
                    panic!(
                        "#659: a divergence on {member} must be refused — an unchecked bound \
                         member is a member that is not bound"
                    )
                };
                assert!(
                    why.contains(member) && why.contains("CIRISPersist#659"),
                    "#659: the refusal must name {member}: {why}"
                );
            }

            // Row-side divergence too, on the member whose row spelling is the
            // record's own name.
            rec.key_id = "k2".into();
            let why = verify_envelope_binds_subject(&rec)
                .expect_err("#659: a diverging subject is refused");
            assert!(
                why.contains("key_id") && why.contains("CIRISPersist#659"),
                "{why}"
            );
        }

        // The producer OVERWRITES a conflicting caller-supplied value; it does
        // not defer to it. A fill-only-if-missing producer would let a caller's
        // stale or hostile `key_id` ride into the bytes the accord signs, and
        // the record would then be refused at the gate with the caller's value
        // in the message — a confusing failure for a shape the helper is
        // supposed to make impossible. (This arm exists because a mutation that
        // changed `insert` to `entry().or_insert` survived the whole suite.)
        let mut hostile = json!({
            "key_id": "somebody-else",
            // 13.1.0 — the hostile envelope claims a PRIVILEGED standing, which
            // is the fourth member's whole reason for existing: a producer that
            // deferred to this value would let a caller carry `canonical` into
            // the bytes the accord signs.
            "identity_type": "canonical",
            "pubkey_ed25519_base64": "SOMEBODY-ELSES-KEY",
            "pubkey_ml_dsa_65_base64": "SOMEBODY-ELSES-PQC-KEY",
            "purpose": "kept",
        });
        bind_subject_into_envelope(&mut hostile, "k1", "node", "ED", None).expect("bind");
        assert_eq!(hostile["key_id"], json!("k1"));
        assert_eq!(hostile["identity_type"], json!("node"));
        assert_eq!(hostile["pubkey_ed25519_base64"], json!("ED"));
        assert!(hostile["pubkey_ml_dsa_65_base64"].is_null());
        assert_eq!(hostile["purpose"], json!("kept"));

        // The producer refuses a non-object envelope rather than dropping the
        // binding on the floor.
        let mut not_an_object = json!("just a string");
        assert!(bind_subject_into_envelope(&mut not_an_object, "k1", "node", "ED", None).is_err());
    }

    /// v31.0.0 (CIRISPersist#659) — [`test_support::accord_conferred`] is the
    /// SECOND producer of co-scrubbed records, and it takes a record the caller
    /// built — so it is the one that can be handed a subject-blind envelope.
    ///
    /// Its callers today all carry `ConferralMode::DelegatedFromTrustRoot`
    /// types, which do not reach the co-scrub gate, so nothing else in the
    /// suite notices whether it binds: a mutation deleting its binding survived
    /// the entire suite. That is precisely why this witness exists — a producer
    /// whose correctness nothing checks is a producer that will drift the
    /// moment a caller of a gated type appears.
    #[test]
    fn accord_conferred_binds_the_subject_it_scrubs_659() {
        use crate::federation::admission::verify_envelope_binds_subject;
        let holder = test_support::Identity::new("ac659-h0");
        // A record whose envelope names NOBODY — the shape the gate refuses.
        let mut blind = test_support::signed_canonical_record(
            "ac659-subject",
            "node",
            test_support::PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            json!({ "purpose": "unbound on purpose" }),
            &[&holder],
        );
        blind.registration_envelope = json!({ "purpose": "unbound on purpose" });
        assert!(
            verify_envelope_binds_subject(&blind).is_err(),
            "#659: the fixture must START from the shape the gate refuses"
        );

        let conferred = test_support::accord_conferred(blind, &[&holder]);
        verify_envelope_binds_subject(&conferred)
            .expect("#659: whatever `accord_conferred` scrubs, it must first bind");
        assert_eq!(
            conferred.registration_envelope["purpose"],
            json!("unbound on purpose"),
            "#659: and the caller's own fields survive the binding"
        );
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
