// v0.7.0-α2: the federation-stable wire types in this file mirror
// `CIRISNodeCore/SCHEMA.md` §3-§10. Per-field documentation lives in
// the SCHEMA.md source-of-truth; we allow `missing_docs` at the file
// level rather than copy-pasting field semantics. v0.7.0-α2 follow-up
// can add curated rustdoc cross-references once the surface settles.
#![allow(missing_docs)]

//! Federation-stable wire types for the CIRISNodeCore consensus
//! substrate (v0.7.0+; FSD Appendix A.2 / A.3).
//!
//! These types cross the PyO3 boundary (JSON-encoded), the
//! persistence boundary (postgres JSONB columns + typed columns),
//! and any future HTTP boundary. Shape follows
//! `CIRISNodeCore/SCHEMA.md` §3-§10.
//!
//! # Payload typing
//!
//! Persist accepts `serde_json::Value` for per-subject-kind
//! payloads (§4.1-§4.10 — `arc_question`, `proposed_battery`,
//! `prompt_edit`, etc.). The full payload taxonomy lives in
//! `ciris-node-core`'s schema crate; persist is the substrate, not
//! the policy.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── envelope-level shared types ────────────────────────────────────

/// `(domain, language, subject?)` tuple — the
/// CIRISNodeCore/SCHEMA.md §2.5 cell that scopes every Contribution,
/// Vote, Ledger entry, and Expertise attestation.
///
/// For Contribution / Vote envelopes + Credits ledger entries,
/// `subject` is the `subject_kind` (e.g. `"arc_question"`,
/// `"proposed_battery"`, `"prompt_edit"`) — required.
///
/// For Expertise attestation + Expertise ledger entries, the cell
/// is `(domain, language)` only per SCHEMA.md §7 / §10 — `subject`
/// is `None`. Forcing a required `subject` here would make Expertise
/// callers carry a dummy value; the Option lets one type cover
/// both shapes cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cell {
    /// Federation domain (e.g. `"mental_health"`).
    pub domain: String,
    /// BCP-47 language tag (e.g. `"am"`, `"en"`, `"sw"`).
    pub language: String,
    /// `subject_kind` for Contribution / Vote / Credits paths;
    /// `None` for Expertise paths per SCHEMA.md §7 / §10.
    pub subject: Option<String>,
}

/// Hybrid signature pair — classical Ed25519 + post-quantum ML-DSA-65.
/// Matches the federation_directory shape from V004 onward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Base64-encoded Ed25519 signature (64 bytes raw).
    pub ed25519: String,
    /// Base64-encoded ML-DSA-65 signature (3309 bytes raw per FIPS 204
    /// final). Optional during hybrid-pending writes; required for
    /// canonical-chain promotion.
    pub ml_dsa_65: Option<String>,
    /// Wall-clock at signing time.
    pub signed_at: DateTime<Utc>,
}

/// One witness inside a [`WitnessSet`] — `CIRISNodeCore/SCHEMA.md` §6.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Witness {
    /// Witness contributor id (base64url Ed25519).
    pub witness_id: String,
    /// Jurisdiction code (e.g. `"ET"`, `"KE"`).
    pub jurisdiction: String,
    /// Operator id (`"org_id_or_self"` per spec).
    pub operator: String,
    /// Software stack identifier (e.g. `"ciris-agent-2.8.9-stable"`).
    pub software_stack: String,
    /// Witness's expertise in the cell, in `[0, 1]`.
    pub cell_expertise: f64,
    /// Hybrid signature over the witness attestation bytes.
    pub signature: HybridSignature,
}

/// Diversity accounting carried alongside the witness list. The
/// crate validates this against the computed diversity at submission
/// time; mismatch rejects the WitnessSet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiversityProof {
    /// Distinct jurisdictions represented.
    pub jurisdictions: Vec<String>,
    /// Count of distinct operators (independent of jurisdiction).
    pub operators_distinct: u32,
    /// Count of distinct software stacks.
    pub software_stacks_distinct: u32,
    /// Whether every witness met the cell's per-witness expertise
    /// floor (configurable per `MISSION.md` §9 question 10).
    pub cell_expertise_floor_met: bool,
}

/// `CIRISNodeCore/SCHEMA.md` §6 WitnessSet — N witnesses + the
/// explicit diversity accounting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessSet {
    /// Witness attestations.
    pub witnesses: Vec<Witness>,
    /// Diversity accounting.
    pub diversity_proof: DiversityProof,
}

/// `contribution_type` discriminator per `SCHEMA.md` §3.1. The
/// payload shape on [`ContributionEnvelope::payload`] varies per
/// variant; persist treats payloads as opaque JSONB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionType {
    /// Consumer requests routing to qualified WAs (`SCHEMA.md` §4.7).
    DeferralRequest,
    /// Routed WA's signed response (`SCHEMA.md` §4.8).
    DeferralResponse,
    /// Battery / free-form argument / policy / edit proposal
    /// (`SCHEMA.md` §4.1–§4.6). Sub-discriminated by
    /// `subject.subject_kind`.
    Proposal,
    /// Self- or peer-nomination for Wise Authority standing
    /// (`SCHEMA.md` §4.9).
    WaCandidacy,
    /// Expertise-bearer attests another contributor has expertise in
    /// a cell (`SCHEMA.md` §4.10 / §7).
    ExpertiseAttestation,
    /// Accusation of rogue action (`SCHEMA.md` §4.11 / §8).
    ModerationEvent,
    /// Signed request to reverse a prior SlashingAttestation
    /// (`SCHEMA.md` §4.12 / §9).
    ReconsiderationRequest,
}

// ─── Canonical-promotion (v0.7.2, CIRISPersist#32) ─────────────────

/// Which cirisnode class a [`PromotionAttestation`] targets. v60.0.0: each
/// names a row family ([`super::rows::promotion_target_family`]); the target
/// ids are the rows' `attestation_id`s. Reconsideration **requests** are
/// intentionally absent — their canonical lifecycle is carried by the ruling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetRowKind {
    Contribution,
    Vote,
    ModerationEvent,
    SlashingAttestation,
    ReconsiderationAttestation,
}

/// Signed federation-consensus record that PROMOTES held rows (local
/// bookkeeping). v0.7.2 (CIRISPersist#32); v60.0.0 — the targets are rows
/// this node holds on the target kind's family, every one checked before the
/// record is written (all or none). There is no `is_canonical` column left
/// to flip: a row is promoted when a promotion record names it.
///
/// Bulk shape per issue #32: one attestation can name N target_ids
/// of the same target_kind. Cross-kind promotion requires N
/// attestations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromotionAttestation {
    /// ULID.
    pub attestation_id: String,
    /// Which V011 row class is being promoted.
    pub target_kind: TargetRowKind,
    /// The target rows' `attestation_id`s. Every one must be held on the
    /// target kind's family.
    pub target_ids: Vec<String>,
    /// Identity (Ed25519 pubkey, base64) of the consensus crate
    /// instance that signed this attestation. Per SCHEMA.md §2.2,
    /// the identity IS the pubkey — verify is self-signed.
    pub attested_by: String,
    /// Threshold-crossing details the consensus crate used to
    /// decide promotion (vote tallies, witness counts, time
    /// windows, etc.). Free-form per-policy.
    pub aggregate_evidence: serde_json::Value,
    /// Hybrid Ed25519 + ML-DSA-65 signature over the canonical
    /// envelope (signature field stripped).
    pub signature: HybridSignature,
    /// Caller-asserted wall-clock at signing time.
    pub attested_at: DateTime<Utc>,
}

// ─── Ledger types (SCHEMA.md §10) ───────────────────────────────────

/// One row from `cirisnode.credits_ledger` — v60.0.0, the projection of
/// this node's latest `credits:` row on the key. Read-view shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreditsLedgerEntry {
    pub contributor_id: String,
    pub domain: String,
    pub language: String,
    /// Per-subject Credits bucket (e.g. `"arc_question"`,
    /// `"prompt_edit"`).
    pub subject: String,
    /// Balance — negative allowed for slashing outcomes.
    pub balance: f64,
    /// The `source_contribution` of the projected row.
    pub last_update_contribution: Option<String>,
    /// The projected row's signed instant.
    pub last_updated_at: DateTime<Utc>,
    /// v60.0.0 — the projected row's signed instant too (the ledger row is
    /// a pure function of one row).
    pub created_at: DateTime<Utc>,
    /// v60.0.0 — the row this ledger row projects (`None`: a pre-V203
    /// balance not yet re-emitted).
    #[serde(default)]
    pub attestation_id: Option<String>,
}

/// One row from `cirisnode.expertise_ledger` — v60.0.0, the projection of
/// this node's latest `expertise:` row on the key. Read-view shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpertiseLedgerEntry {
    pub contributor_id: String,
    pub domain: String,
    pub language: String,
    /// Expertise in `[0, 1]`.
    pub expertise: f64,
    /// `SCHEMA.md` §3.8 active-tier flag.
    pub is_active: bool,
    pub last_updated_at: DateTime<Utc>,
    pub last_update_contribution: Option<String>,
    pub created_at: DateTime<Utc>,
    /// v60.0.0 — the row this ledger row projects (`None`: a pre-V203
    /// balance not yet re-emitted).
    #[serde(default)]
    pub attestation_id: Option<String>,
}

// ─── Update / write inputs ──────────────────────────────────────────

/// Input to `update_credits_ledger`: v60.0.0, the body of this node's
/// `credits:{domain}:{language}:{subject}` row (`super::rows::plan_credits_row`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreditsUpdate {
    pub contributor_id: String,
    pub domain: String,
    pub language: String,
    pub subject: String,
    /// New balance after the update.
    pub new_balance: f64,
    /// The Contribution row whose outcome moved the balance.
    pub source_contribution: String,
}

/// Input to `update_expertise_ledger`: v60.0.0, the body of this node's
/// `expertise:{domain}:{language}` row (`super::rows::plan_expertise_row`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpertiseUpdate {
    pub contributor_id: String,
    pub domain: String,
    pub language: String,
    pub new_expertise: f64,
    pub new_active_tier: bool,
    pub source_contribution: String,
}

/// Routing-eligibility result row — one entry per qualified
/// contributor for `(domain, language)`. Used by
/// `MISSION.md` §3.3 deferral routing (steps 1-2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutableContributor {
    pub contributor_id: String,
    /// Expertise in `[0, 1]` — used to rank candidates.
    pub expertise: f64,
}

/// Vote weight computed at aggregation time per `SCHEMA.md` §5.2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoteWeight {
    pub contributor_id: String,
    pub domain: String,
    pub language: String,
    pub subject: String,
    pub credits: f64,
    pub expertise_multiplier: f64,
    pub active_tier_multiplier: f64,
    /// Final weight = credits × expertise_multiplier × active_tier_multiplier.
    pub weight: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contribution_type_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&ContributionType::DeferralRequest).unwrap(),
            r#""deferral_request""#
        );
        let back: ContributionType = serde_json::from_str(r#""wa_candidacy""#).unwrap();
        assert_eq!(back, ContributionType::WaCandidacy);
    }

    #[test]
    fn cell_round_trip() {
        // With subject (Contribution / Vote / Credits path).
        let c = Cell {
            domain: "mental_health".into(),
            language: "am".into(),
            subject: Some("arc_question".into()),
        };
        let s = serde_json::to_string(&c).unwrap();
        let back: Cell = serde_json::from_str(&s).unwrap();
        assert_eq!(back, c);

        // Without subject (Expertise path per SCHEMA.md §7 / §10).
        let c = Cell {
            domain: "mental_health".into(),
            language: "am".into(),
            subject: None,
        };
        let s = serde_json::to_string(&c).unwrap();
        let back: Cell = serde_json::from_str(&s).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn routable_contributor_round_trip() {
        let r = RoutableContributor {
            contributor_id: "abc".into(),
            expertise: 0.75,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: RoutableContributor = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn credits_ledger_entry_serde() {
        let e = CreditsLedgerEntry {
            contributor_id: "abc".into(),
            domain: "mental_health".into(),
            language: "am".into(),
            subject: "arc_question".into(),
            balance: 12.5,
            last_update_contribution: Some("01HX".into()),
            last_updated_at: Utc::now(),
            created_at: Utc::now(),
            attestation_id: None,
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: CreditsLedgerEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(back.balance, e.balance);
    }
}
