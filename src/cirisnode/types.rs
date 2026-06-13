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

use super::federation_announcement::{AnnouncementKind, AnnouncementPriority, AuthorityClass};

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

// ─── Contribution envelope (the common shell, SCHEMA.md §3) ─────────

/// Common Contribution envelope. Discriminated by
/// [`ContributionType`]; payload shape varies per variant +
/// `subject.subject_kind` for `proposal`-type Contributions.
///
/// Persist stores the row in `cirisnode.contributions` (V011) with
/// the envelope-level fields normalized into columns and the
/// per-variant payload kept as JSONB. The wire-encoded contribution
/// id is a ULID string; persist parses it to UUID at insert.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContributionEnvelope {
    /// ULID per `SCHEMA.md` §2.2.
    pub contribution_id: String,
    /// `contribution_type` discriminator.
    pub contribution_type: ContributionType,
    /// Author contributor id (base64url Ed25519). MUST match
    /// `signature.ed25519` signer (verified at insert time).
    pub author_id: String,
    /// Cell — `(domain, language, subject_kind)`.
    pub subject: Cell,
    /// Subject-kind-specific payload per `SCHEMA.md` §4.
    pub payload: serde_json::Value,
    /// Witness set for high-stakes contributions per `MISSION.md`
    /// Primitive 10 / `SCHEMA.md` §3.5.
    pub witness_set: Option<WitnessSet>,
    /// Hybrid signature over the canonical envelope bytes.
    pub signature: HybridSignature,
    /// Caller-asserted wall-clock at submission.
    pub submitted_at: DateTime<Utc>,
}

// ─── Vote envelope (SCHEMA.md §5) ───────────────────────────────────

/// Vote envelope per `SCHEMA.md` §5. Votes are weighted at
/// aggregation time per §5.2 (`credits × expertise_multiplier ×
/// active_tier_multiplier`); the raw vote is recorded here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoteEnvelope {
    /// ULID per `SCHEMA.md` §2.2.
    pub vote_id: String,
    /// Voter contributor id.
    pub voter_id: String,
    /// What's being voted on. Optional for free-form polls; required
    /// for Contribution adoption votes.
    pub contribution_id: Option<String>,
    /// Cell scope.
    pub cell: Cell,
    /// Score payload (§5.1: `battery_response` or `proposal_adoption`
    /// shape; persisted as JSONB).
    pub score: serde_json::Value,
    /// Optional rationale text.
    pub rationale: Option<String>,
    /// Hybrid signature.
    pub signature: HybridSignature,
    /// Caller-asserted wall-clock at vote cast.
    pub cast_at: DateTime<Utc>,
}

// ─── Moderation + Slashing (SCHEMA.md §8) ──────────────────────────

/// `SCHEMA.md` §8 ModerationEvent — accusation of rogue action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModerationEvent {
    /// ULID.
    pub moderation_id: String,
    /// Who is being accused (contributor id).
    pub target_contributor: String,
    /// Who is filing.
    pub accuser_id: String,
    /// Accusation payload (evidence refs, alleged violation, etc.).
    pub payload: serde_json::Value,
    /// Caller-asserted wall-clock.
    pub filed_at: DateTime<Utc>,
    /// Hybrid signature.
    pub signature: HybridSignature,
}

/// `SCHEMA.md` §8 SlashingAttestation — adjudication outcome on a
/// ModerationEvent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlashingAttestation {
    /// ULID.
    pub slashing_id: String,
    /// FK to the ModerationEvent being adjudicated.
    pub moderation_id: String,
    /// Adjudicator contributor id.
    pub adjudicator_id: String,
    /// Outcome payload (sustain / dismiss / partial + rationale).
    pub payload: serde_json::Value,
    pub attested_at: DateTime<Utc>,
    pub signature: HybridSignature,
}

// ─── Reconsideration (SCHEMA.md §9) ─────────────────────────────────

/// `SCHEMA.md` §9 ReconsiderationRequest — signed request to
/// reverse a prior SlashingAttestation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconsiderationRequest {
    /// ULID.
    pub request_id: String,
    /// FK to the SlashingAttestation being reconsidered.
    pub slashing_id: String,
    /// Requester contributor id.
    pub requester_id: String,
    /// Grounds for reconsideration + new evidence (JSONB).
    pub payload: serde_json::Value,
    pub requested_at: DateTime<Utc>,
    pub signature: HybridSignature,
}

/// `SCHEMA.md` §9 ReconsiderationAttestation — outcome of a
/// ReconsiderationRequest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconsiderationAttestation {
    /// ULID.
    pub reconsideration_id: String,
    /// FK to the ReconsiderationRequest.
    pub request_id: String,
    /// Adjudicator contributor id.
    pub adjudicator_id: String,
    /// Outcome payload (uphold / reverse / partial + rationale).
    pub payload: serde_json::Value,
    pub attested_at: DateTime<Utc>,
    pub signature: HybridSignature,
}

// ─── Canonical-promotion (v0.7.2, CIRISPersist#32) ─────────────────

/// Which V011 row class a [`PromotionAttestation`] targets. The 5
/// variants correspond to V011 tables that ship with an
/// `is_canonical` column. Reconsideration **requests** are
/// intentionally absent — their canonical lifecycle is carried by
/// the paired ReconsiderationAttestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetRowKind {
    Contribution,
    Vote,
    ModerationEvent,
    SlashingAttestation,
    ReconsiderationAttestation,
}

/// Signed federation-consensus attestation that promotes target
/// rows from `is_canonical=FALSE` to `is_canonical=TRUE`. v0.7.2
/// (CIRISPersist#32) — closes the write-side gap exposed by
/// CIRISNodeCore's substrate-contract test.
///
/// Persist enforces transactionally: the attestation row is
/// INSERTed AND the target rows' `is_canonical` flag is flipped to
/// TRUE with `canonicalized_at = NOW()` in the SAME transaction.
/// Partial promotion is impossible — either every named target
/// flips or none do.
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
    /// IDs of the target rows. All must exist in the corresponding
    /// V011 table; the transactional UPDATE asserts that the
    /// affected-row count matches `target_ids.len()`.
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

/// One row from `cirisnode.credits_ledger`. Read-view shape.
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
    /// Most-recent Contribution that affected this row.
    pub last_update_contribution: Option<String>,
    pub last_updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// One row from `cirisnode.expertise_ledger`. Read-view shape.
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
}

// ─── Update / write inputs ──────────────────────────────────────────

/// Update payload for `update_credits_ledger`. Set to upsert.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreditsUpdate {
    pub contributor_id: String,
    pub domain: String,
    pub language: String,
    pub subject: String,
    /// New balance after the update.
    pub new_balance: f64,
    /// Contribution that triggered this update.
    pub source_contribution: String,
}

/// Update payload for `update_expertise_ledger`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpertiseUpdate {
    pub contributor_id: String,
    pub domain: String,
    pub language: String,
    pub new_expertise: f64,
    pub new_active_tier: bool,
    pub source_contribution: String,
}

// ─── Read-side filters + pagination ─────────────────────────────────

/// Filter for `list_contributions` per FSD Appendix A.3. Composes
/// AND-style; every field optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionsFilter {
    /// Narrow by contribution_type.
    pub contribution_type: Option<ContributionType>,
    /// Narrow by cell (any of domain/language/subject_kind).
    pub domain: Option<String>,
    pub language: Option<String>,
    pub subject_kind: Option<String>,
    /// Narrow by author.
    pub author_id: Option<String>,
    /// `SCHEMA.md` §13.2 pending-vs-canonical split. `Some(true)`
    /// returns only canonical-chain rows; `Some(false)` returns
    /// only pending; `None` returns both.
    pub is_canonical: Option<bool>,
    /// v2.1 (CIRISPersist#101) — narrow `federation_announcement`
    /// rows by AnnouncementPriority. Applies only when
    /// `subject_kind = "federation_announcement"`; the SQL composes
    /// AND-style with the other filters, so passing this without
    /// `subject_kind = Some("federation_announcement")` returns rows
    /// whose `announcement_priority` matches (non-announcement rows
    /// always have NULL here and are excluded by the column filter).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<AnnouncementPriority>,
    /// v2.1 (CIRISPersist#101) — narrow `federation_announcement`
    /// rows by AuthorityClass. Same composition semantics as
    /// `priority`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_class: Option<AuthorityClass>,
    /// v2.1 (CIRISPersist#101) — narrow `federation_announcement`
    /// rows by [`AnnouncementKind`]. The kind is carried in the
    /// payload JSONB (not a dedicated column — kind is
    /// presentation-tier routing data, not a write-time CHECK
    /// constraint surface). Filter runs against
    /// `payload->>'kind'`. Applies only to rows where
    /// `subject_kind = 'federation_announcement'`; non-announcement
    /// rows lack a `payload.kind` field and are excluded.
    ///
    /// `AnnouncementKind::Custom(s)` filters against the serde-
    /// wire shape (`{"custom": "..."}`) — not a useful filter
    /// surface for v0.1; v0.1 callers will typically pass
    /// `KeyRotation` / `PolicyUpdate` / `ThreatAdvisory` / etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<AnnouncementKind>,
}

/// Filter for `list_votes`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VotesFilter {
    pub contribution_id: Option<String>,
    pub voter_id: Option<String>,
    pub domain: Option<String>,
    pub language: Option<String>,
    pub is_canonical: Option<bool>,
}

/// Opaque cursor for bulk-list reads. Mirrors v0.5.5 §I cursor
/// shape (`(timestamp, id)` tuple, newest-first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListCursor {
    /// Cursor format version. v0.7.0 ships `"v1"`.
    pub version: String,
    /// Timestamp of the trailing row.
    pub last_ts: DateTime<Utc>,
    /// Id of the trailing row.
    pub last_id: String,
}

impl ListCursor {
    /// Construct a v1 cursor.
    pub fn from_trailing(last_ts: DateTime<Utc>, last_id: String) -> Self {
        ListCursor {
            version: "v1".to_owned(),
            last_ts,
            last_id,
        }
    }
}

/// One page of Contributions, newest-first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContributionListPage {
    pub items: Vec<ContributionEnvelope>,
    pub next_cursor: Option<ListCursor>,
}

/// One page of Votes, newest-first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoteListPage {
    pub items: Vec<VoteEnvelope>,
    pub next_cursor: Option<ListCursor>,
}

// ─── Media-detector read filters (v6.3.0, CIRISPersist#135) ─────────
//
// Lane C of the 6.X series — the federation read accessors lens-core's
// multimedia detector family (CIRISLensCore#29) joins on. Both filters
// follow the `EventFilter` / `ContributionsFilter` idiom: an optional
// secondary key plus a `[since, until)` time window, all AND-composed,
// every field optional. Paging reuses [`ListCursor`] /
// [`ContributionListPage`]'s `(submitted_at, contribution_id)`-DESC
// tuple cursor so a media-row page advances on the same deterministic
// ordering the underlying `list_takedowns_for` / `list_key_grants_for`
// storage queries already emit (`ORDER BY submitted_at DESC,
// contribution_id DESC`; V054 indexed predicates).

/// Filter for [`crate::Engine::list_takedowns_for`] (CIRISLensCore#29.4
/// takedown-abuse detector). The PRIMARY key — the takedown TARGET
/// `content_sha256` — is the method argument, not a filter field; this
/// struct carries the optional secondary key + time window the detector
/// AND-composes on top. Every field optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakedownFilter {
    /// Narrow to takedowns filed by this claimant
    /// (`payload.claimant_key_id`). `None` returns every claimant —
    /// the per-target read; `Some` is the per-target × per-claimant
    /// read the detector uses to catch "single claimant emitting many
    /// takedowns against one target".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimant_key_id: Option<String>,
    /// Keep rows with `submitted_at >= since`. `None` = no lower bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<DateTime<Utc>>,
    /// Keep rows with `submitted_at < until` (half-open, mirrors the
    /// change-feed cursor's strict upper boundary). `None` = no upper
    /// bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Utc>>,
}

/// Filter for [`crate::Engine::list_key_grants_for`] (CIRISLensCore#29.3
/// key_grant-abuse detector). The PRIMARY key — the grant
/// `recipient_key_id` — is the method argument; this struct carries the
/// optional secondary key + content scope + time window. Every field
/// optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyGrantFilter {
    /// Narrow to grants issued by this publisher (the Contribution
    /// `author_id`). `None` returns every publisher — the per-recipient
    /// read; `Some` is the per-recipient × per-publisher read the
    /// detector uses to catch "single recipient receiving key_grants
    /// from many unrelated publishers in a short window".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_key_id: Option<String>,
    /// Narrow to grants over this content hash
    /// (`media_content_sha256`). When set, the read uses the
    /// `list_key_grants_for_content` two-axis index path; `None` uses
    /// the recipient-only index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    /// Keep rows with `submitted_at >= since`. `None` = no lower bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<DateTime<Utc>>,
    /// Keep rows with `submitted_at < until` (half-open). `None` = no
    /// upper bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Utc>>,
}

/// One page of takedown-notice Contributions, newest-first
/// (`submitted_at DESC, contribution_id DESC`). v6.3.0 (#135).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TakedownListPage {
    /// Matching `takedown_notice` Contributions.
    pub items: Vec<ContributionEnvelope>,
    /// Cursor for the next page; `None` at end of stream.
    pub next_cursor: Option<ListCursor>,
}

/// One page of key_grant Contributions, newest-first
/// (`submitted_at DESC, contribution_id DESC`). v6.3.0 (#135).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyGrantListPage {
    /// Matching `key_grant` Contributions.
    pub items: Vec<ContributionEnvelope>,
    /// Cursor for the next page; `None` at end of stream.
    pub next_cursor: Option<ListCursor>,
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
    fn contribution_envelope_round_trip() {
        let env = ContributionEnvelope {
            contribution_id: "01HX5ABCDEFGHIJK".into(),
            contribution_type: ContributionType::Proposal,
            author_id: "Zm9vYmFy".into(),
            subject: Cell {
                domain: "mental_health".into(),
                language: "am".into(),
                subject: Some("arc_question".into()),
            },
            payload: serde_json::json!({"question_id": "am_mh_v4_q01"}),
            witness_set: None,
            signature: HybridSignature {
                ed25519: "AAAA".into(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: ContributionEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back.contribution_id, env.contribution_id);
        assert_eq!(back.contribution_type, env.contribution_type);
    }

    #[test]
    fn list_cursor_v1() {
        let c = ListCursor::from_trailing(Utc::now(), "01HX".into());
        assert_eq!(c.version, "v1");
        let s = serde_json::to_string(&c).unwrap();
        let back: ListCursor = serde_json::from_str(&s).unwrap();
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
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: CreditsLedgerEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(back.balance, e.balance);
    }
}
