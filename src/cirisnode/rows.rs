//! v60.0.0 (CIRISPersist#988 item 1, #803, #854; CC 3.1.9, CC 3.1.1,
//! CC 3.3.2) — **the cirisnode classes are `scores` rows.**
//!
//! Signed attestations are the only state. Each cirisnode class is a
//! dimension CC 3.1.9 registers, so each is a hybrid-signed `scores` row on
//! the attestation plane, admitted by the plane's own door (the moderation
//! gate, the v59 reconsideration standing rule, the takedown notice's
//! duty-holder rule) and replicated like any row:
//!
//! | class | dimension | attester → attested |
//! |---|---|---|
//! | Contribution (CC 2.1) | `contribution:{subject_kind}:v1` | the author → the author |
//! | takedown notice | `takedown_notice:{basis}:v1` (CC 3.1.1) | the claimant (duty-holder) |
//! | vote | `vote:{contribution_id}:v1` | the voter → the contribution's author |
//! | moderation event | `moderation:{allegation_type}:v1` | the accuser → the accused |
//! | slashing | `slashing:{outcome}:v1` | the adjudicator → the accused |
//! | reconsideration filing | `reconsideration:{grounds}:v1` | the filer → the slashed party |
//! | reconsideration ruling | `reconsideration:{grounds}:v1` + `outcome` | the review-holder → the same |
//! | credits balance | `credits:{domain}:{language}:{subject}:v1` | this node → the contributor |
//! | expertise balance | `expertise:{domain}:{language}:v1` | this node → the contributor |
//!
//! Every leaf carries CC 3.1.7's trailing version segment (`:v1`).
//!
//! A `contribution_id` is the Contribution row's `attestation_id`; a
//! slashing names its moderation event, a filing its slashing and a ruling
//! its filing by `references_attestation_id`.
//!
//! **The planners are pure or read only the rows they name**
//! ([`plan_contribution_row`] … [`plan_expertise_row`]): each returns the
//! [`EmitAttestationInput`] the signer signs. The Engine doors
//! (`Engine::cirisnode_*`) sign it with the engine's own composed hybrid
//! signer (`emit_attestation_self`) and put it through the plane's door, so
//! the Ed25519-only fallback of the typed track is gone: every row is
//! hybrid-signed by a federation key, and its subject ids are canonical
//! federation key ids (#854). A caller holding another signer plans the row
//! here and signs it itself.
//!
//! **Retired objects are refused by name.** A v59 typed envelope (it carries
//! its own `signature` and a contributor-id member) offered at a cirisnode
//! door is [`refusal::TYPED_OBJECT_RETIRED`]; a Contribution naming the
//! `key_grant` subject kind is [`refusal::KEY_GRANT_RETIRED`] (the key-grant
//! plane, `key_grant:{axis}:v1`, is the one door for a wrapped key).

use serde::{Deserialize, Serialize};

use super::media_sharing::{
    extract_takedown_notice_payload, TakedownNoticePayload, KEY_GRANT_SUBJECT_KIND,
    TAKEDOWN_NOTICE_SUBJECT_KIND,
};
use super::types::{
    Cell, ContributionType, CreditsUpdate, ExpertiseUpdate, TargetRowKind, WitnessSet,
};
use super::Error;
use crate::federation::envelope::EnvelopeCore;
use crate::federation::ledger_projection as lp;
use crate::federation::types::{attestation_type, cohort_scope};
use crate::federation::{Attestation, EmitAttestationInput, FederationDirectory};

/// The stable refusal tokens of the retired cirisnode objects (each the
/// `kind()` of an [`Error::Retired`]).
pub mod refusal {
    /// A Contribution naming the retired `key_grant` subject kind.
    pub const KEY_GRANT_RETIRED: &str = "cirisnode_key_grant_retired";
    /// A v59 typed cirisnode envelope (self-signed, carrying its contributor
    /// id) offered at a door that now takes a row's body.
    pub const TYPED_OBJECT_RETIRED: &str = "cirisnode_typed_object_retired";
    /// Every token.
    pub const ALL: &[&str] = &[KEY_GRANT_RETIRED, TYPED_OBJECT_RETIRED];
}

/// The `contribution:{subject_kind}` family stem.
pub const CONTRIBUTION_PREFIX: &str = "contribution:";
/// The `vote:{contribution_id}` family stem (CC 3.1.9.3).
pub const VOTE_PREFIX: &str = "vote:";
/// The `slashing:{outcome}` family stem (CC 3.1.9.2).
pub const SLASHING_PREFIX: &str = "slashing:";
/// The `moderation:{allegation_type}` family stem (CC 3.1.9.2).
pub const MODERATION_PREFIX: &str = crate::federation::admission::MODERATION_DIMENSION_PREFIX;
/// The `reconsideration:{grounds}` family stem (CC 3.1.9.2).
pub const RECONSIDERATION_PREFIX: &str =
    crate::federation::admission::RECONSIDERATION_DIMENSION_PREFIX;
/// The member a reconsideration RULING carries.
pub const OUTCOME_MEMBER: &str = crate::federation::admission::RECONSIDERATION_OUTCOME_MEMBER;

/// The members a v59 typed envelope carried and a row body never does: its
/// self-signature and its contributor ids (the row's attester is the
/// contributor).
const RETIRED_TYPED_MEMBERS: &[&str] = &[
    "signature",
    "author_id",
    "voter_id",
    "accuser_id",
    "adjudicator_id",
    "requester_id",
    "claimant_key_id",
];

/// The family a promotion of `kind` targets.
#[must_use]
pub const fn promotion_target_family(kind: TargetRowKind) -> &'static str {
    match kind {
        TargetRowKind::Contribution => CONTRIBUTION_PREFIX,
        TargetRowKind::Vote => VOTE_PREFIX,
        TargetRowKind::ModerationEvent => MODERATION_PREFIX,
        TargetRowKind::SlashingAttestation => SLASHING_PREFIX,
        TargetRowKind::ReconsiderationAttestation => RECONSIDERATION_PREFIX,
    }
}

/// Is `row` a held row of the family a promotion of `kind` targets? A
/// reconsideration promotion names a RULING (a row carrying `outcome`).
#[must_use]
pub fn is_promotion_target(row: &Attestation, kind: TargetRowKind) -> bool {
    if row.attestation_type != attestation_type::SCORES {
        return false;
    }
    let Some(d) = crate::federation::admission::envelope_dimension(&row.attestation_envelope)
    else {
        return false;
    };
    d.starts_with(promotion_target_family(kind))
        && (kind != TargetRowKind::ReconsiderationAttestation
            || row.attestation_envelope.get(OUTCOME_MEMBER).is_some())
}

// ─── inputs ──────────────────────────────────────────────────────────

/// A Contribution's body (CC 2.1): what `cirisnode_put_contribution` takes.
/// v60.0.0 — no id, author or signature: the row's id is minted at signing,
/// its attester is the author and its scrubs are its signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionInput {
    /// `contribution_type` discriminator.
    pub contribution_type: ContributionType,
    /// `(domain, language, subject_kind)`; the subject kind is required.
    pub subject: Cell,
    /// Subject-kind-specific payload (`SCHEMA.md` §4).
    pub payload: serde_json::Value,
    /// Witness set for high-stakes contributions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_set: Option<WitnessSet>,
}

/// A vote's body: a signed score on a held Contribution row (CC 3.1.9.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoteInput {
    /// The Contribution row voted on (its `attestation_id`).
    pub contribution_id: String,
    /// The score, `[-1, 1]` (the CC 2.1 scalar).
    pub score: f64,
    /// The structured vote (`battery_response` / `proposal_adoption`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
    /// Optional rationale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// A moderation event's body (CC 3.1.9.2): an accusation against a keyed
/// contributor in a community.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationInput {
    /// The accused (a federation key id).
    pub target_contributor: String,
    /// `{allegation_type}` (`rogue_vote`, `coordinated_voting`, …).
    pub allegation_type: String,
    /// The community whose `moderate` duty-holders may accuse.
    pub community_id: String,
    /// Evidence refs, alleged violation, ….
    pub payload: serde_json::Value,
}

/// A slashing's body: the adjudication of a held moderation event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlashingInput {
    /// The moderation event row adjudicated.
    pub moderation_id: String,
    /// `{outcome}` (`proven_rogue` / `not_proven`, …).
    pub outcome: String,
    /// Rationale.
    pub payload: serde_json::Value,
}

/// A reconsideration filing's body: a request to reverse a held slashing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconsiderationRequestInput {
    /// The slashing row reconsidered.
    pub slashing_id: String,
    /// `{grounds}` (`new_evidence` / `procedural_error` / `quorum_compromise`).
    pub grounds: String,
    /// Grounds + new evidence.
    pub payload: serde_json::Value,
}

/// A reconsideration ruling's body: the outcome of a held filing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconsiderationRulingInput {
    /// The filing row ruled on.
    pub request_id: String,
    /// `reversed` / `partial` / `upheld`.
    pub outcome: String,
    /// Rationale.
    pub payload: serde_json::Value,
}

/// Decode a cirisnode door's JSON body, refusing a retired typed object BY
/// NAME before the shape check: a v59 envelope carries its own `signature`
/// and contributor id, and a row body never does.
///
/// # Errors
///
/// [`Error::Retired`] ([`refusal::TYPED_OBJECT_RETIRED`]) naming the member;
/// [`Error::InvalidArgument`] for any other shape error.
pub fn decode_input<T: serde::de::DeserializeOwned>(json: &str, object: &str) -> Result<T, Error> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| Error::InvalidArgument(format!("{object} JSON decode: {e}")))?;
    if let Some(member) = RETIRED_TYPED_MEMBERS.iter().find(|m| v.get(**m).is_some()) {
        return Err(Error::Retired {
            token: refusal::TYPED_OBJECT_RETIRED,
            detail: format!(
                "{object} carries `{member}`: the v59 typed cirisnode object is retired \
                 (v60.0.0, CIRISPersist#988). A {object} is a signed scores row now; send its \
                 body and the engine signs the row, or plan the row and sign it yourself"
            ),
        });
    }
    serde_json::from_value(v).map_err(|e| Error::InvalidArgument(format!("{object}: {e}")))
}

/// v60.0.0 — **the promotion record's target rule**, decided once for both
/// backends: every named target is a row held here on the target kind's
/// family ([`is_promotion_target`]); one that is not refuses the whole
/// record. Ids are deduplicated (a record naming a row twice names it once).
///
/// # Errors
///
/// [`Error::InvalidArgument`] naming the first target that is not held on
/// the family; directory reads.
pub async fn check_promotion_targets(
    dir: &dyn FederationDirectory,
    kind: TargetRowKind,
    target_ids: &[String],
) -> Result<(), Error> {
    if target_ids.is_empty() {
        return Err(Error::InvalidArgument(
            "target_ids must not be empty".into(),
        ));
    }
    for id in target_ids {
        let held = dir.get_attestation(id).await.map_err(Error::from)?;
        if !held.as_ref().is_some_and(|r| is_promotion_target(r, kind)) {
            return Err(Error::InvalidArgument(format!(
                "target {id} is not a `{}` row held here (a promotion names held rows of its \
                 kind; nothing was written)",
                promotion_target_family(kind)
            )));
        }
    }
    Ok(())
}

/// v60.0.0 — **the delivery attestation's announcement rule** (the V046
/// foreign key's, now that the announcement is a row): `announcement_id` is
/// a `contribution:federation_announcement` row held here.
///
/// # Errors
///
/// [`Error::InvalidArgument`] when it is not; directory reads.
pub async fn check_announcement_held(
    dir: &dyn FederationDirectory,
    announcement_id: &str,
) -> Result<(), Error> {
    let want = format!(
        "{CONTRIBUTION_PREFIX}{}:v1",
        super::federation_announcement::SUBJECT_KIND
    );
    let held = dir
        .get_attestation(announcement_id)
        .await
        .map_err(Error::from)?;
    let ok = held.as_ref().is_some_and(|r| {
        r.attestation_type == attestation_type::SCORES
            && crate::federation::admission::envelope_dimension(&r.attestation_envelope)
                == Some(want.as_str())
    });
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "announcement {announcement_id} is not a `{want}` row held here"
        )))
    }
}

// ─── planners ────────────────────────────────────────────────────────

/// A CC 3.1.7 lowercase vocabulary segment (`[a-z0-9][a-z0-9_]*`).
fn vocab_segment(field: &str, v: &str) -> Result<(), Error> {
    let ok = v
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "{field} {v:?} is not a lowercase vocabulary token ([a-z0-9][a-z0-9_]*, CC 3.1.7 R3)"
        )))
    }
}

/// A row id named by a body: non-empty, no `:` (it becomes a dimension
/// segment on a vote).
fn row_id(field: &str, v: &str) -> Result<(), Error> {
    if v.is_empty() || v.contains(':') || v.chars().any(char::is_whitespace) {
        return Err(Error::InvalidArgument(format!(
            "{field} {v:?} is not a row id"
        )));
    }
    Ok(())
}

fn envelope(
    mut members: serde_json::Value,
    dimension: &str,
    score: f64,
) -> Result<EnvelopeCore, Error> {
    members["dimension"] = serde_json::json!(dimension);
    members["score"] = serde_json::json!(score);
    members["confidence"] = serde_json::json!(1.0);
    EnvelopeCore::from_value(members).map_err(Error::from)
}

fn input(env: EnvelopeCore) -> EmitAttestationInput {
    EmitAttestationInput::with_envelope(attestation_type::SCORES, env, cohort_scope::FEDERATION)
}

/// The row named by `id`, held here on `family`, or [`Error::NotFound`].
async fn held_on_family(
    dir: &dyn FederationDirectory,
    field: &str,
    id: &str,
    family: &str,
) -> Result<Attestation, Error> {
    row_id(field, id)?;
    let row = dir
        .get_attestation(id)
        .await
        .map_err(Error::from)?
        .ok_or_else(|| Error::NotFound(format!("{field} {id}: no such row is held here")))?;
    let on_family = row.attestation_type == attestation_type::SCORES
        && crate::federation::admission::envelope_dimension(&row.attestation_envelope)
            .is_some_and(|d| d.starts_with(family));
    if !on_family {
        return Err(Error::InvalidArgument(format!(
            "{field} {id} is held but is not a `{family}` row"
        )));
    }
    Ok(row)
}

/// **A Contribution as a row** (CC 2.1): `contribution:{subject_kind}`,
/// score `+1`, the body under `contribution_type` / `subject_kind` /
/// `domain` / `language` / `payload` / `witness_set`. A
/// `federation_announcement` keeps its constitutional asymmetry (FSD §4.5);
/// a `takedown_notice` is the notice row ([`plan_takedown_notice_row`],
/// routed by the door); `key_grant` is retired.
///
/// # Errors
///
/// [`Error::Retired`] for `key_grant`; [`Error::InvalidArgument`] for a
/// missing or non-vocabulary subject kind, a `takedown_notice` (its own
/// planner), or an announcement that breaks the asymmetry.
pub fn plan_contribution_row(c: &ContributionInput) -> Result<EmitAttestationInput, Error> {
    let subject_kind = c.subject.subject.as_deref().ok_or_else(|| {
        Error::InvalidArgument("subject.subject (subject_kind) is required".into())
    })?;
    if subject_kind == KEY_GRANT_SUBJECT_KIND {
        return Err(Error::Retired {
            token: refusal::KEY_GRANT_RETIRED,
            detail: "the `key_grant` Contribution is retired (v60.0.0, CIRISPersist#988): a \
                     wrapped key is a `key_grant:{axis}:v1` row on the key-grant plane"
                .into(),
        });
    }
    if subject_kind == TAKEDOWN_NOTICE_SUBJECT_KIND {
        return Err(Error::InvalidArgument(
            "a takedown notice is a takedown_notice:{basis}:v1 row: plan it with \
             plan_takedown_notice_row"
                .into(),
        ));
    }
    vocab_segment("subject_kind", subject_kind)?;
    super::federation_announcement::extract_announcement_payload(subject_kind, &c.payload)?;
    let ct = serde_json::to_value(c.contribution_type)
        .map_err(|e| Error::Internal(format!("contribution_type: {e}")))?;
    let mut members = serde_json::json!({
        "contribution_type": ct,
        "subject_kind": subject_kind,
        "domain": c.subject.domain,
        "language": c.subject.language,
        "payload": c.payload,
    });
    if let Some(ws) = &c.witness_set {
        members["witness_set"] =
            serde_json::to_value(ws).map_err(|e| Error::Internal(format!("witness_set: {e}")))?;
    }
    let dimension = format!("{CONTRIBUTION_PREFIX}{subject_kind}:v1");
    Ok(input(envelope(members, &dimension, 1.0)?))
}

/// **A takedown notice as a row** (CC 3.1.1 / CC 3.3.2, CIRISPersist#803;
/// CLM-takedown-notice-row): `takedown_notice:{basis}:v1`, score `-1`,
/// `subject_kind: takedown_notice`, the CC 3.3.2 members at the envelope's
/// top level, `claimant_key_id` = `signer_key_id` (the row's
/// attester — CC: "the federation_keys row issuing the notice"), the
/// notice's `expires_at` the row's. Its admission is the duty-holder gate at
/// the plane's door.
///
/// # Errors
///
/// [`Error::InvalidArgument`] for a malformed payload or an `expires_at`
/// that is not in the future of `now`.
pub fn plan_takedown_notice_row(
    p: &TakedownNoticePayload,
    signer_key_id: &str,
) -> Result<EmitAttestationInput, Error> {
    let value = serde_json::to_value(p).map_err(|e| Error::Internal(format!("notice: {e}")))?;
    extract_takedown_notice_payload(TAKEDOWN_NOTICE_SUBJECT_KIND, &value)?;
    let mut members = value;
    members["subject_kind"] = serde_json::json!(TAKEDOWN_NOTICE_SUBJECT_KIND);
    members["claimant_key_id"] = serde_json::json!(signer_key_id);
    members["legal_basis"] = serde_json::json!(p.legal_basis.as_str());
    if let Some(m) = members.as_object_mut() {
        m.remove("expires_at");
    }
    let dimension = crate::federation::takedown_tombstone::notice_dimension(p.legal_basis.as_str());
    let mut row = input(envelope(members, &dimension, -1.0)?);
    row.expires_at = Some(p.expires_at);
    Ok(row)
}

/// **A vote as a row** (CC 3.1.9.3): `vote:{contribution_id}` on a
/// Contribution row held here, attested to its author, carrying the
/// contribution's `domain` / `language`.
///
/// # Errors
///
/// [`Error::NotFound`] when the Contribution is not held;
/// [`Error::InvalidArgument`] for a score outside `[-1, 1]` or a target that
/// is not a Contribution row.
pub async fn plan_vote_row(
    dir: &dyn FederationDirectory,
    v: &VoteInput,
) -> Result<EmitAttestationInput, Error> {
    if !(-1.0..=1.0).contains(&v.score) {
        return Err(Error::InvalidArgument(format!(
            "vote score {} is outside [-1, 1]",
            v.score
        )));
    }
    let target = held_on_family(
        dir,
        "contribution_id",
        &v.contribution_id,
        CONTRIBUTION_PREFIX,
    )
    .await?;
    let mut members = serde_json::json!({
        "domain": target.attestation_envelope.get("domain"),
        "language": target.attestation_envelope.get("language"),
    });
    if let Some(d) = &v.detail {
        members["detail"] = d.clone();
    }
    if let Some(r) = &v.rationale {
        members["rationale"] = serde_json::json!(r);
    }
    let dimension = format!("{VOTE_PREFIX}{}:v1", v.contribution_id);
    let mut row = input(envelope(members, &dimension, v.score)?);
    row.attested_key_id = Some(target.attesting_key_id);
    Ok(row)
}

/// **A moderation event as a row** (CC 3.1.9.2): `moderation:{allegation_type}`,
/// score `-1`, attested to and naming as subject the accused, carrying
/// `community_id` (the plane's moderation gate admits the community's
/// `moderate` duty-holders).
///
/// # Errors
///
/// [`Error::InvalidArgument`] for a non-vocabulary allegation type or an
/// empty community / target.
pub fn plan_moderation_row(m: &ModerationInput) -> Result<EmitAttestationInput, Error> {
    vocab_segment("allegation_type", &m.allegation_type)?;
    if m.community_id.is_empty() || m.target_contributor.is_empty() {
        return Err(Error::InvalidArgument(
            "a moderation event names its community and its target".into(),
        ));
    }
    let members = serde_json::json!({
        "community_id": m.community_id,
        "payload": m.payload,
    });
    let dimension = format!("{MODERATION_PREFIX}{}:v1", m.allegation_type);
    let mut row = input(envelope(members, &dimension, -1.0)?);
    row.attested_key_id = Some(m.target_contributor.clone());
    row.subject_key_ids = vec![m.target_contributor.clone()];
    Ok(row)
}

/// **A slashing as a row** (CC 3.1.9.2): `slashing:{outcome}` over a
/// moderation event held here (`references_attestation_id`), attested to and
/// naming as subject the accused (the subject's standing to file a
/// reconsideration), in the moderation's community.
///
/// # Errors
///
/// [`Error::NotFound`] / [`Error::InvalidArgument`] for the target; a
/// non-vocabulary outcome.
pub async fn plan_slashing_row(
    dir: &dyn FederationDirectory,
    s: &SlashingInput,
) -> Result<EmitAttestationInput, Error> {
    vocab_segment("outcome", &s.outcome)?;
    let target = held_on_family(dir, "moderation_id", &s.moderation_id, MODERATION_PREFIX).await?;
    let mut members = serde_json::json!({
        "references_attestation_id": s.moderation_id,
        "payload": s.payload,
    });
    if let Some(c) = target.attestation_envelope.get("community_id") {
        members["community_id"] = c.clone();
    }
    let dimension = format!("{SLASHING_PREFIX}{}:v1", s.outcome);
    let mut row = input(envelope(members, &dimension, 1.0)?);
    row.attested_key_id = Some(target.attested_key_id.clone());
    row.subject_key_ids = vec![target.attested_key_id];
    Ok(row)
}

/// **A reconsideration filing as a row** (CC 3.1.9.2 / CC 4.5.5):
/// `reconsideration:{grounds}` over a slashing held here, in the slashing's
/// community, attested to the slashed party. The v59 subject-standing rule
/// (`admission::check_reconsideration_admission`) admits the slashing's
/// signed subjects and the community's review-holders.
///
/// # Errors
///
/// As [`plan_slashing_row`].
pub async fn plan_reconsideration_request_row(
    dir: &dyn FederationDirectory,
    r: &ReconsiderationRequestInput,
) -> Result<EmitAttestationInput, Error> {
    vocab_segment("grounds", &r.grounds)?;
    let target = held_on_family(dir, "slashing_id", &r.slashing_id, SLASHING_PREFIX).await?;
    let mut members = serde_json::json!({
        "references_attestation_id": r.slashing_id,
        "payload": r.payload,
    });
    if let Some(c) = target.attestation_envelope.get("community_id") {
        members["community_id"] = c.clone();
    }
    let dimension = format!("{RECONSIDERATION_PREFIX}{}:v1", r.grounds);
    let mut row = input(envelope(members, &dimension, 1.0)?);
    row.attested_key_id = Some(target.attested_key_id);
    Ok(row)
}

/// **A reconsideration ruling as a row**: the filing's own
/// `reconsideration:{grounds}` dimension with an `outcome` member, over the
/// filing held here, in its community. Only the community's review-holders
/// admit (CC 4.5.5: "the ruling on it stays with the review-holders").
///
/// # Errors
///
/// As [`plan_slashing_row`]; a target that is itself a ruling; an outcome
/// outside `reversed` / `partial` / `upheld`.
pub async fn plan_reconsideration_ruling_row(
    dir: &dyn FederationDirectory,
    r: &ReconsiderationRulingInput,
) -> Result<EmitAttestationInput, Error> {
    if !["reversed", "partial", "upheld"].contains(&r.outcome.as_str()) {
        return Err(Error::InvalidArgument(format!(
            "outcome {:?} is not reversed / partial / upheld (CC 3.1.9.2)",
            r.outcome
        )));
    }
    let target = held_on_family(dir, "request_id", &r.request_id, RECONSIDERATION_PREFIX).await?;
    if target.attestation_envelope.get(OUTCOME_MEMBER).is_some() {
        return Err(Error::InvalidArgument(format!(
            "request_id {} is a ruling, not a filing",
            r.request_id
        )));
    }
    let dimension = crate::federation::admission::envelope_dimension(&target.attestation_envelope)
        .unwrap_or_default()
        .to_owned();
    let mut members = serde_json::json!({
        "references_attestation_id": r.request_id,
        OUTCOME_MEMBER: r.outcome,
        "payload": r.payload,
    });
    if let Some(c) = target.attestation_envelope.get("community_id") {
        members["community_id"] = c.clone();
    }
    let mut row = input(envelope(members, &dimension, 1.0)?);
    row.attested_key_id = Some(target.attested_key_id);
    Ok(row)
}

/// **A credits balance as a row** (CC 3.1.9.6):
/// `credits:{domain}:{language}:{subject}`, attested to the contributor, the
/// balance in `balance` (score `+1`: the family is positive-only and a
/// balance is not a `[-1, 1]` scalar). This node's rows project into
/// `credits_ledger` ([`crate::federation::ledger_projection`]).
///
/// # Errors
///
/// [`Error::InvalidArgument`] for a non-finite balance or a non-vocabulary
/// segment.
pub fn plan_credits_row(u: &CreditsUpdate) -> Result<EmitAttestationInput, Error> {
    if !u.new_balance.is_finite() {
        return Err(Error::InvalidArgument("new_balance is not finite".into()));
    }
    for (f, v) in [("domain", &u.domain), ("subject", &u.subject)] {
        vocab_segment(f, v)?;
    }
    if u.language.is_empty() || u.contributor_id.is_empty() {
        return Err(Error::InvalidArgument(
            "a balance names its contributor and language".into(),
        ));
    }
    let members = serde_json::json!({
        lp::BALANCE_MEMBER: u.new_balance,
        lp::SOURCE_CONTRIBUTION_MEMBER: u.source_contribution,
    });
    let dimension = format!(
        "{}{}:{}:{}:v1",
        lp::CREDITS_PREFIX,
        u.domain,
        u.language,
        u.subject
    );
    let mut row = input(envelope(members, &dimension, 1.0)?);
    row.attested_key_id = Some(u.contributor_id.clone());
    Ok(row)
}

/// **An expertise balance as a row** (CC 3.1.9.6):
/// `expertise:{domain}:{language}`, attested to the contributor, score = the
/// expertise, with `expertise` and `is_active` members.
///
/// # Errors
///
/// [`Error::InvalidArgument`] for an expertise outside `[0, 1]`.
pub fn plan_expertise_row(u: &ExpertiseUpdate) -> Result<EmitAttestationInput, Error> {
    if !(0.0..=1.0).contains(&u.new_expertise) {
        return Err(Error::InvalidArgument(format!(
            "new_expertise must be in [0, 1] (got {})",
            u.new_expertise
        )));
    }
    vocab_segment("domain", &u.domain)?;
    if u.language.is_empty() || u.contributor_id.is_empty() {
        return Err(Error::InvalidArgument(
            "a balance names its contributor and language".into(),
        ));
    }
    let members = serde_json::json!({
        lp::EXPERTISE_MEMBER: u.new_expertise,
        lp::IS_ACTIVE_MEMBER: u.new_active_tier,
        lp::SOURCE_CONTRIBUTION_MEMBER: u.source_contribution,
    });
    let dimension = format!("{}{}:{}:v1", lp::EXPERTISE_PREFIX, u.domain, u.language);
    let mut row = input(envelope(members, &dimension, u.new_expertise)?);
    row.attested_key_id = Some(u.contributor_id.clone());
    Ok(row)
}

/// Route a Contribution body to its planner: a `takedown_notice` subject
/// kind is the notice row (its payload a [`TakedownNoticePayload`]), signed
/// by `signer_key_id`; every other kind is [`plan_contribution_row`].
///
/// # Errors
///
/// The planner's.
pub fn plan_any_contribution(
    c: &ContributionInput,
    signer_key_id: &str,
) -> Result<EmitAttestationInput, Error> {
    if c.subject.subject.as_deref() == Some(TAKEDOWN_NOTICE_SUBJECT_KIND) {
        let p: TakedownNoticePayload = serde_json::from_value(c.payload.clone())
            .map_err(|e| Error::InvalidArgument(format!("takedown_notice payload shape: {e}")))?;
        return plan_takedown_notice_row(&p, signer_key_id);
    }
    plan_contribution_row(c)
}

// ─── reads ───────────────────────────────────────────────────────────

/// A page of rows and the cursor of the next one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RowPage {
    /// The rows, newest first.
    pub items: Vec<Attestation>,
    /// The next page's cursor; `None` at the end.
    pub next_cursor: Option<crate::ceg::list::federation::AttestationCursor>,
}

/// What a Contribution list narrows to, beyond its author.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionsFilter {
    /// Only this `contribution_type`.
    #[serde(default)]
    pub contribution_type: Option<ContributionType>,
    /// Only this subject kind (an exact dimension).
    #[serde(default)]
    pub subject_kind: Option<String>,
    /// Only this domain.
    #[serde(default)]
    pub domain: Option<String>,
    /// Only this language.
    #[serde(default)]
    pub language: Option<String>,
}

fn page_limit(limit: u32) -> Result<std::num::NonZeroU32, Error> {
    std::num::NonZeroU32::new(limit)
        .filter(|n| n.get() <= crate::federation::attestation_query::MAX_PAGE)
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "limit {limit} is outside 1..={}",
                crate::federation::attestation_query::MAX_PAGE
            ))
        })
}

async fn run(
    dir: &dyn FederationDirectory,
    q: crate::federation::attestation_query::AttestationQuery,
    keep: impl Fn(&Attestation) -> bool,
) -> Result<RowPage, Error> {
    use crate::federation::attestation_query::AttestationReads;
    let page = dir
        .query_attestations(&q)
        .await
        .served()
        .map_err(Error::from)?;
    Ok(RowPage {
        items: page.rows.into_iter().filter(|r| keep(r)).collect(),
        next_cursor: page.next,
    })
}

/// `author_id`'s Contribution rows, newest first, narrowed by `filter`. A
/// page holds at most `limit` rows (fewer when the filter narrows inside
/// it); follow `next_cursor` to the end. Rows are read by key, so a list
/// pins its author.
///
/// # Errors
///
/// [`Error::InvalidArgument`] for a bad limit; a read the store did not
/// serve.
pub async fn list_contributions(
    dir: &dyn FederationDirectory,
    author_id: &str,
    filter: &ContributionsFilter,
    after: Option<crate::ceg::list::federation::AttestationCursor>,
    limit: u32,
) -> Result<RowPage, Error> {
    use crate::federation::attestation_query::AttestationQuery;
    let q = AttestationQuery::by(author_id, page_limit(limit)?).after(after);
    let q = match &filter.subject_kind {
        Some(k) => q.dimension(&format!("{CONTRIBUTION_PREFIX}{k}:v1")),
        None => q.dimension_prefix(CONTRIBUTION_PREFIX),
    };
    let ct = filter
        .contribution_type
        .map(|c| serde_json::to_value(c).unwrap_or_default());
    run(dir, q, |r| {
        let e = &r.attestation_envelope;
        ct.as_ref()
            .is_none_or(|c| e.get("contribution_type") == Some(c))
            && filter
                .domain
                .as_ref()
                .is_none_or(|d| e.get("domain").and_then(|v| v.as_str()) == Some(d))
            && filter
                .language
                .as_ref()
                .is_none_or(|l| e.get("language").and_then(|v| v.as_str()) == Some(l))
    })
    .await
}

/// The votes on one held Contribution (`vote:{contribution_id}`, attested
/// to its author), newest first, optionally only `voter_id`'s.
///
/// # Errors
///
/// [`Error::NotFound`] when the Contribution is not held; as
/// [`list_contributions`].
pub async fn list_votes(
    dir: &dyn FederationDirectory,
    contribution_id: &str,
    voter_id: Option<&str>,
    after: Option<crate::ceg::list::federation::AttestationCursor>,
    limit: u32,
) -> Result<RowPage, Error> {
    use crate::federation::attestation_query::AttestationQuery;
    let target =
        held_on_family(dir, "contribution_id", contribution_id, CONTRIBUTION_PREFIX).await?;
    let mut q = AttestationQuery::to(&target.attesting_key_id, page_limit(limit)?)
        .dimension(&format!("{VOTE_PREFIX}{contribution_id}:v1"))
        .after(after);
    if let Some(v) = voter_id {
        q = q.authored_by(v);
    }
    run(dir, q, |_| true).await
}

/// `claimant_key_id`'s takedown notice rows, newest first, optionally only
/// those over `content_sha256` and inside `[since, until)` (signed instant).
///
/// # Errors
///
/// As [`list_contributions`].
pub async fn list_takedowns(
    dir: &dyn FederationDirectory,
    claimant_key_id: &str,
    content_sha256: Option<&str>,
    since: Option<chrono::DateTime<chrono::Utc>>,
    until: Option<chrono::DateTime<chrono::Utc>>,
    after: Option<crate::ceg::list::federation::AttestationCursor>,
    limit: u32,
) -> Result<RowPage, Error> {
    use crate::federation::attestation_query::AttestationQuery;
    let q = AttestationQuery::by(claimant_key_id, page_limit(limit)?)
        .dimension_prefix(crate::federation::takedown_tombstone::NOTICE_DIMENSION_PREFIX)
        .after(after);
    run(dir, q, |r| {
        content_sha256.is_none_or(|c| {
            r.attestation_envelope
                .get("content_sha256")
                .and_then(|v| v.as_str())
                == Some(c)
        }) && since.is_none_or(|s| r.asserted_at >= s)
            && until.is_none_or(|u| r.asserted_at < u)
    })
    .await
}

// ─── the Engine doors ────────────────────────────────────────────────

#[cfg(any(feature = "postgres", feature = "sqlite"))]
impl crate::Engine {
    /// Sign `row` with this engine's own composed hybrid signer and put it
    /// through the plane's door. Returns the row's `attestation_id`.
    async fn cirisnode_emit(&self, row: EmitAttestationInput) -> Result<String, Error> {
        self.emit_attestation_self(row).await.map_err(Error::from)
    }

    async fn cirisnode_signer_key_id(&self) -> Result<String, Error> {
        self.local_derived_key_id()
            .await
            .map_err(|e| Error::Backend(format!("cirisnode signer: {e}")))
    }

    /// v60.0.0 — **put a Contribution**: the `contribution:{subject_kind}` row
    /// (or, for `takedown_notice`, the `takedown_notice:{basis}:v1` row),
    /// signed by this engine. Returns the row's `attestation_id` — the
    /// Contribution's id.
    ///
    /// # Errors
    ///
    /// The planner's refusals; the plane's.
    pub async fn cirisnode_put_contribution(&self, c: &ContributionInput) -> Result<String, Error> {
        let signer = self.cirisnode_signer_key_id().await?;
        let row = plan_any_contribution(c, &signer)?;
        self.cirisnode_emit(row).await
    }

    /// v60.0.0 — **cast a vote**: the `vote:{contribution_id}` row.
    ///
    /// # Errors
    ///
    /// [`plan_vote_row`]'s; the plane's.
    pub async fn cirisnode_cast_vote(&self, v: &VoteInput) -> Result<String, Error> {
        let dir = self.federation_directory();
        let row = plan_vote_row(dir.as_ref(), v).await?;
        self.cirisnode_emit(row).await
    }

    /// v60.0.0 — **file a moderation event**: the `moderation:{allegation_type}`
    /// row; the plane's moderation gate decides who may file.
    ///
    /// # Errors
    ///
    /// [`plan_moderation_row`]'s; the plane's (`DelegatedScopeUnauthorized`).
    pub async fn cirisnode_put_moderation_event(
        &self,
        m: &ModerationInput,
    ) -> Result<String, Error> {
        self.cirisnode_emit(plan_moderation_row(m)?).await
    }

    /// v60.0.0 — **record a slashing**: the `slashing:{outcome}` row.
    ///
    /// # Errors
    ///
    /// [`plan_slashing_row`]'s; the plane's.
    pub async fn cirisnode_put_slashing_attestation(
        &self,
        s: &SlashingInput,
    ) -> Result<String, Error> {
        let dir = self.federation_directory();
        let row = plan_slashing_row(dir.as_ref(), s).await?;
        self.cirisnode_emit(row).await
    }

    /// v60.0.0 — **file a reconsideration**: the `reconsideration:{grounds}`
    /// filing row.
    ///
    /// # Errors
    ///
    /// [`plan_reconsideration_request_row`]'s; the plane's.
    pub async fn cirisnode_put_reconsideration_request(
        &self,
        r: &ReconsiderationRequestInput,
    ) -> Result<String, Error> {
        let dir = self.federation_directory();
        let row = plan_reconsideration_request_row(dir.as_ref(), r).await?;
        self.cirisnode_emit(row).await
    }

    /// v60.0.0 — **rule on a reconsideration**: the ruling row.
    ///
    /// # Errors
    ///
    /// [`plan_reconsideration_ruling_row`]'s; the plane's.
    pub async fn cirisnode_put_reconsideration_attestation(
        &self,
        r: &ReconsiderationRulingInput,
    ) -> Result<String, Error> {
        let dir = self.federation_directory();
        let row = plan_reconsideration_ruling_row(dir.as_ref(), r).await?;
        self.cirisnode_emit(row).await
    }

    /// v60.0.0 — **set a credits balance**: this node's
    /// `credits:{domain}:{language}:{subject}` row, projected into
    /// `credits_ledger` in the row's transaction. Rehomes any pre-V203
    /// balance first.
    ///
    /// # Errors
    ///
    /// [`plan_credits_row`]'s; the plane's.
    pub async fn cirisnode_update_credits_ledger(
        &self,
        u: &CreditsUpdate,
    ) -> Result<String, Error> {
        self.cirisnode_rehome_ledgers().await?;
        self.cirisnode_emit(plan_credits_row(u)?).await
    }

    /// v60.0.0 — **set an expertise balance**: this node's
    /// `expertise:{domain}:{language}` row, projected into `expertise_ledger`.
    /// Rehomes any pre-V203 balance first.
    ///
    /// # Errors
    ///
    /// [`plan_expertise_row`]'s; the plane's.
    pub async fn cirisnode_update_expertise_ledger(
        &self,
        u: &ExpertiseUpdate,
    ) -> Result<String, Error> {
        self.cirisnode_rehome_ledgers().await?;
        self.cirisnode_emit(plan_expertise_row(u)?).await
    }

    /// v60.0.0 — **re-emit every pre-V203 ledger balance as this node's row**
    /// (the hard_case / detection rehome precedent). A legacy ledger row
    /// carries no `attestation_id`, so the projection rebuild reports it red
    /// until it is moved; each one becomes a signed row whose projection
    /// replaces it. Returns how many were moved. A no-op when none remain.
    ///
    /// # Errors
    ///
    /// A ledger read; a refused row (the balance stays as it is and the
    /// rebuild keeps reporting it).
    pub async fn cirisnode_rehome_ledgers(&self) -> Result<usize, Error> {
        use super::service::{LegacyLedgerRow, NodeCoreService as _};
        let legacy = match self.node_core_service() {
            #[cfg(feature = "postgres")]
            crate::engine::NodeCoreDispatch::Postgres(b) => b.legacy_ledger_rows().await?,
            #[cfg(feature = "sqlite")]
            crate::engine::NodeCoreDispatch::Sqlite(b) => b.legacy_ledger_rows().await?,
        };
        let n = legacy.len();
        for row in legacy {
            let planned = match &row {
                LegacyLedgerRow::Credits(u) => plan_credits_row(u)?,
                LegacyLedgerRow::Expertise(u) => plan_expertise_row(u)?,
            };
            self.cirisnode_emit(planned).await?;
        }
        Ok(n)
    }

    /// v60.0.0 — **execute a takedown**: the notice row `notice_attestation_id`
    /// (held here) through the tombstone door
    /// ([`Engine::takedown_tombstone`](crate::Engine::takedown_tombstone)).
    ///
    /// # Errors
    ///
    /// `takedown_unauthorised` when no such notice row is held; the door's.
    pub async fn cirisnode_process_takedown_admission(
        &self,
        notice_attestation_id: &str,
    ) -> Result<crate::federation::takedown_tombstone::TakedownReport, crate::federation::Error>
    {
        super::takedown_handler::process_takedown_admission(self, notice_attestation_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(kind: &str) -> Cell {
        Cell {
            domain: "health".into(),
            language: "en".into(),
            subject: Some(kind.into()),
        }
    }

    fn contribution(kind: &str) -> ContributionInput {
        ContributionInput {
            contribution_type: ContributionType::Proposal,
            subject: cell(kind),
            payload: serde_json::json!({"q": 1}),
            witness_set: None,
        }
    }

    /// I1167 (unit) — the planners mint the registered dimensions, scores in
    /// the families' polarity, and the attested key the table above names.
    #[test]
    fn i1167_each_class_plans_its_registered_row() {
        let c = plan_contribution_row(&contribution("arc_question")).unwrap();
        assert_eq!(
            c.attestation_envelope.dimension.as_deref(),
            Some("contribution:arc_question:v1")
        );
        assert_eq!(c.attestation_type, "scores");
        assert_eq!(c.cohort_scope, "federation");
        let m = plan_moderation_row(&ModerationInput {
            target_contributor: "bad-actor".into(),
            allegation_type: "rogue_vote".into(),
            community_id: "comm".into(),
            payload: serde_json::json!({}),
        })
        .unwrap();
        assert_eq!(
            m.attestation_envelope.dimension.as_deref(),
            Some("moderation:rogue_vote:v1")
        );
        assert_eq!(m.attested_key_id.as_deref(), Some("bad-actor"));
        assert_eq!(m.subject_key_ids, vec!["bad-actor".to_owned()]);
        assert_eq!(
            m.attestation_envelope.to_value()["score"],
            serde_json::json!(-1.0),
            "an accusation scores -1"
        );
        for (community, target) in [("", "bad-actor"), ("comm", "")] {
            let e = plan_moderation_row(&ModerationInput {
                target_contributor: target.into(),
                allegation_type: "rogue_vote".into(),
                community_id: community.into(),
                payload: serde_json::json!({}),
            })
            .unwrap_err();
            assert_eq!(
                e.kind(),
                "cirisnode_invalid_argument",
                "{community:?}/{target:?}"
            );
        }
        let cr = plan_credits_row(&CreditsUpdate {
            contributor_id: "alice".into(),
            domain: "health".into(),
            language: "en".into(),
            subject: "arc_question".into(),
            new_balance: -3.5,
            source_contribution: "c1".into(),
        })
        .unwrap();
        assert_eq!(
            cr.attestation_envelope.dimension.as_deref(),
            Some("credits:health:en:arc_question:v1")
        );
        let v = cr.attestation_envelope.to_value();
        assert_eq!(v["balance"], serde_json::json!(-3.5));
        assert_eq!(
            v["score"],
            serde_json::json!(1.0),
            "credits are positive-only"
        );
        let ex = plan_expertise_row(&ExpertiseUpdate {
            contributor_id: "alice".into(),
            domain: "health".into(),
            language: "en".into(),
            new_expertise: 0.25,
            new_active_tier: true,
            source_contribution: "c1".into(),
        })
        .unwrap();
        let v = ex.attestation_envelope.to_value();
        assert_eq!(v["dimension"], "expertise:health:en:v1");
        assert_eq!(
            (v["expertise"].clone(), v["is_active"].clone()),
            (0.25.into(), true.into())
        );
        for (who, lang) in [("", "en"), ("alice", "")] {
            let c = plan_credits_row(&CreditsUpdate {
                contributor_id: who.into(),
                domain: "health".into(),
                language: lang.into(),
                subject: "arc_question".into(),
                new_balance: 1.0,
                source_contribution: "c1".into(),
            });
            assert!(c.is_err(), "credits {who:?}/{lang:?}");
            let x = plan_expertise_row(&ExpertiseUpdate {
                contributor_id: who.into(),
                domain: "health".into(),
                language: lang.into(),
                new_expertise: 0.5,
                new_active_tier: true,
                source_contribution: "c1".into(),
            });
            assert!(x.is_err(), "expertise {who:?}/{lang:?}");
        }
        assert!(plan_expertise_row(&ExpertiseUpdate {
            new_expertise: 1.5,
            ..ExpertiseUpdate {
                contributor_id: "a".into(),
                domain: "d".into(),
                language: "en".into(),
                new_expertise: 0.0,
                new_active_tier: false,
                source_contribution: "c".into(),
            }
        })
        .is_err());
    }

    /// I1168 (unit) — the retired objects are refused BY NAME: a
    /// `key_grant` Contribution, and every v59 typed envelope member.
    #[test]
    fn i1168_retired_objects_are_refused_by_name() {
        let e = plan_contribution_row(&contribution("key_grant")).unwrap_err();
        assert_eq!(e.kind(), refusal::KEY_GRANT_RETIRED, "{e}");
        assert!(e.to_string().contains("key_grant:{axis}:v1"), "{e}");
        for member in RETIRED_TYPED_MEMBERS {
            let json = serde_json::json!({
                "contribution_type": "proposal",
                "subject": {"domain": "d", "language": "en", "subject": "x"},
                "payload": {},
                *member: "x",
            })
            .to_string();
            let e = decode_input::<ContributionInput>(&json, "contribution").unwrap_err();
            assert_eq!(e.kind(), refusal::TYPED_OBJECT_RETIRED, "{member}: {e}");
        }
        let ok = serde_json::json!({
            "contribution_type": "proposal",
            "subject": {"domain": "d", "language": "en", "subject": "x"},
            "payload": {},
        })
        .to_string();
        decode_input::<ContributionInput>(&ok, "contribution").expect("a body decodes");
        let e = plan_contribution_row(&contribution("Arc")).unwrap_err();
        assert_eq!(e.kind(), "cirisnode_invalid_argument");
    }

    /// I1168 (unit) — the shape checks a planner runs before it reads a row:
    /// a vocabulary segment is `[a-z0-9][a-z0-9_]*` (a bad first byte or a
    /// bad later byte each refuse), and a row id carries no `:` or whitespace
    /// and is not empty (it becomes a dimension segment), refused before any
    /// read as `cirisnode_invalid_argument`, never `cirisnode_not_found`.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1168_ids_and_vocabulary_are_shape_checked() {
        for bad in ["arc-question", "_arc", "Arc", ""] {
            let e = plan_contribution_row(&contribution(bad)).unwrap_err();
            assert_eq!(e.kind(), "cirisnode_invalid_argument", "{bad:?}: {e}");
        }
        plan_contribution_row(&contribution("arc_q2")).expect("a vocabulary token");
        let dir = crate::store::test_backend::test_backend();
        for bad in ["a:b", "", "a b", "x\t"] {
            let e = plan_vote_row(
                &dir,
                &VoteInput {
                    contribution_id: bad.to_owned(),
                    score: 0.0,
                    detail: None,
                    rationale: None,
                },
            )
            .await
            .unwrap_err();
            assert_eq!(e.kind(), "cirisnode_invalid_argument", "{bad:?}: {e}");
        }
        let e = plan_vote_row(
            &dir,
            &VoteInput {
                contribution_id: "held-nowhere".into(),
                score: 0.0,
                detail: None,
                rationale: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            e.kind(),
            "cirisnode_not_found",
            "a well-formed id is read: {e}"
        );
    }

    /// I1170 (unit) — the notice row: CC 3.3.2's members at the top level,
    /// the signer as claimant, `-1`, the notice's expiry the row's, and the
    /// basis in CC's spelling.
    #[test]
    fn i1170_the_takedown_notice_plans_its_row() {
        let p = TakedownNoticePayload {
            content_sha256: "ab".repeat(32),
            perceptual_hash: None,
            content_holder_key_ids: vec![],
            legal_basis: super::super::media_sharing::LegalBasis::Dmca512,
            jurisdiction: "US".into(),
            good_faith_statement: "gf".into(),
            claim_text: "claim".into(),
            evidence_refs: vec![],
            counter_notice_channel: None,
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        };
        let row = plan_takedown_notice_row(&p, "claimant-k").unwrap();
        let v = row.attestation_envelope.to_value();
        assert_eq!(v["dimension"], "takedown_notice:dmca512:v1");
        assert_eq!(v["legal_basis"], "dmca512");
        assert_eq!(v["claimant_key_id"], "claimant-k");
        assert_eq!(v["subject_kind"], TAKEDOWN_NOTICE_SUBJECT_KIND);
        assert_eq!(v["score"], serde_json::json!(-1.0));
        assert!(v.get("expires_at").is_none() || v["expires_at"].is_null());
        assert_eq!(row.expires_at, Some(p.expires_at));
        let routed = plan_any_contribution(
            &ContributionInput {
                contribution_type: ContributionType::Proposal,
                subject: cell(TAKEDOWN_NOTICE_SUBJECT_KIND),
                payload: serde_json::to_value(&p).unwrap(),
                witness_set: None,
            },
            "claimant-k",
        )
        .unwrap();
        assert_eq!(
            routed.attestation_envelope.to_value()["dimension"],
            "takedown_notice:dmca512:v1"
        );
        assert!(plan_contribution_row(&contribution(TAKEDOWN_NOTICE_SUBJECT_KIND)).is_err());
    }
}
