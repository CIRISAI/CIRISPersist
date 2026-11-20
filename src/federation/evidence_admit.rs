//! v61 (CIRISPersist#934, S4a) — **the location proof, touch claim and
//! wholeness witness doors, decided once.**
//!
//! `put_location_proof`, `withdraw_location_proof`, `put_touch_claim` and
//! `put_wholeness_witness` were written twice, in
//! `store/{sqlite,postgres}.rs`, with the same gates in the same order. Each
//! door is now one function here; a backend implements [`EvidenceStore`]:
//! the SQL, the serve position (V130) and the signed wire index. It decides
//! nothing.
//!
//! # Which instant each plan reads
//!
//! `put_touch_claim`'s future-skew bound is judged at the door's one clock
//! read (`received_at`); `put_wholeness_witness` stamps `admitted_at` with it
//! on both backends (postgres took the column's database default before v61).
//! The location proof doors read no instant: the withdrawal is judged on the
//! two records.

use chrono::{DateTime, Utc};

use super::types::{SignedLocationProof, SignedTouchClaim};
use super::{Error, FederationDirectory, TouchApplyOutcome};

/// A touch claim the plan admitted, its two JSON columns encoded.
#[derive(Debug, Clone)]
pub(crate) struct PlannedTouchClaim<'a> {
    /// The admitted claim.
    pub(crate) claim: &'a SignedTouchClaim,
    /// `signed_envelope`, JSON text.
    pub(crate) envelope_json: String,
    /// `signature`, JSON text.
    pub(crate) signature_json: String,
}

/// v62.0.0 (v62 P5b) — a NODE-LOCAL touch the plan admitted: the floor's
/// fields, and nothing signed (the node is the only author; the row never
/// crosses the mesh).
#[derive(Debug, Clone)]
pub(crate) struct PlannedLocalTouch<'a> {
    /// What is being kept alive.
    pub(crate) target_key_id: &'a str,
    /// The kind of thing `target_key_id` names.
    pub(crate) target_kind: &'a str,
    /// The lower bound to merge (monotonic max).
    pub(crate) fresh_as_of: DateTime<Utc>,
    /// The mandatory privacy row, checked.
    pub(crate) cohort_scope: &'a str,
    /// The writing node's own key id (`node_key_id`), or empty when the
    /// store has none: provenance only, never a signer.
    pub(crate) node_key_id: String,
}

/// A wholeness witness the plan admitted, its integer columns checked into
/// the stored widths.
#[derive(Debug, Clone)]
pub(crate) struct PlannedWitness {
    /// The admitted witness.
    pub(crate) stored: crate::witness::StoredWitness,
    /// `epoch_id`, as stored.
    pub(crate) epoch_id: i64,
    /// `observed_at_unix_ms`, as stored.
    pub(crate) observed_at_unix_ms: i64,
    /// `claim_namespaces`, a JSON array of strings.
    pub(crate) claim_namespaces: serde_json::Value,
    /// The per-peer corpus cap ([`crate::witness::WITNESS_CORPUS_K`]).
    pub(crate) keep: i64,
    /// The door's receipt instant.
    pub(crate) admitted_at: DateTime<Utc>,
}

/// The evidence executor. Storage only.
#[async_trait::async_trait]
pub(crate) trait EvidenceStore: FederationDirectory + Sized {
    /// The monotonic-max merge into `freshness_floor`: `true` when the floor
    /// advanced (inserted, or the stored `fresh_as_of` was older).
    async fn store_planned_touch_claim(
        &self,
        planned: PlannedTouchClaim<'_>,
    ) -> Result<bool, Error>;

    /// v62.0.0 (v62 P5b) — the same monotonic-max merge for a node-local
    /// touch: `true` when the floor advanced. The row is stored under
    /// [`NODE_LOCAL_TOUCH_FORM`](super::types::NODE_LOCAL_TOUCH_FORM), with an
    /// empty `signature` and `{}` as `signed_envelope` (an advanced
    /// earlier-form row loses its signature: the floor it now holds is the
    /// node's own).
    async fn store_planned_touch_claim_local(
        &self,
        planned: PlannedLocalTouch<'_>,
    ) -> Result<bool, Error>;

    /// In ONE transaction: insert the witness (idempotent on
    /// `(peer_id, epoch_id, observed_at_unix_ms)`), then prune the peer's
    /// corpus to its newest [`PlannedWitness::keep`].
    async fn store_planned_witness(&self, planned: PlannedWitness) -> Result<(), Error>;
}

/// The door: every backend's `put_location_proof`.
pub(crate) async fn put_location_proof_planned<D: EvidenceStore>(
    dir: &D,
    proof: SignedLocationProof,
) -> Result<(), Error> {
    // v52.0.0 (CIRISPersist#672) — a re-offer of a held record settles here,
    // before any verification.
    if super::replication_policy::settle_if_held(
        dir,
        super::replication_policy::EnvelopeKind::LocationProof,
        &proof,
    )
    .await?
    {
        return Ok(());
    }
    // v62.0.0 (JSON-cut slice A) — after the held settle (I235), the
    // earlier-form refusal.
    super::edition2::door::refuse_earlier_form("location_proof")?;
    // v62.0.0 (F0-cp9) — the earlier-form location proof (a bound-hybrid
    // authority signature) is deleted with its verify: an edition-2
    // `location_proof:{version}` statement is read through the voices, not
    // stored here.
    Err(super::edition2::door::earlier_form_signature(
        "location_proof",
    ))
}

/// The door: every backend's `withdraw_location_proof`.
pub(crate) async fn withdraw_location_proof_planned<D: EvidenceStore>(
    dir: &D,
    proof: SignedLocationProof,
) -> Result<(), Error> {
    // v62.0.0 (JSON-cut slice F) — the one shared earlier-form refusal,
    // before any parse or verify (CC 2.6.1.12).
    super::edition2::door::refuse_earlier_form("location_proof")?;
    // v62.0.0 (F0-cp9) — as `put_location_proof_planned`: deleted with the
    // earlier form.
    let _ = (dir, proof);
    Err(super::edition2::door::earlier_form_signature(
        "location_proof",
    ))
}

/// The door: every backend's `put_touch_claim`.
pub(crate) async fn put_touch_claim_planned<D: EvidenceStore>(
    dir: &D,
    claim: &SignedTouchClaim,
) -> Result<TouchApplyOutcome, Error> {
    super::edition2::door::refuse_earlier_form("touch_claim")?;
    // v21.6.0 (#519 item 2a-iii) — verify-before-mutation: the full hybrid
    // admission gate, THEN the future-skew guard, THEN the monotonic-max
    // merge.
    super::admission::verify_signed_touch_claim(dir, claim).await?;
    let received_at = crate::host::clock::now();
    super::admission::verify_touch_claim_admission(
        claim,
        received_at,
        super::admission::DEFAULT_MAX_TOUCH_SKEW,
    )?;
    let envelope_json = serde_json::to_string(&claim.signed_envelope)
        .map_err(|e| Error::Backend(format!("signed_envelope: {e}")))?;
    let signature_json = serde_json::to_string(&claim.signature)
        .map_err(|e| Error::Backend(format!("signature: {e}")))?;
    let advanced = dir
        .store_planned_touch_claim(PlannedTouchClaim {
            claim,
            envelope_json,
            signature_json,
        })
        .await?;
    Ok(if advanced {
        TouchApplyOutcome::Advanced
    } else {
        TouchApplyOutcome::NotFresher
    })
}

/// v62.0.0 (v62 P5b; RULINGS "a touch claim is node-local";
/// CC_FAMILYMAP_ANSWER: a node-local fold) — **the door: every backend's
/// `put_touch_claim_local`.** The node's own write of its freshness floor:
/// no object, no signature (the node is the only author, and the floor never
/// crosses the mesh), so no earlier-form refusal applies. The rules the
/// signed door enforced on the floor itself stand, verify-before-mutation:
/// a non-empty target, a closed-set `cohort_scope`
/// ([`check_cohort_scope`](super::admission::check_cohort_scope), the
/// mandatory privacy row), the future-skew guard at the door's one clock
/// read ([`check_touch_fresh_as_of_skew`](super::admission::check_touch_fresh_as_of_skew),
/// [`DEFAULT_MAX_TOUCH_SKEW`](super::admission::DEFAULT_MAX_TOUCH_SKEW)),
/// then the monotonic-max merge.
pub(crate) async fn put_touch_claim_local_planned<D: EvidenceStore>(
    dir: &D,
    target_key_id: &str,
    target_kind: &str,
    fresh_as_of: DateTime<Utc>,
    cohort_scope: &str,
) -> Result<TouchApplyOutcome, Error> {
    if target_key_id.is_empty() || target_kind.is_empty() {
        return Err(Error::InvalidArgument(
            "touch_claim: target_key_id and target_kind must be non-empty".into(),
        ));
    }
    super::admission::check_cohort_scope(cohort_scope)?;
    let received_at = crate::host::clock::now();
    super::admission::check_touch_fresh_as_of_skew(
        fresh_as_of,
        received_at,
        super::admission::DEFAULT_MAX_TOUCH_SKEW,
    )?;
    let advanced = dir
        .store_planned_touch_claim_local(PlannedLocalTouch {
            target_key_id,
            target_kind,
            fresh_as_of,
            cohort_scope,
            node_key_id: dir.node_key_id().unwrap_or_default(),
        })
        .await?;
    Ok(if advanced {
        TouchApplyOutcome::Advanced
    } else {
        TouchApplyOutcome::NotFresher
    })
}

/// The door: every backend's `put_wholeness_witness`. Verify BEFORE persist
/// (N3 / RC8 / AV-9): on any failure nothing is written.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn put_wholeness_witness_planned<D: EvidenceStore>(
    dir: &D,
    witness: &ciris_verify_core::substrate::WholenessWitness,
    signature: &crate::verify::sig19::Sig19,
    pqc_key_id: &str,
    ed25519_pubkey_b64: &str,
    ml_dsa_65_pubkey_b64: Option<&str>,
    disclosed_leaves: Option<&[Vec<u8>]>,
) -> Result<(), Error> {
    let stored = crate::witness::admit_witness(
        witness,
        signature,
        pqc_key_id,
        ed25519_pubkey_b64,
        ml_dsa_65_pubkey_b64,
        disclosed_leaves,
    )?;
    let epoch_id = i64::try_from(stored.epoch_id)
        .map_err(|_| Error::Backend("witness epoch_id exceeds i64".into()))?;
    let observed_at_unix_ms = i64::try_from(stored.observed_at_unix_ms)
        .map_err(|_| Error::Backend("witness observed_at_unix_ms exceeds i64".into()))?;
    let claim_namespaces = serde_json::Value::Array(
        stored
            .claim_namespaces
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect(),
    );
    dir.store_planned_witness(PlannedWitness {
        stored,
        epoch_id,
        observed_at_unix_ms,
        claim_namespaces,
        keep: i64::try_from(crate::witness::WITNESS_CORPUS_K).unwrap_or(i64::MAX),
        admitted_at: crate::host::clock::now(),
    })
    .await
}
