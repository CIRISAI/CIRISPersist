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

use super::location::{check_location_proof_withdrawal, LocationProofWithdrawal};
use super::types::{SignedLocationProof, SignedTouchClaim};
use super::{Error, FederationDirectory, TouchApplyOutcome};

/// A location proof the plan admitted: its `persist_row_hash` derived, and
/// the signed wire index key it is indexed under.
#[derive(Debug, Clone)]
pub(crate) struct PlannedLocationProof {
    /// The record, `location_proof.persist_row_hash` set.
    pub(crate) proof: SignedLocationProof,
    /// `wire_index::record_key` over `(subject_key_id, asserted_at)`.
    pub(crate) wire_index_key: String,
}

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
    /// The held proof under `(subject_key_id, asserted_at)`, if any.
    async fn held_location_proof(
        &self,
        subject_key_id: &str,
        asserted_at: DateTime<Utc>,
    ) -> Result<Option<SignedLocationProof>, Error>;

    /// Insert the planned proof at a fresh serve position, then index it.
    /// A held primary key is the store's refusal (its error, unchanged).
    async fn store_planned_location_proof(
        &self,
        planned: PlannedLocationProof,
    ) -> Result<(), Error>;

    /// Compare-and-set the planned withdrawal onto the held, unwithdrawn row
    /// at a fresh serve position, then index it. `false`: no unwithdrawn row
    /// matched (a rival won), and nothing was written.
    async fn store_planned_location_proof_withdrawal(
        &self,
        planned: PlannedLocationProof,
    ) -> Result<bool, Error>;

    /// Test-only (#986): apply the rival withdrawal armed on this backend,
    /// if any, through its own door.
    #[cfg(test)]
    async fn rival_location_proof_withdrawal(&self) -> Result<(), Error>;

    /// The monotonic-max merge into `freshness_floor`: `true` when the floor
    /// advanced (inserted, or the stored `fresh_as_of` was older).
    async fn store_planned_touch_claim(
        &self,
        planned: PlannedTouchClaim<'_>,
    ) -> Result<bool, Error>;

    /// In ONE transaction: insert the witness (idempotent on
    /// `(peer_id, epoch_id, observed_at_unix_ms)`), then prune the peer's
    /// corpus to its newest [`PlannedWitness::keep`].
    async fn store_planned_witness(&self, planned: PlannedWitness) -> Result<(), Error>;
}

/// `wire_index::record_key` over a proof's primary key, at the
/// microsecond-floor spelling postgres reloads (#646).
fn location_proof_index_key(subject_key_id: &str, asserted_at: &DateTime<Utc>) -> String {
    super::wire_index::record_key(&[
        ("subject_key_id", subject_key_id),
        (
            "asserted_at",
            &super::wire_index::locator_instant(asserted_at),
        ),
    ])
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
    // v21.0.0 (CIRISPersist#502 E4) — mechanistic authorship BEFORE any
    // other admission step.
    super::verify_location_proof_admission(dir, &proof).await?;
    // v53.1.2 (CIRISPersist#984 row 19) — a held PK re-offered as a
    // WITHDRAWAL is the withdraw door's case: the local and the replicated
    // path run the one predicate. Any other re-offer keeps its path (the PK
    // refuses it).
    if proof.location_proof.withdrawn_at.is_some()
        && dir
            .held_location_proof(
                &proof.location_proof.subject_key_id,
                proof.location_proof.asserted_at,
            )
            .await?
            .is_some()
    {
        return withdraw_location_proof_planned(dir, proof).await;
    }
    let mut proof = proof;
    let row = &mut proof.location_proof;
    super::location::validate_location_cell(&row.cell_id, row.cell_resolution)?;
    row.persist_row_hash = super::types::compute_persist_row_hash(&*row)?;
    let wire_index_key = location_proof_index_key(&row.subject_key_id, &row.asserted_at);
    dir.store_planned_location_proof(PlannedLocationProof {
        proof,
        wire_index_key,
    })
    .await
}

/// The door: every backend's `withdraw_location_proof`.
pub(crate) async fn withdraw_location_proof_planned<D: EvidenceStore>(
    dir: &D,
    proof: SignedLocationProof,
) -> Result<(), Error> {
    // #984 row 16 — the signature and standing legs, exactly as a put.
    super::verify_location_proof_admission(dir, &proof).await?;
    let subject = proof.location_proof.subject_key_id.clone();
    let asserted_at = proof.location_proof.asserted_at;
    let Some(held) = dir.held_location_proof(&subject, asserted_at).await? else {
        return Err(Error::InvalidArgument(format!(
            "location_proof_withdraw_not_held: no proof by {subject} at {} is held here",
            asserted_at.to_rfc3339()
        )));
    };
    match check_location_proof_withdrawal(&held, &proof)? {
        LocationProofWithdrawal::AlreadyWithdrawn => return Ok(()),
        LocationProofWithdrawal::Apply => {}
    }
    #[cfg(test)]
    dir.rival_location_proof_withdrawal().await?;
    let mut proof = proof;
    proof.location_proof.persist_row_hash =
        super::types::compute_persist_row_hash(&proof.location_proof)?;
    let wire_index_key = location_proof_index_key(&subject, &asserted_at);
    if dir
        .store_planned_location_proof_withdrawal(PlannedLocationProof {
            proof,
            wire_index_key,
        })
        .await?
    {
        return Ok(());
    }
    // v53.1.3 (#986) — lost the race: the rival's withdrawal stands (the
    // first instant wins), or the row is gone.
    match dir.held_location_proof(&subject, asserted_at).await? {
        Some(now) if now.location_proof.withdrawn_at.is_some() => Ok(()),
        _ => Err(Error::Backend(format!(
            "withdraw_location_proof: the held proof by {subject} at {} changed under the write \
             and is not withdrawn",
            asserted_at.to_rfc3339()
        ))),
    }
}

/// The door: every backend's `put_touch_claim`.
pub(crate) async fn put_touch_claim_planned<D: EvidenceStore>(
    dir: &D,
    claim: &SignedTouchClaim,
) -> Result<TouchApplyOutcome, Error> {
    // v21.6.0 (#519 item 2a-iii) — verify-before-mutation: the full hybrid
    // admission gate, THEN the future-skew guard, THEN the monotonic-max
    // merge.
    super::admission::verify_signed_touch_claim(dir, claim).await?;
    let received_at = Utc::now();
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

/// The door: every backend's `put_wholeness_witness`. Verify BEFORE persist
/// (N3 / RC8 / AV-9): on any failure nothing is written.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn put_wholeness_witness_planned<D: EvidenceStore>(
    dir: &D,
    witness: &ciris_verify_core::substrate::WholenessWitness,
    sig_ed25519_b64: &str,
    sig_ml_dsa_65_b64: Option<&str>,
    pqc_key_id: &str,
    ed25519_pubkey_b64: &str,
    ml_dsa_65_pubkey_b64: Option<&str>,
    disclosed_leaves: Option<&[Vec<u8>]>,
) -> Result<(), Error> {
    let stored = crate::witness::admit_witness(
        witness,
        sig_ed25519_b64,
        sig_ml_dsa_65_b64,
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
        admitted_at: Utc::now(),
    })
    .await
}
