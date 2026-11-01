//! v61 (CIRISPersist#934, S4a) — **the accord evidence doors, decided
//! once.**
//!
//! `put_accord_proposal`, `put_accord_participation` and `put_accord_decision`
//! were written twice, in `store/{sqlite,postgres}.rs`: the same evidence
//! cursor allocation (`monotonic_admission_instant` over the stored maximum),
//! the same `accord_quorum::prepare_*` gate, the same M2 / M6 / nonce
//! single-use verdicts. Each door is now one function here; a backend
//! implements [`AccordStore`]: the SQL, the transaction and the lock. It
//! decides nothing: every verdict about the caller's record is the plan's,
//! and a write reports what it found ([`HeldRow`]), never what that means.
//!
//! # Which instant each plan reads
//!
//! The door's one clock read is `received_at`. The proposal's `created_at`
//! and the participation's `server_arrival_at` are allocated from it and the
//! stored maximum (the evidence cursor, #662); the decision's `decided_at` is
//! `received_at` itself.

use chrono::{DateTime, Utc};

use super::accord_quorum::{self, PreparedDecision, PreparedParticipation, PreparedProposal};
use super::{Error, FederationDirectory};
use ciris_verify_core::accord_live_quorum::{AccordDecision, AccordParticipation, AccordProposal};
use ciris_verify_core::threshold::ThresholdMember;

/// What a write keyed on an immutable row found: the row was absent and is
/// now written, or a row was already held under the key with this content
/// hash, or with a different one. The plan decides what each means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeldRow {
    /// No row was held; this write stored it.
    Inserted,
    /// A row with the same `persist_row_hash` was held; nothing written.
    Identical,
    /// A row with a different `persist_row_hash` was held; nothing written.
    Differs,
}

impl HeldRow {
    /// The verdict over a held content hash (`None`: no row was held).
    #[must_use]
    pub(crate) fn of_held(held: Option<&str>, planned: &str) -> Self {
        match held {
            None => Self::Inserted,
            Some(h) if h == planned => Self::Identical,
            Some(_) => Self::Differs,
        }
    }
}

/// The accord evidence executor. Storage only.
#[async_trait::async_trait]
pub(crate) trait AccordStore: FederationDirectory + Sized {
    /// `MAX(created_at)` over `accord_proposal` (the evidence cursor's
    /// proposal half).
    async fn last_accord_proposal_created_at(&self) -> Result<Option<DateTime<Utc>>, Error>;

    /// `MAX(server_arrival_at)` over `accord_participation` (the cursor's
    /// other half).
    async fn last_accord_participation_arrival(&self) -> Result<Option<DateTime<Utc>>, Error>;

    /// In ONE transaction (postgres: under the nonce advisory lock): a held
    /// `proposal_digest` writes nothing and is `None`; otherwise claim
    /// `(family_key_id, nonce)` (V189) and, when the claim is this proposal's,
    /// insert the row (`None`). `Some(owner)`: the claim names another
    /// proposal, and nothing was written.
    async fn store_planned_accord_proposal(
        &self,
        prep: PreparedProposal,
    ) -> Result<Option<String>, Error>;

    /// Insert the participation keyed on `(proposal_digest, pinned_pubkey)`
    /// unless one is held, and report the held row's hash against the
    /// planned one (re-read after a concurrent insert won).
    async fn store_planned_accord_participation(
        &self,
        prep: PreparedParticipation,
    ) -> Result<HeldRow, Error>;

    /// Insert the decision keyed on `proposal_digest` unless one is held,
    /// and report the held row's hash against the planned one.
    async fn store_planned_accord_decision(&self, prep: PreparedDecision)
        -> Result<HeldRow, Error>;
}

/// The door: every backend's `put_accord_proposal`.
pub(crate) async fn put_accord_proposal_planned<D: AccordStore>(
    dir: &D,
    proposal: AccordProposal,
    authority_signature: Option<serde_json::Value>,
) -> Result<(), Error> {
    let received_at = Utc::now();
    let last = dir.last_accord_proposal_created_at().await?;
    let created_at = super::types::monotonic_admission_instant(received_at, last);
    let prep = accord_quorum::prepare_proposal(&proposal, authority_signature, created_at)?;
    // v54.1.0 (#1047) — single use: the proposer-minted nonce names one
    // proposal per family; a held digest is an idempotent replay.
    match dir.store_planned_accord_proposal(prep).await? {
        Some(owner) => Err(accord_quorum::nonce_reused(&proposal, &owner)),
        None => Ok(()),
    }
}

/// The door: every backend's `put_accord_participation`.
pub(crate) async fn put_accord_participation_planned<D: AccordStore>(
    dir: &D,
    participation: AccordParticipation,
    standing_roster: &[ThresholdMember],
) -> Result<(), Error> {
    // The proposal MUST exist: verify-before-mutation needs it to verify the
    // participation's binding.
    let stored = dir
        .get_accord_proposal(&participation.proposal_digest)
        .await?
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "accord participation references unknown proposal {:?}",
                participation.proposal_digest
            ))
        })?;
    let received_at = Utc::now();
    let last = dir.last_accord_participation_arrival().await?;
    let arrival = super::types::monotonic_admission_instant(received_at, last);
    let prep = accord_quorum::verify_and_prepare_participation(
        &stored.proposal,
        &participation,
        standing_roster,
        arrival,
    )?;
    // M6 — one vote per holder (pinned pubkey): an identical re-PUT is a
    // no-op, a different vote a conflict.
    match dir.store_planned_accord_participation(prep).await? {
        HeldRow::Inserted | HeldRow::Identical => Ok(()),
        HeldRow::Differs => Err(Error::Conflict(format!(
            "accord participation: holder (pinned pubkey) already voted differently on proposal \
             {:?} (M6 — one vote per holder)",
            participation.proposal_digest
        ))),
    }
}

/// The door: every backend's `put_accord_decision`.
pub(crate) async fn put_accord_decision_planned<D: AccordStore>(
    dir: &D,
    decision: AccordDecision,
) -> Result<(), Error> {
    let received_at = Utc::now();
    let prep = accord_quorum::prepare_decision(&decision, received_at)?;
    let digest = prep.proposal_digest.clone();
    // M2 — immutable: an identical re-PUT is a no-op, a differing one a
    // conflict.
    match dir.store_planned_accord_decision(prep).await? {
        HeldRow::Inserted | HeldRow::Identical => Ok(()),
        HeldRow::Differs => Err(Error::Conflict(format!(
            "accord decision for proposal {digest:?} already recorded with different content \
             (M2 — immutable)"
        ))),
    }
}
