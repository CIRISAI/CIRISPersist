//! #302 (FSD-004) — accord live-quorum storage substrate.
//!
//! The durable half of the constitutional kill-switch's decimation-recovery
//! live quorum. CIRISVerify ships the **stateless** machinery in
//! [`ciris_verify_core::accord_live_quorum`] (CIRISVerify#150 / #98); the
//! CIRISServer Phase-3 runtime (CIRISServer#122) drives it and writes the
//! wire objects + anti-replay state **through** persist. Persist is the
//! storage substrate, so the tables are ours (V091) — the live-quorum
//! sibling of the `federation_keys` accord-holder storage.
//!
//! Division of labour (from #302): **persist stores + dedups + verifies
//! participations + holds nonce/halt state; the SERVER runs the tally**
//! (`verify_fire_by_live_quorum` etc. re-verify every participation at tally
//! time — persist stores the inputs + the server's frozen `AccordDecision`).
//!
//! Load-bearing rule: store the verify-core canonical objects **verbatim**
//! and DERIVE the indexed columns from them via verify-core
//! ([`AccordProposal::digest`] etc.) — never trust a caller-supplied digest,
//! never re-derive the bytes by hand.
//!
//! **Recovery (`verify_recovery_supersede`, H7) is deliberately absent** —
//! it bends entrenchment for the captured-roster case and cannot go live
//! until the CIRIS Constitution sanctions it (CIRISAccord#4). This module
//! handles `fire` / `roster_change` / `resume` only.

use chrono::{DateTime, Utc};
use ciris_verify_core::accord_live_quorum::{AccordDecision, AccordParticipation, AccordProposal};

// v62.0.0 (JSON-cut slice F; CC rc20) — the prepared write columns, the
// participation verify and the nonce dedup are gone with the write doors:
// rc20 has no accord proposal, participation or decision object. The read
// row types below stay for what an upgraded store holds.

/// v54.1.0 (CIRISPersist#1042 follow-up C) — the stable refusal token of
/// [`crate::federation::Error::AccordProposalNonceReused`].
pub const ACCORD_PROPOSAL_NONCE_REUSED: &str = "accord_proposal_nonce_reused";

// ─────────────────────────────────────────────────────────────────────
// Read row types — what list/get return. The verbatim `*_json` round-trips
// back to the verify-core object for the server's tally.
// ─────────────────────────────────────────────────────────────────────

/// A stored `accord_proposal`: the verbatim verify-core object + the
/// server-supplied authority signature envelope.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredProposal {
    /// The verbatim verify-core proposal (round-trips for the server tally).
    pub proposal: AccordProposal,
    /// The server-supplied authority-signature envelope, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_signature: Option<serde_json::Value>,
    /// Substrate row hash (canonical SHA-256 of the stored proposal).
    pub persist_row_hash: String,
    /// When persist admitted the proposal.
    pub created_at: DateTime<Utc>,
}

/// A stored `accord_participation`: the verbatim verify-core object + the
/// authoritative server-arrival instant (C2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredParticipation {
    /// The verbatim verify-core participation (incl. the hybrid signature).
    pub participation: AccordParticipation,
    /// The member's PINNED Ed25519 pubkey — the M6 dedup key.
    pub pinned_pubkey: String,
    /// The AUTHORITATIVE arrival instant persist stamped (C2 window clock);
    /// `participation.signed_at` is advisory only.
    pub server_arrival_at: DateTime<Utc>,
    /// Substrate row hash (canonical SHA-256 of the stored participation).
    pub persist_row_hash: String,
}

/// A stored `accord_decision`: the verbatim frozen-L snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredDecision {
    /// The verbatim verify-core frozen-L decision snapshot (M2, immutable).
    pub decision: AccordDecision,
    /// Substrate row hash (canonical SHA-256 of the stored decision).
    pub persist_row_hash: String,
    /// When persist admitted the decision.
    pub decided_at: DateTime<Utc>,
}

/// The active CONSTITUTIONAL halt for a family (H2). `None` when no halt is
/// active (a resume cleared it).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveHalt {
    /// The accord family the halt applies to.
    pub family_key_id: String,
    /// The active CONSTITUTIONAL halt id (a resume binds `sha256(this)`).
    pub active_halt_id: String,
    /// When the halt became active.
    pub set_at: DateTime<Utc>,
}
