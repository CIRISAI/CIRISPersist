//! The `LedgerService` trait — the working-index surface over CC 3.3.10.1
//! ledgers. Implemented by both persistent backends; consumers reach it
//! through the FFI or directly on the backend handle.

use std::future::Future;

use super::types::{
    AdvanceOutcome, ForkEvidenceRow, LedgerCheckpointRow, LedgerEntryRangeRow, LedgerHeadRow,
    RegisterOutcome,
};
use super::Error;

/// Working-index operations for owner-serialized ledgers.
///
/// Every write verb is idempotent for byte-identical re-puts and
/// fail-secure for differing claims on occupied keys — the same
/// absorb-the-race-then-re-read discipline `put_accord_participation`
/// settled in #719: `ON CONFLICT DO NOTHING` alone silently accepts a
/// differing concurrent write, which is exactly what these doors exist to
/// refuse, so a zero-row result re-reads to decide.
pub trait LedgerService: Send + Sync {
    /// L1 — register the ledger for `(owner_key_id, unit,
    /// standard_version)`. The `ledger_id` is derived internally via
    /// [`crate::ledgers::standard::derive_ledger_id`] — callers never
    /// choose it, which is what makes "a second ledger claiming an
    /// occupied triple" structurally refusable.
    ///
    /// Identical re-registration → `Ok(AlreadyRegistered)`. A concurrent
    /// or prior differing claim → `Error::Conflict`.
    fn register_ledger(
        &self,
        owner_key_id: &str,
        unit: &str,
        standard_version: &str,
    ) -> impl Future<Output = Result<(String, RegisterOutcome), Error>> + Send;

    /// L4 bookkeeping — move the stored head forward.
    ///
    /// * new seq > stored (or no head yet) → `Advanced`
    /// * identical `(seq, head_hash)` → `Unchanged`
    /// * seq below stored head → `Stale` (no-op)
    /// * DIFFERENT hash at the stored seq → `Error::Conflict` — the
    ///   fork shape; the door never overwrites, the caller assembles
    ///   [`crate::ledgers::standard::ForkEvidence`] and records it.
    fn advance_head(
        &self,
        ledger_id: &str,
        seq: u64,
        head_hash: &str,
        witness_anchor_ref: Option<&str>,
        source_envelope_ref: Option<&str>,
    ) -> impl Future<Output = Result<AdvanceOutcome, Error>> + Send;

    /// Point lookup by `ledger_id`.
    fn get_ledger(
        &self,
        ledger_id: &str,
    ) -> impl Future<Output = Result<Option<LedgerHeadRow>, Error>> + Send;

    /// Point lookup by the L1 triple.
    fn find_ledger_by_triple(
        &self,
        owner_key_id: &str,
        unit: &str,
        standard_version: &str,
    ) -> impl Future<Output = Result<Option<LedgerHeadRow>, Error>> + Send;

    /// All ledgers bound to one steward-bound identity (the
    /// `idx_ledger_heads_owner` index), ordered by `ledger_id`.
    fn list_ledgers_for_owner(
        &self,
        owner_key_id: &str,
    ) -> impl Future<Output = Result<Vec<LedgerHeadRow>, Error>> + Send;

    /// L5 — store a co-witnessed checkpoint. Checkpoints are immutable:
    /// identical re-put is a no-op (`Ok(false)`), first write is
    /// `Ok(true)`, a differing row at an occupied `(ledger_id, seq)` is
    /// `Error::Conflict`. `balance_minor` must be a canonical i128
    /// decimal string. The ledger must be registered (`NotFound`).
    fn put_checkpoint(
        &self,
        checkpoint: &LedgerCheckpointRow,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// The highest-seq checkpoint for a ledger, if any.
    fn latest_checkpoint(
        &self,
        ledger_id: &str,
    ) -> impl Future<Output = Result<Option<LedgerCheckpointRow>, Error>> + Send;

    /// L2/L6 — index which `evidence_refs` blob holds entries
    /// `[from_seq, to_seq]`. Same immutable/idempotent shape as
    /// checkpoints, keyed on `(ledger_id, from_seq)`.
    fn put_entry_range(
        &self,
        range: &LedgerEntryRangeRow,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// All entry ranges for a ledger, ordered by `from_seq`.
    fn list_entry_ranges(
        &self,
        ledger_id: &str,
    ) -> impl Future<Output = Result<Vec<LedgerEntryRangeRow>, Error>> + Send;

    /// L8 — record a proven fork for the adjudication plane. The
    /// `evidence_id` is derived from the evidence content
    /// (idempotent; returns the id either way). Deliberately no
    /// registered-ledger precondition — evidence about a ledger this
    /// node never registered must not be droppable.
    fn record_fork_evidence(
        &self,
        evidence: &crate::ledgers::standard::ForkEvidence,
    ) -> impl Future<Output = Result<String, Error>> + Send;

    /// All recorded fork evidence for a ledger, ordered by `evidence_id`.
    fn list_fork_evidence(
        &self,
        ledger_id: &str,
    ) -> impl Future<Output = Result<Vec<ForkEvidenceRow>, Error>> + Send;
}
