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

/// v62.0.0 (wave GC6; CC 2.7 rc21 X4) — **I3885: two heads at one seq are
/// contested, in either arrival order.** Two ledgers (owners `{tag}-ab` and
/// `{tag}-ba`) each receive heads `A` and `B` at seq 3, in opposite orders.
/// Both end the same: the second offer answers `Contested`, no head concludes
/// (`seq`/`head_hash` both `None`), both heads are kept as
/// `ledger_triple_contested` evidence, a re-offer of either answers
/// `Contested` and adds nothing, and a later seq advances nothing.
#[cfg(test)]
pub(crate) async fn contest_either_order_body<S: LedgerService>(svc: &S, tag: &str) {
    use super::standard::LEDGER_TRIPLE_CONTESTED;
    use super::types::AdvanceOutcome;
    let mut ends = Vec::new();
    for (owner, first, second) in [
        (format!("{tag}-ab"), "hash-a", "hash-b"),
        (format!("{tag}-ba"), "hash-b", "hash-a"),
    ] {
        let (id, _) = svc.register_ledger(&owner, "usd", "1").await.unwrap();
        assert_eq!(
            svc.advance_head(&id, 3, first, None, None).await.unwrap(),
            AdvanceOutcome::Advanced,
            "I3885: the first head lands"
        );
        assert_eq!(
            svc.advance_head(&id, 3, second, None, None).await.unwrap(),
            AdvanceOutcome::Contested,
            "I3885: the second head contests it, never refused"
        );
        let row = svc.get_ledger(&id).await.unwrap().unwrap();
        assert_eq!(
            (row.seq, row.head_hash.as_deref()),
            (None, None),
            "I3885: neither head concludes"
        );
        assert_eq!(
            svc.advance_head(&id, 3, first, None, None).await.unwrap(),
            AdvanceOutcome::Contested,
            "I3885: a re-offer of the first changes nothing"
        );
        assert_eq!(
            svc.advance_head(&id, 4, "hash-c", None, None)
                .await
                .unwrap(),
            AdvanceOutcome::Contested,
            "I3885: nothing advances a contested ledger"
        );
        let kept: std::collections::BTreeSet<String> = svc
            .list_fork_evidence(&id)
            .await
            .unwrap()
            .iter()
            .filter(|f| f.evidence_json["reason"] == LEDGER_TRIPLE_CONTESTED)
            .map(|f| {
                (
                    f.seq,
                    f.evidence_json["head_hash"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                )
            })
            .map(|(seq, h)| format!("{seq}:{h}"))
            .collect();
        ends.push((row.seq, row.head_hash, kept));
    }
    assert_eq!(
        ends[0], ends[1],
        "I3885: the same end state whichever head arrived first"
    );
    assert_eq!(
        ends[0].2,
        ["3:hash-a".to_owned(), "3:hash-b".to_owned()]
            .into_iter()
            .collect::<std::collections::BTreeSet<String>>(),
        "I3885: both heads kept, at the contested seq"
    );
}
