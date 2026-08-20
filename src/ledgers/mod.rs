//! The `ledgers` consumer-table family (CIRISPersist#754, CC 3.3.10.1 rc4.3).
//!
//! CIRISConstitution#92 designates in-grammar ledgers: owner-serialized
//! *content* whose total order lives in the ledger's own hash chain, with
//! conservation verified as a deterministic byte-equal fold by the cohort.
//! The chain itself rides `scores` rows on the `ledger:*` dimension family
//! (chain blobs in `evidence_refs[]`) — **constitutionally NOT a new
//! envelope plane** (CC 1.7 lockdown: no new attestation_type, no new
//! envelope field). This module is the node's **working index** over that
//! content: heads, checkpoints, entry-range pointers, and fork evidence —
//! what lets a node answer "what is this ledger's head / latest witnessed
//! checkpoint / where do its entries live" without replaying blobs.
//!
//! Staging (the #754 contract): rows on the `ledger:*` dimensions are
//! governed and therefore REFUSED at federation tier until CC#92 graduates
//! the family into the vendored `namespace_registry.json` — the re-vendor
//! itself opens the door (see `admission.rs`, the `ledger:` stem). These
//! tables carry no such latch: a consumer that enables the feature may
//! index its own ledgers immediately; nothing here federates.
//!
//! # 4 tables, 11 trait methods
//!
//! - `register_ledger` — L1: one ledger per `(owner_key_id, unit,
//!   standard_version)`. The `ledger_id` is DERIVED
//!   ([`standard::derive_ledger_id`]), never caller-chosen; identical
//!   re-registration is an idempotent no-op, a differing claim on an
//!   occupied triple is `Conflict` (fail-secure, per the rc4.3 text).
//! - `advance_head` — L4 bookkeeping: heads move forward only. Same
//!   `(seq, head_hash)` is idempotent (`Unchanged`); a LOWER seq is
//!   `Stale` (normal under replication, a no-op); a DIFFERENT hash at the
//!   CURRENT seq is `Conflict` — fork-shaped, the door never overwrites,
//!   and the caller assembles [`standard::ForkEvidence`].
//! - `get_ledger` / `find_ledger_by_triple` / `list_ledgers_for_owner` —
//!   point and index reads.
//! - `put_checkpoint` / `latest_checkpoint` — L5: checkpoints are
//!   IMMUTABLE once written (a witnessed fact pins, never flips);
//!   identical re-put is a no-op, a differing row at the same
//!   `(ledger_id, seq)` is `Conflict`.
//! - `put_entry_range` / `list_entry_ranges` — L2/L6: which
//!   `evidence_refs` blob holds entries `[from_seq, to_seq]`.
//! - `record_fork_evidence` / `list_fork_evidence` — L8: detection
//!   RECORDS; adjudication punishes. The evidence id is derived from the
//!   evidence content, so recording is idempotent, and there is
//!   deliberately no FK to `ledger_heads` — a fork about a ledger this
//!   node never registered must not be droppable for lack of a local row.
//!
//! # FK semantics
//!
//! `ledger_checkpoints.ledger_id` and `ledger_entry_ranges.ledger_id`
//! reference `ledger_heads(ledger_id)` — immediate on both dialects (no
//! ceremony writes parent+child in one transaction here). Fork evidence
//! carries NO FK, for the reason above.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `ledgers_invalid_argument`, `ledgers_not_found`, `ledgers_conflict`,
//!   `ledgers_backend`, `ledgers_internal`.

// The pure `standard` module is UNGATED: `admission.rs`'s L1 arm consumes
// `derive_ledger_id` on every build, and an admission gate whose behaviour
// varies by feature set is the class certify-per-SET exists to catch. A
// second spelling inside admission.rs would be the #663 class. The SERVICE
// surface (tables, trait, backends, FFI) stays behind `ledgers`.
#[cfg(all(feature = "ledgers", feature = "postgres"))]
pub mod postgres;
#[cfg(feature = "ledgers")]
pub mod service;
#[cfg(all(feature = "ledgers", feature = "sqlite"))]
pub mod sqlite;
pub mod standard;
#[cfg(feature = "ledgers")]
pub mod types;

#[cfg(feature = "ledgers")]
pub use service::LedgerService;
pub use standard::{
    conservation_fold, derive_ledger_id, detect_double_head, entry_content_hash,
    fold_canonical_bytes, verify_chain_from_checkpoint, verify_chain_from_genesis,
    ConservationFold, ForkEvidence, LedgerEntry, LedgerEntryKind, LEDGER_STANDARD_VERSION,
};
#[cfg(feature = "ledgers")]
pub use types::{
    AdvanceOutcome, ForkEvidenceRow, LedgerCheckpointRow, LedgerEntryRangeRow, LedgerHeadRow,
    RegisterOutcome,
};

/// ledgers-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty ids, a non-canonical
    /// `balance_minor` decimal, an inverted range, etc.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found — advancing or checkpointing a ledger that was
    /// never registered.
    #[error("not found: {0}")]
    NotFound(String),

    /// The fail-secure refusals: a differing claim on an occupied L1
    /// triple, a differing head at the current seq (fork-shaped), or a
    /// differing checkpoint/range at an occupied key (immutable planes).
    #[error("conflict: {0}")]
    Conflict(String),

    /// Backend-level error (connection, transaction, lock).
    #[error("backend: {0}")]
    Backend(String),

    /// Internal serialization / type-conversion bug.
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "ledgers_invalid_argument",
            Error::NotFound(_) => "ledgers_not_found",
            Error::Conflict(_) => "ledgers_conflict",
            Error::Backend(_) => "ledgers_backend",
            Error::Internal(_) => "ledgers_internal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_tokens_stable() {
        assert_eq!(
            Error::InvalidArgument("x".into()).kind(),
            "ledgers_invalid_argument"
        );
        assert_eq!(Error::NotFound("x".into()).kind(), "ledgers_not_found");
        assert_eq!(Error::Conflict("x".into()).kind(), "ledgers_conflict");
        assert_eq!(Error::Backend(String::new()).kind(), "ledgers_backend");
        assert_eq!(Error::Internal(String::new()).kind(), "ledgers_internal");
    }
}

/// Shared write-side validation, spelled once so the two dialects cannot
/// drift (`validation.rs`-in-miniature; both backends call these).
#[cfg(feature = "ledgers")]
pub(crate) mod validate {
    use super::Error;

    /// `balance_minor` must be a CANONICAL i128 decimal — parse and
    /// re-format must round-trip byte-identically, refusing `+5`, `007`,
    /// `-0`, whitespace, and anything wider than i128. The fold's
    /// arithmetic is i128; a non-canonical spelling stored today is a
    /// byte-equality failure in someone's fold tomorrow.
    pub fn balance_minor(s: &str) -> Result<i128, Error> {
        let v: i128 = s
            .parse()
            .map_err(|e| Error::InvalidArgument(format!("balance_minor `{s}`: {e}")))?;
        if v.to_string() != s {
            return Err(Error::InvalidArgument(format!(
                "balance_minor `{s}` is not canonical (canonical is `{v}`)"
            )));
        }
        Ok(v)
    }

    /// Sequence numbers are `u64` in the standard but stored in signed
    /// 64-bit columns; refuse what the column cannot hold rather than
    /// wrapping.
    pub fn seq_as_i64(seq: u64, what: &str) -> Result<i64, Error> {
        i64::try_from(seq)
            .map_err(|_| Error::InvalidArgument(format!("{what} {seq} exceeds i64::MAX")))
    }

    pub fn non_empty(v: &str, what: &str) -> Result<(), Error> {
        if v.is_empty() {
            return Err(Error::InvalidArgument(format!("{what} required")));
        }
        Ok(())
    }

    /// `witness_refs` must be a JSON array (of opaque ref strings).
    pub fn witness_refs(v: &serde_json::Value) -> Result<(), Error> {
        if !v.is_array() {
            return Err(Error::InvalidArgument(
                "witness_refs must be a JSON array".into(),
            ));
        }
        Ok(())
    }
}
