//! Row types and outcome enums for the `ledgers` consumer-table family.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One row of `ledger_heads` — the L1 binding plus the current head.
///
/// `seq`/`head_hash` are `Option` as a pair: a registered ledger with no
/// promoted head yet holds `None` for both ("registered, no head" is a real
/// state; a seq-0 sentinel would collapse it into "head at genesis"). The
/// schema CHECK pins the pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerHeadRow {
    pub ledger_id: String,
    pub owner_key_id: String,
    pub unit: String,
    pub standard_version: String,
    pub seq: Option<u64>,
    pub head_hash: Option<String>,
    pub witness_anchor_ref: Option<String>,
    pub source_envelope_ref: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One row of `ledger_checkpoints` — an L5 co-witnessed balance snapshot.
/// Immutable once written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCheckpointRow {
    pub ledger_id: String,
    pub seq: u64,
    /// Canonical i128 decimal string — validated on write.
    pub balance_minor: String,
    /// JSON array of witness refs (opaque pointers into the CC 5.4.5
    /// witness chain, which persist stores but does not resolve).
    pub witness_refs: serde_json::Value,
    pub supersedes_ref: Option<String>,
    pub source_envelope_ref: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// One row of `ledger_entry_ranges` — which `evidence_refs` blob holds
/// entries `[from_seq, to_seq]` of a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntryRangeRow {
    pub ledger_id: String,
    pub from_seq: u64,
    pub to_seq: u64,
    pub blob_ref: String,
    pub head_hash_at_to: String,
    pub created_at: DateTime<Utc>,
}

/// One row of `ledger_fork_evidence` — an L8 record for the adjudication
/// plane. `evidence_id` is derived from the evidence content, so recording
/// is idempotent and the same fork observed twice is one row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkEvidenceRow {
    pub evidence_id: String,
    pub ledger_id: String,
    pub seq: u64,
    /// `"double_head"` or `"witness_contradiction"` — pinned by a schema
    /// CHECK in both dialects.
    pub fork_kind: String,
    pub evidence_json: serde_json::Value,
    pub detected_at: DateTime<Utc>,
}

/// Outcome of [`crate::ledgers::LedgerService::register_ledger`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterOutcome {
    /// The triple was free; the ledger row now exists.
    Registered,
    /// The identical triple was already registered — idempotent no-op.
    AlreadyRegistered,
}

/// Outcome of [`crate::ledgers::LedgerService::advance_head`].
///
/// The fork-shaped case — a DIFFERENT hash at the CURRENT seq — is not an
/// outcome: it is `Error::Conflict`, because the door refuses rather than
/// choosing a winner (L8: detection is the roster's, adjudication is the
/// adjudication plane's, and this table is neither).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvanceOutcome {
    /// The head moved forward.
    Advanced,
    /// Identical `(seq, head_hash)` re-asserted — idempotent no-op.
    Unchanged,
    /// The offered seq is below the stored head — normal under
    /// replication, recorded as a no-op, never an error.
    Stale,
}
