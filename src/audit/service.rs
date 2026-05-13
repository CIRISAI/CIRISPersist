//! `AuditService` trait surface (v0.8.1, CIRISPersist#35).
//!
//! 3 methods: `record_entry`, `list_entries`, `verify_chain`.
//!
//! # Threat-model anchors (THREAT_MODEL.md §4)
//!
//! - **AV-49** — hash-chain integrity: `record_entry` re-derives
//!   `entry_hash` from canonical bytes, refuses INSERT when
//!   caller-claimed `entry_hash` mismatches or `prev_hash` doesn't
//!   match the prior entry's `entry_hash`.
//! - **AV-50** — chain fork detection: `verify_chain` walks the
//!   chain end-to-end and surfaces breaks (entry_hash mismatch,
//!   prev_hash mismatch, signature failure, sequence gap) via the
//!   typed [`super::ChainVerifyOutcome`] result.
//! - **AV-51** — tenant isolation: `list_entries` and `verify_chain`
//!   take `tenant_id` non-optionally; no cross-tenant reads on this
//!   surface.

use std::future::Future;

use super::types::{AuditCursor, AuditEntry, AuditFilter, AuditListPage, ChainVerification};
use super::Error;

/// Hash-chained audit trail surface (v0.8.1). 3 methods: write
/// (with full chain-integrity + signature gate), list (cursor-paged,
/// tenant-scoped), verify (end-to-end chain walk with typed break
/// diagnostic).
pub trait AuditService: Send + Sync {
    /// Verify-and-insert an audit entry. Persist:
    /// 1. Re-derives `entry_hash` from canonical bytes; rejects on
    ///    mismatch with caller-claimed value (AV-49).
    /// 2. Verifies Ed25519 signature against `actor_id` (which IS
    ///    the pubkey).
    /// 3. Asserts `sequence_number = (prior entry's seq) + 1` for
    ///    the tenant; sequence_number=1 must have
    ///    `prev_hash = GENESIS_PREV_HASH`.
    /// 4. Asserts `prev_hash` matches the prior entry's
    ///    `entry_hash` (or zeros for genesis).
    /// 5. INSERTs with `signature_verified=TRUE`.
    ///
    /// Duplicate `(tenant_id, sequence_number)` → `Error::Conflict`.
    fn record_entry(&self, entry: AuditEntry) -> impl Future<Output = Result<(), Error>> + Send;

    /// Cursor-paged listing scoped to one tenant (AV-51). Newest-
    /// first by `recorded_at`.
    fn list_entries(
        &self,
        filter: AuditFilter,
        cursor: Option<AuditCursor>,
        limit: i64,
    ) -> impl Future<Output = Result<AuditListPage, Error>> + Send;

    /// AV-50: walk the chain end-to-end for one tenant from
    /// `from_sequence` to `to_sequence` (inclusive), returning the
    /// first break + reason if any. Re-verifies entry_hash,
    /// prev_hash chain, sequence continuity, and signature on
    /// every entry walked.
    ///
    /// `to_sequence = None` means "walk to the current tail".
    fn verify_chain(
        &self,
        tenant_id: &str,
        from_sequence: i64,
        to_sequence: Option<i64>,
    ) -> impl Future<Output = Result<ChainVerification, Error>> + Send;
}
