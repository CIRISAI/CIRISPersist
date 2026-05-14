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

use super::types::{
    AuditCursor, AuditEntry, AuditEventRef, AuditFilter, AuditListPage, ChainVerification,
    CorrelationQuery,
};
use super::Error;
use crate::ClaimResult;

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

    /// Atomic-claim variant of [`AuditService::record_entry`]
    /// (v1.0.0; CIRISAgent#756 concern #2).
    ///
    /// Caller supplies `content_hash` (typically
    /// `sha256(canonical_envelope_bytes)`); implementations INSERT
    /// the audit row with the hash as the unique key. On race the
    /// first writer wins (`ClaimResult::Stored`); subsequent writers
    /// observe the UNIQUE conflict and receive the existing row's
    /// reference (`ClaimResult::AlreadyClaimed`).
    ///
    /// Unlike [`crate::secrets::SecretsService::try_claim_secret`],
    /// the hash is caller-computed (not derived from a master key)
    /// because audit content isn't sensitive — sha256 is fine for
    /// dedup AND public auditability.
    ///
    /// `accessor` is a free-form observability tag surfaced into
    /// tracing only; the cryptographic actor identity remains
    /// `entry.actor_id` (self-signed: actor_id IS the pubkey).
    ///
    /// # Determinism guarantee
    ///
    /// Implementations MUST be atomic — two concurrent callers
    /// passing the same `content_hash` end up with one row, not
    /// two. PG backend: `INSERT … ON CONFLICT (content_hash) DO
    /// NOTHING RETURNING …`; SQLite: `INSERT OR IGNORE …` plus a
    /// follow-up SELECT on conflict.
    ///
    /// # Default impl
    ///
    /// Returns [`Error::NotImplemented`] — backends without the
    /// content-hash UNIQUE column (legacy stubs, in-memory test
    /// shims) opt into the surface explicitly.
    fn try_claim_event(
        &self,
        content_hash: [u8; 32],
        entry: AuditEntry,
        accessor: String,
    ) -> impl Future<Output = Result<ClaimResult<AuditEventRef>, Error>> + Send {
        let _ = (content_hash, entry, accessor);
        async { Err(Error::NotImplemented("try_claim_event")) }
    }

    /// Read audit entries whose payload JSONB carries the given
    /// `correlation_id`. Newest-first. Used by callers that need the
    /// "what audit events relate to this correlation_id" trace —
    /// previously served by the agent's graph-node side which is now
    /// collapsed into persist (CIRISAgent#756 Q4, v1.0.0).
    ///
    /// Filter: `tenant_id` is required (AV-51 per-tenant isolation
    /// invariant); `time_window_start` + `time_window_end` are
    /// optional inclusive bounds; `limit` caps the result set
    /// (default 100; clamped to `CORRELATION_QUERY_MAX_LIMIT` = 1000).
    ///
    /// Returns newest-first by `recorded_at` then `sequence_number`.
    /// Empty `correlation_id` returns an empty Vec. Cross-tenant
    /// `tenant_id` mismatches return an empty Vec (AV-51).
    ///
    /// # Default impl
    ///
    /// Returns [`Error::NotImplemented`] — backends opt in
    /// explicitly. The PG impl uses `payload @> jsonb_build_object(
    /// 'correlation_id', $2::text)` (index-friendly containment);
    /// the SQLite impl uses `json_extract(payload,
    /// '$.correlation_id') = ?`.
    fn query_by_correlation_id(
        &self,
        tenant_id: &str,
        correlation_id: &str,
        filter: CorrelationQuery,
    ) -> impl Future<Output = Result<Vec<AuditEntry>, Error>> + Send {
        let _ = (tenant_id, correlation_id, filter);
        async { Err(Error::NotImplemented("query_by_correlation_id")) }
    }
}
