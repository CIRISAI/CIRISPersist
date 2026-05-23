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
use ciris_verify_core::transparency::{ConsistencyProof, MerkleProof, SignedTreeHead};

/// Per-tenant chain head — the `(sequence_number, entry_hash)` of the
/// tail row, suitable for composing the next [`AuditEntry`].
///
/// Returned by [`AuditService::next_chain_position`] so emit-side
/// callers (v1.5.0 Phase E `federation::emit::grant_trust`) can build
/// and sign the next entry without re-implementing the tenant-tail
/// probe each backend already performs in `record_entry` under
/// `SELECT … FOR UPDATE` / `BEGIN IMMEDIATE`. This helper is best-
/// effort: by the time the caller commits its newly-signed entry the
/// tail may have advanced. The backend's transactional gate inside
/// `record_entry` is the source of truth — a stale read here surfaces
/// as `Error::ChainIntegrity` on the insert and the caller retries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainPosition {
    /// Next sequence number to assign (`1` for a brand-new tenant
    /// chain, `tail.sequence_number + 1` otherwise).
    pub next_sequence_number: i64,
    /// `prev_hash` value the new entry must carry (zeros for a
    /// brand-new tenant chain, `tail.entry_hash` otherwise).
    pub prev_hash: [u8; 32],
}

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

    /// v1.5.0 Phase E — return the per-tenant chain head as a
    /// [`ChainPosition`] (`next_sequence_number` + `prev_hash`) suitable
    /// for building the next [`AuditEntry`]. New-tenant cases return
    /// `(1, GENESIS_PREV_HASH)`; existing-tenant cases return
    /// `(tail.sequence_number + 1, tail.entry_hash)`.
    ///
    /// This is a **read-only convenience probe**. The
    /// [`AuditService::record_entry`] gate is still the source of
    /// truth — a stale read here surfaces as `Error::ChainIntegrity`
    /// on the subsequent insert (the backend re-reads the tail under
    /// `SELECT … FOR UPDATE` / `BEGIN IMMEDIATE`). Callers SHOULD
    /// retry once on `ChainIntegrity` under contention.
    ///
    /// # Default impl
    ///
    /// Returns [`Error::NotImplemented`] — backends opt in by
    /// overriding. Both PG + SQLite ship overrides at v1.5.0 Phase E.
    fn next_chain_position(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<ChainPosition, Error>> + Send {
        let _ = tenant_id;
        async { Err(Error::NotImplemented("next_chain_position")) }
    }

    /// v1.5.0 Phase E — return the most-recent
    /// [`ciris_verify_core::transparency::SignedTreeHead`] for the
    /// tenant's Merkle log, or `None` if no STH has been signed yet
    /// (Merkle hook disabled, or chain empty).
    ///
    /// Backends implement by constructing a per-tenant
    /// `TransparencyStore<AuditLeaf>` (PgMerkleStore / SqliteMerkleStore)
    /// and calling its `latest_sth()`. Phase E's `grant_trust` uses
    /// this to surface the post-emit STH on the receipt without
    /// changing the [`AuditService::record_entry`] return type.
    /// Phase G's "current STH" read API will hit this same surface.
    ///
    /// # Default impl
    ///
    /// Returns [`Error::NotImplemented`].
    fn current_sth(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<Option<SignedTreeHead>, Error>> + Send {
        let _ = tenant_id;
        async { Err(Error::NotImplemented("current_sth")) }
    }

    /// Look up the canonical `grant_id` (federation_trust_grants PK)
    /// for the projection row materialized by a specific chain event.
    /// Used by Phase E's `grant_trust` to surface the canonical
    /// projection PK on the receipt (rather than a fresh UUID that
    /// wouldn't match a subsequent read-path lookup, especially on
    /// re-issuance where the UPSERT keeps the original `grant_id`
    /// stable).
    ///
    /// Lookups are tenant-scoped: `audit_log.sequence_number` is
    /// `UNIQUE(tenant_id, sequence_number)` (per-tenant, not global),
    /// so a `chain_event_id` alone may match multiple
    /// `federation_trust_grants` rows across tenants. Phase E's
    /// `grant_trust` always knows the tenant it just emitted into; the
    /// migration `V045__federation_trust_grants_unique_tenant_chain`
    /// adds `UNIQUE(tenant_id, chain_event_id)` to make the schema
    /// enforce the invariant the API now relies on.
    ///
    /// Returns `Ok(None)` if no projection row exists for the chain
    /// event in the given tenant (caller wasn't a `trust_grant`
    /// subject_kind, or the projection failed and Phase I backfill
    /// hasn't caught up).
    ///
    /// # Default impl
    ///
    /// Returns [`Error::NotImplemented`].
    fn lookup_grant_id_by_chain_event(
        &self,
        tenant_id: &str,
        chain_event_id: i64,
    ) -> impl Future<Output = Result<Option<uuid::Uuid>, Error>> + Send {
        let _ = (tenant_id, chain_event_id);
        async { Err(Error::NotImplemented("lookup_grant_id_by_chain_event")) }
    }

    // ── v1.5.0 Phase F+G — trust-grant read API + proof retrieval ───
    //
    // FSD §4.3 (read API) + §4.1 (inclusion / consistency proof
    // signatures). Phase F is the projection-side queries; Phase G is
    // the Merkle-side proof generation against the per-tenant store
    // already shipped at Phase B.

    /// v1.5.0 Phase F — point-lookup a trust grant by its canonical
    /// PK (`federation_trust_grants.grant_id`). Returns `None` if no
    /// such row exists. Used by Phase G's inclusion-proof API to
    /// resolve a grant_id back to its `(tenant_id, chain_event_id)`
    /// coordinates before generating the Merkle proof.
    ///
    /// # Default impl
    ///
    /// Returns [`Error::NotImplemented`].
    fn get_trust_grant(
        &self,
        grant_id: uuid::Uuid,
    ) -> impl Future<Output = Result<Option<crate::federation::trust_grant::TrustGrantRow>, Error>> + Send
    {
        let _ = grant_id;
        async { Err(Error::NotImplemented("get_trust_grant")) }
    }

    /// v1.5.0 Phase F — live-grants lookup for `(grantee, purpose, scope)`.
    /// Returns rows from **all** granters that match — caller filters by
    /// granter (NodeCore's `resolve_trust` composes this) and decides
    /// whether a wildcard scope satisfies the query. Per FSD §3.3
    /// wildcards (`scope = '*'`) are also surfaced unconditionally:
    /// the caller is the policy layer.
    ///
    /// `include_revoked` flips whether rows with `revoked_at IS NOT NULL`
    /// are returned. `include_expired` flips whether rows with
    /// `expires_at <= NOW()` are returned (which are NOT necessarily
    /// `revoked_at`-populated until a re-issuance projects them).
    ///
    /// # Default impl
    ///
    /// Returns [`Error::NotImplemented`].
    fn lookup_trust_grant(
        &self,
        grantee_key: &str,
        purpose: crate::federation::trust_grant::TrustPurpose,
        scope: &str,
        include_revoked: bool,
        include_expired: bool,
    ) -> impl Future<Output = Result<Vec<crate::federation::trust_grant::TrustGrantRow>, Error>> + Send
    {
        let _ = (
            grantee_key,
            purpose,
            scope,
            include_revoked,
            include_expired,
        );
        async { Err(Error::NotImplemented("lookup_trust_grant")) }
    }

    /// v1.5.0 Phase F — filter query over `federation_trust_grants`.
    /// All non-`None` fields on the filter are AND-intersected.
    /// `scope_prefix` matches via SQL `LIKE '<prefix>%'`. Revoked /
    /// expired rows are excluded unless the matching `include_*` flag
    /// on the filter is set.
    ///
    /// # Default impl
    ///
    /// Returns [`Error::NotImplemented`].
    fn list_trust_grants(
        &self,
        filter: crate::federation::trust_grant::TrustGrantFilter,
    ) -> impl Future<Output = Result<Vec<crate::federation::trust_grant::TrustGrantRow>, Error>> + Send
    {
        let _ = filter;
        async { Err(Error::NotImplemented("list_trust_grants")) }
    }

    /// v1.5.0 Phase G — fetch the `canonical_bytes` column for the
    /// merkle_leaves row keyed by `(tenant_id, chain_event_id)`. These
    /// are the RFC 6962 §2.1 hashing-form bytes a verifier needs to
    /// recompute `leaf_hash = sha256(0x00 || canonical_bytes)` and
    /// walk the inclusion proof up to the STH's root_hash without
    /// trusting the directory's projection.
    ///
    /// Returns `Ok(None)` if no merkle leaf was appended for the
    /// chain event (Merkle hook disabled at emit time, or Phase I
    /// backfill not yet run).
    ///
    /// # Default impl
    ///
    /// Returns [`Error::NotImplemented`].
    fn leaf_canonical_bytes_for_chain_event(
        &self,
        tenant_id: &str,
        chain_event_id: i64,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, Error>> + Send {
        let _ = (tenant_id, chain_event_id);
        async {
            Err(Error::NotImplemented(
                "leaf_canonical_bytes_for_chain_event",
            ))
        }
    }

    /// v1.5.0 Phase G — RFC 6962 inclusion proof for a chain event
    /// against the **current** STH for its tenant. Wraps a per-tenant
    /// `TransparencyStore<AuditLeaf>` in a `TransparencyLog` and
    /// delegates to `inclusion_proof(leaf_index)`. Maps
    /// `chain_event_id → leaf_index` via the merkle_leaves table.
    ///
    /// Returns [`Error::NotFound`] if no merkle leaf exists for the
    /// chain event.
    ///
    /// # Default impl
    ///
    /// Returns [`Error::NotImplemented`].
    fn inclusion_proof_for_chain_event(
        &self,
        tenant_id: &str,
        chain_event_id: i64,
    ) -> impl Future<Output = Result<MerkleProof, Error>> + Send {
        let _ = (tenant_id, chain_event_id);
        async { Err(Error::NotImplemented("inclusion_proof_for_chain_event")) }
    }

    /// v1.5.0 Phase G — RFC 6962 consistency proof between two tree
    /// sizes for a tenant. Verifier confirms STH(old_size) →
    /// STH(new_size) is a legal append (no retroactive rewrite).
    ///
    /// # Default impl
    ///
    /// Returns [`Error::NotImplemented`].
    fn consistency_proof(
        &self,
        tenant_id: &str,
        old_size: u64,
        new_size: u64,
    ) -> impl Future<Output = Result<ConsistencyProof, Error>> + Send {
        let _ = (tenant_id, old_size, new_size);
        async { Err(Error::NotImplemented("consistency_proof")) }
    }

    /// v1.5.0 Phase I (FSD §6.2) — enumerate V020 trust rows where
    /// `trusted_by` matches `local_pubkey`. Used by
    /// [`crate::federation::backfill::backfill_v020_trust_rows`] to
    /// drive the one-shot migration from the V020 trust columns on
    /// `federation_keys` to V021's signed-event substrate.
    ///
    /// Returned rows satisfy `trust_relationship IS NOT NULL` (i.e.,
    /// they have an explicit V020 grant — rows with NULL trust
    /// columns are pre-V020 and not backfillable). Rows where
    /// `trusted_by` is some *other* agent's `key_id` are excluded
    /// per the FSD §6.2 scope constraint: only the granter can
    /// re-emit on the chain (FSD §3.1, signer == author_id).
    ///
    /// # Default impl
    ///
    /// Returns [`Error::NotImplemented`]. PG + SQLite both ship
    /// concrete overrides at v1.5.0 Phase I.
    fn read_v020_trust_rows_for_local(
        &self,
        local_pubkey: &str,
    ) -> impl Future<Output = Result<Vec<crate::federation::trust_grant::V020TrustRow>, Error>> + Send
    {
        let _ = local_pubkey;
        async { Err(Error::NotImplemented("read_v020_trust_rows_for_local")) }
    }
}
