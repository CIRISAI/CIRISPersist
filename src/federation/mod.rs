//! Federation directory — pubkey + attestation + revocation substrate
//! (v0.2.0+, PoB §3.1).
//!
//! # Mission alignment (MISSION.md §2 — `federation/`)
//!
//! Persist holds the substrate; consumers compose policy. This module
//! defines the [`FederationDirectory`] trait — CRUD over three tables
//! (`federation_keys`, `federation_attestations`, `federation_revocations`)
//! plus serde wire types and write-authority guards. Backends (memory,
//! postgres, sqlite) implement the trait in [`crate::store`].
//!
//! **No `is_trusted()` / `trust_score()` / `trust_path()` methods.**
//! Those are policy decisions consumers compose by walking the
//! attestation graph however they want; persist exposes the edges, the
//! consumer composes the traversal. See `docs/FEDERATION_DIRECTORY.md`
//! §"Explicit non-goals" for the architectural boundary.
//!
//! ## Wire-format compatibility with CIRISRegistry
//!
//! `CIRISRegistry/rust-registry/src/federation/types.rs` vendors the
//! same shapes as this module's [`types`]. The contract:
//!
//! - Field names + types match field-for-field.
//! - Field ordering matters for `serde_json` default serialization
//!   (registry hashes the vendored shape; persist hashes its own).
//! - `persist_row_hash` is computed server-side by persist via the
//!   `PythonJsonDumpsCanonicalizer` (sorted keys, no whitespace,
//!   `ensure_ascii=True`) and shipped on read responses. Consumers
//!   store + string-compare; they don't reproduce the canonicalizer.
//!
//! See `docs/FEDERATION_DIRECTORY.md` for the architectural contract
//! and the registry-side `docs/FEDERATION_CLIENT.md` for the consumer
//! complement.

pub mod admission;
#[cfg(feature = "cirisaudit")]
pub mod backfill;
pub mod blackhole;
pub mod blobs;
#[cfg(feature = "cirisaudit")]
pub mod emit;
pub mod goal;
pub mod hardware_attestation;
pub mod perceptual_hash;
pub mod precedence;
#[cfg(feature = "cirisaudit")]
pub mod read;
pub mod replication;
pub mod rooting;
pub mod schema_resolver;
#[cfg(feature = "sqlite")]
pub mod sqlite_open;
pub mod topology;
pub mod trust_grant;
pub mod types;
pub mod verify_coord;

/// Base64-string serde codec for `Vec<u8>` byte fields. Mirrors the
/// private module of the same name in `crate::audit::types` — kept
/// in lockstep so federation + audit wire shapes serialize byte
/// fields identically (base64 standard alphabet). Visibility is
/// `pub(crate)` so the federation submodules use it via
/// `#[serde(with = "crate::federation::serde_bytes_b64")]` without
/// re-exporting the codec on the public surface.
pub(crate) mod serde_bytes_b64 {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        B64.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s).map_err(serde::de::Error::custom)
    }
}

pub use admission::{
    check_cohort_scope, check_observed_region, AttestationLadderTransitionPolicy,
    DimensionAdmissionPolicy, DimensionRejectionReason, ReservedPrefixRule,
    ATTESTATION_LADDER_MECHANISMS,
};
pub use blackhole::{BlackholeRecord, BlackholeRules, RETICULUM_IDENTITY_HASH_LEN};
pub use blobs::{
    holds_bytes_attestation_envelope, holds_bytes_attestation_type, BlobBody, BlobError,
    BlobStorage, EvictActorReport, ExternalRef, PutBlobAttestation, DEFAULT_INLINE_BYTES_CAP,
    HOLDS_BYTES_ATTESTATION_TYPE_PREFIX, HOLDS_BYTES_PREFIX_HEX_LEN,
};
pub use goal::{
    canonicalize_goal_text, DeliberationRef, Goal, GoalScope, GoalsFilter, M1Dimension,
    MetaGoalAlignment,
};
pub use hardware_attestation::{HardwareAttestationPolicy, DEFAULT_MAX_NONCE_AGE};
pub use perceptual_hash::{
    HashDatabaseId, HashMatchError, HashMatchResult, MatcherUnreachablePolicy,
    NullPerceptualHashMatcher, OnMatchPolicy, PerceptualHashMatcher, SharedMatcher,
};
pub use replication::{
    aggregate_trust_score, withdraws_attestation_envelope, AdmissionGate, EvictionCandidate,
    EvictionDecay, EvictionSweeper, MemoryTrustScoring, ReplicationConfig, SweepReport,
    TrustScoring, TrustScoringError, DEFAULT_SWEEP_BATCH, MIN_SWEEP_INTERVAL,
};
pub use rooting::{
    provenance_chain, root_binding, ProvenanceChain, ProvenanceLink, RootingRejection,
    RootingVerdict, MAX_PROVENANCE_DEPTH,
};
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub use schema_resolver::BlobBackedSchemaResolver;
pub use schema_resolver::{
    axis_from_dimension, AxisSchema, NoOpSchemaResolver, SchemaResolver, SchemaResolverError,
};
#[cfg(feature = "sqlite")]
pub use sqlite_open::FederationDirectorySqlite;
pub use topology::{
    build_delegation_graph, build_trust_topology, AuditChainEntry, AuditChainProof, DelegationEdge,
    DelegationGraph, EdgeType, FederationDirectoryFilter, TrustEdge, TrustNode, TrustTopology,
    WithdrawalEntry, MAX_DELEGATION_DEPTH,
};
pub use types::{
    Attestation, HybridPendingRow, KeyRecord, PeerMetadataRow, PeerPolicyBlob, Revocation,
    SignedAttestation, SignedKeyRecord, SignedRevocation, TrustClass, TrustFilter, TrustGrant,
    TrustRelationship, TrustRow, TrustType,
};

/// Federation directory trait — the registry/lens/agent's read+write
/// surface over persist's three federation tables.
///
/// # Object-safety (v2.6.0, CIRISPersist#106)
///
/// The trait is annotated with [`#[async_trait]`](async_trait::async_trait)
/// so it is **object-safe** — consumers can build
/// `Arc<dyn FederationDirectory>` (the shape
/// [`Engine::federation_directory`](crate::Engine::federation_directory)
/// returns). The macro rewrites each `async fn` to a `Pin<Box<dyn
/// Future<Output = …> + Send + '_>>` return — one heap allocation per
/// call. For the federation directory's call frequency (admission paths,
/// directory lookups, attestation enumeration) the per-call alloc is
/// not a hot-path concern.
///
/// # Wire-format note
///
/// Read methods return [`KeyRecord`] / [`Attestation`] / [`Revocation`]
/// with `persist_row_hash` populated server-side (see
/// [`types::KeyRecord::persist_row_hash`] for the canonicalization
/// contract). CIRISVerify v3.2.0+ binds the field into
/// `FederationProvenance::persist_row_hash` so a downstream consumer
/// can trace an attestation back to its underlying persist row
/// (CIRISPersist#108).
///
/// Write methods take [`SignedKeyRecord`] / [`SignedAttestation`] /
/// [`SignedRevocation`] — wrappers carrying a record the caller has
/// signed but persist has not yet stored. Persist verifies the
/// scrub-signature on receipt before writing.
#[async_trait::async_trait]
pub trait FederationDirectory: Send + Sync {
    // ── Public keys ────────────────────────────────────────────────

    /// Insert a new pubkey row. Idempotent on `key_id` collision with
    /// matching content (no-op); errors on `key_id` collision with
    /// differing content.
    async fn put_public_key(&self, record: SignedKeyRecord) -> Result<(), Error>;

    /// Fetch a single pubkey row by `key_id`. Returns `None` if absent.
    async fn lookup_public_key(&self, key_id: &str) -> Result<Option<KeyRecord>, Error>;

    /// Fetch all pubkey rows for a given identity. Used by the
    /// "all keys for primitive X" lookup the v0.2.x verify subsumption
    /// proxy will call.
    async fn lookup_keys_for_identity(&self, identity_ref: &str) -> Result<Vec<KeyRecord>, Error>;

    /// v2.6.0 (CIRISPersist#105) — enumerate `federation_keys` rows
    /// by `identity_type` (e.g. [`types::identity_type::ACCORD_HOLDER`],
    /// [`types::identity_type::STEWARD`]).
    ///
    /// Used by CIRISEdge for class-based directory queries:
    /// - `identity_type::ACCORD_HOLDER` → 2-of-3 constitutional
    ///   verification set (CIRISEdge#19).
    /// - `identity_type::STEWARD` → high-priority recipient class for
    ///   gossip topology (CIRISEdge#20).
    ///
    /// Rows are returned in stable lex order by `key_id` so callers
    /// can deterministically pick a subset (e.g. "first N by key_id"
    /// for rotation phasing). Empty `Vec` if no rows match.
    async fn list_keys_by_identity_type(
        &self,
        identity_type: &str,
    ) -> Result<Vec<KeyRecord>, Error>;

    // ── Attestations ───────────────────────────────────────────────

    /// Insert a new attestation row.
    async fn put_attestation(&self, attestation: SignedAttestation) -> Result<(), Error>;

    /// All attestations targeting `attested_key_id` (consumer asks
    /// "who vouches for K?"). Ordered by `asserted_at` DESC.
    async fn list_attestations_for(&self, attested_key_id: &str)
        -> Result<Vec<Attestation>, Error>;

    /// All attestations issued by `attesting_key_id` (consumer asks
    /// "which keys does K vouch for?"). Ordered by `asserted_at` DESC.
    async fn list_attestations_by(&self, attesting_key_id: &str)
        -> Result<Vec<Attestation>, Error>;

    /// v3.6.0 (CIRISPersist#134, CEG 0.3 §8.1.10 Policy J / §11.5.3)
    /// — return the chain of `content_rating:*` attestations rooted
    /// at a `trusted_publisher` identity_type that vouches for
    /// `content_sha256`. Returns an empty vector when the content is
    /// not trusted-publisher-blessed.
    ///
    /// Composition (default impl):
    ///
    ///   1. Enumerate all `trusted_publisher`-type keys via
    ///      [`Self::list_keys_by_identity_type`].
    ///   2. For each, list attestations issued by the key via
    ///      [`Self::list_attestations_by`].
    ///   3. Keep `scores` attestations whose envelope `dimension`
    ///      starts with `content_rating:` AND whose `evidence_refs`
    ///      array contains the hex `content_sha256`.
    ///
    /// CEG 0.3 §11.5.3: only `trusted_publisher`-type keys may emit
    /// publisher-curated content ratings (the
    /// [`super::admission::default_reserved_prefix_rules`]
    /// admission gate enforces this at write time). The returned set
    /// is the publisher's vouch chain — receiver-side Policy J
    /// composition consumes the chain alongside the age-assurance
    /// gate.
    ///
    /// # Default impl rationale
    ///
    /// Composes [`Self::list_keys_by_identity_type`] +
    /// [`Self::list_attestations_by`] (both already trait-required);
    /// no per-backend SQL needed. Memory / Postgres / SQLite backends
    /// inherit the same shape. Backends with a `content_rating:*`
    /// secondary index may override for O(log N) lookup instead of the
    /// default O(P · A) scan (P trusted_publishers, A attestations
    /// each).
    async fn lookup_trusted_publisher_chain(
        &self,
        content_sha256: &str,
    ) -> Result<Vec<Attestation>, Error> {
        // Validate hex shape early — callers may pass arbitrary user input.
        if content_sha256.len() != 64 || !content_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(Vec::new());
        }
        let publishers = self
            .list_keys_by_identity_type(types::identity_type::TRUSTED_PUBLISHER)
            .await?;
        let mut chain: Vec<Attestation> = Vec::new();
        for publisher in publishers {
            let attestations = self.list_attestations_by(&publisher.key_id).await?;
            for att in attestations {
                if att.attestation_type != types::attestation_type::SCORES {
                    continue;
                }
                // CEG 0.3 §5.6.8.3 reserved-prefix rule: content_rating:*
                // dimensions are emitter-restricted to trusted_publisher,
                // so a (publisher, content_rating:*) pair carries the
                // publisher's vouch by construction.
                let dimension_match = att
                    .attestation_envelope
                    .get("dimension")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s.starts_with("content_rating:"));
                if !dimension_match {
                    continue;
                }
                let evidence_match = att
                    .attestation_envelope
                    .get("evidence_refs")
                    .and_then(|v| v.as_array())
                    .is_some_and(|arr| arr.iter().any(|r| r.as_str() == Some(content_sha256)));
                if !evidence_match {
                    continue;
                }
                chain.push(att);
            }
        }
        Ok(chain)
    }

    // ── Revocations ────────────────────────────────────────────────

    /// Insert a new revocation row. Append-only — revocations of an
    /// already-revoked key are accepted (the latest-effective-at one
    /// wins under most consumer policies).
    async fn put_revocation(&self, revocation: SignedRevocation) -> Result<(), Error>;

    /// All revocations targeting `revoked_key_id`. Ordered by
    /// `effective_at` DESC. Consumers walk this list and apply their
    /// policy ("is K revoked at time T?").
    async fn revocations_for(&self, revoked_key_id: &str) -> Result<Vec<Revocation>, Error>;

    // ── Cold-path PQC fill-in (writer contract step 4) ─────────────
    //
    // Per `docs/FEDERATION_DIRECTORY.md` §"Trust contract — eventual
    // consistency as a federation primitive" + §"PQC strategy", the
    // writer contract is:
    //   1. Sign canonical with Ed25519 (hot)
    //   2. Write the row (PQC fields None)
    //   3. IMMEDIATELY kick off ML-DSA-65 sign on cold path
    //   4. Call attach_*_pqc_signature once ML-DSA completes
    //
    // These three methods implement step 4. They:
    //   - Reject if the row is already hybrid-complete (no double-fill)
    //   - Update PQC fields atomically
    //   - Set pqc_completed_at = NOW()
    //   - Recompute persist_row_hash since row content changed
    //
    // Persist does NOT verify the cryptographic validity of the PQC
    // signature on attach — that's the writer's responsibility.
    // Persist verifies on read at the consumer's policy layer.

    /// Attach the PQC components to a hybrid-pending federation_keys row.
    /// Updates pubkey_ml_dsa_65_base64 + scrub_signature_pqc + pqc_completed_at.
    /// Errors if the row is already PQC-complete.
    async fn attach_key_pqc_signature(
        &self,
        key_id: &str,
        pubkey_ml_dsa_65_base64: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), Error>;

    /// Attach the PQC signature to a hybrid-pending
    /// `federation_attestations` row. Attestations don't have their
    /// own pubkey — they reference the existing
    /// `federation_keys.scrub_key_id`'s pubkey for verification.
    async fn attach_attestation_pqc_signature(
        &self,
        attestation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), Error>;

    /// Attach the PQC signature to a hybrid-pending
    /// `federation_revocations` row. Same shape as attestations.
    async fn attach_revocation_pqc_signature(
        &self,
        revocation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), Error>;

    // ── Hybrid-pending sweep (CIRISPersist#11, v0.3.2) ─────────────
    //
    // Per V004's schema header §"Phase transitions":
    //   "Pre-flip rows that are still pending get walked through the
    //    upgrade pipeline."
    // These three methods feed that pipeline. Persist's PyO3
    // `Engine.run_pqc_sweep()` walks each batch and drives cold-path
    // PQC fill-in for rows authored before the writer was configured
    // with a PQC local signer (or where the per-write cold-path failed
    // transiently). Idempotent at the consumer level —
    // `attach_*_pqc_signature` already guards against double-fill via
    // `WHERE pqc_completed_at IS NULL`.

    /// Return up to `limit` `federation_keys` rows where
    /// `pqc_completed_at IS NULL`, ordered oldest first by
    /// `valid_from`. Returns `(key_id, registration_envelope,
    /// scrub_signature_classical)` triples sufficient to reconstruct
    /// the cold-path bound-signature input.
    async fn list_hybrid_pending_keys(&self, limit: i64) -> Result<Vec<HybridPendingRow>, Error>;

    /// Return up to `limit` `federation_attestations` rows where
    /// `pqc_completed_at IS NULL`, ordered oldest first by
    /// `asserted_at`.
    async fn list_hybrid_pending_attestations(
        &self,
        limit: i64,
    ) -> Result<Vec<HybridPendingRow>, Error>;

    /// Return up to `limit` `federation_revocations` rows where
    /// `pqc_completed_at IS NULL`, ordered oldest first by
    /// `revoked_at`.
    async fn list_hybrid_pending_revocations(
        &self,
        limit: i64,
    ) -> Result<Vec<HybridPendingRow>, Error>;

    // ── Trust grants (v1.3.0, CIRISPersist#46 + #47) ───────────────
    //
    // Persist absorbs NodeCore's `crate::trust` module surface at
    // the M2 cut. Raw CRUD over the trust-hierarchy columns on
    // `federation_keys` (added by V020); NodeCore composes the
    // transitive-resolution policy on top via `resolve_trust`.
    //
    // Default impls return `Error::Backend` with a stable
    // "trust_methods_not_implemented" marker so backends that
    // haven't been ported yet (memory/test shims) compile cleanly.
    // The real backends (postgres, sqlite) override every method.
    //
    // # Audit chain coupling
    //
    // CIRISAgent#756 Q4 verdict: state transitions for the trust
    // hierarchy live in the audit chain (`cirislens.audit_log`),
    // not in a separate revocation_history table. The
    // `AuditEventType::TrustGranted` / `TrustRevoked` vocabulary +
    // V020 CHECK extension carry the wire-shape; persist callers
    // compose the pair (write the trust row via this trait, then
    // write the audit entry via `AuditService::record_entry` /
    // `try_claim_event` with a caller-signed `AuditEntry`). Persist
    // does not auto-sign because the audit chain's self-signed
    // identity model (AV-49) requires the caller's Ed25519 key.

    /// Insert or update a trust row on `federation_keys`.
    /// Implementations:
    ///   1. Validate `grant.trusted_by != grant.key` (no self-trust);
    ///      reject with [`Error::InvalidArgument`].
    ///   2. Validate `Registry`-relationship grants carry a non-empty
    ///      `trust_domains`; reject with [`Error::InvalidArgument`].
    ///   3. UPSERT on `key_id` — preserves the pubkey + signature
    ///      envelope written by the prior `put_public_key`, overwrites
    ///      the trust columns. `trusted_at` is set to `NOW()`.
    async fn grant_trust(&self, grant: TrustGrant) -> Result<(), Error> {
        let _ = grant;
        Err(Error::Backend(
            "grant_trust not implemented for this backend".into(),
        ))
    }

    /// Soft-delete a trust row by setting `expires_at = NOW()`.
    /// Idempotent — revoking an already-expired row is a no-op.
    async fn revoke_trust(&self, key: &str, revoked_by: &str) -> Result<(), Error> {
        let _ = (key, revoked_by);
        Err(Error::Backend(
            "revoke_trust not implemented for this backend".into(),
        ))
    }

    /// Point lookup — the raw trust row, no transitive resolution.
    /// `None` if no trust row exists for `key` (i.e., the row
    /// exists in `federation_keys` but `trusted_by` is NULL — a
    /// pre-V020 row, or a key registered without a trust grant).
    async fn lookup_trust(&self, key: &str) -> Result<Option<TrustRow>, Error> {
        let _ = key;
        Err(Error::Backend(
            "lookup_trust not implemented for this backend".into(),
        ))
    }

    /// All currently-trusted keys matching `filter`. Server-side
    /// filtering for relationship + domain; expired rows excluded
    /// unless `filter.include_expired = true`. Pre-V020 rows
    /// (`trusted_by IS NULL`) are excluded — the surface returns
    /// only rows with an explicit trust grant.
    async fn list_trusted_keys(&self, filter: TrustFilter) -> Result<Vec<TrustRow>, Error> {
        let _ = filter;
        Err(Error::Backend(
            "list_trusted_keys not implemented for this backend".into(),
        ))
    }

    // ── Goals (v2.10.0, CIRISPersist#114) ──────────────────────────
    //
    // The typed `Goal` primitive (see [`goal`]) carries M-1 alignment
    // as a structural construction-time invariant — a Goal cannot be
    // constructed without [`MetaGoalAlignment`]. The persistence
    // surface mirrors that discipline: every write goes through a
    // typed `Goal`, never a free-form JSON envelope.
    //
    // F-3 detector consumers (CIRISLensCore#23 / #24 / #26) walk
    // these rows to aggregate goals by `declared_by_key_id` + scope +
    // `m1_dimension`. The hot path skips retired goals (the
    // `(retired_at IS NULL)` partial index), so `list_goals` defaults
    // to live-only via `GoalsFilter::include_retired = false`.
    //
    // Defaults route to `Error::Backend(...)` so the memory shim and
    // any future test-only backend compile cleanly; the real backends
    // (postgres, sqlite) override every method.

    /// Insert a [`Goal`]. The row is persisted with a server-computed
    /// `persist_row_hash` over the canonical bytes (same shape as
    /// `KeyRecord` et al.). Errors:
    /// - [`Error::InvalidArgument`] when `declared_by_key_id` is not
    ///   present in `federation_keys` (FK enforcement).
    /// - [`Error::Conflict`] when `goal_id` is already in the table
    ///   with content that differs from the submitted row.
    async fn put_goal(&self, goal: Goal) -> Result<(), Error> {
        let _ = goal;
        Err(Error::Backend(
            "put_goal not implemented for this backend".into(),
        ))
    }

    /// Fetch a single [`Goal`] by `goal_id`. Returns `None` when
    /// absent.
    async fn get_goal(&self, goal_id: uuid::Uuid) -> Result<Option<Goal>, Error> {
        let _ = goal_id;
        Err(Error::Backend(
            "get_goal not implemented for this backend".into(),
        ))
    }

    /// Enumerate [`Goal`] rows matching `filter`. Fields AND-composed
    /// (see [`GoalsFilter`]); retired rows are filtered out by
    /// default. Returned in stable lex order by `(declared_at,
    /// goal_id)` so callers can deterministically paginate.
    async fn list_goals(&self, filter: GoalsFilter) -> Result<Vec<Goal>, Error> {
        let _ = filter;
        Err(Error::Backend(
            "list_goals not implemented for this backend".into(),
        ))
    }

    /// Mark a [`Goal`] retired at `retired_at`. **Idempotent.** A
    /// second call against an already-retired goal returns `Ok(())`
    /// without changing the stored `retired_at` — the chosen
    /// discipline matches [`revoke_trust`](Self::revoke_trust)'s
    /// "soft-delete, idempotent" shape so consumers driving
    /// retirement from a queue don't need to special-case the
    /// race-replay window. Callers wanting strict-once semantics
    /// MUST guard at their layer (the
    /// [`Engine::receive_and_persist`](crate::Engine::receive_and_persist)
    /// pattern uses content-hash dedup for that). When the row does
    /// not exist, [`Error::InvalidArgument`] is returned.
    async fn retire_goal(
        &self,
        goal_id: uuid::Uuid,
        retired_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error> {
        let _ = (goal_id, retired_at);
        Err(Error::Backend(
            "retire_goal not implemented for this backend".into(),
        ))
    }

    // ── Peer-mutation surface (v3.1.0, CIRISPersist#117) ───────────
    //
    // Unblocks CIRISEdge v0.13.0's `PEER_MUTATION_FOLLOWUP` stubs in
    // `src/ffi/uniffi_impl.rs`. Operator-driven writes against the
    // V051 `federation_peer_metadata` sibling table. Access control
    // for these methods is enforced OUTSIDE persist (the UniFFI layer
    // is operator-local); persist's responsibility is value-domain
    // validation — typed errors, no silent coercion.
    //
    // Defaults route to `Error::Backend(...)` so backends that
    // haven't been ported yet compile cleanly. The real backends
    // (memory, postgres, sqlite) override every method.

    /// Insert a new peer row. Atomically:
    /// 1. Inserts a minimal `federation_keys` identity row carrying
    ///    `key_id`, `pubkey_ed25519_base64`, `identity_type`.
    /// 2. Inserts the sibling `federation_peer_metadata` row with
    ///    default `trust = TrustClass::Untrusted` + the supplied
    ///    `transport_identity`.
    ///
    /// Both writes happen in a single transaction; either both land
    /// or neither does.
    ///
    /// Errors:
    /// - [`Error::Conflict`] when `key_id` already exists with
    ///   different content.
    /// - [`Error::InvalidArgument`] when `key_id` /
    ///   `pubkey_ed25519_base64` / `identity_type` are empty.
    async fn add_peer_record(
        &self,
        key_id: &str,
        pubkey_ed25519_base64: &str,
        identity_type: &str,
        transport_identity: Option<String>,
    ) -> Result<(), Error> {
        let _ = (
            key_id,
            pubkey_ed25519_base64,
            identity_type,
            transport_identity,
        );
        Err(Error::Backend(
            "add_peer_record not implemented for this backend".into(),
        ))
    }

    /// Remove a peer row. Two modes:
    /// - `hard = false` (recommended): marks
    ///   `federation_peer_metadata.removed_at = NOW()`; subsequent
    ///   reads filter the row out. The federation_keys row is
    ///   preserved — the audit trail of "this peer was once a peer"
    ///   stays intact.
    /// - `hard = true`: DELETEs the federation_keys row in the same
    ///   transaction; the FK ON DELETE CASCADE removes the
    ///   federation_peer_metadata row too. **Rejected** with
    ///   [`Error::HardRemoveWithActiveAttestations`] when the peer
    ///   still has rows in `federation_attestations` —
    ///   hard-removing would orphan the attestation_envelope. Caller
    ///   must either soft-remove (preserve the audit trail) OR
    ///   explicitly revoke the key first.
    ///
    /// Errors:
    /// - [`Error::PeerNotFound`] when no peer row exists for
    ///   `key_id`.
    /// - [`Error::HardRemoveWithActiveAttestations`] when `hard =
    ///   true` and the peer has active attestations.
    async fn remove_peer_record(&self, key_id: &str, hard: bool) -> Result<(), Error> {
        let _ = (key_id, hard);
        Err(Error::Backend(
            "remove_peer_record not implemented for this backend".into(),
        ))
    }

    /// Set the peer's operator-local alias. `None` clears it. Bumps
    /// `updated_at` and recomputes `persist_row_hash`.
    ///
    /// Errors:
    /// - [`Error::PeerNotFound`] when no peer row exists for
    ///   `key_id`.
    async fn update_peer_alias(&self, key_id: &str, alias: Option<String>) -> Result<(), Error> {
        let _ = (key_id, alias);
        Err(Error::Backend(
            "update_peer_alias not implemented for this backend".into(),
        ))
    }

    /// Set the peer's operator-trust class. Typed enum (no silent
    /// coercion of unrecognized strings). Bumps `updated_at` and
    /// recomputes `persist_row_hash`.
    ///
    /// Errors:
    /// - [`Error::PeerNotFound`] when no peer row exists for
    ///   `key_id`.
    async fn update_peer_trust(&self, key_id: &str, trust: TrustClass) -> Result<(), Error> {
        let _ = (key_id, trust);
        Err(Error::Backend(
            "update_peer_trust not implemented for this backend".into(),
        ))
    }

    /// Set the peer's operator-local notes. `None` clears the field.
    /// Bumps `updated_at` and recomputes `persist_row_hash`.
    ///
    /// Errors:
    /// - [`Error::PeerNotFound`] when no peer row exists for
    ///   `key_id`.
    async fn update_peer_notes(&self, key_id: &str, notes: Option<String>) -> Result<(), Error> {
        let _ = (key_id, notes);
        Err(Error::Backend(
            "update_peer_notes not implemented for this backend".into(),
        ))
    }

    /// Set the peer's opaque policy blob. Persist round-trips the
    /// JSON verbatim; the shape is owned by the consumer (CIRISEdge
    /// UniFFI's `PeerPolicy`). Bumps `updated_at` and recomputes
    /// `persist_row_hash`.
    ///
    /// Errors:
    /// - [`Error::PeerNotFound`] when no peer row exists for
    ///   `key_id`.
    async fn update_peer_policy(&self, key_id: &str, policy: PeerPolicyBlob) -> Result<(), Error> {
        let _ = (key_id, policy);
        Err(Error::Backend(
            "update_peer_policy not implemented for this backend".into(),
        ))
    }

    /// v3.4.1 (CIRISPersist#127) — read accessor for
    /// `federation_peer_metadata`. Returns the full row shape for
    /// active peers; `None` for non-existent or soft-removed peers
    /// (`removed_at IS NOT NULL`).
    ///
    /// Symmetric to [`update_peer_policy`] + the four other peer
    /// update methods — the write side shipped in v3.1.0 (#117); this
    /// is the read side CIRISEdge#48 (cohort_scope consumer-side
    /// enforcement) requires for `peer.policy_blob.cohort_scope`
    /// comparison.
    ///
    /// The `policy_blob` field is opaque JSON (the same shape callers
    /// pass to [`update_peer_policy`]); consumer is responsible for
    /// the typed decode.
    async fn peer_metadata_for(&self, key_id: &str) -> Result<Option<PeerMetadataRow>, Error> {
        let _ = key_id;
        Err(Error::Backend(
            "peer_metadata_for not implemented for this backend".into(),
        ))
    }
}

/// Federation directory errors. Distinct from
/// [`crate::store::Error`] (which covers trace ingest / lens schema
/// concerns) — federation has its own failure surface for write
/// validation and quota enforcement.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments (empty `key_id`, malformed
    /// pubkey, scrub_key_id doesn't exist, etc.).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Scrub-signature on the incoming row did not verify against
    /// the scrub_key_id's pubkey. Indicates either tampering or a
    /// caller bug. Persist does not store the row.
    #[error("scrub-signature verification failed: {0}")]
    SignatureInvalid(String),

    /// Per-source-IP rate limit exceeded (default 60 writes/min/IP)
    /// or per-primitive write quota exceeded (default 10 keys/day).
    /// Caller should retry after `retry_after_seconds`.
    #[error("rate limited: retry after {retry_after_seconds}s")]
    RateLimited {
        /// Seconds the caller should wait before retrying.
        retry_after_seconds: u64,
    },

    /// Row would conflict with an existing row whose content differs.
    /// Idempotent re-submission of the *same* content is OK; this
    /// fires only when the caller is overwriting.
    #[error("conflicts with existing row: {0}")]
    Conflict(String),

    /// v2.4.0 (CIRISPersist#102 Ask 3a). The submitted `scores`
    /// attestation's `dimension` begins with `accord:` but the
    /// `attesting_key_id`'s `identity_type` is not `accord_holder`.
    /// The federation's one constitutional asymmetry per FSD-002
    /// §4.1 + §7.1; the admission gate refused the write.
    #[error(
        "accord:* dimensions require identity_type=accord_holder \
         (got dimension={dimension:?}, attesting identity_type={identity_type:?})"
    )]
    AccordDimensionRequiresAccordHolder {
        /// The `dimension` from the attestation envelope that
        /// triggered the rejection.
        dimension: String,
        /// The attesting key's `identity_type` as resolved at
        /// admission time.
        identity_type: String,
    },

    /// v2.4.0 (CIRISPersist#102 Ask 3b). The submitted `scores`
    /// attestation's `dimension` failed one of the four
    /// operational-language tests (FSD-002 §1.10.1): rules/verdicts
    /// separation (T1), mechanism-descriptive-not-judgment naming
    /// (T2), version-pinning (T3), adjudication separation (T4).
    /// See [`admission::DimensionAdmissionPolicy`] for the policy
    /// shape and `docs/FEDERATION_DIRECTORY.md` for the rationale.
    #[error("dimension rejected by admission policy: {reason} (dimension={dimension:?})")]
    DimensionRejected {
        /// The `dimension` value that failed the gate.
        dimension: String,
        /// Stable machine-readable reason token (matches one of
        /// [`admission::DimensionRejectionReason`]'s `as_str()`).
        reason: &'static str,
    },

    /// v3.0.0 (CIRISPersist#116, CEG 0.2 §7.0). The submitted
    /// `scores` attestation's `dimension` matches a reserved-prefix
    /// pattern (`system:*`, `audit_chain:*`, `transparency_log:cosigned:*`,
    /// `capacity:*` self-emission, …) but the `attesting_key_id`'s
    /// `identity_type` does not satisfy the emitter rule for that
    /// prefix. Rejected at admission; the row is not stored. See
    /// [`admission::ReservedPrefixRule`] for the per-prefix rule
    /// shape and [`admission::DimensionAdmissionPolicy::reserved_prefix_rules`]
    /// for the default policy contents.
    #[error(
        "reserved-prefix emitter mismatch: dimension {dimension:?} requires \
         identity_type ∈ {required:?} but got identity_type={got_identity_type:?}"
    )]
    ReservedPrefixEmitterMismatch {
        /// The `dimension` value from the attestation envelope.
        dimension: String,
        /// The reserved prefix pattern that matched.
        prefix: String,
        /// Identity-type vocabulary the prefix accepts (sorted for
        /// deterministic error output).
        required: Vec<String>,
        /// The submitting key's resolved `identity_type`.
        got_identity_type: String,
    },

    /// v2.5.0 (CIRISPersist#102 Ask 4). The submitted `scores`
    /// attestation's `attestation_envelope` failed JSON Schema
    /// validation against the per-axis schema registered for the
    /// dimension's axis (FSD-002 §4.9.1 operational-definition
    /// "evidence-shape requirement"). The schema's `evidence_refs`
    /// requirement (the schema SHA must appear in the envelope's
    /// `evidence_refs[]`) is part of the schema document, not
    /// separately enforced — JSON Schema does that work.
    #[error(
        "envelope schema violation for dimension {dimension:?} (axis={axis:?}): \
         {} violation(s)", violations.len()
    )]
    EnvelopeSchemaViolation {
        /// The `dimension` value from the attestation envelope.
        dimension: String,
        /// The axis derived from `dimension` (per
        /// [`axis_from_dimension`]).
        axis: String,
        /// Human-readable violation strings, one per JSON Schema
        /// failure. Order matches `jsonschema::iter_errors`.
        violations: Vec<String>,
    },

    /// v2.5.0 (CIRISPersist#102 Ask 8). The submitted
    /// `federation_keys` row has `identity_type = 'accord_holder'`
    /// but no `attestation_evidence` field, or the field is null /
    /// fails to deserialize. Per FSD-002 §7.3, accord-holder keys
    /// MUST live on hardware substrate; the admission hook reads
    /// `attestation_evidence` to confirm. Defense-in-depth:
    /// V048 CHECK constraint catches the same shape if a row
    /// bypasses the admission hook (e.g., direct SQL).
    #[error(
        "accord_holder row requires non-null attestation_evidence \
         (key_id={key_id:?}): {detail}"
    )]
    AccordHolderRequiresAttestationEvidence {
        /// The `key_id` of the rejected row.
        key_id: String,
        /// Detail: "missing", "null", "malformed: <serde err>", etc.
        detail: String,
    },

    /// v2.5.0 (CIRISPersist#102 Ask 8). The submitted
    /// `attestation_evidence` carries a `hardware_type` that
    /// [`HardwareAttestationPolicy`] does not accept for accord-
    /// holder identity. The default policy refuses
    /// `HardwareType::SoftwareOnly` — Verify's one structural floor
    /// (`supports_professional_license() == false`); operator
    /// policies may tighten further.
    #[error(
        "accord_holder hardware_type {got:?} not accepted by policy \
         (accepted={accepted:?})"
    )]
    HardwareTypeNotAccepted {
        /// The submitted hardware_type variant name (e.g.
        /// `"SoftwareOnly"`, `"AndroidStrongbox"`).
        got: String,
        /// The policy's accepted set, serialized for the error
        /// message. Sorted for deterministic output.
        accepted: Vec<String>,
    },

    /// v2.5.0 (CIRISPersist#102 Ask 8). The submitted
    /// `PlatformAttestation` variant matches the
    /// [`HardwareAttestationPolicy`] but is structurally
    /// incomplete — missing one of the variant's required fields
    /// (e.g. Android without `key_attestation_chain`; TPM without
    /// `pcr_values`). Persist does NOT do active chain validation
    /// here (that's CIRISVerify#32 Ask 5); only structural
    /// field-presence checks locally.
    #[error(
        "accord_holder attestation_evidence incomplete \
         (hardware_type={hardware_type:?}, missing={missing_fields:?})"
    )]
    AttestationEvidenceIncomplete {
        /// The hardware type variant from the submitted evidence.
        hardware_type: String,
        /// The list of required-but-missing field names. Stable
        /// vocabulary; tests pin specific names.
        missing_fields: Vec<String>,
    },

    /// v2.5.0 (CIRISPersist#102 Ask 8). The submitted
    /// `attestation_evidence` carries a `nonce_captured_at`
    /// timestamp older than [`HardwareAttestationPolicy::max_nonce_age`].
    /// Defeats replay of an old attestation against a new key-
    /// binding event.
    #[error(
        "accord_holder attestation_evidence stale \
         (captured_at={captured_at}, max_age={max_age_secs}s)"
    )]
    AttestationEvidenceStale {
        /// RFC3339 timestamp of the captured nonce.
        captured_at: chrono::DateTime<chrono::Utc>,
        /// Max age in seconds (`HardwareAttestationPolicy::max_nonce_age`).
        max_age_secs: u64,
    },

    /// v3.1.0 (CIRISPersist#117). The peer-mutation surface was
    /// called with a `key_id` that has no row in
    /// `federation_peer_metadata`. Distinct from
    /// [`Error::InvalidArgument`] so consumers can deterministically
    /// pattern-match the "you addressed an unknown peer" outcome.
    #[error("peer record not found for key_id={key_id}")]
    PeerNotFound {
        /// The `key_id` the caller addressed.
        key_id: String,
    },

    /// v3.1.0 (CIRISPersist#117). [`FederationDirectory::remove_peer_record`]
    /// was called with `hard = true` against a peer that still has
    /// `federation_attestations` rows attesting to / from / scrubbed-by
    /// the key. A hard remove would orphan those attestations'
    /// `attestation_envelope` (the federation_keys row they reference
    /// would disappear). The caller MUST either soft-remove (preserve
    /// the audit trail) OR explicitly revoke the key first.
    #[error(
        "hard remove of peer with active attestations rejected — \
         use soft remove or revoke the key first; key_id={key_id}, \
         attestation_count={attestation_count}"
    )]
    HardRemoveWithActiveAttestations {
        /// The `key_id` the caller tried to hard-remove.
        key_id: String,
        /// The count of attestations that would have been orphaned.
        attestation_count: usize,
    },

    /// v3.4.0 (CIRISPersist#123) — the
    /// [`AdmissionGate`](crate::federation::AdmissionGate) rejected the
    /// write: the attesting key's aggregate trust score is below the
    /// deployment's `trust_threshold`. The row was NOT written.
    /// Distinct from [`Error::InvalidArgument`] so consumers can
    /// match the trust-rejection deterministically without parsing
    /// the error string. The trust gate runs BEFORE FK validation,
    /// envelope-schema validation, and signature verification — by
    /// design, an unauthorized writer should not learn whether the
    /// downstream checks would have succeeded.
    #[error("trust score {score} for key_id={key_id} is below threshold {threshold}")]
    TrustBelowThreshold {
        /// The attesting key the gate evaluated.
        key_id: String,
        /// The aggregate score returned by the resolver.
        score: f64,
        /// The configured threshold.
        threshold: f64,
    },

    /// v3.9.1 (CIRISPersist#150 Ask 3, CEG 0.4 §4.2.4). The submitted
    /// attestation's `cohort_scope` is outside the closed set
    /// `{self, family, community, affiliations, species, biosphere,
    /// federation}` — most commonly `global`, which is a §8.1.8
    /// feed-name (`{species, biosphere, federation}` aggregate), not a
    /// wire value. Rejected at admission by
    /// [`admission::check_cohort_scope`]; the row is not stored.
    /// Distinct from [`Error::InvalidArgument`] so consumers can
    /// pattern-match the cohort_scope rejection deterministically. The
    /// V056 `CHECK (cohort_scope IN (...))` constraint is the
    /// defense-in-depth backstop for rows that bypass this hook.
    #[error(
        "cohort_scope {cohort_scope:?} is not in the closed set \
         {{self, family, community, affiliations, species, biosphere, federation}}"
    )]
    CohortScopeRejected {
        /// The rejected `cohort_scope` value as submitted.
        cohort_scope: String,
    },

    /// v3.11.0 (CIRISPersist#143, CIRISVerify FEDERATION_THREAT_MODEL
    /// §3.3.2 R1). The submitted revocation's `observed_region` is
    /// outside the closed set `{us, eu, apac}`. Rejected at admission
    /// by [`admission::check_observed_region`]; the row is not stored.
    /// Distinct from [`Error::InvalidArgument`] so consumers can
    /// pattern-match the region-closed-set rejection deterministically.
    #[error("observed_region {observed_region:?} is not in the closed set {{us, eu, apac}}")]
    RegionRejected {
        /// The rejected `observed_region` value as submitted.
        observed_region: String,
    },

    /// v3.11.0 (CIRISPersist#143, CIRISVerify FEDERATION_THREAT_MODEL
    /// §3.3.2 Q1, F-AV-ROLLBACK closure). The submitted revocation's
    /// `signed_timestamp` is **not strictly later than** the most-
    /// recent existing revocation for the same `revoked_key_id`. The
    /// spec's anti-rollback contract is enforced **at admission**,
    /// before quorum is asked — a sufficient minority of regions
    /// cannot ratify a rollback because the rollback never enters the
    /// quorum gate.
    ///
    /// `existing_signed_timestamp` is the latest already-stored
    /// timestamp the gate compared against; `submitted_signed_timestamp`
    /// is the rejected row's. Equal timestamps reject too (strictly
    /// greater is required).
    #[error(
        "anti-rollback: revocation for {revoked_key_id:?} signed_timestamp \
         {submitted_signed_timestamp} is not strictly later than existing \
         {existing_signed_timestamp}"
    )]
    RevocationRollback {
        /// The `revoked_key_id` the new revocation targets.
        revoked_key_id: String,
        /// The latest signed_timestamp already on file for this target.
        existing_signed_timestamp: chrono::DateTime<chrono::Utc>,
        /// The submitted (rejected) signed_timestamp.
        submitted_signed_timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Backend-level error (DB connection, serialization, etc.).
    /// String-typed because each backend has its own error tree.
    #[error("backend: {0}")]
    Backend(String),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "federation_invalid_argument",
            Error::SignatureInvalid(_) => "federation_signature_invalid",
            Error::RateLimited { .. } => "federation_rate_limited",
            Error::Conflict(_) => "federation_conflict",
            Error::AccordDimensionRequiresAccordHolder { .. } => {
                "federation_accord_dimension_requires_accord_holder"
            }
            Error::DimensionRejected { .. } => "federation_dimension_rejected",
            Error::ReservedPrefixEmitterMismatch { .. } => {
                "federation_reserved_prefix_emitter_mismatch"
            }
            Error::EnvelopeSchemaViolation { .. } => "federation_envelope_schema_violation",
            Error::AccordHolderRequiresAttestationEvidence { .. } => {
                "federation_accord_holder_requires_attestation_evidence"
            }
            Error::HardwareTypeNotAccepted { .. } => "federation_hardware_type_not_accepted",
            Error::AttestationEvidenceIncomplete { .. } => {
                "federation_attestation_evidence_incomplete"
            }
            Error::AttestationEvidenceStale { .. } => "federation_attestation_evidence_stale",
            Error::PeerNotFound { .. } => "federation_peer_not_found",
            Error::HardRemoveWithActiveAttestations { .. } => {
                "federation_hard_remove_with_active_attestations"
            }
            Error::TrustBelowThreshold { .. } => "federation_trust_below_threshold",
            Error::CohortScopeRejected { .. } => "federation_cohort_scope_rejected",
            Error::RegionRejected { .. } => "federation_region_rejected",
            Error::RevocationRollback { .. } => "federation_revocation_rollback",
            Error::Backend(_) => "federation_backend",
        }
    }
}
