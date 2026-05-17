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

use std::future::Future;

#[cfg(feature = "cirisaudit")]
pub mod emit;
#[cfg(feature = "cirisaudit")]
pub mod read;
#[cfg(feature = "sqlite")]
pub mod sqlite_open;
pub mod trust_grant;
pub mod types;

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

#[cfg(feature = "sqlite")]
pub use sqlite_open::FederationDirectorySqlite;
pub use types::{
    Attestation, HybridPendingRow, KeyRecord, Revocation, SignedAttestation, SignedKeyRecord,
    SignedRevocation, TrustFilter, TrustGrant, TrustRelationship, TrustRow, TrustType,
};

/// Federation directory trait — the registry/lens/agent's read+write
/// surface over persist's three federation tables.
///
/// **Async surface uses Rust 1.75+ `async fn in trait` directly**;
/// futures are constrained `Send` so backends can be used from
/// `tokio::spawn`-style multi-threaded contexts (matches
/// [`crate::store::Backend`] convention).
///
/// # Wire-format note
///
/// Read methods return [`KeyRecord`] / [`Attestation`] / [`Revocation`]
/// with `persist_row_hash` populated server-side (see
/// [`types::KeyRecord::persist_row_hash`] for the canonicalization
/// contract).
///
/// Write methods take [`SignedKeyRecord`] / [`SignedAttestation`] /
/// [`SignedRevocation`] — wrappers carrying a record the caller has
/// signed but persist has not yet stored. Persist verifies the
/// scrub-signature on receipt before writing.
pub trait FederationDirectory: Send + Sync {
    // ── Public keys ────────────────────────────────────────────────

    /// Insert a new pubkey row. Idempotent on `key_id` collision with
    /// matching content (no-op); errors on `key_id` collision with
    /// differing content.
    fn put_public_key(
        &self,
        record: SignedKeyRecord,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Fetch a single pubkey row by `key_id`. Returns `None` if absent.
    fn lookup_public_key(
        &self,
        key_id: &str,
    ) -> impl Future<Output = Result<Option<KeyRecord>, Error>> + Send;

    /// Fetch all pubkey rows for a given identity. Used by the
    /// "all keys for primitive X" lookup the v0.2.x verify subsumption
    /// proxy will call.
    fn lookup_keys_for_identity(
        &self,
        identity_ref: &str,
    ) -> impl Future<Output = Result<Vec<KeyRecord>, Error>> + Send;

    // ── Attestations ───────────────────────────────────────────────

    /// Insert a new attestation row.
    fn put_attestation(
        &self,
        attestation: SignedAttestation,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// All attestations targeting `attested_key_id` (consumer asks
    /// "who vouches for K?"). Ordered by `asserted_at` DESC.
    fn list_attestations_for(
        &self,
        attested_key_id: &str,
    ) -> impl Future<Output = Result<Vec<Attestation>, Error>> + Send;

    /// All attestations issued by `attesting_key_id` (consumer asks
    /// "which keys does K vouch for?"). Ordered by `asserted_at` DESC.
    fn list_attestations_by(
        &self,
        attesting_key_id: &str,
    ) -> impl Future<Output = Result<Vec<Attestation>, Error>> + Send;

    // ── Revocations ────────────────────────────────────────────────

    /// Insert a new revocation row. Append-only — revocations of an
    /// already-revoked key are accepted (the latest-effective-at one
    /// wins under most consumer policies).
    fn put_revocation(
        &self,
        revocation: SignedRevocation,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// All revocations targeting `revoked_key_id`. Ordered by
    /// `effective_at` DESC. Consumers walk this list and apply their
    /// policy ("is K revoked at time T?").
    fn revocations_for(
        &self,
        revoked_key_id: &str,
    ) -> impl Future<Output = Result<Vec<Revocation>, Error>> + Send;

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
    fn attach_key_pqc_signature(
        &self,
        key_id: &str,
        pubkey_ml_dsa_65_base64: &str,
        scrub_signature_pqc: &str,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Attach the PQC signature to a hybrid-pending
    /// `federation_attestations` row. Attestations don't have their
    /// own pubkey — they reference the existing
    /// `federation_keys.scrub_key_id`'s pubkey for verification.
    fn attach_attestation_pqc_signature(
        &self,
        attestation_id: &str,
        scrub_signature_pqc: &str,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Attach the PQC signature to a hybrid-pending
    /// `federation_revocations` row. Same shape as attestations.
    fn attach_revocation_pqc_signature(
        &self,
        revocation_id: &str,
        scrub_signature_pqc: &str,
    ) -> impl Future<Output = Result<(), Error>> + Send;

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
    fn list_hybrid_pending_keys(
        &self,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<HybridPendingRow>, Error>> + Send;

    /// Return up to `limit` `federation_attestations` rows where
    /// `pqc_completed_at IS NULL`, ordered oldest first by
    /// `asserted_at`.
    fn list_hybrid_pending_attestations(
        &self,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<HybridPendingRow>, Error>> + Send;

    /// Return up to `limit` `federation_revocations` rows where
    /// `pqc_completed_at IS NULL`, ordered oldest first by
    /// `revoked_at`.
    fn list_hybrid_pending_revocations(
        &self,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<HybridPendingRow>, Error>> + Send;

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
    fn grant_trust(&self, grant: TrustGrant) -> impl Future<Output = Result<(), Error>> + Send {
        let _ = grant;
        async {
            Err(Error::Backend(
                "grant_trust not implemented for this backend".into(),
            ))
        }
    }

    /// Soft-delete a trust row by setting `expires_at = NOW()`.
    /// Idempotent — revoking an already-expired row is a no-op.
    fn revoke_trust(
        &self,
        key: &str,
        revoked_by: &str,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        let _ = (key, revoked_by);
        async {
            Err(Error::Backend(
                "revoke_trust not implemented for this backend".into(),
            ))
        }
    }

    /// Point lookup — the raw trust row, no transitive resolution.
    /// `None` if no trust row exists for `key` (i.e., the row
    /// exists in `federation_keys` but `trusted_by` is NULL — a
    /// pre-V020 row, or a key registered without a trust grant).
    fn lookup_trust(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<TrustRow>, Error>> + Send {
        let _ = key;
        async {
            Err(Error::Backend(
                "lookup_trust not implemented for this backend".into(),
            ))
        }
    }

    /// All currently-trusted keys matching `filter`. Server-side
    /// filtering for relationship + domain; expired rows excluded
    /// unless `filter.include_expired = true`. Pre-V020 rows
    /// (`trusted_by IS NULL`) are excluded — the surface returns
    /// only rows with an explicit trust grant.
    fn list_trusted_keys(
        &self,
        filter: TrustFilter,
    ) -> impl Future<Output = Result<Vec<TrustRow>, Error>> + Send {
        let _ = filter;
        async {
            Err(Error::Backend(
                "list_trusted_keys not implemented for this backend".into(),
            ))
        }
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
            Error::Backend(_) => "federation_backend",
        }
    }
}
