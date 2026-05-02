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

pub mod types;

pub use types::{
    Attestation, KeyRecord, Revocation, SignedAttestation, SignedKeyRecord, SignedRevocation,
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
