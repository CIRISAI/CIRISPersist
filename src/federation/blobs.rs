//! Content-addressable byte storage substrate (v2.3, CIRISPersist#103).
//!
//! # Mission alignment (MISSION.md §2 — `federation/`)
//!
//! Persist already has the federation directory naming what exists
//! (federation_keys / federation_attestations / federation_revocations).
//! This module adds where the **bytes** referenced by SHA-256
//! evidence_refs (FSD-002 §2.1, agent_files:*, the federation
//! announcement payload references) actually live.
//!
//! The [`BlobStorage`] trait is a sibling to
//! [`FederationDirectory`](crate::federation::FederationDirectory) —
//! both are implemented by the same backends (postgres, sqlite) over
//! the same connection pool, but the conceptual surface is distinct:
//! the federation directory is about *identities and trust statements*,
//! while blob storage is about *content-addressable bytes*. Keeping the
//! traits separate lets a caller implement / mock one without the
//! other, and lets the trait doc-comments scope cleanly.
//!
//! # The four operations (per CIRISPersist#103)
//!
//! 1. [`put_blob`](BlobStorage::put_blob) — hash-on-write, SHA-keyed
//!    idempotency, auto-emits a `holds_bytes:sha256:<prefix>`
//!    attestation to the existing `federation_attestations` table.
//! 2. [`get_blob`](BlobStorage::get_blob) — returns the [`BlobBody`]
//!    variant matching the row's `storage_kind`. Persist NEVER fetches
//!    from S3 / external URLs; the caller streams the External case.
//! 3. [`has_blob`](BlobStorage::has_blob) — existence check.
//! 4. [`list_holders`](BlobStorage::list_holders) — queries the
//!    `holds_bytes:sha256:<prefix>` attestation index for keys that
//!    have written this blob. Prefix-not-full-hash for index size; the
//!    full SHA hides in the attestation envelope's `evidence_refs`
//!    array to discriminate prefix collisions (8-hex prefix gives 32
//!    bits → birthday collision around 65k distinct blobs, well below
//!    federation scale; the full SHA hides any structural collisions).
//!
//! # Why no GC in v0.1
//!
//! The v0.1 contract is **blobs persist forever**. The trait
//! deliberately exposes NO `delete_blob`. A future release will add
//! reference counting + a `prune_blobs(min_age)` API once the
//! reference-graph shape stabilizes. Operators run space policy outside
//! persist until then.
//!
//! # Hash-on-write contract
//!
//! `put_blob(sha256_arg, body, ...)` MUST:
//!
//! 1. For `Inline(bytes)`: compute SHA-256 over the bytes; compare to
//!    `sha256_arg`; reject mismatches with [`BlobError::HashMismatch`].
//! 2. For `External`: the trait has no bytes to hash — persist
//!    **trusts the caller** to have computed the SHA correctly. This
//!    is the same trust posture as `signature_verified` on a scrub
//!    envelope: the caller signed for the bytes; persist records.
//!
//! # Inline-size cap
//!
//! Persist refuses `Inline(bytes)` payloads larger than a configurable
//! cap (default [`DEFAULT_INLINE_BYTES_CAP`] = 1 MiB). This is a
//! belt-and-suspenders guard against a misbehaving caller inlining a
//! 1 GB blob; it is **not** the inline-vs-S3 routing policy (which
//! lives at the deployer's caller, not in persist). The cap is
//! configurable via the engine layer; backends ship the default.
//!
//! # Conflicting storage_kind (idempotency policy)
//!
//! When two writers `put_blob` the same SHA with different
//! `storage_kind` (one Inline, one External), the **first write
//! wins**: the table PK collapses the replay, and the second writer's
//! `storage_kind` is silently ignored. Rationale: the blob is
//! content-addressed — the SHA IS the identity. `storage_kind` is a
//! per-host hint about how the bytes are *stored locally*, not a wire
//! property of the blob. Two hosts having different opinions is the
//! expected federation shape, not an error. (`list_holders` returns
//! BOTH key_ids regardless — the `holds_bytes` attestation is per
//! attester.)

use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// v2.3 (CIRISPersist#103) — default maximum byte length for an
/// `Inline` payload. 1 MiB (1,048,576 bytes).
pub const DEFAULT_INLINE_BYTES_CAP: usize = 1024 * 1024;

/// v3.0.0 (CIRISPersist#116, CEG 0.2 §10.1.2) — default TTL for a
/// `holds_bytes:sha256:{prefix}` directory entry. Measured from the
/// attestation's `asserted_at` (the `signed_at` in CEG §10.1.2 wire
/// terms). After this window passes the holder is considered stale
/// and [`BlobStorage::list_holders`] filters the row out.
///
/// **24 hours per CEG §10.1.2.** The constant is the operator-tunable
/// default; sovereign deployments override per their freshness
/// policy (e.g., LAN-only edges that always-on may tighten the TTL;
/// cold-archive nodes may extend it). Persist exposes the constant
/// rather than a runtime field so the default is the same shape across
/// every deployment that hasn't overridden — operators tune by
/// providing their own freshness window when consuming `list_holders`
/// (the trait surface returns the unfiltered + filtered shapes
/// depending on the implementation; see [`BlobStorage::list_holders`]
/// for the contract).
pub const DEFAULT_HOLDS_BYTES_TTL: Duration = Duration::from_secs(24 * 3600);

/// v2.3 (CIRISPersist#103) — hex-prefix length for the
/// `holds_bytes:sha256:<prefix>` attestation index.
///
/// 8 hex chars = 4 bytes = 32 bits of prefix entropy. Birthday
/// collision at ~sqrt(2^32) = 65k distinct blobs — well below
/// federation scale. The full SHA-256 lives in the attestation
/// envelope's `evidence_refs` array to discriminate any prefix
/// collisions.
pub const HOLDS_BYTES_PREFIX_HEX_LEN: usize = 8;

/// v2.3 (CIRISPersist#103) — the `attestation_type` prefix prepended
/// to the SHA prefix for `holds_bytes` attestations.
///
/// Full string shape: `"holds_bytes:sha256:<8-hex-prefix>"`. The
/// `attestation_type` column on `federation_attestations` is free-form
/// TEXT (no enum CHECK in V004), so the new prefix rides existing
/// storage without a schema break.
pub const HOLDS_BYTES_ATTESTATION_TYPE_PREFIX: &str = "holds_bytes:sha256:";

/// Reference to a blob stored externally (S3 or arbitrary URL).
///
/// Persist NEVER dereferences the URI — the caller streams the bytes
/// from S3 / the URL itself, using whatever auth the caller's
/// deployment shape requires (IAM, bearer tokens, etc.). Persist just
/// stores the pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRef {
    /// S3 URI (e.g. `s3://my-bucket/some/key`) or plain HTTP(S) URL.
    pub uri: String,
    /// Authoritative byte length of the blob.
    pub size_bytes: u64,
    /// Informational media type. `None` → implicit
    /// "application/octet-stream".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

/// The body of a [`BlobStorage::put_blob`] / [`BlobStorage::get_blob`]
/// payload — either the inline bytes themselves, or a pointer to an
/// external store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobBody {
    /// Inline byte payload. Maximum size is bounded by the
    /// deployment's inline cap (default
    /// [`DEFAULT_INLINE_BYTES_CAP`]).
    Inline(Vec<u8>),
    /// External reference (S3 URI or arbitrary URL).
    External(ExternalRef),
}

impl BlobBody {
    /// True iff this is the [`BlobBody::Inline`] variant.
    pub fn is_inline(&self) -> bool {
        matches!(self, BlobBody::Inline(_))
    }

    /// Size hint for this body.
    pub fn size_bytes(&self) -> u64 {
        match self {
            BlobBody::Inline(b) => b.len() as u64,
            BlobBody::External(e) => e.size_bytes,
        }
    }

    /// The wire `storage_kind` string for this body.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub(crate) fn storage_kind(&self) -> &'static str {
        match self {
            BlobBody::Inline(_) => "inline",
            BlobBody::External(e) if e.uri.starts_with("s3://") => "s3",
            BlobBody::External(_) => "external_url",
        }
    }
}

/// v2.3 (CIRISPersist#103) — Content-addressable byte storage trait.
///
/// Sibling to [`FederationDirectory`](crate::federation::FederationDirectory).
/// The same backends implement both — they share the federation
/// connection pool — but the trait surfaces are kept distinct so the
/// federation-directory surface stays focused on identity/trust
/// statements while blob storage stays focused on bytes.
///
/// **Async surface uses Rust 1.75+ `async fn in trait` directly** via
/// `impl Future + Send`; not object-safe.
pub trait BlobStorage: Send + Sync {
    /// Maximum bytes the [`BlobBody::Inline`] arm accepts. Backends
    /// hold this as a configurable field, defaulting to
    /// [`DEFAULT_INLINE_BYTES_CAP`].
    fn inline_bytes_cap(&self) -> usize;

    /// Write a blob, with hash-on-write validation and auto-emission
    /// of the holder attestation.
    ///
    /// # Validation
    ///
    /// 1. For `BlobBody::Inline(bytes)`:
    ///    - `bytes.len() <= self.inline_bytes_cap()` else
    ///      [`BlobError::InlineSizeExceeded`].
    ///    - `sha2::Sha256(bytes) == *sha256` else
    ///      [`BlobError::HashMismatch`].
    /// 2. For `BlobBody::External`: the SHA is trusted; persist does
    ///    not have the bytes.
    ///
    /// # Idempotency + conflicting storage_kind
    ///
    /// On SHA collision the existing row is kept (first-write-wins on
    /// `storage_kind` / `external_ref`). The holder attestation is
    /// emitted on every call, so two hosts writing the same SHA both
    /// land in `list_holders`. See module-level docs for the full
    /// conflict policy.
    fn put_blob(
        &self,
        sha256: &[u8; 32],
        body: BlobBody,
        media_type: Option<&str>,
        attestation: PutBlobAttestation,
    ) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// Read a blob by its SHA-256.
    ///
    /// Returns the [`BlobBody`] variant matching the row's stored
    /// `storage_kind`. Persist never fetches from S3 / external URLs;
    /// the External arm hands back the pointer and the caller streams
    /// the bytes themselves.
    fn get_blob(
        &self,
        sha256: &[u8; 32],
    ) -> impl Future<Output = Result<Option<BlobBody>, BlobError>> + Send;

    /// Existence check. Cheaper than [`get_blob`](BlobStorage::get_blob)
    /// — does not pull the body column.
    fn has_blob(&self, sha256: &[u8; 32]) -> impl Future<Output = Result<bool, BlobError>> + Send;

    /// List the `key_id`s of every **currently-live** attester that
    /// has emitted a `holds_bytes:sha256:<prefix>` attestation for
    /// this blob.
    ///
    /// Queries the `federation_attestations` table:
    ///
    /// 1. WHERE attestation_type = `holds_bytes:sha256:<8-hex-prefix>`
    /// 2. AND evidence_refs (from the JSONB envelope) contains the
    ///    full hex SHA (discriminates prefix collisions)
    /// 3. AND `asserted_at + DEFAULT_HOLDS_BYTES_TTL > now` (the
    ///    CEG §10.1.2 24-hour freshness window; expired holders are
    ///    treated as stale per the spec)
    /// 4. AND the attester has NOT emitted a `withdraws` structural
    ///    composer against the holds_bytes attestation (CEG §10.1.2
    ///    ContentMiss feedback loop — when a consumer fetches from a
    ///    holder via the directory and the holder no longer has the
    ///    blob, the consumer emits a `withdraws` against the stale
    ///    `holds_bytes` row; the directory filters the row out
    ///    before serving the next consumer)
    ///
    /// Returns an empty `Vec` when no live holders exist. The
    /// substrate stores every holds_bytes row honestly (the audit
    /// chain is complete); the freshness filter applies at read.
    ///
    /// # Default TTL
    ///
    /// [`DEFAULT_HOLDS_BYTES_TTL`] is the CEG §10.1.2 24-hour
    /// default. Sovereign deployments override via their own
    /// implementation if they need a different freshness window;
    /// the trait's default behavior matches the spec.
    fn list_holders(
        &self,
        sha256: &[u8; 32],
    ) -> impl Future<Output = Result<Vec<String>, BlobError>> + Send;
}

/// Caller-supplied envelope for the holder attestation emitted by
/// [`BlobStorage::put_blob`].
///
/// Persist auto-emits a `holds_bytes:sha256:<prefix>` attestation on
/// every successful `put_blob`. The attestation requires the same
/// scrub-signature fields as any other federation attestation (V004
/// schema NOT NULL columns) — the caller pre-signs the envelope and
/// hands persist the components.
#[derive(Debug, Clone)]
pub struct PutBlobAttestation {
    /// `attesting_key_id` for the holder attestation. The
    /// federation_keys row referenced MUST exist (FK constraint on
    /// federation_attestations).
    pub attesting_key_id: String,
    /// Pre-computed UUID v4 for the attestation row's PK.
    pub attestation_id: String,
    /// SHA-256 of the canonical attestation envelope — the
    /// `original_content_hash` column. Hex-encoded.
    pub original_content_hash_hex: String,
    /// Caller's Ed25519 scrub signature over the canonical envelope.
    /// Base64-encoded.
    pub scrub_signature_classical: String,
    /// Optional ML-DSA-65 PQC signature; populated by the cold-path
    /// sweep if `None` at write time.
    pub scrub_signature_pqc: Option<String>,
    /// `scrub_key_id` — the federation_keys row that signed the
    /// envelope.
    pub scrub_key_id: String,
    /// Timestamp on the scrub signature.
    pub scrub_timestamp: chrono::DateTime<chrono::Utc>,
}

/// v2.3 (CIRISPersist#103) — typed errors from the [`BlobStorage`] trait.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// `put_blob(sha, Inline(bytes), ...)` where
    /// `sha2::Sha256(bytes) != sha`.
    #[error("blob hash mismatch: expected sha256={expected_hex}, computed={got_hex}")]
    HashMismatch {
        /// Hex-encoded expected SHA (the caller-supplied `sha256_arg`).
        expected_hex: String,
        /// Hex-encoded actually-computed SHA over the inline bytes.
        got_hex: String,
    },

    /// `put_blob(_, Inline(bytes), ...)` where
    /// `bytes.len() > inline_bytes_cap`.
    #[error(
        "inline blob size {size} exceeds deployment cap {cap} bytes; \
         use BlobBody::External for larger payloads"
    )]
    InlineSizeExceeded {
        /// Byte length of the rejected payload.
        size: usize,
        /// The configured cap that was exceeded.
        cap: usize,
    },

    /// Caller passed invalid arguments.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Holder attestation could not be emitted — typically an FK
    /// violation on `attesting_key_id` not existing in
    /// `federation_keys`. The blob row itself was NOT written
    /// (transactional rollback).
    #[error("attestation emission failed: {0}")]
    AttestationEmissionFailed(String),

    /// Backend-level error (DB connection, serialization, etc.).
    #[error("backend: {0}")]
    Backend(String),
}

impl BlobError {
    /// Stable string-token for telemetry / structured logging.
    /// THREAT_MODEL.md AV-15: closed-set kind() vocabulary.
    pub fn kind(&self) -> &'static str {
        match self {
            BlobError::HashMismatch { .. } => "blob_hash_mismatch",
            BlobError::InlineSizeExceeded { .. } => "blob_inline_size_exceeded",
            BlobError::InvalidArgument(_) => "blob_invalid_argument",
            BlobError::AttestationEmissionFailed(_) => "blob_attestation_emission_failed",
            BlobError::Backend(_) => "blob_backend",
        }
    }
}

/// v2.3 (CIRISPersist#103) — compute the `holds_bytes:sha256:<prefix>`
/// attestation_type string for the given full SHA-256.
pub fn holds_bytes_attestation_type(sha256: &[u8; 32]) -> String {
    let full_hex = hex::encode(sha256);
    debug_assert!(full_hex.len() >= HOLDS_BYTES_PREFIX_HEX_LEN);
    format!(
        "{}{}",
        HOLDS_BYTES_ATTESTATION_TYPE_PREFIX,
        &full_hex[..HOLDS_BYTES_PREFIX_HEX_LEN]
    )
}

/// v2.3 (CIRISPersist#103) — compute the canonical
/// `attestation_envelope` JSON for a `holds_bytes` attestation.
///
/// Shape:
///
/// ```json
/// {
///   "kind": "holds_bytes",
///   "evidence_refs": ["<full-hex-sha256>"]
/// }
/// ```
pub fn holds_bytes_attestation_envelope(sha256: &[u8; 32]) -> serde_json::Value {
    serde_json::json!({
        "kind": "holds_bytes",
        "evidence_refs": [hex::encode(sha256)],
    })
}

/// v2.3 (CIRISPersist#103) — verify a `[u8; 32]` SHA-256 against an
/// inline byte payload. Used by [`BlobStorage::put_blob`] implementations.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) fn verify_inline_hash(expected: &[u8; 32], bytes: &[u8]) -> Result<(), BlobError> {
    use sha2::{Digest, Sha256};
    let computed = Sha256::digest(bytes);
    if computed.as_slice() == expected.as_slice() {
        Ok(())
    } else {
        Err(BlobError::HashMismatch {
            expected_hex: hex::encode(expected),
            got_hex: hex::encode(computed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_bytes_prefix_shape() {
        let sha = [0xab_u8; 32];
        let kind = holds_bytes_attestation_type(&sha);
        assert_eq!(kind, "holds_bytes:sha256:abababab");
        assert_eq!(
            kind.len(),
            HOLDS_BYTES_ATTESTATION_TYPE_PREFIX.len() + HOLDS_BYTES_PREFIX_HEX_LEN
        );
    }

    #[test]
    fn holds_bytes_envelope_shape() {
        let sha = [0x42_u8; 32];
        let env = holds_bytes_attestation_envelope(&sha);
        assert_eq!(env["kind"], "holds_bytes");
        let refs = env["evidence_refs"].as_array().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], hex::encode(sha));
    }

    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    #[test]
    fn body_storage_kind_strings() {
        assert_eq!(BlobBody::Inline(vec![1, 2, 3]).storage_kind(), "inline");
        assert_eq!(
            BlobBody::External(ExternalRef {
                uri: "s3://bucket/key".into(),
                size_bytes: 100,
                media_type: None,
            })
            .storage_kind(),
            "s3"
        );
        assert_eq!(
            BlobBody::External(ExternalRef {
                uri: "https://example.com/blob.bin".into(),
                size_bytes: 100,
                media_type: None,
            })
            .storage_kind(),
            "external_url"
        );
    }

    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    #[test]
    fn verify_inline_hash_round_trip() {
        use sha2::Digest;
        let bytes = b"hello world";
        let expected = sha2::Sha256::digest(bytes);
        let mut expected_arr = [0u8; 32];
        expected_arr.copy_from_slice(&expected);

        verify_inline_hash(&expected_arr, bytes).expect("matching hash");

        let mut wrong = expected_arr;
        wrong[0] ^= 0xff;
        let err = verify_inline_hash(&wrong, bytes).expect_err("mismatch");
        assert!(matches!(err, BlobError::HashMismatch { .. }));
        assert_eq!(err.kind(), "blob_hash_mismatch");
    }
}
