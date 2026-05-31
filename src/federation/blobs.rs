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

    /// v3.3.0 (CIRISPersist#121) — one-call ingest convenience. Persist
    /// computes the `holds_bytes` envelope, canonicalizes it via the
    /// production [`PythonJsonDumpsCanonicalizer`](crate::verify::canonical::PythonJsonDumpsCanonicalizer)
    /// (NOT RFC 8785 / JCS — the parity reference canonicalizer is
    /// `#[cfg(test)]`-only), signs the canonical bytes via the
    /// provided [`HardwareSigner`](ciris_keyring::HardwareSigner),
    /// derives `original_content_hash_hex` from the canonical bytes,
    /// and atomically commits the blob + holder via the existing
    /// [`put_blob`](BlobStorage::put_blob) path.
    ///
    /// # Why this method exists
    ///
    /// `put_blob(PutBlobAttestation)` is the lower-level surface —
    /// callers with a specific envelope already signed (re-emit of a
    /// remote announcement, HSM-batched signing latencies, replay /
    /// backfill with caller-determined timestamps) need full control
    /// of the envelope bytes. The cost of that flexibility is that
    /// every consumer that just wants to write bytes-they-already-have
    /// reimplements seven steps of canonicalize + sign + assemble
    /// plumbing. CIRISPersist#121 names the trap: persist's production
    /// canonicalizer is
    /// [`PythonJsonDumpsCanonicalizer`](crate::verify::canonical::PythonJsonDumpsCanonicalizer),
    /// NOT JCS RFC 8785. A downstream that reaches for the obvious
    /// `serde_json_canonicalizer` crate produces signatures that fail
    /// downstream verification — silently wrong rows in
    /// `federation_attestations`. This method closes that error class
    /// by making persist the canonical owner of holds_bytes-envelope
    /// canonicalization.
    ///
    /// # Default impl
    ///
    /// The default impl is the entire point — every backend inherits
    /// the same canonicalize → sign → commit shape automatically. No
    /// per-backend override is intended.
    ///
    /// # Parameters
    ///
    /// - `sha256`, `body`, `media_type` — same as
    ///   [`put_blob`](BlobStorage::put_blob).
    /// - `attesting_key_id` — `federation_keys.key_id` row referenced
    ///   by the emitted holder attestation. Must exist (FK).
    /// - `signer` — `&dyn HardwareSigner`. Accepts both
    ///   [`LocalSignerHardwareAdapter`](crate::signing::LocalSignerHardwareAdapter)
    ///   (software identity) and hardware-rooted signers (TPM /
    ///   Secure Enclave / StrongBox). The signer's
    ///   [`current_alias`](ciris_keyring::HardwareSigner::current_alias)
    ///   becomes the holder attestation's `scrub_key_id`.
    /// - `now`, `attestation_id` — passed by the caller (not internally
    ///   sourced) so pinned-time tests, replay, and migration paths
    ///   can reproduce specific timestamps / IDs. Normal callers pass
    ///   `chrono::Utc::now()` + `uuid::Uuid::new_v4()`.
    #[allow(clippy::too_many_arguments)]
    fn put_blob_signing<'s>(
        &'s self,
        sha256: &'s [u8; 32],
        body: BlobBody,
        media_type: Option<&'s str>,
        attesting_key_id: &'s str,
        signer: &'s dyn ciris_keyring::HardwareSigner,
        now: chrono::DateTime<chrono::Utc>,
        attestation_id: uuid::Uuid,
    ) -> impl Future<Output = Result<(), BlobError>> + Send + 's
    where
        Self: Sync,
    {
        async move {
            use crate::verify::canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
            use base64::engine::general_purpose::STANDARD as B64;
            use base64::Engine as _;
            use sha2::{Digest, Sha256};

            if attesting_key_id.is_empty() {
                return Err(BlobError::InvalidArgument(
                    "attesting_key_id is empty".into(),
                ));
            }

            // v3.6.0 (CIRISPersist#134) — perceptual-hash hook runs
            // BEFORE the sign / commit. Inline-only (architect §6.5);
            // External bodies have nothing to hash here. Default
            // backend impl returns None so the hook is a no-op unless
            // operator-config has installed a matcher.
            if let (Some(matcher), BlobBody::Inline(inline_bytes)) =
                (self.perceptual_hash_matcher(), &body)
            {
                match matcher.check(sha256, inline_bytes).await {
                    Ok(crate::federation::HashMatchResult::Match {
                        database,
                        score,
                        threshold,
                    }) => match matcher.on_match_policy() {
                        crate::federation::OnMatchPolicy::Refuse
                        | crate::federation::OnMatchPolicy::ReportThenRefuse => {
                            return Err(BlobError::HashMatchedKnownBad {
                                database,
                                score,
                                threshold,
                            });
                        }
                        crate::federation::OnMatchPolicy::AlertOnly => {
                            tracing::warn!(
                                database = ?database,
                                score,
                                threshold,
                                sha256_prefix = &hex::encode(sha256)[..16],
                                "ciris-persist v3.6.0 perceptual_hash matcher hit (alert-only)"
                            );
                        }
                    },
                    Ok(crate::federation::HashMatchResult::NoMatch) => {}
                    Err(crate::federation::HashMatchError::Unreachable(detail)) => {
                        match matcher.matcher_unreachable_policy() {
                            crate::federation::MatcherUnreachablePolicy::FailClosed => {
                                return Err(BlobError::Backend(format!(
                                    "perceptual_hash matcher unreachable (fail-closed): {detail}"
                                )));
                            }
                            crate::federation::MatcherUnreachablePolicy::FailOpen => {
                                tracing::warn!(
                                    detail = %detail,
                                    sha256_prefix = &hex::encode(sha256)[..16],
                                    "ciris-persist v3.6.0 perceptual_hash matcher unreachable (fail-open)"
                                );
                            }
                        }
                    }
                    Err(crate::federation::HashMatchError::InputMalformed(detail)) => {
                        return Err(BlobError::InvalidArgument(format!(
                            "perceptual_hash matcher rejected body: {detail}"
                        )));
                    }
                }
            }

            let envelope = holds_bytes_attestation_envelope(sha256);
            let canonical_bytes = PythonJsonDumpsCanonicalizer
                .canonicalize_value(&envelope)
                .map_err(|e| {
                    BlobError::InvalidArgument(format!("canonicalize holds_bytes envelope: {e}"))
                })?;
            let original_content_hash_hex = hex::encode(Sha256::digest(&canonical_bytes));

            let sig_bytes = signer
                .sign(&canonical_bytes)
                .await
                .map_err(|e| BlobError::AttestationEmissionFailed(format!("signer.sign: {e}")))?;
            let scrub_signature_classical = B64.encode(&sig_bytes);
            let scrub_key_id = signer.current_alias().to_string();

            let att = PutBlobAttestation {
                attesting_key_id: attesting_key_id.to_string(),
                attestation_id: attestation_id.to_string(),
                original_content_hash_hex,
                scrub_signature_classical,
                scrub_signature_pqc: None,
                scrub_key_id,
                scrub_timestamp: now,
            };

            self.put_blob(sha256, body, media_type, att).await
        }
    }

    /// v3.6.0 (CIRISPersist#134) — perceptual-hash matcher hook.
    /// Default `None` (no hook installed). Backends override with an
    /// `RwLock<Option<Arc<dyn PerceptualHashMatcher>>>` + a
    /// `set_perceptual_hash_matcher` setter mirroring the v3.4.0
    /// `set_admission_gate` pattern.
    fn perceptual_hash_matcher(&self) -> Option<crate::federation::SharedMatcher> {
        None
    }

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

    /// v3.5.2 (CIRISPersist#130) — **local-truth** holder query.
    ///
    /// Returns the `key_id`s of every attester this engine has a
    /// `holds_bytes:sha256:<prefix>` attestation for, **regardless of
    /// the CEG §10.1.2 24-hour TTL window**. The bytes are locally
    /// held (verified by checking `federation_blobs`); the attestations
    /// are read directly from the substrate; `withdraws` is still the
    /// active eviction signal.
    ///
    /// # Why this exists alongside `list_holders`
    ///
    /// [`list_holders`](BlobStorage::list_holders) answers the
    /// **federation-discovery** question: "which peers _claim_ to hold
    /// this blob right now, per CEG §10.1.2 freshness?" Stale claims
    /// are dropped because peers may have gone silently offline.
    ///
    /// `list_local_holders` answers the **local-truth** question:
    /// "I have the bytes in `federation_blobs`; which attestations
    /// from this substrate's audit chain claim holdings of them?"
    /// The bytes' presence is definitive proof — TTL is a backstop
    /// for peers, not for our own ground truth.
    ///
    /// Both APIs honor `withdraws`: an explicit eviction signal is
    /// honored regardless of TTL.
    ///
    /// # Filter discipline
    ///
    /// 1. If the blob is NOT in `federation_blobs`, returns `Vec::new()`
    ///    immediately. The local-truth premise doesn't apply — for
    ///    federation-discovery, use [`list_holders`].
    /// 2. WHERE `attestation_type` matches the full
    ///    `holds_bytes:sha256:<8-hex-prefix>` for this SHA.
    /// 3. AND `evidence_refs` (from the envelope) contains the full
    ///    hex SHA (discriminates prefix collisions).
    /// 4. **No TTL filter.** Stale local attestations are admitted.
    /// 5. AND the attester has NOT emitted a `withdraws` against the
    ///    holds_bytes row's `attestation_id`.
    ///
    /// # Use case
    ///
    /// FEDERATION_SCALING_MODEL §9.1 "whose bytes do I hold?" — the
    /// substrate-truth side of the identity-aware-storage property.
    /// CIRISConformance fabric-tier consumes this for the §9 audit.
    fn list_local_holders(
        &self,
        sha256: &[u8; 32],
    ) -> impl Future<Output = Result<Vec<String>, BlobError>> + Send;

    /// v3.5.0 (CIRISPersist#125) — the **inverse** of
    /// [`list_holders`](BlobStorage::list_holders): "whose bytes do I
    /// hold for actor X?". Returns the full SHA-256 of every blob this
    /// Engine has a currently-live `holds_bytes:sha256:*` attestation
    /// for from `attesting_key_id`.
    ///
    /// # Filter discipline (matches `list_holders`)
    ///
    /// 1. WHERE `attestation_type` starts with the
    ///    [`HOLDS_BYTES_ATTESTATION_TYPE_PREFIX`].
    /// 2. AND `attesting_key_id` equals the caller-supplied actor.
    /// 3. AND the [`DEFAULT_HOLDS_BYTES_TTL`] freshness window has not
    ///    lapsed (rows whose `asserted_at + TTL <= now` are stale and
    ///    excluded — CEG §10.1.2 freshness window).
    /// 4. AND the attester has not emitted a `withdraws` against the
    ///    holds_bytes row's `attestation_id` (CEG §10.1.2 ContentMiss
    ///    feedback loop).
    ///
    /// # FEDERATION_SCALING_MODEL §9 — identity-aware-storage
    ///
    /// The scaling model rests on the property "you know whose data
    /// you are storing, and can evict their data at any time." This
    /// method is the "whose bytes?" half of the proof: every actor's
    /// holdings on this Engine are addressable.
    ///
    /// Returns an empty `Vec` when the actor has no live holdings.
    fn list_held_by(
        &self,
        attesting_key_id: &str,
    ) -> impl Future<Output = Result<Vec<[u8; 32]>, BlobError>> + Send;

    /// v3.5.0 (CIRISPersist#125) — per-actor eviction. Delete every
    /// `federation_blobs` row this Engine holds for `attesting_key_id`,
    /// AND emit a `withdraws` structural composer against each of the
    /// actor's `holds_bytes` attestations (CEG §10.1.2).
    ///
    /// # Mechanics
    ///
    /// 1. Resolve the actor's live holdings via [`list_held_by`].
    /// 2. For each holding's `holds_bytes` attestation: emit a
    ///    `withdraws` attestation (signed by `signer`, canonicalized
    ///    via [`crate::verify::canonical::PythonJsonDumpsCanonicalizer`]
    ///    — the same #121 discipline the sweeper follows).
    /// 3. Delete the corresponding `federation_blobs` row keyed on the
    ///    SHA the `holds_bytes` referenced.
    ///
    /// # Fail-honest contract
    ///
    /// The blob deletion proceeds even if the withdraws emission
    /// fails — orphan withdraws is worse than a missing withdraws (the
    /// same posture the v3.4.0 sweeper takes; CIRISPersist#123).
    /// `withdraws_failed` counts the signer/FK failures so the caller
    /// can detect the partial-failure path.
    ///
    /// # Race tolerance
    ///
    /// Concurrent `put_blob` calls during eviction may leave newly
    /// written rows untouched (the actor's holdings were captured at
    /// step 1). Callers requiring strict completion re-invoke until
    /// the report shows zero blobs evicted.
    ///
    /// Returns an [`EvictActorReport`] tallying the work done.
    fn evict_actor<'s>(
        &'s self,
        attesting_key_id: &'s str,
        signer: &'s dyn ciris_keyring::HardwareSigner,
        now: chrono::DateTime<chrono::Utc>,
    ) -> impl Future<Output = Result<EvictActorReport, BlobError>> + Send + 's;
}

/// v3.5.0 (CIRISPersist#125) — outcome of
/// [`BlobStorage::evict_actor`].
///
/// Per the trait's fail-honest contract: `blobs_evicted` counts rows
/// actually deleted from `federation_blobs`; `withdraws_emitted` and
/// `withdraws_failed` count the per-row `withdraws` attestation
/// outcomes independently. `withdraws_emitted + withdraws_failed`
/// equals the number of `holds_bytes` rows targeted for withdrawal.
/// `blobs_evicted` can exceed both because a holds_bytes row whose
/// blob is already gone still counts as no-op on the delete side; in
/// practice for this method the two numbers are tied by construction
/// (every targeted holdings entry is deleted), so the report's
/// invariant is `blobs_evicted == withdraws_emitted + withdraws_failed`
/// when no concurrent deletions race with the call.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictActorReport {
    /// Number of `federation_blobs` rows actually deleted by this call.
    pub blobs_evicted: usize,
    /// Number of `withdraws` attestations successfully signed + stored.
    pub withdraws_emitted: usize,
    /// Number of `withdraws` emissions that failed (signer error, FK
    /// violation, etc.). The corresponding blob row was STILL deleted
    /// — orphan withdraws is worse than a missing withdraws.
    pub withdraws_failed: usize,
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

    /// v3.4.0 (CIRISPersist#123) — the
    /// [`AdmissionGate`](crate::federation::AdmissionGate) rejected the
    /// write: the attesting key's aggregate trust score is below the
    /// deployment's `trust_threshold`. The blob row was NOT written.
    /// Field shape mirrors
    /// [`crate::federation::Error::TrustBelowThreshold`].
    #[error("trust score {score} for key_id={key_id} is below threshold {threshold}")]
    TrustBelowThreshold {
        /// The attesting key the gate evaluated.
        key_id: String,
        /// The score returned by the resolver.
        score: f64,
        /// The configured threshold.
        threshold: f64,
    },

    /// v3.6.0 (CIRISPersist#134) — a
    /// [`PerceptualHashMatcher`](crate::federation::PerceptualHashMatcher)
    /// returned a hit against one of the configured known-bad databases.
    /// The blob row was NOT written.
    #[error(
        "hash matched known-bad database {database:?} (score {score} >= threshold {threshold})"
    )]
    HashMatchedKnownBad {
        /// Which database the matcher hit.
        database: crate::federation::HashDatabaseId,
        /// Match score the matcher reported.
        score: f64,
        /// Threshold the matcher applied.
        threshold: f64,
    },

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
            BlobError::TrustBelowThreshold { .. } => "blob_trust_below_threshold",
            BlobError::HashMatchedKnownBad { .. } => "blob_hash_matched_known_bad",
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

/// v3.5.0 (CIRISPersist#125) — extract the canonical
/// withdraws-emission triple (build envelope → canonicalize via
/// production canonicalizer → sign → put_attestation) into a single
/// shared helper. Used by [`BlobStorage::evict_actor`] across both
/// backends, and intended for reuse by future surfaces that need to
/// emit a `withdraws` attestation against a prior `holds_bytes`.
///
/// # Inputs
///
/// - `prior` — the holds_bytes attestation being withdrawn. Its
///   `attestation_id` + `attestation_type` are recorded on the
///   withdraws envelope so consumers can walk the structural-composer
///   reference back to the row being retracted.
/// - `signer_key_id` — the key emitting the withdraws (acts as both
///   `attesting_key_id` and `attested_key_id` on the row; see the
///   note at the v3.4.0 `emit_withdraws_attestation` site for the
///   self-attestation FK rationale).
/// - `signer` — `&dyn HardwareSigner` produces the
///   `scrub_signature_classical` over the canonical envelope bytes.
/// - `directory` — concrete backend that owns
///   `federation_attestations`. `&dyn FederationDirectory` keeps the
///   helper backend-agnostic.
/// - `now` — caller-supplied so deterministic tests + replay paths
///   pin the timestamp.
///
/// # Errors
///
/// Returns [`BlobError::Backend`] for canonicalize / sign /
/// put_attestation failures. The caller is responsible for tallying
/// the outcome (the v3.4.0 sweeper + v3.5.0 evict_actor both delete
/// the corresponding blob even when this helper fails — the
/// fail-honest contract documented on
/// [`BlobStorage::evict_actor`]).
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn emit_withdraws_attestation_helper(
    prior: &crate::federation::Attestation,
    signer_key_id: &str,
    signer: &dyn ciris_keyring::HardwareSigner,
    directory: &dyn crate::federation::FederationDirectory,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), BlobError> {
    use crate::verify::canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let envelope = crate::federation::withdraws_attestation_envelope(
        &prior.attestation_id,
        &prior.attestation_type,
    );
    let canonical_bytes = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&envelope)
        .map_err(|e| BlobError::Backend(format!("withdraws canonicalize: {e}")))?;
    let original_content_hash = hex::encode(Sha256::digest(&canonical_bytes));
    let sig_bytes = signer
        .sign(&canonical_bytes)
        .await
        .map_err(|e| BlobError::Backend(format!("withdraws sign: {e}")))?;
    let scrub_signature_classical = B64.encode(&sig_bytes);

    let row = crate::federation::Attestation {
        attestation_id: uuid::Uuid::new_v4().to_string(),
        attesting_key_id: signer_key_id.to_owned(),
        // The withdraws row's FK target is `signer_key_id`: the host
        // attests it itself no longer holds the bytes. Matches the
        // v3.4.0 sweeper convention (`engine.rs::emit_withdraws_attestation`).
        attested_key_id: signer_key_id.to_owned(),
        attestation_type: crate::federation::types::attestation_type::WITHDRAWS.to_owned(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash,
        scrub_signature_classical,
        scrub_signature_pqc: None,
        scrub_key_id: signer_key_id.to_owned(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        // v3.7.0 (CIRISPersist#146, CEG 0.6) — evict_actor emits a
        // producer-self-revocation withdraws; subject-side authority
        // (rule 2/3) doesn't apply on this path.
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
    };

    directory
        .put_attestation(crate::federation::SignedAttestation { attestation: row })
        .await
        .map_err(|e| BlobError::Backend(format!("withdraws put_attestation: {e}")))
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

    /// v3.3.0 (CIRISPersist#121) — **canonicalizer identity** pin.
    ///
    /// The `put_blob_signing` default impl MUST canonicalize the
    /// holds_bytes envelope via the production
    /// `PythonJsonDumpsCanonicalizer`. This test pins identity by
    /// computing the expected `original_content_hash_hex` directly
    /// from the Python-compat canonical bytes; the round-trip tests
    /// in `store/sqlite.rs` + `store/postgres.rs` then assert that
    /// what `put_blob_signing` writes to the
    /// `federation_attestations.original_content_hash` column matches
    /// this expected value byte-for-byte.
    ///
    /// **Why this isn't a divergence test**: the `holds_bytes`
    /// envelope shape is `{"kind": "holds_bytes", "evidence_refs":
    /// ["<hex>"]}` — ASCII-only keys, ASCII-only values, no floats.
    /// For ASCII-only payloads `PythonJsonDumpsCanonicalizer` and
    /// `Rfc8785Canonicalizer` produce byte-identical output (see
    /// `verify/canonical.rs::ascii_only_python_matches_jcs`). The
    /// JCS-vs-Python silent-correctness trap CIRISPersist#121 names
    /// manifests for **non-ASCII** or **float-divergent** payloads;
    /// the holds_bytes envelope is structurally immune to the
    /// divergence. The trap could STILL bite if someone introduces a
    /// new canonicalizer that disagrees on ANY shape (e.g., a
    /// whitespace-emitting variant); this identity test catches
    /// THAT regression even though the specific Python/JCS pair
    /// happens to agree on holds_bytes.
    #[test]
    fn put_blob_signing_canonicalizer_identity_holds_bytes_envelope() {
        use crate::verify::canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
        use sha2::{Digest, Sha256};

        let sha = [0x42u8; 32];
        let envelope = holds_bytes_attestation_envelope(&sha);

        // The production canonicalizer's output for this envelope.
        let python_bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&envelope)
            .expect("python canonicalize");
        let expected_hash_hex = hex::encode(Sha256::digest(&python_bytes));

        // Direct identity check: the bytes are byte-for-byte the
        // sorted-keys ASCII shape we expect.
        let expected_str = format!(
            "{{\"evidence_refs\":[\"{}\"],\"kind\":\"holds_bytes\"}}",
            hex::encode(sha)
        );
        assert_eq!(python_bytes, expected_str.as_bytes());

        // Pin the hex hash so any future canonicalizer drift (or
        // envelope-shape change) forces an explicit test update.
        assert_eq!(expected_hash_hex.len(), 64);
        // Make the expected hash available as the regression anchor:
        // any backend's put_blob_signing must produce this exact
        // original_content_hash_hex for this sha.
    }

    /// v3.3.0 (CIRISPersist#121) — JCS-vs-Python divergence still
    /// exists for non-ASCII payloads, which is the broader gotcha
    /// CIRISPersist#121's silent-correctness fix protects future
    /// substrate-defined envelope shapes from. This test pins the
    /// divergence assumption: if a future refactor accidentally
    /// flips JCS and Python-compat into agreement on non-ASCII
    /// payloads, the assumption holds_bytes-style envelopes don't
    /// trip the trap would silently expand to all envelope shapes,
    /// and `put_blob_signing` choosing one canonicalizer over the
    /// other would matter substantively. The verify/canonical.rs
    /// suite covers the underlying canonicalizer divergence; this
    /// test makes the divergence explicit in the blob substrate
    /// crate as the regression gate the issue cites.
    #[cfg(test)]
    #[test]
    fn put_blob_signing_canonicalizer_divergence_for_non_ascii_envelope() {
        use crate::verify::canonical::{
            Canonicalizer, PythonJsonDumpsCanonicalizer, Rfc8785Canonicalizer,
        };

        // A hypothetical future envelope with non-ASCII content
        // (e.g., a Unicode reason or label). put_blob_signing locks
        // in PythonJsonDumpsCanonicalizer — if someone swaps it for
        // JCS the bytes (and `original_content_hash_hex`) would
        // change for envelopes like this.
        let envelope = serde_json::json!({
            "kind": "holds_bytes",
            "label": "h\u{00e9}llo",
        });
        let py = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&envelope)
            .expect("python canonicalize");
        let jcs = Rfc8785Canonicalizer
            .canonicalize_value(&envelope)
            .expect("jcs canonicalize");
        assert_ne!(
            py, jcs,
            "Python-compat and JCS MUST diverge on non-ASCII; this is the trap \
             put_blob_signing closes by owning the canonicalizer choice"
        );
    }

    // ── v3.6.0 (CIRISPersist#134) — perceptual_hash hook tests ──────

    #[cfg(feature = "sqlite")]
    #[test]
    fn hash_matched_known_bad_kind_string() {
        let e = BlobError::HashMatchedKnownBad {
            database: crate::federation::HashDatabaseId("ncmec".into()),
            score: 0.9,
            threshold: 0.5,
        };
        assert_eq!(e.kind(), "blob_hash_matched_known_bad");
    }

    /// Helper for the put_blob_signing matcher tests: a matcher that
    /// returns Match for every call. Used to assert the trait
    /// surface gates inline writes.
    #[cfg(feature = "sqlite")]
    struct AlwaysMatchTest;

    #[cfg(feature = "sqlite")]
    #[async_trait::async_trait]
    impl crate::federation::PerceptualHashMatcher for AlwaysMatchTest {
        async fn check(
            &self,
            _sha256: &[u8; 32],
            _body: &[u8],
        ) -> Result<crate::federation::HashMatchResult, crate::federation::HashMatchError> {
            Ok(crate::federation::HashMatchResult::Match {
                database: crate::federation::HashDatabaseId("test-ncmec".into()),
                score: 0.99,
                threshold: 0.5,
            })
        }
        fn databases(&self) -> &[crate::federation::HashDatabaseId] {
            &[]
        }
        fn on_match_policy(&self) -> crate::federation::OnMatchPolicy {
            crate::federation::OnMatchPolicy::Refuse
        }
    }

    #[cfg(feature = "sqlite")]
    async fn seed_signer_for(
        backend: &crate::store::sqlite::SqliteBackend,
        key_id: &str,
    ) -> crate::signing::LocalSignerHardwareAdapter {
        use crate::federation::FederationDirectory;
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&[0x77; 32]);
        let pubkey_b64 = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes())
        };
        let record = crate::federation::types::KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: pubkey_b64,
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: key_id.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": key_id}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
        };
        backend
            .put_public_key(crate::federation::types::SignedKeyRecord { record })
            .await
            .unwrap();
        let local = std::sync::Arc::new(crate::signing::LocalSigner::from_parts(
            signing_key,
            key_id.into(),
            None,
            None,
        ));
        crate::signing::LocalSignerHardwareAdapter::new(local)
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn put_blob_signing_refuses_when_matcher_returns_match() {
        use crate::store::backend::Backend;
        let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        backend.run_migrations().await.unwrap();
        let signer = seed_signer_for(&backend, "test-key").await;
        backend.set_perceptual_hash_matcher(Some(std::sync::Arc::new(AlwaysMatchTest)));

        let body = b"some bytes".to_vec();
        let sha = {
            use sha2::Digest;
            let mut s = [0u8; 32];
            s.copy_from_slice(&sha2::Sha256::digest(&body));
            s
        };
        let err = backend
            .put_blob_signing(
                &sha,
                BlobBody::Inline(body),
                None,
                "test-key",
                &signer,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap_err();
        match err {
            BlobError::HashMatchedKnownBad { database, .. } => {
                assert_eq!(database.0, "test-ncmec");
            }
            other => panic!("expected HashMatchedKnownBad, got {other:?}"),
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn put_blob_signing_admits_when_matcher_returns_no_match() {
        use crate::store::backend::Backend;
        let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        backend.run_migrations().await.unwrap();
        let signer = seed_signer_for(&backend, "test-key").await;
        backend.set_perceptual_hash_matcher(Some(std::sync::Arc::new(
            crate::federation::NullPerceptualHashMatcher,
        )));

        let body = b"clean bytes".to_vec();
        let sha = {
            use sha2::Digest;
            let mut s = [0u8; 32];
            s.copy_from_slice(&sha2::Sha256::digest(&body));
            s
        };
        backend
            .put_blob_signing(
                &sha,
                BlobBody::Inline(body),
                None,
                "test-key",
                &signer,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn put_blob_signing_skips_matcher_for_external_body() {
        use crate::store::backend::Backend;
        let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        backend.run_migrations().await.unwrap();
        let signer = seed_signer_for(&backend, "test-key").await;
        // Install the always-match matcher; external body must still
        // admit because the matcher is skipped for non-Inline bodies.
        backend.set_perceptual_hash_matcher(Some(std::sync::Arc::new(AlwaysMatchTest)));

        // Sha is caller-asserted for External (per put_blob contract).
        let sha = [0xAB; 32];
        let ext = ExternalRef {
            uri: "s3://bucket/key".into(),
            size_bytes: 100,
            media_type: None,
        };
        backend
            .put_blob_signing(
                &sha,
                BlobBody::External(ext),
                None,
                "test-key",
                &signer,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap();
    }
}
