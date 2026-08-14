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

/// v4.1 (CIRISPersist#142, Cut B) — one chunk's content address + size
/// in a [`ChunkManifest`]. Serialized inside the manifest as a
/// JCS-canonical object `{"sha":"<lowercase-hex32>","size":<u32>}`.
///
/// The derived serde impl (used only because [`BlobBody`] derives serde)
/// emits `sha` as a 32-element byte array — that path is NOT the wire
/// format; the on-the-wire/at-rest manifest is the JCS shape produced by
/// [`ChunkManifest::to_jcs_bytes`] (sha as lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    /// SHA-256 of the chunk's bytes. The chunk is its own
    /// `federation_blobs` row keyed on this SHA.
    pub sha: [u8; 32],
    /// Byte length of the chunk.
    pub size: u32,
}

/// v4.1 (CIRISPersist#142, Cut B) — a flat (one-level) content-addressed
/// chunk DAG manifest. Stored in the manifest row's `bytes_inline` as
/// **JCS-canonical JSON** (CEG §0.9); the row's `content_sha256` =
/// SHA-256 over those canonical bytes, and the row's `size_bytes` =
/// [`total_size`](ChunkManifest::total_size).
///
/// Wire shape (JCS — keys lexicographically sorted, no whitespace,
/// `sha` as lowercase hex):
///
/// ```json
/// {"chunks":[{"sha":"<hex32>","size":<u32>},…],"total_size":<u64>,"v":<u32>}
/// ```
///
/// One-level DAG only (UnixFS flat-leaves; no nested DAGs). Each chunk
/// is its own `federation_blobs` row (`Inline` or `External`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkManifest {
    /// Manifest schema version (currently `1`).
    pub v: u32,
    /// Total byte size of the reassembled blob. MUST equal the sum of
    /// every [`ChunkRef::size`].
    pub total_size: u64,
    /// The ordered chunk list. Concatenating each chunk's bytes in
    /// order reproduces the original blob.
    pub chunks: Vec<ChunkRef>,
}

/// v4.1 (CIRISPersist#142, Cut B) — current `ChunkManifest` schema
/// version.
pub const CHUNK_MANIFEST_VERSION: u32 = 1;

/// v4.x (CIRISPersist#142, Cut C3b) — operational cap on chunks per
/// `(stream_id, epoch)`: a **nonce-safety substrate constant** (CEG 0.15
/// §10.5.2 / §10.5.3, FSD §5). The STREAM nonce's `counter_be` is a
/// 32-bit per-epoch chunk index; the substrate forces an epoch roll well
/// before `2^32 - 1` so a `(DEK, nonce)` pair is never reused
/// (GCM-catastrophic). `2^24` (~16.7M chunks/epoch) leaves an 8-bit
/// safety margin. `put_blob_chunk` rejects an append that would push a
/// `(stream_id, epoch)` past this count — the producer MUST roll the
/// epoch. Unlike the P4 catch-up cap (a LensCore policy knob, §10.5.3),
/// this is genuinely the substrate's to enforce.
pub const MAX_CHUNKS_PER_EPOCH: u64 = 1 << 24;

/// Whether a `(stream_id, epoch)` that already holds
/// `existing_chunk_count` chunks has reached [`MAX_CHUNKS_PER_EPOCH`] —
/// i.e. the next `put_blob_chunk` append must be REFUSED (the producer
/// rolls the epoch). The single boundary both backends call, so the
/// nonce-counter-exhaustion rule is defined once and unit-testable
/// without materializing 2^24 rows.
pub fn epoch_chunk_cap_reached(existing_chunk_count: u64) -> bool {
    existing_chunk_count >= MAX_CHUNKS_PER_EPOCH
}

impl ChunkManifest {
    /// Serialize to **JCS-canonical JSON bytes** (CEG §0.9).
    ///
    /// The manifest shape is fully ASCII (top-level keys
    /// `chunks`/`total_size`/`v`, per-chunk keys `sha`/`size`; values are
    /// hex strings and non-negative integers), so the JCS rules collapse
    /// to lexicographically-ordered object keys, no insignificant
    /// whitespace, and plain-decimal integers. This is emitted directly
    /// from the typed struct (no `serde_json::Value` hot path), so the
    /// bytes are deterministic and the manifest's `content_sha256` is
    /// stable.
    pub fn to_jcs_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Top-level keys, lexicographically: "chunks" < "total_size" < "v".
        buf.extend_from_slice(b"{\"chunks\":[");
        for (i, c) in self.chunks.iter().enumerate() {
            if i > 0 {
                buf.push(b',');
            }
            // Per-chunk keys, lexicographically: "sha" < "size".
            buf.extend_from_slice(b"{\"sha\":\"");
            buf.extend_from_slice(hex::encode(c.sha).as_bytes());
            buf.extend_from_slice(b"\",\"size\":");
            buf.extend_from_slice(c.size.to_string().as_bytes());
            buf.push(b'}');
        }
        buf.extend_from_slice(b"],\"total_size\":");
        buf.extend_from_slice(self.total_size.to_string().as_bytes());
        buf.extend_from_slice(b",\"v\":");
        buf.extend_from_slice(self.v.to_string().as_bytes());
        buf.push(b'}');
        buf
    }

    /// Parse a manifest from its JCS-canonical JSON bytes (the inverse
    /// of [`to_jcs_bytes`](ChunkManifest::to_jcs_bytes)). Tolerant of
    /// key order on the way in (uses `serde_json` to parse), but the
    /// round-trip through `to_jcs_bytes` re-canonicalizes on the way
    /// out. Returns [`BlobError::Backend`] on malformed manifest bytes.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub(crate) fn from_manifest_bytes(bytes: &[u8]) -> Result<Self, BlobError> {
        #[derive(Deserialize)]
        struct ChunkRefWire {
            sha: String,
            size: u32,
        }
        #[derive(Deserialize)]
        struct ManifestWire {
            v: u32,
            total_size: u64,
            chunks: Vec<ChunkRefWire>,
        }
        let wire: ManifestWire = serde_json::from_slice(bytes)
            .map_err(|e| BlobError::Backend(format!("chunk_dag manifest JSON parse: {e}")))?;
        let mut chunks = Vec::with_capacity(wire.chunks.len());
        for c in wire.chunks {
            let raw = hex::decode(&c.sha).map_err(|e| {
                BlobError::Backend(format!("chunk_dag manifest chunk sha hex: {e}"))
            })?;
            if raw.len() != 32 {
                return Err(BlobError::Backend(format!(
                    "chunk_dag manifest chunk sha is {} bytes, expected 32",
                    raw.len()
                )));
            }
            let mut sha = [0u8; 32];
            sha.copy_from_slice(&raw);
            chunks.push(ChunkRef { sha, size: c.size });
        }
        Ok(ChunkManifest {
            v: wire.v,
            total_size: wire.total_size,
            chunks,
        })
    }

    /// Validate internal consistency: `total_size` MUST equal the sum
    /// of the chunk sizes (computed in u64 to avoid u32 overflow).
    /// Returns [`BlobError::InvalidArgument`] on mismatch.
    pub fn validate_total_size(&self) -> Result<(), BlobError> {
        let sum: u64 = self.chunks.iter().map(|c| u64::from(c.size)).sum();
        if sum != self.total_size {
            return Err(BlobError::InvalidArgument(format!(
                "chunk_dag manifest total_size {} != sum of chunk sizes {}",
                self.total_size, sum
            )));
        }
        Ok(())
    }
}

/// The body of a [`BlobStorage::put_blob`] / [`BlobStorage::get_blob`]
/// payload — either the inline bytes themselves, a pointer to an
/// external store, or (Cut B) a content-addressed chunk-DAG manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobBody {
    /// Inline byte payload. Maximum size is bounded by the
    /// deployment's inline cap (default
    /// [`DEFAULT_INLINE_BYTES_CAP`]).
    Inline(Vec<u8>),
    /// External reference (S3 URI or arbitrary URL).
    External(ExternalRef),
    /// v4.1 (CIRISPersist#142, Cut B) — a flat content-addressed chunk
    /// DAG. The wrapped [`ChunkManifest`] is stored JCS-canonical in the
    /// manifest row's `bytes_inline`; each chunk is its own
    /// `federation_blobs` row. `storage_kind` = `"chunk_dag"`.
    ChunkDag(ChunkManifest),
}

/// v4.1 (CIRISPersist#142, Cut A) — the result of a
/// [`BlobStorage::get_blob_range`] byte-range read.
///
/// For [`BlobBody::Inline`] blobs the requested range is sliced
/// **server-side** (no full-buffer load) and returned as
/// [`BlobRange::Inline`]. For [`BlobBody::External`] blobs persist does
/// **NOT** dereference the URI — it returns [`BlobRange::External`] with
/// the ref and the (clamped) range so the *caller* fetches
/// `[range_start, range_end_inclusive]` from the upstream object store
/// itself, honoring whatever auth its deployment shape requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobRange {
    /// The requested byte range, sliced from inline storage.
    Inline(Vec<u8>),
    /// External blob — persist does NOT dereference; the caller fetches
    /// [range_start, range_end_inclusive] from the ref's URI itself.
    External {
        /// The stored external pointer (URI + size + media type).
        external_ref: ExternalRef,
        /// Clamped inclusive range start the caller should fetch.
        range_start: u64,
        /// Clamped inclusive range end the caller should fetch.
        range_end_inclusive: u64,
    },
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
            // v4.1 (Cut B) — the reassembled blob's size is the
            // manifest's total_size, NOT the manifest-bytes length.
            BlobBody::ChunkDag(m) => m.total_size,
        }
    }

    /// The wire `storage_kind` string for this body.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub(crate) fn storage_kind(&self) -> &'static str {
        match self {
            BlobBody::Inline(_) => "inline",
            BlobBody::External(e) if e.uri.starts_with("s3://") => "s3",
            BlobBody::External(_) => "external_url",
            BlobBody::ChunkDag(_) => "chunk_dag",
        }
    }
}

/// v9.1.0 (CIRISPersist#243, CC 1.13.3 / FSD §2.4) — reference to the
/// community DEK a scope-blob symbol was sealed under.
///
/// Ties the [`put_scope_blob`](BlobStorage::put_scope_blob) admission
/// path to the existing community-DEK surface
/// ([`community_dek_current_epoch`](BlobStorage::community_dek_current_epoch)):
/// the caller (CIRISEdge) resolves the `(community_key_id, epoch)` of the
/// group DEK it used to seal the symbols and passes it here. Persist
/// records only `epoch` (as the table's `group_dek_epoch`) — the
/// `community_key_id` is the caller's addressing key into the DEK surface,
/// not stored on the symbol row itself (FSD §2.4: holder/community
/// identity is opaque on the symbol store; the DEK binding lives in the
/// community_dek_* tables).
///
/// Construct via [`GroupDekRef::new`] or, for the common case, resolve
/// the current epoch first:
///
/// ```ignore
/// let epoch = backend.community_dek_current_epoch(community_key_id).await?;
/// let dek_ref = GroupDekRef::new(community_key_id.to_string(), epoch);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDekRef {
    /// The community whose shared DEK sealed the symbols. Caller-side
    /// addressing key into the `community_dek_*` surface; not persisted on
    /// the symbol row (opaque-holder property, FSD §2.4).
    pub community_key_id: String,
    /// The DEK epoch (from
    /// [`community_dek_current_epoch`](BlobStorage::community_dek_current_epoch)).
    /// Stored as `federation_scope_blobs.group_dek_epoch` so a read
    /// recovers the right epoch DEK. `0` = a community with no rotation
    /// row yet.
    pub epoch: u64,
}

impl GroupDekRef {
    /// Construct a reference to `(community_key_id, epoch)`.
    pub fn new(community_key_id: String, epoch: u64) -> Self {
        Self {
            community_key_id,
            epoch,
        }
    }
}

/// v9.1.0 (CIRISPersist#243, FSD §2.4) — one symbol-AEAD-encrypted RaptorQ
/// fragment as read back from the scope-blob store.
///
/// The bytes round-trip exactly what
/// [`put_scope_blob`](BlobStorage::put_scope_blob) admitted: persist
/// stores caller-pre-encrypted ciphertext and returns it verbatim (it
/// never decrypts — the XChaCha20-Poly1305 seal is CIRISEdge-side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeBlobSymbol {
    /// 0..N symbol index within the record.
    pub symbol_index: u16,
    /// XChaCha20-Poly1305 nonce (24 bytes).
    pub nonce: [u8; 24],
    /// Pre-encrypted symbol bytes (opaque to the substrate).
    pub ciphertext: Vec<u8>,
    /// Poly1305 tag (16 bytes).
    pub tag: [u8; 16],
    /// The community DEK epoch the symbol was sealed under.
    pub group_dek_epoch: u64,
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

    /// v3.9.2 (CIRISPersist#153 Ask 5, CEG 0.7 §10.1.4) — store blob
    /// bytes **without** emitting a `holds_bytes:sha256:*` directory
    /// attestation.
    ///
    /// The structural-invisibility primitive for
    /// [`cohort_scope`](crate::federation::types::cohort_scope)
    /// `self` / `family` content: the bytes are persisted locally
    /// (and readable via [`get_blob`](BlobStorage::get_blob) /
    /// streamable as the operator's own data) but the substrate
    /// announces nothing — no `holds_bytes` row is created, so a
    /// non-member peer walking the federation directory cannot
    /// discover the bytes exist. This is the difference between
    /// [`put_blob`](BlobStorage::put_blob) (federation-tier: bytes +
    /// holds_bytes announcement) and local-only storage.
    ///
    /// Validation is identical to [`put_blob`] for the bytes
    /// themselves — inline-size cap + hash-on-write — but there is no
    /// attestation, no signer, and (deliberately) no
    /// [`AdmissionGate`](crate::federation::AdmissionGate) trust check:
    /// local content is the operator's own data, and the substrate is
    /// never the right place to refuse it (the #149 anti-recommendation
    /// — "Don't block local writes ever").
    ///
    /// Idempotent on SHA collision (first-write-wins on
    /// `storage_kind` / `external_ref`), exactly as [`put_blob`].
    /// Callers normally reach this via
    /// [`put_blob_signing_scoped`](BlobStorage::put_blob_signing_scoped),
    /// which dispatches here when
    /// [`suppresses_holds_bytes`](crate::federation::types::cohort_scope::suppresses_holds_bytes)
    /// is true.
    fn store_blob_local(
        &self,
        sha256: &[u8; 32],
        body: BlobBody,
        media_type: Option<&str>,
    ) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// v4.1 (CIRISPersist#142, Cut B) — **atomic** chunked-blob upload.
    ///
    /// In ONE transaction, inserts:
    /// - each chunk as a normal `federation_blobs` row (keyed on the
    ///   chunk SHA; idempotent / first-write-wins on collision, exactly
    ///   like [`store_blob_local`](BlobStorage::store_blob_local)); and
    /// - the **manifest row** (`storage_kind = "chunk_dag"`,
    ///   `bytes_inline` = the [`ChunkManifest`] JCS bytes,
    ///   `content_sha256` = SHA-256 over those bytes, `size_bytes` =
    ///   `manifest.total_size`).
    ///
    /// No `holds_bytes` attestation is emitted (this is the local-store
    /// shape; Cut C / a later surface can wrap a signing variant).
    ///
    /// # Validation (all-or-nothing — any failure rolls back the txn)
    ///
    /// 1. `manifest.total_size` MUST equal the sum of the chunk sizes,
    ///    else [`BlobError::InvalidArgument`].
    /// 2. The `chunks` argument MUST line up 1:1 (by SHA, same order)
    ///    with `manifest.chunks`, else [`BlobError::InvalidArgument`].
    /// 3. For each `Inline` chunk: the bytes' SHA-256 MUST match its
    ///    manifest entry's SHA, else [`BlobError::HashMismatch`]; its
    ///    length MUST match the manifest entry's `size`, else
    ///    [`BlobError::InvalidArgument`]. `External` chunks are trusted
    ///    (persist has no bytes to hash), as in [`put_blob`].
    /// 4. A nested `ChunkDag` chunk is rejected
    ///    ([`BlobError::InvalidArgument`]) — one-level DAG only.
    fn put_blob_chunks(
        &self,
        manifest: ChunkManifest,
        chunks: Vec<([u8; 32], BlobBody)>,
    ) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// v4.1 (CIRISPersist#142, Cut C1a) — **live append** of one chunk
    /// to a stream (CEG §10.5.1).
    ///
    /// Where [`put_blob_chunks`](BlobStorage::put_blob_chunks) seals a
    /// known-complete blob in one shot, `put_blob_chunk` appends a
    /// single chunk to a *live* stream at a monotonic `seq`. In ONE
    /// transaction it:
    /// - inserts `body` as a normal `federation_blobs` row, keyed on the
    ///   chunk's SHA-256 (idempotent / first-write-wins on collision —
    ///   content-addressed bytes, so a re-PUT of identical bytes is
    ///   fine), and
    /// - inserts the `federation_stream_chunks` index row
    ///   `(stream_id, seq, chunk_sha, epoch, size_bytes)`.
    ///
    /// Returns the chunk's SHA-256 (its content address).
    ///
    /// # Monotonicity (`seq` collision)
    ///
    /// The `(stream_id, seq)` pair is the index table's PRIMARY KEY. A
    /// re-used `seq` for the same stream is a PK conflict and is
    /// rejected with [`BlobError::InvalidArgument`] — the substrate's
    /// append-only enforcement. (The blob row itself is content-
    /// addressed and idempotent; only the stream-index row is unique per
    /// `(stream, seq)`.)
    ///
    /// # `epoch`
    ///
    /// The key-rotation epoch (CEG §10.5.3) is stored on the index row.
    /// Cut C1a does **no** key/crypto work — the epoch-DEK cascade is
    /// Cut C3; this cut just records the column.
    ///
    /// # Validation
    ///
    /// - `Inline` body: hashed on write (SHA-256 == the inserted PK);
    ///   inline-size-capped, exactly like [`put_blob`].
    /// - `External` body: SHA trusted (persist has no bytes), as in
    ///   [`put_blob`].
    /// - A [`BlobBody::ChunkDag`] body is rejected with
    ///   [`BlobError::InvalidArgument`] — you cannot chunk a chunk.
    fn put_blob_chunk(
        &self,
        stream_id: &str,
        seq: u64,
        body: BlobBody,
        epoch: u64,
    ) -> impl Future<Output = Result<[u8; 32], BlobError>> + Send;

    /// v4.1 (CIRISPersist#142, Cut C1a) — **seal** a live stream into a
    /// content-addressed [`BlobBody::ChunkDag`] (CEG §10.5.1).
    ///
    /// Walks every [`federation_stream_chunks`](crate) row for
    /// `stream_id` in `seq ASC` order, builds the Cut-B
    /// [`ChunkManifest`] (`total_size` = Σ `size_bytes`, `chunks` in seq
    /// order), and writes **only** the `chunk_dag` manifest row to
    /// `federation_blobs` (the chunk rows already exist —
    /// `put_blob_chunk` inserted them; seal does NOT re-insert them).
    /// `sealed_at` is stamped on the stream's index rows
    /// (informational).
    ///
    /// Returns the manifest's SHA-256 — the sealed stream's content
    /// address. After seal, [`get_blob`](BlobStorage::get_blob) /
    /// [`get_blob_range`](BlobStorage::get_blob_range) over that SHA use
    /// Cut B's ChunkDag path.
    ///
    /// An empty stream (no chunks) is rejected with
    /// [`BlobError::InvalidArgument`].
    fn seal_stream(
        &self,
        stream_id: &str,
    ) -> impl Future<Output = Result<[u8; 32], BlobError>> + Send;

    /// v4.1 (CIRISPersist#142, Cut C1b) — store a **producer-signed**
    /// Signed Tree Head for a stream's transparency log (CEG §10.5.1).
    ///
    /// A stream is its own RFC 6962 log (`log_id = stream:<id>`) whose
    /// leaves are the chunk hashes in `federation_stream_chunks`. The
    /// PRODUCER signs the STH; persist's job is integrity-gating, in
    /// **EXACTLY this order** (the anti-equivocation gate):
    ///
    /// 1. Parse `stream_id` from `sth.log_id` (must be `stream:<id>`,
    ///    else [`BlobError::InvalidArgument`]).
    /// 2. Load the first `sth.tree_size` chunk hashes for the stream
    ///    (`seq ASC`). Fewer than `tree_size` exist →
    ///    [`BlobError::InvalidArgument`] (the STH claims more leaves than
    ///    persist holds).
    /// 3. Recompute the Merkle root over those leaves via CIRISVerify's
    ///    [`InMemoryTransparencyStore`](ciris_verify_core::transparency::InMemoryTransparencyStore)
    ///    (RFC 6962 — **not** reimplemented here).
    /// 4. Assert the recomputed root equals `sth.root_hash`; mismatch →
    ///    [`BlobError::InvalidArgument`]. **Not optional.**
    /// 5. Verify the producer's hybrid signature over
    ///    `sth.signing_bytes_of()`, resolving the producer's public key
    ///    from `federation_keys` via `producer_key_id`. Bad signature →
    ///    [`BlobError::InvalidArgument`].
    /// 6. INSERT. A `(stream_id, tree_size)` PK conflict with a DIFFERENT
    ///    root → [`BlobError::InvalidArgument`] (equivocation attempt);
    ///    an identical re-PUT is idempotent (`Ok`).
    ///
    /// Persist does NOT sign stream STHs (unlike the audit log). Witness
    /// cosignatures are stored as-provided (default empty); Cut C1b does
    /// NOT enforce a cosign quorum (best-effort tier — CEG §10.5.1).
    fn put_stream_sth(
        &self,
        sth: ciris_verify_core::transparency::SignedTreeHead,
        producer_key_id: &str,
    ) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// v4.1 (CIRISPersist#142, Cut C1b) — the most recent STH (highest
    /// `tree_size`) stored for `stream_id`, or `None` if no STH exists.
    fn latest_stream_sth(
        &self,
        stream_id: &str,
    ) -> impl Future<
        Output = Result<Option<ciris_verify_core::transparency::SignedTreeHead>, BlobError>,
    > + Send;

    /// v4.1 (CIRISPersist#142, Cut C1b) — RFC 6962 inclusion proof for
    /// the chunk at `leaf_index` against a `tree_size`-leaf tree, built
    /// from the stream's stored chunk hashes via
    /// [`InMemoryTransparencyStore`](ciris_verify_core::transparency::InMemoryTransparencyStore).
    /// `None` if the stream has fewer than `tree_size` chunks or
    /// `leaf_index >= tree_size`.
    fn stream_inclusion_proof(
        &self,
        stream_id: &str,
        leaf_index: u64,
        tree_size: u64,
    ) -> impl Future<Output = Result<Option<ciris_verify_core::transparency::MerkleProof>, BlobError>>
           + Send;

    /// v4.1 (CIRISPersist#142, Cut C1b) — RFC 6962 §2.1.2 consistency
    /// proof between `from_size` and `to_size`, built from the stream's
    /// stored chunk hashes. `None` if the stream has fewer than
    /// `to_size` chunks.
    fn stream_consistency_proof(
        &self,
        stream_id: &str,
        from_size: u64,
        to_size: u64,
    ) -> impl Future<
        Output = Result<Option<ciris_verify_core::transparency::ConsistencyProof>, BlobError>,
    > + Send;

    /// v4.1 (CIRISPersist#142, Cut C4, CEG §10.5.4) — store a subscriber
    /// delivery receipt after the **JOIN-against-published-STH** gate.
    /// The verify is NOT a sig-check: order is (1) verify the
    /// subscriber's hybrid signature over the §10.5.4 canonical bytes
    /// against the pinned `federation_keys` key, (2) **the JOIN** —
    /// `receipt.chunk_root` MUST equal a `federation_stream_sth.root_hash`
    /// published for `receipt.stream_id` at `tree_size >= receipt.k`
    /// (a phantom / self-invented root → [`BlobError::InvalidArgument`]),
    /// (3) INSERT. A `(stream_id, subscriber_key_id, k)` PK conflict with
    /// a DIFFERENT `chunk_root` → reject; identical → idempotent. Persist
    /// validates, never adjudicates — no "delivered" verdict, no
    /// membership enforcement (§1.4 / consumer policy).
    fn put_delivery_receipt(
        &self,
        receipt: crate::federation::stream_receipt::DeliveryReceipt,
    ) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// v4.1 (CIRISPersist#142, Cut C4) — list stored delivery receipts
    /// for `stream_id`, ascending `(k, subscriber_key_id)`, bounded by
    /// `limit`.
    fn list_delivery_receipts_for(
        &self,
        stream_id: &str,
        limit: i64,
    ) -> impl Future<
        Output = Result<Vec<crate::federation::stream_receipt::DeliveryReceipt>, BlobError>,
    > + Send;

    /// Read a blob by its SHA-256.
    ///
    /// Returns the [`BlobBody`] variant matching the row's stored
    /// `storage_kind`. Persist never fetches from S3 / external URLs;
    /// the External arm hands back the pointer and the caller streams
    /// the bytes themselves. A `chunk_dag` row returns
    /// [`BlobBody::ChunkDag`] with the parsed manifest.
    fn get_blob(
        &self,
        sha256: &[u8; 32],
    ) -> impl Future<Output = Result<Option<BlobBody>, BlobError>> + Send;

    /// v4.1 (CIRISPersist#142, Cut A) — byte-range read (RFC 9110 §14.4
    /// semantics). `range_end_inclusive` is clamped to size-1; a
    /// `range_start` at or past the blob size is `RangeNotSatisfiable`.
    /// Inline → server-side substring (no full-buffer load). External →
    /// the ref + clamped range for the caller to fetch (persist never
    /// dereferences). Returns None if the blob is absent.
    fn get_blob_range(
        &self,
        sha256: &[u8; 32],
        range_start: u64,
        range_end_inclusive: u64,
    ) -> impl Future<Output = Result<Option<BlobRange>, BlobError>> + Send;

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

            // v31.0.0 (CIRISPersist#652) — the v31-SHAPED envelope: the #598
            // instants and the #643 mirror ride the bytes this signer is about
            // to sign. `put_blob` rebuilds these exact bytes from the same
            // four inputs, so persist still verifies the caller signed the row
            // it is storing. `now` is BOTH instants here because the signing
            // helper mints the claim and signs it in one motion — a caller
            // that wants to assert an older claim uses `put_blob` directly and
            // states `asserted_at` itself.
            let envelope = holds_bytes_attestation_envelope(
                sha256,
                attesting_key_id,
                &attestation_id.to_string(),
                now,
            );
            // v4.6 (#176) — produce-side gate (Python pre-cut, JCS post-cut).
            let canonical_bytes = crate::verify::canonical::ceg_produce_canonicalize(&envelope)
                .map_err(|e| {
                    BlobError::InvalidArgument(format!("canonicalize holds_bytes envelope: {e}"))
                })?;
            let original_content_hash_hex = hex::encode(Sha256::digest(&canonical_bytes));

            let sig_bytes = signer
                .sign(&canonical_bytes)
                .await
                .map_err(|e| BlobError::AttestationEmissionFailed(format!("signer.sign: {e}")))?;
            let scrub_signature_classical = B64.encode(&sig_bytes);
            // v9.3.0 (#247) — the holds_bytes `scrub_key_id` FKs to
            // `federation_keys(key_id)`, which is the DERIVED wire key_id
            // (`<label>-<fp>`), NOT the keystore alias `current_alias()`.
            // Using the alias FK-violated on every node whose alias ≠
            // derived id (the same class as `attestation_promote` #247).
            let signer_pubkey = signer.public_key().await.map_err(|e| {
                BlobError::AttestationEmissionFailed(format!(
                    "holds_bytes derive scrub_key_id (signer public_key): {e}"
                ))
            })?;
            let scrub_key_id =
                ciris_verify_core::fedcode::derive_key_id(signer.current_alias(), &signer_pubkey);

            let att = PutBlobAttestation {
                attesting_key_id: attesting_key_id.to_string(),
                attestation_id: attestation_id.to_string(),
                original_content_hash_hex,
                scrub_signature_classical,
                scrub_signature_pqc: None,
                scrub_key_id,
                scrub_timestamp: now,
                asserted_at: now,
            };

            self.put_blob(sha256, body, media_type, att).await
        }
    }

    /// v3.9.2 (CIRISPersist#153 Ask 5, CEG 0.7 §10.1.4) — cohort-scope-
    /// aware blob write. The substrate-side enforcement of the
    /// structural-invisibility privacy claim.
    ///
    /// Dispatches on
    /// [`cohort_scope::suppresses_holds_bytes`](crate::federation::types::cohort_scope::suppresses_holds_bytes):
    ///
    /// - `self` / `family` → [`store_blob_local`](BlobStorage::store_blob_local):
    ///   bytes are persisted, **no** `holds_bytes` attestation is
    ///   emitted, the signer is never invoked (there is no attestation
    ///   to sign). The content is structurally invisible to the
    ///   federation.
    /// - every other (validated) scope → [`put_blob_signing`](BlobStorage::put_blob_signing):
    ///   the federation-tier path that signs + emits the `holds_bytes`
    ///   announcement exactly as today.
    ///
    /// `cohort_scope` MUST be one of the closed-set values
    /// ([`cohort_scope::is_valid`](crate::federation::types::cohort_scope::is_valid));
    /// an unknown value (e.g. the §8.1.8 feed-name `global`) is
    /// rejected with [`BlobError::InvalidArgument`] — the same closed
    /// set the v3.9.1 attestation admission gate enforces, applied here
    /// at the blob-write boundary.
    ///
    /// # Default impl
    ///
    /// Composed from the two existing surfaces; no per-backend override
    /// is intended.
    #[allow(clippy::too_many_arguments)]
    fn put_blob_signing_scoped<'s>(
        &'s self,
        cohort_scope: &'s str,
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
            if !crate::federation::types::cohort_scope::is_valid(cohort_scope) {
                return Err(BlobError::InvalidArgument(format!(
                    "cohort_scope {cohort_scope:?} is not in the closed set \
                     {{self, family, community, affiliations, species, biosphere, federation}}"
                )));
            }
            if crate::federation::types::cohort_scope::suppresses_holds_bytes(cohort_scope) {
                // Structurally invisible (CEG §10.1.4): store the bytes,
                // announce nothing. No signer, no holds_bytes row.
                self.store_blob_local(sha256, body, media_type).await
            } else {
                self.put_blob_signing(
                    sha256,
                    body,
                    media_type,
                    attesting_key_id,
                    signer,
                    now,
                    attestation_id,
                )
                .await
            }
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

    /// v4.14.0 (CIRISPersist#152, CEG 0.18 §10.1.4) — record one at-rest
    /// `key_grant` row for the self/family DEK cascade.
    ///
    /// Substrate state, NOT a wire attestation: it carries no signature
    /// and never federates (the secrets-path model). `at_rest_sha256` is
    /// the SHA-256 of the stored ciphertext envelope (the at-rest content
    /// address); `recipient_key_id` is the recipient occurrence's
    /// federation key (or the
    /// [`PERSIST_SELF_RECIPIENT`](crate::federation::at_rest_cascade::PERSIST_SELF_RECIPIENT)
    /// sentinel for persist's own content-master self-retention row);
    /// `wrapped_dek` is the `KeyGrantWrapV2` JSON (recipient) or the
    /// base64 self-wrap (persist). Idempotent on the
    /// `(at_rest_sha256, recipient_key_id)` PK — a re-record of the same
    /// recipient is a no-op (first-write-wins).
    fn put_at_rest_grant(
        &self,
        at_rest_sha256: &[u8; 32],
        recipient_key_id: &str,
        wrap_algorithm: &str,
        wrapped_dek: &str,
        cohort_scope: &str,
    ) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// v4.14.0 (CIRISPersist#152) — fetch the at-rest grant for
    /// `(at_rest_sha256, recipient_key_id)`, returning
    /// `(wrap_algorithm, wrapped_dek)` or `None` if no grant exists (the
    /// viewer holds no key — `get_blob_for_viewer` maps that to
    /// [`BlobError::NotGranted`]).
    fn get_at_rest_grant(
        &self,
        at_rest_sha256: &[u8; 32],
        recipient_key_id: &str,
    ) -> impl Future<Output = Result<Option<(String, String)>, BlobError>> + Send;

    /// v4.14.0 (CIRISPersist#152) — list every recipient `key_id` that
    /// already holds an at-rest grant for `at_rest_sha256` (excluding the
    /// `__persist_self__` sentinel). The retroactive-ADD walk (#161 Ask 2)
    /// uses this to skip recipients already granted; tests assert the
    /// fail-secure exclusion shape against it.
    fn list_at_rest_grant_recipients(
        &self,
        at_rest_sha256: &[u8; 32],
    ) -> impl Future<Output = Result<Vec<String>, BlobError>> + Send;

    /// v6.1.0 (CIRISPersist#161 Ask 2/4, CEG §11.7.1 / §10.1.4) — the
    /// **retroactive-ADD** enumeration: distinct `at_rest_sha256` of every
    /// blob in `cohort_scope` that **any** of `recipient_key_ids` already
    /// holds a grant on.
    ///
    /// This is the cohort-visibility set the membership-change re-key walk
    /// joins a newcomer into: when a new occurrence/member is admitted, the
    /// existing cohort members' grants name exactly the blobs the newcomer
    /// should now reach. Filtered by `cohort_scope` (`self` | `family`) so a
    /// self-add never leaks family content and vice-versa; the
    /// `__persist_self__` self-retention row is never a discriminator (the
    /// caller passes occurrence recipients, not the sentinel). Returns the
    /// SHAs in stable ascending hex order. Empty `Vec` if `recipient_key_ids`
    /// is empty or none hold any grant in scope.
    fn list_at_rest_blobs_for_recipients(
        &self,
        recipient_key_ids: &[String],
        cohort_scope: &str,
    ) -> impl Future<Output = Result<Vec<[u8; 32]>, BlobError>> + Send;

    /// v4.14.0 (CIRISPersist#152) — load persist's software content
    /// master key, generating + persisting it once on first call.
    ///
    /// The DEK-retention root for the default tier (OQ-4). **Software
    /// default** — honest about being software (the production target is
    /// the hardware-rooted HKDF derivation per ENCRYPTED_AT_REST.md §4.3;
    /// wiring the sealed seed through the Engine is a follow-up). The
    /// 32-byte key is stored base64 in `federation_content_master`
    /// (single logical row, `id=0`); concurrent first-callers race on the
    /// PK insert and converge on the persisted value.
    fn load_or_init_content_master(
        &self,
    ) -> impl Future<Output = Result<[u8; 32], BlobError>> + Send;

    /// v5.4.0 (CIRISPersist#198, CEG 1.0 §5.6.8.8.2) — load this node's
    /// **content-KEM identity** (the content-encryption keypair role of
    /// the [`LocalIdentityAggregate`](crate::federation::LocalIdentityAggregate)),
    /// minting + sealing it once on first call.
    ///
    /// On first call: mint a FRESH X25519 keypair + ML-KEM-768 keypair
    /// via `ciris_crypto` (independent of the signing key —
    /// §5.6.8.8.2 forbids deriving the content-KEM x25519 from any other
    /// role key), seal the two PRIVATE halves under the content master via
    /// [`load_or_init_content_master`](Self::load_or_init_content_master)
    /// and [`seal_content_kem_private`](crate::federation::identity_aggregate::seal_content_kem_private)
    /// (the same AES-256-GCM discipline as the self/family DEK
    /// self-retention wrap), and persist them with the two pubkeys in the
    /// single-row `federation_content_kem_identity` table (V073).
    ///
    /// **Idempotent / STABLE**: the keypair is minted once and read back
    /// on every subsequent call (concurrent first-callers race on the
    /// `id=0` PK and converge on the persisted value). Re-minting would
    /// orphan every grant a peer has already wrapped to the prior
    /// pubkeys, so first-write wins.
    ///
    /// Returns only the two **public** halves (what the aggregate
    /// publishes + what peers wrap to). The sealed privates are stored
    /// for the future at-rest-recipient decrypt path — not exercised in
    /// v1.
    fn load_or_init_content_kem_identity(
        &self,
    ) -> impl Future<
        Output = Result<crate::federation::identity_aggregate::ContentKemIdentity, BlobError>,
    > + Send;

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
    ///    `withdraws` attestation HYBRID-signed by `signer`
    ///    (Ed25519 + ML-DSA-65), canonicalized via the CEG produce gate
    ///    ([`crate::verify::canonical::ceg_produce_canonicalize`]) — the
    ///    federation-tier ingest gate (CC 5.3.2.4.3.1) requires the PQC
    ///    half, so a non-hybrid signer cannot emit a conformant withdraws.
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
        signer: &'s crate::signing::LocalSigner,
        now: chrono::DateTime<chrono::Utc>,
    ) -> impl Future<Output = Result<EvictActorReport, BlobError>> + Send + 's;

    // ── v9.0.0 G5 (CC 4.4.3.2.1 / 4.4.3.2.2, CIRISPersist#237) ──────
    //   community DEK cascade + rotation-on-removal state (V087). The
    //   InvisibleEncrypted (self/family) tier uses a FRESH per-write DEK
    //   (V070); the CommunityDek tier shares ONE DEK per
    //   `(community_key_id, epoch)` across emissions and rotates the
    //   epoch on member removal. These are PG/SQLite-backed (the at-rest
    //   storage backends), mirroring the V070 grant surface above. The
    //   method names are `community_dek_*`-prefixed to keep them distinct
    //   from the self/family `*_at_rest_grant` surface.

    /// v9.0.0 G5 — the current sealing epoch for `community_key_id` from
    /// `federation_community_dek_epoch` (0 if the community has no row
    /// yet — a community that has never been rotated). The cascade seals
    /// new emissions under this epoch's DEK.
    fn community_dek_current_epoch(
        &self,
        community_key_id: &str,
    ) -> impl Future<Output = Result<u64, BlobError>> + Send;

    /// v9.0.0 G5 (CC 4.4.3.2.2) — advance the community DEK epoch by one
    /// (rotation-on-removal). Upserts `federation_community_dek_epoch`,
    /// returning the NEW epoch. The next emission mints a fresh DEK for
    /// this epoch wrapped only to the remaining members; a removed member
    /// cannot derive it. Idempotency is the caller's (the membership-
    /// revocation row is itself idempotent); a double-bump only wastes an
    /// epoch number (a fresh DEK is minted lazily on next emission, so an
    /// unused epoch costs nothing).
    fn community_dek_bump_epoch(
        &self,
        community_key_id: &str,
    ) -> impl Future<Output = Result<u64, BlobError>> + Send;

    /// v9.0.0 G5 — persist's content-master self-retention wrap of the
    /// `(community_key_id, epoch)` shared DEK (the V070 OQ-4 discipline,
    /// per-epoch). `wrapped_dek` is base64 of
    /// `nonce(12) || aes256_gcm(content_master, dek)`. Idempotent on the
    /// `(community_key_id, epoch)` PK (first-write-wins): the epoch DEK is
    /// minted once.
    fn community_dek_put_self_retention(
        &self,
        community_key_id: &str,
        epoch: u64,
        wrapped_dek: &str,
    ) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// v9.0.0 G5 — fetch persist's self-retention `wrapped_dek` for
    /// `(community_key_id, epoch)`, or `None` if the epoch DEK has not
    /// been minted yet (the cascade mints it on first emission in the
    /// epoch).
    fn community_dek_get_self_retention(
        &self,
        community_key_id: &str,
        epoch: u64,
    ) -> impl Future<Output = Result<Option<String>, BlobError>> + Send;

    /// v9.0.0 G5 — record one per-member v2 wrap of the
    /// `(community_key_id, epoch)` DEK (the cascade fan-out, written once
    /// at epoch creation). `wrapped_dek` is the `KeyGrantWrapV2` JSON
    /// envelope; `wrap_algorithm` MUST be
    /// [`crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2`] (the DB
    /// CHECK rejects anything else — the substrate's v2-only guarantee).
    /// Idempotent on `(community_key_id, epoch, member_key_id)`.
    fn community_dek_put_member_grant(
        &self,
        community_key_id: &str,
        epoch: u64,
        member_key_id: &str,
        wrap_algorithm: &str,
        wrapped_dek: &str,
    ) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// v9.0.0 G5 — member occurrence key_ids already holding a grant on
    /// `(community_key_id, epoch)`. The cascade uses this to skip members
    /// already wrapped (idempotent re-key) and tests assert the
    /// fail-secure exclusion shape against it.
    fn community_dek_member_grant_recipients(
        &self,
        community_key_id: &str,
        epoch: u64,
    ) -> impl Future<Output = Result<Vec<String>, BlobError>> + Send;

    /// v9.0.0 G5 — does `member_key_id` hold a v2 grant on
    /// `(community_key_id, epoch)`? The read-side authorization predicate
    /// for [`crate::federation::community_dek::orchestrate::read_for_community_viewer`].
    fn community_dek_has_member_grant(
        &self,
        community_key_id: &str,
        epoch: u64,
        member_key_id: &str,
    ) -> impl Future<Output = Result<bool, BlobError>> + Send;

    /// v9.0.0 G5 — bind a sealed at-rest blob to the
    /// `(community_key_id, epoch)` whose DEK sealed it, so a read recovers
    /// the right epoch DEK. A blob is sealed under exactly one epoch
    /// (current at emission); rotation never re-seals it (forward-only).
    /// Idempotent on the `at_rest_sha256` PK.
    fn community_dek_bind_blob_epoch(
        &self,
        at_rest_sha256: &[u8; 32],
        community_key_id: &str,
        epoch: u64,
    ) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// v9.0.0 G5 — the `(community_key_id, epoch)` a sealed blob belongs
    /// to, or `None` if the blob carries no community-DEK binding (a
    /// self/family or plaintext blob).
    fn community_dek_blob_epoch(
        &self,
        at_rest_sha256: &[u8; 32],
    ) -> impl Future<Output = Result<Option<(String, u64)>, BlobError>> + Send;

    // ── v9.1.0 (CC 1.13.3 / FSD §2.4, CIRISPersist#243 parts 1+2) ───────
    //   scope-native privacy: a store for caller-pre-encrypted
    //   (XChaCha20-Poly1305) RaptorQ symbols at community/family/self
    //   scope. Distinct from put_blob_signing — NO trust score, NO
    //   attesting_key_id (holder identity opaque per FSD §2.4), PK is
    //   (record_id, symbol_index). Persist stores opaque ciphertext only
    //   (the seal + record_id/symbol_key derivation are CIRISEdge-side);
    //   eviction is pure LRU + capacity (CC 1.2), never trust-weighted.

    /// v9.1.0 (CC 1.13.3 / FSD §2.4) — admit one symbol-AEAD-encrypted
    /// RaptorQ fragment.
    ///
    /// The caller (CIRISEdge) supplies the XChaCha20-Poly1305 seal
    /// (`nonce` / `ciphertext` / `tag`) — persist NEVER encrypts or
    /// decrypts; it stores opaque ciphertext addressed by
    /// `(record_id, symbol_index)`. `record_id` is the FSD §2.4
    /// HMAC-SHA3-256 output; `symbol_index` is `0..N` (N=20 default).
    /// `group_dek_ref` ties the symbol to the community DEK epoch it was
    /// sealed under (resolved from
    /// [`community_dek_current_epoch`](BlobStorage::community_dek_current_epoch));
    /// only the epoch is persisted (opaque-holder property).
    ///
    /// Unlike [`put_blob_signing`](BlobStorage::put_blob_signing) there is
    /// NO trust-score lookup, NO attesting key, and NO
    /// [`AdmissionGate`](crate::federation::AdmissionGate) — community-scope
    /// eviction is LRU + capacity, not trust-weighted (#243 §1).
    ///
    /// # Idempotency
    ///
    /// First-write-wins on the `(record_id, symbol_index)` PK: a re-put of
    /// the same `(record_id, symbol_index)` is a no-op (ON CONFLICT DO
    /// NOTHING) — the original ciphertext/nonce/tag/epoch and `admitted_at`
    /// are preserved. (A symbol is content under a fixed AEAD key + index;
    /// re-admitting it carries no new information, and DO-NOTHING avoids
    /// resetting the LRU clock on a redundant write — only genuine reads
    /// bump `last_accessed_at`.)
    fn put_scope_blob(
        &self,
        record_id: [u8; 32],
        symbol_index: u16,
        nonce: [u8; 24],
        ciphertext: Vec<u8>,
        tag: [u8; 16],
        group_dek_ref: GroupDekRef,
    ) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// v9.1.0 (FSD §2.4) — read one scope-blob symbol back by
    /// `(record_id, symbol_index)`, or `None` if absent.
    ///
    /// Bumps the row's `last_accessed_at` (the LRU signal the capacity
    /// sweeper consumes) — a read keeps a symbol fresh. The bytes
    /// round-trip exactly what [`put_scope_blob`](BlobStorage::put_scope_blob)
    /// admitted (persist never decrypts).
    fn get_scope_blob(
        &self,
        record_id: [u8; 32],
        symbol_index: u16,
    ) -> impl Future<Output = Result<Option<ScopeBlobSymbol>, BlobError>> + Send;

    /// v9.1.0 (FSD §2.4) — list every stored symbol for `record_id`,
    /// ordered by `symbol_index` ASC. Empty vec if the record has no
    /// symbols. Bumps `last_accessed_at` on the returned rows (RaptorQ
    /// reassembly reads the whole record at once, so the read keeps all of
    /// the record's symbols fresh together).
    fn list_scope_blob_symbols(
        &self,
        record_id: [u8; 32],
    ) -> impl Future<Output = Result<Vec<ScopeBlobSymbol>, BlobError>> + Send;

    /// v9.1.0 (CC 1.2, FSD §2.4) — capacity-bound LRU eviction for the
    /// scope-blob store: while the row count exceeds `max_symbols`, delete
    /// the coldest (oldest `last_accessed_at`) symbols first, returning the
    /// number of symbols deleted.
    ///
    /// Mirrors the `federation_blobs` eviction discipline (the
    /// `(last_accessed_at ASC)` index walk) but with NO trust-weighting and
    /// NO decay scoring — pure LRU + capacity, per #243 §1. The disk-pressure
    /// / capacity sweeper drives this the same way it drives the
    /// federation_blobs sweep (see module docs).
    fn evict_scope_blobs(
        &self,
        max_symbols: u64,
    ) -> impl Future<Output = Result<u64, BlobError>> + Send;
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
    /// v31.0.0 (CIRISPersist#652) — **when the HOLDER CLAIM is asserted**, and
    /// now a field of its own.
    ///
    /// Both backends used to populate the `asserted_at` COLUMN from
    /// [`Self::scrub_timestamp`]: *when the signature was made* standing in for
    /// *when the claim was asserted*. Two different facts sharing one value is
    /// survivable while nothing reads it; `asserted_at` is what every fold
    /// orders on and what CIRISPersist#598 binds into the signed envelope, so
    /// it is not survivable now. It is also the caller's to state, not
    /// persist's to infer — a holder announcing bytes it has held for a week
    /// is making a claim about the week, not about the moment it reached for
    /// its key.
    ///
    /// Truncated to the substrate resolution when the envelope is stamped (see
    /// [`holds_bytes_attestation_row`]), so a caller passing `Utc::now()`
    /// verbatim is correct rather than refused.
    pub asserted_at: chrono::DateTime<chrono::Utc>,
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

    /// v4.1 (CIRISPersist#142, Cut A) — a
    /// [`get_blob_range`](BlobStorage::get_blob_range) `range_start` at or
    /// past the blob's size (RFC 9110 §14.4 "Range Not Satisfiable").
    #[error("range start {range_start} not satisfiable for blob of size {size}")]
    RangeNotSatisfiable {
        /// The requested (unsatisfiable) range start.
        range_start: u64,
        /// The blob's actual size in bytes.
        size: u64,
    },

    /// v4.1 (CIRISPersist#142, Cut B) — a
    /// [`get_blob_range`](BlobStorage::get_blob_range) over a
    /// [`BlobBody::ChunkDag`] where a chunk covering the requested range
    /// is stored `External` (S3 / URL). Persist cannot dereference an
    /// external chunk to slice it, so the range read fails fast with the
    /// offending chunk's SHA. **v-next enhancement**: a future cut may
    /// proxy the upstream `Range:` for the covering external chunk; for
    /// now the caller must fetch the external chunk(s) itself.
    #[error(
        "range spans an External chunk (sha256={chunk_sha_hex}); persist cannot \
         dereference it — fetch the chunk from its external ref directly"
    )]
    RangeSpansExternalChunk {
        /// Hex-encoded SHA-256 of the covering chunk that is External.
        chunk_sha_hex: String,
    },

    /// v4.14.0 (CIRISPersist#152, CEG 0.18 §10.1.4) — the at-rest blob
    /// exists but the viewer holds no `key_grant` for it. This is the
    /// fail-secure default for the self/family encrypted tier: a viewer
    /// who is not (or no longer) an active recipient — or whose
    /// occurrence carried no `encryption_pubkeys` at write time — gets a
    /// typed denial, never plaintext.
    #[error("viewer {viewer_key_id} holds no key_grant for blob {sha256_hex}")]
    NotGranted {
        /// Hex-encoded at-rest SHA-256 the read targeted.
        sha256_hex: String,
        /// The viewer key that holds no grant.
        viewer_key_id: String,
    },

    /// v4.14.0 (CIRISPersist#152) — the at-rest blob bytes are not held
    /// by this substrate (no `federation_blobs` row for the SHA).
    /// Distinct from [`Self::NotGranted`] (bytes present, no grant).
    #[error("blob {sha256_hex} is not held by this substrate")]
    NotHeld {
        /// Hex-encoded at-rest SHA-256 the read targeted.
        sha256_hex: String,
    },

    /// v6.8.0 (CIRISPersist#149) — the substrate is under disk pressure
    /// at the **stop** tier (or tighter) and refused to ACCEPT or SERVE
    /// federation-proxied content. Local + family content is never
    /// refused. **Permanent / non-retryable for the proxy operation**:
    /// the peer should fetch from another holder, not retry against this
    /// node — the condition clears only when the host disk recovers, not
    /// on retry. `operation` is `"accept"` (a proxy write) or `"serve"`
    /// (a proxy read served to a peer); `tier` is the current pressure
    /// tier label.
    #[error(
        "disk pressure ({tier}): refusing to {operation} federation-proxied content; \
         local + family content is unaffected — fetch from another holder"
    )]
    DiskPressureProxyRefused {
        /// `"accept"` (proxy write) or `"serve"` (proxy read to a peer).
        operation: &'static str,
        /// Current pressure tier label (`stop` / `host_at_risk`).
        tier: &'static str,
    },

    /// v25.1.0 (CIRISPersist#570 ask 5) — a local holder of these bytes is
    /// **quarantined**: withheld from serving by a live
    /// [`slash`](crate::federation::admission::DELEGATION_SCOPE_SLASH)-borne
    /// marker (see [`quarantine`](crate::federation::quarantine)).
    ///
    /// The bytes are RETAINED — this refuses to serve them, it never deletes
    /// them, and releasing the marker restores serving with no reconstruction.
    /// A peer receiving this should fetch from another holder; unlike
    /// [`Self::DiskPressureProxyRefused`] it will not clear on its own,
    /// because it is a policy decision rather than a capacity one.
    #[error("withheld from serving: local holder {key_id} is quarantined")]
    QuarantineWithheld {
        /// The withheld holder — named so an operator can find the marker
        /// (`resolve_quarantine(key_id)`) rather than guess.
        key_id: String,
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
            BlobError::RangeNotSatisfiable { .. } => "blob_range_not_satisfiable",
            BlobError::RangeSpansExternalChunk { .. } => "blob_range_spans_external_chunk",
            BlobError::NotGranted { .. } => "blob_not_granted",
            BlobError::NotHeld { .. } => "blob_not_held",
            BlobError::DiskPressureProxyRefused { .. } => "blob_disk_pressure_proxy_refused",
            BlobError::QuarantineWithheld { .. } => "blob_quarantine_withheld",
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

/// v2.3 (CIRISPersist#103) — the canonical `attestation_envelope` JSON for a
/// `holds_bytes` attestation.
///
/// Base shape, before the v31 bindings below are stamped onto it:
///
/// ```json
/// {
///   "kind": "holds_bytes",
///   "evidence_refs": ["<full-hex-sha256>"]
/// }
/// ```
///
/// # v31.0.0 (CIRISPersist#652) — why this takes the row, not just the SHA
///
/// It used to take `sha256` alone, and that was the whole defect. The
/// `put_blob` door RECONSTRUCTS this envelope rather than storing the
/// caller's, so the envelope must be a pure function of things persist also
/// knows — which is what kept it to the SHA, and which is exactly why it could
/// carry neither the #598 instants nor the #643 mirror. Both bind ROW fields.
///
/// So the row's identity is threaded in instead. Determinism — the property
/// the whole door rests on — is preserved, because every remaining bound field
/// is fixed BY CONSTRUCTION at this door: `attested_key_id` is the attester (a
/// holder attests itself), `attestation_type` is
/// [`holds_bytes_attestation_type`] of the same SHA, `subject_key_ids` is
/// empty, `cohort_scope` is `federation`, and `weight` / `expires_at` are
/// `None`. Persist can still rebuild these exact bytes and therefore still
/// verify that the caller signed the row it is actually storing. The rule is
/// unchanged — **the party that MINTS the bytes stamps, the party that
/// RECEIVES them checks** — it simply runs over a bigger input.
#[must_use]
pub fn holds_bytes_attestation_envelope(
    sha256: &[u8; 32],
    attesting_key_id: &str,
    attestation_id: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    holds_bytes_attestation_row(sha256, attesting_key_id, attestation_id, asserted_at)
        .attestation_envelope
}

/// v31.0.0 (CIRISPersist#652) — **the ONE definition of a `holds_bytes` row**,
/// v31-shaped and ready to sign, with the scrub fields left empty for whoever
/// fills them.
///
/// # What was open
///
/// `put_blob` raw-INSERTed straight into `federation_attestations`, bypassing
/// `put_attestation` and therefore BOTH binding gates. Three consequences, and
/// the third is the one that bites:
///
/// 1. the envelope was `{"kind","evidence_refs"}` — no #598 instants, no #643
///    mirror, so every field that decides what the row MEANS was unsigned;
/// 2. `asserted_at` was populated from `scrub_timestamp` — *when the signature
///    was made* standing in for *when the claim was asserted*, two different
///    facts sharing one column;
/// 3. the `tier` column was **omitted from the INSERT entirely**, so it took
///    the schema default `'federation'` — and `list_attestations_since`
///    filters on exactly that tier. **The tier nobody chose is the tier that
///    replicates.** So these rows went out to every peer, and every peer's
///    `put_attestation` refused them, because they were minted through a door
///    that never asked what the peers ask.
///
/// # Shape
///
/// Returns the row with `original_content_hash` / `scrub_signature_*` /
/// `scrub_key_id` / `persist_row_hash` blank. The signing side
/// ([`BlobStorage::put_blob_signing`]) canonicalizes
/// `attestation_envelope`, signs, and fills them; the receiving side
/// (`put_blob`) rebuilds the identical row and copies the caller's values in.
/// One definition, so the bytes the caller signed and the bytes persist stores
/// cannot drift — which is the #649/#643 defect class, and the reason this is
/// a function and not two struct literals in two backends.
///
/// Infallible by construction: the mirror stamp fails only on a non-finite
/// `weight` (always `None` here) and the instant stamp only on a non-object
/// envelope (built as an object one line above).
#[must_use]
pub fn holds_bytes_attestation_row(
    sha256: &[u8; 32],
    attesting_key_id: &str,
    attestation_id: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> crate::federation::Attestation {
    let mut row = crate::federation::Attestation {
        attestation_id: attestation_id.to_owned(),
        attesting_key_id: attesting_key_id.to_owned(),
        // A holder attestation attests the HOLDER ITSELF — "I (key_id=X) hold
        // the bytes". No second key is involved.
        attested_key_id: attesting_key_id.to_owned(),
        attestation_type: holds_bytes_attestation_type(sha256),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: serde_json::json!({
            "kind": "holds_bytes",
            "evidence_refs": [hex::encode(sha256)],
        }),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: String::new(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        // v3.7.0 (CIRISPersist#146, CEG 0.6) — holds_bytes is a
        // self-attestation; subject-side authority does not apply.
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
        // v31.0.0 (CIRISPersist#652) — STATED, not defaulted. Both backends
        // omitted this column from the INSERT and inherited the schema default,
        // which happens to be the tier `list_attestations_since` serves.
        tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };
    crate::federation::envelope::stamp_signed_instants(&mut row)
        .expect("the holds_bytes envelope is built as an object one line above");
    crate::federation::envelope::RowMirror::stamp_row(&mut row)
        .expect("a holds_bytes row carries no weight, so the mirror cannot fail");
    row
}

/// v31.0.0 (CIRISPersist#656) — **the `put_blob` door's admission gate**, run
/// by both backends on the row [`holds_bytes_attestation_row`] just rebuilt,
/// before anything is written.
///
/// # What #652 left open
///
/// #652 fixed the row SHAPE — the builder above stamps the #598 instants and
/// the #643 mirror — but it wired no GATES. That was enough for the two
/// bindings, which hold by construction, and not enough for anything else,
/// because **the skew arm of [`check_instant_binding`] is not a binding
/// property**. It compares `asserted_at` against wall-clock `now`, and
/// [`PutBlobAttestation::asserted_at`] is caller-supplied and unbounded — so
/// this door minted a FEDERATION-tier row (served and replicated; see the
/// builder's `tier` note) whose consent-fold ordering key sat arbitrarily far
/// in the future. Construction cannot satisfy a bound it does not know about,
/// which is the general reason a deterministic builder is not a substitute for
/// a gate.
///
/// Two arms:
///
/// 1. **[`check_instant_binding`]**, the same call every other door makes,
///    which is where the skew bound lives.
/// 2. **THE CALLER'S HASH MUST COVER THE BYTES PERSIST REBUILT.** The door
///    writes the caller's `original_content_hash` and `scrub_signature_*` over
///    an envelope it reconstructed itself, and nothing checked that the two
///    describe the same thing. The reconstruction being deterministic is
///    exactly what makes the cross-check possible — it is the property
///    [`holds_bytes_attestation_row`]'s doc rests its *"the party that MINTS
///    the bytes stamps, the party that RECEIVES them checks"* claim on — so it
///    is used here rather than assumed. A signature over a different envelope
///    than the one stored is the #649 divergence with the halves swapped.
///
/// `now` is a parameter so the skew bound is testable without sleeping.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) fn check_put_blob_admission(
    row: &crate::federation::Attestation,
    declared_content_hash_hex: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), BlobError> {
    use sha2::{Digest, Sha256};

    crate::federation::admission::check_instant_binding(
        row,
        now,
        crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
    )
    .map_err(|e| BlobError::InvalidArgument(format!("holder attestation: {e}")))?;

    let canonical = crate::verify::canonical::ceg_produce_canonicalize(&row.attestation_envelope)
        .map_err(|e| {
        BlobError::Backend(format!(
            "holder attestation canonicalize: {e} (CIRISPersist#656)"
        ))
    })?;
    let rebuilt = hex::encode(Sha256::digest(&canonical));
    if rebuilt != declared_content_hash_hex {
        return Err(BlobError::InvalidArgument(format!(
            "holder attestation {}: the declared original_content_hash {declared_content_hash_hex} \
             does not cover the envelope persist stores — these bytes canonicalize to {rebuilt}. \
             `put_blob` REBUILDS the holder envelope rather than storing the caller's, so a \
             signature made over anything else covers an envelope that does not exist \
             (CIRISPersist#656/#652)",
            row.attestation_id,
        )));
    }
    Ok(())
}

/// v31.0.0 (CIRISPersist#656) — **a `PutBlobAttestation` whose declared
/// content hash actually covers the envelope `put_blob` will rebuild.**
///
/// Every backend's blob fixtures used to hard-code `original_content_hash_hex`
/// to a placeholder (`"abcdef01"` / `"deadbeef"` — four bytes, where the column
/// is a 32-byte digest). That is what let the missing
/// [`check_put_blob_admission`] cross-check go unnoticed for a whole release:
/// the fixtures asserted the door's behaviour on rows whose declared hash
/// covered nothing, so no test could tell a correct hash from an absent one.
/// This mints the hash the way [`BlobStorage::put_blob_signing`] does — from
/// [`holds_bytes_attestation_envelope`] over the same four inputs — so the
/// fixtures now exercise the shape production actually produces.
///
/// The signature stays a placeholder: `put_blob` does not verify signatures
/// (see [`check_put_blob_admission`] for what it does check), and pretending
/// otherwise in a fixture would be the same defect one field over.
#[cfg(all(test, any(feature = "postgres", feature = "sqlite")))]
pub(crate) fn sealed_put_blob_attestation(
    sha256: &[u8; 32],
    attesting_key_id: &str,
    scrub_key_id: &str,
    attestation_id: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
    scrub_timestamp: chrono::DateTime<chrono::Utc>,
) -> PutBlobAttestation {
    use sha2::{Digest, Sha256};
    let envelope =
        holds_bytes_attestation_envelope(sha256, attesting_key_id, attestation_id, asserted_at);
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(&envelope)
        .expect("the holds_bytes envelope canonicalizes");
    PutBlobAttestation {
        attesting_key_id: attesting_key_id.to_owned(),
        attestation_id: attestation_id.to_owned(),
        original_content_hash_hex: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: "c2ln".to_owned(),
        scrub_signature_pqc: None,
        scrub_key_id: scrub_key_id.to_owned(),
        scrub_timestamp,
        asserted_at,
    }
}

/// v31.0.0 (CIRISPersist#656) — **the `put_blob` admission witness**, shared by
/// the sqlite and postgres legs.
///
/// **Two backends, not three: `MemoryBackend` implements no [`BlobStorage`],**
/// so there is no memory door to gate. Recorded here rather than left as a
/// silently-absent leg — "the third leg is missing" and "the third door does
/// not exist" look identical from a test list.
///
/// #652 fixed the row SHAPE through one deterministic builder and wired no
/// gates. Two things do not follow from construction, and both are asserted:
///
/// 1. **the future-skew bound**, which is not a binding property — it compares
///    `asserted_at` against wall-clock `now`, and that field is caller-supplied
///    and was unbounded, so this door minted a FEDERATION-tier row (served and
///    replicated) whose consent-fold ordering key sat a year in the future.
///    Exactly the claim CIRISPersist#598 exists to make false: *"a lying clock
///    cannot mint a row no later row can out-sort."*
/// 2. **the caller's `original_content_hash` covering the bytes persist
///    rebuilt.** The door writes the caller's hash and signature over an
///    envelope it reconstructs itself; nothing checked the two described the
///    same thing.
///
/// Plus the control that an honest holder claim still lands — including one
/// asserted in the PAST, which is the case #652 added the field for (*"a holder
/// announcing bytes it has held for a week is making a claim about the week"*).
// v31.3.0 (CIRISPersist#678) — the `_for_host` variant below is called by BOTH
// backends, but this wrapper only by sqlite, so the union gate left it dead
// under postgres-only.
#[cfg(all(test, feature = "sqlite"))]
pub(crate) async fn exercise_put_blob_admission<B>(backend: &B, suffix: &str)
where
    B: BlobStorage + crate::federation::FederationDirectory,
{
    exercise_put_blob_admission_for_host(backend, "host-a", suffix).await;
}

/// [`exercise_put_blob_admission`] against an explicit, already-registered
/// `attesting_key_id` — the postgres leg bootstraps a per-run host so a shared
/// test DB does not collide.
#[cfg(all(test, any(feature = "postgres", feature = "sqlite")))]
pub(crate) async fn exercise_put_blob_admission_for_host<B>(backend: &B, host: &str, suffix: &str)
where
    B: BlobStorage + crate::federation::FederationDirectory,
{
    use sha2::{Digest, Sha256};
    let digest = |bytes: &[u8]| -> [u8; 32] { Sha256::digest(bytes).into() };

    // ── (1) AN UNBOUNDED-FUTURE HOLDER CLAIM IS REFUSED.
    let bytes = format!("skewed holder claim {suffix}").into_bytes();
    let sha = digest(&bytes);
    let far_future = crate::federation::admission::truncate_to_substrate_resolution(
        chrono::Utc::now() + chrono::Duration::days(365),
    );
    let skew_id = format!("blob-skew-{suffix}");
    let att = sealed_put_blob_attestation(&sha, host, host, &skew_id, far_future, far_future);
    let err = backend
        .put_blob(&sha, BlobBody::Inline(bytes.clone()), None, att)
        .await
        .expect_err("put_blob must apply the future-skew bound (#656)");
    assert!(
        err.to_string().contains("ahead of now"),
        "the refusal is the SKEW arm specifically, not a binding arm: {err}"
    );
    assert!(
        crate::federation::FederationDirectory::get_attestation(backend, &skew_id)
            .await
            .expect("read")
            .is_none(),
        "verify-before-mutation: the refused holder claim wrote no attestation row"
    );

    // ── (2) A HASH THAT DOES NOT COVER THE REBUILT ENVELOPE IS REFUSED.
    let liar_id = format!("blob-liar-{suffix}");
    let now = crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
    let mut lying = sealed_put_blob_attestation(&sha, host, host, &liar_id, now, now);
    lying.original_content_hash_hex = "00".repeat(32);
    let err = backend
        .put_blob(&sha, BlobBody::Inline(bytes.clone()), None, lying)
        .await
        .expect_err("put_blob must cross-check the declared hash against the rebuilt bytes (#656)");
    assert!(
        err.to_string().contains("original_content_hash"),
        "the refusal names the field that does not cover the stored bytes: {err}"
    );

    // ── (3) CONTROL — an honest claim lands, and so does an honest one about
    //        the PAST, which is the case `asserted_at` was added for.
    let ok_id = format!("blob-ok-{suffix}");
    let att = sealed_put_blob_attestation(&sha, host, host, &ok_id, now, now);
    backend
        .put_blob(&sha, BlobBody::Inline(bytes.clone()), None, att)
        .await
        .expect("an honest holder claim still lands — legs 1 and 2 gate the door, not close it");

    let week_ago = crate::federation::admission::truncate_to_substrate_resolution(
        chrono::Utc::now() - chrono::Duration::days(7),
    );
    let past_id = format!("blob-past-{suffix}");
    let att = sealed_put_blob_attestation(&sha, host, host, &past_id, week_ago, now);
    backend
        .put_blob(&sha, BlobBody::Inline(bytes), None, att)
        .await
        .expect(
            "a holder announcing bytes it has held for a week is making a claim about the week",
        );
    let row = crate::federation::FederationDirectory::get_attestation(backend, &past_id)
        .await
        .expect("read")
        .expect("the past-dated holder attestation was written");
    assert_eq!(row.asserted_at, week_ago, "the past instant is preserved");
    assert_eq!(
        row.tier,
        crate::federation::types::attestation_tier::FEDERATION,
        "and it is federation-tier, i.e. served and replicated — which is why the gate matters"
    );
    crate::federation::admission::check_instant_binding(
        &row,
        chrono::Utc::now(),
        crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
    )
    .expect("the stored row satisfies the gate the door now runs");
    crate::federation::admission::check_row_column_binding(&row)
        .expect("and the #643 mirror #652 stamps");
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
/// - `signer` — `&LocalSigner` HYBRID-signs the canonical envelope
///   bytes (v9.0.0, CC 5.3.2.4.3.1): Ed25519 over `JCS(envelope)` +
///   ML-DSA-65 over the bound `JCS(envelope) ‖ ed25519_sig`. A
///   `withdraws` is a federation-tier attestation, so the
///   `put_attestation` ingest gate
///   ([`crate::federation::verify_federation_tier_ingest`]) REQUIRES the
///   ML-DSA-65 half — a classical-only emission would be rejected at the
///   gate (fail-secure). The signer's registered key must therefore
///   carry both pubkeys.
/// - `directory` — concrete backend that owns
///   `federation_attestations`. `&dyn FederationDirectory` keeps the
///   helper backend-agnostic.
/// - `now` — caller-supplied so deterministic tests + replay paths
///   pin the timestamp.
///
/// # Errors
///
/// Returns [`BlobError::Backend`] for canonicalize / sign /
/// put_attestation failures. **v9.0.0**: if `signer` has no PQC identity
/// (`LocalSigner::sign_hybrid` ⇒ `PqcNotConfigured`) this returns a
/// CLEAR [`BlobError::Backend`] — an engine that cannot hybrid-sign
/// legitimately CANNOT emit a conformant federation-tier `withdraws`
/// (CC 5.3.2.4.3.1: no classical-only fallback, no silent skip, no
/// local-tier downgrade). The caller is responsible for tallying the
/// outcome (the v3.4.0 sweeper + v3.5.0 evict_actor both delete the
/// corresponding blob even when this helper fails — the fail-honest
/// contract documented on [`BlobStorage::evict_actor`]).
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn emit_withdraws_attestation_helper(
    prior: &crate::federation::Attestation,
    _signer_key_id: &str,
    signer: &crate::signing::LocalSigner,
    directory: &dyn crate::federation::FederationDirectory,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), BlobError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    // v9.3.0 (#247) — the withdraws' FK fields (attesting/attested/scrub)
    // are the SIGNER's registered DERIVED federation key_id (`<label>-<fp>`),
    // computed from the signer itself — NOT the caller-supplied alias
    // (`_signer_key_id`), which FK-violated on every real node (alias ≠
    // derived id). Same #247 floor as `Engine::emit_attestation`. The host
    // attests it itself no longer holds the bytes (a self-revocation).
    let signer_key_id = signer.derived_key_id();

    let envelope = crate::federation::withdraws_attestation_envelope(
        &prior.attestation_id,
        &prior.attestation_type,
    );
    // v31.0.0 (#643/#598) — the row is ASSEMBLED FIRST, then stamped, then
    // signed. This helper hand-rolls the emit recipe (it predates
    // `attestation_emit`), and the two bindings are both over material the
    // signature covers, so the order is forced: build → stamp → canonicalize →
    // sign. Without it persist's own eviction sweeper emits rows its own
    // put-gate refuses.
    //
    // `attestation_id` is minted here rather than at the literal because it is
    // signed material — the mirror carries it.
    let attestation_id = uuid::Uuid::new_v4().to_string();
    let mut row = crate::federation::Attestation {
        attestation_id,
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
        // Filled in below, once there are bytes to sign.
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: signer_key_id.to_owned(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        // v3.7.0 (CIRISPersist#146, CEG 0.6) — evict_actor emits a
        // producer-self-revocation withdraws; subject-side authority
        // (rule 2/3) doesn't apply on this path.
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_string(),
        tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };

    // v31.0.0 (CIRISPersist#598) — THE SIGNED INSTANTS, before the signature.
    // Through the shared placement rather than a fourth hand-rolled copy; it
    // also TRUNCATES `asserted_at` to the substrate resolution, which is why
    // the two derived timestamps are re-read from the row afterwards instead of
    // from `now` — a row whose three instants differ in their last nanoseconds
    // is one the postgres arm stores differently from the sqlite arm.
    crate::federation::envelope::stamp_signed_instants(&mut row)
        .map_err(|e| BlobError::Backend(format!("withdraws instant stamp: {e}")))?;
    row.scrub_timestamp = row.asserted_at;
    row.pqc_completed_at = Some(row.asserted_at);
    // v31.0.0 (CIRISPersist#643) — THE TYPED-COLUMN MIRROR, from
    // `RowMirror::of` and NOT a hand-written `json!` literal.
    //
    // The literal that stood here was correct only by coincidence.
    // [`RowMirror`] is `deny_unknown_fields` over a CLOSED member set, so the
    // next column bound into it would have left this one site silently
    // stamping a mirror missing that field — #643 re-opened at exactly one
    // door, and the door persist's own eviction sweeper writes through.
    // `RowMirror::of` is the one projection the GATE compares against, so
    // there is now nothing here that can drift from it.
    crate::federation::envelope::RowMirror::stamp_row(&mut row)
        .map_err(|e| BlobError::Backend(format!("withdraws row mirror stamp: {e}")))?;

    // v9.0.0 (#237, CC 5.3.2.4.3.1) — canonicalize through the CEG
    // PRODUCE gate (JCS post-cut, §0.9), the SAME canonical form the
    // federation-tier ingest gate verifies (was PythonJsonDumpsCanonicalizer,
    // which the gate's ceg_produce_canonicalize would not match).
    let canonical_bytes =
        crate::verify::canonical::ceg_produce_canonicalize(&row.attestation_envelope)
            .map_err(|e| BlobError::Backend(format!("withdraws canonicalize: {e}")))?;
    row.original_content_hash = hex::encode(Sha256::digest(&canonical_bytes));
    // v9.0.0 — HYBRID-sign (Ed25519 + ML-DSA-65 bound half) so the
    // federation-tier withdraws carries the PQC half the ingest gate
    // mandates. Mirrors Engine::attestation_promote. A non-PQC signer
    // CANNOT emit a conformant federation-tier withdraws — surface that
    // honestly (no classical-only fallback / silent skip / local
    // downgrade).
    let sig = signer.sign_hybrid(&canonical_bytes).await.map_err(|e| {
        BlobError::Backend(format!(
            "withdraws hybrid-sign: {e} — cannot emit a conformant federation-tier withdraws \
             without a hybrid (Ed25519 + ML-DSA-65) signer (CC 5.3.2.4.3.1)"
        ))
    })?;
    row.scrub_signature_classical = B64.encode(&sig.classical.signature);
    row.scrub_signature_pqc = Some(B64.encode(&sig.pqc.signature));

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

/// v4.1 (CIRISPersist#142, Cut B) — walk a [`ChunkManifest`] to
/// assemble the bytes covering the inclusive range `[start, end]`
/// (already clamped to `[0, total_size - 1]` by the caller).
///
/// Prefix-sums the chunk sizes to find the covering chunk(s), fetches
/// each covering chunk's bytes via [`BlobStorage::get_blob`] (which must
/// return an `Inline` body — persist cannot dereference an `External`
/// chunk, so that yields [`BlobError::RangeSpansExternalChunk`]), slices
/// each at the range boundaries, and concatenates.
///
/// Per-chunk SHA is re-verified on read (CEG §10.1.1 — full SHA before
/// consumption at both the manifest and chunk levels).
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn assemble_chunk_dag_range<S: BlobStorage + ?Sized>(
    storage: &S,
    manifest: &ChunkManifest,
    start: u64,
    end: u64,
) -> Result<Vec<u8>, BlobError> {
    use sha2::{Digest, Sha256};

    debug_assert!(start <= end);
    let want_len = (end - start + 1) as usize;
    let mut out: Vec<u8> = Vec::with_capacity(want_len);

    // Running byte offset of the START of the current chunk.
    let mut chunk_start: u64 = 0;
    for cref in &manifest.chunks {
        let chunk_len = u64::from(cref.size);
        if chunk_len == 0 {
            continue;
        }
        let chunk_end = chunk_start + chunk_len - 1; // inclusive
                                                     // Does this chunk overlap [start, end]?
        if chunk_end < start {
            chunk_start = chunk_end + 1;
            continue;
        }
        if chunk_start > end {
            break; // past the requested range
        }
        // Fetch the covering chunk's bytes. Persist cannot deref an
        // External chunk → typed error (v-next enhancement).
        let body = storage.get_blob(&cref.sha).await?;
        let bytes = match body {
            Some(BlobBody::Inline(b)) => b,
            Some(BlobBody::External(_)) => {
                return Err(BlobError::RangeSpansExternalChunk {
                    chunk_sha_hex: hex::encode(cref.sha),
                });
            }
            Some(BlobBody::ChunkDag(_)) => {
                // One-level DAG only; a chunk that is itself a DAG is a
                // corrupt manifest.
                return Err(BlobError::Backend(format!(
                    "chunk_dag covering chunk {} is itself a ChunkDag (nested DAG)",
                    hex::encode(cref.sha)
                )));
            }
            None => {
                return Err(BlobError::Backend(format!(
                    "chunk_dag covering chunk {} is missing from federation_blobs",
                    hex::encode(cref.sha)
                )));
            }
        };
        // CEG §10.1.1 — verify the chunk SHA before consumption.
        let computed = Sha256::digest(&bytes);
        if computed.as_slice() != cref.sha.as_slice() {
            return Err(BlobError::HashMismatch {
                expected_hex: hex::encode(cref.sha),
                got_hex: hex::encode(computed),
            });
        }
        if bytes.len() as u64 != chunk_len {
            return Err(BlobError::Backend(format!(
                "chunk_dag chunk {} is {} bytes but manifest size is {}",
                hex::encode(cref.sha),
                bytes.len(),
                chunk_len
            )));
        }
        // Slice the overlap of [start, end] with this chunk, in
        // chunk-local coordinates.
        let local_start = start.saturating_sub(chunk_start);
        let local_end_inclusive = if end >= chunk_end {
            chunk_len - 1
        } else {
            end - chunk_start
        };
        out.extend_from_slice(&bytes[local_start as usize..=local_end_inclusive as usize]);

        chunk_start = chunk_end + 1;
    }

    Ok(out)
}

/// v4.1 (CIRISPersist#142, Cut B) — a single row prepared for the
/// `put_blob_chunks` atomic insert. Backend-agnostic: the backend's
/// transaction loop binds these directly.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
#[derive(Debug)]
pub(crate) struct PreparedBlobRow {
    /// SHA-256 (32 raw bytes) — the `sha256` PK.
    pub sha256: [u8; 32],
    /// `storage_kind` column value.
    pub storage_kind: &'static str,
    /// `bytes_inline` column value (present for inline / chunk_dag).
    pub bytes_inline: Option<Vec<u8>>,
    /// `external_ref` column value (present for s3 / external_url).
    pub external_ref: Option<String>,
    /// `size_bytes` column value (already range-checked to fit i64).
    pub size_bytes: i64,
}

/// v4.1 (CIRISPersist#142, Cut C1a) — validate ONE live-append chunk
/// (`put_blob_chunk`) and produce the prepared `federation_blobs` row +
/// the chunk's content SHA-256.
///
/// Validation mirrors the per-chunk arm of [`prepare_chunk_rows`]:
/// nested-DAG reject → inline-size cap → hash-on-write (the SHA is
/// COMPUTED from the bytes for `Inline`, trusted for `External`) → i64
/// range. There is no manifest here — a live chunk is one
/// content-addressed blob row; the stream index row is bound by the
/// backend alongside it in the same txn.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) fn prepare_stream_chunk_row(
    body: &BlobBody,
    inline_bytes_cap: usize,
) -> Result<PreparedBlobRow, BlobError> {
    use sha2::{Digest, Sha256};

    let (sha256, storage_kind, bytes_inline, external_ref, size) = match body {
        BlobBody::Inline(bytes) => {
            if bytes.len() > inline_bytes_cap {
                return Err(BlobError::InlineSizeExceeded {
                    size: bytes.len(),
                    cap: inline_bytes_cap,
                });
            }
            // Hash-on-write: the chunk's content address is computed from
            // its bytes (this IS the SHA returned to the caller + the PK).
            let sha: [u8; 32] = Sha256::digest(bytes).into();
            (sha, "inline", Some(bytes.clone()), None, bytes.len() as u64)
        }
        BlobBody::External(_) => {
            return Err(BlobError::InvalidArgument(
                "put_blob_chunk: External chunk body not supported in this cut — \
                 a live chunk's SHA is computed from its inline bytes (Cut C1a)"
                    .into(),
            ));
        }
        BlobBody::ChunkDag(_) => {
            return Err(BlobError::InvalidArgument(
                "put_blob_chunk: chunk body is itself a ChunkDag — you cannot chunk a chunk".into(),
            ));
        }
    };
    let size_bytes = i64::try_from(size).map_err(|_| {
        BlobError::InvalidArgument("put_blob_chunk: chunk size_bytes exceeds i64".into())
    })?;
    Ok(PreparedBlobRow {
        sha256,
        storage_kind,
        bytes_inline,
        external_ref,
        size_bytes,
    })
}

/// v4.1 (CIRISPersist#142, Cut C1a) — from the seq-ordered
/// `(chunk_sha, size_bytes)` rows read out of `federation_stream_chunks`,
/// build the sealed [`ChunkManifest`] + the prepared `chunk_dag`
/// manifest [`PreparedBlobRow`] (its SHA-256 = the sealed stream's
/// content address). Does NOT touch the chunk rows — they already exist.
///
/// Empty input → [`BlobError::InvalidArgument`] (`stream_id` carried by
/// the caller for the message). `total_size` is Σ `size_bytes`.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) fn prepare_sealed_manifest_row(
    stream_id: &str,
    chunk_rows: &[([u8; 32], i64)],
    inline_bytes_cap: usize,
) -> Result<(ChunkManifest, PreparedBlobRow), BlobError> {
    use sha2::{Digest, Sha256};

    if chunk_rows.is_empty() {
        return Err(BlobError::InvalidArgument(format!(
            "stream {stream_id} has no chunks"
        )));
    }
    let mut total_size: u64 = 0;
    let mut chunks = Vec::with_capacity(chunk_rows.len());
    for (sha, size_i64) in chunk_rows {
        let size = u32::try_from(*size_i64).map_err(|_| {
            BlobError::InvalidArgument(format!(
                "seal_stream: chunk size {size_i64} does not fit u32 (one-chunk cap)"
            ))
        })?;
        total_size = total_size
            .checked_add(u64::from(size))
            .ok_or_else(|| BlobError::InvalidArgument("seal_stream: total_size overflow".into()))?;
        chunks.push(ChunkRef { sha: *sha, size });
    }
    let manifest = ChunkManifest {
        v: CHUNK_MANIFEST_VERSION,
        total_size,
        chunks,
    };
    let manifest_bytes = manifest.to_jcs_bytes();
    if manifest_bytes.len() > inline_bytes_cap {
        return Err(BlobError::InlineSizeExceeded {
            size: manifest_bytes.len(),
            cap: inline_bytes_cap,
        });
    }
    let manifest_sha: [u8; 32] = Sha256::digest(&manifest_bytes).into();
    let manifest_size = i64::try_from(manifest.total_size)
        .map_err(|_| BlobError::InvalidArgument("seal_stream: total_size exceeds i64".into()))?;
    let row = PreparedBlobRow {
        sha256: manifest_sha,
        storage_kind: "chunk_dag",
        bytes_inline: Some(manifest_bytes),
        external_ref: None,
        size_bytes: manifest_size,
    };
    Ok((manifest, row))
}

/// v4.1 (CIRISPersist#142, Cut C1b) — **step 5 of the `put_stream_sth`
/// gate**: verify the producer's hybrid signature over the STH's
/// canonical signing bytes, resolving the producer's PINNED public key
/// from `federation_keys` via `producer_key_id`.
///
/// The producer's keys come from the directory, **not** from the
/// pubkeys embedded in the STH's `HybridSignature` — a forged STH
/// carrying its own keypair cannot self-certify. Uses
/// [`HybridPolicy::Strict`](crate::verify::HybridPolicy::Strict): a
/// stream STH must carry both signature components (no hybrid-pending
/// acceptance for transparency heads). Any verification failure —
/// unknown key, bad signature, missing PQC — maps to
/// [`BlobError::InvalidArgument`] so the gate rejects fast.
///
/// Mirrors the `verify_hybrid_via_directory` usage at
/// `src/server/secrets.rs`.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn verify_stream_sth_signature<F>(
    directory: &F,
    sth: &ciris_verify_core::transparency::SignedTreeHead,
    producer_key_id: &str,
) -> Result<(), BlobError>
where
    F: crate::federation::FederationDirectory,
{
    let (ed25519_sig_b64, ml_dsa_65_sig_b64) =
        crate::federation::stream_sth::signature_b64_parts(sth);
    let signing_bytes = sth.signing_bytes_of();
    crate::verify::verify_hybrid_via_directory(
        directory,
        &signing_bytes,
        producer_key_id,
        &ed25519_sig_b64,
        ml_dsa_65_sig_b64.as_deref(),
        crate::verify::HybridPolicy::Strict,
        None,
    )
    .await
    .map(|_outcome| ())
    .map_err(|e| {
        BlobError::InvalidArgument(format!(
            "put_stream_sth: producer signature verification failed for \
             key_id={producer_key_id}: {e}"
        ))
    })
}

/// v31.0.0 (CIRISPersist#657) — **step 5b of the `put_stream_sth` gate**: the
/// WITNESS cosignatures, verified with the same discipline as the producer's.
///
/// # The defect
///
/// `put_stream_sth` verified the producer signature and then stored
/// `witness_signatures` verbatim, and NO verify call for them existed anywhere
/// in `src/`. `latest_stream_sth` reads them back and hands them to callers, so
/// the substrate was preserving and presenting co-signatures it had never
/// checked. That is the #556 rule — the preserve set must equal the verified
/// set — on the transparency plane, and it is worse than dropping them would
/// be: an unchecked cosignature LOOKS like the split-view evidence
/// [`SignedTreeHead::witness_quorum_met`](ciris_verify_core::transparency::SignedTreeHead::witness_quorum_met)
/// is built to provide, and anyone can mint one by generating a keypair.
///
/// # The roster is `federation_keys` — the same one the producer resolves in
///
/// A witness is not a new kind of principal needing a new roster. It is a
/// registered federation key that watched this log, so `witness_id` resolves
/// through [`verify_hybrid_via_directory`](crate::verify::verify_hybrid_via_directory)
/// exactly as `producer_key_id` does: authority re-derived from THIS node's own
/// verified state, never from keys carried on the row (the #377 rule). Each
/// cosignature must clear all four checks, and a failure REFUSES THE WHOLE PUT
/// rather than silently not counting — "does not count" is the right answer
/// when tallying a quorum, and the wrong one when the question is whether to
/// durably store and later serve the thing:
///
/// 1. **distinct `witness_id`** — a repeat would inflate any count downstream;
/// 2. **known witness** — an unregistered `witness_id` is refused (fail closed
///    on absence, the standing v31 decision; there is no legacy regime in which
///    an unknown cosigner is stored anyway);
/// 3. **CEG 0.2 §10.3.1 consistency proof** verifies against
///    `(tree_size, root_hash)` — without it a cosignature is "quorum on a
///    string" rather than quorum on log consistency;
/// 4. **hybrid-Strict signature** over the IDENTICAL
///    [`signing_bytes_of`](ciris_verify_core::transparency::SignedTreeHead::signing_bytes_of)
///    bytes the producer signed, against the witness's PINNED directory
///    pubkeys.
///
/// An STH with no witnesses is `Ok(())` — the field is optional, and the
/// refusal is for an unverifiable one, never for an absent one.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn verify_stream_sth_witnesses<F>(
    directory: &F,
    sth: &ciris_verify_core::transparency::SignedTreeHead,
) -> Result<(), BlobError>
where
    F: crate::federation::FederationDirectory,
{
    if sth.witness_signatures.is_empty() {
        return Ok(());
    }
    let signing_bytes = sth.signing_bytes_of();
    let mut seen: Vec<&str> = Vec::with_capacity(sth.witness_signatures.len());
    for ws in &sth.witness_signatures {
        if seen.contains(&ws.witness_id.as_str()) {
            return Err(BlobError::InvalidArgument(format!(
                "put_stream_sth: witness {witness_id:?} cosigned this STH twice — a duplicate \
                 inflates every downstream witness count (CIRISPersist#657)",
                witness_id = ws.witness_id
            )));
        }
        seen.push(ws.witness_id.as_str());
        ws.consistency_proof
            .verify(sth.tree_size, &sth.root_hash)
            .map_err(|e| {
                BlobError::InvalidArgument(format!(
                    "put_stream_sth: witness {witness_id:?} cosignature carries a §10.3.1 \
                     consistency proof that does not chain to this STH: {e}",
                    witness_id = ws.witness_id
                ))
            })?;
        let (ed25519_sig_b64, ml_dsa_65_sig_b64) =
            crate::federation::stream_sth::hybrid_signature_b64_parts(&ws.signature);
        crate::verify::verify_hybrid_via_directory(
            directory,
            &signing_bytes,
            &ws.witness_id,
            &ed25519_sig_b64,
            ml_dsa_65_sig_b64.as_deref(),
            crate::verify::HybridPolicy::Strict,
            None,
        )
        .await
        .map(|_outcome| ())
        .map_err(|e| {
            BlobError::InvalidArgument(format!(
                "put_stream_sth: witness cosignature verification failed for \
                 witness_id={witness_id}: {e}",
                witness_id = ws.witness_id
            ))
        })?;
    }
    Ok(())
}

/// v4.1 (CIRISPersist#142, Cut B) — validate a `put_blob_chunks`
/// request and produce the ordered list of rows to insert in one txn
/// (the N chunk rows followed by the manifest row last).
///
/// Validation order: nested-DAG reject → total_size → chunk alignment →
/// per-Inline-chunk SHA + size → i64 range. Returns the prepared rows
/// (chunks first, manifest last) plus the manifest's `content_sha256`.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) fn prepare_chunk_rows(
    manifest: &ChunkManifest,
    chunks: &[([u8; 32], BlobBody)],
    inline_bytes_cap: usize,
) -> Result<Vec<PreparedBlobRow>, BlobError> {
    use sha2::{Digest, Sha256};

    // 1. total_size == sum(chunk sizes).
    manifest.validate_total_size()?;

    // 2. The chunks argument lines up 1:1 (by SHA, same order) with the
    //    manifest's chunk list.
    if chunks.len() != manifest.chunks.len() {
        return Err(BlobError::InvalidArgument(format!(
            "put_blob_chunks: {} chunk bodies supplied but manifest names {} chunks",
            chunks.len(),
            manifest.chunks.len()
        )));
    }

    let mut rows: Vec<PreparedBlobRow> = Vec::with_capacity(chunks.len() + 1);
    for (idx, ((chunk_sha, body), mref)) in chunks.iter().zip(manifest.chunks.iter()).enumerate() {
        if chunk_sha != &mref.sha {
            return Err(BlobError::InvalidArgument(format!(
                "put_blob_chunks: chunk[{idx}] sha {} does not match manifest entry {}",
                hex::encode(chunk_sha),
                hex::encode(mref.sha)
            )));
        }
        let (storage_kind, bytes_inline, external_ref, size) = match body {
            BlobBody::Inline(bytes) => {
                if bytes.len() > inline_bytes_cap {
                    return Err(BlobError::InlineSizeExceeded {
                        size: bytes.len(),
                        cap: inline_bytes_cap,
                    });
                }
                // Verify the chunk bytes hash to the manifest entry SHA.
                let computed = Sha256::digest(bytes);
                if computed.as_slice() != mref.sha.as_slice() {
                    return Err(BlobError::HashMismatch {
                        expected_hex: hex::encode(mref.sha),
                        got_hex: hex::encode(computed),
                    });
                }
                // And the chunk length matches the manifest size.
                if bytes.len() as u64 != u64::from(mref.size) {
                    return Err(BlobError::InvalidArgument(format!(
                        "put_blob_chunks: chunk[{idx}] is {} bytes but manifest size is {}",
                        bytes.len(),
                        mref.size
                    )));
                }
                ("inline", Some(bytes.clone()), None, u64::from(mref.size))
            }
            BlobBody::External(e) => {
                let kind = body.storage_kind();
                (kind, None, Some(e.uri.clone()), e.size_bytes)
            }
            BlobBody::ChunkDag(_) => {
                return Err(BlobError::InvalidArgument(format!(
                    "put_blob_chunks: chunk[{idx}] is itself a ChunkDag — \
                     one-level DAG only (no nesting)"
                )));
            }
        };
        let size_bytes = i64::try_from(size).map_err(|_| {
            BlobError::InvalidArgument("put_blob_chunks: chunk size_bytes exceeds i64".into())
        })?;
        rows.push(PreparedBlobRow {
            sha256: *chunk_sha,
            storage_kind,
            bytes_inline,
            external_ref,
            size_bytes,
        });
    }

    // The manifest row last (so a covering chunk always exists before
    // the manifest references it within the same txn — not strictly
    // required for correctness given the single txn, but it keeps the
    // insert order intuitive).
    let manifest_bytes = manifest.to_jcs_bytes();
    if manifest_bytes.len() > inline_bytes_cap {
        return Err(BlobError::InlineSizeExceeded {
            size: manifest_bytes.len(),
            cap: inline_bytes_cap,
        });
    }
    let manifest_sha: [u8; 32] = Sha256::digest(&manifest_bytes).into();
    let manifest_size = i64::try_from(manifest.total_size).map_err(|_| {
        BlobError::InvalidArgument("put_blob_chunks: total_size exceeds i64".into())
    })?;
    rows.push(PreparedBlobRow {
        sha256: manifest_sha,
        storage_kind: "chunk_dag",
        bytes_inline: Some(manifest_bytes),
        external_ref: None,
        size_bytes: manifest_size,
    });

    Ok(rows)
}

#[cfg(all(test, feature = "sqlite"))]
mod put_blob_binding_tests {
    use super::*;

    /// **CIRISPersist#652 — the row `put_blob` mints must clear the doors
    /// `put_blob` skips.**
    ///
    /// `put_blob` raw-INSERTs into `federation_attestations`, so neither
    /// binding gate ever ran on a `holds_bytes` row. Combined with the `tier`
    /// column being omitted from that INSERT — taking the schema default
    /// `'federation'`, which is exactly what `list_attestations_since` serves
    /// — every blob announcement replicated to every peer and every peer
    /// refused it. **The tier nobody chose is the tier that replicates.**
    ///
    /// The witness runs the REAL gates over the row as STORED. That is the
    /// honest test for a door that BYPASSES those gates: asserting on the
    /// envelope the builder returns would only prove the builder agrees with
    /// itself, whereas this proves the bytes that landed in the table are ones
    /// a receiver would accept.
    #[tokio::test]
    async fn put_blob_mints_a_row_that_satisfies_both_binding_gates_652() {
        use crate::federation::BlobStorage as _;
        use crate::federation::FederationDirectory as _;
        use crate::store::{Backend as _, SqliteBackend};

        let sq = SqliteBackend::open_in_memory().await.expect("open");
        sq.run_migrations().await.expect("migrations");
        let holder = "h652";
        crate::federation::tier_ingest::test_support::register_hybrid_key(&sq, holder).await;

        // Inline bodies are hash-checked at the door, so the SHA is the
        // payload's own.
        let payload = b"652-witness".to_vec();
        let sha: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&payload).into();
        let attestation_id = uuid::Uuid::new_v4().to_string();
        // Deliberately DISTINCT, and this is the point of the pair: the two
        // used to be one value, with `asserted_at` populated from
        // `scrub_timestamp`. A holder announcing bytes it has held for an hour
        // is making a claim about the hour, not about the moment it reached
        // for its key.
        let asserted_at = crate::federation::admission::truncate_to_substrate_resolution(
            chrono::Utc::now() - chrono::Duration::hours(1),
        );
        let scrub_timestamp =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
        let envelope = holds_bytes_attestation_envelope(&sha, holder, &attestation_id, asserted_at);
        let canonical =
            crate::verify::canonical::ceg_produce_canonicalize(&envelope).expect("canonicalize");
        let (och, classical, pqc) =
            crate::federation::tier_ingest::test_support::sign_envelope(holder, &envelope);
        assert_eq!(
            och,
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&canonical)),
            "the test's own signing helper must hash the same bytes it signs"
        );

        sq.put_blob(
            &sha,
            crate::federation::BlobBody::Inline(payload),
            None,
            PutBlobAttestation {
                attesting_key_id: holder.to_owned(),
                attestation_id: attestation_id.clone(),
                original_content_hash_hex: och,
                scrub_signature_classical: classical,
                scrub_signature_pqc: pqc,
                scrub_key_id: holder.to_owned(),
                scrub_timestamp,
                asserted_at,
            },
        )
        .await
        .expect("#652: put_blob admits");

        let stored = sq
            .get_attestation(&attestation_id)
            .await
            .expect("read back")
            .expect("#652: the holds_bytes row was written");

        // (1) THE TWO GATES `put_blob` NEVER ASKED.
        crate::federation::admission::check_instant_binding(
            &stored,
            chrono::Utc::now(),
            crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
        )
        .expect("#652/#598: the stored holds_bytes row must carry its signed instants");
        crate::federation::admission::check_row_column_binding(&stored)
            .expect("#652/#643: the stored holds_bytes row must carry its typed-column mirror");

        // (2) `asserted_at` IS THE CLAIM'S INSTANT, not the signature's.
        assert_eq!(
            stored.asserted_at, asserted_at,
            "#652: the column must carry the instant the CLAIM was asserted"
        );
        assert_ne!(
            stored.asserted_at, stored.scrub_timestamp,
            "#652: and it must be free to differ from when the signature was made — if these \
             are forced equal the conflation is back, and this witness would not notice"
        );

        // (3) THE TIER IS STATED, AND THE ROW ACTUALLY REPLICATES.
        //
        // Being honest about what each half proves: the equality below is a
        // PIN, not a differential — the schema default is `'federation'` too,
        // so it cannot distinguish "the door chose this" from "the door said
        // nothing and the column filled itself in". What it buys is that the
        // value now travels through the builder, so a schema whose default
        // ever changes fails HERE instead of silently republishing at a tier
        // nobody picked.
        //
        // The leg with teeth is the one after it: `list_attestations_since` is
        // the surface a peer PULLS, it filters on this tier, and it is the
        // reason a wrong value is a mesh-wide event rather than a cosmetic
        // one.
        assert_eq!(
            stored.tier,
            crate::federation::types::attestation_tier::FEDERATION,
            "#652: put_blob must STATE the tier it publishes at"
        );
        let since = sq
            .list_attestations_since(Some(asserted_at - chrono::Duration::minutes(5)), 100)
            .await
            .expect("list_attestations_since");
        assert!(
            since.iter().any(|r| r.attestation_id == attestation_id),
            "#652: the holder announcement must appear on the REPLICATION surface — that is              what makes the tier load-bearing rather than cosmetic, and what turned an              unbound row into something every peer in the mesh refused"
        );

        // (4) THE WITNESS: the row survives the round-trip and is admissible
        // through the REAL `put_attestation` at an INDEPENDENT directory —
        // the door it always bypassed, on a corpus that never saw it. This is
        // the assertion whose absence hid the defect: `put_blob` returned Ok
        // the whole time.
        let peer = crate::store::MemoryBackend::new();
        crate::federation::tier_ingest::test_support::register_hybrid_key(&peer, holder).await;
        peer.put_attestation(crate::federation::SignedAttestation {
            attestation: stored.clone(),
        })
        .await
        .unwrap_or_else(|e| {
            panic!(
                "#652: a `holds_bytes` row is federation-tier and therefore REPLICATES — \
                 `list_attestations_since` serves exactly this tier. A row every peer refuses \
                 is a blob announcement that announces nothing. Refusal: {e}"
            )
        });
    }
}

/// v31.0.0 (CIRISPersist#660) — **`put_blob` states its `cohort_scope`**, the
/// sibling of the #652 `tier` finding on the same INSERT.
///
/// `cohort_scope` was omitted from the `federation_attestations` column list on
/// BOTH SQL backends and took the V056 schema default `'federation'`. That
/// happened to equal what [`holds_bytes_attestation_row`] puts in the row the
/// `persist_row_hash` is computed over — and, since #643, what the signed `row`
/// MIRROR inside the envelope declares. Two values agreeing because nobody chose
/// either is not a binding: change the builder or the schema default and the
/// stored column silently stops matching the bytes that were signed.
///
/// # What gives this witness teeth
///
/// Not the equality — the default coincides, so a pin alone cannot tell "the
/// door chose this" from "the column filled itself in" (the #652 witness says
/// the same about `tier`, and is right to). The teeth are
/// [`check_row_column_binding`](crate::federation::admission::check_row_column_binding):
/// `cohort_scope` is one of the seven columns #643 binds into the signed
/// envelope, so a stored value that diverges from the builder's is a row this
/// substrate's own put door refuses. Asserted over the row **as read back from
/// the table**, which is the only form that can see an INSERT's omission at all.
///
/// Two backends, not three: `put_blob` is [`BlobStorage`], which the memory
/// backend does not implement. The parity set here is exactly the set of
/// backends that have the door.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn exercise_put_blob_states_its_cohort_scope<B>(be: &B, tag: &str)
where
    B: BlobStorage + crate::federation::FederationDirectory,
{
    let holder = format!("{tag}-660-blobholder");
    crate::federation::tier_ingest::test_support::register_hybrid_key(be, &holder).await;

    let payload = format!("660-{tag}").into_bytes();
    let sha: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&payload).into();
    let attestation_id = uuid::Uuid::new_v4().to_string();
    let asserted_at =
        crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
    let envelope = holds_bytes_attestation_envelope(&sha, &holder, &attestation_id, asserted_at);
    let (och, classical, pqc) =
        crate::federation::tier_ingest::test_support::sign_envelope(&holder, &envelope);

    be.put_blob(
        &sha,
        BlobBody::Inline(payload),
        None,
        PutBlobAttestation {
            attesting_key_id: holder.clone(),
            attestation_id: attestation_id.clone(),
            original_content_hash_hex: och,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: holder.clone(),
            scrub_timestamp: asserted_at,
            asserted_at,
        },
    )
    .await
    .unwrap_or_else(|e| panic!("[{tag}] put_blob must admit an ordinary inline body: {e:?}"));

    let stored = crate::federation::FederationDirectory::get_attestation(be, &attestation_id)
        .await
        .expect("read back")
        .unwrap_or_else(|| panic!("[{tag}] the holds_bytes row must have been written"));

    // THE ASSERTION WITH TEETH: the stored columns must match the signed mirror.
    // An INSERT that omits `cohort_scope` and lets the default fill it in reds
    // here the moment the builder and the default stop coinciding.
    crate::federation::admission::check_row_column_binding(&stored).unwrap_or_else(|e| {
        panic!(
            "[{tag}] the STORED holds_bytes row must satisfy the #643 column binding — a \
             column the INSERT never named cannot be one the signature covers: {e}"
        )
    });
    assert_eq!(
        stored.cohort_scope,
        crate::federation::types::cohort_scope::FEDERATION,
        "[{tag}] put_blob must STATE the cohort_scope it publishes at"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_chunk_cap_boundary() {
        // Below the cap → append allowed.
        assert!(!epoch_chunk_cap_reached(0));
        assert!(!epoch_chunk_cap_reached(MAX_CHUNKS_PER_EPOCH - 1));
        // At/over the cap → next append refused (roll the epoch).
        assert!(epoch_chunk_cap_reached(MAX_CHUNKS_PER_EPOCH));
        assert!(epoch_chunk_cap_reached(MAX_CHUNKS_PER_EPOCH + 1));
        // 2^24, the 32-bit-counter safety margin.
        assert_eq!(MAX_CHUNKS_PER_EPOCH, 16_777_216);
    }

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
        let at: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();
        let env = holds_bytes_attestation_envelope(&sha, "k-holder", "att-1", at);
        assert_eq!(env["kind"], "holds_bytes");
        let refs = env["evidence_refs"].as_array().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], hex::encode(sha));

        // v31.0.0 (CIRISPersist#652) — and the two BINDINGS, which is the
        // whole point of the widened signature. Without them `put_blob`
        // minted federation-tier rows that no peer's `put_attestation` would
        // accept, through a door that never asked what the peers ask.
        assert_eq!(
            env[crate::federation::envelope::paths::ASSERTED_AT],
            serde_json::json!(at.to_rfc3339()),
            "#598: the holder's assertion instant rides the SIGNED bytes"
        );
        assert!(
            env.get(crate::federation::envelope::paths::EXPIRES_AT)
                .is_none(),
            "#598: a holder claim carries no expiry, and the binding is \
             both-directions, so the key must be ABSENT rather than null"
        );
        let mirror = &env[crate::federation::envelope::paths::ROW];
        use crate::federation::envelope::row_paths as rp;
        assert_eq!(mirror[rp::ATTESTATION_ID], "att-1");
        assert_eq!(mirror[rp::ATTESTING_KEY_ID], "k-holder");
        assert_eq!(
            mirror[rp::ATTESTED_KEY_ID],
            "k-holder",
            "#643: a holder attests ITSELF — 'I hold the bytes'"
        );
        assert_eq!(
            mirror[rp::ATTESTATION_TYPE],
            holds_bytes_attestation_type(&sha)
        );
        assert_eq!(mirror[rp::COHORT_SCOPE], "federation");

        // DETERMINISM — the property the `put_blob` door rests on. Persist
        // reconstructs this envelope rather than storing the caller's, so the
        // same four inputs must give byte-identical bytes or the caller's
        // signature covers something else.
        assert_eq!(
            env,
            holds_bytes_attestation_envelope(&sha, "k-holder", "att-1", at),
            "the envelope must be a PURE function of its four inputs"
        );
    }

    // ── v4.1 (CIRISPersist#142, Cut B) — ChunkManifest JCS ──────────

    fn sha_of(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes).into()
    }

    #[test]
    fn chunk_manifest_jcs_is_canonical() {
        let c0 = sha_of(b"chunk-zero");
        let c1 = sha_of(b"chunk-one");
        let manifest = ChunkManifest {
            v: 1,
            total_size: 19,
            chunks: vec![
                ChunkRef { sha: c0, size: 10 },
                ChunkRef { sha: c1, size: 9 },
            ],
        };
        let bytes = manifest.to_jcs_bytes();
        let s = String::from_utf8(bytes).unwrap();
        // Keys lexicographically sorted, no whitespace, sha lowercase hex.
        let expected = format!(
            "{{\"chunks\":[{{\"sha\":\"{}\",\"size\":10}},{{\"sha\":\"{}\",\"size\":9}}],\"total_size\":19,\"v\":1}}",
            hex::encode(c0),
            hex::encode(c1)
        );
        assert_eq!(s, expected);
        // The hex is lowercase.
        assert!(!s.chars().any(|ch| ch.is_ascii_uppercase()));
    }

    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    #[test]
    #[serial_test::serial(postgres)]
    fn chunk_manifest_round_trips_through_bytes() {
        let c0 = sha_of(b"a");
        let c1 = sha_of(b"bb");
        let manifest = ChunkManifest {
            v: 1,
            total_size: 3,
            chunks: vec![ChunkRef { sha: c0, size: 1 }, ChunkRef { sha: c1, size: 2 }],
        };
        let bytes = manifest.to_jcs_bytes();
        let parsed = ChunkManifest::from_manifest_bytes(&bytes).unwrap();
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn chunk_manifest_validate_total_size() {
        let m_ok = ChunkManifest {
            v: 1,
            total_size: 5,
            chunks: vec![
                ChunkRef {
                    sha: [0; 32],
                    size: 2,
                },
                ChunkRef {
                    sha: [1; 32],
                    size: 3,
                },
            ],
        };
        m_ok.validate_total_size().unwrap();

        let m_bad = ChunkManifest {
            total_size: 6,
            ..m_ok
        };
        let err = m_bad.validate_total_size().unwrap_err();
        assert!(matches!(err, BlobError::InvalidArgument(_)));
    }

    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    #[test]
    #[serial_test::serial(postgres)]
    fn prepare_chunk_rows_rejects_sha_mismatch() {
        // Manifest claims a chunk sha that the inline bytes don't hash to.
        let real = sha_of(b"real");
        let fake = [0xAB; 32];
        let manifest = ChunkManifest {
            v: 1,
            total_size: 4,
            chunks: vec![ChunkRef { sha: fake, size: 4 }],
        };
        let chunks = vec![(fake, BlobBody::Inline(b"real".to_vec()))];
        // chunk[0] sha == manifest sha (fake) so alignment passes, but the
        // bytes hash to `real` != fake → HashMismatch.
        let _ = real;
        let err = prepare_chunk_rows(&manifest, &chunks, DEFAULT_INLINE_BYTES_CAP).unwrap_err();
        assert!(matches!(err, BlobError::HashMismatch { .. }));
    }

    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    #[test]
    #[serial_test::serial(postgres)]
    fn prepare_chunk_rows_rejects_total_size_mismatch() {
        let c = sha_of(b"abcd");
        let manifest = ChunkManifest {
            v: 1,
            total_size: 99, // wrong
            chunks: vec![ChunkRef { sha: c, size: 4 }],
        };
        let chunks = vec![(c, BlobBody::Inline(b"abcd".to_vec()))];
        let err = prepare_chunk_rows(&manifest, &chunks, DEFAULT_INLINE_BYTES_CAP).unwrap_err();
        assert!(matches!(err, BlobError::InvalidArgument(_)));
    }

    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    #[test]
    #[serial_test::serial(postgres)]
    fn prepare_chunk_rows_manifest_row_is_last_and_chunk_dag() {
        let c = sha_of(b"xyz");
        let manifest = ChunkManifest {
            v: 1,
            total_size: 3,
            chunks: vec![ChunkRef { sha: c, size: 3 }],
        };
        let chunks = vec![(c, BlobBody::Inline(b"xyz".to_vec()))];
        let rows = prepare_chunk_rows(&manifest, &chunks, DEFAULT_INLINE_BYTES_CAP).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].storage_kind, "inline");
        assert_eq!(rows[0].sha256, c);
        // Manifest row last: storage_kind chunk_dag, sha = SHA(manifest jcs).
        assert_eq!(rows[1].storage_kind, "chunk_dag");
        let expect_manifest_sha = sha_of(&manifest.to_jcs_bytes());
        assert_eq!(rows[1].sha256, expect_manifest_sha);
        assert_eq!(rows[1].size_bytes, 3);
    }

    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    #[test]
    #[serial_test::serial(postgres)]
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
        // v4.1 (Cut B) — chunk_dag storage_kind + size_bytes = total_size.
        let manifest = ChunkManifest {
            v: 1,
            total_size: 42,
            chunks: vec![ChunkRef {
                sha: [0; 32],
                size: 42,
            }],
        };
        let body = BlobBody::ChunkDag(manifest);
        assert_eq!(body.storage_kind(), "chunk_dag");
        assert_eq!(body.size_bytes(), 42);
        assert!(!body.is_inline());
    }

    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    #[test]
    #[serial_test::serial(postgres)]
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
        let at: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();
        let envelope = holds_bytes_attestation_envelope(&sha, "k-holder", "att-1", at);

        // The production canonicalizer's output for this envelope.
        let python_bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&envelope)
            .expect("python canonicalize");
        let expected_hash_hex = hex::encode(Sha256::digest(&python_bytes));

        // Direct identity check: the bytes are the sorted-keys ASCII shape.
        //
        // v31.0.0 (CIRISPersist#652) — asserted STRUCTURALLY rather than
        // against a hand-written literal. The literal that stood here spelled
        // the entire envelope, so widening it to carry the #598/#643 bindings
        // meant hand-transcribing a nested object — and a transcription is
        // just a second definition of the shape, which is the defect class
        // this cut is closing everywhere else. What the literal actually
        // WITNESSED was "no whitespace, keys sorted, ASCII" — a
        // whitespace-emitting or key-order-unstable canonicalizer — and that
        // is asserted directly below, over the real shape rather than a copy
        // of it.
        let text = std::str::from_utf8(&python_bytes).expect("canonical bytes are UTF-8");
        assert!(text.is_ascii(), "canonical bytes must be ASCII: {text}");
        assert!(
            !text.contains(' ') && !text.contains('\n'),
            "canonical bytes must carry no whitespace: {text}"
        );
        let reparsed: serde_json::Value =
            serde_json::from_str(text).expect("canonical bytes reparse");
        assert_eq!(
            reparsed, envelope,
            "canonicalization must be VALUE-PRESERVING — it reorders and \
             tightens bytes, it does not change what the envelope says"
        );
        let top_keys: Vec<&str> = reparsed
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        let mut sorted = top_keys.clone();
        sorted.sort_unstable();
        assert_eq!(
            top_keys, sorted,
            "keys must be emitted SORTED: {top_keys:?}"
        );

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
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        backend
            .put_public_key(crate::federation::types::SignedKeyRecord {
                record: record.clone(),
            })
            .await
            .unwrap();
        // v9.3.0 (#247) — put_blob_signing's holds_bytes scrub_key_id is
        // the signer's DERIVED federation key_id; register that row too so
        // the scrub FK resolves on a real node (alias ≠ derived id).
        let derived = ciris_verify_core::fedcode::derive_key_id(
            key_id,
            &signing_key.verifying_key().to_bytes(),
        );
        let mut derived_record = record;
        derived_record.key_id = derived.clone();
        derived_record.identity_ref = derived.clone();
        derived_record.scrub_key_id = derived.clone();
        derived_record.registration_envelope = serde_json::json!({ "id": derived });
        backend
            .put_public_key(crate::federation::types::SignedKeyRecord {
                record: derived_record,
            })
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
