//! `FSD/BLOB_ENCRYPTION_AT_REST.md` §12 — **chunked content under the
//! envelope** (CIRISPersist#832).
//!
//! §10 sealed a whole body under one envelope; `V4_1_STREAMING_SUBSTRATE.md`
//! made a body many rows. This module is the crossing:
//!
//! - **a chunk is a whole blob** — its own `AtRestEnvelope`, content-addressed
//!   by its CIPHERTEXT, its row recording the tier the door resolved;
//! - **the manifest is sealed under the same DEK** (`ChunkManifest` v2:
//!   ciphertext shas, PLAINTEXT sizes), so the `chunk_dag` row carries
//!   `crypto_tier` like any other row and the door / reader dispatch on the
//!   column, never on bytes (I2);
//! - **the seal door checks the chunk ROWS** — a DAG whose chunks are not all
//!   at its tier is refused (I32);
//! - **reads authorize first, then open per chunk** — the decrypting range
//!   read maps a plaintext range to a chunk set and seeks in O(segment) (I34);
//! - **the transfer path never decrypts** (I36, a from-disk gate).
//!
//! The doors are free functions in [`orchestrate`] shared by the Engine and
//! the PyO3 surface. The storage floor they reach
//! (`put_blob_chunk_with_scope`, `seal_stream_with_scope`) takes a
//! `StorageFloor` token, unconstructible outside the crate (I22); I14 lists
//! this file as the floor's only permitted caller.

use crate::federation::blobs::{BlobBody, BlobError, BlobStorage};
use crate::federation::types::cohort_scope::CryptoTier;

/// §12.4 — the largest content the WHOLE-read door (`read_any_for_viewer`)
/// will materialize for a DAG: 64 MiB, i.e. 64 chunks at the 1 MiB inline
/// cap. Above it the door refuses with `InvalidArgument` naming this cap and
/// the range door — a video is read by range, never assembled whole inside a
/// request handler. A judgement, recorded in §12.4.
pub const DAG_WHOLE_READ_CAP_BYTES: u64 = 64 * 1024 * 1024;

/// #838 (§12.10) — the domain-separation label of a chunk's AAD.
pub const CHUNK_AAD_DOMAIN: &[u8] = b"ciris-persist:chunk:v1";

/// #838 (§12.10) — **a chunk's associated data is its position.** The bytes
/// every sealed chunk is bound to at write and every reader rebuilds:
///
/// ```text
/// "ciris-persist:chunk:v1"
///   ‖ u64_be(len(caller_aad)) ‖ caller_aad      (absent ⇒ length 0)
///   ‖ u64_be(len(stream_id))  ‖ stream_id       (UTF-8)
///   ‖ u64_be(seq)
/// ```
///
/// Domain-separated (a chunk's AAD can never collide with a caller's own
/// bytes on a whole blob or a manifest) and length-prefixed (no boundary
/// ambiguity between the caller's data and the stream id). Pure, no backend
/// `cfg`; its bytes are pinned by `tests::chunk_aad_bytes_are_pinned`. The
/// manifest's own AAD stays the caller's — it has no position.
#[must_use]
pub fn chunk_aad(caller_aad: Option<&[u8]>, stream_id: &str, seq: u64) -> Vec<u8> {
    let caller = caller_aad.unwrap_or(&[]);
    let mut out =
        Vec::with_capacity(CHUNK_AAD_DOMAIN.len() + 8 + caller.len() + 8 + stream_id.len() + 8);
    out.extend_from_slice(CHUNK_AAD_DOMAIN);
    out.extend_from_slice(&(caller.len() as u64).to_be_bytes());
    out.extend_from_slice(caller);
    out.extend_from_slice(&(stream_id.len() as u64).to_be_bytes());
    out.extend_from_slice(stream_id.as_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out
}

/// What `put_blob_chunk_scoped` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutChunkScopedResult {
    /// The chunk row's content address — of the CIPHERTEXT at a sealed tier.
    pub chunk_sha256: [u8; 32],
    /// The tier the door resolved from the directory.
    pub tier: CryptoTier,
    /// The community DEK epoch the chunk was sealed under (community tiers).
    pub epoch: Option<u64>,
    /// Occurrences granted a wrap of the DEK.
    pub granted: Vec<String>,
    /// Occurrences fail-secure excluded (no valid `encryption_pubkeys`).
    pub excluded: Vec<String>,
}

/// What `seal_stream_scoped` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealStreamScopedResult {
    /// The DAG's content address — of the sealed manifest bytes at a sealed
    /// tier, of the JCS manifest at `Plaintext`.
    pub manifest_sha256: [u8; 32],
    /// The tier the door resolved.
    pub tier: CryptoTier,
    /// The community DEK epoch the manifest was sealed under.
    pub epoch: Option<u64>,
    /// How many chunks the manifest lists.
    pub chunk_count: u64,
    /// The DAG's PLAINTEXT total.
    pub total_size: u64,
    /// Occurrences granted a wrap of the manifest's DEK.
    pub granted: Vec<String>,
    /// Occurrences fail-secure excluded.
    pub excluded: Vec<String>,
}

/// The doors and the reads. Free functions over any backend that is both a
/// `FederationDirectory` and a `BlobStorage`, so the Engine and PyO3 share
/// one body.
pub mod orchestrate {
    use super::*;
    use crate::federation::at_rest_cascade::orchestrate::{
        authorize_viewer_by_tier, grant_dek_to_cohort, read_for_viewer_sealed,
    };
    use crate::federation::at_rest_cascade::{
        fresh_dek, resolve_write_tier, seal, sealed_plaintext_len, AtRestEnvelope, AtRestError,
    };
    use crate::federation::blobs::{
        BlobHead, ChunkManifest, ChunkRef, EpochBinding, ManifestRowSpec, StreamChunkRef,
        StreamClaim, CHUNK_MANIFEST_VERSION, CHUNK_MANIFEST_VERSION_SEALED,
    };
    use crate::federation::community_dek::orchestrate::{
        ensure_epoch_dek, open_community_row_as_persist, read_for_community_viewer_sealed,
    };
    use crate::federation::{FederationDirectory, StorageFloor};
    use sha2::{Digest, Sha256};

    fn map_at_rest_err(e: AtRestError) -> BlobError {
        BlobError::Backend(e.to_string())
    }

    /// How many times a community write re-seals under a fresher epoch
    /// when a rotation lands between reading the pointer and binding
    /// (§11.4 / I17). The same bound the whole-blob cascade uses.
    const EPOCH_RACE_ATTEMPTS: usize = 3;

    // ── the chunk door ───────────────────────────────────────────────────

    /// §12.3 — **append one PLAINTEXT segment to a live stream at
    /// `cohort_scope`, sealed where the tier requires it.**
    ///
    /// The tier is resolved from the DIRECTORY (`resolve_write_tier`), the
    /// plaintext is screened once by the matcher (I21), and then:
    /// - `Plaintext` → the bytes as given through the chunk floor;
    /// - `InvisibleEncrypted` → a fresh per-chunk DEK, `seal`, the envelope
    ///   through the floor, then persist's self-retention wrap and a v2 wrap
    ///   to every active occurrence of `community_key_id` (the owner / family
    ///   key) — the grants a whole blob gets, on the chunk row;
    /// - `CommunityDek` → `ensure_epoch_dek` at the CURRENT epoch, `seal`,
    ///   the envelope through the floor WITH the epoch binding in the same
    ///   transaction; a rotation racing the append refuses the whole append
    ///   and this loop re-seals under the new epoch (I17).
    ///
    /// `epoch` is the producer's stream epoch label (the nonce-cap axis) and
    /// is recorded as given; which DEK sealed a community chunk is the chunk
    /// row's binding — a separate fact.
    ///
    /// `signer` is the WRITER (#837, §12.9): its derived key id is the
    /// stream's owner on the first append and must match on every later
    /// one; a foreign writer is refused at its first chunk. `aad` (#831) is
    /// the caller's associated data; at a sealed tier the chunk is bound to
    /// `chunk_aad(aad, stream_id, seq)` — its position — not to `aad` alone
    /// (#838, §12.10).
    #[allow(clippy::too_many_arguments)]
    pub async fn put_blob_chunk_scoped<B>(
        backend: &B,
        signer: &dyn ciris_keyring::HardwareSigner,
        cohort_scope: &str,
        community_key_id: Option<&str>,
        stream_id: &str,
        seq: u64,
        plaintext: &[u8],
        epoch: u64,
        aad: Option<&[u8]>,
    ) -> Result<PutChunkScopedResult, BlobError>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let tier = resolve_write_tier(backend, cohort_scope, community_key_id).await?;
        // #837 (§12.9) — the writer, derived from the signer (never an
        // alias, I23): the stream's owner on its first append.
        let owner_key_id = crate::signing::federation_key_id_of(signer)
            .await
            .map_err(|e| {
                BlobError::Backend(format!("put_blob_chunk_scoped: signer key id: {e}"))
            })?;
        let claim = || StreamClaim {
            community_key_id: community_key_id.map(str::to_owned),
            owner_key_id: Some(owner_key_id.clone()),
        };
        // §11.2 (5) / I21 — the matcher sees the PLAINTEXT, once, before
        // anything is sealed; the chunk floor never screens.
        let plain_sha: [u8; 32] = Sha256::digest(plaintext).into();
        backend.screen_inline_body(&plain_sha, plaintext).await?;
        let plaintext_size = plaintext.len() as u64;
        // #838 (§12.10) — a sealed chunk's AAD is its POSITION.
        let bound_aad = chunk_aad(aad, stream_id, seq);
        match tier {
            CryptoTier::Plaintext => {
                crate::federation::at_rest_cascade::refuse_aad_at_plaintext(&plain_sha, aad)?;
                let sha = backend
                    .put_blob_chunk_with_scope(
                        stream_id,
                        seq,
                        BlobBody::Inline(plaintext.to_vec()),
                        epoch,
                        plaintext_size,
                        cohort_scope,
                        StorageFloor::resolved(CryptoTier::Plaintext),
                        None,
                        claim(),
                    )
                    .await?;
                Ok(PutChunkScopedResult {
                    chunk_sha256: sha,
                    tier,
                    epoch: None,
                    granted: Vec::new(),
                    excluded: Vec::new(),
                })
            }
            CryptoTier::InvisibleEncrypted => {
                let owner = community_key_id.ok_or_else(|| {
                    BlobError::InvalidArgument(format!(
                        "cohort_scope {cohort_scope:?} requires the owner (self) or family key id \
                         in the community_key_id argument"
                    ))
                })?;
                let dek = fresh_dek().map_err(map_at_rest_err)?;
                let envelope = seal(&dek, plaintext, Some(&bound_aad)).map_err(map_at_rest_err)?;
                let sha = backend
                    .put_blob_chunk_with_scope(
                        stream_id,
                        seq,
                        BlobBody::Inline(envelope.to_bytes()),
                        epoch,
                        plaintext_size,
                        cohort_scope,
                        StorageFloor::resolved(CryptoTier::InvisibleEncrypted),
                        None,
                        claim(),
                    )
                    .await?;
                let (granted, excluded) =
                    grant_dek_to_cohort(backend, &sha, cohort_scope, owner, &dek).await?;
                Ok(PutChunkScopedResult {
                    chunk_sha256: sha,
                    tier,
                    epoch: None,
                    granted,
                    excluded,
                })
            }
            CryptoTier::CommunityDek => {
                let comm = community_key_id.ok_or_else(|| {
                    BlobError::InvalidArgument("community_key_id required".into())
                })?;
                let mut last_epoch = 0;
                for _ in 0..EPOCH_RACE_ATTEMPTS {
                    let dek_epoch = backend.community_dek_current_epoch(comm).await?;
                    let (dek, granted, excluded) =
                        ensure_epoch_dek(backend, comm, dek_epoch).await?;
                    let envelope =
                        seal(&dek, plaintext, Some(&bound_aad)).map_err(map_at_rest_err)?;
                    match backend
                        .put_blob_chunk_with_scope(
                            stream_id,
                            seq,
                            BlobBody::Inline(envelope.to_bytes()),
                            epoch,
                            plaintext_size,
                            cohort_scope,
                            StorageFloor::resolved(CryptoTier::CommunityDek),
                            Some(EpochBinding {
                                community_key_id: comm.to_owned(),
                                epoch: dek_epoch,
                            }),
                            claim(),
                        )
                        .await
                    {
                        Ok(sha) => {
                            return Ok(PutChunkScopedResult {
                                chunk_sha256: sha,
                                tier,
                                epoch: Some(dek_epoch),
                                granted,
                                excluded,
                            })
                        }
                        Err(BlobError::EpochNotCurrent { .. }) => {
                            tracing::debug!(
                                community = %comm,
                                epoch = dek_epoch,
                                stream = %stream_id,
                                seq,
                                "chunk cascade: epoch moved under an append; nothing stored, re-sealing"
                            );
                            last_epoch = dek_epoch;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(BlobError::EpochNotCurrent {
                    community_key_id: comm.to_owned(),
                    epoch: last_epoch,
                })
            }
        }
    }

    // ── the seal door ────────────────────────────────────────────────────

    /// §12.3 — **seal a live stream into a `chunk_dag` at `cohort_scope`,
    /// checking the chunk ROWS first (I32).**
    ///
    /// Resolves the tier from the directory, lists the stream through
    /// `stream_chunks`, and refuses unless every chunk row's recorded tier
    /// and cohort are the DAG's (and, for a community, every chunk's binding
    /// names `community_key_id`). Only then it builds the manifest — v2 with
    /// plaintext sizes for a sealed tier, v1 for `Plaintext` — seals it under
    /// the DAG's DEK, stores the row through the manifest floor (binding
    /// in-transaction for a community; self-retention + occurrence grants
    /// for `self` / `family`), and announces `holds_bytes` for the manifest
    /// under `signer`'s derived key at `Plaintext` and `CommunityDek`, as
    /// `put_blob_scoped` does. `InvisibleEncrypted` announces nothing.
    ///
    /// `aad` is the #831 hook for the manifest's seal.
    pub async fn seal_stream_scoped<B>(
        backend: &B,
        signer: &dyn ciris_keyring::HardwareSigner,
        cohort_scope: &str,
        community_key_id: Option<&str>,
        stream_id: &str,
        media_type: Option<&str>,
        aad: Option<&[u8]>,
    ) -> Result<SealStreamScopedResult, BlobError>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let tier = resolve_write_tier(backend, cohort_scope, community_key_id).await?;
        let listing = backend.stream_chunks(stream_id).await?;
        if listing.chunks.is_empty() {
            return Err(BlobError::InvalidArgument(format!(
                "stream {stream_id} has no chunks"
            )));
        }
        let signer_key_id = crate::signing::federation_key_id_of(signer)
            .await
            .map_err(|e| BlobError::Backend(format!("seal_stream_scoped: signer key id: {e}")))?;
        // #837 (§12.9 / I41) — the stream's ROW first: a seal by a signer
        // that is not the owner, or at a cohort / community that is not
        // the stream's, is refused before any chunk row is looked at.
        check_stream_head_matches(
            listing.stream.as_ref(),
            stream_id,
            cohort_scope,
            community_key_id,
            &signer_key_id,
            "seal_stream_scoped",
        )?;
        // I32 — the door checks the ROWS, not the stream's word.
        check_chunk_rows_match_dag(
            backend,
            &listing.chunks,
            tier,
            cohort_scope,
            community_key_id,
        )
        .await?;
        let manifest = build_manifest(stream_id, &listing.chunks, tier)?;
        let chunk_count = listing.chunks.len() as u64;
        let total_size = manifest.total_size;
        let jcs = manifest.to_jcs_bytes();
        let now = chrono::Utc::now();

        match tier {
            CryptoTier::Plaintext => {
                let sha: [u8; 32] = Sha256::digest(&jcs).into();
                crate::federation::at_rest_cascade::refuse_aad_at_plaintext(&sha, aad)?;
                backend
                    .seal_stream_with_scope(
                        stream_id,
                        ManifestRowSpec {
                            sha256: sha,
                            body: jcs.clone(),
                            size_bytes: total_size,
                            expected_chunk_count: chunk_count,
                        },
                        media_type,
                        cohort_scope,
                        StorageFloor::resolved(CryptoTier::Plaintext),
                        None,
                    )
                    .await?;
                // Announce the manifest under the signer's derived key. The
                // row already exists; the signing floor's insert is a no-op
                // on conflict and the attestation is what this adds.
                backend
                    .put_blob_signing_at(
                        cohort_scope,
                        StorageFloor::resolved(CryptoTier::Plaintext),
                        &sha,
                        BlobBody::Inline(jcs),
                        media_type,
                        &signer_key_id,
                        signer,
                        now,
                        uuid::Uuid::new_v4(),
                    )
                    .await?;
                Ok(SealStreamScopedResult {
                    manifest_sha256: sha,
                    tier,
                    epoch: None,
                    chunk_count,
                    total_size,
                    granted: Vec::new(),
                    excluded: Vec::new(),
                })
            }
            CryptoTier::InvisibleEncrypted => {
                let owner = community_key_id.ok_or_else(|| {
                    BlobError::InvalidArgument(format!(
                        "cohort_scope {cohort_scope:?} requires the owner (self) or family key id \
                         in the community_key_id argument"
                    ))
                })?;
                let dek = fresh_dek().map_err(map_at_rest_err)?;
                let body = seal(&dek, &jcs, aad).map_err(map_at_rest_err)?.to_bytes();
                let sha: [u8; 32] = Sha256::digest(&body).into();
                backend
                    .seal_stream_with_scope(
                        stream_id,
                        ManifestRowSpec {
                            sha256: sha,
                            size_bytes: body.len() as u64,
                            body,
                            expected_chunk_count: chunk_count,
                        },
                        media_type,
                        cohort_scope,
                        StorageFloor::resolved(CryptoTier::InvisibleEncrypted),
                        None,
                    )
                    .await?;
                let (granted, excluded) =
                    grant_dek_to_cohort(backend, &sha, cohort_scope, owner, &dek).await?;
                Ok(SealStreamScopedResult {
                    manifest_sha256: sha,
                    tier,
                    epoch: None,
                    chunk_count,
                    total_size,
                    granted,
                    excluded,
                })
            }
            CryptoTier::CommunityDek => {
                let comm = community_key_id.ok_or_else(|| {
                    BlobError::InvalidArgument("community_key_id required".into())
                })?;
                let mut last_epoch = 0;
                for _ in 0..EPOCH_RACE_ATTEMPTS {
                    let dek_epoch = backend.community_dek_current_epoch(comm).await?;
                    let (dek, granted, excluded) =
                        ensure_epoch_dek(backend, comm, dek_epoch).await?;
                    let body = seal(&dek, &jcs, aad).map_err(map_at_rest_err)?.to_bytes();
                    let sha: [u8; 32] = Sha256::digest(&body).into();
                    match backend
                        .seal_stream_with_scope(
                            stream_id,
                            ManifestRowSpec {
                                sha256: sha,
                                size_bytes: body.len() as u64,
                                body: body.clone(),
                                expected_chunk_count: chunk_count,
                            },
                            media_type,
                            cohort_scope,
                            StorageFloor::resolved(CryptoTier::CommunityDek),
                            Some(EpochBinding {
                                community_key_id: comm.to_owned(),
                                epoch: dek_epoch,
                            }),
                        )
                        .await
                    {
                        Ok(()) => {
                            // Announce the SEALED manifest: community content
                            // federates with cleartext provenance (§11.2 (3)).
                            // The sealed-tier token announces a row the floor
                            // already stored and bound (I28).
                            backend
                                .put_blob_signing_at(
                                    cohort_scope,
                                    StorageFloor::resolved(CryptoTier::CommunityDek),
                                    &sha,
                                    BlobBody::Inline(body),
                                    media_type,
                                    &signer_key_id,
                                    signer,
                                    now,
                                    uuid::Uuid::new_v4(),
                                )
                                .await?;
                            return Ok(SealStreamScopedResult {
                                manifest_sha256: sha,
                                tier,
                                epoch: Some(dek_epoch),
                                chunk_count,
                                total_size,
                                granted,
                                excluded,
                            });
                        }
                        Err(BlobError::EpochNotCurrent { .. }) => {
                            last_epoch = dek_epoch;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(BlobError::EpochNotCurrent {
                    community_key_id: comm.to_owned(),
                    epoch: last_epoch,
                })
            }
        }
    }

    /// I32 — every chunk row must be at the DAG's tier and cohort, and for a
    /// community, bound to the community being sealed.
    async fn check_chunk_rows_match_dag<B>(
        backend: &B,
        chunks: &[StreamChunkRef],
        tier: CryptoTier,
        cohort_scope: &str,
        community_key_id: Option<&str>,
    ) -> Result<(), BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        for c in chunks {
            if c.crypto_tier != tier {
                return Err(BlobError::InvalidArgument(format!(
                    "seal_stream_scoped: chunk seq {} ({}) is recorded at tier {:?}, but this DAG \
                     resolves to {tier:?}; a DAG whose chunks are not all at its tier is refused \
                     (BLOB_ENCRYPTION_AT_REST.md §12.3, I32)",
                    c.seq,
                    hex::encode(c.chunk_sha),
                    c.crypto_tier
                )));
            }
            if c.cohort_scope != cohort_scope {
                return Err(BlobError::InvalidArgument(format!(
                    "seal_stream_scoped: chunk seq {} is recorded under cohort {:?}, but this DAG \
                     is being sealed under {cohort_scope:?} (BLOB_ENCRYPTION_AT_REST.md §12.3, I32)",
                    c.seq, c.cohort_scope
                )));
            }
            if tier == CryptoTier::CommunityDek {
                let comm = community_key_id.unwrap_or_default();
                match backend.community_dek_blob_epoch(&c.chunk_sha).await? {
                    Some((bound, _)) if bound == comm => {}
                    Some((bound, _)) => {
                        return Err(BlobError::InvalidArgument(format!(
                            "seal_stream_scoped: chunk seq {} is bound to community {bound:?}, not \
                             {comm:?} (BLOB_ENCRYPTION_AT_REST.md §12.3, I32)",
                            c.seq
                        )))
                    }
                    None => {
                        return Err(BlobError::Backend(format!(
                            "seal_stream_scoped: chunk seq {} is recorded at community_dek but \
                             carries no epoch binding — corruption",
                            c.seq
                        )))
                    }
                }
            }
        }
        Ok(())
    }

    /// #837 (§12.9 / I41) — **the stream's row is the first guard at the
    /// seal.** `None` (a stream with chunks but no row) cannot arise after
    /// V143 — the floor writes the row in the first chunk's transaction and
    /// the backfill covers every older stream — so it is corruption, not a
    /// pass. An owner that is not the signer is refused WITHOUT naming the
    /// owner; a `NULL` owner (unclaimed) admits any signer.
    fn check_stream_head_matches(
        head: Option<&crate::federation::StreamHead>,
        stream_id: &str,
        cohort_scope: &str,
        community_key_id: Option<&str>,
        signer_key_id: &str,
        door: &str,
    ) -> Result<(), BlobError> {
        let Some(head) = head else {
            return Err(BlobError::Backend(format!(
                "{door}: stream {stream_id} has chunk rows but no federation_streams row — \
                 corruption (V143 writes it with the first chunk and backfills the rest)"
            )));
        };
        if head.cohort_scope != cohort_scope || head.community_key_id.as_deref() != community_key_id
        {
            return Err(BlobError::InvalidArgument(format!(
                "{door}: stream {stream_id} belongs to cohort {:?}, community {:?}; this call \
                 names cohort {cohort_scope:?}, community {community_key_id:?} \
                 (BLOB_ENCRYPTION_AT_REST.md §12.9, I41)",
                head.cohort_scope, head.community_key_id
            )));
        }
        if let Some(owner) = head.owner_key_id.as_deref() {
            if owner != signer_key_id {
                return Err(BlobError::InvalidArgument(format!(
                    "{door}: stream {stream_id} belongs to another writer (cohort {:?}, \
                     community {:?}); a seal by a different key is refused \
                     (BLOB_ENCRYPTION_AT_REST.md §12.9, I41)",
                    head.cohort_scope, head.community_key_id
                )));
            }
        }
        Ok(())
    }

    /// The manifest over a listing: v2 with `chunk_tier`, `stream_id` and
    /// each chunk's `seq` for a sealed tier (#838), v1 for plaintext; sizes
    /// are PLAINTEXT sizes either way.
    fn build_manifest(
        stream_id: &str,
        chunks: &[StreamChunkRef],
        tier: CryptoTier,
    ) -> Result<ChunkManifest, BlobError> {
        let mut total_size: u64 = 0;
        let mut refs = Vec::with_capacity(chunks.len());
        let positioned = tier != CryptoTier::Plaintext;
        for c in chunks {
            let size = u32::try_from(c.plaintext_size).map_err(|_| {
                BlobError::InvalidArgument(format!(
                    "seal_stream_scoped: chunk seq {} plaintext size {} does not fit u32",
                    c.seq, c.plaintext_size
                ))
            })?;
            total_size = total_size.checked_add(u64::from(size)).ok_or_else(|| {
                BlobError::InvalidArgument("seal_stream_scoped: total_size overflow".into())
            })?;
            refs.push(ChunkRef {
                sha: c.chunk_sha,
                size,
                seq: positioned.then_some(c.seq),
            });
        }
        let (v, chunk_tier, stream_id) = match tier {
            CryptoTier::Plaintext => (CHUNK_MANIFEST_VERSION, None, None),
            sealed => (
                CHUNK_MANIFEST_VERSION_SEALED,
                Some(sealed),
                Some(stream_id.to_owned()),
            ),
        };
        Ok(ChunkManifest {
            v,
            total_size,
            chunks: refs,
            chunk_tier,
            stream_id,
        })
    }

    // ── the reads ────────────────────────────────────────────────────────

    /// §12.4 — **the decrypting range read**, the door beside
    /// `read_any_for_viewer`. Order: row head → authorize by tier → bounds
    /// against the PLAINTEXT total → dispatch on `(storage_kind,
    /// crypto_tier)`. A sealed DAG opens only the covering chunks; a sealed
    /// whole blob is opened and sliced (no seek — that is what a DAG is for);
    /// a plaintext row or DAG is `get_blob_range`. Every chunk it opens is
    /// checked against the CHUNK ROW: tier, sha, viewer's grant on the
    /// chunk's epoch / row (I38), opened length.
    ///
    /// `start > end_inclusive` ⇒ `InvalidArgument`; `start ≥ total` ⇒
    /// `RangeNotSatisfiable { size: total }`; `end_inclusive` is clamped.
    pub async fn read_any_range_for_viewer<B>(
        backend: &B,
        sha256: &[u8; 32],
        viewer_key_id: &str,
        range_start: u64,
        range_end_inclusive: u64,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        if range_start > range_end_inclusive {
            return Err(BlobError::InvalidArgument("range_start > range_end".into()));
        }
        // 1. The ROW says what this is (§11.1). No row ⇒ the shared refusal
        //    (#833 / I31): swept or never ours, told only to an authorized viewer.
        let Some(head) = backend.blob_head(sha256).await? else {
            return Err(
                crate::federation::at_rest_cascade::orchestrate::refuse_missing_row(
                    backend,
                    sha256,
                    viewer_key_id,
                )
                .await?,
            );
        };
        // 2. AUTHORIZE BY TIER, BEFORE TOUCHING ANY BODY (§11.3 / I4).
        authorize_viewer_by_tier(backend, sha256, head.crypto_tier, viewer_key_id).await?;
        // 3. Dispatch on the columns.
        match (head.storage_kind.as_str(), head.crypto_tier) {
            ("s3" | "external_url", _) => Err(BlobError::InvalidArgument(format!(
                "blob {} is an External reference; persist does not dereference it — \
                 use get_blob to obtain the ref",
                hex::encode(sha256)
            ))),
            ("chunk_dag", _) => {
                read_dag_for_viewer_authorized(
                    backend,
                    sha256,
                    &head,
                    viewer_key_id,
                    Some((range_start, range_end_inclusive)),
                    aad,
                )
                .await
            }
            (_, CryptoTier::Plaintext) => {
                crate::federation::at_rest_cascade::refuse_aad_at_plaintext(sha256, aad)?;
                let total = head.size_bytes;
                let end = clamp_range(range_start, range_end_inclusive, total)?;
                match backend.get_blob_range(sha256, range_start, end).await? {
                    Some(crate::federation::BlobRange::Inline(b)) => Ok(b),
                    Some(crate::federation::BlobRange::External { .. }) => {
                        Err(BlobError::InvalidArgument(format!(
                            "blob {} is an External reference",
                            hex::encode(sha256)
                        )))
                    }
                    None => Err(BlobError::NotHeld {
                        sha256_hex: hex::encode(sha256),
                    }),
                }
            }
            (_, tier) => {
                // A sealed whole blob: the plaintext total is the envelope's
                // content length; open once, slice.
                let total = sealed_plaintext_len(head.size_bytes).ok_or_else(|| {
                    BlobError::Backend(format!(
                        "blob {} is recorded at tier {tier:?} but is shorter than an envelope",
                        hex::encode(sha256)
                    ))
                })?;
                let end = clamp_range(range_start, range_end_inclusive, total)?;
                let bytes =
                    read_sealed_inline_authorized(backend, sha256, tier, viewer_key_id, aad)
                        .await?;
                if bytes.len() as u64 != total {
                    return Err(BlobError::Backend(format!(
                        "blob {} opened to {} bytes but its row implies {total}",
                        hex::encode(sha256),
                        bytes.len()
                    )));
                }
                Ok(bytes[range_start as usize..=end as usize].to_vec())
            }
        }
    }

    /// RFC 9110 §14.4: `start ≥ size` is not satisfiable; the end is clamped.
    fn clamp_range(start: u64, end_inclusive: u64, size: u64) -> Result<u64, BlobError> {
        if start >= size {
            return Err(BlobError::RangeNotSatisfiable {
                range_start: start,
                size,
            });
        }
        Ok(end_inclusive.min(size - 1))
    }

    /// Open a sealed INLINE row for a viewer the caller has already
    /// authorized at the row (the door's step 2). Community rows open under
    /// their own binding's epoch via `read_for_community_viewer_sealed`
    /// (which re-checks the grant — defense in depth); self/family rows via
    /// the self-retention grant.
    async fn read_sealed_inline_authorized<B>(
        backend: &B,
        sha256: &[u8; 32],
        tier: CryptoTier,
        viewer_key_id: &str,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        let Some(BlobBody::Inline(bytes)) = backend.get_blob(sha256).await? else {
            return Err(BlobError::NotHeld {
                sha256_hex: hex::encode(sha256),
            });
        };
        let envelope = AtRestEnvelope::from_bytes(&bytes).map_err(|e| {
            BlobError::Backend(format!(
                "blob {} is recorded at tier {tier:?} but its body is not an at-rest envelope \
                 ({e}) — corruption, not plaintext",
                hex::encode(sha256)
            ))
        })?;
        match tier {
            CryptoTier::Plaintext => Ok(bytes),
            CryptoTier::InvisibleEncrypted => {
                read_for_viewer_sealed(backend, sha256, &envelope, aad).await
            }
            CryptoTier::CommunityDek => {
                read_for_community_viewer_sealed(backend, sha256, viewer_key_id, &envelope, aad)
                    .await
            }
        }
    }

    /// §12.4 — the DAG read for a viewer ALREADY authorized on the manifest
    /// row. `range = None` is the whole read (capped by
    /// [`DAG_WHOLE_READ_CAP_BYTES`]); `Some((start, end))` maps the
    /// PLAINTEXT range to the covering chunk set. Called by
    /// `read_any_for_viewer` and by [`read_any_range_for_viewer`].
    pub(crate) async fn read_dag_for_viewer_authorized<B>(
        backend: &B,
        sha256: &[u8; 32],
        head: &BlobHead,
        viewer_key_id: &str,
        range: Option<(u64, u64)>,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        read_dag_for_viewer_authorized_capped(
            backend,
            sha256,
            head,
            viewer_key_id,
            range,
            aad,
            DAG_WHOLE_READ_CAP_BYTES,
        )
        .await
    }

    /// [`read_dag_for_viewer_authorized`] with the whole-read cap as a
    /// parameter, so I35's witness can drive the refusal without
    /// materializing 64 MiB. Production passes the constant (pinned by
    /// `tests::the_whole_read_door_passes_the_cap_constant`).
    pub(crate) async fn read_dag_for_viewer_authorized_capped<B>(
        backend: &B,
        sha256: &[u8; 32],
        head: &BlobHead,
        viewer_key_id: &str,
        range: Option<(u64, u64)>,
        aad: Option<&[u8]>,
        whole_read_cap: u64,
    ) -> Result<Vec<u8>, BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        let tier = head.crypto_tier;
        // The manifest: parsed for a plaintext DAG, opened for a sealed one.
        let manifest = match backend.get_blob(sha256).await? {
            None => {
                return Err(BlobError::NotHeld {
                    sha256_hex: hex::encode(sha256),
                })
            }
            Some(BlobBody::ChunkDag(m)) => {
                if tier != CryptoTier::Plaintext {
                    return Err(BlobError::Backend(format!(
                        "blob {} is recorded at tier {tier:?} but the storage layer parsed its \
                         manifest as plaintext",
                        hex::encode(sha256)
                    )));
                }
                m
            }
            Some(BlobBody::Inline(_)) => {
                if tier == CryptoTier::Plaintext {
                    return Err(BlobError::Backend(format!(
                        "blob {} is a plaintext chunk_dag row but read back as inline bytes",
                        hex::encode(sha256)
                    )));
                }
                let jcs = read_sealed_inline_authorized(backend, sha256, tier, viewer_key_id, aad)
                    .await?;
                let m = ChunkManifest::from_manifest_bytes(&jcs)?;
                if m.chunk_tier != Some(tier) {
                    return Err(BlobError::Backend(format!(
                        "blob {} is recorded at tier {tier:?} but its manifest says {:?}",
                        hex::encode(sha256),
                        m.chunk_tier
                    )));
                }
                m
            }
            Some(BlobBody::External(_)) => {
                return Err(BlobError::Backend(format!(
                    "blob {} is a chunk_dag row but read back as an External reference",
                    hex::encode(sha256)
                )))
            }
        };
        let total = manifest.total_size;
        let (start, end) = match range {
            Some((s, e)) => (s, clamp_range(s, e, total)?),
            None => {
                if total > whole_read_cap {
                    return Err(BlobError::InvalidArgument(format!(
                        "blob {} is a {total}-byte chunk DAG, above the {whole_read_cap}-byte \
                         whole-read cap; read it by range (read_blob_range_as) \
                         (BLOB_ENCRYPTION_AT_REST.md §12.4)",
                        hex::encode(sha256)
                    )));
                }
                if total == 0 {
                    return Ok(Vec::new());
                }
                (0, total - 1)
            }
        };
        if tier == CryptoTier::Plaintext {
            crate::federation::at_rest_cascade::refuse_aad_at_plaintext(sha256, aad)?;
            // The plaintext assembler: chunk shas re-verified on read.
            return match backend.get_blob_range(sha256, start, end).await? {
                Some(crate::federation::BlobRange::Inline(b)) => Ok(b),
                Some(crate::federation::BlobRange::External { .. }) => {
                    Err(BlobError::InvalidArgument(format!(
                        "blob {} is an External reference",
                        hex::encode(sha256)
                    )))
                }
                None => Err(BlobError::NotHeld {
                    sha256_hex: hex::encode(sha256),
                }),
            };
        }

        // A sealed DAG: only the covering chunks, each opened on its own.
        let mut out = Vec::with_capacity((end - start + 1) as usize);
        // I38 — per-epoch authorization memo for a community DAG: one grant
        // lookup per distinct epoch in the range, not one per chunk.
        let mut authorized_epochs: std::collections::HashSet<(String, u64)> =
            std::collections::HashSet::new();
        // #838 (§12.10) — the manifest names the position every chunk was
        // sealed at; the parser guarantees both fields for v2.
        let stream_id = manifest.stream_id.as_deref().ok_or_else(|| {
            BlobError::Backend(format!(
                "blob {} is a sealed chunk_dag whose manifest carries no stream_id",
                hex::encode(sha256)
            ))
        })?;
        for slice in manifest.slices_for_range(start, end) {
            let cref = &manifest.chunks[slice.index];
            let seq = cref.seq.ok_or_else(|| {
                BlobError::Backend(format!(
                    "blob {} is a sealed chunk_dag whose manifest chunk {} carries no seq",
                    hex::encode(sha256),
                    hex::encode(cref.sha)
                ))
            })?;
            let bound_aad = chunk_aad(aad, stream_id, seq);
            let plain = open_stream_chunk_row_for_viewer(
                backend,
                sha256,
                &cref.sha,
                tier,
                viewer_key_id,
                &bound_aad,
                &mut authorized_epochs,
            )
            .await?;
            if plain.len() as u64 != u64::from(cref.size) {
                return Err(BlobError::Backend(format!(
                    "chunk_dag chunk {} opened to {} bytes but the manifest says {}",
                    hex::encode(cref.sha),
                    plain.len(),
                    cref.size
                )));
            }
            out.extend_from_slice(
                &plain[slice.local_start as usize..=slice.local_end_inclusive as usize],
            );
        }
        Ok(out)
    }

    /// §12.4 / §12.10 — **open ONE sealed stream chunk row for a viewer,
    /// under its position-bound AAD.** The row must exist (else the shared
    /// #833 refusal — swept or never ours, told only to an authorized
    /// viewer), must record `tier`, its sha is re-verified over the stored
    /// bytes (CEG §10.1.1), the viewer is authorized on THIS chunk — their
    /// grant on the row at `self` / `family`, their grant on the row's OWN
    /// binding's epoch at `community` (I38; memoized in `authorized_epochs`
    /// so a range costs one lookup per distinct epoch) — and only then the
    /// envelope opens under `bound_aad`. A refusal names `refused_sha` (the
    /// DAG the viewer asked for, or the chunk itself).
    async fn open_stream_chunk_row_for_viewer<B>(
        backend: &B,
        refused_sha: &[u8; 32],
        chunk_sha: &[u8; 32],
        tier: CryptoTier,
        viewer_key_id: &str,
        bound_aad: &[u8],
        authorized_epochs: &mut std::collections::HashSet<(String, u64)>,
    ) -> Result<Vec<u8>, BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        // A chunk with no row: the same fact as a missing blob — swept (I31)
        // or never ours — told the same way (I4b).
        let Some(chunk_head) = backend.blob_head(chunk_sha).await? else {
            return Err(
                crate::federation::at_rest_cascade::orchestrate::refuse_missing_row(
                    backend,
                    chunk_sha,
                    viewer_key_id,
                )
                .await?,
            );
        };
        // The CHUNK ROW is the authority on its own tier (I2 / I32).
        if chunk_head.crypto_tier != tier {
            return Err(BlobError::Backend(format!(
                "stream chunk {} is recorded at tier {:?} but was asked for at {tier:?}",
                hex::encode(chunk_sha),
                chunk_head.crypto_tier
            )));
        }
        let Some(BlobBody::Inline(bytes)) = backend.get_blob(chunk_sha).await? else {
            return Err(BlobError::Backend(format!(
                "stream chunk {} is not an inline row",
                hex::encode(chunk_sha)
            )));
        };
        // CEG §10.1.1 — the chunk's sha (over its CIPHERTEXT) before use.
        let computed: [u8; 32] = Sha256::digest(&bytes).into();
        if computed != *chunk_sha {
            return Err(BlobError::HashMismatch {
                expected_hex: hex::encode(chunk_sha),
                got_hex: hex::encode(computed),
            });
        }
        let envelope = AtRestEnvelope::from_bytes(&bytes).map_err(|e| {
            BlobError::Backend(format!(
                "stream chunk {} is recorded at tier {tier:?} but is not an envelope ({e})",
                hex::encode(chunk_sha)
            ))
        })?;
        match tier {
            CryptoTier::Plaintext => Err(BlobError::Backend(format!(
                "stream chunk {} is plaintext; nothing to open",
                hex::encode(chunk_sha)
            ))),
            CryptoTier::InvisibleEncrypted => {
                // The viewer's grant on THIS chunk row (I38).
                if backend
                    .get_at_rest_grant(chunk_sha, viewer_key_id)
                    .await?
                    .is_none()
                {
                    return Err(BlobError::NotGranted {
                        sha256_hex: hex::encode(refused_sha),
                        viewer_key_id: viewer_key_id.to_owned(),
                    });
                }
                read_for_viewer_sealed(backend, chunk_sha, &envelope, Some(bound_aad)).await
            }
            CryptoTier::CommunityDek => {
                // The chunk's OWN binding names the DEK that sealed it — a
                // pre-rotation chunk opens under its old epoch (I38) — and the
                // viewer must hold a grant on that epoch.
                let (community, epoch) = backend
                    .community_dek_blob_epoch(chunk_sha)
                    .await?
                    .ok_or_else(|| {
                        BlobError::Backend(format!(
                            "stream chunk {} is recorded at community_dek but carries no epoch \
                             binding",
                            hex::encode(chunk_sha)
                        ))
                    })?;
                let key = (community.clone(), epoch);
                if !authorized_epochs.contains(&key) {
                    if !backend
                        .community_dek_has_member_grant(&community, epoch, viewer_key_id)
                        .await?
                    {
                        return Err(BlobError::NotGranted {
                            sha256_hex: hex::encode(refused_sha),
                            viewer_key_id: viewer_key_id.to_owned(),
                        });
                    }
                    authorized_epochs.insert(key);
                }
                open_community_row_as_persist(
                    backend,
                    chunk_sha,
                    &community,
                    epoch,
                    &envelope,
                    Some(bound_aad),
                )
                .await
            }
        }
    }

    /// #838 (§12.10) — **read one chunk of a stream by POSITION, as
    /// `viewer_key_id`.** The DVR / catch-up read (§12.5): `stream_chunk_at`
    /// names the row at `(stream_id, seq)`, the row's tier authorizes the
    /// viewer before any body is touched (I4), and a sealed chunk opens
    /// under `chunk_aad(aad, stream_id, seq)` — the position it was written
    /// at, which is why a sealed chunk no longer opens by its sha alone
    /// through the whole-blob doors. A plaintext chunk is returned as stored
    /// (and `Some(aad)` is refused, I40). An unknown position is
    /// `InvalidArgument`; a position whose row is gone is the shared #833
    /// refusal.
    pub async fn read_stream_chunk_as<B>(
        backend: &B,
        stream_id: &str,
        seq: u64,
        viewer_key_id: &str,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        let Some(c) = backend.stream_chunk_at(stream_id, seq).await? else {
            return Err(BlobError::InvalidArgument(format!(
                "stream {stream_id} has no chunk at seq {seq}"
            )));
        };
        // 1. The ROW says what this is (§11.1); absent ⇒ the shared refusal.
        let Some(head) = backend.blob_head(&c.chunk_sha).await? else {
            return Err(
                crate::federation::at_rest_cascade::orchestrate::refuse_missing_row(
                    backend,
                    &c.chunk_sha,
                    viewer_key_id,
                )
                .await?,
            );
        };
        // 2. AUTHORIZE BY TIER, BEFORE TOUCHING ANY BODY (§11.3 / I4).
        authorize_viewer_by_tier(backend, &c.chunk_sha, head.crypto_tier, viewer_key_id).await?;
        // 3. Open under the position.
        let plain = match head.crypto_tier {
            CryptoTier::Plaintext => {
                crate::federation::at_rest_cascade::refuse_aad_at_plaintext(&c.chunk_sha, aad)?;
                let Some(BlobBody::Inline(bytes)) = backend.get_blob(&c.chunk_sha).await? else {
                    return Err(BlobError::Backend(format!(
                        "stream chunk {} is not an inline row",
                        hex::encode(c.chunk_sha)
                    )));
                };
                let computed: [u8; 32] = Sha256::digest(&bytes).into();
                if computed != c.chunk_sha {
                    return Err(BlobError::HashMismatch {
                        expected_hex: hex::encode(c.chunk_sha),
                        got_hex: hex::encode(computed),
                    });
                }
                bytes
            }
            tier => {
                let bound_aad = chunk_aad(aad, stream_id, seq);
                open_stream_chunk_row_for_viewer(
                    backend,
                    &c.chunk_sha,
                    &c.chunk_sha,
                    tier,
                    viewer_key_id,
                    &bound_aad,
                    &mut std::collections::HashSet::new(),
                )
                .await?
            }
        };
        if plain.len() as u64 != c.plaintext_size {
            return Err(BlobError::Backend(format!(
                "stream chunk {} opened to {} bytes but its index row says {}",
                hex::encode(c.chunk_sha),
                plain.len(),
                c.plaintext_size
            )));
        }
        Ok(plain)
    }
}

/// §12.7 — the falsifiable invariants, one `exercise_*` body per row,
/// registered in BOTH `store::sqlite` and `store::postgres` tests.
#[cfg(any(test, feature = "test-anchor"))]
#[allow(dead_code)]
pub mod invariants {
    use super::orchestrate::{
        put_blob_chunk_scoped, read_any_range_for_viewer, seal_stream_scoped,
    };
    use crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer;
    use crate::federation::at_rest_cascade::{AtRestEnvelope, AT_REST_ENVELOPE_OVERHEAD};
    use crate::federation::blobs::BlobBody;
    use crate::federation::community_dek::lifecycle_support::{
        revoke_member, seed_community, seed_member,
    };
    use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY, SELF};
    use crate::federation::{BlobError, BlobRange, BlobStorage, FederationDirectory};

    fn sha(bytes: &[u8]) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(bytes).into()
    }

    /// Deterministic, non-trivial segment bytes so a boundary error shows
    /// as a content mismatch rather than a length one.
    fn segment(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                (i as u32)
                    .wrapping_mul(2654435761)
                    .wrapping_add(seed as u32) as u8
            })
            .collect()
    }

    /// A community with one keyed member, the signer that announces, and a
    /// stream of `segments` sealed at `community`. Returns
    /// `(manifest_sha, chunk_shas, plaintext)`.
    async fn sealed_community_stream<B>(
        backend: &B,
        tag: &str,
        run: &str,
        comm: &str,
        stream: &str,
        segments: &[Vec<u8>],
    ) -> ([u8; 32], Vec<[u8; 32]>, Vec<u8>)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let node = format!("{tag}-node-{run}");
        let signer =
            crate::federation::at_rest_cascade::blob_invariants::node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer);
        sealed_community_stream_as(backend, &adapter, tag, comm, stream, segments).await
    }

    /// [`sealed_community_stream`] with the WRITER given: every chunk and
    /// the seal are signed by `adapter`, so the stream belongs to it (#837).
    async fn sealed_community_stream_as<B>(
        backend: &B,
        adapter: &dyn ciris_keyring::HardwareSigner,
        tag: &str,
        comm: &str,
        stream: &str,
        segments: &[Vec<u8>],
    ) -> ([u8; 32], Vec<[u8; 32]>, Vec<u8>)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let mut shas = Vec::new();
        let mut plain = Vec::new();
        for (i, seg) in segments.iter().enumerate() {
            let r = put_blob_chunk_scoped(
                backend,
                adapter,
                COMMUNITY,
                Some(comm),
                stream,
                i as u64,
                seg,
                0,
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("{tag}: community chunk {i} must be writable: {e}"));
            assert_eq!(r.tier, CryptoTier::CommunityDek, "{tag}: resolved tier");
            shas.push(r.chunk_sha256);
            plain.extend_from_slice(seg);
        }
        let sealed =
            seal_stream_scoped(backend, adapter, COMMUNITY, Some(comm), stream, None, None)
                .await
                .unwrap_or_else(|e| panic!("{tag}: a community stream must seal: {e}"));
        assert_eq!(sealed.chunk_count, segments.len() as u64);
        assert_eq!(sealed.total_size, plain.len() as u64);
        (sealed.manifest_sha256, shas, plain)
    }

    // ── I32 (commons half) ───────────────────────────────────────────────
    /// **A seal door checks the chunk ROWS: a DAG whose chunks are not all
    /// at the DAG's tier is refused.** The commons `seal_stream` is a seal
    /// door too — it writes a `chunk_dag` row at `plaintext` — so a stream
    /// carrying a community-sealed chunk row must be refused by it.
    ///
    /// Staged through doors that existed before #832: the community cascade
    /// stores a sealed row; `put_blob_chunk` of the same bytes indexes that
    /// EXISTING row into a stream (the blob insert is `ON CONFLICT DO
    /// NOTHING`, so the row keeps its `community_dek` tier). Before #832 the
    /// commons seal happily wrote a public manifest over it. RED on 170cc89.
    pub async fn exercise_i32_commons_seal_refuses_a_sealed_chunk_row<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        seed_community(backend, &comm, &[(&alice, &alice_occ)]).await;
        let sealed = encrypt_and_cascade_community(backend, &comm, b"segment 0", None)
            .await
            .unwrap();
        let Some(BlobBody::Inline(sealed_bytes)) =
            backend.get_blob(&sealed.at_rest_sha256).await.unwrap()
        else {
            panic!("{tag} I32: precondition — the sealed row is inline");
        };
        let stream = format!("{tag}-stream-{run}");
        let chunk_sha = backend
            .put_blob_chunk(&stream, 0, BlobBody::Inline(sealed_bytes), 0)
            .await
            .unwrap();
        assert_eq!(chunk_sha, sealed.at_rest_sha256, "{tag} I32: precondition");
        assert_eq!(
            backend.blob_crypto_tier(&chunk_sha).await.unwrap(),
            Some(CryptoTier::CommunityDek),
            "{tag} I32: precondition — the chunk row is still at community_dek"
        );

        let res = backend.seal_stream(&stream).await;
        match res {
            Err(BlobError::InvalidArgument(_)) => {}
            Err(other) => panic!("{tag} I32: expected InvalidArgument, got {other:?}"),
            Ok(manifest_sha) => panic!(
                "{tag} I32: the commons seal wrote a PLAINTEXT manifest {} over a chunk row \
                 sealed at community_dek — the seal door took the stream's word instead of \
                 checking the chunk rows' tier",
                hex::encode(manifest_sha)
            ),
        }
    }

    // ── I32 (scoped half) ────────────────────────────────────────────────
    /// **The scoped seal checks the chunk ROWS too**, in both directions: a
    /// community stream with one commons chunk is refused at `community`;
    /// a commons stream is refused at `community`. And the honest case
    /// seals, with the manifest row recording the DAG's tier.
    pub async fn exercise_i32_scoped_seal_checks_chunk_rows<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        seed_community(backend, &comm, &[(&alice, &alice_occ)]).await;
        let node = format!("{tag}-node-{run}");
        let signer =
            crate::federation::at_rest_cascade::blob_invariants::node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer);

        let owner = crate::signing::federation_key_id_of(&adapter)
            .await
            .unwrap();
        // (Before #837 this witness also staged a mixed stream through the
        // commons door; the chunk floor now refuses that append — I41.)

        // A community stream carrying a chunk row at the SAME cohort but at
        // `plaintext` (placed through the floor as an infra-community write
        // would leave it): only the TIER check can refuse this — the cohort
        // matches — and the refusal must be the door's InvalidArgument, not
        // a corruption report from a later step.
        {
            use crate::federation::{StorageFloor, StreamClaim};
            let same_cohort = format!("{tag}-same-cohort-{run}");
            put_blob_chunk_scoped(
                backend,
                &adapter,
                COMMUNITY,
                Some(&comm),
                &same_cohort,
                0,
                b"sealed",
                0,
                None,
            )
            .await
            .unwrap();
            backend
                .put_blob_chunk_with_scope(
                    &same_cohort,
                    1,
                    BlobBody::Inline(b"clear, same cohort".to_vec()),
                    0,
                    18,
                    COMMUNITY,
                    StorageFloor::resolved(CryptoTier::Plaintext),
                    None,
                    StreamClaim {
                        community_key_id: Some(comm.clone()),
                        owner_key_id: Some(owner.clone()),
                    },
                )
                .await
                .unwrap();
            let res = seal_stream_scoped(
                backend,
                &adapter,
                COMMUNITY,
                Some(&comm),
                &same_cohort,
                None,
                None,
            )
            .await;
            match res {
                Err(BlobError::InvalidArgument(msg)) => assert!(
                    msg.contains("tier"),
                    "{tag} I32: the refusal names the TIER mismatch: {msg}"
                ),
                other => panic!(
                    "{tag} I32: a community DAG over a same-cohort PLAINTEXT chunk row was not \
                     refused by the tier check: {other:?}"
                ),
            }
        }

        // A commons stream sealed at community: every chunk row is plaintext.
        let commons = format!("{tag}-commons-{run}");
        backend
            .put_blob_chunk(&commons, 0, BlobBody::Inline(b"public".to_vec()), 0)
            .await
            .unwrap();
        let res = seal_stream_scoped(
            backend,
            &adapter,
            COMMUNITY,
            Some(&comm),
            &commons,
            None,
            None,
        )
        .await;
        assert!(
            matches!(res, Err(BlobError::InvalidArgument(_))),
            "{tag} I32: a commons stream was sealed as a community DAG: {res:?}"
        );

        // The FLOOR refuses a self-contradicting row (I25): a sealed-tier
        // token over a body that is not an envelope, and a plaintext token
        // whose declared size is not the body's.
        {
            use crate::federation::{EpochBinding, StorageFloor, StreamClaim};
            let floor_stream = format!("{tag}-floor-{run}");
            let res = backend
                .put_blob_chunk_with_scope(
                    &floor_stream,
                    0,
                    BlobBody::Inline(b"not an envelope".to_vec()),
                    0,
                    15,
                    COMMUNITY,
                    StorageFloor::resolved(CryptoTier::CommunityDek),
                    Some(EpochBinding {
                        community_key_id: comm.clone(),
                        epoch: 0,
                    }),
                    StreamClaim::default(),
                )
                .await;
            assert!(
                matches!(res, Err(BlobError::InvalidArgument(_))),
                "{tag} I32: the chunk floor recorded a sealed tier over PLAINTEXT bytes: {res:?}"
            );
            assert!(
                !backend.has_blob(&sha(b"not an envelope")).await.unwrap(),
                "{tag} I32: refused bytes are not on disk"
            );
            let res = backend
                .put_blob_chunk_with_scope(
                    &floor_stream,
                    0,
                    BlobBody::Inline(b"plain".to_vec()),
                    0,
                    4, // lies about the size
                    COMMUNITY,
                    StorageFloor::resolved(CryptoTier::Plaintext),
                    None,
                    StreamClaim::default(),
                )
                .await;
            assert!(
                matches!(res, Err(BlobError::InvalidArgument(_))),
                "{tag} I32: the chunk floor accepted a plaintext_size that is not the body's: {res:?}"
            );
        }

        // The honest case (its own node key: the helper registers one).
        let good = format!("{tag}-good-{run}");
        let (manifest, _, _) = sealed_community_stream(
            backend,
            tag,
            &format!("{run}-good"),
            &comm,
            &good,
            &[b"one".to_vec(), b"two".to_vec()],
        )
        .await;
        let head = backend
            .blob_head(&manifest)
            .await
            .unwrap()
            .expect("manifest row");
        assert_eq!(
            head.storage_kind, "chunk_dag",
            "{tag} I32: the row is a DAG"
        );
        assert_eq!(
            head.crypto_tier,
            CryptoTier::CommunityDek,
            "{tag} I32: the manifest row records the DAG's tier"
        );
        assert_eq!(head.cohort_scope, COMMUNITY);
        assert!(
            backend
                .community_dek_blob_epoch(&manifest)
                .await
                .unwrap()
                .is_some(),
            "{tag} I32: the manifest row is bound to the epoch it was sealed under"
        );
    }

    // ── I33 ──────────────────────────────────────────────────────────────
    /// **A sealed manifest is opaque at the storage layer and refused to a
    /// stranger at the read door.** `get_blob` hands out the envelope bytes
    /// (never a parsed manifest, never a parse error); `get_blob_range`
    /// serves a substring of them; the row's `size_bytes` is the envelope
    /// length; the manifest is content-addressed by those bytes; and
    /// neither the manifest nor a chunk opens for a non-member.
    pub async fn exercise_i33_sealed_manifest_is_opaque_and_stranger_refused<B>(
        backend: &B,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        seed_community(backend, &comm, &[(&alice, &alice_occ)]).await;
        let stream = format!("{tag}-stream-{run}");
        let (manifest, chunks, _) = sealed_community_stream(
            backend,
            tag,
            &run,
            &comm,
            &stream,
            &[segment(1, 100), segment(2, 50)],
        )
        .await;

        let Some(BlobBody::Inline(envelope)) = backend.get_blob(&manifest).await.unwrap() else {
            panic!(
                "{tag} I33: get_blob on a SEALED chunk_dag row must return the opaque envelope \
                 bytes for a relay, not a parsed manifest (or a parse error)"
            );
        };
        assert!(
            AtRestEnvelope::has_magic(&envelope),
            "{tag} I33: the stored manifest is an envelope"
        );
        assert_eq!(
            sha(&envelope),
            manifest,
            "{tag} I33: addressed by its ciphertext"
        );
        let head = backend.blob_head(&manifest).await.unwrap().unwrap();
        assert_eq!(
            head.size_bytes,
            envelope.len() as u64,
            "{tag} I33: size_bytes is the STORED length (what get_blob_range bounds on)"
        );
        match backend.get_blob_range(&manifest, 0, 7).await.unwrap() {
            Some(BlobRange::Inline(b)) => assert_eq!(
                b,
                envelope[..8].to_vec(),
                "{tag} I33: get_blob_range serves the stored bytes verbatim"
            ),
            other => panic!("{tag} I33: get_blob_range over a sealed manifest: {other:?}"),
        }

        // Every chunk row is sealed and addressed by its ciphertext.
        for c in &chunks {
            let Some(BlobBody::Inline(bytes)) = backend.get_blob(c).await.unwrap() else {
                panic!("{tag} I33: chunk row is inline");
            };
            assert!(
                AtRestEnvelope::has_magic(&bytes),
                "{tag} I33: chunk is sealed"
            );
            assert_eq!(sha(&bytes), *c, "{tag} I33: chunk addressed by ciphertext");
            assert_eq!(
                backend.blob_crypto_tier(c).await.unwrap(),
                Some(CryptoTier::CommunityDek),
                "{tag} I33: the chunk row records its tier"
            );
        }

        // The read door: a stranger is refused BEFORE any body — at the
        // manifest and at a chunk, whole or ranged.
        let stranger = format!("{tag}-stranger-{run}");
        for (what, sha_) in [("manifest", manifest), ("chunk", chunks[0])] {
            let whole = read_any_for_viewer(backend, &sha_, &stranger, None).await;
            assert!(
                matches!(whole, Err(BlobError::NotGranted { .. })),
                "{tag} I33: a stranger read the {what} whole: {whole:?}"
            );
            let ranged = read_any_range_for_viewer(backend, &sha_, &stranger, 0, 0, None).await;
            assert!(
                matches!(ranged, Err(BlobError::NotGranted { .. })),
                "{tag} I33: a stranger read the {what} by range: {ranged:?}"
            );
        }
    }

    // ── I34 ──────────────────────────────────────────────────────────────
    /// **The decrypting range read returns exactly the plaintext range**,
    /// at every boundary shape, with RFC 9110 bounds against the PLAINTEXT
    /// total — and `get_blob_range` over the same address is still
    /// ciphertext, so the two doors are distinct.
    pub async fn exercise_i34_range_read_maps_plaintext_to_chunks<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        seed_community(backend, &comm, &[(&alice, &alice_occ)]).await;
        let stream = format!("{tag}-stream-{run}");
        let segs = [segment(7, 5000), segment(8, 3000), segment(9, 7000)];
        let (manifest, _, plain) =
            sealed_community_stream(backend, tag, &run, &comm, &stream, &segs).await;
        let total = plain.len() as u64;
        assert_eq!(total, 15000);

        let cases: [(u64, u64); 9] = [
            (0, 4999),      // exactly chunk 0
            (4999, 5000),   // straddles chunk 0 → 1
            (5000, 7999),   // exactly chunk 1
            (4000, 9000),   // spans all three
            (0, 14999),     // everything
            (14999, 14999), // last byte
            (7999, 8000),   // straddles chunk 1 → 2
            (12345, 99999), // end past total — clamped
            (3, 3),         // one byte
        ];
        for (s, e) in cases {
            let got = read_any_range_for_viewer(backend, &manifest, &alice_occ, s, e, None)
                .await
                .unwrap_or_else(|err| panic!("{tag} I34: range {s}..={e}: {err}"));
            let e_clamped = e.min(total - 1);
            assert_eq!(
                got,
                plain[s as usize..=e_clamped as usize].to_vec(),
                "{tag} I34: range {s}..={e} returned the wrong bytes"
            );
        }
        // Bounds against the PLAINTEXT total.
        match read_any_range_for_viewer(backend, &manifest, &alice_occ, total, total, None).await {
            Err(BlobError::RangeNotSatisfiable { range_start, size }) => {
                assert_eq!(
                    (range_start, size),
                    (total, total),
                    "{tag} I34: names the plaintext size"
                );
            }
            other => panic!("{tag} I34: start == total must be RangeNotSatisfiable: {other:?}"),
        }
        assert!(
            matches!(
                read_any_range_for_viewer(backend, &manifest, &alice_occ, 5, 4, None).await,
                Err(BlobError::InvalidArgument(_))
            ),
            "{tag} I34: start > end is InvalidArgument"
        );
        // The storage-layer read over the same address is NOT plaintext.
        match backend.get_blob_range(&manifest, 0, 7).await.unwrap() {
            Some(BlobRange::Inline(b)) => assert_ne!(
                b,
                plain[..8].to_vec(),
                "{tag} I34: get_blob_range must keep serving stored (cipher) bytes"
            ),
            other => panic!("{tag} I34: {other:?}"),
        }
    }

    // ── I34b — self/family ───────────────────────────────────────────────
    /// **A `self` DAG is a per-chunk fresh-DEK DAG**: each chunk row and
    /// the manifest carry persist's self-retention grant and the owner's
    /// occurrence grant; the occurrence reads whole and by range; a stranger
    /// is refused; nothing is announced.
    pub async fn exercise_i34b_self_dag_reads_by_grant<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::PERSIST_SELF_RECIPIENT;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let owner = format!("{tag}-owner-{run}");
        let occ = format!("{tag}-owner-occ-{run}");
        seed_member(backend, &owner, &occ).await;
        let node = format!("{tag}-node-{run}");
        let signer =
            crate::federation::at_rest_cascade::blob_invariants::node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer);
        let stream = format!("{tag}-stream-{run}");
        let segs = [segment(3, 2000), segment(4, 1000)];
        let mut plain = Vec::new();
        let mut chunk_shas = Vec::new();
        for (i, seg) in segs.iter().enumerate() {
            let r = put_blob_chunk_scoped(
                backend,
                &adapter,
                SELF,
                Some(&owner),
                &stream,
                i as u64,
                seg,
                0,
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I34b: self chunk {i}: {e}"));
            assert_eq!(r.tier, CryptoTier::InvisibleEncrypted);
            assert!(
                r.granted.contains(&occ),
                "{tag} I34b: the owner's occurrence is granted on chunk {i}: {:?}",
                r.granted
            );
            chunk_shas.push(r.chunk_sha256);
            plain.extend_from_slice(seg);
        }
        let sealed = seal_stream_scoped(backend, &adapter, SELF, Some(&owner), &stream, None, None)
            .await
            .unwrap_or_else(|e| panic!("{tag} I34b: seal: {e}"));
        let manifest = sealed.manifest_sha256;
        for s in chunk_shas.iter().chain(std::iter::once(&manifest)) {
            assert!(
                backend
                    .get_at_rest_grant(s, PERSIST_SELF_RECIPIENT)
                    .await
                    .unwrap()
                    .is_some(),
                "{tag} I34b: persist self-retention on every row"
            );
            assert!(
                backend.get_at_rest_grant(s, &occ).await.unwrap().is_some(),
                "{tag} I34b: the occurrence's grant on every row"
            );
        }
        assert!(
            backend.list_holders(&manifest).await.unwrap().is_empty(),
            "{tag} I34b: a self DAG is structurally invisible — no holds_bytes"
        );
        assert_eq!(
            read_any_for_viewer(backend, &manifest, &occ, None)
                .await
                .unwrap(),
            plain,
            "{tag} I34b: whole read"
        );
        assert_eq!(
            read_any_range_for_viewer(backend, &manifest, &occ, 1990, 2010, None)
                .await
                .unwrap(),
            plain[1990..=2010].to_vec(),
            "{tag} I34b: range across the chunk boundary"
        );
        let stranger = format!("{tag}-stranger-{run}");
        assert!(matches!(
            read_any_range_for_viewer(backend, &manifest, &stranger, 0, 10, None).await,
            Err(BlobError::NotGranted { .. })
        ));

        // A sealed self WHOLE blob: the range read's own authorization is the
        // only gate in front of persist's self-retention (no per-chunk check
        // behind it), so a stranger must be refused HERE (I4 / I34).
        {
            use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
            let whole = segment(9, 4000);
            let r = encrypt_and_cascade(backend, SELF, &owner, &whole, None, None)
                .await
                .unwrap();
            assert_eq!(
                read_any_range_for_viewer(backend, &r.at_rest_sha256, &occ, 1000, 1999, None)
                    .await
                    .unwrap(),
                whole[1000..=1999].to_vec(),
                "{tag} I34b: a sealed whole blob is sliced after one open"
            );
            assert!(
                matches!(
                    read_any_range_for_viewer(backend, &r.at_rest_sha256, &stranger, 0, 10, None)
                        .await,
                    Err(BlobError::NotGranted { .. })
                ),
                "{tag} I34b: the range read handed a stranger a sealed whole blob"
            );
        }

        // A second occurrence of the owner that arrived AFTER the chunk was
        // written and BEFORE the seal: granted on the manifest, on no chunk
        // row. The reader checks the CHUNK ROW's grant (I38 for self): it is
        // refused until `rekey_for_newcomers` walks the chunk rows too.
        {
            let stream2 = format!("{tag}-stream2-{run}");
            let seg = segment(13, 700);
            let c = put_blob_chunk_scoped(
                backend,
                &adapter,
                SELF,
                Some(&owner),
                &stream2,
                0,
                &seg,
                0,
                None,
            )
            .await
            .unwrap();
            let later_occ = format!("{tag}-owner-later-occ-{run}");
            seed_occurrence(backend, &owner, &later_occ).await;
            let sealed2 =
                seal_stream_scoped(backend, &adapter, SELF, Some(&owner), &stream2, None, None)
                    .await
                    .unwrap();
            assert!(
                sealed2.granted.contains(&later_occ),
                "{tag} I34b: the later occurrence is granted on the manifest"
            );
            assert!(
                backend
                    .get_at_rest_grant(&c.chunk_sha256, &later_occ)
                    .await
                    .unwrap()
                    .is_none(),
                "{tag} I34b: precondition — and NOT on the chunk row"
            );
            assert!(
                matches!(
                    read_any_range_for_viewer(
                        backend,
                        &sealed2.manifest_sha256,
                        &later_occ,
                        0,
                        9,
                        None
                    )
                    .await,
                    Err(BlobError::NotGranted { .. })
                ),
                "{tag} I34b: a viewer granted on the manifest but not on the chunk row read the \
                 chunk — the reader trusted the manifest's grant for every chunk"
            );
        }
    }

    // ── I35 (commons half) ───────────────────────────────────────────────
    /// **The read door returns a DAG's CONTENT, not its manifest.** A commons
    /// DAG read through `read_any_for_viewer` is the concatenated bytes, so a
    /// consumer never has to know whether a sha names a whole blob or a DAG.
    /// Before #832 the door refused every `chunk_dag` row. RED on 170cc89.
    pub async fn exercise_i35_whole_read_of_a_dag_is_its_content<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let stream = format!("{tag}-stream-{run}");
        let a = format!("{tag}-first-{run}").into_bytes();
        let b = format!("{tag}-second-{run}").into_bytes();
        backend
            .put_blob_chunk(&stream, 0, BlobBody::Inline(a.clone()), 0)
            .await
            .unwrap();
        backend
            .put_blob_chunk(&stream, 1, BlobBody::Inline(b.clone()), 0)
            .await
            .unwrap();
        let manifest_sha = backend.seal_stream(&stream).await.unwrap();
        let mut want = a;
        want.extend_from_slice(&b);
        let got = read_any_for_viewer(backend, &manifest_sha, &format!("{tag}-anyone-{run}"), None)
            .await
            .unwrap_or_else(|e| {
                panic!("{tag} I35: the read door refused a commons DAG instead of returning its content: {e}")
            });
        assert_eq!(got, want, "{tag} I35: the DAG's content, in chunk order");
        // And the commons range read agrees with the plaintext assembler.
        assert_eq!(
            read_any_range_for_viewer(
                backend,
                &manifest_sha,
                "anyone",
                2,
                want.len() as u64 - 2,
                None
            )
            .await
            .unwrap(),
            want[2..want.len() - 1].to_vec()
        );
    }

    // ── I35 (the cap) ────────────────────────────────────────────────────
    /// **The whole read refuses above the cap, naming it, and the range door
    /// still works.** Driven through the capped internal with a cap one
    /// byte under the DAG's total (materializing 64 MiB per backend per run
    /// would make the suite pay for a constant); a from-disk test pins that
    /// the production door passes `DAG_WHOLE_READ_CAP_BYTES`.
    pub async fn exercise_i35_whole_read_refuses_above_the_cap<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use super::orchestrate::read_dag_for_viewer_authorized_capped;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        seed_community(backend, &comm, &[(&alice, &alice_occ)]).await;
        let stream = format!("{tag}-stream-{run}");
        let (manifest, _, plain) = sealed_community_stream(
            backend,
            tag,
            &run,
            &comm,
            &stream,
            &[segment(5, 300), segment(6, 300)],
        )
        .await;
        let head = backend.blob_head(&manifest).await.unwrap().unwrap();
        let total = plain.len() as u64;
        let over = read_dag_for_viewer_authorized_capped(
            backend,
            &manifest,
            &head,
            &alice_occ,
            None,
            None,
            total - 1,
        )
        .await;
        match over {
            Err(BlobError::InvalidArgument(msg)) => assert!(
                msg.contains(&(total - 1).to_string()) && msg.contains("range"),
                "{tag} I35: the refusal names the cap and the range door: {msg}"
            ),
            other => panic!("{tag} I35: a DAG above the cap was read whole: {other:?}"),
        }
        assert_eq!(
            read_dag_for_viewer_authorized_capped(
                backend, &manifest, &head, &alice_occ, None, None, total,
            )
            .await
            .unwrap(),
            plain,
            "{tag} I35: at the cap it reads"
        );
        assert_eq!(
            read_any_range_for_viewer(backend, &manifest, &alice_occ, 299, 300, None)
                .await
                .unwrap(),
            plain[299..=300].to_vec(),
            "{tag} I35: the range door is unaffected by the whole-read cap"
        );
    }

    // ── I37 ──────────────────────────────────────────────────────────────
    /// **`stream_chunks` is the live handle**: before any seal it lists the
    /// chunks in `seq` order with their recorded tier and PLAINTEXT size,
    /// and reports the latest STH's `tree_size` once one is stored.
    pub async fn exercise_i37_stream_chunks_is_the_live_handle<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        seed_community(backend, &comm, &[(&alice, &alice_occ)]).await;
        let writer = crate::signing::LocalSignerHardwareAdapter::new(
            crate::federation::at_rest_cascade::blob_invariants::node_signer(
                backend,
                &format!("{tag}-writer-{run}"),
            )
            .await,
        );
        let stream = format!("{tag}-stream-{run}");
        assert_eq!(
            backend.stream_chunks(&stream).await.unwrap(),
            crate::federation::StreamChunks::default(),
            "{tag} I37: an unknown stream is an empty listing, not an error"
        );
        let segs = [segment(11, 700), segment(12, 40)];
        let mut shas = Vec::new();
        for (i, seg) in segs.iter().enumerate() {
            let r = put_blob_chunk_scoped(
                backend,
                &writer,
                COMMUNITY,
                Some(&comm),
                &stream,
                i as u64,
                seg,
                4,
                None,
            )
            .await
            .unwrap();
            shas.push(r.chunk_sha256);
        }
        let listing = backend.stream_chunks(&stream).await.unwrap();
        assert_eq!(listing.sth_tree_size, None, "{tag} I37: no STH yet");
        assert_eq!(listing.chunks.len(), 2);
        // #837 — the listing carries the stream's row: cohort, community,
        // owner (the writer's DERIVED key id).
        assert_eq!(
            listing.stream,
            Some(crate::federation::StreamHead {
                cohort_scope: COMMUNITY.into(),
                community_key_id: Some(comm.clone()),
                owner_key_id: Some(crate::signing::federation_key_id_of(&writer).await.unwrap()),
            }),
            "{tag} I37: the listing reports who owns the stream and at what cohort"
        );
        for (i, c) in listing.chunks.iter().enumerate() {
            assert_eq!(c.seq, i as u64, "{tag} I37: seq order");
            assert_eq!(c.chunk_sha, shas[i]);
            assert_eq!(c.epoch, 4, "{tag} I37: the producer's label as recorded");
            assert_eq!(
                c.plaintext_size,
                segs[i].len() as u64,
                "{tag} I37: plaintext size"
            );
            assert_eq!(
                c.size_bytes,
                segs[i].len() as u64 + AT_REST_ENVELOPE_OVERHEAD as u64,
                "{tag} I37: stored size is the envelope"
            );
            assert_eq!(c.crypto_tier, CryptoTier::CommunityDek);
            assert_eq!(c.cohort_scope, COMMUNITY);
        }
        // A producer-signed STH over the first chunk: the listing reports it.
        let producer = format!("{tag}-producer-{run}");
        let hybrid = register_hybrid_producer(backend, &producer).await;
        let sth = sign_stream_sth(&hybrid, &stream, &shas, 1);
        backend
            .put_stream_sth(sth, &producer)
            .await
            .unwrap_or_else(|e| panic!("{tag} I37: STH over sealed chunk shas: {e}"));
        let listing = backend.stream_chunks(&stream).await.unwrap();
        assert_eq!(
            listing.sth_tree_size,
            Some(1),
            "{tag} I37: the latest STH's tree_size rides with the listing"
        );
        assert_eq!(
            listing.chunks.len(),
            2,
            "{tag} I37: the tail past the STH is still listed"
        );
        // The chunk is readable by its POSITION, before any seal (DVR) —
        // #838: a sealed chunk is bound to where it was written.
        assert_eq!(
            super::orchestrate::read_stream_chunk_as(backend, &stream, 0, &alice_occ, None)
                .await
                .unwrap(),
            segs[0],
            "{tag} I37: an unsealed stream's chunk opens by its position"
        );
    }

    // ── I38 ──────────────────────────────────────────────────────────────
    /// **A chunk keeps the epoch it was sealed under.** A stream that crosses
    /// a rotation has chunks bound to N and N+1 and a manifest at N+1: a
    /// member of both epochs reads it whole (each chunk opened under its own
    /// binding); the member removed at the rotation is refused at the
    /// manifest, still opens the pre-rotation chunk by its own sha (AV-70
    /// forward-only), and is refused the post-rotation chunk.
    pub async fn exercise_i38_a_chunk_keeps_its_epoch<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        let bob = format!("{tag}-bob-{run}");
        let bob_occ = format!("{tag}-bob-occ-{run}");
        seed_community(backend, &comm, &[(&alice, &alice_occ), (&bob, &bob_occ)]).await;
        let node = format!("{tag}-node-{run}");
        let signer =
            crate::federation::at_rest_cascade::blob_invariants::node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer);
        let stream = format!("{tag}-stream-{run}");
        let seg0 = segment(21, 900);
        let seg1 = segment(22, 600);

        let owner = crate::signing::federation_key_id_of(&adapter)
            .await
            .unwrap();
        let c0 = put_blob_chunk_scoped(
            backend,
            &adapter,
            COMMUNITY,
            Some(&comm),
            &stream,
            0,
            &seg0,
            0,
            None,
        )
        .await
        .unwrap();
        let e0 = c0.epoch.unwrap();
        assert!(
            c0.granted.contains(&bob_occ),
            "{tag} I38: bob is granted at e0"
        );
        // The rotation: bob is removed and the epoch bumps transactionally.
        revoke_member(backend, &comm, &bob).await;
        let c1 = put_blob_chunk_scoped(
            backend,
            &adapter,
            COMMUNITY,
            Some(&comm),
            &stream,
            1,
            &seg1,
            0,
            None,
        )
        .await
        .unwrap();
        let e1 = c1.epoch.unwrap();
        assert!(e1 > e0, "{tag} I38: precondition — rotated");
        assert!(
            !c1.granted.contains(&bob_occ),
            "{tag} I38: bob is not granted at e1"
        );
        // I17 at the chunk floor: an append that binds at the rotated-past
        // epoch (still `enabled` — no sweep ran) is refused as a UNIT: no
        // blob row, no index row, nothing to orphan.
        {
            use crate::federation::at_rest_cascade::{fresh_dek, seal};
            use crate::federation::{EpochBinding, StorageFloor, StreamClaim};
            assert_eq!(
                backend.community_dek_key_state(&comm, e0).await.unwrap(),
                Some(crate::federation::DekKeyState::Enabled),
                "{tag} I38: precondition — e0 is still enabled"
            );
            let stale = seal(&fresh_dek().unwrap(), b"stale", None)
                .unwrap()
                .to_bytes();
            let stale_sha = sha(&stale);
            let res = backend
                .put_blob_chunk_with_scope(
                    &stream,
                    2,
                    BlobBody::Inline(stale),
                    0,
                    5,
                    COMMUNITY,
                    StorageFloor::resolved(CryptoTier::CommunityDek),
                    Some(EpochBinding {
                        community_key_id: comm.clone(),
                        epoch: e0,
                    }),
                    StreamClaim {
                        community_key_id: Some(comm.clone()),
                        owner_key_id: Some(owner.clone()),
                    },
                )
                .await;
            assert!(
                matches!(res, Err(BlobError::EpochNotCurrent { .. })),
                "{tag} I38: the chunk floor bound a chunk to a rotated-past epoch: {res:?}"
            );
            assert!(
                !backend.has_blob(&stale_sha).await.unwrap(),
                "{tag} I38: a refused append left its blob row behind"
            );
            assert_eq!(
                backend.stream_chunks(&stream).await.unwrap().chunks.len(),
                2,
                "{tag} I38: a refused append left its index row behind"
            );
        }
        let sealed = seal_stream_scoped(
            backend,
            &adapter,
            COMMUNITY,
            Some(&comm),
            &stream,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            sealed.epoch,
            Some(e1),
            "{tag} I38: the manifest seals at the current epoch"
        );
        let manifest = sealed.manifest_sha256;

        // Each row keeps its own binding.
        assert_eq!(
            backend
                .community_dek_blob_epoch(&c0.chunk_sha256)
                .await
                .unwrap(),
            Some((comm.clone(), e0)),
            "{tag} I38: chunk 0 stays bound to e0"
        );
        assert_eq!(
            backend
                .community_dek_blob_epoch(&c1.chunk_sha256)
                .await
                .unwrap(),
            Some((comm.clone(), e1))
        );
        assert_eq!(
            backend.community_dek_blob_epoch(&manifest).await.unwrap(),
            Some((comm.clone(), e1))
        );

        // Alice (both epochs) reads the whole DAG — chunk 0 opens under e0's
        // DEK, recovered from ITS binding, not the manifest's.
        let mut plain = seg0.clone();
        plain.extend_from_slice(&seg1);
        assert_eq!(
            read_any_for_viewer(backend, &manifest, &alice_occ, None)
                .await
                .unwrap(),
            plain,
            "{tag} I38: a pre-rotation chunk opens under the epoch it was sealed at"
        );
        assert_eq!(
            read_any_range_for_viewer(backend, &manifest, &alice_occ, 895, 905, None)
                .await
                .unwrap(),
            plain[895..=905].to_vec(),
            "{tag} I38: a range across the rotation boundary"
        );

        // Bob (removed at the rotation): refused at the manifest; still holds
        // what he could already read; refused what came after.
        assert!(
            matches!(
                read_any_for_viewer(backend, &manifest, &bob_occ, None).await,
                Err(BlobError::NotGranted { .. })
            ),
            "{tag} I38: the removed member is refused the post-rotation manifest"
        );
        assert_eq!(
            super::orchestrate::read_stream_chunk_as(backend, &stream, 0, &bob_occ, None)
                .await
                .unwrap(),
            seg0,
            "{tag} I38: AV-70 forward-only — bob keeps the pre-rotation chunk (by position)"
        );
        assert!(
            matches!(
                super::orchestrate::read_stream_chunk_as(backend, &stream, 1, &bob_occ, None).await,
                Err(BlobError::NotGranted { .. })
            ),
            "{tag} I38: bob is refused the post-rotation chunk"
        );
    }

    // ── I41 ──────────────────────────────────────────────────────────────
    /// **A stream belongs to its first append** (§12.9, #837). The first
    /// chunk of a `stream_id` fixes its cohort, community and WRITER; a later
    /// append that does not match all three is refused AT THAT CHUNK, storing
    /// nothing, with a refusal that names the stream's cohort and community
    /// and never the owner's key; the owner keeps appending; a seal by a
    /// different signer is refused; the seal over a mixed stream stays
    /// refused by I32; an unclaimed (commons-started) stream is adopted by
    /// its first attributed append and is then owned; `stream_chunks`
    /// reports the row.
    ///
    /// Written first in a PROBE form against the v44.0.0 surface (the door
    /// had no writer parameter, so the foreign append was a second
    /// community, a second cohort and the commons door on one id) and RED
    /// on 8d5e860 on both backends: the second community's append returned
    /// `Ok` and interleaved. This is the final form, with two writers.
    pub async fn exercise_i41_a_stream_belongs_to_its_first_append<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::types::cohort_scope::FEDERATION;
        use crate::federation::{StorageFloor, StreamClaim, StreamHead};
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        seed_community(backend, &comm, &[(&alice, &alice_occ)]).await;
        let other = format!("{tag}-other-{run}");
        let bob = format!("{tag}-bob-{run}");
        let bob_occ = format!("{tag}-bob-occ-{run}");
        seed_community(backend, &other, &[(&bob, &bob_occ)]).await;
        // Two writers, each a registered node key.
        let writer_a = crate::signing::LocalSignerHardwareAdapter::new(
            crate::federation::at_rest_cascade::blob_invariants::node_signer(
                backend,
                &format!("{tag}-writer-a-{run}"),
            )
            .await,
        );
        let writer_b = crate::signing::LocalSignerHardwareAdapter::new(
            crate::federation::at_rest_cascade::blob_invariants::node_signer(
                backend,
                &format!("{tag}-writer-b-{run}"),
            )
            .await,
        );
        let key_a = crate::signing::federation_key_id_of(&writer_a)
            .await
            .unwrap();
        let key_b = crate::signing::federation_key_id_of(&writer_b)
            .await
            .unwrap();
        assert_ne!(key_a, key_b);
        let stream = format!("{tag}-stream-{run}");

        put_blob_chunk_scoped(
            backend,
            &writer_a,
            COMMUNITY,
            Some(&comm),
            &stream,
            0,
            b"first",
            0,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I41: the first append: {e}"));
        assert_eq!(
            backend.stream_chunks(&stream).await.unwrap().stream,
            Some(StreamHead {
                cohort_scope: COMMUNITY.into(),
                community_key_id: Some(comm.clone()),
                owner_key_id: Some(key_a.clone()),
            }),
            "{tag} I41: the first append wrote the stream's row"
        );

        // A SECOND WRITER, same community, at a seq the first never used:
        // refused at its first chunk, nothing stored, the owner not named.
        let res = put_blob_chunk_scoped(
            backend,
            &writer_b,
            COMMUNITY,
            Some(&comm),
            &stream,
            1,
            b"interloper",
            0,
            None,
        )
        .await;
        match res {
            Err(BlobError::InvalidArgument(msg)) => {
                assert!(
                    msg.contains(&comm) && msg.contains(COMMUNITY),
                    "{tag} I41: the refusal names the stream's cohort and community: {msg}"
                );
                assert!(
                    !msg.contains(&key_a),
                    "{tag} I41: the refusal must not name the owner's key to a non-owner: {msg}"
                );
            }
            other => panic!(
                "{tag} I41: a second writer appended to a stream the first writer started — \
                 the id was shared until the seal: {other:?}"
            ),
        }
        assert_eq!(
            backend.stream_chunks(&stream).await.unwrap().chunks.len(),
            1,
            "{tag} I41: a refused append stores nothing"
        );
        assert!(
            !backend.has_blob(&sha(b"interloper")).await.unwrap(),
            "{tag} I41: no plaintext of a refused append is on disk"
        );

        // The same writer, another community on the same id.
        let res = put_blob_chunk_scoped(
            backend,
            &writer_a,
            COMMUNITY,
            Some(&other),
            &stream,
            1,
            b"elsewhere",
            0,
            None,
        )
        .await;
        match res {
            Err(BlobError::InvalidArgument(msg)) => assert!(
                msg.contains(&comm),
                "{tag} I41: the refusal names the stream's community: {msg}"
            ),
            other => panic!("{tag} I41: another community appended to the stream: {other:?}"),
        }
        // The same writer, another cohort on the same id.
        let res = put_blob_chunk_scoped(
            backend,
            &writer_a,
            SELF,
            Some(&alice),
            &stream,
            2,
            b"mine",
            0,
            None,
        )
        .await;
        match res {
            Err(BlobError::InvalidArgument(msg)) => assert!(
                msg.contains(COMMUNITY),
                "{tag} I41: the refusal names the stream's cohort: {msg}"
            ),
            other => panic!("{tag} I41: another cohort appended to a community stream: {other:?}"),
        }
        // The commons door (no writer at all) on the same id.
        let res = backend
            .put_blob_chunk(&stream, 3, BlobBody::Inline(b"public".to_vec()), 0)
            .await;
        assert!(
            matches!(res, Err(BlobError::InvalidArgument(_))),
            "{tag} I41: the commons door appended to a community stream: {res:?}"
        );

        // The owner keeps appending.
        put_blob_chunk_scoped(
            backend,
            &writer_a,
            COMMUNITY,
            Some(&comm),
            &stream,
            1,
            b"second",
            0,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I41: the owner's second append: {e}"));
        assert_eq!(
            backend.stream_chunks(&stream).await.unwrap().chunks.len(),
            2
        );

        // A FOREIGN SEAL is refused, without naming the owner; the owner's
        // seal is not.
        let res = seal_stream_scoped(
            backend,
            &writer_b,
            COMMUNITY,
            Some(&comm),
            &stream,
            None,
            None,
        )
        .await;
        match res {
            Err(BlobError::InvalidArgument(msg)) => assert!(
                !msg.contains(&key_a),
                "{tag} I41: the seal refusal must not name the owner's key: {msg}"
            ),
            other => panic!("{tag} I41: a non-owner sealed the stream: {other:?}"),
        }
        // The seal at another community / cohort is refused too, naming
        // the stream's.
        let res = seal_stream_scoped(
            backend,
            &writer_a,
            COMMUNITY,
            Some(&other),
            &stream,
            None,
            None,
        )
        .await;
        match res {
            Err(BlobError::InvalidArgument(msg)) => assert!(
                msg.contains(&comm),
                "{tag} I41: the seal refusal names the stream's community: {msg}"
            ),
            other => panic!("{tag} I41: the stream sealed under another community: {other:?}"),
        }
        let sealed = seal_stream_scoped(
            backend,
            &writer_a,
            COMMUNITY,
            Some(&comm),
            &stream,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I41: the owner's seal: {e}"));
        assert_eq!(sealed.chunk_count, 2);

        // The seal over a MIXED stream stays refused by I32 (the second
        // guard): a plaintext row placed through the floor with the owner's
        // own claim — the infra-community shape — under the owner's seal.
        let mixed = format!("{tag}-mixed-{run}");
        put_blob_chunk_scoped(
            backend,
            &writer_a,
            COMMUNITY,
            Some(&comm),
            &mixed,
            0,
            b"sealed",
            0,
            None,
        )
        .await
        .unwrap();
        backend
            .put_blob_chunk_with_scope(
                &mixed,
                1,
                BlobBody::Inline(b"in the clear".to_vec()),
                0,
                12,
                COMMUNITY,
                StorageFloor::resolved(CryptoTier::Plaintext),
                None,
                StreamClaim {
                    community_key_id: Some(comm.clone()),
                    owner_key_id: Some(key_a.clone()),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I41: the owner's claim passes the floor: {e}"));
        match seal_stream_scoped(
            backend,
            &writer_a,
            COMMUNITY,
            Some(&comm),
            &mixed,
            None,
            None,
        )
        .await
        {
            Err(BlobError::InvalidArgument(msg)) => assert!(
                msg.contains("tier"),
                "{tag} I41: the mixed stream is refused by I32's tier check: {msg}"
            ),
            other => panic!("{tag} I41: a mixed stream sealed: {other:?}"),
        }

        // An UNCLAIMED stream (commons-started: no writer) is adopted by its
        // first attributed append, and is then owned.
        let unclaimed = format!("{tag}-unclaimed-{run}");
        backend
            .put_blob_chunk(&unclaimed, 0, BlobBody::Inline(b"public 0".to_vec()), 0)
            .await
            .unwrap();
        assert_eq!(
            backend.stream_chunks(&unclaimed).await.unwrap().stream,
            Some(StreamHead {
                cohort_scope: FEDERATION.into(),
                community_key_id: None,
                owner_key_id: None,
            }),
            "{tag} I41: the commons door starts an unclaimed stream"
        );
        put_blob_chunk_scoped(
            backend,
            &writer_b,
            FEDERATION,
            None,
            &unclaimed,
            1,
            b"public 1",
            0,
            None,
        )
        .await
        .unwrap_or_else(|e| {
            panic!("{tag} I41: an attributed append adopts an unclaimed stream: {e}")
        });
        assert_eq!(
            backend
                .stream_chunks(&unclaimed)
                .await
                .unwrap()
                .stream
                .and_then(|h| h.owner_key_id),
            Some(key_b.clone()),
            "{tag} I41: adopted"
        );
        let res = put_blob_chunk_scoped(
            backend,
            &writer_a,
            FEDERATION,
            None,
            &unclaimed,
            2,
            b"public 2",
            0,
            None,
        )
        .await;
        assert!(
            matches!(res, Err(BlobError::InvalidArgument(_))),
            "{tag} I41: an adopted stream is owned: {res:?}"
        );
        let res = backend
            .put_blob_chunk(&unclaimed, 2, BlobBody::Inline(b"public 2".to_vec()), 0)
            .await;
        assert!(
            matches!(res, Err(BlobError::InvalidArgument(_))),
            "{tag} I41: the commons door cannot append to an owned stream: {res:?}"
        );
    }

    // ── I42 ──────────────────────────────────────────────────────────────
    /// **A chunk is bound to its position** (§12.10, #838). A manifest over
    /// the same rows with two chunks swapped — carrying the swapped
    /// positions, sealed under the community's own DEK, stored through the
    /// floor — does not open: the range read across the boundary and the
    /// whole read fail as a crypto-class error AFTER authorization (a
    /// stranger is still `NotGranted`). A chunk row lifted into a second
    /// stream's DAG does not open there. A stream chunk reads by POSITION
    /// (`read_stream_chunk_as`), at its own position only; by its sha alone
    /// it no longer opens. The honest DAG still opens.
    ///
    /// Written first in a PROBE form (a swapped manifest without positions,
    /// against v44.0.0's reader) and RED on 8d5e860 on both backends: "a
    /// chunk moved to another index OPENED (100 bytes)". This is the final
    /// form.
    pub async fn exercise_i42_a_chunk_is_bound_to_its_position<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use super::orchestrate::read_stream_chunk_as;
        use crate::federation::at_rest_cascade::seal;
        use crate::federation::blobs::{
            ChunkManifest, ChunkRef, EpochBinding, ManifestRowSpec, CHUNK_MANIFEST_VERSION_SEALED,
        };
        use crate::federation::community_dek::orchestrate::ensure_epoch_dek;
        use crate::federation::{StorageFloor, StreamClaim};
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        seed_community(backend, &comm, &[(&alice, &alice_occ)]).await;
        let stranger = format!("{tag}-stranger-{run}");
        let writer = crate::signing::LocalSignerHardwareAdapter::new(
            crate::federation::at_rest_cascade::blob_invariants::node_signer(
                backend,
                &format!("{tag}-writer-{run}"),
            )
            .await,
        );
        let owner = crate::signing::federation_key_id_of(&writer).await.unwrap();
        let stream = format!("{tag}-stream-{run}");
        let segs = [segment(31, 100), segment(32, 200)];
        let (manifest, shas, plain) =
            sealed_community_stream_as(backend, &writer, tag, &comm, &stream, &segs).await;

        // The honest read, across the boundary and whole.
        assert_eq!(
            read_any_range_for_viewer(backend, &manifest, &alice_occ, 90, 110, None)
                .await
                .unwrap(),
            plain[90..=110].to_vec(),
            "{tag} I42: the honest range read opens"
        );
        assert_eq!(
            read_any_for_viewer(backend, &manifest, &alice_occ, None)
                .await
                .unwrap(),
            plain,
            "{tag} I42: the honest whole read opens"
        );

        // A manifest over the SAME rows with the two chunks SWAPPED — each
        // now claiming the other's position — sealed under the community's
        // DEK (reached the way the door reaches it) and stored through the
        // floor as a second DAG over the stream.
        let epoch = backend.community_dek_current_epoch(&comm).await.unwrap();
        let (dek, _, _) = ensure_epoch_dek(backend, &comm, epoch).await.unwrap();
        let swapped = ChunkManifest {
            v: CHUNK_MANIFEST_VERSION_SEALED,
            total_size: 300,
            chunks: vec![
                ChunkRef {
                    sha: shas[1],
                    size: 200,
                    seq: Some(0),
                },
                ChunkRef {
                    sha: shas[0],
                    size: 100,
                    seq: Some(1),
                },
            ],
            chunk_tier: Some(CryptoTier::CommunityDek),
            stream_id: Some(stream.clone()),
        };
        let body = seal(&dek, &swapped.to_jcs_bytes(), None)
            .unwrap()
            .to_bytes();
        let swapped_sha = sha(&body);
        backend
            .seal_stream_with_scope(
                &stream,
                ManifestRowSpec {
                    sha256: swapped_sha,
                    size_bytes: body.len() as u64,
                    body,
                    expected_chunk_count: 2,
                },
                None,
                COMMUNITY,
                StorageFloor::resolved(CryptoTier::CommunityDek),
                Some(EpochBinding {
                    community_key_id: comm.clone(),
                    epoch,
                }),
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I42: the floor stores a second DAG: {e}"));

        // A stranger is refused before any chunk is touched.
        assert!(
            matches!(
                read_any_range_for_viewer(backend, &swapped_sha, &stranger, 0, 10, None).await,
                Err(BlobError::NotGranted { .. })
            ),
            "{tag} I42: the stranger is refused at the manifest"
        );
        // The member: a chunk at another index does not open — a
        // crypto-class error, never bytes, never NotGranted.
        match read_any_range_for_viewer(backend, &swapped_sha, &alice_occ, 0, 99, None).await {
            Err(BlobError::Backend(_)) => {}
            Err(other) => panic!("{tag} I42: wrong refusal class for a moved chunk: {other:?}"),
            Ok(bytes) => panic!(
                "{tag} I42: a chunk moved to another index OPENED ({} bytes) — the chunk's \
                 AAD does not carry its position",
                bytes.len()
            ),
        }
        match read_any_for_viewer(backend, &swapped_sha, &alice_occ, None).await {
            Err(BlobError::Backend(_)) => {}
            other => panic!("{tag} I42: the whole read of a swapped DAG: {other:?}"),
        }

        // Lifted into a second stream's DAG, by the SAME writer (so #837
        // admits it): the row exists (content-addressed); the index row is
        // what a lift is. Sealed through the door, it must not open there.
        let stream2 = format!("{tag}-stream2-{run}");
        let Some(BlobBody::Inline(bytes0)) = backend.get_blob(&shas[0]).await.unwrap() else {
            panic!("{tag} I42: chunk 0 is inline");
        };
        backend
            .put_blob_chunk_with_scope(
                &stream2,
                0,
                BlobBody::Inline(bytes0),
                0,
                100,
                COMMUNITY,
                StorageFloor::resolved(CryptoTier::CommunityDek),
                Some(EpochBinding {
                    community_key_id: comm.clone(),
                    epoch,
                }),
                StreamClaim {
                    community_key_id: Some(comm.clone()),
                    owner_key_id: Some(owner.clone()),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I42: lift through the floor: {e}"));
        let sealed2 = seal_stream_scoped(
            backend,
            &writer,
            COMMUNITY,
            Some(&comm),
            &stream2,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I42: the second stream seals: {e}"));
        match read_any_for_viewer(backend, &sealed2.manifest_sha256, &alice_occ, None).await {
            Err(BlobError::Backend(_)) => {}
            Err(other) => panic!("{tag} I42: wrong refusal class for a lifted chunk: {other:?}"),
            Ok(_) => panic!(
                "{tag} I42: a chunk lifted into a second stream's DAG OPENED there — the \
                 chunk's AAD does not carry its stream"
            ),
        }

        // By POSITION: the chunk opens at its own position, for a member,
        // whole; not at the lifted position; not for a stranger; and not by
        // its sha alone through the whole-blob doors (the sha carries no
        // position), as a crypto-class error after authorization.
        assert_eq!(
            read_stream_chunk_as(backend, &stream, 0, &alice_occ, None)
                .await
                .unwrap(),
            segs[0],
            "{tag} I42: the by-position read opens the chunk at its own position"
        );
        assert_eq!(
            read_stream_chunk_as(backend, &stream, 1, &alice_occ, None)
                .await
                .unwrap(),
            segs[1]
        );
        match read_stream_chunk_as(backend, &stream2, 0, &alice_occ, None).await {
            Err(BlobError::Backend(_)) => {}
            other => panic!("{tag} I42: the lifted position opened the chunk: {other:?}"),
        }
        assert!(
            matches!(
                read_stream_chunk_as(backend, &stream, 0, &stranger, None).await,
                Err(BlobError::NotGranted { .. })
            ),
            "{tag} I42: the by-position read authorizes first"
        );
        assert!(
            matches!(
                read_stream_chunk_as(backend, &stream, 7, &alice_occ, None).await,
                Err(BlobError::InvalidArgument(_))
            ),
            "{tag} I42: an unknown position is InvalidArgument"
        );
        match read_any_range_for_viewer(backend, &shas[0], &alice_occ, 0, 9, None).await {
            Err(BlobError::Backend(_)) => {}
            other => panic!(
                "{tag} I42: a sealed stream chunk opened by its sha alone — the position \
                 binding is not enforced: {other:?}"
            ),
        }
        // The honest DAG is untouched by any of it.
        assert_eq!(
            read_any_for_viewer(backend, &manifest, &alice_occ, None)
                .await
                .unwrap(),
            plain
        );
    }

    /// A SECOND occurrence of an already-registered identity: registers the
    /// occurrence key and publishes a keyed occurrence, without touching
    /// the identity's own key row (`seed_member` re-registers it).
    async fn seed_occurrence<B>(backend: &B, identity_key_id: &str, occurrence_key_id: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::tier_ingest::test_support as ts;
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        ts::register_hybrid_key_as(
            backend,
            occurrence_key_id,
            occurrence_key_id,
            crate::federation::types::identity_type::USER,
        )
        .await;
        let (_xp, x_pub, _mp, ml_pub) =
            crate::federation::identity_aggregate::mint_content_kem_keypair().expect("mint kem");
        backend
            .put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: identity_key_id.to_owned(),
                occurrence_key_id: occurrence_key_id.to_owned(),
                device_class: crate::federation::types::device_class::SERVER.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(crate::federation::EncryptionPubkeys {
                    x25519_base64: B64.encode(x_pub),
                    ml_kem_768_base64: B64.encode(&ml_pub),
                }),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap_or_else(|e| panic!("seed occurrence {occurrence_key_id}: {e}"));
    }

    // ── fixtures for the STH leg of I37 ─────────────────────────────────
    /// A registered hybrid producer key (the same shape as the sqlite STH
    /// tests' `register_hybrid_producer`, generic over the backend). BOXED
    /// and built before the await: the multi-KiB ML-DSA-65 signer must not
    /// live across an await on a 2 MiB test-thread stack.
    async fn register_hybrid_producer<B>(
        backend: &B,
        key_id: &str,
    ) -> Box<ciris_crypto::HybridSigner<ciris_crypto::Ed25519Signer, ciris_crypto::MlDsa65Signer>>
    where
        B: FederationDirectory + Sync,
    {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let ed = ciris_crypto::Ed25519Signer::from_seed(&[0x51; 32]).unwrap();
        let mldsa = ciris_crypto::MlDsa65Signer::from_seed(&[0x52; 32]).unwrap();
        let ed_pub_b64 = {
            use ciris_crypto::ClassicalSigner as _;
            B64.encode(ed.public_key().unwrap())
        };
        let mldsa_pub_b64 = {
            use ciris_crypto::PqcSigner as _;
            B64.encode(mldsa.public_key().unwrap())
        };
        let signer = Box::new(ciris_crypto::HybridSigner::new(ed, mldsa).unwrap());
        let record = crate::federation::KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pub_b64,
            pubkey_ml_dsa_65_base64: Some(mldsa_pub_b64),
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: key_id.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
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
            .put_public_key(crate::federation::SignedKeyRecord { record })
            .await
            .unwrap();
        signer
    }

    fn sign_stream_sth(
        signer: &ciris_crypto::HybridSigner<
            ciris_crypto::Ed25519Signer,
            ciris_crypto::MlDsa65Signer,
        >,
        stream_id: &str,
        chunk_hashes: &[[u8; 32]],
        tree_size: u64,
    ) -> ciris_verify_core::transparency::SignedTreeHead {
        use crate::federation::stream_sth::StreamChunkLeaf;
        use ciris_verify_core::transparency::{InMemoryTransparencyStore, TransparencyStore};
        let store: InMemoryTransparencyStore<StreamChunkLeaf> =
            InMemoryTransparencyStore::new(None);
        for sha in &chunk_hashes[..tree_size as usize] {
            store.append(StreamChunkLeaf::new(*sha)).unwrap();
        }
        let root_hash = store.root().unwrap();
        let log_id = crate::federation::stream_sth::log_id_for_stream(stream_id);
        let timestamp = chrono::Utc::now();
        let signing_bytes = ciris_verify_core::transparency::SignedTreeHead::signing_bytes(
            &log_id, tree_size, &root_hash, timestamp,
        );
        let signature = signer.sign(&signing_bytes).unwrap();
        ciris_verify_core::transparency::SignedTreeHead {
            log_id,
            tree_size,
            root_hash,
            timestamp,
            signature,
            witness_signatures: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    /// #838 (§12.10) — **the chunk AAD's bytes are pinned.** Domain label,
    /// u64-BE length-prefixed caller data (absent ⇒ 0), u64-BE
    /// length-prefixed stream id, u64-BE seq. A change here changes what
    /// every sealed chunk opens under; the FSD's layout is this test.
    #[test]
    fn chunk_aad_bytes_are_pinned() {
        use super::chunk_aad;
        let mut want = b"ciris-persist:chunk:v1".to_vec();
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 3]);
        want.extend_from_slice(b"row");
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 4]);
        want.extend_from_slice(b"s-01");
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 2]);
        assert_eq!(chunk_aad(Some(b"row"), "s-01", 258), want);
        // No caller data: a zero length, then the position.
        let mut want = b"ciris-persist:chunk:v1".to_vec();
        want.extend_from_slice(&[0; 8]);
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        want.extend_from_slice(b"x");
        want.extend_from_slice(&[0; 8]);
        assert_eq!(chunk_aad(None, "x", 0), want);
        assert_eq!(chunk_aad(None, "x", 0), chunk_aad(Some(b""), "x", 0));
        // Length prefixes keep the boundary: (caller "ab", stream "c") and
        // (caller "a", stream "bc") are different bytes.
        assert_ne!(
            chunk_aad(Some(b"ab"), "c", 0),
            chunk_aad(Some(b"a"), "bc", 0)
        );
        assert_ne!(chunk_aad(None, "s", 0), chunk_aad(None, "s", 1));
        assert_ne!(chunk_aad(None, "s", 0), chunk_aad(None, "t", 0));
    }

    /// I35 — the production whole-read door passes the documented cap, so
    /// the capped internal the witness drives is the code a consumer hits.
    #[test]
    fn the_whole_read_door_passes_the_cap_constant() {
        let src = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src/federation/chunk_dag_cascade.rs"),
        )
        .unwrap();
        let at = src
            .find("pub(crate) async fn read_dag_for_viewer_authorized<")
            .expect("the uncapped wrapper");
        let body = &src[at..at + src[at..].find("\n    }\n").expect("body end")];
        assert!(
            body.contains("DAG_WHOLE_READ_CAP_BYTES"),
            "I35: the whole-read wrapper no longer passes DAG_WHOLE_READ_CAP_BYTES"
        );
    }
}
