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

use crate::federation::blobs::{BlobBody, BlobError, BlobStorage, RosterPartition};
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

/// v52.0.0 (CIRISPersist#954) — the domain-separation label of a nested
/// manifest CHILD's AAD. Distinct from [`CHUNK_AAD_DOMAIN`], so a child never
/// opens as a chunk and a chunk never opens as a child.
pub const MANIFEST_CHILD_AAD_DOMAIN: &[u8] = b"ciris-persist:manifest-child:v1";

/// v52.0.0 (#954) — **a v3 child's associated data is its index in its
/// stream's root**: the construction of [`chunk_aad`] under
/// [`MANIFEST_CHILD_AAD_DOMAIN`], with the child's index where a chunk has
/// its `seq`. A child moved to another index, lifted into another stream's
/// DAG, or presented as a chunk fails to open.
#[must_use]
pub fn manifest_child_aad(caller_aad: Option<&[u8]>, stream_id: &str, index: u64) -> Vec<u8> {
    let caller = caller_aad.unwrap_or(&[]);
    let mut out = Vec::with_capacity(
        MANIFEST_CHILD_AAD_DOMAIN.len() + 8 + caller.len() + 8 + stream_id.len() + 8,
    );
    out.extend_from_slice(MANIFEST_CHILD_AAD_DOMAIN);
    out.extend_from_slice(&(caller.len() as u64).to_be_bytes());
    out.extend_from_slice(caller);
    out.extend_from_slice(&(stream_id.len() as u64).to_be_bytes());
    out.extend_from_slice(stream_id.as_bytes());
    out.extend_from_slice(&index.to_be_bytes());
    out
}

/// v52.0.0 (CIRISPersist#954) — what `Engine::abandon_stream` did.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct AbandonReport {
    /// The stream was already abandoned; nothing was done (idempotent).
    pub already: bool,
    /// Index rows deleted.
    pub chunks_dropped: u64,
    /// Stored bytes of the sealed chunk rows evicted.
    pub bytes_evicted: u64,
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
    /// #843 (§12.11, I54) — the same fan-out by roster MEMBER. Empty at
    /// the plaintext tier.
    pub roster: RosterPartition,
    /// #848 (§14) — the `KeyGrant` set the door emits after this append, if
    /// the fan-out changed (see `PutBlobScopedResult::key_grant_emission`).
    pub key_grant_emission: Option<crate::federation::key_grant::KeyGrantAxis>,
}

impl PutChunkScopedResult {
    /// #843 — can NOBODY read this chunk? `false` at the plaintext tier;
    /// otherwise a roster fact.
    #[must_use]
    pub fn readable_by_nobody(&self) -> bool {
        self.tier != CryptoTier::Plaintext && self.roster.readable_by_nobody()
    }
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
    /// #843 (§12.11, I54) — the same fan-out by roster MEMBER. Empty at
    /// the plaintext tier.
    pub roster: RosterPartition,
    /// #848 (§14) — the `KeyGrant` set the door emits after this seal, if
    /// the fan-out changed (see `PutBlobScopedResult::key_grant_emission`).
    pub key_grant_emission: Option<crate::federation::key_grant::KeyGrantAxis>,
    /// v51.0.0 (#923 amendment 2, D9) — the chunk rows the seal granted to
    /// the stream's one access set that lacked it (a self/family stream
    /// written across an occurrence change). Each is a content-axis key-grant
    /// set the caller emits, as it emits [`Self::key_grant_emission`].
    pub chunk_key_grant_emissions: Vec<crate::federation::key_grant::KeyGrantAxis>,
    /// v53.0.0 (CIRISPersist#969) — the stream epochs the seal wrapped to a
    /// recipient that lacked them: one stream-axis set per such epoch, which
    /// the caller emits beside [`Self::key_grant_emission`]. A stream-keyed
    /// DAG's [`Self::chunk_key_grant_emissions`] is empty.
    pub stream_key_grant_emissions: Vec<crate::federation::key_grant::KeyGrantAxis>,
}

impl SealStreamScopedResult {
    /// #843 — can NOBODY read this DAG's manifest? `false` at the plaintext
    /// tier; otherwise a roster fact.
    #[must_use]
    pub fn readable_by_nobody(&self) -> bool {
        self.tier != CryptoTier::Plaintext && self.roster.readable_by_nobody()
    }
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
        fresh_dek, resolve_write_tier, seal, sealed_plaintext_len, unwrap_dek_for_persist,
        AtRestEnvelope, AtRestError, PERSIST_SELF_RECIPIENT,
    };
    use crate::federation::blobs::{
        BlobHead, ChunkManifest, ChunkRef, EpochBinding, ManifestChildRef, ManifestChildRow,
        ManifestRowSpec, NestedManifest, ParsedManifest, StreamChunkRef, StreamClaim,
        CHUNK_MANIFEST_VERSION, CHUNK_MANIFEST_VERSION_SEALED,
    };
    use crate::federation::community_dek::orchestrate::{
        ensure_epoch_dek, open_community_row_for_viewer, read_for_community_viewer_sealed,
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
            stream_key: None,
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
                    roster: RosterPartition::default(),
                    key_grant_emission: None,
                })
            }
            CryptoTier::InvisibleEncrypted => {
                let owner = community_key_id.ok_or_else(|| {
                    BlobError::InvalidArgument(format!(
                        "cohort_scope {cohort_scope:?} requires the owner (self) or family key id \
                         in the community_key_id argument"
                    ))
                })?;
                // v53.0.0 (#969, CC 5.3.3.1) — a stream is sealed under ONE
                // DEK per (stream_id, epoch) with the STREAM nonce. Only a
                // stream that already holds per-chunk-keyed chunks (written
                // before #969: chunks and no stream DEK) keeps per-chunk DEKs
                // to its seal — one DAG never mixes the two.
                let state = backend.stream_key_state(stream_id).await?;
                if state.latest.is_some() || !state.has_chunks {
                    return put_stream_keyed_chunk(
                        backend,
                        StreamWrite {
                            cohort_scope,
                            group_key_id: owner,
                            writer_key_id: &owner_key_id,
                            community_key_id,
                            stream_id,
                            epoch,
                        },
                        seq,
                        plaintext,
                        aad,
                        state,
                    )
                    .await;
                }
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
                let report = grant_dek_to_cohort(backend, &sha, cohort_scope, owner, &dek).await?;
                Ok(PutChunkScopedResult {
                    chunk_sha256: sha,
                    tier,
                    epoch: None,
                    granted: report.granted,
                    excluded: report.excluded,
                    roster: report.roster,
                    // #848 (§14, content axis) — a fresh per-chunk DEK is a
                    // new set every time.
                    key_grant_emission: Some(crate::federation::key_grant::KeyGrantAxis::Content {
                        at_rest_sha256: hex::encode(sha),
                        cohort_scope: cohort_scope.to_owned(),
                        owner_key_id: owner.to_owned(),
                    }),
                })
            }
            CryptoTier::CommunityDek => {
                let comm = community_key_id.ok_or_else(|| {
                    BlobError::InvalidArgument("community_key_id required".into())
                })?;
                let mut last_epoch = 0;
                // #848 (§11) — the minter is the writer (I23).
                let minter = owner_key_id.as_str();
                for _ in 0..EPOCH_RACE_ATTEMPTS {
                    let dek_epoch = backend.community_dek_current_epoch(comm, minter).await?;
                    let ensured = ensure_epoch_dek(backend, comm, minter, dek_epoch).await?;
                    let dek_epoch = ensured.epoch;
                    let envelope =
                        seal(&ensured.dek, plaintext, Some(&bound_aad)).map_err(map_at_rest_err)?;
                    let report = ensured.report;
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
                                minter_key_id: minter.to_owned(),
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
                                granted: report.granted,
                                excluded: report.excluded,
                                roster: report.roster,
                                key_grant_emission: ensured.changed.then(|| {
                                    crate::federation::key_grant::KeyGrantAxis::Epoch {
                                        community_key_id: comm.to_owned(),
                                        minter_key_id: minter.to_owned(),
                                        epoch: dek_epoch,
                                    }
                                }),
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

    // ── the stream-epoch DEK (v53.0.0, CIRISPersist#969) ────────────────

    /// How many times a stream-keyed append re-reads the stream's key state
    /// and re-seals: a lost counter race, a roll (cap or removal) between
    /// the read and the floor. Each pass either stores or moves the state
    /// forward, so the bound is never reached by a single writer.
    const STREAM_SEAL_ATTEMPTS: usize = 8;

    /// The fixed facts of one stream-keyed append (or terminator).
    #[derive(Clone, Copy)]
    struct StreamWrite<'a> {
        cohort_scope: &'a str,
        group_key_id: &'a str,
        writer_key_id: &'a str,
        community_key_id: Option<&'a str>,
        stream_id: &'a str,
        epoch: u64,
    }

    /// v53.0.0 (#969) — the epoch a stream-keyed append seals under, given
    /// the stream's newest DEK row: the producer's epoch label, never below
    /// the stream's current epoch, and past it once that epoch is closed (a
    /// forced roll at the nonce cap, a removal roll, or a terminator). Pure.
    pub(crate) fn stream_target_epoch(
        latest: Option<&crate::federation::StreamDekRecord>,
        producer_epoch: u64,
    ) -> u64 {
        match latest {
            None => producer_epoch,
            Some(l) if l.closed || l.terminated => producer_epoch.max(l.epoch.saturating_add(1)),
            Some(l) => producer_epoch.max(l.epoch),
        }
    }

    /// v53.0.0 (#969) — the epoch's DEK row: the stream's newest when it is
    /// the target, else minted (a fresh DEK, self-retained under the content
    /// master) — TERMINATING the previous epoch first (the producer rolled
    /// to a higher label), so a stream has ONE open epoch and every epoch it
    /// leaves carries its `last`. Two racing first chunks resolve to one row
    /// (`stream_dek_insert` returns the stored row).
    async fn ensure_stream_epoch<B>(
        backend: &B,
        w: StreamWrite<'_>,
        latest: Option<crate::federation::StreamDekRecord>,
        aad: Option<&[u8]>,
    ) -> Result<crate::federation::StreamDekRecord, BlobError>
    where
        B: BlobStorage + Sync,
    {
        let target = stream_target_epoch(latest.as_ref(), w.epoch);
        if let Some(l) = latest {
            if l.epoch == target {
                return Ok(l);
            }
            if !l.terminated {
                write_terminator(backend, w, l, aad).await?;
            }
        }
        let dek = fresh_dek().map_err(map_at_rest_err)?;
        let content_master = backend.load_or_init_content_master().await?;
        let self_retention_wrap =
            crate::federation::at_rest_cascade::wrap_dek_for_persist(&content_master, &dek)
                .map_err(map_at_rest_err)?;
        backend
            .stream_dek_insert(&crate::federation::StreamDekRecord {
                stream_id: w.stream_id.to_owned(),
                epoch: target,
                owner_key_id: w.writer_key_id.to_owned(),
                cohort_scope: w.cohort_scope.to_owned(),
                group_key_id: w.group_key_id.to_owned(),
                self_retention_wrap,
                chunk_count: 0,
                closed: false,
                terminated: false,
            })
            .await
    }

    /// v53.0.0 (#969) — recover a stream epoch's DEK from its row's
    /// self-retention wrap (this node sealed it).
    async fn stream_epoch_dek<B>(
        backend: &B,
        rec: &crate::federation::StreamDekRecord,
    ) -> Result<[u8; 32], BlobError>
    where
        B: BlobStorage + Sync,
    {
        let content_master = backend.load_or_init_content_master().await?;
        unwrap_dek_for_persist(&content_master, &rec.self_retention_wrap).map_err(map_at_rest_err)
    }

    /// v53.0.0 (#969) — wrap the epoch's DEK to every target lacking a wrap
    /// under the stream's owner. Returns the recipients written.
    async fn grant_stream_epoch<B>(
        backend: &B,
        rec: &crate::federation::StreamDekRecord,
        dek: &[u8; 32],
        targets: &[(String, crate::federation::types::EncryptionPubkeys)],
        held: &std::collections::HashSet<String>,
    ) -> Result<usize, BlobError>
    where
        B: BlobStorage + Sync,
    {
        let mut wraps = Vec::new();
        for (occ, k) in targets {
            if held.contains(occ) {
                continue;
            }
            wraps.push(crate::federation::GrantWrap {
                recipient_key_id: occ.clone(),
                wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.to_owned(),
                wrapped_dek: crate::federation::at_rest_cascade::wrap_dek_v2(
                    &k.x25519_base64,
                    &k.ml_kem_768_base64,
                    dek,
                )
                .map_err(map_at_rest_err)?,
            });
        }
        if wraps.is_empty() {
            return Ok(0);
        }
        backend
            .stream_dek_put_grants(
                &rec.stream_id,
                rec.epoch,
                &rec.owner_key_id,
                &rec.cohort_scope,
                &wraps,
            )
            .await?;
        Ok(wraps.len())
    }

    /// v53.0.0 (#969) — seal one chunk under the stream epoch's DEK with the
    /// STREAM nonce `(counter, last)` and the position-bound AAD.
    fn seal_stream_chunk(
        dek: &[u8; 32],
        stream_id: &str,
        epoch: u64,
        slot: crate::federation::StreamKeySlot,
        plaintext: &[u8],
        bound_aad: &[u8],
    ) -> Result<AtRestEnvelope, BlobError> {
        let nonce = crate::federation::stream_seal::stream_nonce(
            dek,
            stream_id,
            epoch,
            slot.counter,
            slot.last,
        )
        .map_err(|e| BlobError::Backend(format!("stream nonce: {e}")))?;
        crate::federation::at_rest_cascade::seal_aad_at_nonce(dek, nonce, bound_aad, plaintext)
            .map_err(map_at_rest_err)
    }

    /// v53.0.0 (#969, CC 5.3.3.1) — open a stream-keyed chunk: read
    /// `(counter, last)` from the stored nonce, require the stored nonce to
    /// BE `stream_nonce(dek, stream_id, epoch, counter, last)` (a prefix that
    /// does not belong to this DEK, stream and epoch fails closed before the
    /// open), then open under the position-bound AAD. Returns the plaintext
    /// and the slot, for the caller's per-epoch structure check.
    pub(crate) fn open_stream_keyed_chunk(
        dek: &[u8; 32],
        stream_id: &str,
        epoch: u64,
        chunk_sha: &[u8; 32],
        envelope: &AtRestEnvelope,
        bound_aad: &[u8],
    ) -> Result<(Vec<u8>, crate::federation::StreamKeySlot), BlobError> {
        let refuse = |why: &str| {
            BlobError::Backend(format!(
                "stream chunk {} {why} (CC 5.3.3.1; CIRISPersist#969)",
                hex::encode(chunk_sha)
            ))
        };
        let (counter, last) = crate::federation::stream_seal::parse_nonce(&envelope.nonce)
            .ok_or_else(|| refuse("carries a nonce whose flag byte is not a STREAM flag"))?;
        let expect =
            crate::federation::stream_seal::stream_nonce(dek, stream_id, epoch, counter, last)
                .map_err(|e| BlobError::Backend(format!("stream nonce: {e}")))?;
        if expect != envelope.nonce {
            return Err(refuse(
                "carries a nonce that is not the STREAM nonce of its stream, epoch and DEK",
            ));
        }
        let plain = crate::federation::at_rest_cascade::open_aad(dek, Some(bound_aad), envelope)
            .map_err(|e| {
                BlobError::Backend(format!(
                    "stream chunk {} did not open ({e})",
                    hex::encode(chunk_sha)
                ))
            })?;
        Ok((plain, crate::federation::StreamKeySlot { counter, last }))
    }

    /// v53.0.0 (#969) — the chunk door's stream-keyed arm. Per pass: the
    /// epoch's DEK row (minted on its first chunk), the ONE recipient set
    /// resolved now, a REMOVAL roll if a recipient granted on the epoch has
    /// left it (forward secrecy keeps CC 5.1's shape: the next chunk is under
    /// a DEK the removed party never held), a CAP roll if only the
    /// terminator's slot is left, a wrap to every new recipient (the
    /// stream-axis set is emitted then — at the epoch's first chunk and when
    /// the set grows, never per chunk), the seal at the V165 counter, and
    /// the floor, which re-checks the counter and the epoch in the insert's
    /// own transaction. A lost race re-reads and re-seals.
    async fn put_stream_keyed_chunk<B>(
        backend: &B,
        w: StreamWrite<'_>,
        seq: u64,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        first_state: crate::federation::StreamKeyState,
    ) -> Result<PutChunkScopedResult, BlobError>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        // The terminators' positions are persist's (`terminator_seq`); a
        // producer's data chunk stays below them.
        if seq >= TERMINATOR_SEQ_BASE {
            return Err(BlobError::InvalidArgument(format!(
                "put_blob_chunk_scoped: seq {seq} is in the range persist reserves for epoch \
                 terminators (≥ {TERMINATOR_SEQ_BASE}); a producer's seq stays below it \
                 (CIRISPersist#969)"
            )));
        }
        let bound_aad = chunk_aad(aad, w.stream_id, seq);
        let bound_aad = bound_aad.as_slice();
        let plaintext_size = plaintext.len() as u64;
        let mut state = Some(first_state);
        for _ in 0..STREAM_SEAL_ATTEMPTS {
            let latest = match state.take() {
                Some(s) => s.latest,
                None => backend.stream_key_state(w.stream_id).await?.latest,
            };
            let rec = ensure_stream_epoch(backend, w, latest, aad).await?;
            // The terminator's slot is the cap's last: a data chunk that
            // would take it rolls the epoch instead (CEG §10.5.3) — the
            // outgoing epoch's terminator takes that slot now.
            if rec.chunk_count.saturating_add(1) >= crate::federation::blobs::MAX_CHUNKS_PER_EPOCH {
                write_terminator(backend, w, rec, aad).await?;
                continue;
            }
            let (targets, report) =
                crate::federation::at_rest_cascade::orchestrate::resolve_cohort_targets(
                    backend,
                    w.cohort_scope,
                    w.group_key_id,
                )
                .await?;
            let held: std::collections::HashSet<String> = backend
                .stream_dek_grants(w.stream_id, rec.epoch, &rec.owner_key_id)
                .await?
                .into_iter()
                .map(|g| g.recipient_key_id)
                .collect();
            let current: std::collections::HashSet<&str> =
                targets.iter().map(|(k, _)| k.as_str()).collect();
            if held.iter().any(|r| !current.contains(r.as_str())) {
                // A recipient the epoch was granted to is no longer in the
                // cohort: terminate it and seal under a fresh epoch.
                write_terminator(backend, w, rec, aad).await?;
                continue;
            }
            let dek = stream_epoch_dek(backend, &rec).await?;
            let granted_new = grant_stream_epoch(backend, &rec, &dek, &targets, &held).await?;
            let counter = u32::try_from(rec.chunk_count).map_err(|_| {
                BlobError::Backend(format!(
                    "stream {} epoch {} counts {} chunks, past the STREAM counter",
                    w.stream_id, rec.epoch, rec.chunk_count
                ))
            })?;
            let slot = crate::federation::StreamKeySlot {
                counter,
                last: false,
            };
            let envelope =
                seal_stream_chunk(&dek, w.stream_id, rec.epoch, slot, plaintext, bound_aad)?;
            match backend
                .put_blob_chunk_with_scope(
                    w.stream_id,
                    seq,
                    BlobBody::Inline(envelope.to_bytes()),
                    rec.epoch,
                    plaintext_size,
                    w.cohort_scope,
                    StorageFloor::resolved(CryptoTier::InvisibleEncrypted),
                    None,
                    StreamClaim {
                        community_key_id: w.community_key_id.map(str::to_owned),
                        owner_key_id: Some(w.writer_key_id.to_owned()),
                        stream_key: Some(slot),
                    },
                )
                .await
            {
                Ok(sha) => {
                    return Ok(PutChunkScopedResult {
                        chunk_sha256: sha,
                        tier: CryptoTier::InvisibleEncrypted,
                        epoch: None,
                        granted: report.granted,
                        excluded: report.excluded,
                        roster: report.roster,
                        // #969 — the stream-axis set, when this append wrote
                        // a wrap (the epoch's first chunk, a new recipient).
                        key_grant_emission: (granted_new > 0).then(|| {
                            crate::federation::key_grant::KeyGrantAxis::Stream {
                                stream_id: w.stream_id.to_owned(),
                                epoch: rec.epoch,
                                cohort_scope: w.cohort_scope.to_owned(),
                                owner_key_id: w.group_key_id.to_owned(),
                            }
                        }),
                    });
                }
                Err(BlobError::InvalidArgument(m))
                    if m.starts_with(crate::federation::blobs::STREAM_COUNTER_MOVED)
                        || m.starts_with(crate::federation::blobs::STREAM_EPOCH_CLOSED) =>
                {
                    tracing::debug!(
                        stream = %w.stream_id,
                        epoch = rec.epoch,
                        seq,
                        "stream-keyed append lost its slot; nothing stored, re-sealing"
                    );
                }
                Err(e) => return Err(e),
            }
        }
        Err(BlobError::Backend(format!(
            "put_blob_chunk_scoped: stream {} could not settle a STREAM-nonce slot in \
             {STREAM_SEAL_ATTEMPTS} attempts",
            w.stream_id
        )))
    }

    /// v53.0.0 (#969) — the first `seq` persist reserves for epoch
    /// terminators. A terminator's position is persist's own act — the roll
    /// is — so it is allocated by persist, not taken from the producer:
    /// epoch E's terminator sits at `TERMINATOR_SEQ_BASE + E`. It sorts after
    /// every data chunk (a producer's seq is refused at or above the base),
    /// so in seq order each epoch's terminator is its final chunk, and a
    /// manifest's positions stay strictly increasing. `2^62` keeps every
    /// position inside the index's signed 64-bit column.
    pub(crate) const TERMINATOR_SEQ_BASE: u64 = 1 << 62;

    /// The position of epoch `epoch`'s terminator.
    pub(crate) fn terminator_seq(epoch: u64) -> Result<u64, BlobError> {
        TERMINATOR_SEQ_BASE
            .checked_add(epoch)
            .filter(|s| i64::try_from(*s).is_ok())
            .ok_or_else(|| {
                BlobError::InvalidArgument(format!(
                    "stream epoch {epoch} is past the terminator range (CIRISPersist#969)"
                ))
            })
    }

    /// v53.0.0 (#969, CC 5.3.3.1) — **terminate one epoch**: an empty chunk
    /// sealed under the epoch's DEK with `last_flag = 0x01` at the epoch's
    /// next counter (the V165 count), at `terminator_seq(epoch)`. The floor
    /// stamps the epoch closed AND terminated in the terminator's own insert
    /// transaction — that IS the roll's close — so nothing can follow it.
    /// Called at every roll (cap, removal, a producer's higher label) and at
    /// the seal. Idempotent: an epoch found terminated is done.
    async fn write_terminator<B>(
        backend: &B,
        w: StreamWrite<'_>,
        rec: crate::federation::StreamDekRecord,
        aad: Option<&[u8]>,
    ) -> Result<(), BlobError>
    where
        B: BlobStorage + Sync,
    {
        if rec.owner_key_id != w.writer_key_id {
            return Err(BlobError::InvalidArgument(format!(
                "stream {} epoch {} was sealed by another writer; a terminator is appended only \
                 by the stream's single sender (CC 5.3.3.1)",
                w.stream_id, rec.epoch
            )));
        }
        let seq = terminator_seq(rec.epoch)?;
        let dek = stream_epoch_dek(backend, &rec).await?;
        let mut rec = rec;
        for _ in 0..STREAM_SEAL_ATTEMPTS {
            if rec.terminated {
                return Ok(());
            }
            let counter = u32::try_from(rec.chunk_count).map_err(|_| {
                BlobError::Backend(format!(
                    "stream {} epoch {} past the STREAM counter",
                    w.stream_id, rec.epoch
                ))
            })?;
            let slot = crate::federation::StreamKeySlot {
                counter,
                last: true,
            };
            let bound = chunk_aad(aad, w.stream_id, seq);
            let envelope = seal_stream_chunk(&dek, w.stream_id, rec.epoch, slot, &[], &bound)?;
            match backend
                .put_blob_chunk_with_scope(
                    w.stream_id,
                    seq,
                    BlobBody::Inline(envelope.to_bytes()),
                    rec.epoch,
                    0,
                    w.cohort_scope,
                    StorageFloor::resolved(CryptoTier::InvisibleEncrypted),
                    None,
                    StreamClaim {
                        community_key_id: w.community_key_id.map(str::to_owned),
                        owner_key_id: Some(w.writer_key_id.to_owned()),
                        stream_key: Some(slot),
                    },
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(BlobError::InvalidArgument(m))
                    if m.starts_with(crate::federation::blobs::STREAM_COUNTER_MOVED)
                        || m.starts_with(crate::federation::blobs::STREAM_EPOCH_CLOSED) =>
                {
                    let epoch = rec.epoch;
                    rec = backend
                        .stream_dek_list(w.stream_id)
                        .await?
                        .into_iter()
                        .find(|r| r.epoch == epoch)
                        .ok_or_else(|| {
                            BlobError::Backend(format!(
                                "stream {} epoch {epoch} lost its DEK row",
                                w.stream_id
                            ))
                        })?;
                }
                Err(e) => return Err(e),
            }
        }
        Err(BlobError::Backend(format!(
            "stream {} epoch {} could not settle its terminator",
            w.stream_id, rec.epoch
        )))
    }

    /// v53.0.0 (#969) — **close every epoch with its terminator** at the
    /// seal ([`write_terminator`] for each epoch not yet terminated). Returns
    /// how many were written.
    async fn terminate_stream_epochs<B>(
        backend: &B,
        w: StreamWrite<'_>,
        aad: Option<&[u8]>,
    ) -> Result<u64, BlobError>
    where
        B: BlobStorage + Sync,
    {
        let mut written = 0u64;
        for rec in backend.stream_dek_list(w.stream_id).await? {
            if rec.terminated {
                continue;
            }
            write_terminator(backend, w, rec, aad).await?;
            written += 1;
        }
        Ok(written)
    }

    /// v53.0.0 (#969, CC 5.3.3.1) — **the per-epoch structure of a
    /// stream-keyed DAG**: `entries` are `(seq, epoch, slot)` in seq order.
    /// Within each epoch the counters run 0, 1, 2, … in seq order (strictly
    /// increasing and gap-free — a dropped or reordered chunk breaks it), and
    /// exactly ONE chunk carries `last`, the epoch's final one. A DAG whose
    /// terminator was dropped — truncated — is refused. Pure.
    pub(crate) fn check_stream_epoch_structure(
        dag_sha: &[u8; 32],
        entries: &[(u64, u64, crate::federation::StreamKeySlot)],
    ) -> Result<(), BlobError> {
        let mut per_epoch: std::collections::BTreeMap<u64, (u32, bool)> =
            std::collections::BTreeMap::new();
        for (seq, epoch, slot) in entries {
            let refuse = |why: String| {
                BlobError::Backend(format!(
                    "chunk_dag {} chunk seq {seq} (epoch {epoch}): {why} (CC 5.3.3.1; \
                     CIRISPersist#969)",
                    hex::encode(dag_sha)
                ))
            };
            let (next, closed) = per_epoch.entry(*epoch).or_insert((0, false));
            if *closed {
                return Err(refuse(
                    "follows its epoch's last chunk — nothing may be appended after it".into(),
                ));
            }
            if slot.counter != *next {
                return Err(refuse(format!(
                    "carries counter {} where its epoch's next is {next} — a chunk was dropped, \
                     duplicated or moved",
                    slot.counter
                )));
            }
            *next = next.saturating_add(1);
            *closed = slot.last;
        }
        if let Some((epoch, _)) = per_epoch.iter().find(|(_, (_, closed))| !*closed) {
            return Err(BlobError::Backend(format!(
                "chunk_dag {} epoch {epoch} carries no last chunk: the DAG is truncated (CC \
                 5.3.3.1; CIRISPersist#969)",
                hex::encode(dag_sha)
            )));
        }
        Ok(())
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
    ///
    /// `pqc` — CIRISPersist#851 §20.5: a classical-only claim is confined to
    /// local tier (CC 5.3.2.4.3.1); with a LocalSigner the claim is
    /// hybrid-signed so peers admit it.
    #[allow(clippy::too_many_arguments)]
    pub async fn seal_stream_scoped<B>(
        backend: &B,
        local: &crate::signing::LocalSigner,
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
        let mut listing = backend.stream_chunks(stream_id).await?;
        if listing.chunks.is_empty() {
            return Err(BlobError::InvalidArgument(format!(
                "stream {stream_id} has no chunks"
            )));
        }
        // §11.2 (6) / I23 / §20.5 — the announcing identity IS the PQC
        // LocalSigner's derived id; hybrid-only, so there is no other.
        let signer_key_id = local.derived_key_id();
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
        // v53.0.0 (#969, CC 5.3.3.1) — a stream-keyed stream: every epoch is
        // closed by its terminator BEFORE the manifest lists the chunks, so
        // the manifest names each epoch's last chunk, and every chunk must
        // sit at an epoch this node holds the DEK of.
        let stream_epochs = if tier == CryptoTier::InvisibleEncrypted {
            backend.stream_dek_list(stream_id).await?
        } else {
            Vec::new()
        };
        let stream_keyed = !stream_epochs.is_empty();
        if stream_keyed {
            let group = community_key_id.ok_or_else(|| {
                BlobError::InvalidArgument(format!(
                    "cohort_scope {cohort_scope:?} requires the owner (self) or family key id \
                     in the community_key_id argument"
                ))
            })?;
            let w = StreamWrite {
                cohort_scope,
                group_key_id: group,
                writer_key_id: &signer_key_id,
                community_key_id,
                stream_id,
                epoch: 0,
            };
            if terminate_stream_epochs(backend, w, aad).await? > 0 {
                listing = backend.stream_chunks(stream_id).await?;
                check_chunk_rows_match_dag(
                    backend,
                    &listing.chunks,
                    tier,
                    cohort_scope,
                    community_key_id,
                )
                .await?;
            }
            let known: std::collections::HashSet<u64> =
                stream_epochs.iter().map(|r| r.epoch).collect();
            if let Some(c) = listing.chunks.iter().find(|c| !known.contains(&c.epoch)) {
                return Err(BlobError::InvalidArgument(format!(
                    "seal_stream_scoped: chunk seq {} of stream {stream_id} is at epoch {}, which \
                     holds no stream DEK on this node — one DAG never mixes per-chunk and \
                     stream keys (CIRISPersist#969)",
                    c.seq, c.epoch
                )));
            }
        }
        let manifest = build_manifest(stream_id, &listing.chunks, tier, stream_keyed)?;
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
                            children: Vec::new(),
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
                        local,
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
                    roster: RosterPartition::default(),
                    key_grant_emission: None,
                    chunk_key_grant_emissions: Vec::new(),
                    stream_key_grant_emissions: Vec::new(),
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
                // #954 — a manifest above the cap is a v3 root over sealed
                // children, each under its own fresh DEK.
                let (root_jcs, child_rows, child_items) =
                    match plan_children(&manifest, backend.inline_bytes_cap())? {
                        None => (jcs.clone(), Vec::new(), Vec::new()),
                        Some(children) => seal_children(&children, stream_id, tier, aad, |_| {
                            fresh_dek().map_err(map_at_rest_err)
                        })?,
                    };
                let body = seal(&dek, &root_jcs, aad)
                    .map_err(map_at_rest_err)?
                    .to_bytes();
                let sha: [u8; 32] = Sha256::digest(&body).into();
                backend
                    .seal_stream_with_scope(
                        stream_id,
                        ManifestRowSpec {
                            sha256: sha,
                            size_bytes: body.len() as u64,
                            body,
                            expected_chunk_count: chunk_count,
                            children: child_rows,
                        },
                        media_type,
                        cohort_scope,
                        StorageFloor::resolved(CryptoTier::InvisibleEncrypted),
                        None,
                    )
                    .await?;
                // #923 amendment 2 (D9) — ONE access set per stream: the
                // manifest and every chunk are wrapped to the recipient set
                // resolved ONCE, here. A chunk written before an occurrence
                // joined gains it; the name (sealed under the manifest's DEK)
                // and the bytes are one fact. Each chunk DEK is recovered
                // through persist's self-retention, as the rekey walk does.
                let content_master = backend.load_or_init_content_master().await?;
                let mut items: Vec<([u8; 32], [u8; 32])> = vec![(sha, dek)];
                // #954 (D9) — the children join the one access set.
                items.extend(child_items);
                // v53.0.0 (#969) — a stream-keyed DAG's chunks carry no
                // per-chunk DEK: the manifest (and children) take content
                // grants, and each EPOCH's DEK is wrapped to the same one
                // recipient set — O(epochs × recipients), never per chunk.
                let chunk_rows: &[StreamChunkRef] =
                    if stream_keyed { &[] } else { &listing.chunks };
                for c in chunk_rows {
                    let self_grant = backend
                        .get_at_rest_grant(&c.chunk_sha, PERSIST_SELF_RECIPIENT)
                        .await?
                        .ok_or_else(|| {
                            BlobError::Backend(format!(
                                "seal_stream_scoped: chunk {} of stream {stream_id} has no \
                                 persist self-retention row (corrupt cascade state)",
                                c.seq
                            ))
                        })?;
                    let chunk_dek = unwrap_dek_for_persist(&content_master, &self_grant.1)
                        .map_err(map_at_rest_err)?;
                    items.push((c.chunk_sha, chunk_dek));
                }
                crate::federation::at_rest_cascade::orchestrate::self_retain_deks(
                    backend,
                    &items,
                    cohort_scope,
                )
                .await?;
                let (targets, report) =
                    crate::federation::at_rest_cascade::orchestrate::resolve_cohort_targets(
                        backend,
                        cohort_scope,
                        owner,
                    )
                    .await?;
                let changed =
                    crate::federation::at_rest_cascade::orchestrate::grant_deks_to_targets(
                        backend,
                        &items,
                        cohort_scope,
                        &targets,
                    )
                    .await?;
                let mut stream_key_grant_emissions = Vec::new();
                for rec in &stream_epochs {
                    let held: std::collections::HashSet<String> = backend
                        .stream_dek_grants(stream_id, rec.epoch, &rec.owner_key_id)
                        .await?
                        .into_iter()
                        .map(|g| g.recipient_key_id)
                        .collect();
                    if targets.iter().all(|(k, _)| held.contains(k)) {
                        continue;
                    }
                    let epoch_dek = stream_epoch_dek(backend, rec).await?;
                    if grant_stream_epoch(backend, rec, &epoch_dek, &targets, &held).await? > 0 {
                        stream_key_grant_emissions.push(
                            crate::federation::key_grant::KeyGrantAxis::Stream {
                                stream_id: stream_id.to_owned(),
                                epoch: rec.epoch,
                                cohort_scope: cohort_scope.to_owned(),
                                owner_key_id: owner.to_owned(),
                            },
                        );
                    }
                }
                let axis = |s: &[u8; 32]| crate::federation::key_grant::KeyGrantAxis::Content {
                    at_rest_sha256: hex::encode(s),
                    cohort_scope: cohort_scope.to_owned(),
                    owner_key_id: owner.to_owned(),
                };
                Ok(SealStreamScopedResult {
                    manifest_sha256: sha,
                    tier,
                    epoch: None,
                    chunk_count,
                    total_size,
                    granted: report.granted,
                    excluded: report.excluded,
                    roster: report.roster,
                    // #848 (§14, content axis) — the sealed manifest has its
                    // own per-write DEK and grants; a new set every time.
                    key_grant_emission: Some(axis(&sha)),
                    chunk_key_grant_emissions: changed
                        .iter()
                        .filter(|s| **s != sha)
                        .map(axis)
                        .collect(),
                    stream_key_grant_emissions,
                })
            }
            CryptoTier::CommunityDek => {
                let comm = community_key_id.ok_or_else(|| {
                    BlobError::InvalidArgument("community_key_id required".into())
                })?;
                let mut last_epoch = 0;
                // #848 (§11) — the minter is the sealer (I23).
                let minter = signer_key_id.as_str();
                for _ in 0..EPOCH_RACE_ATTEMPTS {
                    let dek_epoch = backend.community_dek_current_epoch(comm, minter).await?;
                    let ensured = ensure_epoch_dek(backend, comm, minter, dek_epoch).await?;
                    let dek_epoch = ensured.epoch;
                    let report = ensured.report;
                    // #954 — children under the same epoch DEK, bound to the
                    // same epoch in the floor's transaction.
                    let (root_jcs, child_rows, _) =
                        match plan_children(&manifest, backend.inline_bytes_cap())? {
                            None => (jcs.clone(), Vec::new(), Vec::new()),
                            Some(children) => {
                                seal_children(&children, stream_id, tier, aad, |_| Ok(ensured.dek))?
                            }
                        };
                    let body = seal(&ensured.dek, &root_jcs, aad)
                        .map_err(map_at_rest_err)?
                        .to_bytes();
                    let sha: [u8; 32] = Sha256::digest(&body).into();
                    match backend
                        .seal_stream_with_scope(
                            stream_id,
                            ManifestRowSpec {
                                sha256: sha,
                                size_bytes: body.len() as u64,
                                body: body.clone(),
                                expected_chunk_count: chunk_count,
                                children: child_rows,
                            },
                            media_type,
                            cohort_scope,
                            StorageFloor::resolved(CryptoTier::CommunityDek),
                            Some(EpochBinding {
                                community_key_id: comm.to_owned(),
                                minter_key_id: minter.to_owned(),
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
                                    local,
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
                                granted: report.granted,
                                excluded: report.excluded,
                                roster: report.roster,
                                key_grant_emission: ensured.changed.then(|| {
                                    crate::federation::key_grant::KeyGrantAxis::Epoch {
                                        community_key_id: comm.to_owned(),
                                        minter_key_id: minter.to_owned(),
                                        epoch: dek_epoch,
                                    }
                                }),
                                chunk_key_grant_emissions: Vec::new(),
                                stream_key_grant_emissions: Vec::new(),
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
                    Some((bound, _, _)) if bound == comm => {}
                    Some((bound, _, _)) => {
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
        stream_keyed: bool,
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
                // #969 — the epoch whose DEK sealed it, authoritative inside
                // the sealed v4 manifest.
                epoch: stream_keyed.then_some(c.epoch),
            });
        }
        let (v, chunk_tier, stream_id) = match tier {
            CryptoTier::Plaintext => (CHUNK_MANIFEST_VERSION, None, None),
            sealed => (
                if stream_keyed {
                    crate::federation::blobs::CHUNK_MANIFEST_VERSION_STREAM
                } else {
                    CHUNK_MANIFEST_VERSION_SEALED
                },
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

    /// v52.0.0 (#954) — **does this sealed manifest need children, and which?**
    /// `None` when the v2 manifest's sealed envelope fits `cap` (it stays v2,
    /// byte-identical, same address). Otherwise the chunks partitioned
    /// greedily, in order, into v2 children whose envelopes each fit `cap`.
    /// Deterministic given the cap. A plaintext (v1) manifest is never
    /// partitioned: its row is parsed by the storage layer, and above the
    /// cap the floor refuses it by name (`InlineSizeExceeded`).
    pub(crate) fn plan_children(
        manifest: &ChunkManifest,
        cap: usize,
    ) -> Result<Option<Vec<ChunkManifest>>, BlobError> {
        if manifest.chunk_tier.is_none() {
            return Ok(None);
        }
        let budget =
            cap.saturating_sub(crate::federation::at_rest_cascade::AT_REST_ENVELOPE_OVERHEAD);
        let entry_len = |c: &ChunkRef| {
            // #969 — a v4 entry carries `"epoch":E,` ahead of its seq.
            c.epoch.map_or(0, |e| format!("\"epoch\":{e},").len())
                + format!(
                    "{{\"seq\":{},\"sha\":\"{}\",\"size\":{}}}",
                    c.seq.unwrap_or_default(),
                    hex::encode(c.sha),
                    c.size
                )
                .len()
        };
        // The wrapper with a 20-digit total: an upper bound for any child.
        let wrapper = ChunkManifest {
            v: manifest.v,
            total_size: u64::MAX,
            chunks: Vec::new(),
            chunk_tier: manifest.chunk_tier,
            stream_id: manifest.stream_id.clone(),
        }
        .to_jcs_bytes()
        .len();
        let flat_len = wrapper
            + manifest.chunks.iter().map(entry_len).sum::<usize>()
            + manifest.chunks.len().saturating_sub(1);
        if flat_len <= budget {
            return Ok(None);
        }
        let mut children: Vec<ChunkManifest> = Vec::new();
        let mut run: Vec<ChunkRef> = Vec::new();
        let mut run_len = wrapper;
        let close = |run: Vec<ChunkRef>| ChunkManifest {
            v: manifest.v,
            total_size: run.iter().map(|c| u64::from(c.size)).sum(),
            chunks: run,
            chunk_tier: manifest.chunk_tier,
            stream_id: manifest.stream_id.clone(),
        };
        for c in &manifest.chunks {
            let add = entry_len(c) + usize::from(!run.is_empty());
            if !run.is_empty() && run_len + add > budget {
                children.push(close(std::mem::take(&mut run)));
                run_len = wrapper;
            }
            run_len += entry_len(c) + usize::from(!run.is_empty());
            if run_len > budget {
                return Err(BlobError::InvalidArgument(format!(
                    "seal_stream_scoped: the inline cap ({cap} bytes) cannot hold a manifest \
                     child of even one chunk (CIRISPersist#954)"
                )));
            }
            run.push(c.clone());
        }
        if !run.is_empty() {
            children.push(close(run));
        }
        Ok(Some(children))
    }

    /// v52.0.0 (#954) — seal each planned child under `dek_for(index)` with
    /// its position-bound AAD, and build the v3 root over them. Returns the
    /// root's JCS, the child rows for the floor, and each child's
    /// `(sha, dek)` for the grant cascade.
    #[allow(clippy::type_complexity)]
    pub(crate) fn seal_children(
        children: &[ChunkManifest],
        stream_id: &str,
        tier: CryptoTier,
        caller_aad: Option<&[u8]>,
        mut dek_for: impl FnMut(u64) -> Result<[u8; 32], BlobError>,
    ) -> Result<(Vec<u8>, Vec<ManifestChildRow>, Vec<([u8; 32], [u8; 32])>), BlobError> {
        let mut rows = Vec::with_capacity(children.len());
        let mut entries = Vec::with_capacity(children.len());
        let mut items = Vec::with_capacity(children.len());
        for (i, child) in children.iter().enumerate() {
            let index = i as u64;
            let dek = dek_for(index)?;
            let aad = manifest_child_aad(caller_aad, stream_id, index);
            let body = seal(&dek, &child.to_jcs_bytes(), Some(&aad))
                .map_err(map_at_rest_err)?
                .to_bytes();
            let sha: [u8; 32] = Sha256::digest(&body).into();
            let (Some(first), Some(last)) = (
                child.chunks.first().and_then(|c| c.seq),
                child.chunks.last().and_then(|c| c.seq),
            ) else {
                return Err(BlobError::Backend(
                    "seal_stream_scoped: a planned child lists no positioned chunk".into(),
                ));
            };
            entries.push(ManifestChildRef {
                chunk_count: child.chunks.len() as u64,
                first_seq: first,
                last_seq: last,
                sha,
                size: child.total_size,
            });
            rows.push(ManifestChildRow {
                index,
                sha256: sha,
                body,
            });
            items.push((sha, dek));
        }
        let root = NestedManifest {
            total_size: entries.iter().map(|e| e.size).sum(),
            chunk_tier: tier,
            stream_id: stream_id.to_owned(),
            children: entries,
        };
        root.validate()?;
        Ok((root.to_jcs_bytes(), rows, items))
    }

    // ── the sealed-DAG adopt (v51.3.0, CIRISPersist#947) ─────────────────

    /// One chunk of an opened sealed manifest, as the puller needs it: the
    /// CIPHERTEXT address to fetch by, the plaintext size, the position to
    /// adopt it at.
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    pub struct SealedManifestChunk {
        /// The chunk's content address (over its CIPHERTEXT): fetch by this.
        pub sha256_hex: String,
        /// The chunk's PLAINTEXT size — `plaintext_size` at the adopt.
        pub size: u32,
        /// The chunk's position in the stream — adopt it at `(stream_id, seq)`.
        pub seq: u64,
        /// v53.0.0 (#969) — the epoch to adopt it at: `Some` for a v4
        /// (stream-keyed) manifest, whose reader opens the chunk under the
        /// stream grant of this epoch; `None` for a v2 one.
        pub epoch: Option<u64>,
    }

    /// `Engine::open_sealed_manifest_as` — a sealed DAG's manifest, opened for
    /// an authorized viewer: the chunk list to fetch and adopt, the stream to
    /// adopt it under, and the three bounds the puller checks BEFORE it
    /// fetches (per-chunk inline cap, whole-read cap, chunk-count cap).
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    pub struct SealedManifestView {
        /// The manifest's address (the DAG's address).
        pub sha256_hex: String,
        /// `inline` for a manifest adopted and not yet promoted; `chunk_dag`
        /// once promoted, or at the origin.
        pub storage_kind: String,
        /// The row's recorded crypto tier (`invisible_encrypted` / `community_dek`).
        pub tier: String,
        /// The stream the chunks belong to — the `stream_id` to adopt them under.
        pub stream_id: String,
        /// The file's plaintext size (the sum of the chunks' sizes).
        pub total_size: u64,
        /// The manifest's schema version: `2` (every chunk listed here) or
        /// `3` (a nested root: `chunks` is EMPTY and the chunks are in
        /// `children`, each opened with `open_sealed_manifest_page_as`).
        pub version: u32,
        /// The chunks, in stream order (v2). Empty for a v3 root.
        pub chunks: Vec<SealedManifestChunk>,
        /// v52.0.0 (#954) — a v3 root's children, in order. Empty for v2.
        pub children: Vec<SealedManifestChildRef>,
        /// This node's inline cap: a chunk envelope above it is refused at the adopt.
        pub inline_bytes_cap: u64,
        /// The whole-read cap: a file above it is read by range only.
        pub whole_read_cap_bytes: u64,
        /// The chunk-count cap.
        pub max_chunks: u64,
    }

    /// v52.0.0 (#954) — one child of a v3 root, as the puller needs it: the
    /// child row's address to fetch by and adopt with
    /// `adopt_sealed_manifest_child`, and the run of chunks it lists.
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    pub struct SealedManifestChildRef {
        /// The child's index in the root.
        pub index: u64,
        /// The child row's content address (over its sealed envelope).
        pub sha256_hex: String,
        /// The first chunk's `seq`.
        pub first_seq: u64,
        /// The last chunk's `seq`.
        pub last_seq: u64,
        /// How many chunks the child lists.
        pub chunk_count: u64,
        /// The child's plaintext total.
        pub size: u64,
    }

    /// `Engine::promote_adopted_manifest_to_dag`'s answer.
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    pub struct DagPromotion {
        /// The manifest's address (the DAG's address).
        pub sha256_hex: String,
        /// `false` when the row was already a `chunk_dag` (idempotent).
        pub promoted: bool,
        /// The chunks the manifest names, all held.
        pub chunk_count: u64,
        /// The file's plaintext size.
        pub total_size: u64,
    }

    /// The manifest of a SEALED DAG this node holds, opened for `viewer`:
    /// authorized by the row's tier exactly as `read_any_for_viewer`
    /// (a stranger is `NotGranted` and learns nothing; a withdrawn blob
    /// refuses), then the inline envelope opened under `caller_aad` and
    /// parsed as a v2 manifest at the row's tier. A plaintext row, a sealed
    /// whole blob, or a v1 manifest is `InvalidArgument` (named).
    async fn opened_sealed_manifest<B>(
        backend: &B,
        sha256: &[u8; 32],
        viewer_key_id: &str,
        caller_aad: Option<&[u8]>,
    ) -> Result<(BlobHead, ParsedManifest), BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
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
        let tier = head.crypto_tier;
        if tier == CryptoTier::Plaintext {
            return Err(BlobError::InvalidArgument(format!(
                "blob {} is recorded at the plaintext tier: a plaintext DAG's manifest is in \
                 clear (get_blob) and is stored through put_blob_chunks; only a SEALED \
                 manifest is opened here",
                hex::encode(sha256)
            )));
        }
        authorize_viewer_by_tier(backend, sha256, tier, viewer_key_id).await?;
        crate::federation::at_rest_cascade::refuse_if_withdrawn(backend, sha256).await?;
        if head.storage_kind != "inline" && head.storage_kind != "chunk_dag" {
            return Err(BlobError::InvalidArgument(format!(
                "blob {} is a {:?} row, not a held envelope",
                hex::encode(sha256),
                head.storage_kind
            )));
        }
        let jcs =
            read_sealed_inline_authorized(backend, sha256, tier, viewer_key_id, caller_aad).await?;
        let m = ParsedManifest::parse(&jcs).map_err(|e| {
            BlobError::InvalidArgument(format!(
                "blob {} opened, but its plaintext is not a chunk manifest ({e}): a sealed whole \
                 blob is read with read_blob_as, not promoted",
                hex::encode(sha256)
            ))
        })?;
        if let ParsedManifest::Nested(root) = &m {
            if root.chunk_tier != tier {
                return Err(BlobError::InvalidArgument(format!(
                    "blob {} is a v3 root at tier {:?} recorded at {tier:?}",
                    hex::encode(sha256),
                    root.chunk_tier
                )));
            }
            return Ok((head, m));
        }
        let ParsedManifest::Flat(ref f) = m else {
            unreachable!("the nested arm returned")
        };
        if (f.v != CHUNK_MANIFEST_VERSION_SEALED
            && f.v != crate::federation::blobs::CHUNK_MANIFEST_VERSION_STREAM)
            || f.chunk_tier != Some(tier)
            || f.stream_id.is_none()
        {
            return Err(BlobError::InvalidArgument(format!(
                "blob {} is not a v{CHUNK_MANIFEST_VERSION_SEALED} sealed manifest at tier {tier:?} \
                 (v = {}, chunk_tier = {:?}, stream_id = {:?})",
                hex::encode(sha256),
                f.v,
                f.chunk_tier,
                f.stream_id
            )));
        }
        Ok((head, m))
    }

    /// v52.0.0 (#954) — **open child `index` of a v3 root for a viewer.** The
    /// child row must be held (else `NotHeld` naming the CHILD — fetch it and
    /// adopt it with `adopt_sealed_manifest_child`), recorded at the root's
    /// tier as an inline envelope; the viewer is authorized on the child row
    /// itself; it opens under `manifest_child_aad(caller_aad, stream_id,
    /// index)` and must be exactly the v2 manifest the root's entry names.
    pub(crate) async fn open_manifest_child<B>(
        backend: &B,
        root: &NestedManifest,
        index: usize,
        viewer_key_id: &str,
        caller_aad: Option<&[u8]>,
    ) -> Result<ChunkManifest, BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        let Some(entry) = root.children.get(index) else {
            return Err(BlobError::InvalidArgument(format!(
                "child index {index} is outside the root's {} children",
                root.children.len()
            )));
        };
        let Some(head) = backend.blob_head(&entry.sha).await? else {
            return Err(BlobError::NotHeld {
                sha256_hex: hex::encode(entry.sha),
            });
        };
        if head.crypto_tier != root.chunk_tier || head.storage_kind != "inline" {
            return Err(BlobError::Backend(format!(
                "manifest child {index} ({}) is a {:?} row at {:?}, not an inline envelope at \
                 the root's {:?}",
                hex::encode(entry.sha),
                head.storage_kind,
                head.crypto_tier,
                root.chunk_tier
            )));
        }
        authorize_viewer_by_tier(backend, &entry.sha, head.crypto_tier, viewer_key_id).await?;
        let aad = manifest_child_aad(caller_aad, &root.stream_id, index as u64);
        let jcs = read_sealed_inline_authorized(
            backend,
            &entry.sha,
            head.crypto_tier,
            viewer_key_id,
            Some(&aad),
        )
        .await?;
        let child = ChunkManifest::from_manifest_bytes(&jcs)?;
        root.check_child(index, &child)?;
        Ok(child)
    }

    /// `Engine::open_sealed_manifest_page_as` (v52.0.0, #954) — the chunks
    /// child `index` of a v3 root lists, opened for `viewer_key_id`
    /// (authorized on the root as `read_blob_as`, then on the child row).
    /// A v2 manifest is `InvalidArgument`: its chunks are in the view.
    pub async fn open_sealed_manifest_page_for_viewer<B>(
        backend: &B,
        sha256: &[u8; 32],
        index: u64,
        viewer_key_id: &str,
        caller_aad: Option<&[u8]>,
    ) -> Result<Vec<SealedManifestChunk>, BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        let (_, m) = opened_sealed_manifest(backend, sha256, viewer_key_id, caller_aad).await?;
        let ParsedManifest::Nested(root) = m else {
            return Err(BlobError::InvalidArgument(format!(
                "blob {} is a v2 manifest: its chunks are listed by open_sealed_manifest_as",
                hex::encode(sha256)
            )));
        };
        let index = usize::try_from(index)
            .map_err(|_| BlobError::InvalidArgument("child index exceeds usize".into()))?;
        let child = open_manifest_child(backend, &root, index, viewer_key_id, caller_aad).await?;
        Ok(chunk_views(&child))
    }

    fn chunk_views(m: &ChunkManifest) -> Vec<SealedManifestChunk> {
        m.chunks
            .iter()
            .map(|c| SealedManifestChunk {
                sha256_hex: hex::encode(c.sha),
                size: c.size,
                seq: c.seq.unwrap_or_default(),
                epoch: c.epoch,
            })
            .collect()
    }

    /// `Engine::open_sealed_manifest_as` (#947 ask 2) — see
    /// [`SealedManifestView`]. Nothing is written.
    pub async fn open_sealed_manifest_for_viewer<B>(
        backend: &B,
        sha256: &[u8; 32],
        viewer_key_id: &str,
        caller_aad: Option<&[u8]>,
    ) -> Result<SealedManifestView, BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        let (head, m) = opened_sealed_manifest(backend, sha256, viewer_key_id, caller_aad).await?;
        let (version, chunks, children) = match &m {
            ParsedManifest::Flat(f) => (f.v, chunk_views(f), Vec::new()),
            ParsedManifest::Nested(n) => (
                crate::federation::blobs::CHUNK_MANIFEST_VERSION_NESTED,
                Vec::new(),
                n.children
                    .iter()
                    .enumerate()
                    .map(|(i, c)| SealedManifestChildRef {
                        index: i as u64,
                        sha256_hex: hex::encode(c.sha),
                        first_seq: c.first_seq,
                        last_seq: c.last_seq,
                        chunk_count: c.chunk_count,
                        size: c.size,
                    })
                    .collect(),
            ),
        };
        Ok(SealedManifestView {
            sha256_hex: hex::encode(sha256),
            storage_kind: head.storage_kind.clone(),
            tier: head.crypto_tier.as_str().to_owned(),
            stream_id: m.stream_id().unwrap_or_default().to_owned(),
            total_size: m.total_size(),
            version,
            chunks,
            children,
            inline_bytes_cap: backend.inline_bytes_cap() as u64,
            whole_read_cap_bytes: DAG_WHOLE_READ_CAP_BYTES,
            max_chunks: crate::federation::blobs::MAX_CHUNKS_PER_EPOCH,
        })
    }

    /// `Engine::promote_adopted_manifest_to_dag` (#947 ask 1) — **the adopt
    /// door's DAG half.** Opens the held manifest as `viewer_key_id` (the
    /// same authorization as the bytes read), requires every chunk it names
    /// to be held under the manifest's `stream_id` at its `seq` with the
    /// named sha, plaintext size and tier — the checks `prepare_chunk_rows`
    /// makes for a plaintext DAG, made here against the adopted chunk ROWS —
    /// and then flips the row through the storage floor. A missing chunk
    /// names its `(seq, sha)`; nothing is written until every chunk is held.
    /// Idempotent: a row already promoted (or sealed here) answers
    /// `promoted: false`.
    pub async fn promote_adopted_manifest_to_dag<B>(
        backend: &B,
        sha256: &[u8; 32],
        viewer_key_id: &str,
        caller_aad: Option<&[u8]>,
    ) -> Result<DagPromotion, BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        let (head, m) = opened_sealed_manifest(backend, sha256, viewer_key_id, caller_aad).await?;
        let stream_id = m.stream_id().unwrap_or_default().to_owned();
        let chunk_count = m.chunk_count();
        let total_size = m.total_size();
        let done = |promoted: bool| DagPromotion {
            sha256_hex: hex::encode(sha256),
            promoted,
            chunk_count,
            total_size,
        };
        if head.storage_kind == "chunk_dag" {
            return Ok(done(false));
        }
        let listing = backend.stream_chunks(&stream_id).await?;
        let by_seq: std::collections::HashMap<u64, &StreamChunkRef> =
            listing.chunks.iter().map(|r| (r.seq, r)).collect();
        // v53.0.0 (#969) — a stream-keyed DAG's chunks, for the structure
        // check below (read from the stored nonces: I45, nothing is opened).
        let mut keyed_chunks: Vec<ChunkRef> = Vec::new();
        match &m {
            ParsedManifest::Flat(f) => {
                check_chunks_held(&by_seq, &f.chunks, sha256, &stream_id, head.crypto_tier)?;
                if f.is_stream_keyed() {
                    keyed_chunks.extend(f.chunks.iter().cloned());
                }
            }
            ParsedManifest::Nested(root) => {
                // #954 — every child held AND recorded (so eviction finds it
                // without opening the root), then every chunk it lists.
                let recorded = backend.manifest_children(sha256).await?;
                for (i, entry) in root.children.iter().enumerate() {
                    if !recorded.contains(&(i as u64, entry.sha)) {
                        return Err(BlobError::InvalidArgument(format!(
                            "child {i} ({}) of manifest {} is not held: fetch it by that sha and \
                             adopt it with adopt_sealed_manifest_child before promoting",
                            hex::encode(entry.sha),
                            hex::encode(sha256)
                        )));
                    }
                }
                for i in 0..root.children.len() {
                    let child =
                        open_manifest_child(backend, root, i, viewer_key_id, caller_aad).await?;
                    check_chunks_held(
                        &by_seq,
                        &child.chunks,
                        sha256,
                        &stream_id,
                        head.crypto_tier,
                    )?;
                    if child.is_stream_keyed() {
                        keyed_chunks.extend(child.chunks.iter().cloned());
                    }
                }
            }
        }
        if !keyed_chunks.is_empty() {
            check_held_stream_structure(backend, sha256, &keyed_chunks).await?;
        }
        let promoted = backend
            .promote_adopted_manifest_to_dag(sha256, &stream_id, chunk_count)
            .await?;
        Ok(done(promoted))
    }

    /// v53.0.0 (#969, CC 5.3.3.1) — **the promote's truncation check, without
    /// a key**: each held chunk's STREAM `(counter, last)` is read from the
    /// nonce stored in its envelope — the clear half of the envelope, so
    /// nothing is opened (I45) — and the epochs must be whole
    /// ([`check_stream_epoch_structure`]). A DAG whose terminator was dropped
    /// is refused here, before it becomes a `chunk_dag`. The nonce's prefix
    /// is bound to the DEK, which the reader checks when it opens.
    async fn check_held_stream_structure<B>(
        backend: &B,
        sha256: &[u8; 32],
        chunks: &[ChunkRef],
    ) -> Result<(), BlobError>
    where
        B: BlobStorage + Sync,
    {
        let mut slots = Vec::with_capacity(chunks.len());
        for c in chunks {
            let (Some(seq), Some(epoch)) = (c.seq, c.epoch) else {
                return Err(BlobError::InvalidArgument(format!(
                    "manifest {} is stream-keyed but chunk {} carries no seq or epoch",
                    hex::encode(sha256),
                    hex::encode(c.sha)
                )));
            };
            let Some(BlobBody::Inline(bytes)) = backend.get_blob(&c.sha).await? else {
                return Err(BlobError::NotHeld {
                    sha256_hex: hex::encode(c.sha),
                });
            };
            let envelope = AtRestEnvelope::from_bytes(&bytes).map_err(|e| {
                BlobError::Backend(format!(
                    "chunk {} is not an at-rest envelope ({e})",
                    hex::encode(c.sha)
                ))
            })?;
            let (counter, last) = crate::federation::stream_seal::parse_nonce(&envelope.nonce)
                .ok_or_else(|| {
                    BlobError::InvalidArgument(format!(
                        "chunk {} of stream-keyed manifest {} carries no STREAM nonce",
                        hex::encode(c.sha),
                        hex::encode(sha256)
                    ))
                })?;
            slots.push((
                seq,
                epoch,
                crate::federation::StreamKeySlot { counter, last },
            ));
        }
        slots.sort_by_key(|(seq, _, _)| *seq);
        check_stream_epoch_structure(sha256, &slots)
            .map_err(|e| BlobError::InvalidArgument(e.to_string()))
    }

    /// v53.0.0 (CIRISPersist#969) — one key a viewer lacks, as
    /// [`sealed_dag_readiness_for_viewer`] names it.
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    #[serde(tag = "axis", rename_all = "snake_case")]
    pub enum MissingChunkKey {
        /// A legacy chunk's own content grant.
        Content {
            /// The chunk's position.
            seq: u64,
            /// The chunk's content address, hex.
            chunk_sha256: String,
        },
        /// A stream epoch's grant, covering the chunks `seq_from ..= seq_to`
        /// of the DAG at that epoch.
        Stream {
            /// The stream.
            stream_id: String,
            /// The epoch.
            epoch: u64,
            /// The first chunk of the DAG at this epoch.
            seq_from: u64,
            /// The last chunk of the DAG at this epoch.
            seq_to: u64,
        },
        /// A v3 root's child manifest the viewer holds no grant on.
        Child {
            /// The child's index in the root.
            index: u64,
            /// The child row's content address, hex.
            child_sha256: String,
        },
    }

    /// v53.0.0 (CIRISPersist#969) — **can `viewer` read this sealed DAG on
    /// this node now, and if not, what is missing** — answered from the
    /// index and grant rows, without opening any chunk.
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    pub struct SealedDagReadiness {
        /// The DAG's address.
        pub sha256_hex: String,
        /// `stream_epoch` (v4) or `content` (per-chunk keys, legacy).
        pub chunk_keys: &'static str,
        /// Every chunk (and v3 child) the manifest names is held here.
        pub held: bool,
        /// `held` and nothing `missing`: a whole read would open every chunk.
        pub readable: bool,
        /// The keys the viewer lacks: per EPOCH for a stream-keyed DAG
        /// (O(epochs)), per chunk for a legacy one.
        pub missing: Vec<MissingChunkKey>,
        /// The chunks (`seq`) not held here, so a host knows what to fetch.
        pub not_held: Vec<u64>,
    }

    /// `Engine::sealed_dag_readiness` — see [`SealedDagReadiness`]. The
    /// manifest is opened for `viewer_key_id` exactly as
    /// [`open_sealed_manifest_for_viewer`] opens it: a stranger (no grant on
    /// the manifest) is `NotGranted` and learns nothing about the chunks.
    pub async fn sealed_dag_readiness_for_viewer<B>(
        backend: &B,
        sha256: &[u8; 32],
        viewer_key_id: &str,
        caller_aad: Option<&[u8]>,
    ) -> Result<SealedDagReadiness, BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        let (_, m) = opened_sealed_manifest(backend, sha256, viewer_key_id, caller_aad).await?;
        let stream_id = m.stream_id().unwrap_or_default().to_owned();
        let mut missing = Vec::new();
        let mut not_held = Vec::new();
        let mut held = true;
        let mut runs: Vec<ChunkManifest> = Vec::new();
        match &m {
            ParsedManifest::Flat(f) => runs.push(f.clone()),
            ParsedManifest::Nested(root) => {
                for (i, entry) in root.children.iter().enumerate() {
                    match open_manifest_child(backend, root, i, viewer_key_id, caller_aad).await {
                        Ok(child) => runs.push(child),
                        Err(BlobError::NotHeld { .. }) => held = false,
                        Err(BlobError::NotGranted { .. }) => missing.push(MissingChunkKey::Child {
                            index: i as u64,
                            child_sha256: hex::encode(entry.sha),
                        }),
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        let stream_keyed = runs.iter().any(ChunkManifest::is_stream_keyed);
        // Per epoch, the DAG's seq span (stream-keyed), in epoch order.
        let mut epochs: std::collections::BTreeMap<u64, (u64, u64)> =
            std::collections::BTreeMap::new();
        for c in runs.iter().flat_map(|r| r.chunks.iter()) {
            let seq = c.seq.unwrap_or_default();
            if backend.blob_head(&c.sha).await?.is_none() {
                held = false;
                not_held.push(seq);
            }
            match c.epoch {
                Some(epoch) => {
                    let span = epochs.entry(epoch).or_insert((seq, seq));
                    span.0 = span.0.min(seq);
                    span.1 = span.1.max(seq);
                }
                None => {
                    if backend
                        .get_at_rest_grant(&c.sha, viewer_key_id)
                        .await?
                        .is_none()
                    {
                        missing.push(MissingChunkKey::Content {
                            seq,
                            chunk_sha256: hex::encode(c.sha),
                        });
                    }
                }
            }
        }
        for (epoch, (seq_from, seq_to)) in epochs {
            if stream_grant_sealer(backend, &stream_id, epoch, viewer_key_id)
                .await?
                .is_none()
            {
                missing.push(MissingChunkKey::Stream {
                    stream_id: stream_id.clone(),
                    epoch,
                    seq_from,
                    seq_to,
                });
            }
        }
        Ok(SealedDagReadiness {
            sha256_hex: hex::encode(sha256),
            chunk_keys: if stream_keyed {
                crate::federation::blobs::CHUNK_KEYS_STREAM_EPOCH
            } else {
                "content"
            },
            held,
            readable: held && missing.is_empty(),
            missing,
            not_held,
        })
    }

    /// v53.0.0 (CIRISPersist#963 / #942, CC 3.1.3.3) — what a held row is,
    /// as a custody `here` must know it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DagHolding {
        /// The row is a whole blob (or no row is held): its row is the copy.
        NotADag,
        /// A chunk DAG whose every chunk (and v3 child) is held here.
        Complete,
        /// A chunk DAG this node holds only part of: `not_held` names the
        /// chunks (`seq`) missing here.
        Incomplete {
            /// The chunks not held here.
            not_held: Vec<u64>,
        },
        /// A row recorded `chunk_dag` whose manifest `holder_key_id` cannot
        /// open, so whether every chunk is held cannot be asked.
        Unverifiable,
    }

    /// **Is the held row `sha256` a chunk DAG, and is all of it here?** Asked
    /// as `holder_key_id` (the node filing a custody report), from the
    /// opened manifest and the chunk rows this node holds.
    ///
    /// - a plaintext `chunk_dag` row: the clear manifest's chunks;
    /// - a sealed row recorded `chunk_dag` (the seal floor's, or a promoted
    ///   adoption): [`sealed_dag_readiness_for_viewer`]'s `held`;
    /// - a sealed `inline` row: opened, and a DAG iff its plaintext PARSES as
    ///   a manifest — the adopted, not-yet-promoted case, whose chunks may be
    ///   partly here. A sealed inline row the holder cannot open is reported
    ///   [`DagHolding::NotADag`]: nothing here can tell its bytes apart from a
    ///   whole blob (the residual, documented on `custody_ack_input_for`).
    pub async fn held_dag_completeness<B>(
        backend: &B,
        sha256: &[u8; 32],
        holder_key_id: &str,
    ) -> Result<DagHolding, BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        let Some(head) = backend.blob_head(sha256).await? else {
            return Ok(DagHolding::NotADag);
        };
        let recorded_dag = head.storage_kind == "chunk_dag";
        if head.crypto_tier == CryptoTier::Plaintext {
            if !recorded_dag {
                return Ok(DagHolding::NotADag);
            }
            let Some(BlobBody::Inline(bytes)) = backend.get_blob(sha256).await? else {
                return Ok(DagHolding::Unverifiable);
            };
            let mut not_held = Vec::new();
            match ParsedManifest::parse(&bytes)? {
                ParsedManifest::Flat(f) => {
                    for (i, c) in f.chunks.iter().enumerate() {
                        if backend.blob_head(&c.sha).await?.is_none() {
                            not_held.push(c.seq.unwrap_or(i as u64));
                        }
                    }
                }
                ParsedManifest::Nested(_) => return Ok(DagHolding::Unverifiable),
            }
            return Ok(if not_held.is_empty() {
                DagHolding::Complete
            } else {
                DagHolding::Incomplete { not_held }
            });
        }
        if !recorded_dag {
            if head.storage_kind != "inline" {
                return Ok(DagHolding::NotADag);
            }
            let Ok(jcs) = read_sealed_inline_authorized(
                backend,
                sha256,
                head.crypto_tier,
                holder_key_id,
                None,
            )
            .await
            else {
                return Ok(DagHolding::NotADag);
            };
            if ParsedManifest::parse(&jcs).is_err() {
                return Ok(DagHolding::NotADag);
            }
        }
        match sealed_dag_readiness_for_viewer(backend, sha256, holder_key_id, None).await {
            Ok(r) if r.held => Ok(DagHolding::Complete),
            Ok(r) => Ok(DagHolding::Incomplete {
                not_held: r.not_held,
            }),
            Err(BlobError::NotGranted { .. }) => Ok(DagHolding::Unverifiable),
            Err(e) => Err(e),
        }
    }

    /// The per-chunk promotion checks (#947): each chunk the manifest names
    /// is held at its `(stream_id, seq)` with the named sha, plaintext size
    /// and the manifest's tier.
    fn check_chunks_held(
        by_seq: &std::collections::HashMap<u64, &StreamChunkRef>,
        chunks: &[ChunkRef],
        sha256: &[u8; 32],
        stream_id: &str,
        tier: CryptoTier,
    ) -> Result<(), BlobError> {
        for (i, c) in chunks.iter().enumerate() {
            let Some(seq) = c.seq else {
                return Err(BlobError::InvalidArgument(format!(
                    "manifest chunk [{i}] of {} carries no seq: not a positioned sealed manifest",
                    hex::encode(sha256)
                )));
            };
            let Some(row) = by_seq.get(&seq) else {
                return Err(BlobError::InvalidArgument(format!(
                    "chunk seq {seq} ({}) of stream {stream_id} is not held: fetch it by that sha \
                     and adopt it at (stream_id, seq) with plaintext_size {} before promoting \
                     (adopt_sealed_chunk)",
                    hex::encode(c.sha),
                    c.size
                )));
            };
            if row.chunk_sha != c.sha {
                return Err(BlobError::InvalidArgument(format!(
                    "chunk seq {seq} of stream {stream_id} is held as {} but the manifest names {}",
                    hex::encode(row.chunk_sha),
                    hex::encode(c.sha)
                )));
            }
            if row.plaintext_size != u64::from(c.size) {
                return Err(BlobError::InvalidArgument(format!(
                    "chunk seq {seq} of stream {stream_id} was adopted with plaintext_size {} but \
                     the manifest says {}",
                    row.plaintext_size, c.size
                )));
            }
            if row.crypto_tier != tier {
                return Err(BlobError::InvalidArgument(format!(
                    "chunk seq {seq} of stream {stream_id} is recorded at tier {:?} but the \
                     manifest is at {:?}",
                    row.crypto_tier, tier
                )));
            }
            // #969 — a v4 manifest names the epoch whose DEK sealed the chunk;
            // the adopt must have recorded it there (the reader opens by it).
            if let Some(epoch) = c.epoch {
                if row.epoch != epoch {
                    return Err(BlobError::InvalidArgument(format!(
                        "chunk seq {seq} of stream {stream_id} was adopted at epoch {} but the \
                         manifest says {epoch}: adopt it at the manifest's epoch",
                        row.epoch
                    )));
                }
            }
        }
        Ok(())
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
        // 2½. CC 2.3 at the bytes plane (v47.2.0, #853) — after authorization.
        crate::federation::at_rest_cascade::refuse_if_withdrawn(backend, sha256).await?;
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
                read_for_viewer_sealed(backend, sha256, viewer_key_id, &envelope, aad).await
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
                ParsedManifest::Flat(m)
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
                let m = ParsedManifest::parse(&jcs)?;
                if m.chunk_tier() != Some(tier) {
                    return Err(BlobError::Backend(format!(
                        "blob {} is recorded at tier {tier:?} but its manifest says {:?}",
                        hex::encode(sha256),
                        m.chunk_tier()
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
        let total = manifest.total_size();
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
        // lookup per distinct epoch in the range, not one per chunk. #969 —
        // and one stream-epoch DEK recovery per epoch.
        let mut memo = ChunkReadMemo::default();
        let mut stream_keyed = false;
        match &manifest {
            ParsedManifest::Flat(m) => {
                stream_keyed = m.is_stream_keyed();
                read_flat_chunks(
                    backend,
                    sha256,
                    m,
                    tier,
                    viewer_key_id,
                    aad,
                    (start, end),
                    &mut out,
                    &mut memo,
                )
                .await?
            }
            // #954 — the children covering the range are chosen by prefix sum
            // BEFORE any is opened; each is opened, then read within.
            ParsedManifest::Nested(root) => {
                for (i, ls, le) in root.children_for_range(start, end) {
                    let child = open_manifest_child(backend, root, i, viewer_key_id, aad).await?;
                    stream_keyed |= child.is_stream_keyed();
                    read_flat_chunks(
                        backend,
                        sha256,
                        &child,
                        tier,
                        viewer_key_id,
                        aad,
                        (ls, le),
                        &mut out,
                        &mut memo,
                    )
                    .await?;
                }
            }
        }
        // v53.0.0 (#969, CC 5.3.3.1) — a WHOLE read of a stream-keyed DAG
        // opened every chunk: their counters and terminators must form each
        // epoch whole (truncation resistance). Zero-length terminators lie
        // outside every byte range, so they are opened here for the check.
        if stream_keyed && range.is_none() {
            check_whole_stream_structure(
                backend,
                sha256,
                &manifest,
                tier,
                viewer_key_id,
                aad,
                &mut memo,
            )
            .await?;
        }
        Ok(out)
    }

    /// v53.0.0 (#969) — the whole-read structure check: open the chunks the
    /// byte loop skipped (zero-length — the terminators), then
    /// [`check_stream_epoch_structure`] over every slot in seq order.
    #[allow(clippy::too_many_arguments)]
    async fn check_whole_stream_structure<B>(
        backend: &B,
        sha256: &[u8; 32],
        manifest: &ParsedManifest,
        tier: CryptoTier,
        viewer_key_id: &str,
        aad: Option<&[u8]>,
        memo: &mut ChunkReadMemo,
    ) -> Result<(), BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        let chunks: Vec<(String, ChunkRef)> = match manifest {
            ParsedManifest::Flat(m) => {
                let sid = m.stream_id.clone().unwrap_or_default();
                m.chunks.iter().map(|c| (sid.clone(), c.clone())).collect()
            }
            ParsedManifest::Nested(root) => {
                let mut v = Vec::new();
                for i in 0..root.children.len() {
                    let child = open_manifest_child(backend, root, i, viewer_key_id, aad).await?;
                    v.extend(
                        child
                            .chunks
                            .into_iter()
                            .map(|c| (root.stream_id.clone(), c)),
                    );
                }
                v
            }
        };
        for (sid, c) in chunks.iter().filter(|(_, c)| c.size == 0) {
            let (Some(seq), Some(epoch)) = (c.seq, c.epoch) else {
                return Err(BlobError::Backend(format!(
                    "chunk_dag {} v4 chunk {} lacks its seq or epoch",
                    hex::encode(sha256),
                    hex::encode(c.sha)
                )));
            };
            open_stream_chunk_row_for_viewer(
                backend,
                sha256,
                &c.sha,
                tier,
                viewer_key_id,
                &chunk_aad(aad, sid, seq),
                ChunkPos {
                    stream_id: sid,
                    seq,
                    keys: ChunkKeys::StreamEpoch(epoch),
                    dag_authorized: true,
                },
                memo,
            )
            .await?;
        }
        let mut slots = std::mem::take(&mut memo.stream_slots);
        slots.sort_by_key(|(seq, _, _)| *seq);
        slots.dedup_by_key(|(seq, _, _)| *seq);
        if slots.len() != chunks.len() {
            return Err(BlobError::Backend(format!(
                "chunk_dag {}: {} of its {} chunks were opened under a stream key",
                hex::encode(sha256),
                slots.len(),
                chunks.len()
            )));
        }
        check_stream_epoch_structure(sha256, &slots)
    }

    /// The chunk loop of a sealed v2 manifest (or one v3 child) over its
    /// local inclusive range: every covering chunk opened under its
    /// position-bound AAD and sliced, appended to `out`.
    #[allow(clippy::too_many_arguments)]
    async fn read_flat_chunks<B>(
        backend: &B,
        sha256: &[u8; 32],
        manifest: &ChunkManifest,
        tier: CryptoTier,
        viewer_key_id: &str,
        aad: Option<&[u8]>,
        (start, end): (u64, u64),
        out: &mut Vec<u8>,
        memo: &mut ChunkReadMemo,
    ) -> Result<(), BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
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
            // #969 — a v4 manifest names the epoch whose DEK sealed the chunk.
            let keys = match (manifest.is_stream_keyed(), cref.epoch) {
                (false, _) => ChunkKeys::PerChunk,
                (true, Some(e)) => ChunkKeys::StreamEpoch(e),
                (true, None) => {
                    return Err(BlobError::Backend(format!(
                        "blob {} is a v4 chunk_dag whose chunk {} carries no epoch",
                        hex::encode(sha256),
                        hex::encode(cref.sha)
                    )))
                }
            };
            let plain = open_stream_chunk_row_for_viewer(
                backend,
                sha256,
                &cref.sha,
                tier,
                viewer_key_id,
                &bound_aad,
                ChunkPos {
                    stream_id,
                    seq,
                    keys,
                    dag_authorized: true,
                },
                memo,
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
        Ok(())
    }

    /// v53.0.0 (CIRISPersist#969) — which keys sealed a chunk, as the reader
    /// knows it: from the manifest (`PerChunk` for v2, `StreamEpoch` for v4,
    /// with the epoch the manifest names), or — for a live chunk read by
    /// position, before any manifest exists — `Live` with the index row's
    /// epoch: a per-chunk grant if the viewer holds one (a pre-#969 stream),
    /// else the stream grant of that epoch.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum ChunkKeys {
        /// A legacy chunk: its own DEK and grants.
        PerChunk,
        /// A stream-keyed chunk at this epoch (a v4 manifest says so).
        StreamEpoch(u64),
        /// A live chunk at this index-row epoch: per-chunk if granted, else
        /// stream-keyed.
        Live(u64),
    }

    /// Where a chunk sits and how the read reached it.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct ChunkPos<'a> {
        /// The stream the chunk was sealed in.
        pub stream_id: &'a str,
        /// Its position.
        pub seq: u64,
        /// Which keys sealed it.
        pub keys: ChunkKeys,
        /// The viewer was authorized on the DAG's manifest: a missing chunk
        /// key is then the typed, RETRYABLE refusal naming the key (sets may
        /// still be arriving), never the stranger's `NotGranted`.
        pub dag_authorized: bool,
    }

    /// What one sealed read remembers across its chunks: the community epochs
    /// already authorized (I38), the stream-epoch DEKs already recovered
    /// (#969 — one recovery per epoch, not per chunk), and the STREAM slots
    /// opened, in order, for the whole read's structure check.
    #[derive(Default)]
    pub(crate) struct ChunkReadMemo {
        community_epochs: std::collections::HashSet<(String, String, u64)>,
        stream_deks: std::collections::HashMap<(String, u64), [u8; 32]>,
        stream_slots: Vec<(u64, u64, crate::federation::StreamKeySlot)>,
    }

    /// v53.0.0 (#969) — the viewer's wrap of `(stream_id, epoch)`, taken only
    /// from a sealer that speaks for the stream's owner as THIS node records
    /// it (a set for another owner's stream id grants nothing), and the DEK
    /// it carries: through the epoch's self-retention when this node sealed
    /// the stream, else by opening the viewer's wrap with this node's
    /// content-KEM identity. `None` when the viewer holds no such wrap.
    pub(crate) async fn stream_dek_for_viewer<B>(
        backend: &B,
        stream_id: &str,
        epoch: u64,
        viewer_key_id: &str,
    ) -> Result<Option<[u8; 32]>, BlobError>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let Some(sealer) = stream_grant_sealer(backend, stream_id, epoch, viewer_key_id).await?
        else {
            return Ok(None);
        };
        let (sealer, wrap) = sealer;
        if let Some(rec) = backend
            .stream_dek_list(stream_id)
            .await?
            .into_iter()
            .find(|r| r.epoch == epoch && r.owner_key_id == sealer)
        {
            return stream_epoch_dek(backend, &rec).await.map(Some);
        }
        let private = backend.load_content_kem_private_halves().await?;
        crate::federation::at_rest_cascade::unwrap_dek_v2_json(&private, &wrap.wrapped_dek)
            .map(Some)
            .map_err(|e| {
                BlobError::Backend(format!(
                    "stream {stream_id} epoch {epoch}: the wrap addressed to {viewer_key_id:?} \
                     does not open with this node's content-KEM identity — that occurrence's \
                     private half lives on another device ({e})"
                ))
            })
    }

    /// v53.0.0 (#969) — the viewer's admissible wrap of `(stream_id, epoch)`
    /// with its sealer, WITHOUT opening it: what authorization and the
    /// readiness door ask.
    pub(crate) async fn stream_grant_sealer<B>(
        backend: &B,
        stream_id: &str,
        epoch: u64,
        viewer_key_id: &str,
    ) -> Result<Option<(String, crate::federation::GrantWrap)>, BlobError>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let Some(owner) = backend.stream_key_state(stream_id).await?.owner_key_id else {
            return Ok(None);
        };
        for (sealer, wrap) in backend
            .stream_dek_grants_for_recipient(stream_id, epoch, viewer_key_id)
            .await?
        {
            if sealer == owner
                || crate::federation::self_collective::speaks_for(backend, &sealer, &owner)
                    .await
                    .map_err(|e| BlobError::Backend(format!("stream grant sealer: {e}")))?
            {
                return Ok(Some((sealer, wrap)));
            }
        }
        Ok(None)
    }

    /// §12.4 / §12.10 — **open ONE sealed stream chunk row for a viewer,
    /// under its position-bound AAD.** The row must exist (else the shared
    /// #833 refusal — swept or never ours, told only to an authorized
    /// viewer) and must record `tier`; the viewer is authorized on THIS
    /// chunk BEFORE its body is read — their grant on the row (a legacy
    /// self/family chunk), their grant on the chunk's stream epoch (#969), or
    /// their grant on the row's OWN binding's epoch at `community` (I38) —
    /// then the sha is re-verified over the stored bytes (CEG §10.1.1) and
    /// the envelope opens under `bound_aad`. A stream-keyed chunk's nonce is
    /// recomputed and must match (#969). A refusal names `refused_sha` (the
    /// DAG the viewer asked for, or the chunk itself); a viewer authorized
    /// on the DAG who lacks the chunk's key is told WHICH key, retryably.
    #[allow(clippy::too_many_arguments)]
    async fn open_stream_chunk_row_for_viewer<B>(
        backend: &B,
        refused_sha: &[u8; 32],
        chunk_sha: &[u8; 32],
        tier: CryptoTier,
        viewer_key_id: &str,
        bound_aad: &[u8],
        pos: ChunkPos<'_>,
        memo: &mut ChunkReadMemo,
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
        let missing_key = |key: crate::federation::blobs::ChunkKeyRef| {
            if pos.dag_authorized {
                BlobError::ChunkKeyNotYetGranted {
                    sha256_hex: hex::encode(refused_sha),
                    viewer_key_id: viewer_key_id.to_owned(),
                    seq: pos.seq,
                    chunk_sha_hex: hex::encode(chunk_sha),
                    key,
                }
            } else {
                BlobError::NotGranted {
                    sha256_hex: hex::encode(refused_sha),
                    viewer_key_id: viewer_key_id.to_owned(),
                }
            }
        };
        // AUTHORIZE, then read (I4): which key, and does the viewer hold it.
        enum Material {
            PerChunk,
            Stream(u64, [u8; 32]),
            Community(String, String, u64),
        }
        let material = match tier {
            CryptoTier::Plaintext => {
                return Err(BlobError::Backend(format!(
                    "stream chunk {} is plaintext; nothing to open",
                    hex::encode(chunk_sha)
                )))
            }
            CryptoTier::InvisibleEncrypted => {
                let keys = match pos.keys {
                    ChunkKeys::Live(epoch) => {
                        if backend
                            .get_at_rest_grant(chunk_sha, viewer_key_id)
                            .await?
                            .is_some()
                        {
                            ChunkKeys::PerChunk
                        } else {
                            ChunkKeys::StreamEpoch(epoch)
                        }
                    }
                    k => k,
                };
                match keys {
                    ChunkKeys::StreamEpoch(epoch) => {
                        let memo_key = (pos.stream_id.to_owned(), epoch);
                        let dek = match memo.stream_deks.get(&memo_key) {
                            Some(d) => *d,
                            None => {
                                let Some(d) = stream_dek_for_viewer(
                                    backend,
                                    pos.stream_id,
                                    epoch,
                                    viewer_key_id,
                                )
                                .await?
                                else {
                                    return Err(missing_key(
                                        crate::federation::blobs::ChunkKeyRef::Stream {
                                            stream_id: pos.stream_id.to_owned(),
                                            epoch,
                                        },
                                    ));
                                };
                                memo.stream_deks.insert(memo_key, d);
                                d
                            }
                        };
                        Material::Stream(epoch, dek)
                    }
                    _ => {
                        // The viewer's grant on THIS chunk row (I38).
                        if backend
                            .get_at_rest_grant(chunk_sha, viewer_key_id)
                            .await?
                            .is_none()
                        {
                            return Err(missing_key(
                                crate::federation::blobs::ChunkKeyRef::Content {
                                    at_rest_sha256: hex::encode(chunk_sha),
                                },
                            ));
                        }
                        Material::PerChunk
                    }
                }
            }
            CryptoTier::CommunityDek => {
                // The chunk's OWN binding names the DEK that sealed it — a
                // pre-rotation chunk opens under its old epoch (I38) — and the
                // viewer must hold a grant on that epoch. #848 — the binding
                // is `(community, minter, epoch)`.
                let (community, minter, epoch) = backend
                    .community_dek_blob_epoch(chunk_sha)
                    .await?
                    .ok_or_else(|| {
                        BlobError::Backend(format!(
                            "stream chunk {} is recorded at community_dek but carries no epoch \
                             binding",
                            hex::encode(chunk_sha)
                        ))
                    })?;
                let key = (community.clone(), minter.clone(), epoch);
                if !memo.community_epochs.contains(&key) {
                    if !backend
                        .community_dek_has_member_grant(&community, &minter, epoch, viewer_key_id)
                        .await?
                    {
                        return Err(BlobError::NotGranted {
                            sha256_hex: hex::encode(refused_sha),
                            viewer_key_id: viewer_key_id.to_owned(),
                        });
                    }
                    memo.community_epochs.insert(key);
                }
                Material::Community(community, minter, epoch)
            }
        };
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
        match material {
            Material::PerChunk => {
                read_for_viewer_sealed(
                    backend,
                    chunk_sha,
                    viewer_key_id,
                    &envelope,
                    Some(bound_aad),
                )
                .await
            }
            Material::Stream(epoch, dek) => {
                let (plain, slot) = open_stream_keyed_chunk(
                    &dek,
                    pos.stream_id,
                    epoch,
                    chunk_sha,
                    &envelope,
                    bound_aad,
                )?;
                memo.stream_slots.push((pos.seq, epoch, slot));
                Ok(plain)
            }
            Material::Community(community, minter, epoch) => {
                open_community_row_for_viewer(
                    backend,
                    chunk_sha,
                    &community,
                    &minter,
                    epoch,
                    viewer_key_id,
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
        // 2. AUTHORIZE BY TIER, BEFORE TOUCHING ANY BODY (§11.3 / I4). A
        //    self/family chunk is authorized inside the opener, before its
        //    body: per-chunk grant, or (#969) the stream grant of its epoch.
        if head.crypto_tier != CryptoTier::InvisibleEncrypted {
            authorize_viewer_by_tier(backend, &c.chunk_sha, head.crypto_tier, viewer_key_id)
                .await?;
        }
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
                    ChunkPos {
                        stream_id,
                        seq,
                        keys: ChunkKeys::Live(c.epoch),
                        dag_authorized: false,
                    },
                    &mut ChunkReadMemo::default(),
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
        sealed_community_stream_as(backend, &signer, tag, comm, stream, segments).await
    }

    /// [`sealed_community_stream`] with the WRITER given: every chunk and
    /// the seal are signed by `adapter`, so the stream belongs to it (#837).
    async fn sealed_community_stream_as<B>(
        backend: &B,
        local: &std::sync::Arc<crate::signing::LocalSigner>,
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
            let chunk_writer = crate::signing::LocalSignerHardwareAdapter::new(local.clone());
            let r = put_blob_chunk_scoped(
                backend,
                &chunk_writer,
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
        let sealed = seal_stream_scoped(backend, local, COMMUNITY, Some(comm), stream, None, None)
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
        let minter = format!("{tag}-minter-{run}");
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        seed_community(backend, &comm, &[(&alice, &alice_occ)]).await;
        let sealed =
            encrypt_and_cascade_community(backend, &comm, b"segment 0", None, Some(&minter))
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
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());
        let minter = signer.derived_key_id();

        let owner = signer.derived_key_id();
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
                        stream_key: None,
                    },
                )
                .await
                .unwrap();
            let res = seal_stream_scoped(
                backend,
                &signer,
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
            &signer,
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
                        minter_key_id: minter.clone(),
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
    /// **A `self` DAG is stream-keyed** (v53.0.0, #969): the manifest carries
    /// persist's self-retention grant and the owner's occurrence grant; the
    /// chunk rows carry NONE — the stream epoch's DEK is wrapped once to the
    /// occurrence; the occurrence reads whole and by range; a stranger is
    /// refused; nothing is announced.
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
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());
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
        let sealed = seal_stream_scoped(backend, &signer, SELF, Some(&owner), &stream, None, None)
            .await
            .unwrap_or_else(|e| panic!("{tag} I34b: seal: {e}"));
        let manifest = sealed.manifest_sha256;
        assert!(
            backend
                .get_at_rest_grant(&manifest, PERSIST_SELF_RECIPIENT)
                .await
                .unwrap()
                .is_some(),
            "{tag} I34b: persist self-retention on the manifest"
        );
        assert!(
            backend
                .get_at_rest_grant(&manifest, &occ)
                .await
                .unwrap()
                .is_some(),
            "{tag} I34b: the occurrence's grant on the manifest"
        );
        for s in &chunk_shas {
            assert!(
                backend.list_at_rest_grants(s).await.unwrap().is_empty()
                    && backend
                        .get_at_rest_grant(s, PERSIST_SELF_RECIPIENT)
                        .await
                        .unwrap()
                        .is_none(),
                "{tag} I34b: a stream-keyed chunk row carries no per-chunk grant (#969)"
            );
        }
        let writer = signer.derived_key_id();
        assert!(
            backend
                .stream_dek_grants(&stream, 0, &writer)
                .await
                .unwrap()
                .iter()
                .any(|w| w.recipient_key_id == occ),
            "{tag} I34b: the occurrence holds the stream epoch's wrap"
        );
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
            let r = encrypt_and_cascade(backend, SELF, &owner, &whole, None, None, None)
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

        // v51.0.0 (#923 amendment 2, D9) — a second occurrence of the owner
        // that arrived AFTER the chunk was written and BEFORE the seal: the
        // seal wraps the manifest and EVERY chunk to one recipient set, so it
        // reads the whole stream (one access set per stream; the descriptor
        // under the manifest's DEK and the bytes are one fact). The reader
        // still checks the CHUNK ROW's grant (I38 for self): a viewer granted
        // on the manifest alone is refused.
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
                seal_stream_scoped(backend, &signer, SELF, Some(&owner), &stream2, None, None)
                    .await
                    .unwrap();
            assert!(
                sealed2.granted.contains(&later_occ),
                "{tag} I34b: the later occurrence is granted on the manifest"
            );
            assert!(
                backend
                    .stream_dek_grants(&stream2, 0, &signer.derived_key_id())
                    .await
                    .unwrap()
                    .iter()
                    .any(|w| w.recipient_key_id == later_occ),
                "{tag} D9: the seal widened the stream epoch to the stream's access set"
            );
            assert!(
                backend
                    .list_at_rest_grants(&c.chunk_sha256)
                    .await
                    .unwrap()
                    .is_empty(),
                "{tag} D9: and not the chunk row (#969)"
            );
            assert!(sealed2.chunk_key_grant_emissions.is_empty());
            assert_eq!(
                sealed2.stream_key_grant_emissions.len(),
                1,
                "{tag} D9: the widened epoch's key-grant set is emitted, once"
            );
            assert_eq!(
                read_any_for_viewer(backend, &sealed2.manifest_sha256, &later_occ, None)
                    .await
                    .unwrap(),
                seg,
                "{tag} D9: the occurrence that joined mid-write reads the whole stream"
            );
            // I38 still holds: a grant on the manifest alone opens no chunk
            let ghost = format!("{tag}-owner-ghost-occ-{run}");
            let (algo, wrapped) = backend
                .get_at_rest_grant(&sealed2.manifest_sha256, &later_occ)
                .await
                .unwrap()
                .unwrap();
            backend
                .put_at_rest_grant(&sealed2.manifest_sha256, &ghost, &algo, &wrapped, SELF)
                .await
                .unwrap();
            assert!(
                matches!(
                    read_any_range_for_viewer(
                        backend,
                        &sealed2.manifest_sha256,
                        &ghost,
                        0,
                        9,
                        None
                    )
                    .await,
                    Err(BlobError::ChunkKeyNotYetGranted {
                        key: crate::federation::ChunkKeyRef::Stream { .. },
                        ..
                    })
                ),
                "{tag} I34b: a viewer granted on the manifest but not on the chunk's epoch read \
                 the chunk — the reader trusted the manifest's grant for every chunk (#969: \
                 the refusal names the stream key, retryably)"
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
        let writer_local = crate::federation::at_rest_cascade::blob_invariants::node_signer(
            backend,
            &format!("{tag}-writer-{run}"),
        )
        .await;
        let writer = crate::signing::LocalSignerHardwareAdapter::new(writer_local.clone());
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
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());
        let minter = signer.derived_key_id();
        let stream = format!("{tag}-stream-{run}");
        let seg0 = segment(21, 900);
        let seg1 = segment(22, 600);

        let owner = signer.derived_key_id();
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
        // epoch is refused as a UNIT: no blob row, no index row, nothing to
        // orphan. #848 (§15, I63): the seal at e1 above DISABLED e0 — a
        // removal was admitted after e0 was minted, and "rotated past" now
        // means it at the next seal, not at the next sweep. The floor's
        // refusal below is therefore doubly grounded (pointer AND state);
        // what it measures is that the append lands as a unit or not at all.
        {
            use crate::federation::at_rest_cascade::{fresh_dek, seal};
            use crate::federation::{EpochBinding, StorageFloor, StreamClaim};
            assert_eq!(
                backend.community_dek_key_state(&comm, &minter, e0).await.unwrap(),
                Some(crate::federation::DekKeyState::Disabled),
                "{tag} I38: precondition — e0 was disabled by the seal that rotated past it (#848 §15)"
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
                        minter_key_id: minter.clone(),
                        epoch: e0,
                    }),
                    StreamClaim {
                        community_key_id: Some(comm.clone()),
                        owner_key_id: Some(owner.clone()),
                        stream_key: None,
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
            &signer,
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
            Some((comm.clone(), minter.clone(), e0)),
            "{tag} I38: chunk 0 stays bound to e0"
        );
        assert_eq!(
            backend
                .community_dek_blob_epoch(&c1.chunk_sha256)
                .await
                .unwrap(),
            Some((comm.clone(), minter.clone(), e1))
        );
        assert_eq!(
            backend.community_dek_blob_epoch(&manifest).await.unwrap(),
            Some((comm.clone(), minter.clone(), e1))
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
        let writer_a_local = crate::federation::at_rest_cascade::blob_invariants::node_signer(
            backend,
            &format!("{tag}-writer-a-{run}"),
        )
        .await;
        let writer_a = crate::signing::LocalSignerHardwareAdapter::new(writer_a_local.clone());
        let writer_b_local = crate::federation::at_rest_cascade::blob_invariants::node_signer(
            backend,
            &format!("{tag}-writer-b-{run}"),
        )
        .await;
        let writer_b = crate::signing::LocalSignerHardwareAdapter::new(writer_b_local.clone());
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
            &writer_b_local,
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
            &writer_a_local,
            COMMUNITY,
            Some(&other),
            &stream,
            None,
            None,
        )
        .await;
        match res {
            Err(BlobError::InvalidArgument(msg)) => assert!(
                msg.contains(&comm) && msg.contains("belongs to"),
                "{tag} I41: the seal refusal is the STREAM ROW's (\"belongs to\"), naming the \
                 stream's community, and fires before I32's chunk-row check: {msg}"
            ),
            other => panic!("{tag} I41: the stream sealed under another community: {other:?}"),
        }
        let sealed = seal_stream_scoped(
            backend,
            &writer_a_local,
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
                    stream_key: None,
                },
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I41: the owner's claim passes the floor: {e}"));
        match seal_stream_scoped(
            backend,
            &writer_a_local,
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

        // The COMMONS seal refuses a stream whose row is not at `federation`,
        // on the one stream I32 cannot refuse: an infra-shaped community
        // stream whose chunk rows are all plaintext. Without the row check
        // the commons seal writes a public manifest over community rows.
        let infra = format!("{tag}-infra-{run}");
        backend
            .put_blob_chunk_with_scope(
                &infra,
                0,
                BlobBody::Inline(b"infra plaintext".to_vec()),
                0,
                15,
                COMMUNITY,
                StorageFloor::resolved(CryptoTier::Plaintext),
                None,
                StreamClaim {
                    community_key_id: Some(comm.clone()),
                    owner_key_id: Some(key_a.clone()),
                    stream_key: None,
                },
            )
            .await
            .unwrap();
        match backend.seal_stream(&infra).await {
            Err(BlobError::InvalidArgument(msg)) => assert!(
                msg.contains("belongs to cohort"),
                "{tag} I41: the commons seal's refusal is the stream row's: {msg}"
            ),
            other => panic!(
                "{tag} I41: the commons seal wrote a federation manifest over a community-cohort \
                 stream (all-plaintext, so I32 could not refuse it): {other:?}"
            ),
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
        let writer_local = crate::federation::at_rest_cascade::blob_invariants::node_signer(
            backend,
            &format!("{tag}-writer-{run}"),
        )
        .await;
        let writer = crate::signing::LocalSignerHardwareAdapter::new(writer_local.clone());
        let owner = crate::signing::federation_key_id_of(&writer).await.unwrap();
        // #848 — the writer IS the minter (I23): the floor is driven below
        // under the epoch the door minted for this key.
        let minter = owner.clone();
        let stream = format!("{tag}-stream-{run}");
        let segs = [segment(31, 100), segment(32, 200)];
        let (manifest, shas, plain) =
            sealed_community_stream_as(backend, &writer_local, tag, &comm, &stream, &segs).await;

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
        let epoch = backend
            .community_dek_current_epoch(&comm, &minter)
            .await
            .unwrap();
        let dek = ensure_epoch_dek(backend, &comm, &minter, epoch)
            .await
            .unwrap()
            .dek;
        let swapped = ChunkManifest {
            v: CHUNK_MANIFEST_VERSION_SEALED,
            total_size: 300,
            chunks: vec![
                ChunkRef {
                    sha: shas[1],
                    size: 200,
                    seq: Some(0),
                    epoch: None,
                },
                ChunkRef {
                    sha: shas[0],
                    size: 100,
                    seq: Some(1),
                    epoch: None,
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
                    children: Vec::new(),
                },
                None,
                COMMUNITY,
                StorageFloor::resolved(CryptoTier::CommunityDek),
                Some(EpochBinding {
                    community_key_id: comm.clone(),
                    minter_key_id: minter.clone(),
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
            Err(BlobError::SealDidNotOpen { .. }) => {} // v47.1.0 #842: typed, not prose
            Err(other) => panic!("{tag} I42: wrong refusal class for a moved chunk: {other:?}"),
            Ok(bytes) => panic!(
                "{tag} I42: a chunk moved to another index OPENED ({} bytes) — the chunk's \
                 AAD does not carry its position",
                bytes.len()
            ),
        }
        match read_any_for_viewer(backend, &swapped_sha, &alice_occ, None).await {
            Err(BlobError::SealDidNotOpen { .. }) => {} // v47.1.0 #842: typed, not prose
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
                    minter_key_id: minter.clone(),
                    epoch,
                }),
                StreamClaim {
                    community_key_id: Some(comm.clone()),
                    owner_key_id: Some(owner.clone()),
                    stream_key: None,
                },
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I42: lift through the floor: {e}"));
        let sealed2 = seal_stream_scoped(
            backend,
            &writer_local,
            COMMUNITY,
            Some(&comm),
            &stream2,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I42: the second stream seals: {e}"));
        match read_any_for_viewer(backend, &sealed2.manifest_sha256, &alice_occ, None).await {
            Err(BlobError::SealDidNotOpen { .. }) => {} // v47.1.0 #842: typed, not prose
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
            Err(BlobError::SealDidNotOpen { .. }) => {} // v47.1.0 #842: typed, not prose
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
        // A plaintext (commons) stream reads by position the same way, and
        // refuses associated data it cannot bind (I40 at this door too).
        let commons = format!("{tag}-commons-{run}");
        backend
            .put_blob_chunk(&commons, 3, BlobBody::Inline(b"public bytes".to_vec()), 0)
            .await
            .unwrap();
        assert_eq!(
            read_stream_chunk_as(backend, &commons, 3, &stranger, None)
                .await
                .unwrap(),
            b"public bytes".to_vec(),
            "{tag} I42: a commons chunk reads by position, by anyone"
        );
        assert!(
            matches!(
                read_stream_chunk_as(backend, &commons, 3, &stranger, Some(b"x")).await,
                Err(BlobError::InvalidArgument(_))
            ),
            "{tag} I42: associated data at a plaintext position is refused, not dropped"
        );
        match read_any_range_for_viewer(backend, &shas[0], &alice_occ, 0, 9, None).await {
            Err(BlobError::SealDidNotOpen { .. }) => {} // v47.1.0 #842: typed, not prose
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

        // `seq` is the manifest's WORD, not the list index: a stream whose
        // producer skipped numbers (5, 7) seals and reads honestly, whole,
        // by range across the boundary, and by position. A reader that
        // rebuilt the AAD from the index would fail here and nowhere else.
        let sparse = format!("{tag}-sparse-{run}");
        let sparse_segs = [segment(41, 64), segment(42, 32)];
        for (seq, seg) in [(5u64, &sparse_segs[0]), (7u64, &sparse_segs[1])] {
            put_blob_chunk_scoped(
                backend,
                &writer,
                COMMUNITY,
                Some(&comm),
                &sparse,
                seq,
                seg,
                0,
                None,
            )
            .await
            .unwrap();
        }
        let sealed_sparse = seal_stream_scoped(
            backend,
            &writer_local,
            COMMUNITY,
            Some(&comm),
            &sparse,
            None,
            None,
        )
        .await
        .unwrap();
        let mut sparse_plain = sparse_segs[0].clone();
        sparse_plain.extend_from_slice(&sparse_segs[1]);
        assert_eq!(
            read_any_for_viewer(backend, &sealed_sparse.manifest_sha256, &alice_occ, None)
                .await
                .unwrap(),
            sparse_plain,
            "{tag} I42: a sparse-seq stream opens whole — the AAD uses the manifest's seq"
        );
        assert_eq!(
            read_any_range_for_viewer(
                backend,
                &sealed_sparse.manifest_sha256,
                &alice_occ,
                60,
                70,
                None
            )
            .await
            .unwrap(),
            sparse_plain[60..=70].to_vec()
        );
        assert_eq!(
            read_stream_chunk_as(backend, &sparse, 7, &alice_occ, None)
                .await
                .unwrap(),
            sparse_segs[1]
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
                device_class: crate::federation::types::device_class::LAPTOP.into(),
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
