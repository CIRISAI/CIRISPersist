//! CIRISPersist#846 (`FSD/BLOB_REPLICATION.md` §3, §6) — **the adopt doors:
//! store a sealed blob received from a peer, verbatim, at the tier and under
//! the binding its provenance declares.**
//!
//! Every write door persist had was wrong for received ciphertext: `put_blob`
//! stored it as a plaintext-tier row, `put_blob_scoped` re-sealed (which
//! "sealed once, wrapped per recipient, never re-encoded" forbids), and
//! `store_blob_local` announced nothing. No sealed blob had ever been stored
//! by a node that did not seal it (§3). This is the receiver-side twin of
//! `serve_blob_to_peer`, and like it contains no `open(` — the from-disk gate
//! I45 holds that.
//!
//! The order is the FSD's: shape, tier, the WILL decision ([`would_hold`]),
//! then the floor. Nothing is written before the decision.
//!
//! # `aad` is carried, not recorded
//!
//! Associated data is the READER's fact: `read_blob_as` / `read_stream_chunk_as`
//! take it at open time and bind it into the tag (#831, I40). The at-rest row
//! stores no AAD (I40 — "bound into the seal and never stored"), so an adopt
//! has nothing to record; the parameter is accepted so a caller that received
//! the AAD beside the bytes has one call shape, and it is deliberately unused.

use crate::federation::at_rest_cascade::AtRestEnvelope;
use crate::federation::replication::hold::{would_hold, BlobProvenance, HoldContext};
use crate::federation::types::cohort_scope::CryptoTier;
use crate::federation::{BlobError, BlobStorage, EpochBinding, FederationDirectory, StorageFloor};

/// #846 (§4, §6.1) — Edge's `admit_blob_store` trichotomy, minus `Refuse`
/// (a refusal never reaches this door). Carried, not re-derived: persist
/// does not second-guess the MAY decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptDisposition {
    /// Store and emit this node's holding claim (v55.0.0, CIRISPersist#989:
    /// `custody:ack:v1` `here`), placed at the content's own scope — the
    /// owner's `self`, the family, the room — so it reaches the cohort only.
    Announce,
    /// Store; emit nothing.
    LocalOnly,
}

/// #846 (§6.1) — what an adopt returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptOutcome {
    /// The address: SHA-256 of the ciphertext as stored.
    pub sha256: [u8; 32],
    /// Whether a holding claim was emitted.
    pub announced: bool,
    /// Content-axis wraps projected from `KeyGrant` sets that arrived before
    /// the bytes and were signed by the author (§13; 0 when none waited).
    pub pending_wraps: usize,
}

/// Shape and tier checks shared by the blob and chunk doors: the bytes must
/// parse as an [`AtRestEnvelope`] (a structural check, NOT an open — I45),
/// the provenance must be at a sealed tier, and a `CommunityDek` provenance
/// must name its `(community, epoch)`. Returns the floor token and the
/// binding to write AS DECLARED.
/// v46.0.0 (#876) — async because the binding's minter is resolved, not
/// inferred: `backend` is asked which admitted `key_grant` set names it,
/// and `our_key_id` is the viewer whose wrap identifies that set.
async fn resolve_adopt<B>(
    backend: &B,
    our_key_id: &str,
    envelope: &[u8],
    provenance: &BlobProvenance,
) -> Result<(StorageFloor, Option<EpochBinding>), BlobError>
where
    B: BlobStorage + FederationDirectory + Sync + ?Sized,
{
    check_envelope_shape(envelope)?;
    resolve_provenance(backend, our_key_id, provenance).await
}

/// The envelope-shape half of [`resolve_adopt`]: a structural parse, NOT an
/// open (I45).
fn check_envelope_shape(envelope: &[u8]) -> Result<(), BlobError> {
    AtRestEnvelope::from_bytes(envelope).map_err(|e| {
        BlobError::InvalidArgument(format!(
            "adopt: the bytes do not have the at-rest envelope shape ({e}); an adopt stores \
             sealed bytes verbatim and nothing else"
        ))
    })?;
    Ok(())
}

/// The provenance half of [`resolve_adopt`]: the tier, the floor token, and
/// the binding to write AS DECLARED. Per stream, so a batch runs it once.
async fn resolve_provenance<B>(
    backend: &B,
    our_key_id: &str,
    provenance: &BlobProvenance,
) -> Result<(StorageFloor, Option<EpochBinding>), BlobError>
where
    B: BlobStorage + FederationDirectory + Sync + ?Sized,
{
    let binding = match provenance.tier {
        CryptoTier::Plaintext => {
            return Err(BlobError::InvalidArgument(format!(
                "adopt: provenance at {:?} declares plaintext; plaintext is put_blob's door \
                 (BLOB_REPLICATION.md §6.1)",
                provenance.cohort_scope
            )))
        }
        CryptoTier::InvisibleEncrypted => None,
        CryptoTier::CommunityDek => {
            let (Some(community), Some(epoch)) =
                (provenance.community_key_id.as_deref(), provenance.epoch)
            else {
                return Err(BlobError::InvalidArgument(
                    "adopt: a community_dek provenance must name its community and epoch — the \
                     binding is the author's fact and is recorded as declared (§3)"
                        .into(),
                ));
            };
            // v46.0.0 (CIRISPersist#876, `FSD/EPOCH_MINTER.md`) — the minter
            // is NAMED or DERIVED, never inferred from the author. The old
            // spelling (`minter_key_id: provenance.author_key_id`) assumed
            // the author's cascade minted the epoch; a chat row is authored
            // by a person and sealed by their node, and the binding then
            // named a key that holds no DEK and no grants.
            Some(EpochBinding {
                community_key_id: community.to_owned(),
                minter_key_id: super::epoch_minter::resolve(
                    backend,
                    provenance.minter_key_id.as_deref(),
                    community,
                    epoch,
                    our_key_id,
                    &provenance.author_key_id,
                )
                .await?,
                epoch,
            })
        }
    };
    let floor = StorageFloor::resolved(provenance.tier);
    // I25 — a self/family row is never plaintext, commons never sealed; the
    // floor refuses the contradiction, but refusing here keeps the decision
    // ahead of the bytes.
    floor.check_scope(&provenance.cohort_scope)?;
    Ok((floor, binding))
}

/// v55.0.0 (CIRISPersist#989) — the group an adopted sealed row names: the
/// binding's community for a room, else the provenance's owner or family.
/// Recorded on the row (V177) and the scope its holding claim is placed at.
fn adopt_group<'a>(
    provenance: &'a BlobProvenance,
    binding: Option<&'a EpochBinding>,
) -> Option<&'a str> {
    binding
        .map(|b| b.community_key_id.as_str())
        .or(provenance.community_key_id.as_deref())
}

/// #846 (§6.1) — **adopt a received sealed blob.** See the module doc for
/// the order; `ctx` is the Engine's hold context (pressure, local-or-family,
/// this node's key), and `signer` signs the holder claim when `disposition`
/// is [`AdoptDisposition::Announce`].
///
/// v55.0.0 (CIRISPersist#989, CC 3.1.3.3) — every sealed tier may announce:
/// the claim is placed at the content's scope (`self`, the family, the room),
/// so a `self` / `family` adopt announces to its own cohort and nobody else
/// (I52 refused it while the only claim was the federation-scoped
/// `holds_bytes`). The holder must be in the cohort; a node that is not is
/// refused at the floor before anything is written.
///
/// `pqc` — CIRISPersist#851 §20.5: a classical-only claim is confined to
/// local tier (CC 5.3.2.4.3.1); with a LocalSigner the claim is
/// hybrid-signed so peers admit it.
#[allow(clippy::too_many_arguments)]
pub async fn adopt_sealed_blob<B, F>(
    backend: &B,
    local: Option<&crate::signing::LocalSigner>,
    ctx: &HoldContext<'_, F>,
    envelope: &[u8],
    provenance: &BlobProvenance,
    aad: Option<&[u8]>,
    disposition: AdoptDisposition,
) -> Result<AdoptOutcome, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
    F: Fn(&str) -> bool,
{
    // Carried, not recorded — see the module doc.
    let _ = aad;
    let (floor, binding) = resolve_adopt(backend, ctx.our_key_id, envelope, provenance).await?;
    let announce = disposition == AdoptDisposition::Announce;
    would_hold(backend, ctx, provenance).await?;
    let claim = if announce {
        use sha2::Digest as _;
        let sha256: [u8; 32] = sha2::Sha256::digest(envelope).into();
        // The HOLDER claims (I23): attested and signed by this node's
        // derived key, never the author's.
        let local = local.ok_or_else(|| {
            BlobError::AttestationEmissionFailed(
                "hybrid-only: announcing an adopted blob needs this node's PQC LocalSigner \
                 (CIRISPersist#851 §20.5); adopt it LocalOnly to hold without announcing"
                    .into(),
            )
        })?;
        // v55.0.0 (CIRISPersist#989) — the claim at the content's scope; the
        // floor rebuilds the same scope from its own tier, cohort and group.
        let scope = crate::federation::holding_claim::ClaimScope::of_content(
            provenance.tier,
            &provenance.cohort_scope,
            adopt_group(provenance, binding.as_ref()),
        )?;
        Some(
            crate::federation::holding_claim::sign_holding_claim(
                local,
                &sha256,
                uuid::Uuid::new_v4(),
                chrono::Utc::now(),
                envelope.len() as u64,
                &scope,
            )
            .await?,
        )
    } else {
        None
    };
    let sha256 = backend
        .adopt_sealed_blob_at(
            envelope.to_vec(),
            None,
            &provenance.cohort_scope,
            &provenance.author_key_id,
            floor,
            binding.clone(),
            adopt_group(provenance, binding.as_ref()),
            claim,
        )
        .await?;
    // #848 §13 (CIRISPersist#850 review) — the row now names its author:
    // project every content-axis `KeyGrant` set the AUTHOR signed that
    // arrived before the bytes — or, since v46.3.0 (#884), one of the
    // author's ACTIVE occurrences, the node that sealed the bytes. A set
    // signed by anyone else stays a stored attestation and grants nothing. Order independence is kept here, not
    // by projecting an unverifiable set at admission.
    let pending_wraps = crate::federation::key_grant::project_pending_content_grants(
        backend,
        &sha256,
        &provenance.cohort_scope,
        &provenance.author_key_id,
    )
    .await
    .map_err(|e| BlobError::Backend(format!("pending key_grant projection: {e}")))?;
    Ok(AdoptOutcome {
        sha256,
        announced: announce,
        pending_wraps,
    })
}

/// #846 (§6.2) — **adopt one received sealed chunk** at `(stream_id, seq)`.
/// The same shape / tier / WILL steps as [`adopt_sealed_blob`], then the
/// chunk floor with the AUTHOR as the stream's claimed owner (I50). Chunks
/// are not announced individually: the sealed manifest is adopted as a blob
/// like any other, and that is what federates.
#[allow(clippy::too_many_arguments)]
pub async fn adopt_sealed_chunk<B, F>(
    backend: &B,
    ctx: &HoldContext<'_, F>,
    stream_id: &str,
    seq: u64,
    envelope: &[u8],
    epoch: u64,
    plaintext_size: u64,
    provenance: &BlobProvenance,
) -> Result<[u8; 32], BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
    F: Fn(&str) -> bool,
{
    // #957 — one chunk is a batch of one: one door spelling.
    let mut out = adopt_sealed_chunks(
        backend,
        ctx,
        stream_id,
        &[AdoptChunkItem {
            seq,
            envelope,
            plaintext_size,
        }],
        epoch,
        provenance,
    )
    .await?;
    out.pop().expect("a batch of one answers with one result")
}

/// v52.0.0 (CIRISPersist#957) — one chunk of a batched adopt: its position,
/// the sealed envelope verbatim, and the plaintext length it carries.
#[derive(Debug, Clone, Copy)]
pub struct AdoptChunkItem<'a> {
    /// The chunk's position in the stream.
    pub seq: u64,
    /// The sealed chunk envelope, as received.
    pub envelope: &'a [u8],
    /// The plaintext length the envelope carries.
    pub plaintext_size: u64,
}

/// v55.0.0 (CIRISPersist#977) — **a stream-keyed room chunk is never bound
/// under a community epoch.** A `community_dek` chunk provenance that names
/// an epoch is the pre-v55 shape (a chunk sealed under the community DEK);
/// for a stream-keyed chunk the epoch is the manifest pointer's, carried over
/// by reusing the manifest's provenance, and binding it records the chunk
/// under a key that did not seal it: the positional read then opens it under
/// the community DEK and fails, and the community epoch counts it as one of
/// its objects. Refused wherever this node already knows `(stream_id,
/// epoch)` is stream-keyed: it holds that stream epoch's DEK row, or a wrap
/// of it addressed to this node or sealed by the chunk's author
/// (`key_grant:stream:v1`). Where it does not know yet (the chunk arrived
/// before the stream's key rows), the chunk lands bound and the promote,
/// which opens the manifest, refuses the DAG with the same token
/// (`promote_checks`): nothing is promoted or announced under a wrong
/// binding. Build the chunk's provenance with
/// [`BlobProvenance::for_stream_keyed_chunk`].
pub(crate) async fn refuse_community_epoch_on_a_stream_keyed_chunk<B>(
    backend: &B,
    our_key_id: &str,
    stream_id: &str,
    epoch: u64,
    provenance: &BlobProvenance,
) -> Result<(), BlobError>
where
    B: BlobStorage + Sync + ?Sized,
{
    let Some(named) = provenance.epoch else {
        return Ok(());
    };
    if provenance.tier != CryptoTier::CommunityDek {
        return Ok(());
    }
    let stream_keyed = backend
        .stream_dek_list(stream_id)
        .await?
        .iter()
        .any(|r| r.epoch == epoch)
        || !backend
            .stream_dek_grants_for_recipient(stream_id, epoch, our_key_id)
            .await?
            .is_empty()
        || !backend
            .stream_dek_grants(stream_id, epoch, &provenance.author_key_id)
            .await?
            .is_empty();
    if stream_keyed {
        return Err(BlobError::StreamKeyedChunkCommunityEpoch {
            stream_id: stream_id.to_owned(),
            epoch,
            community_epoch: named,
            chunk_sha256_hex: None,
        });
    }
    Ok(())
}

/// v52.0.0 (CIRISPersist#957) — **adopt a run of sealed chunks of one
/// stream**: [`adopt_sealed_chunk`]'s steps once per batch where they are
/// per-stream (the provenance's tier and binding, the WILL decision) and
/// once per item where they are per-chunk (the envelope's shape — never an
/// open, I45 — the floor, the pending content-set projection).
///
/// The outer `Err` refuses the whole batch with nothing written: the
/// provenance, `would_hold`, the batch bounds, or the stream's claim at the
/// floor. Otherwise each item answers in its slot, in order: a malformed
/// envelope, a seq conflict or the nonce cap refuses that item alone.
pub async fn adopt_sealed_chunks<B, F>(
    backend: &B,
    ctx: &HoldContext<'_, F>,
    stream_id: &str,
    items: &[AdoptChunkItem<'_>],
    epoch: u64,
    provenance: &BlobProvenance,
) -> Result<Vec<Result<[u8; 32], BlobError>>, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
    F: Fn(&str) -> bool,
{
    // Shape first, per item (I45: a structural check, not an open).
    let mut answers: Vec<Option<Result<[u8; 32], BlobError>>> = items
        .iter()
        .map(|i| check_envelope_shape(i.envelope).err().map(Err))
        .collect();
    let shaped: Vec<(usize, &AdoptChunkItem<'_>)> = items
        .iter()
        .enumerate()
        .filter(|(n, _)| answers[*n].is_none())
        .collect();
    if shaped.is_empty() {
        return Ok(answers.into_iter().map(|a| a.expect("answered")).collect());
    }
    // v55.0.0 (#977) — a stream-keyed ROOM chunk carries no community binding:
    // its key is the stream epoch's (`epoch` below), and its provenance names
    // the community and no community epoch. Only the chunk door reads it so;
    // a whole community blob still names its epoch.
    let (floor, binding) = if provenance.tier == CryptoTier::CommunityDek
        && provenance.epoch.is_none()
        && provenance.community_key_id.is_some()
    {
        let floor = StorageFloor::resolved(provenance.tier);
        floor.check_scope(&provenance.cohort_scope)?;
        (floor, None)
    } else {
        refuse_community_epoch_on_a_stream_keyed_chunk(
            backend,
            ctx.our_key_id,
            stream_id,
            epoch,
            provenance,
        )
        .await?;
        resolve_provenance(backend, ctx.our_key_id, provenance).await?
    };
    would_hold(backend, ctx, provenance).await?;
    let stored = backend
        .adopt_sealed_chunks_at(
            stream_id,
            shaped
                .iter()
                .map(|(_, i)| (i.seq, i.envelope.to_vec(), i.plaintext_size))
                .collect(),
            epoch,
            &provenance.cohort_scope,
            &provenance.author_key_id,
            floor,
            binding,
            // v55.0.0 (#977) — a room stream is the room's whether or not a
            // community epoch binds its chunks (the origin's claim names it);
            // a self/family stream's claim is unchanged.
            provenance
                .community_key_id
                .as_deref()
                .filter(|_| provenance.tier == CryptoTier::CommunityDek),
        )
        .await?;
    for ((slot, _), got) in shaped.iter().zip(stored) {
        if let Ok(sha256) = &got {
            // #848 §13 (PR #850 review, round three) — a self/family chunk
            // has its own DEK and its own content-axis set; the set that
            // arrived before the chunk projects here, exactly as for a blob.
            crate::federation::key_grant::project_pending_content_grants(
                backend,
                sha256,
                &provenance.cohort_scope,
                &provenance.author_key_id,
            )
            .await
            .map_err(|e| BlobError::Backend(format!("pending key_grant projection: {e}")))?;
        }
        answers[*slot] = Some(got);
    }
    Ok(answers.into_iter().map(|a| a.expect("answered")).collect())
}
