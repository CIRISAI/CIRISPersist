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
use crate::federation::types::cohort_scope::{self as cs, CryptoTier};
use crate::federation::{BlobError, BlobStorage, EpochBinding, FederationDirectory, StorageFloor};

/// #846 (§4, §6.1) — Edge's `admit_blob_store` trichotomy, minus `Refuse`
/// (a refusal never reaches this door). Carried, not re-derived: persist
/// does not second-guess the MAY decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptDisposition {
    /// Store and emit `holds_bytes` signed by this node, carrying the
    /// cleartext provenance CC 3.2 requires.
    Announce,
    /// Store; emit nothing.
    LocalOnly,
}

/// #846 (§6.1) — what an adopt returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptOutcome {
    /// The address: SHA-256 of the ciphertext as stored.
    pub sha256: [u8; 32],
    /// Whether a `holds_bytes` claim was emitted.
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
fn resolve_adopt(
    envelope: &[u8],
    provenance: &BlobProvenance,
) -> Result<(StorageFloor, Option<EpochBinding>), BlobError> {
    AtRestEnvelope::from_bytes(envelope).map_err(|e| {
        BlobError::InvalidArgument(format!(
            "adopt: the bytes do not have the at-rest envelope shape ({e}); an adopt stores \
             sealed bytes verbatim and nothing else"
        ))
    })?;
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
            Some(EpochBinding {
                community_key_id: community.to_owned(),
                // #848 (§11) — the AUTHOR is the minter; `BlobProvenance`
                // needs no new field: its `author_key_id` IS the epoch's
                // minter, because the author's cascade minted the epoch the
                // blob is sealed under.
                minter_key_id: provenance.author_key_id.clone(),
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

/// #846 (§6.1) — **adopt a received sealed blob.** See the module doc for
/// the order; `ctx` is the Engine's hold context (pressure, local-or-family,
/// this node's key), and `signer` signs the holder claim when `disposition`
/// is [`AdoptDisposition::Announce`].
///
/// A `self` / `family` provenance can never announce (CC 5.2 — no holder
/// claim is ever emitted for structurally invisible content); it is refused
/// before the floor (I52).
#[allow(clippy::too_many_arguments)]
pub async fn adopt_sealed_blob<B, F>(
    backend: &B,
    signer: &dyn ciris_keyring::HardwareSigner,
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
    let (floor, binding) = resolve_adopt(envelope, provenance)?;
    let announce = disposition == AdoptDisposition::Announce;
    if announce && cs::suppresses_holds_bytes(&provenance.cohort_scope) {
        return Err(BlobError::InvalidArgument(format!(
            "adopt: {:?} content is structurally invisible — no holds_bytes claim is ever \
             emitted for it (CC 5.2); adopt it LocalOnly",
            provenance.cohort_scope
        )));
    }
    would_hold(backend, ctx, provenance).await?;
    let claim = if announce {
        use sha2::Digest as _;
        let sha256: [u8; 32] = sha2::Sha256::digest(envelope).into();
        // The HOLDER claims (I23): attested and signed by this node's
        // derived key, never the author's.
        Some(
            crate::federation::blobs::sign_holds_bytes_claim(
                signer,
                &sha256,
                ctx.our_key_id,
                uuid::Uuid::new_v4(),
                chrono::Utc::now(),
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
            binding,
            claim,
        )
        .await?;
    // #848 §13 (CIRISPersist#850 review) — the row now names its author:
    // project every content-axis `KeyGrant` set the AUTHOR signed that
    // arrived before the bytes. A set signed by anyone else stays a stored
    // attestation and grants nothing. Order independence is kept here, not
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
    let (floor, binding) = resolve_adopt(envelope, provenance)?;
    would_hold(backend, ctx, provenance).await?;
    backend
        .adopt_sealed_chunk_at(
            stream_id,
            seq,
            envelope.to_vec(),
            epoch,
            plaintext_size,
            &provenance.cohort_scope,
            &provenance.author_key_id,
            floor,
            binding,
        )
        .await
}
