//! v46.0.0 (CIRISPersist#876, `FSD/EPOCH_MINTER.md`) — **who minted
//! `(community, epoch)`**, answered once for every door.
//!
//! `BLOB_REPLICATION.md` §11 ruled per-minter epochs and then said a blob's
//! key identity is `(community, author, epoch)` "because the author is
//! already on the row". Author and minter are two different questions: the
//! author attests the row, the minter's cascade holds the DEK. They
//! coincide only where a node authors its own content. A chat row is
//! authored by a PERSON and sealed by their NODE, so the adopt keyed the
//! binding by the person while the seal path and the `key_grant` set keyed
//! everything by the node — and every cross-node community body read
//! `NotGranted` with the viewer and its wrap both correct (#876).
//!
//! The bytes cannot arbitrate: an [`AtRestEnvelope`](super::at_rest_cascade::AtRestEnvelope)
//! is `magic ‖ nonce ‖ ciphertext`, carrying no key id. So the answer comes
//! from what the producer NAMED or from what this node has VERIFIED, in
//! that order, and never from a guess between two candidates.

use super::{BlobError, BlobStorage, FederationDirectory};

/// The empty string is not a key id; a caller that means "I do not know"
/// passes `None`.
fn check_named(minter_key_id: &str) -> Result<(), BlobError> {
    if minter_key_id.trim().is_empty() {
        return Err(BlobError::InvalidArgument(
            "minter_key_id: named but empty — an epoch belongs to its minter \
             (FSD/EPOCH_MINTER.md §2); pass None to have it derived"
                .into(),
        ));
    }
    Ok(())
}

/// **The one answer** (`FSD/EPOCH_MINTER.md` §2), in order:
///
/// 1. `named` — what the producer declared, when it declared one;
/// 2. the minter of the **one** admitted `key_grant` set that granted
///    `viewer_key_id` a wrap at `(community_key_id, epoch)`;
/// 3. `author_key_id` — the pre-v46 answer, correct wherever the author IS
///    the sealing engine, and kept so upgrading changes nothing a caller
///    depends on.
///
/// Two candidate sets means the multi-minter state #848 made the key
/// three-part for. Step 2 narrows — one candidate or several (#1271: a single
/// candidate is not exempt) — to the candidates that ARE the author
/// or act for it ([`principals_of`](super::self_collective::principals_of)
/// names the author): in a pair room every member node mints its own epoch
/// and wraps it to every member, the viewer's own node included, so the
/// viewer is granted by two minters and only one of them sealed for this
/// author. One survivor is the minter; none or several, and step 3 applies.
/// Never picks the first of several.
pub async fn resolve<B>(
    backend: &B,
    named: Option<&str>,
    community_key_id: &str,
    epoch: u64,
    viewer_key_id: &str,
    author_key_id: &str,
) -> Result<String, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync + ?Sized,
{
    if let Some(named) = named {
        check_named(named)?;
        return Ok(named.to_owned());
    }
    let candidates = backend
        .community_dek_minters_granting(community_key_id, epoch, viewer_key_id)
        .await?;
    // CIRISPersist#1271 — ONE candidate is filtered exactly as
    // several are. "The only minter granting this viewer" is not "the minter
    // of this author's epoch": in a room where the viewer was seated late,
    // the first grant to land can be ANOTHER member's epoch, and binding the
    // row to it pinned the bytes to a DEK that never sealed them — a
    // permanent `SealDidNotOpen` (Edge `seal_mismatch`) the stranded repair
    // could not reach, because that minter holds state. The author fallback
    // below is a STRANDED binding, which the repair and the read-side heal
    // both fix; a wrong binding to a stateful minter is fixed only by the heal.
    let mut sealers_for_author = Vec::new();
    for candidate in &candidates {
        if acts_for_author(backend, candidate, author_key_id).await? {
            sealers_for_author.push(candidate);
        }
    }
    if let [only] = sealers_for_author.as_slice() {
        return Ok((*only).clone());
    }
    Ok(author_key_id.to_owned())
}

/// CIRISPersist#1271 — **does `minter_key_id` seal for
/// `author_key_id`?** The minter IS the author, or names it among its
/// [`principals_of`](super::self_collective::principals_of). The one
/// predicate the derivation ([`resolve`]) and the repair
/// ([`rebind_stranded_for_authors`]) ask, so the two cannot disagree on
/// whose epoch a row belongs to.
pub(crate) async fn acts_for_author<B>(
    backend: &B,
    minter_key_id: &str,
    author_key_id: &str,
) -> Result<bool, BlobError>
where
    B: FederationDirectory + Sync + ?Sized,
{
    if minter_key_id == author_key_id {
        return Ok(true);
    }
    Ok(
        super::self_collective::principals_of(backend, minter_key_id)
            .await
            .map_err(|e| {
                BlobError::Backend(format!("epoch minter: principals of {minter_key_id}: {e}"))
            })?
            .iter()
            .any(|p| p == author_key_id),
    )
}

/// CIRISPersist#1271 (`FSD/EPOCH_MINTER.md` §3) — **the repair,
/// author-checked.** The body of
/// [`BlobStorage::rebind_stranded_blob_epochs`] on every backend: rebind a
/// STRANDED binding at `(community_key_id, epoch)` onto `minter_key_id` only
/// when that minter acts for THAT ROW's author ([`acts_for_author`]).
///
/// v46's repair rebound every stranded row at the community and epoch onto
/// whichever minter's set was admitted next. In a room each member node
/// mints its own epoch, so "a set at this epoch landed" says nothing about
/// whose bytes a row holds; the next set to land claimed rows another member
/// sealed. A row whose author is unknown (`None`: pre-V144, or the
/// signer-less commons door) is not rebound — nothing proves the minter's
/// claim to it — and stays for the read-side heal, where AEAD decides.
///
/// Each rebind is a compare-and-set on the row's recorded minter
/// ([`BlobStorage::rebind_blob_epoch_minter_cas`]), so a row another writer
/// re-pointed between the list and the update is left as that writer left
/// it. The stranded predicate itself is SQL on both backends
/// ([`BlobStorage::list_stranded_blob_epochs`]).
pub async fn rebind_stranded_for_authors<B>(
    backend: &B,
    community_key_id: &str,
    minter_key_id: &str,
    epoch: u64,
) -> Result<usize, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync + ?Sized,
{
    let mut rebound = 0usize;
    for (sha, recorded, author) in backend
        .list_stranded_blob_epochs(community_key_id, epoch)
        .await?
    {
        if recorded == minter_key_id {
            continue;
        }
        let Some(author) = author else { continue };
        if !acts_for_author(backend, minter_key_id, &author).await? {
            continue;
        }
        if backend
            .rebind_blob_epoch_minter_cas(&sha, &recorded, minter_key_id)
            .await?
        {
            rebound += 1;
        }
    }
    Ok(rebound)
}

/// **The seal side of the same question** (`FSD/EPOCH_MINTER.md` §2/§4).
/// The minter of an epoch this node is minting is the key that will sign
/// the `key_grant` set: the caller's named key, else this node's own key.
/// The adopt resolves the SAME property from the other end
/// ([`resolve`]); both go through this module so the two halves of
/// `(community, minter, epoch)` cannot be computed two ways.
pub fn for_seal<B>(backend: &B, named: Option<&str>) -> Result<String, BlobError>
where
    B: FederationDirectory + ?Sized,
{
    if let Some(a) = named {
        if !a.trim().is_empty() {
            return Ok(a.to_owned());
        }
    }
    backend.node_key_id().ok_or_else(|| {
        BlobError::InvalidArgument(
            "community DEK cascade: no minter — the write named no author and the backend \
             knows no node key. An epoch belongs to its minter (BLOB_REPLICATION.md §11); \
             pass the author's derived key id"
                .into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_named_minter_is_refused_by_member() {
        let e = check_named("   ").expect_err("empty is not a key id");
        assert!(e.to_string().contains("minter_key_id"), "{e}");
        check_named("node-a").expect("a real key id");
    }
}
