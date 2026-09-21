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
/// three-part for: step 2 declines, step 3 applies, and naming the minter
/// is the only way through. Never picks the first of several.
pub async fn resolve<B>(
    backend: &B,
    named: Option<&str>,
    community_key_id: &str,
    epoch: u64,
    viewer_key_id: &str,
    author_key_id: &str,
) -> Result<String, BlobError>
where
    B: BlobStorage + Sync + ?Sized,
{
    if let Some(named) = named {
        check_named(named)?;
        return Ok(named.to_owned());
    }
    let candidates = backend
        .community_dek_minters_granting(community_key_id, epoch, viewer_key_id)
        .await?;
    if let [only] = candidates.as_slice() {
        return Ok(only.clone());
    }
    Ok(author_key_id.to_owned())
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
