//! `FSD/BLOB_ENCRYPTION_AT_REST.md` §12 — **chunked content under the
//! envelope** (CIRISPersist#832).
//!
//! The witnesses live here first; the doors follow.

/// §12.7 — the falsifiable invariants, one `exercise_*` body per row,
/// registered in BOTH `store::sqlite` and `store::postgres` tests.
#[cfg(any(test, feature = "test-anchor"))]
#[allow(dead_code)]
pub mod invariants {
    use crate::federation::blobs::BlobBody;
    use crate::federation::{BlobError, BlobStorage, FederationDirectory};

    fn sha(bytes: &[u8]) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(bytes).into()
    }

    // ── I32 (commons half) ───────────────────────────────────────────────
    /// **A seal door checks the chunk ROWS: a DAG whose chunks are not all
    /// at the DAG's tier is refused.** The commons `seal_stream` is a seal
    /// door too — it writes a `chunk_dag` row at `plaintext` — so a stream
    /// carrying a community-sealed chunk row must be refused by it.
    ///
    /// Staged through doors that exist today: the community cascade stores a
    /// sealed row; `put_blob_chunk` of the same bytes indexes that EXISTING
    /// row into a stream (the blob insert is `ON CONFLICT DO NOTHING`, so
    /// the row keeps its `community_dek` tier). Before #832 the commons seal
    /// happily wrote a public manifest over it.
    pub async fn exercise_i32_commons_seal_refuses_a_sealed_chunk_row<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
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
            Some(crate::federation::types::cohort_scope::CryptoTier::CommunityDek),
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

    // ── I35 (commons half) ───────────────────────────────────────────────
    /// **The read door returns a DAG's CONTENT, not its manifest.** A commons
    /// DAG read through `read_any_for_viewer` is the concatenated bytes, so a
    /// consumer never has to know whether a sha names a whole blob or a DAG.
    /// Before #832 the door refused every `chunk_dag` row.
    pub async fn exercise_i35_whole_read_of_a_dag_is_its_content<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer;
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
        let got = read_any_for_viewer(backend, &manifest_sha, &format!("{tag}-anyone-{run}"))
            .await
            .unwrap_or_else(|e| {
                panic!("{tag} I35: the read door refused a commons DAG instead of returning its content: {e}")
            });
        assert_eq!(got, want, "{tag} I35: the DAG's content, in chunk order");
        let _ = sha(&want);
    }
}
