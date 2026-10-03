//! v53.0.0 (CIRISEdge#763) — **repair after eviction, and the custody report
//! under the data a DAG was sealed with.**
//!
//! - **I415c** (sqlite, postgres) — a chunk DAG sealed under associated data
//!   (an edge file pointer's `content_aad`) files `here` when the report
//!   names that data; with none, or other data, it is refused
//!   `custody_ack_here_seal_did_not_open` — never filed as a whole blob.
//! - **I415d** (two nodes, sqlite and postgres) — chunk repair: node B holds
//!   a promoted DAG, evicts chunk 1, and re-adopting the IDENTICAL `(seq,
//!   chunk_sha)` brings it back at its position; the DAG reads whole.
//! - **I415e** (same body) — a DIFFERENT sha at a held position is still
//!   refused, and stores nothing.
//! - **I415f** (two nodes, sqlite and postgres) — whole-file repair: B evicts
//!   the manifest and every chunk; the manifest's at-rest grant survives the
//!   eviction (a grant is a key-plane fact), and after B re-fetches the bytes
//!   it reads whole with NO key_grant set applied again.
//!
//! A tombstone never deleted a grant (the I67 gate pins the only grant-delete
//! sites: `delete_blob` until v53, the epoch destruction sweep, an abandoned
//! stream). I149 witnesses that a member HOLDING the grant is refused
//! `Withdrawn` on a withdrawn blob, so a grant kept across an eviction cannot
//! reopen a tombstoned one.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::custody_ack::CustodyState;
    use crate::federation::epoch_minter_invariants::bodies::Pick;
    use crate::federation::key_grant::SignedKeyGrantSet;
    use crate::federation::nested_manifest_invariants::bodies::{pair, Pair};
    use crate::federation::types::cohort_scope::{self, CryptoTier};
    use crate::federation::{
        AdoptDisposition, BlobBody, BlobError, BlobProvenance, BlobStorage, FederationDirectory,
    };

    fn segment(i: usize) -> Vec<u8> {
        (0..48 + (i % 3) * 13).map(|j| (i * 29 + j) as u8).collect()
    }

    async fn inline<B: BlobStorage + Sync>(b: &B, sha: &[u8; 32]) -> Vec<u8> {
        let Some(BlobBody::Inline(v)) = b.get_blob(sha).await.unwrap() else {
            panic!("{} is inline", hex::encode(sha))
        };
        v
    }

    fn hexsha(h: &str) -> [u8; 32] {
        let mut sha = [0u8; 32];
        hex::decode_to_slice(h, &mut sha).unwrap();
        sha
    }

    /// A `self` stream of `n` chunks on A under `aad`, sealed; returns the
    /// plaintext and the manifest's address.
    async fn write_and_seal<B>(
        p: &Pair<B>,
        stream: &str,
        n: usize,
        aad: Option<&[u8]>,
    ) -> (Vec<u8>, [u8; 32])
    where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let mut plain = Vec::new();
        for i in 0..n {
            let seg = segment(i);
            p.a.put_blob_chunk_scoped(
                cohort_scope::SELF,
                Some(&p.owner),
                stream,
                i as u64,
                &seg,
                0,
                aad,
            )
            .await
            .unwrap_or_else(|e| panic!("chunk {i}: {e}"));
            plain.extend_from_slice(&seg);
        }
        let root =
            p.a.seal_stream_scoped(cohort_scope::SELF, Some(&p.owner), stream, None, aad)
                .await
                .unwrap_or_else(|e| panic!("seal {stream}: {e}"))
                .manifest_sha256;
        (plain, root)
    }

    fn prov<B>(p: &Pair<B>) -> BlobProvenance {
        BlobProvenance {
            author_key_id: p.owner.clone(),
            cohort_scope: cohort_scope::SELF.to_owned(),
            community_key_id: None,
            epoch: None,
            tier: CryptoTier::InvisibleEncrypted,
            minter_key_id: Some(p.key_a.clone()),
        }
    }

    /// B receives A's DAG the way a host delivers it: A's key_grant sets,
    /// the sealed manifest, every chunk at its position, then the promote.
    /// Returns the chunks as `(seq, sha, envelope, epoch, size)`.
    async fn deliver<B>(
        p: &Pair<B>,
        stream: &str,
        root: &[u8; 32],
    ) -> Vec<(u64, [u8; 32], Vec<u8>, u64, u64)>
    where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        p.a.emit_pending_key_grants().await.unwrap();
        for set in
            p.sa.list_attestations_by(&p.key_a)
                .await
                .unwrap()
                .into_iter()
                .filter(|x| x.attestation_type.starts_with("key_grant:"))
        {
            p.b.apply_replicated_key_grant(SignedKeyGrantSet { attestation: set })
                .await
                .expect("B applies A's set");
        }
        p.b.adopt_sealed_blob(
            &inline(p.sa.as_ref(), root).await,
            prov(p),
            None,
            AdoptDisposition::LocalOnly,
        )
        .await
        .expect("B adopts the manifest");
        let view =
            p.b.open_sealed_manifest_as(root, &p.key_b, None)
                .await
                .expect("B opens the manifest");
        let mut out = Vec::new();
        for c in &view.chunks {
            let sha = hexsha(&c.sha256_hex);
            let env = inline(p.sa.as_ref(), &sha).await;
            let epoch = c.epoch.expect("a v4 chunk names its epoch");
            p.b.adopt_sealed_chunk(stream, c.seq, &env, epoch, u64::from(c.size), prov(p))
                .await
                .unwrap_or_else(|e| panic!("chunk {}: {e}", c.seq));
            out.push((c.seq, sha, env, epoch, u64::from(c.size)));
        }
        p.b.promote_adopted_manifest_to_dag(root, &p.key_b, None)
            .await
            .expect("B promotes");
        out
    }

    /// **I415c** — the custody report opens the manifest under the data the
    /// DAG was sealed with.
    pub(crate) async fn i415c_here_opens_under_the_sealed_data<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i415c").await;
        let aad = b"alice\n2026-10-02T00:00:00Z\ncontent".to_vec();
        let (_, root) = write_and_seal(&p, &format!("i415c-{run}"), 3, Some(&aad)).await;
        for (label, given) in [
            ("no data", None),
            (
                "other data",
                Some(b"not what it was sealed under".as_slice()),
            ),
        ] {
            let r =
                p.a.put_custody_ack(&root, CustodyState::Here, None, None, given)
                    .await;
            assert!(
                r.as_ref()
                    .is_err_and(|e| e.to_string().contains("custody_ack_here_seal_did_not_open")),
                "I415c `here` under {label} is refused by name, never filed as a whole blob: {r:?}"
            );
        }
        p.a.put_custody_ack(&root, CustodyState::Here, None, None, Some(&aad))
            .await
            .expect("I415c `here` under the data the DAG was sealed with is filed");
    }

    /// **I415d / I415e** — chunk repair at a held position.
    pub(crate) async fn i415d_e_a_lost_chunk_is_re_adopted_at_its_position<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i415d").await;
        let stream = format!("i415d-{run}");
        let (plain, root) = write_and_seal(&p, &stream, 4, None).await;
        let chunks = deliver(&p, &stream, &root).await;
        assert_eq!(
            p.b.read_blob_as(&root, &p.key_b, None).await.unwrap(),
            plain,
            "I415d control: B reads the delivered DAG"
        );
        let (seq, sha, env, epoch, size) =
            chunks.iter().find(|c| c.0 == 1).cloned().expect("chunk 1");
        assert!(
            p.sb.delete_blob(&sha).await.unwrap(),
            "I415d chunk 1 is evicted on B"
        );
        assert!(
            p.b.read_blob_as(&root, &p.key_b, None).await.is_err(),
            "I415d with chunk 1 gone the DAG does not read"
        );
        // I415e first, while the position is held and its bytes are gone: a
        // DIFFERENT sha at seq 1 is refused and stores nothing.
        let (_, other_sha, other_env, _, other_size) =
            chunks.iter().find(|c| c.0 == 2).cloned().expect("chunk 2");
        let r =
            p.b.adopt_sealed_chunk(&stream, 1, &other_env, epoch, other_size, prov(&p))
                .await;
        assert!(
            matches!(&r, Err(BlobError::InvalidArgument(m)) if m.contains("already exists")),
            "I415e a different sha at a held position is refused: {r:?}"
        );
        assert!(
            p.sb.blob_head(&sha).await.unwrap().is_none(),
            "I415e the refusal stored nothing: chunk 1's bytes are still absent (and {} did \
             not take its place)",
            hex::encode(other_sha)
        );
        // I415d — the identical chunk comes back at its position.
        let got =
            p.b.adopt_sealed_chunk(&stream, seq, &env, epoch, size, prov(&p))
                .await
                .expect("I415d re-adopting the identical (seq, chunk_sha) is admitted");
        assert_eq!(got, sha, "I415d the same chunk, by its address");
        assert!(p.sb.blob_head(&sha).await.unwrap().is_some());
        assert_eq!(
            p.b.read_blob_as(&root, &p.key_b, None).await.unwrap(),
            plain,
            "I415d the repaired DAG reads whole"
        );
        // Idempotent while held, too.
        assert_eq!(
            p.b.adopt_sealed_chunk(&stream, seq, &env, epoch, size, prov(&p))
                .await
                .expect("I415d a second identical re-adopt is admitted"),
            sha
        );
    }

    /// **I415f** — whole-file repair: the grant survives the eviction.
    pub(crate) async fn i415f_a_lost_file_reads_again_without_a_new_set<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i415f").await;
        let stream = format!("i415f-{run}");
        let (plain, root) = write_and_seal(&p, &stream, 3, None).await;
        let chunks = deliver(&p, &stream, &root).await;
        assert_eq!(
            p.b.read_blob_as(&root, &p.key_b, None).await.unwrap(),
            plain,
            "I415f control: B reads the delivered DAG"
        );
        let manifest_env = inline(p.sb.as_ref(), &root).await;
        let granted_before = p.sb.get_at_rest_grant(&root, &p.key_b).await.unwrap();
        assert!(
            granted_before.is_some(),
            "I415f precondition: B holds the manifest's at-rest grant"
        );
        // Evict the whole file on B: the manifest and every chunk.
        assert!(p.sb.delete_blob(&root).await.unwrap());
        for (_, sha, _, _, _) in &chunks {
            assert!(p.sb.delete_blob(sha).await.unwrap());
        }
        assert!(
            p.sb.get_at_rest_grant(&root, &p.key_b)
                .await
                .unwrap()
                .is_some(),
            "I415f an eviction removes bytes, not the key-plane grant"
        );
        // Re-fetch: the manifest and the chunks, no key_grant set re-applied.
        p.b.adopt_sealed_blob(&manifest_env, prov(&p), None, AdoptDisposition::LocalOnly)
            .await
            .expect("I415f B re-adopts the manifest");
        for (seq, _, env, epoch, size) in &chunks {
            p.b.adopt_sealed_chunk(&stream, *seq, env, *epoch, *size, prov(&p))
                .await
                .unwrap_or_else(|e| panic!("I415f re-adopt chunk {seq}: {e}"));
        }
        p.b.promote_adopted_manifest_to_dag(&root, &p.key_b, None)
            .await
            .expect("I415f B promotes the re-fetched manifest");
        assert_eq!(
            p.b.read_blob_as(&root, &p.key_b, None).await.unwrap(),
            plain,
            "I415f the re-fetched file reads whole with the grant B already held"
        );
    }
}

#[cfg(test)]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! pair_case {
        ($name:ident, $body:ident) => {
            mod $name {
                #[cfg(feature = "sqlite")]
                #[tokio::test]
                async fn sqlite() {
                    super::super::bodies::$body(
                        "sqlite::memory:",
                        "sqlite::memory:",
                        &super::suffix(),
                        (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
                            as crate::federation::epoch_minter_invariants::bodies::Pick<
                                crate::store::sqlite::SqliteBackend,
                            >,
                    )
                    .await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test]
                async fn postgres() {
                    let (Some(a), Some(b)) =
                        (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn())
                    else {
                        return;
                    };
                    super::super::bodies::$body(
                        &a,
                        &b,
                        &super::suffix(),
                        (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
                            as crate::federation::epoch_minter_invariants::bodies::Pick<
                                crate::store::postgres::PostgresBackend,
                            >,
                    )
                    .await;
                }
            }
        };
    }

    pair_case!(i415c, i415c_here_opens_under_the_sealed_data);
    pair_case!(i415d_e, i415d_e_a_lost_chunk_is_re_adopted_at_its_position);
    pair_case!(i415f, i415f_a_lost_file_reads_again_without_a_new_set);
}
