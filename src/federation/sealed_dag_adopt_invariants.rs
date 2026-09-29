//! v51.3.0 (CIRISPersist#947; CIRISEdge#717) — **a second device reads a
//! sealed chunk-DAG as the file, not as its manifest.**
//!
//! - **I144** (two nodes, sqlite and postgres) — A seals a three-chunk `self`
//!   stream; B, the owner's other device, receives the content sets, adopts
//!   the manifest as received (an inline envelope — the shape v50/v51 left it
//!   in, pinned: the read returns the manifest JSON), opens the chunk list,
//!   is refused promotion while a chunk is missing, adopts every chunk at the
//!   manifest's `(stream_id, seq)`, promotes, and reads the file whole and by
//!   range. A stranger cannot open the list; promotion is idempotent.
//! - **I145** (one node, sqlite and postgres) — `put_blob_chunks_signing`
//!   stores a plaintext DAG and announces its manifest: the pulled commons
//!   DAG is a holder by name.

pub(crate) mod bodies {
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Pick};
    use crate::federation::key_grant::SignedKeyGrantSet;
    use crate::federation::key_grant_invariants::two_node::{introduce_as, Node};
    use crate::federation::self_collective_invariants::bodies::bind;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{self, CryptoTier};
    use crate::federation::types::identity_type::USER;
    use crate::federation::types::EncryptionPubkeys;
    use crate::federation::{
        AdoptDisposition, BlobBody, BlobError, BlobProvenance, BlobStorage, ChunkManifest,
        ChunkRef, FederationDirectory,
    };

    async fn kem_of<B: BlobStorage + Sync>(b: &B) -> EncryptionPubkeys {
        let id = b.load_or_init_content_kem_identity().await.unwrap();
        EncryptionPubkeys {
            x25519_base64: id.x25519_pubkey_b64,
            ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
        }
    }

    pub(crate) async fn i144_a_second_device_reads_a_sealed_dag_as_the_file<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        // The I138 shape (the proven "second device opens" path): two engines
        // that know each other, one owner with BOTH devices bound (occurrence
        // + owner binding) on BOTH nodes before the write, so A's cascade wraps
        // every chunk and the manifest to B and B admits A's content sets.
        let (alias_a, alias_b) = (format!("sd-a-{run}"), format!("sd-b-{run}"));
        let engine_a = crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias_a), dsn_a)
            .await
            .unwrap();
        let engine_b = crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias_b), dsn_b)
            .await
            .unwrap();
        for (e, alias) in [(&engine_a, &alias_a), (&engine_b, &alias_b)] {
            e.register_self_federation_key(
                crate::federation::types::identity_type::NODE,
                alias,
                None,
                serde_json::json!({}),
                vec![],
            )
            .await
            .unwrap();
        }
        let (sa, sb) = (pick(&engine_a), pick(&engine_b));
        let a = Node {
            backend: sa.as_ref(),
            signer: ts::local_signer(&alias_a),
            key: engine_a.local_derived_key_id().await.unwrap(),
            kem: kem_of(sa.as_ref()).await,
        };
        let b = Node {
            backend: sb.as_ref(),
            signer: ts::local_signer(&alias_b),
            key: engine_b.local_derived_key_id().await.unwrap(),
            kem: kem_of(sb.as_ref()).await,
        };
        introduce_as(
            &[&a, &b],
            &[&alias_a, &alias_b],
            crate::federation::types::identity_type::NODE,
        )
        .await;
        let owner = format!("i144-owner-{run}");
        for n in [&a, &b] {
            ts::register_hybrid_key_as(n.backend, &owner, &owner, USER).await;
            for dev in [&a, &b] {
                bind(n.backend, &owner, &dev.key, Some(dev.kem.clone())).await;
                ts::put_owner_binding(n.backend, &owner, &dev.key).await;
            }
        }

        // Two single-chunk streams beside the main one, for the negative
        // cases: a chunk adopted at the right position with the WRONG sha
        // (s2), and with the wrong plaintext size (s3).
        let (s2, s3) = (format!("i144-s2-{run}"), format!("i144-s3-{run}"));
        for (sid, seg) in [(&s2, vec![5u8; 300]), (&s3, vec![6u8; 250])] {
            engine_a
                .put_blob_chunk_scoped(cohort_scope::SELF, Some(&owner), sid, 0, &seg, 0, None)
                .await
                .unwrap();
        }
        let m2 = engine_a
            .seal_stream_scoped(cohort_scope::SELF, Some(&owner), &s2, None, None)
            .await
            .unwrap()
            .manifest_sha256;
        let m3 = engine_a
            .seal_stream_scoped(cohort_scope::SELF, Some(&owner), &s3, None, None)
            .await
            .unwrap()
            .manifest_sha256;

        // A: a three-chunk self stream, sealed.
        let stream = format!("i144-stream-{run}");
        let segs: [Vec<u8>; 3] = [vec![1u8; 700], vec![2u8; 900], vec![3u8; 400]];
        for (i, seg) in segs.iter().enumerate() {
            engine_a
                .put_blob_chunk_scoped(
                    cohort_scope::SELF,
                    Some(&owner),
                    &stream,
                    i as u64,
                    seg,
                    0,
                    None,
                )
                .await
                .unwrap_or_else(|e| panic!("A: chunk {i}: {e}"));
        }
        let sealed = engine_a
            .seal_stream_scoped(
                cohort_scope::SELF,
                Some(&owner),
                &stream,
                Some("video/mp4"),
                None,
            )
            .await
            .expect("A seals");
        assert_eq!(sealed.tier, CryptoTier::InvisibleEncrypted);
        let manifest = sealed.manifest_sha256;
        let plain: Vec<u8> = segs.concat();
        assert_eq!(
            engine_a
                .read_blob_as(&manifest, &a.key, None)
                .await
                .unwrap(),
            plain,
            "A reads its own DAG whole"
        );
        // The content sets A's node emitted, carried to B.
        engine_a.emit_pending_key_grants().await.unwrap();
        let sets: Vec<_> = sa
            .list_attestations_by(&a.key)
            .await
            .unwrap()
            .into_iter()
            .filter(|x| {
                x.attestation_type
                    == crate::federation::key_grant::KEY_GRANT_CONTENT_ATTESTATION_TYPE
            })
            .collect();
        assert!(
            sets.len() >= 4,
            "a set per chunk and one for the manifest: {}",
            sets.len()
        );
        for a in &sets {
            engine_b
                .apply_replicated_key_grant(SignedKeyGrantSet {
                    attestation: a.clone(),
                })
                .await
                .expect("B applies A's set");
        }
        let prov = BlobProvenance {
            author_key_id: owner.clone(),
            cohort_scope: cohort_scope::SELF.to_owned(),
            community_key_id: None,
            epoch: None,
            tier: CryptoTier::InvisibleEncrypted,
            minter_key_id: Some(a.key.clone()),
        };
        // B adopts the manifest AS RECEIVED: an inline envelope.
        let Some(BlobBody::Inline(menv)) = sa.get_blob(&manifest).await.unwrap() else {
            panic!("the sealed manifest is an inline envelope on A")
        };
        engine_b
            .adopt_sealed_blob(&menv, prov.clone(), None, AdoptDisposition::LocalOnly)
            .await
            .expect("B adopts the manifest");
        // THE DEFECT, pinned: before promotion B serves the manifest JSON as the file.
        let served = engine_b
            .read_blob_as(&manifest, &b.key, None)
            .await
            .expect("B opens what it holds");
        assert_ne!(
            served, plain,
            "#947: the adopted manifest read back as the file"
        );
        assert!(
            served.starts_with(b"{"),
            "#947: what B served was the manifest JSON: {:?}",
            String::from_utf8_lossy(&served[..served.len().min(40)])
        );
        // A stranger cannot open the chunk list.
        let stranger = format!("i144-stranger-{run}");
        assert!(
            matches!(
                engine_b
                    .open_sealed_manifest_as(&manifest, &stranger, None)
                    .await,
                Err(BlobError::NotGranted { .. })
            ),
            "a stranger is NotGranted on the chunk list"
        );
        // B opens the chunk list.
        let view = engine_b
            .open_sealed_manifest_as(&manifest, &b.key, None)
            .await
            .expect("B opens the chunk list");
        assert_eq!(view.storage_kind, "inline");
        assert_eq!(view.stream_id, stream);
        assert_eq!(view.total_size, plain.len() as u64);
        assert_eq!(view.chunks.len(), 3);
        assert_eq!(
            view.chunks.iter().map(|c| c.seq).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(view.chunks[1].size, 900);
        // Promotion before the chunks are held is refused, naming the first missing one.
        let e = engine_b
            .promote_adopted_manifest_to_dag(&manifest, &b.key, None)
            .await
            .expect_err("no chunk held yet");
        assert!(
            matches!(&e, BlobError::InvalidArgument(m) if m.contains("seq 0") && m.contains("not held")),
            "{e:?}"
        );
        // The negative cases on s2 / s3 (their manifests adopted the same way).
        for m in [&m2, &m3] {
            let Some(BlobBody::Inline(env)) = sa.get_blob(m).await.unwrap() else {
                panic!("inline")
            };
            engine_b
                .adopt_sealed_blob(&env, prov.clone(), None, AdoptDisposition::LocalOnly)
                .await
                .unwrap();
        }
        let v2 = engine_b
            .open_sealed_manifest_as(&m2, &b.key, None)
            .await
            .unwrap();
        let v3 = engine_b
            .open_sealed_manifest_as(&m3, &b.key, None)
            .await
            .unwrap();
        let chunk_env = |sha_hex: &str| {
            let mut sha = [0u8; 32];
            hex::decode_to_slice(sha_hex, &mut sha).unwrap();
            let sa = sa.clone();
            async move {
                let Some(BlobBody::Inline(env)) = sa.get_blob(&sha).await.unwrap() else {
                    panic!("chunk inline")
                };
                env
            }
        };
        // s2: s3's chunk adopted at s2's seq 0 — held, but not the sha the manifest names
        let wrong = chunk_env(&v3.chunks[0].sha256_hex).await;
        engine_b
            .adopt_sealed_chunk(
                &v2.stream_id,
                0,
                &wrong,
                0,
                u64::from(v3.chunks[0].size),
                prov.clone(),
            )
            .await
            .unwrap();
        let e = engine_b
            .promote_adopted_manifest_to_dag(&m2, &b.key, None)
            .await
            .expect_err("the wrong chunk at the right position");
        assert!(
            matches!(&e, BlobError::InvalidArgument(m) if m.contains("held as") && m.contains("manifest names")),
            "{e:?}"
        );
        // s3: the right chunk with the wrong plaintext size is refused at the
        // ADOPT (the chunk floor checks the declared size against the length
        // the envelope carries, §12.3), so the promotion's size check behind
        // it is defence in depth; then the right size adopts and a
        // single-chunk manifest promotes.
        let right = chunk_env(&v3.chunks[0].sha256_hex).await;
        let e = engine_b
            .adopt_sealed_chunk(
                &v3.stream_id,
                0,
                &right,
                0,
                u64::from(v3.chunks[0].size) + 1,
                prov.clone(),
            )
            .await
            .expect_err("the wrong plaintext size is refused at the adopt");
        assert!(
            matches!(&e, BlobError::InvalidArgument(m) if m.contains("plaintext_size")),
            "{e:?}"
        );
        engine_b
            .adopt_sealed_chunk(
                &v3.stream_id,
                0,
                &right,
                0,
                u64::from(v3.chunks[0].size),
                prov.clone(),
            )
            .await
            .unwrap();
        assert!(
            engine_b
                .promote_adopted_manifest_to_dag(&m3, &b.key, None)
                .await
                .unwrap()
                .promoted
        );
        assert_eq!(
            engine_b.read_blob_as(&m3, &b.key, None).await.unwrap(),
            vec![6u8; 250],
            "a single-chunk DAG reads whole after promotion"
        );
        assert_eq!(
            engine_b
                .open_sealed_manifest_as(&m2, &b.key, None)
                .await
                .unwrap()
                .storage_kind,
            "inline",
            "nothing was written on a refused promotion"
        );
        // B fetches each chunk by sha and adopts it at the manifest's (stream_id, seq).
        for c in &view.chunks {
            let mut sha = [0u8; 32];
            hex::decode_to_slice(&c.sha256_hex, &mut sha).unwrap();
            let Some(BlobBody::Inline(cenv)) = sa.get_blob(&sha).await.unwrap() else {
                panic!("chunk {} inline on A", c.sha256_hex)
            };
            let got = engine_b
                .adopt_sealed_chunk(
                    &view.stream_id,
                    c.seq,
                    &cenv,
                    0,
                    u64::from(c.size),
                    prov.clone(),
                )
                .await
                .unwrap_or_else(|e| panic!("B adopts chunk {}: {e}", c.seq));
            assert_eq!(got, sha);
            if c.seq == 0 {
                // one chunk held, two missing: still refused, naming seq 1
                let e = engine_b
                    .promote_adopted_manifest_to_dag(&manifest, &b.key, None)
                    .await
                    .expect_err("two chunks missing");
                assert!(
                    matches!(&e, BlobError::InvalidArgument(m) if m.contains("seq 1")),
                    "{e:?}"
                );
            }
        }
        let p = engine_b
            .promote_adopted_manifest_to_dag(&manifest, &b.key, None)
            .await
            .expect("every chunk held: promoted");
        assert!(p.promoted);
        assert_eq!(p.chunk_count, 3);
        assert_eq!(p.total_size, plain.len() as u64);
        // Now B reads the FILE, whole and by range, across a chunk boundary.
        assert_eq!(
            engine_b
                .read_blob_as(&manifest, &b.key, None)
                .await
                .unwrap(),
            plain,
            "I144: after promotion the second device reads the file"
        );
        assert_eq!(
            engine_b
                .read_blob_range_as(&manifest, &b.key, 690, 720, None)
                .await
                .unwrap(),
            plain[690..=720].to_vec()
        );
        assert_eq!(
            engine_b
                .open_sealed_manifest_as(&manifest, &b.key, None)
                .await
                .unwrap()
                .storage_kind,
            "chunk_dag"
        );
        // Idempotent.
        let again = engine_b
            .promote_adopted_manifest_to_dag(&manifest, &b.key, None)
            .await
            .unwrap();
        assert!(!again.promoted);
        // The stranger still reads nothing.
        assert!(matches!(
            engine_b.read_blob_as(&manifest, &stranger, None).await,
            Err(BlobError::NotGranted { .. })
        ));
    }

    pub(crate) async fn i145_a_pulled_commons_dag_is_a_holder_by_name<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use sha2::Digest as _;
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let author = format!("i145-author-{run}");
        ts::register_hybrid_key_as(l.ba.as_ref(), &author, &author, USER).await;
        let segs: [Vec<u8>; 2] = [vec![7u8; 500], vec![9u8; 300]];
        let chunks: Vec<([u8; 32], BlobBody)> = segs
            .iter()
            .map(|s| (sha2::Sha256::digest(s).into(), BlobBody::Inline(s.clone())))
            .collect();
        let manifest = ChunkManifest {
            v: crate::federation::blobs::CHUNK_MANIFEST_VERSION,
            total_size: 800,
            chunks: chunks
                .iter()
                .zip(segs.iter())
                .map(|((sha, _), s)| ChunkRef {
                    sha: *sha,
                    size: s.len() as u32,
                    seq: None,
                })
                .collect(),
            chunk_tier: None,
            stream_id: None,
        };
        let sha = l
            .engine_a
            .put_blob_chunks_signing(manifest, chunks, &author)
            .await
            .expect("stored and announced");
        assert_eq!(
            l.engine_a.read_blob_as(&sha, "", None).await.unwrap(),
            segs.concat(),
            "the plaintext DAG reads whole"
        );
        let holders = l.ba.list_holders(&sha).await.unwrap();
        assert!(
            holders.contains(&l.node_a),
            "I145: this node announced the manifest: {holders:?}"
        );
        assert!(
            matches!(
                l.engine_a
                    .open_sealed_manifest_as(&sha, &l.node_a, None)
                    .await,
                Err(BlobError::InvalidArgument(_))
            ),
            "a plaintext DAG is not opened as sealed"
        );
    }
}

#[cfg(test)]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }
    macro_rules! runners {
        ($modname:ident, $dsns:expr, $pick:expr) => {
            mod $modname {
                use super::super::bodies;
                use crate::federation::epoch_minter_invariants::bodies::Pick;
                #[tokio::test]
                async fn i144() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i144_a_second_device_reads_a_sealed_dag_as_the_file(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                    )
                    .await
                }
                #[tokio::test]
                async fn i145() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i145_a_pulled_commons_dag_is_a_holder_by_name(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                    )
                    .await
                }
            }
        };
    }
    #[cfg(feature = "sqlite")]
    runners!(
        sqlite,
        Some(("sqlite::memory:".to_owned(), "sqlite::memory:".to_owned())),
        (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
            as Pick<crate::store::sqlite::SqliteBackend>
    );
    #[cfg(feature = "postgres")]
    runners!(
        postgres,
        (|| Some((crate::test_pg::empty_dsn()?, crate::test_pg::empty_dsn()?)))(),
        (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
            as Pick<crate::store::postgres::PostgresBackend>
    );
}
