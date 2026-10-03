//! v52.0.0 (CIRISPersist#954; `FSD/BLOB_REPLICATION.md` §6.6,
//! `FSD/BLOB_ENCRYPTION_AT_REST.md` §12.12) — **a file is not capped by its
//! manifest, and an abandoned stream leaves nothing behind.**
//!
//! - **I202** (sqlite, postgres) — at a 4 KiB inline cap a 60-chunk `self`
//!   stream seals as a v3 root over v2 children (the v2 manifest would not
//!   fit: before #954 the seal refused it `InlineSizeExceeded`), reads whole,
//!   and reads by range inside a child, across a child boundary, and at the
//!   last byte. A 3-chunk stream at the same cap stays v2.
//! - **I203** (unit) — a manifest that fits is never partitioned; the v3 root's
//!   JCS bytes are pinned.
//! - **I204** (two nodes, sqlite and postgres) — the owner's other device
//!   pulls the v3 DAG through the planes: content sets, the root, each child
//!   (`adopt_sealed_manifest_child`), each page's chunks, promotion (refused
//!   while a child is missing, naming it), then the file whole and by range.
//! - **I205** (unit) — a child opens only at its own index of its own stream,
//!   and never as a chunk; the child AAD's bytes are pinned.
//! - **I206** (unit) — the v3 parser and `check_child` refuse: Σ size ≠
//!   total, overlapping runs, an empty root, a count mismatch, a child that is
//!   itself v3.
//! - **I207** (sqlite, postgres) — `abandon_stream`: another writer is
//!   refused, a sealed stream is refused, the counts are right, sealed chunk
//!   bytes are evicted, a plaintext chunk's bytes stay, the stream then
//!   refuses append and seal `stream_abandoned`, and a second call is
//!   `already`.
//! - **I208** — RESERVED, not built: the design withdrew each emitted content
//!   set so peers retire its grants, but CC 3 (a shared key cannot be
//!   retroactively un-shared) and the withdraws gate that enforces it refuse a
//!   `withdraws` naming a `key_grant` row. Abandon is a local cleanup; a set
//!   for bytes a peer never receives stays an inert pending row there.
//! - **I209** (sqlite, postgres) — a community stream's abandon evicts its
//!   chunks, and the epoch key survives for the community's other content.

pub(crate) mod bodies {
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Pick};
    use crate::federation::key_grant::{SignedKeyGrantSet, KEY_GRANT_CONTENT_ATTESTATION_TYPE};
    use crate::federation::key_grant_invariants::two_node::{introduce_as, Node};
    use crate::federation::self_collective_invariants::bodies::bind;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{self, CryptoTier};
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::types::EncryptionPubkeys;
    use crate::federation::{
        AdoptDisposition, BlobBody, BlobError, BlobProvenance, BlobStorage, FederationDirectory,
    };
    use std::sync::Arc;

    /// Shrink a backend's inline cap (each backend's inherent setter).
    pub(crate) type SetCap<B> = fn(&B, usize);

    /// The cap every body runs the nested manifest at.
    const CAP: usize = 4096;

    pub(crate) async fn kem_of<B: BlobStorage + Sync>(b: &B) -> EncryptionPubkeys {
        let id = b.load_or_init_content_kem_identity().await.unwrap();
        EncryptionPubkeys {
            x25519_base64: id.x25519_pubkey_b64,
            ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
        }
    }

    /// Two engines that know each other, one owner with BOTH devices bound
    /// on BOTH nodes (the I138 / I144 shape).
    pub(crate) struct Pair<B> {
        pub(crate) a: crate::Engine,
        pub(crate) b: crate::Engine,
        pub(crate) sa: Arc<B>,
        pub(crate) sb: Arc<B>,
        pub(crate) key_a: String,
        pub(crate) key_b: String,
        pub(crate) owner: String,
    }

    pub(crate) async fn pair<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
        tag: &str,
    ) -> Pair<B>
    where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let (alias_a, alias_b) = (format!("{tag}-a-{run}"), format!("{tag}-b-{run}"));
        let a = crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias_a), dsn_a)
            .await
            .unwrap();
        let b = crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias_b), dsn_b)
            .await
            .unwrap();
        for (e, alias) in [(&a, &alias_a), (&b, &alias_b)] {
            e.register_self_federation_key(NODE, alias, None, serde_json::json!({}), vec![])
                .await
                .unwrap();
        }
        let (sa, sb) = (pick(&a), pick(&b));
        let na = Node {
            backend: sa.as_ref(),
            signer: ts::local_signer(&alias_a),
            key: a.local_derived_key_id().await.unwrap(),
            kem: kem_of(sa.as_ref()).await,
        };
        let nb = Node {
            backend: sb.as_ref(),
            signer: ts::local_signer(&alias_b),
            key: b.local_derived_key_id().await.unwrap(),
            kem: kem_of(sb.as_ref()).await,
        };
        introduce_as(&[&na, &nb], &[&alias_a, &alias_b], NODE).await;
        let owner = format!("{tag}-owner-{run}");
        for n in [&na, &nb] {
            ts::register_hybrid_key_as(n.backend, &owner, &owner, USER).await;
            for dev in [&na, &nb] {
                bind(n.backend, &owner, &dev.key, Some(dev.kem.clone())).await;
                ts::put_owner_binding(n.backend, &owner, &dev.key).await;
            }
        }
        let (key_a, key_b) = (na.key.clone(), nb.key.clone());
        Pair {
            a,
            b,
            sa,
            sb,
            key_a,
            key_b,
            owner,
        }
    }

    fn segment(i: usize) -> Vec<u8> {
        (0..100 + (i % 7) * 13)
            .map(|j| (i * 31 + j) as u8)
            .collect()
    }

    /// Write `n` self chunks to `stream` on `e`; the plaintext.
    async fn write_self(e: &crate::Engine, owner: &str, stream: &str, n: usize) -> Vec<u8> {
        let mut plain = Vec::new();
        for i in 0..n {
            let seg = segment(i);
            e.put_blob_chunk_scoped(
                cohort_scope::SELF,
                Some(owner),
                stream,
                i as u64,
                &seg,
                0,
                None,
            )
            .await
            .unwrap_or_else(|err| panic!("chunk {i}: {err}"));
            plain.extend_from_slice(&seg);
        }
        plain
    }

    fn hexsha(h: &str) -> [u8; 32] {
        let mut sha = [0u8; 32];
        hex::decode_to_slice(h, &mut sha).unwrap();
        sha
    }

    pub(crate) async fn i202_a_file_is_not_capped_by_its_manifest<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
        set_cap: SetCap<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i202").await;
        set_cap(p.sa.as_ref(), CAP);
        let stream = format!("i202-{run}");
        let plain = write_self(&p.a, &p.owner, &stream, 60).await;
        let sealed =
            p.a.seal_stream_scoped(cohort_scope::SELF, Some(&p.owner), &stream, None, None)
                .await
                .expect("I202: a 60-chunk stream seals at a 4 KiB cap (v3)");
        let root = sealed.manifest_sha256;
        let view =
            p.a.open_sealed_manifest_as(&root, &p.key_a, None)
                .await
                .unwrap();
        assert_eq!(view.version, 3, "I202: the manifest is a nested root");
        assert!(view.chunks.is_empty(), "I202: a v3 view lists no chunks");
        assert!(view.children.len() >= 2, "I202: {:?}", view.children);
        // #969 — sixty chunks and the epoch's terminator.
        assert_eq!(view.children.iter().map(|c| c.chunk_count).sum::<u64>(), 61);
        assert_eq!(view.total_size, plain.len() as u64);
        assert_eq!(
            p.a.read_blob_as(&root, &p.key_a, None).await.unwrap(),
            plain,
            "I202: the file reads whole"
        );
        let b0 = view.children[0].size;
        for (s, e) in [
            (3, 40),
            (b0 - 5, b0 + 9),
            (plain.len() as u64 - 1, plain.len() as u64 - 1),
        ] {
            assert_eq!(
                p.a.read_blob_range_as(&root, &p.key_a, s, e, None)
                    .await
                    .unwrap_or_else(|err| panic!("I202: range {s}..={e}: {err}")),
                plain[s as usize..=e as usize].to_vec(),
                "I202: range {s}..={e}"
            );
        }
        // Every page opens and lists its run.
        let mut seqs = Vec::new();
        for c in &view.children {
            let page =
                p.a.open_sealed_manifest_page_as(&root, c.index, &p.key_a, None)
                    .await
                    .unwrap();
            assert_eq!(page.len() as u64, c.chunk_count);
            seqs.extend(page.iter().map(|x| x.seq));
        }
        let mut want: Vec<u64> = (0..60).collect();
        want.push(crate::federation::chunk_dag_cascade::orchestrate::TERMINATOR_SEQ_BASE);
        assert_eq!(seqs, want, "sixty chunks and persist's terminator position");
        // A stranger is refused at the root.
        assert!(matches!(
            p.a.open_sealed_manifest_page_as(&root, 0, &format!("i202-stranger-{run}"), None)
                .await,
            Err(BlobError::NotGranted { .. })
        ));
        // Below the cap: v2, unchanged.
        let small = format!("i202-small-{run}");
        write_self(&p.a, &p.owner, &small, 3).await;
        let s =
            p.a.seal_stream_scoped(cohort_scope::SELF, Some(&p.owner), &small, None, None)
                .await
                .unwrap();
        assert_eq!(
            p.a.open_sealed_manifest_as(&s.manifest_sha256, &p.key_a, None)
                .await
                .unwrap()
                .version,
            crate::federation::CHUNK_MANIFEST_VERSION_STREAM,
            "I202: a manifest that fits stays flat (v4 since #969: stream-keyed)"
        );
        // Eviction takes the children with the root.
        let kids = p.sa.manifest_children(&root).await.unwrap();
        assert_eq!(kids.len(), view.children.len());
        assert!(p.sa.delete_blob(&root).await.unwrap());
        for (_, k) in &kids {
            assert!(
                !p.sa.has_blob(k).await.unwrap(),
                "I202: a child outlived its root"
            );
        }
        assert!(p.sa.manifest_children(&root).await.unwrap().is_empty());
    }

    pub(crate) async fn i204_the_second_device_pulls_a_nested_dag<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
        set_cap: SetCap<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i204").await;
        set_cap(p.sa.as_ref(), CAP);
        let stream = format!("i204-{run}");
        let plain = write_self(&p.a, &p.owner, &stream, 60).await;
        let root =
            p.a.seal_stream_scoped(cohort_scope::SELF, Some(&p.owner), &stream, None, None)
                .await
                .unwrap()
                .manifest_sha256;
        p.a.emit_pending_key_grants().await.unwrap();
        for set in
            p.sa.list_attestations_by(&p.key_a)
                .await
                .unwrap()
                .into_iter()
                .filter(|x| {
                    x.attestation_type == KEY_GRANT_CONTENT_ATTESTATION_TYPE
                        || x.attestation_type
                            == crate::federation::key_grant::KEY_GRANT_STREAM_ATTESTATION_TYPE
                })
        {
            p.b.apply_replicated_key_grant(SignedKeyGrantSet { attestation: set })
                .await
                .expect("B applies A's set");
        }
        let prov = BlobProvenance {
            author_key_id: p.owner.clone(),
            cohort_scope: cohort_scope::SELF.to_owned(),
            community_key_id: None,
            epoch: None,
            tier: CryptoTier::InvisibleEncrypted,
            minter_key_id: Some(p.key_a.clone()),
        };
        let env = |sha: [u8; 32]| {
            let sa = p.sa.clone();
            async move {
                let Some(BlobBody::Inline(b)) = sa.get_blob(&sha).await.unwrap() else {
                    panic!("{} is inline on A", hex::encode(sha))
                };
                b
            }
        };
        // A child before its root is refused.
        let view_a =
            p.a.open_sealed_manifest_as(&root, &p.key_a, None)
                .await
                .unwrap();
        let c0 = hexsha(&view_a.children[0].sha256_hex);
        assert!(matches!(
            p.b.adopt_sealed_manifest_child(&root, 0, &env(c0).await, prov.clone())
                .await,
            Err(BlobError::NotHeld { .. })
        ));
        p.b.adopt_sealed_blob(
            &env(root).await,
            prov.clone(),
            None,
            AdoptDisposition::LocalOnly,
        )
        .await
        .expect("B adopts the root");
        let view =
            p.b.open_sealed_manifest_as(&root, &p.key_b, None)
                .await
                .expect("B opens the root");
        assert_eq!(view.version, 3);
        // The page of a child not yet held names the child.
        match p
            .b
            .open_sealed_manifest_page_as(&root, 0, &p.key_b, None)
            .await
        {
            Err(BlobError::NotHeld { sha256_hex }) => {
                assert_eq!(sha256_hex, view.children[0].sha256_hex)
            }
            other => panic!("I204: {other:?}"),
        }
        let mut pages = Vec::new();
        for (i, c) in view.children.iter().enumerate() {
            let got =
                p.b.adopt_sealed_manifest_child(
                    &root,
                    c.index,
                    &env(hexsha(&c.sha256_hex)).await,
                    prov.clone(),
                )
                .await
                .unwrap_or_else(|e| panic!("I204: B adopts child {i}: {e}"));
            assert_eq!(hex::encode(got), c.sha256_hex);
            pages.push(
                p.b.open_sealed_manifest_page_as(&root, c.index, &p.key_b, None)
                    .await
                    .unwrap_or_else(|e| panic!("I204: B opens page {i}: {e}")),
            );
            if i == 0 && view.children.len() > 1 {
                let e =
                    p.b.promote_adopted_manifest_to_dag(&root, &p.key_b, None)
                        .await
                        .expect_err("children missing");
                assert!(
                    matches!(&e, BlobError::InvalidArgument(m) if m.contains("child 1") && m.contains("not held")),
                    "{e:?}"
                );
            }
        }
        for c in pages.iter().flatten() {
            p.b.adopt_sealed_chunk(
                &stream,
                c.seq,
                &env(hexsha(&c.sha256_hex)).await,
                c.epoch.unwrap_or(0),
                u64::from(c.size),
                prov.clone(),
            )
            .await
            .unwrap_or_else(|e| panic!("I204: chunk {}: {e}", c.seq));
        }
        let promoted =
            p.b.promote_adopted_manifest_to_dag(&root, &p.key_b, None)
                .await
                .expect("I204: promoted");
        assert!(promoted.promoted);
        assert_eq!(
            promoted.chunk_count, 61,
            "sixty chunks and the terminator (#969)"
        );
        assert_eq!(
            p.b.read_blob_as(&root, &p.key_b, None).await.unwrap(),
            plain,
            "I204: the second device reads the file"
        );
        let b0 = view.children[0].size;
        assert_eq!(
            p.b.read_blob_range_as(&root, &p.key_b, b0 - 2, b0 + 2, None)
                .await
                .unwrap(),
            plain[b0 as usize - 2..=b0 as usize + 2].to_vec()
        );
    }

    pub(crate) async fn i207_abandon_stream<B>(dsn_a: &str, dsn_b: &str, run: &str, pick: Pick<B>)
    where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i207").await;
        let stream = format!("i207-{run}");
        write_self(&p.a, &p.owner, &stream, 3).await;
        let listing = p.sa.stream_chunks(&stream).await.unwrap();
        let shas: Vec<[u8; 32]> = listing.chunks.iter().map(|c| c.chunk_sha).collect();
        // Another writer is refused.
        let e =
            p.sa.abandon_stream_floor(&stream, "someone-else")
                .await
                .expect_err("not the owner");
        assert!(
            matches!(&e, BlobError::InvalidArgument(m) if m.contains("stream_not_owned")),
            "{e:?}"
        );
        // A sealed stream is refused.
        let sealed = format!("i207-sealed-{run}");
        write_self(&p.a, &p.owner, &sealed, 2).await;
        p.a.seal_stream_scoped(cohort_scope::SELF, Some(&p.owner), &sealed, None, None)
            .await
            .unwrap();
        let e = p.a.abandon_stream(&sealed).await.expect_err("sealed");
        assert!(
            matches!(&e, BlobError::InvalidArgument(m) if m.contains("stream_sealed")),
            "{e:?}"
        );
        // The owner abandons.
        p.a.emit_pending_key_grants().await.unwrap();
        let r = p.a.abandon_stream(&stream).await.expect("I207: abandoned");
        assert!(!r.already);
        assert_eq!(r.chunks_dropped, 3);
        assert!(r.bytes_evicted > 0);
        // CC 3 — the sets already emitted stay: no withdraws was written.
        assert!(
            !p.sa
                .list_attestations_by(&p.key_a)
                .await
                .unwrap()
                .iter()
                .any(
                    |x| x.attestation_type == crate::federation::types::attestation_type::WITHDRAWS
                ),
            "I207: abandon emitted a withdraws of a key_grant row (refused by CC 3)"
        );
        for s in &shas {
            assert!(
                !p.sa.has_blob(s).await.unwrap(),
                "I207: a sealed chunk outlived its abandoned stream"
            );
        }
        assert!(p.sa.stream_chunks(&stream).await.unwrap().chunks.is_empty());
        let e =
            p.a.put_blob_chunk_scoped(
                cohort_scope::SELF,
                Some(&p.owner),
                &stream,
                3,
                b"late",
                0,
                None,
            )
            .await
            .expect_err("append after abandon");
        assert!(
            matches!(&e, BlobError::InvalidArgument(m) if m.contains("stream_abandoned")),
            "{e:?}"
        );
        let e =
            p.a.seal_stream_scoped(cohort_scope::SELF, Some(&p.owner), &stream, None, None)
                .await
                .expect_err("seal after abandon");
        assert!(
            matches!(&e, BlobError::InvalidArgument(m) if m.contains("stream_abandoned") || m.contains("no chunks")),
            "{e:?}"
        );
        let again = p.a.abandon_stream(&stream).await.unwrap();
        assert!(again.already && again.chunks_dropped == 0);
        // A plaintext (commons) chunk's bytes stay: content-addressed, shareable.
        let commons = format!("i207-commons-{run}");
        let r =
            p.a.put_blob_chunk_scoped(
                cohort_scope::FEDERATION,
                None,
                &commons,
                0,
                format!("shared {run}").as_bytes(),
                0,
                None,
            )
            .await
            .unwrap();
        let r2 = p.a.abandon_stream(&commons).await.unwrap();
        assert_eq!((r2.chunks_dropped, r2.bytes_evicted), (1, 0));
        assert!(
            p.sa.has_blob(&r.chunk_sha256).await.unwrap(),
            "I207: a plaintext chunk's bytes were evicted"
        );
    }

    pub(crate) async fn i209_a_community_abandon_evicts_its_chunks<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let stream = format!("i209-{run}");
        let mut shas = Vec::new();
        for i in 0..2u64 {
            shas.push(
                l.engine_a
                    .put_blob_chunk_scoped(
                        cohort_scope::COMMUNITY,
                        Some(&l.comm),
                        &stream,
                        i,
                        &segment(i as usize),
                        0,
                        None,
                    )
                    .await
                    .unwrap()
                    .chunk_sha256,
            );
        }
        let r = l.engine_a.abandon_stream(&stream).await.unwrap();
        assert_eq!(r.chunks_dropped, 2);
        // The epoch the chunks were sealed under still opens the community's
        // other content: an abandon never touches the epoch plane.
        let kept = l
            .engine_a
            .put_blob_scoped(
                cohort_scope::COMMUNITY,
                Some(&l.comm),
                format!("i209 kept {run}").as_bytes(),
                None,
                None,
            )
            .await
            .unwrap();
        assert!(l
            .engine_a
            .read_blob_as(&kept.at_rest_sha256, &l.node_a, None)
            .await
            .is_ok());
        for s in &shas {
            assert!(!l.ba.has_blob(s).await.unwrap(), "I209: evicted");
        }
    }
}

#[cfg(test)]
mod unit {
    use crate::federation::blobs::{
        ChunkManifest, ChunkRef, ManifestChildRef, NestedManifest, ParsedManifest,
        CHUNK_MANIFEST_VERSION_SEALED,
    };
    use crate::federation::chunk_dag_cascade::orchestrate::plan_children;
    use crate::federation::chunk_dag_cascade::{chunk_aad, manifest_child_aad};
    use crate::federation::types::cohort_scope::CryptoTier;

    fn flat(n: u64) -> ChunkManifest {
        let chunks: Vec<ChunkRef> = (0..n)
            .map(|i| ChunkRef {
                sha: [i as u8; 32],
                size: 100,
                seq: Some(i),
                epoch: None,
            })
            .collect();
        ChunkManifest {
            v: CHUNK_MANIFEST_VERSION_SEALED,
            total_size: 100 * n,
            chunks,
            chunk_tier: Some(CryptoTier::InvisibleEncrypted),
            stream_id: Some("s".into()),
        }
    }

    /// I203 — a manifest that fits is never partitioned; one that does not is
    /// partitioned into children that each fit, covering every chunk in order.
    #[test]
    fn i203_a_manifest_that_fits_stays_flat() {
        assert!(plan_children(&flat(3), 1 << 20).unwrap().is_none());
        assert!(plan_children(&flat(3), 4096).unwrap().is_none());
        let kids = plan_children(&flat(60), 4096)
            .unwrap()
            .expect("partitioned");
        assert!(kids.len() >= 2);
        let budget = 4096 - crate::federation::at_rest_cascade::AT_REST_ENVELOPE_OVERHEAD;
        for k in &kids {
            assert!(k.to_jcs_bytes().len() <= budget, "a child exceeds the cap");
            k.validate_total_size().unwrap();
        }
        let seqs: Vec<u64> = kids
            .iter()
            .flat_map(|k| k.chunks.iter().map(|c| c.seq.unwrap()))
            .collect();
        assert_eq!(seqs, (0..60).collect::<Vec<_>>());
        // A plaintext manifest is never partitioned.
        let mut plain = flat(60);
        plain.v = 1;
        plain.chunk_tier = None;
        plain.stream_id = None;
        for c in &mut plain.chunks {
            c.seq = None;
        }
        assert!(plan_children(&plain, 4096).unwrap().is_none());
    }

    fn root() -> NestedManifest {
        NestedManifest {
            total_size: 300,
            chunk_tier: CryptoTier::InvisibleEncrypted,
            stream_id: "s".into(),
            children: vec![
                ManifestChildRef {
                    chunk_count: 2,
                    first_seq: 0,
                    last_seq: 1,
                    sha: [0xaa; 32],
                    size: 200,
                },
                ManifestChildRef {
                    chunk_count: 1,
                    first_seq: 2,
                    last_seq: 2,
                    sha: [0xbb; 32],
                    size: 100,
                },
            ],
        }
    }

    /// I203 — the v3 root's JCS bytes are pinned, and round-trip.
    #[test]
    fn i203_the_v3_root_jcs_is_pinned() {
        let r = root();
        let jcs = String::from_utf8(r.to_jcs_bytes()).unwrap();
        assert_eq!(
            jcs,
            format!(
                "{{\"children\":[{{\"chunk_count\":2,\"first_seq\":0,\"last_seq\":1,\"sha\":\"{}\",\"size\":200}},{{\"chunk_count\":1,\"first_seq\":2,\"last_seq\":2,\"sha\":\"{}\",\"size\":100}}],\"chunk_tier\":\"invisible_encrypted\",\"stream_id\":\"s\",\"total_size\":300,\"v\":3}}",
                "aa".repeat(32),
                "bb".repeat(32)
            )
        );
        assert_eq!(
            ParsedManifest::parse(jcs.as_bytes()).unwrap(),
            ParsedManifest::Nested(r)
        );
        // A flat parser refuses v3 by name.
        let e = ChunkManifest::from_manifest_bytes(jcs.as_bytes()).unwrap_err();
        assert!(format!("{e}").contains("nested root"), "{e}");
    }

    /// I205 — a child's AAD is its index in its stream, under its own domain:
    /// distinct from a chunk's at the same position, from another index, from
    /// another stream. The bytes are pinned.
    #[test]
    fn i205_a_child_opens_only_at_its_own_position() {
        use crate::federation::at_rest_cascade::{fresh_dek, open, seal};
        let dek = fresh_dek().unwrap();
        let env = seal(&dek, b"child", Some(&manifest_child_aad(None, "s", 1))).unwrap();
        assert_eq!(
            open(&dek, &env, Some(&manifest_child_aad(None, "s", 1))).unwrap(),
            b"child"
        );
        for wrong in [
            manifest_child_aad(None, "s", 0),
            manifest_child_aad(None, "t", 1),
            chunk_aad(None, "s", 1),
        ] {
            assert!(
                open(&dek, &env, Some(&wrong)).is_err(),
                "I205: a child opened at another position"
            );
        }
        let mut want = b"ciris-persist:manifest-child:v1".to_vec();
        want.extend_from_slice(&0u64.to_be_bytes());
        want.extend_from_slice(&1u64.to_be_bytes());
        want.extend_from_slice(b"s");
        want.extend_from_slice(&7u64.to_be_bytes());
        assert_eq!(manifest_child_aad(None, "s", 7), want);
    }

    /// I206 — the v3 parser and `check_child` refuse every malformed shape.
    #[test]
    fn i206_the_nested_parser_refuses() {
        let bad = |f: &dyn Fn(&mut NestedManifest)| {
            let mut r = root();
            f(&mut r);
            NestedManifest::from_manifest_bytes(&r.to_jcs_bytes()).is_err()
        };
        assert!(bad(&|r| r.total_size = 301), "Σ size ≠ total");
        assert!(bad(&|r| r.children[1].first_seq = 1), "overlapping runs");
        assert!(bad(&|r| r.children.clear()), "no children");
        assert!(bad(&|r| r.children[0].chunk_count = 0), "an empty child");
        assert!(
            bad(&|r| {
                r.children[0].first_seq = 1;
                r.children[0].last_seq = 0;
            }),
            "a reversed run"
        );
        let r = root();
        let child = |n: u64, first: u64, size: u32| ChunkManifest {
            v: CHUNK_MANIFEST_VERSION_SEALED,
            total_size: u64::from(size) * n,
            chunks: (0..n)
                .map(|i| ChunkRef {
                    sha: [1; 32],
                    size,
                    seq: Some(first + i),
                    epoch: None,
                })
                .collect(),
            chunk_tier: Some(CryptoTier::InvisibleEncrypted),
            stream_id: Some("s".into()),
        };
        r.check_child(0, &child(2, 0, 100)).unwrap();
        assert!(
            r.check_child(0, &child(1, 0, 200)).is_err(),
            "count mismatch"
        );
        assert!(r.check_child(0, &child(2, 1, 100)).is_err(), "run mismatch");
        assert!(r.check_child(0, &child(2, 0, 99)).is_err(), "size mismatch");
        let mut other = child(2, 0, 100);
        other.stream_id = Some("t".into());
        assert!(r.check_child(0, &other).is_err(), "another stream");
        // A v3 child is refused by the flat parser that opens children.
        assert!(ChunkManifest::from_manifest_bytes(&r.to_jcs_bytes()).is_err());
        // Ranges pick children by prefix sum.
        assert_eq!(r.children_for_range(0, 99), vec![(0, 0, 99)]);
        assert_eq!(
            r.children_for_range(195, 204),
            vec![(0, 195, 199), (1, 0, 4)]
        );
        assert_eq!(r.children_for_range(299, 299), vec![(1, 99, 99)]);
    }
}

#[cfg(test)]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }
    macro_rules! runners {
        ($modname:ident, $dsns:expr, $pick:expr, $cap:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i202() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i202_a_file_is_not_capped_by_its_manifest(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                        $cap,
                    )
                    .await
                }
                #[tokio::test]
                async fn i204() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i204_the_second_device_pulls_a_nested_dag(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                        $cap,
                    )
                    .await
                }
                #[tokio::test]
                async fn i207() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i207_abandon_stream(&a, &b, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i209() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i209_a_community_abandon_evicts_its_chunks(
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
            as crate::federation::epoch_minter_invariants::bodies::Pick<
                crate::store::sqlite::SqliteBackend,
            >,
        (|b: &crate::store::sqlite::SqliteBackend, cap: usize| b.set_inline_bytes_cap(cap))
            as crate::federation::nested_manifest_invariants::bodies::SetCap<
                crate::store::sqlite::SqliteBackend,
            >
    );
    #[cfg(feature = "postgres")]
    runners!(
        postgres,
        (|| Some((crate::test_pg::empty_dsn()?, crate::test_pg::empty_dsn()?)))(),
        (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
            as crate::federation::epoch_minter_invariants::bodies::Pick<
                crate::store::postgres::PostgresBackend,
            >,
        (|b: &crate::store::postgres::PostgresBackend, cap: usize| b.set_inline_bytes_cap(cap))
            as crate::federation::nested_manifest_invariants::bodies::SetCap<
                crate::store::postgres::PostgresBackend,
            >
    );
}
