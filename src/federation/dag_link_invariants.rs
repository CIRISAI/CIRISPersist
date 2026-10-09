//! v53.1.0 (CIRISPersist#979, CC 2.3; CIRISEdge#771, #766) — **a chunk of a
//! withdrawn file is judged by its file.** Referencing rows bind a DAG's
//! manifest, never its chunks; V176 relates a sealed manifest to its chunks,
//! written by persist when the manifest becomes a DAG on a node (the seal, or
//! the promote of an adopted manifest), so the fold, the serve door and the
//! eviction can reach the chunks.
//!
//! Every body runs on two nodes (sqlite and postgres; the memory backend has
//! no blob storage): A writes and seals a `self` stream, B adopts and promotes
//! it the way a host delivers it — Edge's leg.
//!
//! - **I480** — the seal relates A's manifest to every chunk, terminator
//!   included; `chunks_of_manifest` / `dag_contains_chunk` answer from it.
//! - **I481** — B's promote writes the same relation; nothing is opened by
//!   the lookups.
//! - **I482** — the owner withdraws the file on B: every chunk (terminator
//!   included) and the manifest are refused at B's peer-serve door and read
//!   door; before the withdraw they served.
//! - **I483** — B evicts the withdrawn manifest: every chunk's bytes go with
//!   it (`dag_chunks_evicted`), the relation rows stay, and an unrelated live
//!   DAG on B is untouched.
//! - **I484** — a chunk two DAGs hold stays live and served while either is
//!   live, is withdrawn only when both are, and the eviction of the first
//!   leaves it.
//! - **I485** — a referencing row that names the stream (an author-asserted
//!   pointer member) cannot revive a withdrawn DAG's chunks.
//! - **I486** — a DAG with no relation (from before V176) behaves as before:
//!   its chunks read Unbound and serve.
//! - **I487** — a re-promote by a viewer relates such a DAG (the backfill).
//! - **I576** (v54.0.0, #994) — the boot/operator sweep relates every
//!   pre-V176 DAG this node can open, exactly its chunks; a DAG whose stream
//!   moved is skipped, never mis-linked; a DAG sealed under a viewer's
//!   associated data is skipped as unopenable; the pass is idempotent.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::blob_tombstone::{binding_state, BindingState};
    use crate::federation::epoch_minter_invariants::bodies::Pick;
    use crate::federation::key_grant::SignedKeyGrantSet;
    use crate::federation::nested_manifest_invariants::bodies::{pair, Pair};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type;
    use crate::federation::types::cohort_scope::{self, CryptoTier};
    use crate::federation::{
        AdoptDisposition, BlobBody, BlobError, BlobProvenance, BlobStorage, FederationDirectory,
        SignedAttestation,
    };

    /// The test seam that edits V176 rows directly (see each backend's
    /// `test_dag_link`).
    pub(crate) trait LinkSeam {
        async fn dag_link(&self, manifest: &[u8; 32], add: Option<(u64, [u8; 32], &str)>);
        async fn drop_stream_row(&self, stream_id: &str, seq: u64);
    }
    #[cfg(feature = "sqlite")]
    impl LinkSeam for crate::store::sqlite::SqliteBackend {
        async fn dag_link(&self, manifest: &[u8; 32], add: Option<(u64, [u8; 32], &str)>) {
            self.test_dag_link(manifest, add).await
        }
        async fn drop_stream_row(&self, stream_id: &str, seq: u64) {
            self.test_drop_stream_chunk_row(stream_id, seq).await
        }
    }
    #[cfg(feature = "postgres")]
    impl LinkSeam for crate::store::postgres::PostgresBackend {
        async fn dag_link(&self, manifest: &[u8; 32], add: Option<(u64, [u8; 32], &str)>) {
            self.test_dag_link(manifest, add).await
        }
        async fn drop_stream_row(&self, stream_id: &str, seq: u64) {
            self.test_drop_stream_chunk_row(stream_id, seq).await
        }
    }

    fn segment(i: usize) -> Vec<u8> {
        (0..40 + (i % 3) * 11).map(|j| (i * 37 + j) as u8).collect()
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

    /// A `self` stream of `n` chunks on A, sealed; the manifest's address.
    async fn write_and_seal<B>(p: &Pair<B>, stream: &str, n: usize) -> [u8; 32]
    where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        for i in 0..n {
            p.a.put_blob_chunk_scoped(
                cohort_scope::SELF,
                Some(&p.owner),
                stream,
                i as u64,
                &segment(i),
                0,
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("chunk {i}: {e}"));
        }
        p.a.seal_stream_scoped(cohort_scope::SELF, Some(&p.owner), stream, None, None)
            .await
            .unwrap_or_else(|e| panic!("seal {stream}: {e}"))
            .manifest_sha256
    }

    /// B receives A's DAG the way a host delivers it — A's key_grant sets, the
    /// sealed manifest, every chunk at its position, the promote. Returns the
    /// chunk addresses in seq order (terminator last).
    async fn deliver<B>(p: &Pair<B>, stream: &str, root: &[u8; 32]) -> Vec<(u64, [u8; 32])>
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
            // A set B already applied answers as a duplicate; the delivery is
            // what matters, not the count.
            let _ =
                p.b.apply_replicated_key_grant(SignedKeyGrantSet { attestation: set })
                    .await;
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
            out.push((c.seq, sha));
        }
        p.b.promote_adopted_manifest_to_dag(root, &p.key_b, None)
            .await
            .expect("B promotes");
        out.sort_by_key(|(seq, _)| *seq);
        out
    }

    /// The owner's federation-tier `file:v1` row binding `root`, on `b`;
    /// optionally a pointer member naming `stream` too (I485's forgery
    /// shape). Returns the row id.
    async fn bind<B>(b: &B, id: &str, owner: &str, sha_hex: &str, stream: Option<&str>) -> String
    where
        B: FederationDirectory + Sync,
    {
        let mut env = serde_json::json!({
            "id": id, "dimension": "file:v1", "cohort_scope": "federation",
            "evidence_refs": [sha_hex]
        });
        if let Some(s) = stream {
            env["content"] = serde_json::json!({
                "content_sha256": sha_hex, "community_key_id": "",
                "tier": "invisible_encrypted", "stream_id": s
            });
        }
        let mut row = ts::bare_attestation(id, owner, owner, &env);
        row.attestation_type = attestation_type::SCORES.into();
        row.cohort_scope = "federation".into();
        row.subject_key_ids = vec![owner.to_owned()];
        ts::seal_row_in_place(owner, &mut row);
        b.put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap_or_else(|e| panic!("bind {id}: {e}"));
        id.to_owned()
    }

    async fn withdraw<B>(b: &B, id: &str, owner: &str, target: &str)
    where
        B: FederationDirectory + Sync,
    {
        let env = serde_json::json!({
            "references_attestation_id": target, "withdrawal_reason": "CC 2.3",
        });
        let mut w = ts::bare_attestation(id, owner, owner, &env);
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.cohort_scope = "federation".into();
        ts::seal_row_in_place(owner, &mut w);
        b.put_attestation(SignedAttestation { attestation: w })
            .await
            .unwrap_or_else(|e| panic!("withdraw {id}: {e}"));
    }

    fn withdrawn(s: &BindingState) -> bool {
        matches!(s, BindingState::Withdrawn { .. })
    }

    async fn served<B: Sync>(p: &Pair<B>, sha: &[u8; 32]) -> Result<(), BlobError> {
        p.b.serve_blob_to_peer(sha, &p.key_a).await.map(|_| ())
    }

    /// **I480 / I481** — the relation at the seal and at the promote.
    pub(crate) async fn i480_481_the_relation_is_written_by_persist<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i480").await;
        let stream = format!("i480-{run}");
        let root = write_and_seal(&p, &stream, 3).await;
        let on_a = p.a.chunks_of_manifest(&root).await.unwrap();
        let listing = p.sa.stream_chunks(&stream).await.unwrap();
        assert_eq!(
            on_a,
            listing
                .chunks
                .iter()
                .map(|c| (c.seq, c.chunk_sha))
                .collect::<Vec<_>>(),
            "I480 the seal relates the manifest to every chunk of its stream"
        );
        assert_eq!(
            on_a.len(),
            4,
            "I480 three chunks and the epoch's terminator"
        );
        assert!(
            on_a.last().unwrap().0 >= 1 << 62,
            "I480 the terminator is related too (seq 2^62 + epoch)"
        );
        for (_, c) in &on_a {
            assert!(p.a.dag_contains_chunk(&root, c).await.unwrap());
        }
        let other = write_and_seal(&p, &format!("i480-other-{run}"), 1).await;
        assert!(
            !p.a.dag_contains_chunk(&other, &on_a[0].1).await.unwrap(),
            "I480 a chunk is not in a DAG it does not belong to"
        );
        assert!(
            p.a.chunks_of_manifest(&on_a[0].1).await.unwrap().is_empty(),
            "I480 a chunk is no manifest: no relation"
        );

        let on_b = deliver(&p, &stream, &root).await;
        assert_eq!(
            p.b.chunks_of_manifest(&root).await.unwrap(),
            on_b,
            "I481 B's promote relates the adopted manifest to every chunk it checked"
        );
        assert_eq!(on_b, on_a, "I481 the same relation on both nodes");
    }

    /// **I482 / I483** — Edge's leg: withdraw on B, then serve and evict.
    pub(crate) async fn i482_483_a_withdrawn_file_takes_its_chunks<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i482").await;
        let stream = format!("i482-{run}");
        let root = write_and_seal(&p, &stream, 3).await;
        let chunks = deliver(&p, &stream, &root).await;
        let keep_stream = format!("i482-keep-{run}");
        let keep = write_and_seal(&p, &keep_stream, 2).await;
        let keep_chunks = deliver(&p, &keep_stream, &keep).await;
        let row = bind(
            p.sb.as_ref(),
            &format!("i482-file-{run}"),
            &p.owner,
            &hex::encode(root),
            None,
        )
        .await;
        bind(
            p.sb.as_ref(),
            &format!("i482-keep-{run}"),
            &p.owner,
            &hex::encode(keep),
            None,
        )
        .await;
        for (seq, c) in &chunks {
            served(&p, c)
                .await
                .unwrap_or_else(|e| panic!("I482 control: chunk {seq} serves while live: {e}"));
        }
        withdraw(p.sb.as_ref(), &format!("i482-w-{run}"), &p.owner, &row).await;
        assert!(withdrawn(
            &binding_state(p.sb.as_ref(), &root).await.unwrap()
        ));
        for (seq, c) in &chunks {
            assert!(
                withdrawn(&binding_state(p.sb.as_ref(), c).await.unwrap()),
                "I482 chunk {seq} folds Withdrawn by its file"
            );
            let r = served(&p, c).await;
            assert!(
                matches!(r, Err(BlobError::Withdrawn { .. })),
                "I482 B's peer-serve door refuses chunk {seq}: {r:?}"
            );
            let r = p.b.read_blob_as(c, &p.key_b, None).await;
            assert!(
                matches!(r, Err(BlobError::Withdrawn { .. })),
                "I482 B's read door refuses chunk {seq}: {r:?}"
            );
        }
        assert!(matches!(
            served(&p, &root).await,
            Err(BlobError::Withdrawn { .. })
        ));
        for (_, c) in &keep_chunks {
            served(&p, c)
                .await
                .expect("I482 an unrelated live DAG still serves");
        }

        let rep = p.b.evict_blob(&root, chrono::Utc::now()).await.unwrap();
        assert!(rep.blob_deleted, "I483 the manifest's bytes go");
        assert_eq!(
            rep.dag_chunks_evicted,
            chunks.len(),
            "I483 every chunk, terminator included, goes with it"
        );
        for (seq, c) in &chunks {
            assert!(
                !p.sb.has_blob(c).await.unwrap(),
                "I483 chunk {seq} is gone from B"
            );
        }
        assert_eq!(
            p.b.chunks_of_manifest(&root).await.unwrap(),
            chunks,
            "I483 the relation stays (structure, as the at-rest grants are)"
        );
        for (_, c) in &keep_chunks {
            assert!(
                p.sb.has_blob(c).await.unwrap(),
                "I483 the live DAG is untouched"
            );
        }
        assert!(p.sb.has_blob(&keep).await.unwrap());
    }

    /// **I484** — a chunk two DAGs hold.
    pub(crate) async fn i484_a_shared_chunk_needs_both_withdrawn<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + LinkSeam + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i484").await;
        let (s1, s2) = (format!("i484-1-{run}"), format!("i484-2-{run}"));
        let m1 = write_and_seal(&p, &s1, 2).await;
        let m2 = write_and_seal(&p, &s2, 2).await;
        let c1 = deliver(&p, &s1, &m1).await;
        deliver(&p, &s2, &m2).await;
        // Two real seals never share a chunk (each encrypts its own bytes);
        // the seam relates chunk 0 of m1 to m2 as well.
        let (seq, shared) = c1[0];
        p.sb.dag_link(&m2, Some((1_000 + seq, shared, &s2))).await;
        let r1 = bind(
            p.sb.as_ref(),
            &format!("i484-r1-{run}"),
            &p.owner,
            &hex::encode(m1),
            None,
        )
        .await;
        let r2 = bind(
            p.sb.as_ref(),
            &format!("i484-r2-{run}"),
            &p.owner,
            &hex::encode(m2),
            None,
        )
        .await;
        withdraw(p.sb.as_ref(), &format!("i484-w1-{run}"), &p.owner, &r1).await;
        assert_eq!(
            binding_state(p.sb.as_ref(), &shared).await.unwrap(),
            BindingState::Live,
            "I484 one of its DAGs is live: the shared chunk is live"
        );
        served(&p, &shared).await.expect("I484 and it serves");
        assert!(
            withdrawn(&binding_state(p.sb.as_ref(), &c1[1].1).await.unwrap()),
            "I484 m1's own chunk is withdrawn"
        );
        let rep = p.b.evict_blob(&m1, chrono::Utc::now()).await.unwrap();
        assert_eq!(
            rep.dag_chunks_evicted,
            c1.len() - 1,
            "I484 all of m1's chunks but the shared one"
        );
        assert!(
            p.sb.has_blob(&shared).await.unwrap(),
            "I484 the shared chunk stays"
        );
        withdraw(p.sb.as_ref(), &format!("i484-w2-{run}"), &p.owner, &r2).await;
        assert!(
            withdrawn(&binding_state(p.sb.as_ref(), &shared).await.unwrap()),
            "I484 both withdrawn: the shared chunk is withdrawn"
        );
    }

    /// **I485** — an author-asserted pointer naming the stream revives nothing.
    pub(crate) async fn i485_a_forged_pointer_revives_nothing<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i485").await;
        let stream = format!("i485-{run}");
        let root = write_and_seal(&p, &stream, 2).await;
        let chunks = deliver(&p, &stream, &root).await;
        let row = bind(
            p.sb.as_ref(),
            &format!("i485-file-{run}"),
            &p.owner,
            &hex::encode(root),
            None,
        )
        .await;
        withdraw(p.sb.as_ref(), &format!("i485-w-{run}"), &p.owner, &row).await;
        // A live row by a stranger names the SAME stream in its pointer member
        // but binds bytes of its own: it relates nothing.
        let stranger = format!("i485-stranger-{run}");
        ts::register_hybrid_key_as(
            p.sb.as_ref(),
            &stranger,
            &stranger,
            crate::federation::types::identity_type::USER,
        )
        .await;
        bind(
            p.sb.as_ref(),
            &format!("i485-forged-{run}"),
            &stranger,
            &"ab".repeat(32),
            Some(&stream),
        )
        .await;
        for (seq, c) in &chunks {
            assert!(
                matches!(served(&p, c).await, Err(BlobError::Withdrawn { .. })),
                "I485 chunk {seq} stays withdrawn: a pointer's stream_id relates nothing"
            );
        }
    }

    /// **I486 / I487** — a DAG with no relation, and the backfill.
    pub(crate) async fn i486_487_an_unrelated_dag_and_the_backfill<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + LinkSeam + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i486").await;
        // I486 — a DAG with no relation (from before V176), withdrawn: its
        // chunks read Unbound and serve, exactly as before. The promote opens
        // the manifest, which refuses a withdrawn one, so such a DAG is never
        // backfilled; the host's revocation register (CIRISEdge#771) is what
        // refuses its chunks.
        let old_stream = format!("i486-{run}");
        let old = write_and_seal(&p, &old_stream, 2).await;
        let old_chunks = deliver(&p, &old_stream, &old).await;
        let row = bind(
            p.sb.as_ref(),
            &format!("i486-file-{run}"),
            &p.owner,
            &hex::encode(old),
            None,
        )
        .await;
        p.sb.dag_link(&old, None).await;
        withdraw(p.sb.as_ref(), &format!("i486-w-{run}"), &p.owner, &row).await;
        assert!(p.b.chunks_of_manifest(&old).await.unwrap().is_empty());
        for (seq, c) in &old_chunks {
            assert_eq!(
                binding_state(p.sb.as_ref(), c).await.unwrap(),
                BindingState::Unbound,
                "I486 with no relation chunk {seq} reads Unbound, as before V176"
            );
            served(&p, c).await.expect("I486 and serves, as before");
        }
        // I487 — a LIVE DAG with no relation: a viewer's re-promote relates
        // it, and a later withdraw then reaches its chunks.
        let stream = format!("i487-{run}");
        let root = write_and_seal(&p, &stream, 2).await;
        let chunks = deliver(&p, &stream, &root).await;
        let row = bind(
            p.sb.as_ref(),
            &format!("i487-file-{run}"),
            &p.owner,
            &hex::encode(root),
            None,
        )
        .await;
        p.sb.dag_link(&root, None).await;
        assert!(p.b.chunks_of_manifest(&root).await.unwrap().is_empty());
        let again =
            p.b.promote_adopted_manifest_to_dag(&root, &p.key_b, None)
                .await
                .unwrap();
        assert!(!again.promoted, "I487 the row was already a DAG");
        assert_eq!(
            p.b.chunks_of_manifest(&root).await.unwrap(),
            chunks,
            "I487 a viewer's re-promote relates it (the backfill)"
        );
        withdraw(p.sb.as_ref(), &format!("i487-w-{run}"), &p.owner, &row).await;
        for (seq, c) in &chunks {
            assert!(
                matches!(served(&p, c).await, Err(BlobError::Withdrawn { .. })),
                "I487 and chunk {seq} is now refused by its file"
            );
        }
    }

    /// **I576** (v54.0.0, #994, for CIRISEdge#771) — **the V176 backfill
    /// sweep.** A seals three DAGs and B adopts and promotes the first; every
    /// relation is then dropped (the pre-V176 shape). On A one stream loses a
    /// row (it no longer holds exactly its manifest's chunks) and one DAG was
    /// sealed under a viewer's associated data. A's sweep relates exactly the
    /// first DAG's chunks, skips the moved stream and the unopenable one, and
    /// a second pass relates nothing new. B's sweep relates the DAG it adopted,
    /// opened with its own grant.
    pub(crate) async fn i576_the_backfill_sweep<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + LinkSeam + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i576").await;
        let (s1, s2, s3) = (
            format!("i576-1-{run}"),
            format!("i576-2-{run}"),
            format!("i576-3-{run}"),
        );
        let good = write_and_seal(&p, &s1, 3).await;
        let moved = write_and_seal(&p, &s2, 2).await;
        for i in 0..2 {
            p.a.put_blob_chunk_scoped(
                cohort_scope::SELF,
                Some(&p.owner),
                &s3,
                i,
                &segment(i as usize),
                0,
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("chunk {i}: {e}"));
        }
        let aad: &[u8] = b"i576-viewer-context";
        let sealed_with_aad =
            p.a.seal_stream_scoped(cohort_scope::SELF, Some(&p.owner), &s3, None, Some(aad))
                .await
                .unwrap_or_else(|e| panic!("seal {s3}: {e}"))
                .manifest_sha256;
        let want_a = p.a.chunks_of_manifest(&good).await.unwrap();
        assert_eq!(
            want_a.len(),
            4,
            "I576 precondition: three chunks and a terminator"
        );
        let on_b = deliver(&p, &s1, &good).await;
        for m in [&good, &moved, &sealed_with_aad] {
            p.sa.dag_link(m, None).await;
        }
        p.sb.dag_link(&good, None).await;
        p.sa.drop_stream_row(&s2, 0).await;
        assert!(p.a.chunks_of_manifest(&good).await.unwrap().is_empty());

        let r =
            p.a.backfill_dag_chunk_links(1_000)
                .await
                .expect("A's sweep");
        assert_eq!(
            (
                r.scanned,
                r.linked,
                r.skipped_stream_mismatch,
                r.skipped_no_key,
                r.truncated
            ),
            (3, 1, 1, 1, false),
            "I576 A: one linked, the moved stream skipped, the AAD-sealed DAG unopenable: {r:?}"
        );
        assert_eq!(
            p.a.chunks_of_manifest(&good).await.unwrap(),
            want_a,
            "I576 A: exactly the manifest's chunks, terminator included"
        );
        assert!(
            p.a.chunks_of_manifest(&moved).await.unwrap().is_empty(),
            "I576 A: a moved stream is never mis-linked"
        );
        assert!(p
            .a
            .chunks_of_manifest(&sealed_with_aad)
            .await
            .unwrap()
            .is_empty());
        for (_, c) in &want_a {
            assert!(p.a.dag_contains_chunk(&good, c).await.unwrap());
        }
        let again = p.a.backfill_dag_chunk_links(1_000).await.unwrap();
        assert_eq!(
            (again.scanned, again.linked),
            (2, 0),
            "I576 A: idempotent; the skipped two are examined again, nothing new linked"
        );
        let capped = p.a.backfill_dag_chunk_links(1).await.unwrap();
        assert!(
            capped.truncated && capped.scanned == 1,
            "I576 the cap: {capped:?}"
        );

        let rb =
            p.b.backfill_dag_chunk_links(1_000)
                .await
                .expect("B's sweep");
        assert_eq!((rb.scanned, rb.linked), (1, 1), "I576 B: {rb:?}");
        assert_eq!(
            p.b.chunks_of_manifest(&good).await.unwrap(),
            on_b,
            "I576 B: the adopted DAG gains exactly its chunks"
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

    pair_case!(i480_481, i480_481_the_relation_is_written_by_persist);
    pair_case!(i482_483, i482_483_a_withdrawn_file_takes_its_chunks);
    pair_case!(i484, i484_a_shared_chunk_needs_both_withdrawn);
    pair_case!(i485, i485_a_forged_pointer_revives_nothing);
    pair_case!(i486_487, i486_487_an_unrelated_dag_and_the_backfill);
    pair_case!(i576, i576_the_backfill_sweep);

    /// **I576b** — from disk: every Engine constructor that runs the boot
    /// KeyGrant sweep also runs the V176 backfill (comments stripped).
    #[test]
    fn i576b_every_constructor_runs_the_backfill_at_boot() {
        let src: String = include_str!("../engine.rs")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let grants = src
            .matches("engine.sweep_pending_key_grants_at_boot().await;")
            .count();
        let links = src
            .matches("engine.sweep_dag_chunk_links_at_boot().await;")
            .count();
        assert!(grants >= 4, "I576b: the constructors were found ({grants})");
        assert_eq!(links, grants, "I576b: a constructor skips the backfill");
    }
}
