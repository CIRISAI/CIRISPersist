//! v53.0.0 (CIRISPersist#969; `FSD/BLOB_ENCRYPTION_AT_REST.md` §12.13,
//! `FSD/BLOB_REPLICATION.md` §14.1) — **one DEK per (stream, epoch) for a
//! self/family chunk stream, sealed with the CC 5.3.3.1 STREAM nonce.**
//!
//! - **I310** (sqlite, postgres) — a 1024-chunk `self` stream carries exactly
//!   R stream wraps (R = the owner's occurrences) and ZERO per-chunk wraps,
//!   and emits ONE stream-axis set. Before #969: 1024·R content wraps.
//! - **I311** (unit in `stream_seal`, and here on both backends) — every
//!   stored chunk's nonce IS `stream_nonce(dek, stream_id, epoch, counter,
//!   last)`, counters 0, 1, 2, … in seq order.
//! - **I312** — the seal closes every epoch with ONE terminator (`last`), the
//!   final chunk of its epoch; a chunk after it is refused at the floor; a
//!   DAG whose terminator is dropped, or whose counters skip, is refused by
//!   the structure check the promote and the whole read run (unit).
//! - **I313** (two nodes, sqlite and postgres) — the owner's second device
//!   holds the bytes before the stream set: readiness names the EPOCH, a read
//!   is the typed retryable refusal naming `Stream{stream_id, epoch}`; after
//!   ONE set per epoch it reads whole and by range. A late device costs one
//!   re-grant per epoch, not per chunk. A stranger keeps `NotGranted`.
//! - **I314** (sqlite, postgres) — an append that would take the epoch's last
//!   counter (reserved for the terminator) rolls to E+1 under a fresh DEK
//!   with its own set, counter reset; the seal terminates both epochs.
//! - **I315** (sqlite, postgres) — a stream that already holds per-chunk-keyed
//!   chunks (the v52 shape) stays per-chunk to its seal, seals as v2, and
//!   reads whole and by range.
//! - **I316** (two nodes) — a forwarder with no grant adopts every chunk (I45:
//!   nothing is opened); the promote's structure check reads the nonces only.
//! - **I317** (sqlite, postgres) — a nested (v3) root over stream-keyed (v4)
//!   children reads whole and by range.
//! - **I318** (two nodes) — the batched adopt of stream-keyed chunks, then
//!   promote and read.
//! - **I319** (sqlite, postgres) — single sender: a second floor append at an
//!   already-used counter is refused `stream_counter_moved` and stores
//!   nothing; a foreign writer is refused at its first chunk (I41).

// Test-only (the module is `cfg(test)` at its declaration too); marked here
// so the from-disk floor gate (I14) reads its direct floor calls as tests.
#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::adopt_batch_invariants::bodies::CounterProbe;
    use crate::federation::chunk_dag_cascade::orchestrate::{
        check_stream_epoch_structure, MissingChunkKey,
    };
    use crate::federation::epoch_minter_invariants::bodies::Pick;
    use crate::federation::key_grant::{
        SignedKeyGrantSet, KEY_GRANT_CONTENT_ATTESTATION_TYPE, KEY_GRANT_STREAM_ATTESTATION_TYPE,
    };
    use crate::federation::nested_manifest_invariants::bodies::{kem_of, pair, Pair, SetCap};
    use crate::federation::self_collective_invariants::bodies::bind;
    use crate::federation::types::cohort_scope::{self, CryptoTier};
    use crate::federation::{
        AdoptChunkItem, AdoptDisposition, BlobBody, BlobError, BlobProvenance, BlobStorage,
        ChunkKeyRef, FederationDirectory, StreamKeySlot,
    };

    fn segment(i: usize) -> Vec<u8> {
        (0..40 + (i % 5) * 11).map(|j| (i * 17 + j) as u8).collect()
    }

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

    async fn seal(p: &Pair<impl BlobStorage>, stream: &str) -> [u8; 32] {
        p.a.seal_stream_scoped(cohort_scope::SELF, Some(&p.owner), stream, None, None)
            .await
            .unwrap_or_else(|e| panic!("seal {stream}: {e}"))
            .manifest_sha256
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

    /// The (stream, epoch) DEK this node sealed under.
    async fn epoch_dek<B: BlobStorage + Sync>(b: &B, stream: &str, epoch: u64) -> [u8; 32] {
        let rec = b
            .stream_dek_list(stream)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.epoch == epoch)
            .expect("the epoch's DEK row");
        let cm = b.load_or_init_content_master().await.unwrap();
        crate::federation::at_rest_cascade::unwrap_dek_for_persist(&cm, &rec.self_retention_wrap)
            .unwrap()
    }

    pub(crate) async fn i310_one_wrap_per_recipient_per_epoch<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
        n: usize,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i310").await;
        let stream = format!("i310-{run}");
        let plain = write_self(&p.a, &p.owner, &stream, n).await;
        let listing = p.sa.stream_chunks(&stream).await.unwrap();
        assert_eq!(listing.chunks.len(), n);
        for c in &listing.chunks {
            assert!(
                p.sa.list_at_rest_grants(&c.chunk_sha)
                    .await
                    .unwrap()
                    .is_empty(),
                "I310: chunk seq {} carries a per-chunk wrap",
                c.seq
            );
            assert!(
                p.sa.get_at_rest_grant(
                    &c.chunk_sha,
                    crate::federation::at_rest_cascade::PERSIST_SELF_RECIPIENT
                )
                .await
                .unwrap()
                .is_none(),
                "I310: chunk seq {} carries a per-chunk self-retention row",
                c.seq
            );
        }
        let epochs = p.sa.stream_dek_list(&stream).await.unwrap();
        assert_eq!(epochs.len(), 1, "I310: one epoch");
        let wraps = p.sa.stream_dek_grants(&stream, 0, &p.key_a).await.unwrap();
        let mut recipients: Vec<&str> = wraps.iter().map(|w| w.recipient_key_id.as_str()).collect();
        recipients.sort_unstable();
        let mut want = vec![p.key_a.as_str(), p.key_b.as_str()];
        want.sort_unstable();
        assert_eq!(recipients, want, "I310: exactly R = 2 stream wraps");
        let sets: Vec<_> =
            p.sa.list_attestations_by(&p.key_a)
                .await
                .unwrap()
                .into_iter()
                .filter(|x| x.attestation_type.starts_with("key_grant:"))
                .collect();
        assert_eq!(
            sets.iter()
                .filter(|x| x.attestation_type == KEY_GRANT_STREAM_ATTESTATION_TYPE)
                .count(),
            1,
            "I310: ONE stream-axis set for the epoch"
        );
        assert_eq!(
            sets.iter()
                .filter(|x| x.attestation_type == KEY_GRANT_CONTENT_ATTESTATION_TYPE)
                .count(),
            0,
            "I310: no per-chunk content set"
        );
        // I311 — every stored nonce is the STREAM nonce at its counter.
        let dek = epoch_dek(p.sa.as_ref(), &stream, 0).await;
        for (i, c) in listing.chunks.iter().enumerate() {
            let env = crate::federation::at_rest_cascade::AtRestEnvelope::from_bytes(
                &inline(p.sa.as_ref(), &c.chunk_sha).await,
            )
            .unwrap();
            let want = crate::federation::stream_seal::stream_nonce(
                &dek,
                &stream,
                0,
                u32::try_from(i).unwrap(),
                false,
            )
            .unwrap();
            assert_eq!(env.nonce, want, "I311: chunk seq {} nonce", c.seq);
        }
        // The live read by position: per epoch, not per chunk.
        assert_eq!(
            p.a.read_stream_chunk_as(&stream, 3, &p.key_a, None)
                .await
                .unwrap(),
            segment(3)
        );
        let root = seal(&p, &stream).await;
        let view =
            p.a.open_sealed_manifest_as(&root, &p.key_a, None)
                .await
                .unwrap();
        assert!(
            view.version == crate::federation::CHUNK_MANIFEST_VERSION_STREAM
                || view.version == crate::federation::CHUNK_MANIFEST_VERSION_NESTED,
            "I310: a stream-keyed manifest ({})",
            view.version
        );
        assert_eq!(
            p.a.read_blob_as(&root, &p.key_a, None).await.unwrap(),
            plain,
            "I310: the file reads whole"
        );
    }

    pub(crate) async fn i312_every_epoch_ends_in_one_terminator<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i312").await;
        let stream = format!("i312-{run}");
        let plain = write_self(&p.a, &p.owner, &stream, 5).await;
        let root = seal(&p, &stream).await;
        let listing = p.sa.stream_chunks(&stream).await.unwrap();
        assert_eq!(
            listing.chunks.len(),
            6,
            "I312: five chunks and a terminator"
        );
        let last = listing.chunks.last().unwrap();
        assert_eq!(
            (last.seq, last.plaintext_size),
            (5, 0),
            "I312: the terminator"
        );
        let dek = epoch_dek(p.sa.as_ref(), &stream, 0).await;
        let env = crate::federation::at_rest_cascade::AtRestEnvelope::from_bytes(
            &inline(p.sa.as_ref(), &last.chunk_sha).await,
        )
        .unwrap();
        assert_eq!(
            env.nonce,
            crate::federation::stream_seal::stream_nonce(&dek, &stream, 0, 5, true).unwrap(),
            "I312: the terminator carries last_flag at the epoch's final counter"
        );
        let rec = p.sa.stream_dek_list(&stream).await.unwrap().remove(0);
        assert!(rec.terminated && rec.closed, "I312: {rec:?}");
        // The whole read runs the structure check and passes.
        assert_eq!(
            p.a.read_blob_as(&root, &p.key_a, None).await.unwrap(),
            plain
        );
        // A chunk after the epoch's last is refused at the floor, in its own
        // transaction — data or a second terminator alike.
        for last in [false, true] {
            let slot = StreamKeySlot { counter: 6, last };
            let envelope = crate::federation::at_rest_cascade::seal_aad_at_nonce(
                &dek,
                crate::federation::stream_seal::stream_nonce(&dek, &stream, 0, 6, last).unwrap(),
                &crate::federation::chunk_dag_cascade::chunk_aad(None, &stream, 9),
                b"late",
            )
            .unwrap();
            let e =
                p.sa.put_blob_chunk_with_scope(
                    &stream,
                    9,
                    BlobBody::Inline(envelope.to_bytes()),
                    0,
                    4,
                    cohort_scope::SELF,
                    crate::federation::StorageFloor::resolved(CryptoTier::InvisibleEncrypted),
                    None,
                    crate::federation::StreamClaim {
                        community_key_id: Some(p.owner.clone()),
                        owner_key_id: Some(p.key_a.clone()),
                        stream_key: Some(slot),
                    },
                )
                .await
                .expect_err("I312: nothing follows an epoch's last");
            assert!(
                matches!(&e, BlobError::InvalidArgument(m)
                    if m.starts_with(crate::federation::blobs::STREAM_EPOCH_CLOSED)),
                "I312: {e:?}"
            );
        }
        assert!(p.sa.stream_chunk_at(&stream, 9).await.unwrap().is_none());
    }

    pub(crate) async fn i313_the_second_device_needs_one_set_per_epoch<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i313").await;
        let stream = format!("i313-{run}");
        let plain = write_self(&p.a, &p.owner, &stream, 12).await;
        let root = seal(&p, &stream).await;
        p.a.emit_pending_key_grants().await.unwrap();
        let sets: Vec<_> =
            p.sa.list_attestations_by(&p.key_a)
                .await
                .unwrap()
                .into_iter()
                .filter(|x| x.attestation_type.starts_with("key_grant:"))
                .collect();
        let (stream_sets, content_sets): (Vec<_>, Vec<_>) = sets
            .into_iter()
            .partition(|x| x.attestation_type == KEY_GRANT_STREAM_ATTESTATION_TYPE);
        assert_eq!(stream_sets.len(), 1, "I313: one stream set per epoch");
        assert_eq!(
            content_sets.len(),
            1,
            "I313: one content set, the manifest's"
        );
        for set in content_sets {
            p.b.apply_replicated_key_grant(SignedKeyGrantSet { attestation: set })
                .await
                .expect("B applies the manifest's set");
        }
        let prov = BlobProvenance {
            author_key_id: p.owner.clone(),
            cohort_scope: cohort_scope::SELF.to_owned(),
            community_key_id: None,
            epoch: None,
            tier: CryptoTier::InvisibleEncrypted,
            minter_key_id: Some(p.key_a.clone()),
        };
        p.b.adopt_sealed_blob(
            &inline(p.sa.as_ref(), &root).await,
            prov.clone(),
            None,
            AdoptDisposition::LocalOnly,
        )
        .await
        .expect("B adopts the manifest");
        let view =
            p.b.open_sealed_manifest_as(&root, &p.key_b, None)
                .await
                .expect("B opens the manifest");
        assert_eq!(view.chunks.len(), 13);
        // Before any chunk: not held, and the epoch's key is missing.
        let r =
            p.b.sealed_dag_readiness(&root, &p.key_b, None)
                .await
                .unwrap();
        assert!(!r.held && !r.readable, "I313: {r:?}");
        assert_eq!(r.chunk_keys, "stream_epoch");
        assert_eq!(r.not_held.len(), 13);
        for c in &view.chunks {
            p.b.adopt_sealed_chunk(
                &stream,
                c.seq,
                &inline(p.sa.as_ref(), &hexsha(&c.sha256_hex)).await,
                c.epoch.expect("a v4 chunk names its epoch"),
                u64::from(c.size),
                prov.clone(),
            )
            .await
            .unwrap_or_else(|e| panic!("I313: chunk {}: {e}", c.seq));
        }
        p.b.promote_adopted_manifest_to_dag(&root, &p.key_b, None)
            .await
            .expect("I313: promoted (the structure check reads nonces only)");
        // Held, but the epoch's set has not arrived: ONE missing entry for the
        // epoch, spanning every chunk of it.
        let r =
            p.b.sealed_dag_readiness(&root, &p.key_b, None)
                .await
                .unwrap();
        assert!(r.held && !r.readable, "I313: {r:?}");
        assert_eq!(
            r.missing,
            vec![MissingChunkKey::Stream {
                stream_id: stream.clone(),
                epoch: 0,
                seq_from: 0,
                seq_to: 12
            }],
            "I313: O(epochs) — one entry"
        );
        // The authorized viewer is told WHICH key, retryably.
        match p.b.read_blob_as(&root, &p.key_b, None).await {
            Err(BlobError::ChunkKeyNotYetGranted { key, seq, .. }) => {
                assert_eq!(
                    key,
                    ChunkKeyRef::Stream {
                        stream_id: stream.clone(),
                        epoch: 0
                    }
                );
                assert_eq!(seq, 0);
            }
            other => panic!("I313: {other:?}"),
        }
        // A stranger keeps the DAG-only refusal.
        let stranger = format!("i313-stranger-{run}");
        assert!(matches!(
            p.b.read_blob_as(&root, &stranger, None).await,
            Err(BlobError::NotGranted { .. })
        ));
        assert!(matches!(
            p.b.sealed_dag_readiness(&root, &stranger, None).await,
            Err(BlobError::NotGranted { .. })
        ));
        for set in stream_sets {
            p.b.apply_replicated_key_grant(SignedKeyGrantSet { attestation: set })
                .await
                .expect("B applies the stream set");
        }
        let r =
            p.b.sealed_dag_readiness(&root, &p.key_b, None)
                .await
                .unwrap();
        assert!(r.readable && r.missing.is_empty(), "I313: {r:?}");
        assert_eq!(
            p.b.read_blob_as(&root, &p.key_b, None).await.unwrap(),
            plain,
            "I313: the second device reads the file"
        );
        assert_eq!(
            p.b.read_blob_range_as(&root, &p.key_b, 50, 140, None)
                .await
                .unwrap(),
            plain[50..=140].to_vec(),
            "I313: and by range"
        );
        // A late device: one re-grant per EPOCH (and the manifest), not per chunk.
        let late = format!("i313-late-{run}");
        crate::federation::tier_ingest::test_support::register_hybrid_key_as(
            p.sa.as_ref(),
            &late,
            &late,
            crate::federation::types::identity_type::NODE,
        )
        .await;
        bind(
            p.sa.as_ref(),
            &p.owner,
            &late,
            Some(kem_of(p.sb.as_ref()).await),
        )
        .await;
        let rk =
            p.a.rekey_self_occurrence_add(&p.owner, std::slice::from_ref(&late))
                .await
                .unwrap();
        assert_eq!(
            rk.changed_streams,
            vec![(stream.clone(), 0, p.owner.clone())],
            "I313: the late device's stream re-grant is O(epochs)"
        );
        assert_eq!(rk.changed_blobs, vec![root], "I313: and the manifest");
        assert!(
            p.sa.stream_dek_grants(&stream, 0, &p.key_a)
                .await
                .unwrap()
                .iter()
                .any(|w| w.recipient_key_id == late),
            "I313: the late device holds the epoch's wrap"
        );
    }

    pub(crate) async fn i314_the_cap_rolls_the_epoch<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + CounterProbe + Sync + 'static,
    {
        use crate::federation::blobs::MAX_CHUNKS_PER_EPOCH;
        let p = pair(dsn_a, dsn_b, run, pick, "i314").await;
        let stream = format!("i314-{run}");
        write_self(&p.a, &p.owner, &stream, 1).await;
        // Shrink the epoch's headroom: the next data chunk takes the
        // second-to-last counter; the one after would take the terminator's.
        let max = i64::try_from(MAX_CHUNKS_PER_EPOCH).unwrap();
        p.sa.set_counter(&stream, 0, max - 2).await;
        let r1 =
            p.a.put_blob_chunk_scoped(
                cohort_scope::SELF,
                Some(&p.owner),
                &stream,
                1,
                b"near",
                0,
                None,
            )
            .await
            .unwrap();
        assert!(
            r1.key_grant_emission.is_none(),
            "I314: same epoch, no new set"
        );
        let r2 =
            p.a.put_blob_chunk_scoped(
                cohort_scope::SELF,
                Some(&p.owner),
                &stream,
                2,
                b"rolled",
                0,
                None,
            )
            .await
            .unwrap();
        assert!(
            matches!(
                &r2.key_grant_emission,
                Some(crate::federation::key_grant::KeyGrantAxis::Stream { epoch: 1, .. })
            ),
            "I314: E+1 carries its own set: {:?}",
            r2.key_grant_emission
        );
        let at = p.sa.stream_chunk_at(&stream, 2).await.unwrap().unwrap();
        assert_eq!(at.epoch, 1, "I314: the chunk is recorded at E+1");
        let deks = p.sa.stream_dek_list(&stream).await.unwrap();
        assert_eq!(deks.len(), 2);
        assert!(
            deks[0].closed && !deks[0].terminated,
            "I314: E closed to data"
        );
        assert_ne!(
            deks[0].self_retention_wrap, deks[1].self_retention_wrap,
            "I314: a fresh DEK"
        );
        let env = crate::federation::at_rest_cascade::AtRestEnvelope::from_bytes(
            &inline(p.sa.as_ref(), &at.chunk_sha).await,
        )
        .unwrap();
        let dek1 = epoch_dek(p.sa.as_ref(), &stream, 1).await;
        assert_eq!(
            env.nonce,
            crate::federation::stream_seal::stream_nonce(&dek1, &stream, 1, 0, false).unwrap(),
            "I314: the counter resets at E+1"
        );
        // The producer naming the old epoch is carried to the open one.
        p.a.put_blob_chunk_scoped(
            cohort_scope::SELF,
            Some(&p.owner),
            &stream,
            3,
            b"more",
            0,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            p.sa.stream_chunk_at(&stream, 3)
                .await
                .unwrap()
                .unwrap()
                .epoch,
            1
        );
        // The seal terminates both: E at its last counter, E+1 after its two.
        seal(&p, &stream).await;
        let deks = p.sa.stream_dek_list(&stream).await.unwrap();
        assert!(deks.iter().all(|d| d.terminated), "I314: {deks:?}");
        let listing = p.sa.stream_chunks(&stream).await.unwrap();
        let dek0 = epoch_dek(p.sa.as_ref(), &stream, 0).await;
        let t0 = listing.chunks.iter().find(|c| c.seq == 4).unwrap();
        assert_eq!(t0.epoch, 0);
        assert_eq!(
            crate::federation::at_rest_cascade::AtRestEnvelope::from_bytes(
                &inline(p.sa.as_ref(), &t0.chunk_sha).await
            )
            .unwrap()
            .nonce,
            crate::federation::stream_seal::stream_nonce(
                &dek0,
                &stream,
                0,
                u32::try_from(max - 1).unwrap(),
                true
            )
            .unwrap(),
            "I314: E's terminator takes the slot the roll reserved"
        );
    }

    pub(crate) async fn i315_a_v52_stream_reads_forever<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i315").await;
        let stream = format!("i315-{run}");
        // The v52 chunk door, verbatim: a fresh DEK per chunk, the position
        // AAD, the floor with no stream slot, the per-chunk grants.
        let seg0 = segment(0);
        let dek = crate::federation::at_rest_cascade::fresh_dek().unwrap();
        let env = crate::federation::at_rest_cascade::seal(
            &dek,
            &seg0,
            Some(&crate::federation::chunk_dag_cascade::chunk_aad(
                None, &stream, 0,
            )),
        )
        .unwrap();
        let sha =
            p.sa.put_blob_chunk_with_scope(
                &stream,
                0,
                BlobBody::Inline(env.to_bytes()),
                0,
                seg0.len() as u64,
                cohort_scope::SELF,
                crate::federation::StorageFloor::resolved(CryptoTier::InvisibleEncrypted),
                None,
                crate::federation::StreamClaim {
                    community_key_id: Some(p.owner.clone()),
                    owner_key_id: Some(p.key_a.clone()),
                    stream_key: None,
                },
            )
            .await
            .unwrap();
        crate::federation::at_rest_cascade::orchestrate::grant_dek_to_cohort(
            p.sa.as_ref(),
            &sha,
            cohort_scope::SELF,
            &p.owner,
            &dek,
        )
        .await
        .unwrap();
        // The stream continues on the per-chunk path through the door.
        let mut plain = seg0.clone();
        for i in 1..6 {
            let seg = segment(i);
            p.a.put_blob_chunk_scoped(
                cohort_scope::SELF,
                Some(&p.owner),
                &stream,
                i as u64,
                &seg,
                0,
                None,
            )
            .await
            .unwrap();
            plain.extend_from_slice(&seg);
        }
        assert!(
            p.sa.stream_dek_list(&stream).await.unwrap().is_empty(),
            "I315: a v52 stream never gains a stream DEK"
        );
        let root = seal(&p, &stream).await;
        let view =
            p.a.open_sealed_manifest_as(&root, &p.key_a, None)
                .await
                .unwrap();
        assert_eq!(view.version, 2, "I315: legacy stays v2");
        assert_eq!(view.chunks.len(), 6, "I315: no terminator on a legacy DAG");
        assert!(view.chunks.iter().all(|c| c.epoch.is_none()));
        assert_eq!(
            p.a.read_blob_as(&root, &p.key_a, None).await.unwrap(),
            plain
        );
        assert_eq!(
            p.a.read_blob_range_as(&root, &p.key_a, 30, 120, None)
                .await
                .unwrap(),
            plain[30..=120].to_vec()
        );
        let r =
            p.a.sealed_dag_readiness(&root, &p.key_a, None)
                .await
                .unwrap();
        assert!(r.readable && r.chunk_keys == "content", "I315: {r:?}");
        // An authorized viewer missing ONE chunk's grant: per-chunk, typed.
        let stranger_dev = format!("i315-dev-{run}");
        p.sa.put_at_rest_grants(
            &root,
            cohort_scope::SELF,
            &[crate::federation::GrantWrap {
                recipient_key_id: stranger_dev.clone(),
                wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.into(),
                wrapped_dek: "{}".into(),
            }],
        )
        .await
        .unwrap();
        let r =
            p.a.sealed_dag_readiness(&root, &stranger_dev, None)
                .await
                .unwrap();
        assert_eq!(r.missing.len(), 6, "I315: legacy names each chunk: {r:?}");
        assert!(matches!(
            &r.missing[0],
            MissingChunkKey::Content { seq: 0, .. }
        ));
    }

    pub(crate) async fn i316_a_forwarder_holds_without_a_key<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i316").await;
        let stream = format!("i316-{run}");
        write_self(&p.a, &p.owner, &stream, 4).await;
        let root = seal(&p, &stream).await;
        let listing = p.sa.stream_chunks(&stream).await.unwrap();
        // B holds no set at all: the adopt stores every chunk unopened.
        let prov = BlobProvenance {
            author_key_id: p.owner.clone(),
            cohort_scope: cohort_scope::SELF.to_owned(),
            community_key_id: None,
            epoch: None,
            tier: CryptoTier::InvisibleEncrypted,
            minter_key_id: Some(p.key_a.clone()),
        };
        for c in &listing.chunks {
            p.b.adopt_sealed_chunk(
                &stream,
                c.seq,
                &inline(p.sa.as_ref(), &c.chunk_sha).await,
                c.epoch,
                c.plaintext_size,
                prov.clone(),
            )
            .await
            .unwrap_or_else(|e| panic!("I316: a keyless adopt of seq {}: {e}", c.seq));
        }
        let held = p.sb.stream_chunks(&stream).await.unwrap();
        assert_eq!(
            held.chunks
                .iter()
                .map(|c| (c.seq, c.chunk_sha, c.epoch))
                .collect::<Vec<_>>(),
            listing
                .chunks
                .iter()
                .map(|c| (c.seq, c.chunk_sha, c.epoch))
                .collect::<Vec<_>>(),
            "I316: the forwarder holds every chunk at its seq and epoch"
        );
        assert!(
            p.sb.stream_dek_list(&stream).await.unwrap().is_empty(),
            "I316: a forwarder mints and holds no stream key"
        );
        // It cannot read what it holds: it is no viewer of the DAG.
        assert!(matches!(
            p.b.read_blob_as(&root, &p.key_b, None).await,
            Err(BlobError::NotHeld { .. } | BlobError::NotGranted { .. })
        ));
    }

    pub(crate) async fn i317_a_nested_root_over_stream_keyed_children<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
        set_cap: SetCap<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i317").await;
        set_cap(p.sa.as_ref(), 4096);
        let stream = format!("i317-{run}");
        let plain = write_self(&p.a, &p.owner, &stream, 60).await;
        let root = seal(&p, &stream).await;
        let view =
            p.a.open_sealed_manifest_as(&root, &p.key_a, None)
                .await
                .unwrap();
        assert_eq!(view.version, 3, "I317: a nested root");
        let page =
            p.a.open_sealed_manifest_page_as(&root, 0, &p.key_a, None)
                .await
                .unwrap();
        assert!(page.iter().all(|c| c.epoch == Some(0)), "I317: v4 children");
        assert_eq!(
            p.a.read_blob_as(&root, &p.key_a, None).await.unwrap(),
            plain
        );
        let b0 = view.children[0].size;
        assert_eq!(
            p.a.read_blob_range_as(&root, &p.key_a, b0 - 3, b0 + 3, None)
                .await
                .unwrap(),
            plain[b0 as usize - 3..=b0 as usize + 3].to_vec()
        );
        let r =
            p.a.sealed_dag_readiness(&root, &p.key_a, None)
                .await
                .unwrap();
        assert!(r.readable && r.chunk_keys == "stream_epoch", "I317: {r:?}");
    }

    pub(crate) async fn i318_the_batched_adopt_of_stream_keyed_chunks<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i318").await;
        let stream = format!("i318-{run}");
        let plain = write_self(&p.a, &p.owner, &stream, 9).await;
        let root = seal(&p, &stream).await;
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
                .expect("B applies A's sets");
        }
        let prov = BlobProvenance {
            author_key_id: p.owner.clone(),
            cohort_scope: cohort_scope::SELF.to_owned(),
            community_key_id: None,
            epoch: None,
            tier: CryptoTier::InvisibleEncrypted,
            minter_key_id: Some(p.key_a.clone()),
        };
        p.b.adopt_sealed_blob(
            &inline(p.sa.as_ref(), &root).await,
            prov.clone(),
            None,
            AdoptDisposition::LocalOnly,
        )
        .await
        .unwrap();
        let view =
            p.b.open_sealed_manifest_as(&root, &p.key_b, None)
                .await
                .unwrap();
        let mut bodies = Vec::new();
        for c in &view.chunks {
            bodies.push((
                c.seq,
                inline(p.sa.as_ref(), &hexsha(&c.sha256_hex)).await,
                u64::from(c.size),
            ));
        }
        let items: Vec<AdoptChunkItem<'_>> = bodies
            .iter()
            .map(|(seq, env, size)| AdoptChunkItem {
                seq: *seq,
                envelope: env,
                plaintext_size: *size,
            })
            .collect();
        let out =
            p.b.adopt_sealed_chunks(&stream, &items, 0, prov.clone())
                .await
                .unwrap();
        assert!(out.iter().all(Result::is_ok), "I318: {out:?}");
        p.b.promote_adopted_manifest_to_dag(&root, &p.key_b, None)
            .await
            .expect("I318: promoted");
        assert_eq!(
            p.b.read_blob_as(&root, &p.key_b, None).await.unwrap(),
            plain
        );
    }

    pub(crate) async fn i319_one_sender_one_counter<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i319").await;
        let stream = format!("i319-{run}");
        write_self(&p.a, &p.owner, &stream, 2).await;
        // A second append at counter 1 (already used by seq 1).
        let dek = epoch_dek(p.sa.as_ref(), &stream, 0).await;
        let envelope = crate::federation::at_rest_cascade::seal_aad_at_nonce(
            &dek,
            crate::federation::stream_seal::stream_nonce(&dek, &stream, 0, 1, false).unwrap(),
            &crate::federation::chunk_dag_cascade::chunk_aad(None, &stream, 7),
            b"reuse",
        )
        .unwrap();
        let e =
            p.sa.put_blob_chunk_with_scope(
                &stream,
                7,
                BlobBody::Inline(envelope.to_bytes()),
                0,
                5,
                cohort_scope::SELF,
                crate::federation::StorageFloor::resolved(CryptoTier::InvisibleEncrypted),
                None,
                crate::federation::StreamClaim {
                    community_key_id: Some(p.owner.clone()),
                    owner_key_id: Some(p.key_a.clone()),
                    stream_key: Some(StreamKeySlot {
                        counter: 1,
                        last: false,
                    }),
                },
            )
            .await
            .expect_err("I319: a (DEK, nonce) pair is never reused");
        assert!(
            matches!(&e, BlobError::InvalidArgument(m)
                if m.starts_with(crate::federation::blobs::STREAM_COUNTER_MOVED)),
            "I319: {e:?}"
        );
        assert!(p.sa.stream_chunk_at(&stream, 7).await.unwrap().is_none());
        assert_eq!(
            p.sa.stream_dek_list(&stream).await.unwrap()[0].chunk_count,
            2,
            "I319: the refused append stepped nothing"
        );
        // A foreign writer is refused by the stream's floor (I41).
        let foreign =
            p.sa.put_blob_chunk_with_scope(
                &stream,
                8,
                BlobBody::Inline(envelope.to_bytes()),
                0,
                5,
                cohort_scope::SELF,
                crate::federation::StorageFloor::resolved(CryptoTier::InvisibleEncrypted),
                None,
                crate::federation::StreamClaim {
                    community_key_id: Some(p.owner.clone()),
                    owner_key_id: Some(p.key_b.clone()),
                    stream_key: Some(StreamKeySlot {
                        counter: 2,
                        last: false,
                    }),
                },
            )
            .await
            .expect_err("I319: one sender per stream");
        assert!(
            matches!(foreign, BlobError::InvalidArgument(_)),
            "{foreign:?}"
        );
    }

    /// I312 (unit) — the structure check over `(seq, epoch, slot)`.
    pub(crate) fn i312_the_structure_check() {
        let s = |counter, last| StreamKeySlot { counter, last };
        let dag = [7u8; 32];
        let whole = [
            (0, 0, s(0, false)),
            (1, 0, s(1, false)),
            (2, 1, s(0, false)),
            (3, 0, s(2, true)),
            (4, 1, s(1, true)),
        ];
        check_stream_epoch_structure(&dag, &whole).expect("whole");
        // The terminator dropped: truncated.
        let e = check_stream_epoch_structure(&dag, &whole[..4]).unwrap_err();
        assert!(e.to_string().contains("no last chunk"), "{e}");
        // A middle chunk dropped: the counter skips.
        let e = check_stream_epoch_structure(&dag, &[whole[0], whole[3]]).unwrap_err();
        assert!(e.to_string().contains("counter"), "{e}");
        // Something after the last.
        let e = check_stream_epoch_structure(&dag, &[(0, 0, s(0, true)), (1, 0, s(1, false))])
            .unwrap_err();
        assert!(e.to_string().contains("after"), "{e}");
        // Two lasts.
        let e = check_stream_epoch_structure(&dag, &[(0, 0, s(0, true)), (1, 0, s(1, true))])
            .unwrap_err();
        assert!(e.to_string().contains("after"), "{e}");
        // Reordered counters.
        let e = check_stream_epoch_structure(
            &dag,
            &[(0, 0, s(1, false)), (1, 0, s(0, false)), (2, 0, s(2, true))],
        )
        .unwrap_err();
        assert!(e.to_string().contains("counter"), "{e}");
    }
}

#[cfg(test)]
mod unit {
    #[test]
    fn i312_the_structure_check() {
        super::bodies::i312_the_structure_check();
    }

    /// The roll rule (pure): never below the stream's open epoch, past a
    /// closed one, and the producer's higher label wins.
    #[test]
    fn i314_the_target_epoch() {
        use crate::federation::chunk_dag_cascade::orchestrate::stream_target_epoch;
        let rec = |epoch, closed| crate::federation::StreamDekRecord {
            stream_id: "s".into(),
            epoch,
            owner_key_id: "o".into(),
            cohort_scope: "self".into(),
            group_key_id: "g".into(),
            self_retention_wrap: String::new(),
            chunk_count: 0,
            closed,
            terminated: false,
        };
        assert_eq!(stream_target_epoch(None, 4), 4);
        assert_eq!(stream_target_epoch(Some(&rec(3, false)), 0), 3);
        assert_eq!(stream_target_epoch(Some(&rec(3, true)), 0), 4);
        assert_eq!(stream_target_epoch(Some(&rec(3, false)), 9), 9);
        assert_eq!(stream_target_epoch(Some(&rec(3, true)), 9), 9);
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
                async fn i310() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i310_one_wrap_per_recipient_per_epoch(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                        1024,
                    )
                    .await
                }
                #[tokio::test]
                async fn i312() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i312_every_epoch_ends_in_one_terminator(&a, &b, &super::suffix(), $pick)
                        .await
                }
                #[tokio::test]
                async fn i313() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i313_the_second_device_needs_one_set_per_epoch(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                    )
                    .await
                }
                #[tokio::test]
                async fn i314() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i314_the_cap_rolls_the_epoch(&a, &b, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i315() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i315_a_v52_stream_reads_forever(&a, &b, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i316() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i316_a_forwarder_holds_without_a_key(&a, &b, &super::suffix(), $pick)
                        .await
                }
                #[tokio::test]
                async fn i317() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i317_a_nested_root_over_stream_keyed_children(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                        $cap,
                    )
                    .await
                }
                #[tokio::test]
                async fn i318() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i318_the_batched_adopt_of_stream_keyed_chunks(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                    )
                    .await
                }
                #[tokio::test]
                async fn i319() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i319_one_sender_one_counter(&a, &b, &super::suffix(), $pick).await
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
