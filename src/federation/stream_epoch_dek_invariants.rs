//! v55.0.0 (CIRISPersist#977, #981; CC 5.3.3.1, CC 5.1, CC 5.3.3.2.5) —
//! I750–I756: **a room's stream is stream-keyed, and a stream's epoch DEK may
//! be the caller's.**
//!
//! - **I750** (sqlite, postgres; #977) — a community chunk DAG is sealed per
//!   `(stream_id, epoch)`: every chunk's nonce is the STREAM nonce of its
//!   epoch's DEK, no chunk carries a community binding, the seal closes the
//!   epoch with its terminator, and a member's node receives its
//!   `key_grant:stream:v1` row at the room's scope through the plane, adopts
//!   the manifest and the chunks, and reads the DAG whole, byte-identical. A
//!   non-member stays refused.
//! - **I751** (sqlite, postgres; #977) — a removal rolls a room stream's
//!   epoch: the next chunk is at a fresh epoch the removed member holds no
//!   wrap of, and the member keeps the epoch it held (AV-70).
//! - **I752** (sqlite, postgres; #981) — a KEPT stream sealed under a supplied
//!   DEK: one `key_grant:stream:v1` row per audience recipient; the far node
//!   reads it whole through the plane, byte-identical; the same DEK, given to
//!   an MLS-only reader, opens a stored chunk with the public
//!   `stream_seal::open_stream_chunk`.
//! - **I753** (sqlite, postgres; #981) — an UNKEPT stream: zero
//!   `key_grant:stream:v1` rows, the sealer still reads it, a member's node is
//!   told which key it lacks.
//! - **I754** (sqlite, postgres; #981) — a second supply for an epoch is
//!   `stream_epoch_dek_exists` and the stored key stays; a supply by a writer
//!   that is not the stream's is `stream_not_authored`, naming the stream and
//!   never its writer; nothing is written.
//! - **I755** (sqlite, postgres; #981) — a supplied, kept epoch whose
//!   recipient leaves the audience refuses the next chunk with the retryable
//!   `stream_epoch_rotation_required { reason: removal, removed_key_id }`;
//!   persist mints nothing; a chunk at an unsupplied epoch is
//!   `stream_epoch_dek_missing`; once the next epoch is supplied the chunk
//!   lands under it.
//! - **I757** (sqlite, postgres; #977, operator ruling) — a room stream's
//!   chunks fall under the room's retention: the community sweep evicts the
//!   chunks of a stream epoch minted at a past community epoch and keeps those
//!   inside retention.
//! - **I756** (pure; #981) — the roll rule: cap and removal roll a minted
//!   epoch and refuse a supplied one with the reason; nothing else does.

pub(crate) mod bodies {
    use crate::federation::blobs::StreamRotationReason;
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Ladder, Pick};
    use crate::federation::key_grant::{
        is_key_grant_row, key_grant_dimension_of, KEY_GRANT_STREAM_DIMENSION,
    };
    use crate::federation::key_grant_invariants::two_node::key_grant_rows_for;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY};
    use crate::federation::{
        BlobBody, BlobError, BlobProvenance, BlobStorage, FederationDirectory,
    };

    fn segment(i: usize) -> Vec<u8> {
        (0..120 + (i % 5) * 17)
            .map(|j| (i * 29 + j) as u8)
            .collect()
    }

    async fn inline<B: BlobStorage + Sync>(b: &B, sha: &[u8; 32]) -> Vec<u8> {
        match b.get_blob(sha).await.unwrap() {
            Some(BlobBody::Inline(v)) => v,
            other => panic!("inline row expected: {other:?}"),
        }
    }

    /// The room's stream rows `l.engine_a` signed.
    async fn stream_rows<B: FederationDirectory + Sync + ?Sized>(
        b: &B,
        signer: &str,
    ) -> Vec<crate::federation::Attestation> {
        b.list_attestations_by(signer)
            .await
            .unwrap()
            .into_iter()
            .filter(is_key_grant_row)
            .filter(|r| key_grant_dimension_of(r) == Some(KEY_GRANT_STREAM_DIMENSION))
            .collect()
    }

    /// Write `n` room chunks to `stream` on A at producer epoch `epoch`.
    async fn write_room<B>(l: &Ladder<B>, stream: &str, n: usize, epoch: u64) -> Vec<u8>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let mut plain = Vec::new();
        for i in 0..n {
            let seg = segment(i);
            l.engine_a
                .put_blob_chunk_scoped(
                    COMMUNITY,
                    Some(&l.comm),
                    stream,
                    i as u64,
                    &seg,
                    epoch,
                    None,
                )
                .await
                .unwrap_or_else(|e| panic!("room chunk {i}: {e}"));
            plain.extend_from_slice(&seg);
        }
        plain
    }

    /// B pulls what A's plane serves it, adopts the sealed manifest and every
    /// chunk, and promotes.
    async fn deliver_dag<B>(l: &Ladder<B>, stream: &str, root: &[u8; 32], manifest_epoch: u64)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        l.engine_a.emit_pending_key_grants().await.unwrap();
        for row in key_grant_rows_for(l.ba.as_ref(), &l.node_a, &l.node_b).await {
            l.engine_b
                .apply_replicated_key_grant(row)
                .await
                .unwrap_or_else(|e| panic!("B admits A's row: {e}"));
        }
        let manifest_prov = BlobProvenance {
            author_key_id: l.node_a.clone(),
            cohort_scope: COMMUNITY.to_owned(),
            community_key_id: Some(l.comm.clone()),
            epoch: Some(manifest_epoch),
            tier: CryptoTier::CommunityDek,
            minter_key_id: Some(l.node_a.clone()),
        };
        l.engine_b
            .adopt_sealed_blob(
                &inline(l.ba.as_ref(), root).await,
                manifest_prov,
                None,
                crate::federation::AdoptDisposition::LocalOnly,
            )
            .await
            .expect("B adopts the manifest");
        // v55.0.0 (#977) — a stream-keyed room chunk names its community and
        // no community epoch: its key is the stream epoch's.
        let chunk_prov = BlobProvenance {
            author_key_id: l.node_a.clone(),
            cohort_scope: COMMUNITY.to_owned(),
            community_key_id: Some(l.comm.clone()),
            epoch: None,
            tier: CryptoTier::CommunityDek,
            minter_key_id: None,
        };
        for c in l.ba.stream_chunks(stream).await.unwrap().chunks {
            l.engine_b
                .adopt_sealed_chunk(
                    stream,
                    c.seq,
                    &inline(l.ba.as_ref(), &c.chunk_sha).await,
                    c.epoch,
                    c.plaintext_size,
                    chunk_prov.clone(),
                )
                .await
                .unwrap_or_else(|e| panic!("B adopts chunk {}: {e}", c.seq));
        }
        l.engine_b
            .promote_adopted_manifest_to_dag(root, &l.node_b, None)
            .await
            .expect("B promotes");
    }

    /// **I750** — see the module doc.
    pub(crate) async fn i750_a_room_stream_is_stream_keyed<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let stream = format!("i750-{run}");
        let plain = write_room(&l, &stream, 6, 0).await;
        // Stream-keyed: one epoch DEK row, no community binding on a chunk,
        // each chunk's nonce the STREAM nonce at its counter.
        let epochs = l.ba.stream_dek_list(&stream).await.unwrap();
        assert_eq!(epochs.len(), 1, "I750: one stream epoch");
        assert_eq!(epochs[0].cohort_scope, COMMUNITY);
        let master = l.ba.load_or_init_content_master().await.unwrap();
        let dek = crate::federation::at_rest_cascade::unwrap_dek_for_persist(
            &master,
            &epochs[0].self_retention_wrap,
        )
        .unwrap();
        let listing = l.ba.stream_chunks(&stream).await.unwrap();
        for (i, c) in listing.chunks.iter().enumerate() {
            assert_eq!(c.crypto_tier, CryptoTier::CommunityDek, "I750");
            assert!(
                l.ba.community_dek_blob_epoch(&c.chunk_sha)
                    .await
                    .unwrap()
                    .is_none(),
                "I750: a stream-keyed room chunk carries no community binding"
            );
            let env = crate::federation::at_rest_cascade::AtRestEnvelope::from_bytes(
                &inline(l.ba.as_ref(), &c.chunk_sha).await,
            )
            .unwrap();
            assert_eq!(
                env.nonce,
                crate::federation::stream_seal::stream_nonce(
                    &dek,
                    &stream,
                    0,
                    u32::try_from(i).unwrap(),
                    false
                ),
                "I750: chunk {i}'s nonce is the STREAM nonce (CC 5.3.3.1)"
            );
        }
        let sealed = l
            .engine_a
            .seal_stream_scoped(COMMUNITY, Some(&l.comm), &stream, None, None)
            .await
            .expect("A seals the room stream");
        assert!(
            l.ba.stream_dek_list(&stream).await.unwrap()[0].terminated,
            "I750: the seal terminated the epoch"
        );
        // The stream-axis rows at the room's scope, one per recipient.
        let rows = stream_rows(l.ba.as_ref(), &l.node_a).await;
        assert!(
            rows.iter().all(|r| r.cohort_scope == COMMUNITY)
                && rows.iter().any(|r| r.attested_key_id == l.node_b),
            "I750: a row to B at the room's scope: {rows:?}"
        );
        deliver_dag(&l, &stream, &sealed.manifest_sha256, sealed.epoch.unwrap()).await;
        assert_eq!(
            l.engine_b
                .read_blob_as(&sealed.manifest_sha256, &l.node_b, None)
                .await
                .expect("I750: B reads the room DAG whole"),
            plain,
            "I750: byte-identical on the far node"
        );
        let stranger = format!("i750-stranger-{run}");
        assert!(matches!(
            l.engine_b
                .read_blob_as(&sealed.manifest_sha256, &stranger, None)
                .await,
            Err(BlobError::NotGranted { .. })
        ));
    }

    /// Remove bob from the room on A (his own resignation).
    async fn remove_bob<B: FederationDirectory + Sync>(a: &B, comm: &str, bob: &str) {
        let rev = ts::sign_community_membership_revocation(
            bob,
            crate::federation::types::CommunityMembershipRevocation {
                community_key_id: comm.to_owned(),
                removed_identity_key_id: bob.to_owned(),
                removed_at: chrono::Utc::now(),
                effective_at: chrono::Utc::now(),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        a.put_community_membership_revocation(rev).await.unwrap();
    }

    /// **I751** — see the module doc.
    pub(crate) async fn i751_a_removal_rolls_a_room_stream<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let bob = format!("em-bob-{run}");
        let stream = format!("i751-{run}");
        write_room(&l, &stream, 2, 0).await;
        assert!(l
            .ba
            .stream_dek_grants(&stream, 0, &l.node_a)
            .await
            .unwrap()
            .iter()
            .any(|w| w.recipient_key_id == l.node_b));
        remove_bob(l.ba.as_ref(), &l.comm, &bob).await;
        l.engine_a
            .put_blob_chunk_scoped(COMMUNITY, Some(&l.comm), &stream, 2, b"after", 0, None)
            .await
            .expect("I751: the append after the removal");
        let epochs = l.ba.stream_dek_list(&stream).await.unwrap();
        assert_eq!(epochs.len(), 2, "I751: the removal rolled the epoch");
        assert!(epochs[0].terminated, "I751: epoch 0 carries its terminator");
        assert!(
            !l.ba
                .stream_dek_grants(&stream, epochs[1].epoch, &l.node_a)
                .await
                .unwrap()
                .iter()
                .any(|w| w.recipient_key_id == l.node_b),
            "I751: the removed member holds no wrap of the new epoch"
        );
        assert!(
            l.ba.stream_dek_grants(&stream, 0, &l.node_a)
                .await
                .unwrap()
                .iter()
                .any(|w| w.recipient_key_id == l.node_b),
            "I751: AV-70 — the member keeps the epoch it held"
        );
    }

    /// A fresh 32-byte DEK, standing in for an MLS exporter secret.
    fn mls_exporter() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (uuid::Uuid::new_v4().as_bytes()[i % 16]).wrapping_add(i as u8);
        }
        k
    }

    /// **I752** — see the module doc.
    pub(crate) async fn i752_a_kept_supplied_stream<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let stream = format!("i752-{run}");
        let dek = mls_exporter();
        let reg = l
            .engine_a
            .register_stream_epoch_dek(COMMUNITY, &l.comm, &stream, 0, &dek, true, None)
            .await
            .expect("I752: A supplies epoch 0's DEK");
        assert!(reg.keep && reg.granted.contains(&l.node_b), "I752: {reg:?}");
        let plain = write_room(&l, &stream, 4, 0).await;
        let epochs = l.ba.stream_dek_list(&stream).await.unwrap();
        assert_eq!(epochs.len(), 1, "I752: persist minted no epoch of its own");
        assert!(epochs[0].supplied && epochs[0].keep);
        // One row per audience recipient (A's own node and B's).
        let rows = stream_rows(l.ba.as_ref(), &l.node_a).await;
        let mut recipients: Vec<String> = rows.iter().map(|r| r.attested_key_id.clone()).collect();
        recipients.sort();
        let mut want = vec![l.node_a.clone(), l.node_b.clone()];
        want.sort();
        assert_eq!(recipients, want, "I752: one row per audience recipient");
        // An MLS-only reader holding the same DEK opens a stored chunk.
        let c0 =
            l.ba.stream_chunk_at(&stream, 0)
                .await
                .unwrap()
                .expect("chunk 0");
        let env = crate::federation::at_rest_cascade::AtRestEnvelope::from_bytes(
            &inline(l.ba.as_ref(), &c0.chunk_sha).await,
        )
        .unwrap();
        let (opened, slot) =
            crate::federation::stream_seal::open_stream_chunk(&dek, &stream, 0, None, 0, &env)
                .expect("I752: the MLS exporter opens the stored chunk");
        assert_eq!(opened, segment(0));
        assert_eq!((slot.counter, slot.last), (0, false));
        let sealed = l
            .engine_a
            .seal_stream_scoped(COMMUNITY, Some(&l.comm), &stream, None, None)
            .await
            .unwrap();
        deliver_dag(&l, &stream, &sealed.manifest_sha256, sealed.epoch.unwrap()).await;
        assert_eq!(
            l.engine_b
                .read_blob_as(&sealed.manifest_sha256, &l.node_b, None)
                .await
                .expect("I752: the far node reads the supplied-key DAG"),
            plain
        );
    }

    /// **I753** — see the module doc.
    pub(crate) async fn i753_an_unkept_stream_wraps_to_nobody<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let stream = format!("i753-{run}");
        let reg = l
            .engine_a
            .register_stream_epoch_dek(COMMUNITY, &l.comm, &stream, 0, &mls_exporter(), false, None)
            .await
            .unwrap();
        assert!(!reg.keep && reg.granted.is_empty() && reg.key_grant_emission.is_none());
        let plain = write_room(&l, &stream, 3, 0).await;
        let sealed = l
            .engine_a
            .seal_stream_scoped(COMMUNITY, Some(&l.comm), &stream, None, None)
            .await
            .unwrap();
        l.engine_a.emit_pending_key_grants().await.unwrap();
        assert!(
            stream_rows(l.ba.as_ref(), &l.node_a).await.is_empty(),
            "I753: an unkept stream has NO key_grant:stream:v1 row (CC 5.3.3.2.5)"
        );
        assert!(
            l.ba.stream_dek_grants(&stream, 0, &l.node_a)
                .await
                .unwrap()
                .is_empty(),
            "I753: and no wrap"
        );
        assert_eq!(
            l.engine_a
                .read_blob_as(&sealed.manifest_sha256, &l.node_a, None)
                .await
                .expect("I753: the sealer reads through its self-retention"),
            plain
        );
        deliver_dag(&l, &stream, &sealed.manifest_sha256, sealed.epoch.unwrap()).await;
        match l
            .engine_b
            .read_blob_as(&sealed.manifest_sha256, &l.node_b, None)
            .await
        {
            Err(BlobError::ChunkKeyNotYetGranted { .. }) => {}
            other => panic!("I753: the member's node lacks the stream key: {other:?}"),
        }
    }

    /// **I754** — see the module doc.
    pub(crate) async fn i754_exists_and_not_authored<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let stream = format!("i754-{run}");
        let first = mls_exporter();
        l.engine_a
            .register_stream_epoch_dek(COMMUNITY, &l.comm, &stream, 0, &first, true, None)
            .await
            .unwrap();
        write_room(&l, &stream, 1, 0).await;
        let e = l
            .engine_a
            .register_stream_epoch_dek(COMMUNITY, &l.comm, &stream, 0, &mls_exporter(), true, None)
            .await
            .expect_err("I754: a second supply for epoch 0");
        assert!(
            matches!(&e, BlobError::StreamEpochDekExists { epoch: 0, .. }),
            "I754: {e:?}"
        );
        assert_eq!(e.kind(), "blob_stream_epoch_dek_exists");
        // The stored key is the first one: a chunk still opens under it.
        let c0 = l.ba.stream_chunk_at(&stream, 0).await.unwrap().unwrap();
        let env = crate::federation::at_rest_cascade::AtRestEnvelope::from_bytes(
            &inline(l.ba.as_ref(), &c0.chunk_sha).await,
        )
        .unwrap();
        crate::federation::stream_seal::open_stream_chunk(&first, &stream, 0, None, 0, &env)
            .expect("I754: the epoch's key was not replaced");
        // B's node, a member, does not author A's stream: it cannot supply
        // the next epoch's key, and its chunk is refused, writing nothing.
        // (B holds the stream once it adopts; here B's own store records
        // A's stream by adopting one chunk.)
        let chunk_prov = BlobProvenance {
            author_key_id: l.node_a.clone(),
            cohort_scope: COMMUNITY.to_owned(),
            community_key_id: Some(l.comm.clone()),
            epoch: None,
            tier: CryptoTier::CommunityDek,
            minter_key_id: None,
        };
        l.engine_b
            .adopt_sealed_chunk(
                &stream,
                0,
                &inline(l.ba.as_ref(), &c0.chunk_sha).await,
                0,
                c0.plaintext_size,
                chunk_prov,
            )
            .await
            .unwrap();
        let e = l
            .engine_b
            .register_stream_epoch_dek(COMMUNITY, &l.comm, &stream, 1, &mls_exporter(), true, None)
            .await
            .expect_err("I754: a supply by a writer that is not the stream's");
        assert!(
            matches!(&e, BlobError::StreamNotAuthored { stream_id } if *stream_id == stream),
            "I754: {e:?}"
        );
        assert!(
            !e.to_string().contains(&l.node_a),
            "I754: the refusal never names the stream's writer (I41)"
        );
        assert!(
            l.bb.stream_dek_list(&stream).await.unwrap().is_empty(),
            "I754: nothing written"
        );
    }

    /// **I755** — see the module doc.
    pub(crate) async fn i755_a_supplied_epoch_is_the_callers_to_roll<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let bob = format!("em-bob-{run}");
        let stream = format!("i755-{run}");
        l.engine_a
            .register_stream_epoch_dek(COMMUNITY, &l.comm, &stream, 0, &mls_exporter(), true, None)
            .await
            .unwrap();
        write_room(&l, &stream, 2, 0).await;
        // A chunk naming an epoch nobody supplied: persist mints none.
        let e = l
            .engine_a
            .put_blob_chunk_scoped(COMMUNITY, Some(&l.comm), &stream, 2, b"ahead", 5, None)
            .await
            .expect_err("I755: an unsupplied epoch");
        assert!(
            matches!(&e, BlobError::StreamEpochDekMissing { epoch: 5, .. }),
            "I755: {e:?}"
        );
        remove_bob(l.ba.as_ref(), &l.comm, &bob).await;
        let e = l
            .engine_a
            .put_blob_chunk_scoped(COMMUNITY, Some(&l.comm), &stream, 2, b"after", 0, None)
            .await
            .expect_err("I755: the removal waits for the caller's next epoch");
        match &e {
            BlobError::StreamEpochRotationRequired {
                epoch,
                reason,
                removed_key_id,
                ..
            } => {
                assert_eq!(*epoch, 0);
                assert_eq!(*reason, StreamRotationReason::Removal);
                assert_eq!(removed_key_id.as_deref(), Some(l.node_b.as_str()));
            }
            other => panic!("I755: {other:?}"),
        }
        assert_eq!(e.kind(), "blob_stream_epoch_rotation_required");
        assert_eq!(
            l.ba.stream_dek_list(&stream).await.unwrap().len(),
            1,
            "I755: persist rolled nothing"
        );
        assert_eq!(
            l.ba.stream_chunks(&stream).await.unwrap().chunks.len(),
            2,
            "I755: nothing stored"
        );
        // The caller commits the MLS removal and supplies epoch 1.
        l.engine_a
            .register_stream_epoch_dek(COMMUNITY, &l.comm, &stream, 1, &mls_exporter(), true, None)
            .await
            .unwrap();
        l.engine_a
            .put_blob_chunk_scoped(COMMUNITY, Some(&l.comm), &stream, 2, b"after", 1, None)
            .await
            .expect("I755: the resend under the new epoch lands");
        let epochs = l.ba.stream_dek_list(&stream).await.unwrap();
        assert!(
            epochs[0].terminated,
            "I755: epoch 0 closed by the register door"
        );
        assert!(
            !l.ba
                .stream_dek_grants(&stream, 1, &l.node_a)
                .await
                .unwrap()
                .iter()
                .any(|w| w.recipient_key_id == l.node_b),
            "I755: the removed member has no wrap of epoch 1"
        );
    }

    /// **I757** (#977, operator ruling) — a room stream's chunks fall under
    /// the room's retention: with `retain_past_epochs = 0`, the community
    /// sweep evicts the chunks of a stream epoch minted at a past community
    /// epoch and keeps those minted at the current one. A second sweep evicts
    /// nothing more.
    pub(crate) async fn i757_room_stream_chunks_fall_under_retention<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::community_dek::orchestrate::sweep_rotated_epochs;
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let signer = ts::local_signer(&format!("em-a-{run}"));
        assert_eq!(signer.derived_key_id(), l.node_a, "fixture: A's signer");
        let old_stream = format!("i757-old-{run}");
        write_room(&l, &old_stream, 3, 0).await;
        let old = l.ba.stream_chunks(&old_stream).await.unwrap().chunks;
        assert_eq!(
            l.ba.stream_dek_list(&old_stream).await.unwrap()[0].room_epoch,
            Some(0),
            "I757: the stream epoch records the room's epoch at its mint"
        );
        // The room moves on: a new community epoch, and a stream written in it.
        let current =
            l.ba.community_dek_bump_epoch(&l.comm, &l.node_a)
                .await
                .unwrap();
        assert_eq!(current, 1);
        let new_stream = format!("i757-new-{run}");
        write_room(&l, &new_stream, 2, 0).await;
        let new = l.ba.stream_chunks(&new_stream).await.unwrap().chunks;
        assert_eq!(
            l.ba.stream_dek_list(&new_stream).await.unwrap()[0].room_epoch,
            Some(1)
        );
        l.ba.community_dek_set_retain_past_epochs(&l.comm, &l.node_a, Some(0))
            .await
            .unwrap();
        let report = sweep_rotated_epochs(l.ba.as_ref(), &l.comm, &signer, chrono::Utc::now())
            .await
            .expect("I757: the sweep runs");
        assert!(
            report.evicted_objects >= old.len() as u64,
            "I757: the past epoch's room chunks were evicted: {report:?}"
        );
        for c in &old {
            assert!(
                l.ba.blob_head(&c.chunk_sha).await.unwrap().is_none(),
                "I757: chunk {} of the stream minted at a past room epoch is evicted",
                c.seq
            );
        }
        for c in &new {
            assert!(
                l.ba.blob_head(&c.chunk_sha).await.unwrap().is_some(),
                "I757: chunk {} inside retention is kept",
                c.seq
            );
        }
        assert!(l.ba.stream_dek_list(&old_stream).await.unwrap()[0]
            .room_epoch
            .is_some());
        let again = sweep_rotated_epochs(l.ba.as_ref(), &l.comm, &signer, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(
            again.evicted_objects, 0,
            "I757: a second sweep evicts nothing more"
        );
    }

    macro_rules! runners {
        ($modname:ident, $dsn:expr, $pick:expr) => {
            mod $modname {
                use super::*;
                fn run() -> String {
                    uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
                }
                #[tokio::test]
                async fn i750() {
                    let Some((a, b)) = $dsn else { return };
                    i750_a_room_stream_is_stream_keyed(&a, &b, &run(), $pick).await
                }
                #[tokio::test]
                async fn i751() {
                    let Some((a, b)) = $dsn else { return };
                    i751_a_removal_rolls_a_room_stream(&a, &b, &run(), $pick).await
                }
                #[tokio::test]
                async fn i752() {
                    let Some((a, b)) = $dsn else { return };
                    i752_a_kept_supplied_stream(&a, &b, &run(), $pick).await
                }
                #[tokio::test]
                async fn i753() {
                    let Some((a, b)) = $dsn else { return };
                    i753_an_unkept_stream_wraps_to_nobody(&a, &b, &run(), $pick).await
                }
                #[tokio::test]
                async fn i754() {
                    let Some((a, b)) = $dsn else { return };
                    i754_exists_and_not_authored(&a, &b, &run(), $pick).await
                }
                #[tokio::test]
                async fn i757() {
                    let Some((a, b)) = $dsn else { return };
                    i757_room_stream_chunks_fall_under_retention(&a, &b, &run(), $pick).await
                }
                #[tokio::test]
                async fn i755() {
                    let Some((a, b)) = $dsn else { return };
                    i755_a_supplied_epoch_is_the_callers_to_roll(&a, &b, &run(), $pick).await
                }
            }
        };
    }

    #[cfg(feature = "sqlite")]
    runners!(
        sqlite,
        Some(("sqlite::memory:".to_owned(), "sqlite::memory:".to_owned())),
        |e: &crate::Engine| e.sqlite_backend().unwrap().clone()
    );
    #[cfg(feature = "postgres")]
    runners!(
        postgres,
        crate::test_pg::empty_dsn().zip(crate::test_pg::empty_dsn()),
        |e: &crate::Engine| e.postgres_backend().unwrap().clone()
    );

    /// **I756** — the roll rule, pure.
    #[test]
    fn i756_the_roll_rule() {
        use crate::federation::chunk_dag_cascade::orchestrate::{
            stream_epoch_verdict, EpochVerdict,
        };
        let rec = |supplied: bool, count: u64| crate::federation::StreamDekRecord {
            stream_id: "s".into(),
            epoch: 4,
            owner_key_id: "o".into(),
            cohort_scope: "community".into(),
            group_key_id: "c".into(),
            self_retention_wrap: String::new(),
            chunk_count: count,
            closed: false,
            terminated: false,
            supplied,
            keep: true,
            room_epoch: Some(4),
        };
        let cap = 10;
        // Neither: seal, minted or supplied.
        for s in [false, true] {
            assert_eq!(
                stream_epoch_verdict(&rec(s, 3), cap, None).unwrap(),
                EpochVerdict::Seal
            );
        }
        // A minted epoch rolls at the cap and on a removal.
        assert_eq!(
            stream_epoch_verdict(&rec(false, 9), cap, None).unwrap(),
            EpochVerdict::Roll
        );
        assert_eq!(
            stream_epoch_verdict(&rec(false, 3), cap, Some("x")).unwrap(),
            EpochVerdict::Roll
        );
        // A supplied epoch is refused, naming why (and whom).
        match stream_epoch_verdict(&rec(true, 9), cap, None) {
            Err(BlobError::StreamEpochRotationRequired {
                reason: StreamRotationReason::Cap,
                removed_key_id: None,
                epoch: 4,
                ..
            }) => {}
            other => panic!("I756 cap: {other:?}"),
        }
        match stream_epoch_verdict(&rec(true, 3), cap, Some("x")) {
            Err(BlobError::StreamEpochRotationRequired {
                reason: StreamRotationReason::Removal,
                removed_key_id: Some(k),
                ..
            }) if k == "x" => {}
            other => panic!("I756 removal: {other:?}"),
        }
        // The cap is checked first: a supplied epoch at the cap with a
        // removal says Cap (the slot is gone either way).
        assert!(matches!(
            stream_epoch_verdict(&rec(true, 9), cap, Some("x")),
            Err(BlobError::StreamEpochRotationRequired {
                reason: StreamRotationReason::Cap,
                ..
            })
        ));
        assert_eq!(
            serde_json::to_value(StreamRotationReason::Removal).unwrap(),
            "removal"
        );
        assert_eq!(
            serde_json::to_value(StreamRotationReason::Cap).unwrap(),
            "cap"
        );
    }
}
