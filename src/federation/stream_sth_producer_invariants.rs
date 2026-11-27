//! v52.0.0 (CIRISPersist#950; CIRISEdge#734) — **the per-stream STH producer
//! mints exactly what the anti-equivocation gate accepts.**
//!
//! - **I147** (sqlite, postgres) — a two-chunk commons stream; the engine's
//!   STH over the chunks in `seq` order is admitted by `put_stream_sth` and
//!   served back by `latest_stream_sth`; a one-leaf STH (an inline file's
//!   shape) is admitted too; the same shas in the wrong order are refused by
//!   name (`root mismatch`); a `tree_size` beyond the chunks held is refused
//!   by the producer; the producer's key is this node's derived key.
//!   (The one-leaf STH here is a PREFIX of a chunked stream, not an inline
//!   file: that shape was refused until I200.)
//! - **I200** (v52.0.0, #953) — an inline blob's one-leaf log: the STH over
//!   `[sha]` at `inline_blob_stream_id(sha)` is admitted, served, and proves
//!   its leaf; two leaves, a blob this node does not hold, and the
//!   uppercase spelling are refused; the chunk floor refuses a stream named
//!   like a SHA-256 in either case.
//! - **I201** (v52.0.0, #953) — a stored receipt lists with the
//!   `received_at` this node stored it at, and the plain listing is the same
//!   receipts. v62.0.0 (T2-fix9): the receipt is node B's edition-2
//!   `delivery_receipt` statement through A's statement door.
//! - **I4170–I4176** (DR-fix1; sqlite, postgres) — a delivery receipt
//!   produced AS A HOST PRODUCES IT: the subscriber's
//!   `Engine::statement_draft` → `Engine::sign_draft`, then
//!   `Engine::put_edition2_statement`, from the JSON members (no fixture
//!   builder, no hand-assembled statement), against heads that arrive through
//!   the head's own door (`put_stream_sth` over chunks this node holds).
//!   I4170 before the head it waits (`receipt_root_unpublished`), on the
//!   holder and on the subscriber's own node; I4171 the head's door wakes it:
//!   it lands with NO manual re-fold (DR-fix2 is the door's touch); I4172
//!   under a head covering `k` it lands at once, listed with the statement's
//!   composite (3373 bytes), which verifies as the subscriber's over the
//!   statement; I4173 another published root at the same `k` is held
//!   (`receipt_equivocation`); I4174 `sub` ≠ `iss`, I4175 a dimension whose
//!   leaf is not the stream, I4176 a missing member are refused
//!   `edition2_payload_invalid`, nothing kept.

pub(crate) mod bodies {
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Pick};
    use crate::federation::types::cohort_scope::FEDERATION;
    use crate::federation::{BlobError, BlobStorage, FederationDirectory};

    pub(crate) async fn i147_the_producer_mints_what_the_gate_accepts<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let stream = format!("i147-stream-{run}");
        let mut shas = Vec::new();
        for (i, seg) in [vec![1u8; 300], vec![2u8; 200]].iter().enumerate() {
            let r = l
                .engine_a
                .put_blob_chunk_scoped(FEDERATION, None, &stream, i as u64, seg, 0, None)
                .await
                .unwrap_or_else(|e| panic!("chunk {i}: {e}"));
            shas.push(r.chunk_sha256);
        }
        // the STH over both chunks, in seq order
        let sth = l
            .engine_a
            .sign_stream_sth(&stream, &shas, 2)
            .await
            .expect("the engine mints the STH");
        assert_eq!(sth.tree_size, 2);
        assert_eq!(
            sth.log_id,
            crate::federation::stream_sth::log_id_for_stream(&stream)
        );
        l.ba.put_stream_sth(sth.clone(), &l.node_a)
            .await
            .expect("I147: the gate admits the producer's STH");
        let served =
            l.ba.latest_stream_sth(&stream)
                .await
                .unwrap()
                .expect("served back");
        assert_eq!(served.root_hash, sth.root_hash);
        assert_eq!(served.tree_size, 2);
        // a one-leaf STH (the inline-file shape) is a valid prefix
        let one = l.engine_a.sign_stream_sth(&stream, &shas, 1).await.unwrap();
        l.ba.put_stream_sth(one, &l.node_a)
            .await
            .expect("a one-leaf STH admits");
        // the same shas in the WRONG order: refused by name
        let reversed: Vec<[u8; 32]> = shas.iter().rev().copied().collect();
        let wrong = l
            .engine_a
            .sign_stream_sth(&stream, &reversed, 2)
            .await
            .unwrap();
        let e =
            l.ba.put_stream_sth(wrong, &l.node_a)
                .await
                .expect_err("a root over the wrong order is refused");
        assert!(
            matches!(&e, BlobError::InvalidArgument(m) if m.contains("root mismatch")),
            "{e:?}"
        );
        // a tree_size beyond the chunks held is refused by the PRODUCER
        let e = l
            .engine_a
            .sign_stream_sth(&stream, &shas, 3)
            .await
            .expect_err("over-claimed tree_size");
        assert!(matches!(&e, BlobError::InvalidArgument(_)), "{e:?}");
        // the producer's key is this node's derived key: a different producer id fails
        let sth2 = l.engine_a.sign_stream_sth(&stream, &shas, 2).await.unwrap();
        assert!(
            matches!(
                l.ba.put_stream_sth(sth2, &l.node_b).await,
                Err(BlobError::InvalidArgument(_))
            ),
            "the signature verifies against the named producer only"
        );
    }

    /// The JSON members a host states a receipt by (a digest as 64 hex).
    fn receipt_envelope(
        dimension_stream: &str,
        stream: &str,
        k: u64,
        root: &[u8; 32],
    ) -> serde_json::Value {
        serde_json::json!({
            "dimension":
                crate::federation::custody_ack::delivery_receipt_dimension(dimension_stream),
            "stream_id": stream,
            "epoch": 0,
            "k": k,
            "chunk_root": hex::encode(root),
        })
    }

    /// **The host's first two calls**, on the subscriber's engine:
    /// `statement_draft` (row type `scores`, `iss` = `sub` = the engine's
    /// identity-ref unless `sub` says otherwise, the kid the thumbprint that
    /// identity-ref carries), then `sign_draft`. Nothing here builds a
    /// payload, a header or a `COSE_Sign1` by hand.
    async fn host_receipt(
        subscriber: &crate::Engine,
        sub: &str,
        envelope: &serde_json::Value,
    ) -> Result<Vec<u8>, crate::federation::Error> {
        let iss = subscriber.local_derived_key_id().await.expect("iss");
        let kid = hex::encode(
            crate::federation::edition2::ingest::kid_of_identity_ref(&iss)
                .expect("the engine's key id is an identity-ref"),
        );
        let now = u64::try_from(chrono::Utc::now().timestamp_millis()).expect("after 1970");
        let draft = subscriber
            .statement_draft("scores", envelope, &iss, &kid, sub, now, None)
            .await?;
        Ok(subscriber.sign_draft(&draft).await.expect("sign_draft"))
    }

    fn is_payload_invalid(e: &crate::federation::Error) -> bool {
        const TOKEN: &str = crate::federation::malformed_row::EDITION2_PAYLOAD_INVALID;
        matches!(e, crate::federation::Error::MalformedRow { reason, .. } if *reason == TOKEN)
            || e.to_string().contains(TOKEN)
    }

    fn row_id(statement: &[u8]) -> crate::federation::edition2::names::RowId {
        crate::federation::edition2::names::RowId::of_statement(statement).expect("a row statement")
    }

    /// The route refuses `envelope` under `sub` as `edition2_payload_invalid`
    /// (at the draft, which runs the door's payload validator, or at the
    /// holder's statement door), and the holder keeps no statement.
    async fn route_refuses<B>(
        subscriber: &crate::Engine,
        holder: &crate::Engine,
        holder_store: &B,
        sub: &str,
        envelope: &serde_json::Value,
        what: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        match host_receipt(subscriber, sub, envelope).await {
            Err(e) => assert!(is_payload_invalid(&e), "{what}: at the draft: {e}"),
            Ok(st) => {
                let e = holder
                    .put_edition2_statement(&st, None)
                    .await
                    .expect_err(what);
                assert!(is_payload_invalid(&e), "{what}: at the door: {e}");
                assert!(
                    holder_store
                        .edition2_voices(&row_id(&st))
                        .await
                        .unwrap()
                        .is_empty(),
                    "{what}: nothing kept"
                );
            }
        }
    }

    /// I4170–I4176 (DR-fix1). Node A holds the stream and publishes its
    /// heads; node B is the subscriber, a host with its own engine.
    pub(crate) async fn i4170_a_host_produced_receipt_meets_the_heads_door<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::edition2::fold::reason;
        use crate::federation::edition2::ingest::StatementOutcome;
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let stream = format!("i4170-stream-{run}");
        let mut shas = Vec::new();
        for (i, seg) in [vec![3u8; 300], vec![4u8; 200]].iter().enumerate() {
            let r = l
                .engine_a
                .put_blob_chunk_scoped(FEDERATION, None, &stream, i as u64, seg, 0, None)
                .await
                .unwrap_or_else(|e| panic!("chunk {i}: {e}"));
            shas.push(r.chunk_sha256);
        }
        // The heads A will publish: minted, NOT yet through the head's door.
        let head2 = l.engine_a.sign_stream_sth(&stream, &shas, 2).await.unwrap();
        let head1 = l.engine_a.sign_stream_sth(&stream, &shas, 1).await.unwrap();
        assert_ne!(head1.root_hash, head2.root_hash, "two distinct roots");
        let iss = l.engine_b.local_derived_key_id().await.expect("B's id");
        assert_eq!(iss, l.node_b, "the subscriber signs as node B's key");
        let why = |st: &[u8]| {
            let id = row_id(st).0;
            let a = &l.engine_a;
            async move { a.edition2_held_reason(id).await.unwrap().map(|h| h.reason) }
        };

        // I4170 — no head yet: the receipt waits, on the holder and on the
        // subscriber's own node.
        let waiting = host_receipt(
            &l.engine_b,
            &iss,
            &receipt_envelope(&stream, &stream, 2, &head2.root_hash),
        )
        .await
        .expect("I4170: statement_draft produces a delivery receipt from its JSON members");
        let own = l.engine_b.put_edition2_statement(&waiting, None).await;
        assert!(
            matches!(own, Ok(StatementOutcome::Pending { .. })),
            "I4170 on the subscriber's own node (it holds no head): {own:?}"
        );
        let out = l.engine_a.put_edition2_statement(&waiting, None).await;
        assert!(
            matches!(out, Ok(StatementOutcome::Pending { .. })),
            "I4170 no head yet: the receipt waits: {out:?}"
        );
        assert_eq!(
            why(&waiting).await.as_deref(),
            Some(reason::RECEIPT_ROOT_UNPUBLISHED),
            "I4170 held, reason receipt_root_unpublished"
        );
        assert!(
            l.ba.list_delivery_receipts_for(&stream, 10)
                .await
                .unwrap()
                .is_empty(),
            "I4170 no receipt"
        );

        // I4171 — the head arrives through ITS door, and that door wakes the
        // held receipt: nothing here re-folds by hand.
        l.ba.put_stream_sth(head2.clone(), &l.node_a)
            .await
            .expect("I4171: the head's door admits A's head");
        assert_eq!(
            why(&waiting).await,
            None,
            "I4171 the head's door woke the held receipt (no manual re-fold)"
        );
        let listed = l.ba.list_delivery_receipts_for(&stream, 10).await.unwrap();
        assert_eq!(listed.len(), 1, "I4171 the receipt landed");
        assert_eq!(
            (
                listed[0].k,
                &listed[0].subscriber_key_id,
                listed[0].chunk_root
            ),
            (2, &iss, head2.root_hash),
            "I4171"
        );

        // I4172 — a head covering k is published: the receipt lands at once.
        let st = host_receipt(
            &l.engine_b,
            &iss,
            &receipt_envelope(&stream, &stream, 1, &head2.root_hash),
        )
        .await
        .expect("I4172: the draft");
        let out = l.engine_a.put_edition2_statement(&st, None).await.unwrap();
        assert!(
            matches!(out, StatementOutcome::Row { new: true, .. }),
            "I4172 {out:?}"
        );
        let listed = l.ba.list_delivery_receipts_for(&stream, 10).await.unwrap();
        assert_eq!(listed.len(), 2, "I4172 both receipts");
        let mine = listed
            .iter()
            .find(|r| r.k == 1)
            .expect("I4172: the receipt at k = 1 is listed");
        assert_eq!(mine.subscriber_key_id, iss, "I4172 the subscriber");
        assert_eq!(
            (mine.stream_id.as_str(), mine.epoch, mine.chunk_root),
            (stream.as_str(), 0, head2.root_hash),
            "I4172"
        );
        {
            use ciris_verify_core::cde::Value;
            let Ok(Value::Tag(18, inner)) = ciris_verify_core::cde::decode(&st) else {
                panic!("I4172: sign_draft assembles a tag-18 COSE_Sign1");
            };
            let parts = inner.as_array().expect("I4172: the COSE_Sign1 array");
            let (protected, payload, signature) = (
                parts[0].as_bytes().expect("I4172: protected"),
                parts[2].as_bytes().expect("I4172: payload"),
                parts[3].as_bytes().expect("I4172: signature"),
            );
            assert_eq!(
                mine.composite_signature.len(),
                3373,
                "I4172: one composite signature, 3373 bytes"
            );
            assert_eq!(
                mine.composite_signature.as_slice(),
                signature,
                "I4172: the listed receipt carries the statement's composite, whole"
            );
            let tbs = ciris_verify_core::edition2::sig_structure(protected, payload);
            crate::federation::edition2::composite_verify::verify_composite_via_directory(
                l.ba.as_ref(),
                &tbs,
                &iss,
                &mine.composite_signature,
                crate::federation::edition2::composite_verify::now_ms(),
            )
            .await
            .unwrap_or_else(|e| {
                panic!("I4172: the subscriber's composite over the statement: {e}")
            });
        }

        // I4173 — another PUBLISHED root at the same k: kept, concluding
        // nothing. The one-leaf head goes through the head's door too.
        l.ba.put_stream_sth(head1.clone(), &l.node_a)
            .await
            .expect("I4173: the one-leaf head");
        let equivocal = host_receipt(
            &l.engine_b,
            &iss,
            &receipt_envelope(&stream, &stream, 1, &head1.root_hash),
        )
        .await
        .expect("I4173: the draft");
        let out = l.engine_a.put_edition2_statement(&equivocal, None).await;
        assert!(
            matches!(out, Ok(StatementOutcome::Pending { .. })),
            "I4173 kept, concluding nothing: {out:?}"
        );
        assert_eq!(
            why(&equivocal).await.as_deref(),
            Some(reason::RECEIPT_EQUIVOCATION),
            "I4173 held, reason receipt_equivocation"
        );

        // I4174 — the subscriber is the row's sub.
        Box::pin(route_refuses(
            &l.engine_b,
            &l.engine_a,
            l.ba.as_ref(),
            &l.node_a,
            &receipt_envelope(&stream, &stream, 2, &head2.root_hash),
            "I4174 sub is not iss",
        ))
        .await;
        // I4175 — the dimension's leaf is the stream.
        Box::pin(route_refuses(
            &l.engine_b,
            &l.engine_a,
            l.ba.as_ref(),
            &iss,
            &receipt_envelope("another-stream", &stream, 2, &head2.root_hash),
            "I4175 the dimension's leaf is not the stream id",
        ))
        .await;
        // I4176 — every member is required.
        for member in ["chunk_root", "k", "epoch", "stream_id"] {
            let mut env = receipt_envelope(&stream, &stream, 2, &head2.root_hash);
            env.as_object_mut().unwrap().remove(member);
            Box::pin(route_refuses(
                &l.engine_b,
                &l.engine_a,
                l.ba.as_ref(),
                &iss,
                &env,
                &format!("I4176 no `{member}`"),
            ))
            .await;
        }

        let listed = l.ba.list_delivery_receipts_for(&stream, 10).await.unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|r| (r.k, r.chunk_root))
                .collect::<Vec<_>>(),
            vec![(1, head2.root_hash), (2, head2.root_hash)],
            "I4173–I4176 the two landed receipts stand alone"
        );
    }

    pub(crate) async fn i200_an_inline_blob_has_a_one_leaf_log<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::stream_sth::inline_blob_stream_id;
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let put = l
            .engine_a
            .put_blob_scoped(
                FEDERATION,
                None,
                format!("i200 {run}").as_bytes(),
                None,
                None,
            )
            .await
            .expect("an inline blob");
        let sha = put.at_rest_sha256;
        let sid = inline_blob_stream_id(&sha);
        assert_eq!(sid.len(), 64);
        let sth = l.engine_a.sign_stream_sth(&sid, &[sha], 1).await.unwrap();
        l.ba.put_stream_sth(sth.clone(), &l.node_a)
            .await
            .expect("I200: the one-leaf STH over an inline blob is admitted");
        let served =
            l.ba.latest_stream_sth(&sid)
                .await
                .unwrap()
                .expect("served back");
        assert_eq!((served.tree_size, served.root_hash), (1, sth.root_hash));
        assert!(
            l.ba.stream_inclusion_proof(&sid, 0, 1)
                .await
                .unwrap()
                .is_some(),
            "I200: the leaf is provable in its one-leaf log"
        );
        // Two leaves over one blob: over-claimed.
        let two = l
            .engine_a
            .sign_stream_sth(&sid, &[sha, sha], 2)
            .await
            .unwrap();
        l.ba.put_stream_sth(two, &l.node_a)
            .await
            .expect_err("I200: an inline log has one leaf");
        // A sha-shaped id naming a blob this node does NOT hold: nothing to commit to.
        let absent = [0x5au8; 32];
        let ghost = l
            .engine_a
            .sign_stream_sth(&inline_blob_stream_id(&absent), &[absent], 1)
            .await
            .unwrap();
        l.ba.put_stream_sth(ghost, &l.node_a)
            .await
            .expect_err("I200: no held blob, no leaf");
        // The uppercase spelling is not the log's name.
        let upper = l
            .engine_a
            .sign_stream_sth(&sid.to_uppercase(), &[sha], 1)
            .await
            .unwrap();
        l.ba.put_stream_sth(upper, &l.node_a)
            .await
            .expect_err("I200: one spelling");
        // The chunk floor refuses a SHA-shaped stream name, either case.
        for name in [sid.clone(), sid.to_uppercase()] {
            let e = l
                .engine_a
                .put_blob_chunk_scoped(FEDERATION, None, &name, 0, b"squat", 0, None)
                .await
                .expect_err("I200: a chunk under an inline blob's log name");
            assert!(
                matches!(&e, BlobError::InvalidArgument(m) if m.contains("reserved")),
                "{e:?}"
            );
        }
    }

    pub(crate) async fn i201_a_listed_receipt_carries_received_at<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::edition2::fixture_switch as e2;
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let put = l
            .engine_a
            .put_blob_scoped(
                FEDERATION,
                None,
                format!("i201 {run}").as_bytes(),
                None,
                None,
            )
            .await
            .unwrap();
        let sid = crate::federation::stream_sth::inline_blob_stream_id(&put.at_rest_sha256);
        let sth = l
            .engine_a
            .sign_stream_sth(&sid, &[put.at_rest_sha256], 1)
            .await
            .unwrap();
        l.ba.put_stream_sth(sth.clone(), &l.node_a).await.unwrap();
        // v62.0.0 (T2-fix9; F0-cp5 open item c) — B's receipt is its
        // edition-2 `delivery_ack:{stream_id}` statement, signed by B's
        // seed (the ladder's node B key), through A's statement door: the
        // earlier hybrid receipt drove the door F0-cp2 shut. The subject
        // (the stored instant and the two listings) is unchanged.
        let b_seed = format!("em-b-{run}");
        assert_eq!(e2::kid(&b_seed), l.node_b, "I201: B's seed is node B's key");
        let receipt = e2::delivery_receipt_statement(
            &b_seed,
            &sid,
            0,
            1,
            &sth.root_hash,
            e2::ms(chrono::Utc::now()),
        );
        let before = chrono::Utc::now() - chrono::Duration::seconds(5);
        e2::put_statement(&*l.ba, &receipt)
            .await
            .expect("I201: the receipt is stored");
        let after = chrono::Utc::now() + chrono::Duration::seconds(5);
        let stored =
            l.ba.list_stored_delivery_receipts_for(&sid, 10)
                .await
                .unwrap();
        assert_eq!(stored.len(), 1);
        assert!(
            stored[0].received_at > before && stored[0].received_at < after,
            "I201: received_at is the store's instant: {}",
            stored[0].received_at
        );
        assert_eq!(stored[0].receipt.subscriber_key_id, l.node_b);
        let plain = l.ba.list_delivery_receipts_for(&sid, 10).await.unwrap();
        assert_eq!(plain.len(), 1);
        assert_eq!(
            (plain[0].k, &plain[0].subscriber_key_id, plain[0].chunk_root),
            (1, &l.node_b, sth.root_hash)
        );
        let json = serde_json::to_value(&stored[0]).unwrap();
        assert!(
            json.get("received_at").is_some() && json.get("subscriber_key_id").is_some(),
            "I201: the stored receipt serializes flat: {json}"
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
                async fn i147() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i147_the_producer_mints_what_the_gate_accepts(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                    )
                    .await
                }
                #[tokio::test]
                async fn i4170() {
                    let Some((a, b)) = $dsns else { return };
                    Box::pin(bodies::i4170_a_host_produced_receipt_meets_the_heads_door(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                    ))
                    .await
                }
                #[tokio::test]
                async fn i200() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i200_an_inline_blob_has_a_one_leaf_log(&a, &b, &super::suffix(), $pick)
                        .await
                }
                #[tokio::test]
                async fn i201() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i201_a_listed_receipt_carries_received_at(
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
