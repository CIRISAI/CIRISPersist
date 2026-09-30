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
//!   receipts.

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
        use crate::federation::stream_receipt::{receipt_signing_bytes, DeliveryReceipt};
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
        let subscriber =
            crate::federation::tier_ingest::test_support::local_signer(&format!("em-b-{run}"));
        assert_eq!(subscriber.derived_key_id(), l.node_b);
        let bytes = receipt_signing_bytes(&l.node_b, &sid, 0, &sth.root_hash, 1);
        let receipt = DeliveryReceipt {
            stream_id: sid.clone(),
            subscriber_key_id: l.node_b.clone(),
            epoch: 0,
            k: 1,
            chunk_root: sth.root_hash,
            signature: subscriber.sign_hybrid(&bytes).await.unwrap(),
        };
        let before = chrono::Utc::now() - chrono::Duration::seconds(5);
        l.ba.put_delivery_receipt(receipt)
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
