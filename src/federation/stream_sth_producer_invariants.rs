//! v51.4.0 (CIRISPersist#950; CIRISEdge#734) — **the per-stream STH producer
//! mints exactly what the anti-equivocation gate accepts.**
//!
//! - **I147** (sqlite, postgres) — a two-chunk commons stream; the engine's
//!   STH over the chunks in `seq` order is admitted by `put_stream_sth` and
//!   served back by `latest_stream_sth`; a one-leaf STH (an inline file's
//!   shape) is admitted too; the same shas in the wrong order are refused by
//!   name (`root mismatch`); a `tree_size` beyond the chunks held is refused
//!   by the producer; the producer's key is this node's derived key.

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
