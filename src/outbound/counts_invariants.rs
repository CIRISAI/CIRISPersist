//! v54.0.0 (CIRISPersist#996, CIRISEdge#814 item 2) — **I577: the status
//! counts equal the rows.** `outbound_counts()` is one `GROUP BY status`
//! COUNT; on every backend, across an enqueue → claim → deliver → fail →
//! ACK cycle, each status's count equals `list_outbound`'s length for that
//! status, statuses with no row are absent, and every row is counted once
//! (the counts sum to the rows enqueued).

#[cfg(test)]
mod bodies {
    use crate::outbound::{OutboundFilter, OutboundQueue, OutboundStatus};
    use std::collections::HashMap;

    const ALL: [OutboundStatus; 5] = [
        OutboundStatus::Pending,
        OutboundStatus::Sending,
        OutboundStatus::AwaitingAck,
        OutboundStatus::Delivered,
        OutboundStatus::Abandoned,
    ];

    /// The counts, and the same question answered by listing.
    async fn check<Q: OutboundQueue>(q: &Q, step: &str, want: &[(OutboundStatus, u64)]) {
        let counts = q.outbound_counts().await.expect("outbound_counts");
        let mut listed: HashMap<OutboundStatus, u64> = HashMap::new();
        for s in ALL {
            let n = q
                .list_outbound(
                    OutboundFilter {
                        status: Some(s),
                        ..OutboundFilter::default()
                    },
                    10_000,
                )
                .await
                .expect("list_outbound")
                .len() as u64;
            if n > 0 {
                listed.insert(s, n);
            }
        }
        assert_eq!(counts, listed, "I577 {step}: the counts equal the listing");
        let want: HashMap<OutboundStatus, u64> = want.iter().copied().collect();
        assert_eq!(counts, want, "I577 {step}: the expected counts");
        assert_eq!(
            counts.values().sum::<u64>(),
            4,
            "I577 {step}: every row counted once"
        );
    }

    pub(super) async fn i577_the_counts_equal_the_rows<Q>(q: &Q, tag: &str)
    where
        Q: OutboundQueue + crate::federation::FederationDirectory,
    {
        use OutboundStatus::*;
        let now = chrono::Utc::now();
        // The queue's FKs name registered keys.
        let (sender, dest) = (format!("i577-sender-{tag}"), format!("i577-dest-{tag}"));
        crate::federation::tier_ingest::test_support::register_hybrid_key(q, &sender).await;
        crate::federation::tier_ingest::test_support::register_hybrid_key(q, &dest).await;
        let mut ids = Vec::new();
        // (requires_ack, max_attempts, eligible now)
        for (i, (ack, max, now_ok)) in [
            (true, 3, true),
            (false, 3, true),
            (false, 1, true),
            (false, 3, false),
        ]
        .into_iter()
        .enumerate()
        {
            let body = format!("i577-{tag}-{i}").into_bytes();
            let sha: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&body).into();
            let at = if now_ok {
                now - chrono::Duration::seconds(1)
            } else {
                now + chrono::Duration::hours(1)
            };
            let id = q
                .enqueue_outbound(
                    &sender,
                    &dest,
                    "i577",
                    "1",
                    &body,
                    &sha,
                    body.len() as i32,
                    ack,
                    ack.then_some(300),
                    max,
                    3600,
                    at,
                )
                .await
                .expect("enqueue");
            ids.push((id, sha));
        }
        check(q, "enqueued", &[(Pending, 4)]).await;
        let claimed = q
            .claim_pending_outbound(10, 60, "i577-worker")
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 3, "I577: the three eligible rows");
        check(q, "claimed", &[(Pending, 1), (Sending, 3)]).await;
        q.mark_transport_delivered(&ids[0].0, "i577-t")
            .await
            .expect("deliver 0");
        q.mark_transport_delivered(&ids[1].0, "i577-t")
            .await
            .expect("deliver 1");
        check(
            q,
            "delivered",
            &[(Pending, 1), (Sending, 1), (AwaitingAck, 1), (Delivered, 1)],
        )
        .await;
        q.mark_transport_failed(&ids[2].0, "i577", "down", "i577-t", now)
            .await
            .expect("fail 2");
        check(
            q,
            "failed",
            &[
                (Pending, 1),
                (AwaitingAck, 1),
                (Delivered, 1),
                (Abandoned, 1),
            ],
        )
        .await;
        let row = q
            .match_ack_to_outbound(&ids[0].1)
            .await
            .expect("match")
            .expect("the awaiting row");
        q.mark_ack_received(&row.queue_id, b"ack")
            .await
            .expect("ack");
        check(q, "acked", &[(Pending, 1), (Delivered, 2), (Abandoned, 1)]).await;
        // The other `queue_id` doors (every one of which bound a `String`
        // against `$n::uuid` on postgres until this cut).
        let held = q
            .outbound_status(&ids[3].0)
            .await
            .expect("status")
            .expect("the pending row");
        assert_eq!(held.status, Pending);
        q.cancel_outbound(&ids[3].0).await.expect("cancel");
        check(q, "cancelled", &[(Delivered, 2), (Abandoned, 2)]).await;
        q.replay_abandoned(&ids[3].0).await.expect("replay");
        check(
            q,
            "replayed",
            &[(Pending, 1), (Delivered, 2), (Abandoned, 1)],
        )
        .await;
    }
}

#[cfg(test)]
mod run {
    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
    #[tokio::test]
    async fn i577_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        super::bodies::i577_the_counts_equal_the_rows(&b, &tag()).await;
    }
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i577_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i577_the_counts_equal_the_rows(&b, &tag()).await;
    }
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i577_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i577_the_counts_equal_the_rows(&b, &tag()).await;
    }
}
