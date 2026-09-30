//! v52.0.0 (CIRISPersist#930) — **the occurrence plane keeps every
//! assertion**, so a verdict at an earlier instant never moves when a later
//! assertion lands (FSD `SECOND_DEVICE.md` §8.5).
//!
//! - **I270** — a renewal does not move an earlier verdict.
//! - **I271** — the identity re-signing the pair does not erase the
//!   occurrence's agreement.
//! - **I272** — an interval before the occurrence first agreed does not count.
//! - **I273** — a revocation still ends each interval (the #421
//!   re-establishment rule, per assertion).
//! - **I274** — an older assertion arriving after a newer one lands in the
//!   history and counts; the current-state row is unchanged.
//! - **I275** — the V161 backfill: the migration's copy of the current rows
//!   restores the history the fold reads.
//! - **I276** — `node_bearing_at_with_next` names the next historical edge.
//! - **I278** — a trusted-local row is history, never agreement.
//!
//! I277 (the adopter-shaped roster judgement) lives in `rc5_adopts_invariants`
//! beside the infrastructure-room helpers it needs; I279 (the fail-open
//! provenance token) in `self_at_login`. Every body runs on memory, sqlite and
//! postgres — the three folds agree on the same row sequence by construction.

pub(crate) mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type as it;
    use crate::federation::{
        is_node_bearing_key_at, node_bearing_at_with_next, FederationDirectory,
    };
    use chrono::{DateTime, Duration, Utc};

    fn ago(secs: i64) -> DateTime<Utc> {
        let t = Utc::now() - Duration::seconds(secs);
        DateTime::<Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms")
    }

    async fn keys(d: &dyn FederationDirectory, tag: &str) -> (String, String) {
        let node = format!("node-id-{tag}");
        let install = format!("install-{tag}");
        ts::register_hybrid_key_as(d, &node, &node, it::NODE).await;
        ts::register_hybrid_key_as(d, &install, &install, it::PRIMITIVE).await;
        (node, install)
    }

    async fn signed(
        d: &dyn FederationDirectory,
        signer: &str,
        id: &str,
        occ: &str,
        t: DateTime<Utc>,
    ) {
        d.put_identity_occurrence(ts::signed_content_only_occurrence(signer, id, occ, t).await)
            .await
            .unwrap_or_else(|e| panic!("occurrence {id}/{occ} by {signer} at {t}: {e}"));
    }

    /// The identity claims at `t − 1s`, the occurrence agrees at `t`.
    async fn bound_at(d: &dyn FederationDirectory, id: &str, occ: &str, t: DateTime<Utc>) {
        signed(d, id, id, occ, t - Duration::seconds(1)).await;
        signed(d, occ, id, occ, t).await;
    }

    async fn bearing(d: &dyn FederationDirectory, k: &str, t: DateTime<Utc>) -> bool {
        is_node_bearing_key_at(d, k, t).await.expect("fold")
    }

    pub(crate) async fn i270_a_renewal_does_not_move_an_earlier_verdict(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (node, install) = keys(d, tag).await;
        bound_at(d, &node, &install, ago(300)).await;
        assert!(
            bearing(d, &install, ago(200)).await,
            "{tag} I270: bearing at t1"
        );
        // The occurrence renews its own agreement later.
        signed(d, &install, &node, &install, ago(100)).await;
        assert!(
            bearing(d, &install, ago(200)).await,
            "{tag} I270: a renewal at t3 moved the verdict at t1 < t3"
        );
        assert!(
            bearing(d, &install, ago(10)).await,
            "{tag} I270: bearing now"
        );
    }

    pub(crate) async fn i271_the_identity_re_signing_does_not_erase_agreement(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (node, install) = keys(d, tag).await;
        bound_at(d, &node, &install, ago(300)).await;
        // The identity re-signs the pair: the current row is now the
        // identity's, and the occurrence's own row is gone from it.
        signed(d, &node, &node, &install, ago(100)).await;
        assert!(
            crate::federation::occurrence_agreed_to(d, &node, &install)
                .await
                .unwrap(),
            "{tag} I271: the occurrence's agreement survives the identity's re-signing"
        );
        assert!(
            bearing(d, &install, ago(200)).await,
            "{tag} I271: bearing at t1"
        );
        assert!(
            bearing(d, &install, ago(10)).await,
            "{tag} I271: bearing now"
        );
    }

    pub(crate) async fn i272_before_agreement_does_not_count(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (node, install) = keys(d, tag).await;
        let agreed = ago(100);
        signed(d, &node, &node, &install, ago(300)).await;
        signed(d, &install, &node, &install, agreed).await;
        assert_eq!(
            crate::federation::occurrence_agreed_from(d, &node, &install)
                .await
                .unwrap(),
            Some(agreed),
            "{tag} I272: agreement is the occurrence's own first signature"
        );
        assert!(
            !bearing(d, &install, ago(200)).await,
            "{tag} I272: the identity's claim at t0 counted before the occurrence agreed at t2"
        );
        assert!(
            bearing(d, &install, ago(50)).await,
            "{tag} I272: bearing after agreement"
        );
    }

    pub(crate) async fn i273_a_revocation_ends_each_interval(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (node, install) = keys(d, tag).await;
        bound_at(d, &node, &install, ago(300)).await;
        d.put_identity_occurrence_revocation(
            ts::signed_occurrence_revocation(&node, &node, &install, ago(200)).await,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I273: revocation: {e}"));
        bound_at(d, &node, &install, ago(100)).await;
        assert!(
            bearing(d, &install, ago(250)).await,
            "{tag} I273: bearing before the revocation"
        );
        assert!(
            !bearing(d, &install, ago(150)).await,
            "{tag} I273: the revocation ends the first interval"
        );
        assert!(
            bearing(d, &install, ago(50)).await,
            "{tag} I273: re-established after"
        );
    }

    pub(crate) async fn i274_an_older_assertion_arriving_late_counts(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (node, install) = keys(d, tag).await;
        let older = ago(300);
        bound_at(d, &node, &install, ago(100)).await;
        let current_before = d
            .list_identity_occurrences_by_occurrence_key(&install)
            .await
            .unwrap();
        // An OLDER occurrence-signed assertion arrives after the newer one.
        signed(d, &install, &node, &install, older).await;
        assert_eq!(
            d.list_identity_occurrences_by_occurrence_key(&install)
                .await
                .unwrap(),
            current_before,
            "{tag} I274: the current-state row is unchanged by an older assertion"
        );
        let history = d
            .list_identity_occurrence_history_by_occurrence(&install)
            .await
            .unwrap();
        assert_eq!(
            history
                .first()
                .map(|a| (a.asserted_at, a.attesting_key_id.clone())),
            Some((older, Some(install.clone()))),
            "{tag} I274: the older assertion is in the history, first: {history:?}"
        );
        assert!(
            bearing(d, &install, ago(200)).await,
            "{tag} I274: the older assertion's interval counts"
        );
    }

    /// I275 — the V161 backfill copies the current rows. `wipe` empties the
    /// history, `replay` re-runs the migration file against the live store.
    pub(crate) async fn i275_the_backfill_restores_the_history<W, R>(
        d: &dyn FederationDirectory,
        tag: &str,
        wipe: W,
        replay: R,
    ) where
        W: std::future::Future<Output = ()>,
        R: std::future::Future<Output = ()>,
    {
        let (node, install) = keys(d, tag).await;
        bound_at(d, &node, &install, ago(300)).await;
        assert!(
            bearing(d, &install, ago(200)).await,
            "{tag} I275: bearing before"
        );
        wipe.await;
        assert!(
            !bearing(d, &install, ago(200)).await,
            "{tag} I275: with the history emptied the fold sees nothing (it reads history)"
        );
        replay.await;
        assert!(
            bearing(d, &install, ago(200)).await,
            "{tag} I275: the backfill restored the history from the current row"
        );
    }

    pub(crate) async fn i276_the_next_edge_is_historical(d: &dyn FederationDirectory, tag: &str) {
        let (node, install) = keys(d, tag).await;
        let t0 = ago(300);
        let t2 = ago(100);
        bound_at(d, &node, &install, t0).await;
        signed(d, &install, &node, &install, t2).await;
        let (b, next) = node_bearing_at_with_next(d, &install, ago(200))
            .await
            .unwrap();
        assert!(b, "{tag} I276: bearing at t1");
        assert_eq!(
            next,
            Some(t2),
            "{tag} I276: the next edge is the renewal's start"
        );
    }

    pub(crate) async fn i278_a_trusted_local_row_is_history_not_agreement(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (node, install) = keys(d, tag).await;
        d.put_identity_occurrence_local(crate::federation::IdentityOccurrence {
            identity_key_id: node.clone(),
            occurrence_key_id: install.clone(),
            device_class: crate::federation::types::device_class::SERVER.into(),
            hardware_attestation: None,
            asserted_at: ago(300),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap();
        let history = d
            .list_identity_occurrence_history_by_occurrence(&install)
            .await
            .unwrap();
        assert_eq!(history.len(), 1, "{tag} I278: the local row is history");
        assert_eq!(history[0].attesting_key_id, None, "{tag} I278: unsigned");
        assert!(
            !bearing(d, &install, ago(200)).await,
            "{tag} I278: a trusted-local row is never agreement"
        );
        signed(d, &install, &node, &install, ago(100)).await;
        assert!(
            !bearing(d, &install, ago(200)).await,
            "{tag} I278: the local interval starts no earlier than the agreement"
        );
        assert!(
            bearing(d, &install, ago(50)).await,
            "{tag} I278: bearing after agreement"
        );
    }
}

#[cfg(test)]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..10].to_owned()
    }
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                use crate::federation::FederationDirectory;
                macro_rules! w {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(d) = $fresh.await else { return };
                            bodies::$name(&d as &dyn FederationDirectory, &super::suffix()).await
                        }
                    };
                }
                w!(i270_a_renewal_does_not_move_an_earlier_verdict);
                w!(i271_the_identity_re_signing_does_not_erase_agreement);
                w!(i272_before_agreement_does_not_count);
                w!(i273_a_revocation_ends_each_interval);
                w!(i274_an_older_assertion_arriving_late_counts);
                w!(i276_the_next_edge_is_historical);
                w!(i278_a_trusted_local_row_is_history_not_agreement);
            }
        };
    }
    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i275_the_backfill_restores_the_history_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i275_the_backfill_restores_the_history(
            &b as &dyn crate::federation::FederationDirectory,
            &suffix(),
            async {
                b.execute_batch_for_test("DELETE FROM federation_identity_occurrence_history")
            },
            async {
                b.execute_batch_for_test(include_str!(
                    "../../migrations/sqlite/lens/V161__identity_occurrence_history.sql"
                ))
            },
        )
        .await
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i275_the_backfill_restores_the_history_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i275_the_backfill_restores_the_history(
            &b as &dyn crate::federation::FederationDirectory,
            &suffix(),
            async {
                b.get_client()
                    .await
                    .unwrap()
                    .batch_execute("DELETE FROM cirislens.federation_identity_occurrence_history")
                    .await
                    .unwrap()
            },
            async {
                b.get_client()
                    .await
                    .unwrap()
                    .batch_execute(include_str!(
                        "../../migrations/postgres/lens/V161__identity_occurrence_history.sql"
                    ))
                    .await
                    .unwrap()
            },
        )
        .await
    }
    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
